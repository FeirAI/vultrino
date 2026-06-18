//! Vultrino server implementation
//!
//! Provides JSON API mode for execute requests.

use crate::approval::{
    ApprovalLinks, ApprovalNotifier, ApprovalRequest, ApprovalStatus, NewApproval, RequesterInfo,
};
use crate::auth::{AuthManager, AuthResult, Permission, UseToken};
use crate::config::Config;
use crate::plugins::PluginRegistry;
use crate::policy::PolicyEngine;
use crate::router::CredentialResolver;
use crate::storage::StorageBackend;
use crate::{
    Credential, ExecuteRequest, ExecuteResponse, ExecutionOutcome, RequestContext, VultrinoError,
};
use std::sync::Arc;
use tracing::{info, warn};

/// While a serving process executes an approved action, it refreshes the
/// approval's execution claim this often so a slow-but-alive worker is never
/// mistaken for a crashed one. Must be comfortably smaller than the storage
/// backend's stale-claim timeout.
const EXECUTION_HEARTBEAT_SECS: u64 = 30;

/// Upper bound on how long a single halt abort callback may run before the halt
/// proceeds without waiting for it (V6) — a hanging integration can't stall the
/// halt, whose token-revoke + kill-policy legs have already committed.
const HALT_CALLBACK_TIMEOUT_SECS: u64 = 5;

/// Result of halting an agent (V6) — a machine-readable summary of the three
/// kill legs, returned by the halt admin endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HaltOutcome {
    /// The agent label that was halted.
    pub agent_label: String,
    /// Ids of the use tokens revoked by the halt.
    pub revoked_tokens: Vec<String>,
    /// Id of the installed per-agent kill policy.
    pub deny_policy_id: String,
    /// Whether the kill policy is active in the live engine now (true), or only
    /// persisted and pending the next refresh on this process (false).
    pub policy_active: bool,
    /// In-flight sessions for the agent in this process at halt time.
    pub in_flight: Vec<crate::session::SessionEntry>,
    /// How many abort callbacks were fired.
    pub callbacks_fired: usize,
}

/// Authentication context for a (possibly approval-gated) execution.
///
/// Carries the permission/scope source (`auth`) and, when a use token is driving
/// the request, the **whole token** so the server can authoritatively enforce
/// its credential *and* action scope at the seam where the token is spent and
/// consume it — a single source of truth. Also carries the force-approval flag
/// and the requester identity for the approval record.
#[derive(Default)]
pub struct ExecAuth {
    /// Real (API key) or synthesized (use token) auth result. `None` = local.
    pub auth: Option<AuthResult>,
    /// The use token driving this request, if any (single source of truth for
    /// scope enforcement and consumption).
    pub use_token: Option<UseToken>,
    /// Force human approval for this request (e.g. a token's `require_approval`).
    pub force_approval: bool,
    /// Who/what made the request, for the approval record.
    pub requester: RequesterInfo,
}

impl ExecAuth {
    /// Build an `ExecAuth` for an API-key-authenticated request.
    pub fn from_api_key(auth: AuthResult) -> Self {
        let requester = RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some(auth.api_key.id.clone()),
            principal_name: Some(auth.api_key.name.clone()),
            role: Some(auth.role.name.clone()),
        };
        Self {
            auth: Some(auth),
            use_token: None,
            force_approval: false,
            requester,
        }
    }

    /// Build an `ExecAuth` for a use-token-authenticated request. Derives the
    /// synthesized auth, the consume target, the force-approval flag, and the
    /// requester from the one token, so they cannot diverge.
    pub fn from_use_token(token: UseToken) -> Self {
        let requester = RequesterInfo {
            principal_kind: "use_token".to_string(),
            principal_id: Some(token.id.clone()),
            principal_name: Some(token.name.clone()),
            role: None,
        };
        Self {
            auth: Some(AuthResult::for_use_token(&token)),
            force_approval: token.require_approval,
            requester,
            use_token: Some(token),
        }
    }
}

/// Error from [`VultrinoServer::run_action`], tagged with whether the
/// side-effecting `plugin.execute` had begun.
///
/// `committed = false` means the failure happened during preflight (plugin not
/// loaded, invalid params, unusable token) — nothing ran, so resuming an
/// approval can safely retry. `committed = true` means the plugin was invoked
/// and the action may have had an external effect — it must not be retried.
struct RunError {
    /// True only when retrying could plausibly succeed: a *transient* preflight
    /// failure such as a plugin that isn't loaded yet. A *permanent* preflight
    /// failure (unusable use token, invalid params, missing credential) or a
    /// committed `plugin.execute` failure sets this false — a resumed approval is
    /// then finalized terminally instead of busy-polling forever.
    retryable: bool,
    error: VultrinoError,
}

impl RunError {
    /// A transient preflight failure (e.g. plugin not loaded) — safe to retry.
    fn retryable(error: VultrinoError) -> Self {
        Self { retryable: true, error }
    }
    /// A permanent preflight failure (unusable token, bad params, missing
    /// credential) — nothing ran, but retrying won't help.
    fn terminal(error: VultrinoError) -> Self {
        Self { retryable: false, error }
    }
    /// The plugin began executing and then failed — may have side-effected, so
    /// it must not be retried.
    fn committed(error: VultrinoError) -> Self {
        Self { retryable: false, error }
    }
}

/// Main Vultrino server
pub struct VultrinoServer {
    /// Configuration
    config: Config,
    /// Credential resolver
    resolver: CredentialResolver,
    /// Plugin registry
    plugins: Arc<PluginRegistry>,
    /// Policy engine
    policy_engine: Arc<PolicyEngine>,
    /// Storage backend
    storage: Arc<dyn StorageBackend>,
    /// Authentication manager
    auth_manager: Arc<AuthManager>,
    /// Whether authentication is required
    require_auth: bool,
    /// Action approval configuration
    approval_config: crate::approval::ApprovalConfig,
    /// Out-of-band approval notifiers (Telegram, webhook, ...)
    notifiers: Vec<Arc<dyn ApprovalNotifier>>,
    /// In-flight execution registry (V6).
    sessions: Arc<crate::session::SessionRegistry>,
    /// Registered harness abort callbacks, fired on halt (V6).
    halt_callbacks: parking_lot::RwLock<Vec<Arc<dyn crate::session::HaltCallback>>>,
    /// Count of unauthorized (policy/scope-denied) tool-call attempts (V12 metrics).
    /// Per-process, in-memory (resets on restart), like the rate/spend ledgers.
    unauthorized_attempts: std::sync::atomic::AtomicU64,
}

impl VultrinoServer {
    /// Create a new Vultrino server
    pub fn new(
        config: Config,
        storage: Arc<dyn StorageBackend>,
        resolver: CredentialResolver,
    ) -> Self {
        let plugins = Arc::new(PluginRegistry::new());
        let policy_engine = Arc::new(PolicyEngine::new());
        let auth_manager = Arc::new(AuthManager::new());

        // Load policies from config
        policy_engine.load_policies(config.policies.clone());

        // Wire the engine-level default decision (V2): fail-closed unless the
        // operator explicitly opts into legacy fail-open.
        let default_deny = matches!(
            config.enforcement.default_action,
            crate::config::EnforcementDefault::Deny
        );
        policy_engine.set_default_deny(default_deny);

        // Surface the two dangerous zero-policy postures loudly at startup,
        // since either is almost always a misconfiguration that would otherwise
        // be discovered only via behavior (a flood of denials, or — worse —
        // silent fail-open).
        if let Some(msg) = zero_policy_enforcement_warning(default_deny, !config.policies.is_empty())
        {
            warn!("{}", msg);
        }

        // By default, don't require auth in local mode
        let require_auth = config.server.mode == crate::config::ServerMode::Server;

        // Build approval subsystem from config
        let approval_config = config.approval.clone();
        let notifiers = crate::approval::build_notifiers(&approval_config);

        // Warn operators about approval configs that gate actions but can't
        // actually deliver a request to a human out of band.
        if approval_config.enabled {
            if notifiers.is_empty() {
                warn!(
                    "approvals are enabled with no notifier configured — pending requests are \
                     only visible via the web admin panel (`vultrino web`)"
                );
            } else if approval_config.public_base_url.is_none() {
                warn!(
                    "approvals have a notifier but no public_base_url — Telegram/webhook \
                     approve/deny links can't be built; approvals must be decided in the admin panel"
                );
            }
        }

        Self {
            config,
            resolver,
            plugins,
            policy_engine,
            storage,
            auth_manager,
            require_auth,
            approval_config,
            notifiers,
            sessions: Arc::new(crate::session::SessionRegistry::new()),
            halt_callbacks: parking_lot::RwLock::new(Vec::new()),
            unauthorized_attempts: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a server with a custom auth manager (for loading from storage)
    pub fn with_auth_manager(mut self, auth_manager: AuthManager) -> Self {
        self.auth_manager = Arc::new(auth_manager);
        self
    }

    /// Set whether authentication is required
    pub fn with_require_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    /// Load all installed WASM plugins
    pub async fn load_plugins(&self) -> Result<(), VultrinoError> {
        use crate::plugins::{PluginLoader, PluginInstaller};

        let installer = PluginInstaller::default();
        let installed = installer.list().await.map_err(|e| {
            VultrinoError::Plugin(crate::plugins::PluginError::Installation(e.to_string()))
        })?;

        let loader = PluginLoader::default();

        for info in installed {
            if !info.enabled {
                continue;
            }

            match loader.load_plugin(&info.directory).await {
                Ok(plugin) => {
                    tracing::info!(plugin = %info.manifest.plugin.name, "Loaded plugin");
                    self.plugins.register(plugin);
                }
                Err(e) => {
                    tracing::warn!(plugin = %info.manifest.plugin.name, error = %e, "Failed to load plugin");
                }
            }
        }

        Ok(())
    }

    /// Execute a request through Vultrino (no authentication / local use).
    ///
    /// If the action requires approval, this returns a `202` response whose body
    /// describes the pending approval (see [`ExecutionOutcome::into_response`]).
    pub async fn execute(&self, request: ExecuteRequest) -> Result<ExecuteResponse, VultrinoError> {
        self.execute_with_auth(request, None).await
    }

    /// Execute a request with optional API-key authentication.
    ///
    /// Backwards-compatible wrapper that collapses the [`ExecutionOutcome`] into
    /// an [`ExecuteResponse`]. Callers that want to distinguish a pending
    /// approval from a completed action (e.g. the MCP layer) should call
    /// [`Self::execute_gated`] directly.
    pub async fn execute_with_auth(
        &self,
        request: ExecuteRequest,
        auth: Option<&AuthResult>,
    ) -> Result<ExecuteResponse, VultrinoError> {
        let exec_auth = match auth {
            Some(a) => ExecAuth::from_api_key(a.clone()),
            None => ExecAuth::default(),
        };
        Ok(self.execute_gated(request, exec_auth).await?.into_response())
    }

    /// Execute a request, gating it on human approval when required.
    ///
    /// Approval is required when **any** of these hold:
    /// - the credential is flagged with metadata `require_approval = "true"`,
    /// - a matching policy returns `Prompt`,
    /// - the auth context forces it (e.g. a use token with `require_approval`).
    ///
    /// When gated, the action does **not** run: an [`ApprovalRequest`] is
    /// created, persisted, and announced to the configured notifiers, and
    /// [`ExecutionOutcome::Pending`] is returned. Otherwise the action runs
    /// immediately (consuming the use token, if any).
    pub async fn execute_gated(
        &self,
        request: ExecuteRequest,
        exec_auth: ExecAuth,
    ) -> Result<ExecutionOutcome, VultrinoError> {
        let mut context = RequestContext::new();

        // Permission + scope checks (only when authenticated).
        if let Some(auth_result) = &exec_auth.auth {
            context = context.with_auth(auth_result);

            if !auth_result.has_permission(Permission::Execute) {
                return Err(VultrinoError::PolicyDenied(
                    "Missing 'execute' permission".to_string(),
                ));
            }
            if !auth_result.can_access_credential(&request.credential) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Access denied to credential: {}",
                    request.credential
                )));
            }
        }

        // Resolve credential and normalize the action. A govder action label
        // (V8) resolves to the canonical `plugin.action`; the label (if any) is
        // surfaced to the approver/audit.
        let credential = self.resolver.resolve(&request.credential).await?;
        let (canonical_action, action_label) = self.config.resolve_action(&request.action);
        let (plugin_name, action_name) = parse_action(&canonical_action)?;
        let full_action = format!("{}.{}", plugin_name, action_name);

        // Authoritative use-token scope enforcement at the seam where the token
        // is actually spent — both credential and action scope, so the token's
        // single-action restriction is defended in depth rather than only at the
        // (MCP/HTTP) edge. The action scope is satisfied by either the presented
        // form (which may be a govder label) or the resolved canonical action.
        if let Some(token) = &exec_auth.use_token {
            if !token.allows_credential(&credential.alias) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to credential '{}'",
                    credential.alias
                )));
            }
            if !token.allows_action(&request.action) && !token.allows_action(&full_action) {
                // Surface both forms when the presented action was a label, so
                // the diagnostic isn't confusing under a label-scoped token.
                let shown = if action_label.is_some() {
                    format!("'{}' (resolved to '{}')", request.action, full_action)
                } else {
                    format!("'{}'", full_action)
                };
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to action {}",
                    shown
                )));
            }
        }

        // Evaluate policy (URL / method / rate limits / principal / spend). A
        // `Prompt` decision routes into the approval flow rather than failing.
        let url = request.params.get("url").and_then(|v| v.as_str());
        let method = request.params.get("method").and_then(|v| v.as_str());
        // V4: the resolved principal (key/token id + agent label) for
        // principal_pattern matching.
        let principal = exec_auth.auth.as_ref().map(|a| crate::policy::Principal {
            id: a.api_key.id.clone(),
            agent_label: a.api_key.agent_label.clone(),
        });
        // V3: the extracted spend attempt (amount + asset) for SpendCap.
        let spend = crate::policy::extract_spend(
            &self.config.spend_extractors,
            &full_action,
            &credential.alias,
            &request.params,
        );
        let decision = self.policy_engine.evaluate_full(&crate::policy::EvalInput {
            credential_alias: &credential.alias,
            url,
            method,
            principal: principal.as_ref(),
            spend: spend.as_ref(),
        });

        // V12: a dual-control token forces the action through the approval flow
        // (M-of-N), even when policy would Allow it and the credential doesn't
        // require approval — dual control must not be bypassable on the Allow path.
        let dual_control = exec_auth.use_token.as_ref().map(|t| t.dual_control).unwrap_or(false);
        let mut needs_approval = exec_auth.force_approval || dual_control;
        match decision {
            crate::policy::PolicyDecision::Allow => {}
            crate::policy::PolicyDecision::Deny(reason) => {
                self.record_unauthorized_attempt();
                return Err(VultrinoError::PolicyDenied(reason));
            }
            crate::policy::PolicyDecision::Prompt => {
                needs_approval = true;
            }
        }

        // Credential-level opt-in: `vultrino meta set <cred> require_approval true`.
        if credential
            .metadata
            .get("require_approval")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            needs_approval = true;
        }

        if needs_approval {
            if !self.approval_config.enabled {
                return Err(VultrinoError::PolicyDenied(
                    "This action requires human approval, but approvals are not enabled on this \
                     Vultrino instance"
                        .to_string(),
                ));
            }

            // Open an approval request. The use token is NOT consumed yet — it is
            // reserved when the approved action actually runs. The criticality
            // class (V5) drives the escalation/expiry SLA windows.
            let criticality = self
                .approval_config
                .criticality_for(&credential.alias, &full_action);
            let sla = self.approval_config.sla_for(criticality);
            let (approval, decision_token) = ApprovalRequest::open(NewApproval {
                credential: credential.alias.clone(),
                action: full_action.clone(),
                params: request.params.clone(),
                requester: exec_auth.requester.clone(),
                use_token_id: exec_auth.use_token.as_ref().map(|t| t.id.clone()),
                principal_id: principal.as_ref().map(|p| p.id.clone()),
                agent_label: principal.as_ref().and_then(|p| p.agent_label.clone()),
                action_label: action_label.clone(),
                dual_control,
                criticality,
                escalate_after: sla.escalate_after(),
                escalate_window: sla.escalate_window(),
                oob_identity: self.approval_config.oob_approver_identity.clone(),
                reauth_interval_secs: self.approval_config.reauth_interval_secs,
                // V12: dual control requires a second distinct approver (M-of-N,
                // M defaulting to 2). A single-approval request needs just one.
                required_approvals: if dual_control {
                    self.approval_config.dual_control_approvers.max(2)
                } else {
                    1
                },
            });

            // Bound the number of *pending* approvals a use token can open: each
            // open reserves a future use, so outstanding pending approvals plus
            // already-consumed uses must not exceed max_uses — otherwise a
            // single-use token could spawn an unbounded approval/notifier flood
            // (only execution is fail-closed otherwise). The count-and-insert is
            // atomic under the storage lock, so two concurrent opens (web + MCP)
            // can't both pass a stale count.
            let reservation = exec_auth
                .use_token
                .as_ref()
                .and_then(|t| t.max_uses.map(|max| (t.id.clone(), max)));
            match reservation {
                Some((token_id, max)) => {
                    self.storage
                        .store_approval_reserving(&approval, &token_id, max)
                        .await
                        .map_err(|e| match e {
                            crate::storage::StorageError::Conflict(_) => VultrinoError::PolicyDenied(
                                "This use token has no remaining capacity for a new pending approval"
                                    .to_string(),
                            ),
                            other => other.into(),
                        })?;
                }
                None => self.storage.store_approval(&approval).await?,
            }
            self.dispatch_notifications(&approval, &decision_token).await;
            // V9: emit the requested event to the signed outbox.
            self.emit_event(
                &approval.id,
                crate::outbox::EVENT_APPROVAL_REQUESTED,
                serde_json::json!({
                    "approval_id": approval.id,
                    "credential": approval.credential,
                    "action": approval.action,
                    "summary": approval.summary,
                    "requested_by": approval.requester.describe(),
                    "criticality": approval.criticality.to_string(),
                }),
            )
            .await;

            info!(
                approval_id = %approval.id,
                credential = %credential.alias,
                action = %full_action,
                "Action gated on human approval"
            );

            return Ok(ExecutionOutcome::Pending(Box::new(approval)));
        }

        // Not gated: run now (reserving the use token first, fail-closed).
        let response = self
            .run_action(
                credential,
                plugin_name,
                action_name,
                request.params.clone(),
                context,
                exec_auth.use_token.as_ref().map(|t| t.id.as_str()),
            )
            .await
            .map_err(|re| re.error)?;

        Ok(ExecutionOutcome::Completed(response))
    }

    /// Run a plugin action against a resolved credential.
    ///
    /// This is the shared core invoked both by the immediate path
    /// ([`Self::execute_gated`]) and the deferred path after approval
    /// ([`Self::resume_approved`]). It does **not** evaluate approval policy —
    /// that decision has already been made by the caller.
    ///
    /// Ordering matters: the plugin is resolved and params validated *before*
    /// the use token is consumed, so a not-loaded plugin or bad params never
    /// burns a use. The token is then reserved (fail-closed) immediately before
    /// `plugin.execute`, which is the point of no return. Errors are tagged with
    /// [`RunError::committed`] so a caller resuming an approval can tell a
    /// retryable preflight failure from a terminal post-side-effect one.
    async fn run_action(
        &self,
        credential: Credential,
        plugin_name: &str,
        action_name: &str,
        params: serde_json::Value,
        context: RequestContext,
        use_token_id: Option<&str>,
    ) -> Result<ExecuteResponse, RunError> {
        // Preflight (no side effects yet, no token consumed): resolve + validate.
        // A not-loaded plugin is *transient* (it may load later → retryable);
        // invalid params are *permanent* (a retry can't fix them → terminal).
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
            RunError::retryable(VultrinoError::Plugin(
                crate::plugins::PluginError::NotFound(plugin_name.to_string()),
            ))
        })?;
        plugin
            .validate_params(action_name, &params)
            .map_err(|e| RunError::terminal(e.into()))?;

        // Reserve the use token atomically, fail-closed, just before the side
        // effect. A failure here (exhausted/expired/revoked) means nothing ran
        // AND the token will never become usable, so it is terminal — a resumed
        // approval finalizes with the error rather than retrying forever.
        if let Some(tid) = use_token_id {
            self.storage.consume_use_token(tid).await.map_err(|e| {
                RunError::terminal(VultrinoError::PolicyDenied(format!(
                    "Use token cannot be used: {}",
                    e
                )))
            })?;
        }

        let request_id = context.request_id.clone();
        let credential_id = credential.id.clone();
        let credential_alias = credential.alias.clone();
        let credential_metadata = credential.metadata.clone();
        let credential_created_at = credential.created_at;
        // Capture the credential's secret material before it moves into the
        // plugin request, so we can scrub it from the response (V7 egress).
        let secret_material = credential.data.secret_material();
        let full_action = format!("{}.{}", plugin_name, action_name);

        // V6: record this execution as in-flight for the duration of the action
        // (and egress). The RAII guard deregisters on drop — including on error
        // or panic — so the registry reflects only genuinely running work, and a
        // halt can see what an agent is doing and fire its abort callbacks.
        let _session = self.sessions.begin(crate::session::SessionEntry {
            session_id: request_id.clone(),
            agent_label: context.agent_label.clone(),
            principal_id: context.api_key_id.clone(),
            token_id: use_token_id.map(|s| s.to_string()),
            credential: credential_alias.clone(),
            action: full_action.clone(),
            started_at: chrono::Utc::now(),
        });

        let plugin_request = crate::plugins::PluginRequest {
            credential,
            action: action_name.to_string(),
            params,
            context,
        };

        // Point of no return: the action may now have side effects.
        let mut response = plugin
            .execute(plugin_request)
            .await
            .map_err(|e| RunError::committed(e.into()))?;

        // V7 egress controls (before the body ever reaches the agent): fail
        // closed on a still-compressed body, else scrub the credential's own
        // reflected secret and apply operator egress classification, dropping
        // stale framing if the body changed. See `egress::scrub_response`.
        crate::egress::scrub_response(
            &mut response,
            &secret_material,
            &credential_alias,
            &self.config.egress,
            &full_action,
        );

        // Persist any credential update (e.g. OAuth2 token refresh).
        if let Some(updated_data) = &response.updated_credential {
            let updated_credential = crate::Credential {
                id: credential_id,
                alias: credential_alias.clone(),
                credential_type: updated_data.credential_type(),
                data: updated_data.clone(),
                metadata: credential_metadata,
                created_at: credential_created_at,
                updated_at: chrono::Utc::now(),
            };

            if let Err(e) = self.storage.store(&updated_credential).await {
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Failed to persist updated credential (token refresh)"
                );
            }
            // V7/V9: emit an observable rotation event to the signed outbox so a
            // govder subscriber sees in-path token rotation.
            info!(
                event = "credential.rotated",
                credential = %credential_alias,
                credential_type = %updated_data.credential_type(),
                request_id = %request_id,
                "credential rotated in-path (e.g. OAuth2 token refresh)"
            );
            self.emit_event(
                &credential_alias,
                crate::outbox::EVENT_CREDENTIAL_ROTATED,
                serde_json::json!({
                    "credential": credential_alias,
                    "credential_type": updated_data.credential_type().to_string(),
                }),
            )
            .await;
        }

        // Record for rate limiting.
        self.policy_engine.record_request(&credential_alias);

        info!(
            request_id = %request_id,
            credential = %credential_alias,
            action = %format!("{}.{}", plugin_name, action_name),
            status = response.status,
            "Request executed"
        );

        Ok(response)
    }

    /// Run a previously-approved action. Builds the request from the stored
    /// approval and executes it (consuming the use token, if any).
    async fn resume_approved(&self, approval: &ApprovalRequest) -> Result<ExecuteResponse, RunError> {
        // A credential that has gone missing, or an unparseable action, won't
        // recover on retry → terminal.
        let credential = self
            .resolver
            .resolve(&approval.credential)
            .await
            .map_err(RunError::terminal)?;
        let (plugin_name, action_name) =
            parse_action(&approval.action).map_err(RunError::terminal)?;
        let context = RequestContext::new();

        // Re-evaluate policy at execution time so the deferred path still
        // enforces hard *deny* gates — a human approval is not a policy bypass.
        // NOTE (policy-change interaction): policy is re-evaluated read-only at
        // resume, so a policy change between approval and execution applies. If
        // the matching policy is removed (un-policied → fail-closed `no_policy`)
        // OR a new Deny is pushed for the credential/agent (e.g. an emergency
        // kill via the admin API, propagated by the periodic refresh), the
        // resume is denied. That is intentional: a policy revoked or a Deny
        // pushed mid-flight must stop the pending action, not let an
        // already-approved request slip through un-governed. Only `Deny` blocks
        // here — a `Prompt` is already satisfied by the human's approval.
        // This is the READ-ONLY evaluation: rate limits were already counted when
        // the request first opened the approval, so re-counting here would
        // double-charge and could spuriously deny an already-approved action. A
        // `Prompt` is already satisfied (the human approved), so only `Deny`
        // blocks; the use token is left unconsumed when it does.
        let url = approval.params.get("url").and_then(|v| v.as_str());
        let method = approval.params.get("method").and_then(|v| v.as_str());
        // Rebuild the principal (V4) and spend (V3) from the recorded approval so
        // per-agent denies and spend caps are re-evaluated at resume. Spend is
        // checked read-only here (it was charged when the approval was opened).
        // NOTE: the agent_label is point-in-time (snapshotted at open); a per-
        // agent Deny created by binding a *new* label to the token after the
        // approval opened won't re-fire at resume — deny by token id or by the
        // credential to stop an in-flight approval regardless. The principal id
        // is taken from the explicit `approval.principal_id` (set at open), not
        // derived from the requester, so per-agent denies re-evaluate reliably.
        // Fall back to the requester's principal id for approvals persisted
        // before `principal_id` existed. (When both are None — e.g. a local,
        // principal-less requester — per-agent policies correctly don't apply.)
        let principal_id = approval
            .principal_id
            .as_ref()
            .or(approval.requester.principal_id.as_ref())
            .cloned();
        let principal = principal_id.map(|id| crate::policy::Principal {
            id,
            agent_label: approval.agent_label.clone(),
        });
        // Spend was checked AND charged when the approval opened; the read-only
        // resume re-enforces only hard deny gates and does not re-charge, so no
        // spend attempt is needed. A spend cap *changed* after the approval opened
        // therefore does not re-bind to this in-flight action (its spend was
        // already accounted at open); an operator who needs to stop such an
        // in-flight approval should push an explicit Deny policy.
        if let crate::policy::PolicyDecision::Deny(reason) =
            self.policy_engine.evaluate_readonly_full(&crate::policy::EvalInput {
                credential_alias: &credential.alias,
                url,
                method,
                principal: principal.as_ref(),
                spend: None,
            })
        {
            return Err(RunError::terminal(VultrinoError::PolicyDenied(reason)));
        }

        self.run_action(
            credential,
            plugin_name,
            action_name,
            approval.params.clone(),
            context,
            approval.use_token_id.as_deref(),
        )
        .await
    }

    /// Look up an approval and, if it has been approved but not yet run, execute
    /// it now and record the result. This is the polling entry point an agent
    /// calls via `check_approval` (MCP), `GET /api/v1/approvals/{id}` (HTTP), or
    /// `vultrino approval status` (CLI).
    ///
    /// `expected_principal`, when `Some`, must match the approval's requester —
    /// the ownership check happens **before** any execution, so a non-owner can
    /// never trigger another principal's approved action. Pass `None` for a
    /// trusted local caller (CLI/admin).
    ///
    /// Storage is reloaded first so a decision made by another process (the web
    /// admin panel, a Telegram button) is picked up.
    pub async fn check_and_resume_approval(
        &self,
        id: &str,
        expected_principal: Option<&str>,
    ) -> Result<ApprovalRequest, VultrinoError> {
        // Best-effort: pick up cross-process decisions.
        let _ = self.storage.reload().await;

        let approval = self
            .storage
            .get_approval(id)
            .await?
            .ok_or_else(|| VultrinoError::InvalidRequest(format!("Approval not found: {}", id)))?;

        // Ownership check BEFORE any side effect: a non-owner must not be able to
        // trigger execution of someone else's approved action.
        if let Some(pid) = expected_principal {
            if approval.requester.principal_id.as_deref() != Some(pid) {
                return Err(VultrinoError::PolicyDenied(
                    "This approval was requested by a different principal; you are not authorized \
                     to access it"
                        .to_string(),
                ));
            }
        }

        // Advance the SLA lifecycle on poll (V5) — atomically under the storage
        // lock so we never overwrite a decision committed concurrently by another
        // process with a stale local copy. This escalates a pending request past
        // its first window, expires one past its final deadline, and expires an
        // approved-but-unrun grant whose continuous-reauth window lapsed.
        let mut approval = self.storage.poll_refresh_approval(id).await?;
        // Surface the new state to the polling agent unless it's an executable
        // (Approved + not yet run) grant, which we run below.
        if approval.status != ApprovalStatus::Approved || approval.executed {
            return Ok(approval);
        }

        // Approved but not yet executed → run it now (claiming first to avoid a
        // double-run if two polls race).
        if approval.status == ApprovalStatus::Approved && !approval.executed {
            match self.storage.claim_approval_for_execution(id).await? {
                Some(mut claimed) => {
                    // Run the (possibly slow) action while heartbeating the claim,
                    // so a live worker's claim is never judged stale and re-run by
                    // another process. Resume against a clone so `claimed` stays
                    // free to mutate with the result. The select cancels the
                    // heartbeat loop as soon as the action finishes.
                    let resume_input = claimed.clone();
                    let hb_storage = self.storage.clone();
                    let hb_id = id.to_string();
                    let resume_fut = self.resume_approved(&resume_input);
                    tokio::pin!(resume_fut);
                    let outcome = loop {
                        tokio::select! {
                            r = &mut resume_fut => break r,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(
                                EXECUTION_HEARTBEAT_SECS,
                            )) => {
                                let _ = hb_storage.heartbeat_approval(&hb_id).await;
                            }
                        }
                    };

                    match outcome {
                        Ok(resp) => {
                            claimed.result_status = Some(resp.status);
                            // The full body already went to the live caller; cap
                            // what we persist into the (encrypted) vault so a large
                            // response can't bloat the approval record unbounded.
                            claimed.result_body = Some(cap_result_body(&resp.body));
                            claimed.result_error = None;
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        // Not retryable: either the plugin ran and may have
                        // side-effected (committed), or a permanent preflight
                        // failure (unusable token, bad params, missing credential).
                        // Finalize terminally so the agent isn't told to poll forever.
                        Err(re) if !re.retryable => {
                            claimed.result_error = Some(re.error.to_string());
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        // Transient preflight failure (e.g. plugin not loaded yet) —
                        // nothing ran. Release the claim and leave it un-executed so
                        // a later poll can retry.
                        Err(re) => {
                            claimed.executing = false;
                            claimed.executing_since = None;
                            claimed.result_error = Some(format!(
                                "could not start the approved action (will retry on next check): {}",
                                re.error
                            ));
                        }
                    }
                    self.storage.update_approval(&claimed).await?;
                    return Ok(claimed);
                }
                None => {
                    // Another worker owns/owned execution; return the latest.
                    approval = self.storage.get_approval(id).await?.unwrap_or(approval);
                }
            }
        }

        Ok(approval)
    }

    /// Deliver an approval to all configured notifiers (best-effort).
    async fn dispatch_notifications(&self, approval: &ApprovalRequest, decision_token: &str) {
        if self.notifiers.is_empty() {
            return;
        }
        let base = self.approval_config.public_base_url.as_deref().unwrap_or("");
        let links = approval.links(base, decision_token);
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify(approval, &links).await {
                warn!(
                    channel = notifier.channel(),
                    approval_id = %approval.id,
                    error = %e,
                    "Failed to deliver approval notification"
                );
            }
        }
    }

    /// One iteration of the approval SLA sweep (V5): re-read the vault, advance
    /// every open request through its lifecycle (escalate / expire), and re-ping
    /// the notifiers for those that escalated. Returns the sweep result.
    pub async fn sweep_approvals_once(
        &self,
    ) -> Result<crate::storage::ApprovalSweep, crate::storage::StorageError> {
        run_approval_sweep(
            &self.storage,
            &self.notifiers,
            self.approval_config.public_base_url.as_deref(),
        )
        .await
    }

    /// Whether the approval subsystem is enabled.
    pub fn approvals_enabled(&self) -> bool {
        self.approval_config.enabled
    }

    /// Get a reference to the storage backend
    pub fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
    }

    /// Get a reference to the in-flight session registry (V6).
    pub fn sessions(&self) -> &Arc<crate::session::SessionRegistry> {
        &self.sessions
    }

    /// Record an unauthorized tool-call attempt — one blocked by the policy
    /// engine (V12 metrics).
    fn record_unauthorized_attempt(&self) {
        self.unauthorized_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Count of unauthorized (policy-denied) tool-call attempts since start (V12).
    pub fn unauthorized_attempts(&self) -> u64 {
        self.unauthorized_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Best-effort append of an event to the signed outbox (V9). Never fails the
    /// calling operation — an event-log problem must not block the action it
    /// describes (the action's own success is the source of truth).
    pub async fn emit_event(&self, subject: &str, event_type: &str, payload: serde_json::Value) {
        if let Err(e) = self.storage.append_event(subject, event_type, payload).await {
            warn!(error = %e, event_type, "failed to append outbox event");
        }
    }

    /// Register a harness abort callback fired on halt (V6).
    pub fn register_halt_callback(&self, cb: Arc<dyn crate::session::HaltCallback>) {
        self.halt_callbacks.write().push(cb);
    }

    /// Halt an agent (V6 kill switch). Three legs:
    /// 1. **Revoke the agent's use tokens** — storage-authoritative and re-checked
    ///    under the vault lock on every gated call, so it takes effect immediately
    ///    across processes.
    /// 2. **Install an authoritative per-agent kill policy** (`principal_pattern`
    ///    = the label) — covers API-key-authed agents that carry no token. As a
    ///    `kill` policy it overrides any allow rule (it can't be ordered around),
    ///    and it propagates to other processes via the policy refresh.
    /// 3. **Fire registered abort callbacks** for the agent's in-flight sessions
    ///    in *this* process (the registry is per-process). Without a harness abort
    ///    primitive the achievable guarantee is "deny the next gated call"; a
    ///    registered callback can additionally preempt in-flight work.
    pub async fn halt_agent(&self, label: &str) -> Result<HaltOutcome, VultrinoError> {
        let label = label.trim();
        // The label must be a literal principal identifier (an agent label or a
        // key/token id), NOT a glob — otherwise a halt of `*` or `bot-*` would
        // silently deny an entire fleet, since `principal_pattern` is glob-matched.
        // `validate_agent_label` enforces the same `[A-Za-z0-9._-]`, non-empty,
        // ≤128 shape that labels and ids already satisfy, and rejects `*?[]`.
        crate::auth::validate_agent_label(label)
            .map_err(|e| VultrinoError::InvalidRequest(format!("invalid agent label: {e}")))?;

        // Leg 1: revoke every (still-active) use token of this target — matched by
        // the token's agent label OR its id, so halting a label-less agent by its
        // token id revokes that token (consistent with the kill policy, which
        // matches the principal id too). Token ids are prefixed (`vut_…`) and
        // agent labels are not, so `t.id == label` can't collide with a label.
        let tokens = self.storage.list_use_tokens().await?;
        let mut revoked_tokens = Vec::new();
        for t in tokens
            .iter()
            .filter(|t| !t.revoked && (t.agent_label.as_deref() == Some(label) || t.id == label))
        {
            self.storage.set_use_token_revoked(&t.id).await?;
            revoked_tokens.push(t.id.clone());
        }

        // Leg 2: install the authoritative kill policy (fixed id → idempotent).
        let deny_policy_id = format!("halt:{}", label);
        let policy = crate::policy::Policy::kill_switch(deny_policy_id.clone(), label);
        self.storage.store_policy(&policy).await?;
        let policy_active = match self.reload_policies().await {
            Ok(()) => true,
            Err(e) => {
                // The kill policy persisted but the live engine didn't reload; it
                // will apply within the refresh window. Surface it but don't fail
                // the halt — the token revocation (leg 1) already took effect.
                warn!(error = %e, agent = %label, "halt kill policy stored but engine reload failed");
                false
            }
        };

        // Leg 3: fire abort callbacks for what this process has in flight — matched
        // by the same target as the kill policy (label OR principal/token id), so a
        // by-id halt aborts a label-less agent's sessions too. Each callback is
        // best-effort and time-bounded (so a hanging integration can't block the
        // halt — legs 1 & 2 have already taken effect; with N callbacks the wait is
        // bounded by N × the per-callback timeout).
        let in_flight = self.sessions.for_halt_target(label);
        let callbacks = self.halt_callbacks.read().clone();
        for cb in &callbacks {
            if tokio::time::timeout(
                std::time::Duration::from_secs(HALT_CALLBACK_TIMEOUT_SECS),
                cb.on_halt(label, &in_flight),
            )
            .await
            .is_err()
            {
                warn!(callback = cb.name(), agent = %label, "halt abort callback timed out");
            }
        }

        // V9: emit the halt event to the signed outbox.
        self.emit_event(
            label,
            crate::outbox::EVENT_AGENT_HALTED,
            serde_json::json!({
                "agent_label": label,
                "revoked_tokens": revoked_tokens.len(),
                "deny_policy_id": deny_policy_id,
                "in_flight": in_flight.len(),
            }),
        )
        .await;

        info!(
            agent = %label,
            revoked_tokens = revoked_tokens.len(),
            in_flight = in_flight.len(),
            callbacks = callbacks.len(),
            policy_active,
            "agent halted"
        );

        Ok(HaltOutcome {
            agent_label: label.to_string(),
            revoked_tokens,
            deny_policy_id,
            policy_active,
            in_flight,
            callbacks_fired: callbacks.len(),
        })
    }

    /// Lift a previously-installed halt (V6): remove the per-agent kill policy and
    /// reload. Already-revoked tokens stay revoked (revocation is permanent — mint
    /// fresh tokens to resume). Returns whether a kill policy was present.
    pub async fn unhalt_agent(&self, label: &str) -> Result<bool, VultrinoError> {
        let label = label.trim();
        crate::auth::validate_agent_label(label)
            .map_err(|e| VultrinoError::InvalidRequest(format!("invalid agent label: {e}")))?;
        // Distinguish "no halt was present" (Ok false) from a real storage failure
        // (propagate) — the latter must not be reported as a successful no-op.
        let removed = match self.storage.delete_policy(&format!("halt:{}", label)).await {
            Ok(()) => true,
            Err(crate::storage::StorageError::PolicyNotFound(_)) => false,
            Err(e) => return Err(e.into()),
        };
        self.reload_policies().await?;
        Ok(removed)
    }

    /// Get a reference to the plugin registry
    pub fn plugins(&self) -> &Arc<PluginRegistry> {
        &self.plugins
    }

    /// Get a reference to the policy engine
    pub fn policy_engine(&self) -> &Arc<PolicyEngine> {
        &self.policy_engine
    }

    /// Reload the policy engine from the **union** of the static config policies
    /// and the admin-API-managed stored policies (V1). Called once at startup
    /// and after every admin policy mutation so a runtime push takes effect
    /// without a restart. Config policies remain declarative/code-managed; the
    /// admin API only adds, edits, or removes *stored* policies (by id).
    pub async fn reload_policies(&self) -> Result<(), VultrinoError> {
        let stored = self.storage.list_stored_policies().await?;
        self.policy_engine
            .load_policies(merge_policies(&self.config.policies, stored));
        Ok(())
    }

    /// Get the server configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the auth manager
    pub fn auth_manager(&self) -> &Arc<AuthManager> {
        &self.auth_manager
    }

    /// Check if authentication is required
    pub fn requires_auth(&self) -> bool {
        self.require_auth
    }
}

/// Max bytes of an action response body persisted into an approval record. The
/// full body is returned to the live caller; only the stored copy is capped.
const MAX_STORED_RESULT_BODY: usize = 64 * 1024;

/// Render a response body for storage in an approval record, truncating to
/// [`MAX_STORED_RESULT_BODY`] on a UTF-8 boundary with a marker.
fn cap_result_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if text.len() <= MAX_STORED_RESULT_BODY {
        return text.into_owned();
    }
    let mut end = MAX_STORED_RESULT_BODY;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[truncated {} bytes]", &text[..end], text.len() - end)
}

/// Default interval for the background policy refresh on long-running servers.
pub const POLICY_REFRESH_SECS: u64 = 5;

/// Default interval for the background approval SLA sweep (V5).
pub const APPROVAL_SWEEP_SECS: u64 = 15;

/// Default interval for the background event-outbox delivery pass (V9).
pub const OUTBOX_DELIVERY_SECS: u64 = 5;

/// Run GC on this many delivery passes (so it isn't on the hot delivery path).
const OUTBOX_GC_EVERY: u64 = 60;

/// Max events delivered per pass (V9), to bound a single pass's work.
const OUTBOX_BATCH: usize = 64;

/// How long a claimed-for-delivery event is leased (V9) — comfortably longer
/// than the per-request timeout, so a live deliverer's claim isn't judged stale,
/// but short enough that a crashed deliverer's events are re-claimable promptly.
const OUTBOX_LEASE_SECS: u64 = 30;

/// One pass of outbox delivery (V9): deliver the next deliverable event per
/// subject (per-subject ordering preserved), each signed with the shared HMAC
/// secret, recording success / failure (→ retry → dead-letter). A no-op when no
/// URL/secret is configured (events are still appended + replayable via the API).
pub async fn deliver_outbox_once(
    storage: &Arc<dyn StorageBackend>,
    config: &crate::outbox::OutboxConfig,
    client: &reqwest::Client,
) -> Result<(), crate::storage::StorageError> {
    let (Some(url), Some(secret)) = (config.url.as_deref(), config.hmac_secret.as_deref()) else {
        return Ok(());
    };
    // Claim and deliver ONE event at a time (up to a per-pass bound): each event
    // is leased immediately before its single POST, so its lease (>> the request
    // timeout) always covers that POST. Claiming a whole batch up front would let
    // a later event's lease expire while earlier (slow) POSTs run, re-opening the
    // cross-process double-delivery window. The claim+lease is atomic under the fd
    // lock, so a second process (web vs MCP) can't also take the same event.
    // Per-subject ordering still holds: a subject whose head is leased is skipped,
    // so each claim returns a different subject's head (round-robin, FIFO per
    // subject). Cost is one extra lock acquisition per event vs a batch — fine for
    // an outbox where the network POST dominates.
    for _ in 0..OUTBOX_BATCH {
        let mut claimed = storage.claim_deliverable_events(1, OUTBOX_LEASE_SECS).await?;
        debug_assert!(claimed.len() <= 1, "claim(1) must return at most one event");
        let Some(event) = claimed.pop() else {
            break;
        };
        let body = serde_json::to_vec(&event.delivery_body()).unwrap_or_default();
        let signature = crate::outbox::sign_body(secret, &body);
        let outcome = client
            .post(url)
            .header("Govder-Signature", signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        let (success, error) = match outcome {
            Ok(resp) if resp.status().is_success() => (true, None),
            Ok(resp) => (false, Some(format!("delivery returned {}", resp.status()))),
            // Strip the URL from the transport error so it never logs a secret.
            Err(e) => (false, Some(e.without_url().to_string())),
        };
        // A record failure must not abort the whole pass (the POST may have
        // succeeded; bailing here would leave it leased and re-deliver later).
        if let Err(e) = storage
            .record_event_delivery(event.sequence, success, error, config.max_attempts)
            .await
        {
            warn!(error = %e, sequence = event.sequence, "failed to record outbox delivery outcome");
        }
    }
    Ok(())
}

/// Background loop driving outbox delivery + periodic GC (V9). Always runs (when
/// the feature is wired) so the always-on event log is bounded by retention even
/// if push delivery is unconfigured; it pushes only when a URL + secret are set.
/// Safe to run in more than one process over the shared vault — per-subject
/// delivery and the monotonic sequence are atomic under the fd lock.
pub async fn deliver_outbox_periodically(
    storage: Arc<dyn StorageBackend>,
    config: crate::outbox::OutboxConfig,
    interval: std::time::Duration,
) {
    // A per-request timeout so one slow consumer can't stall the whole pass; the
    // lease (re-claimable once stale) covers an event whose POST times out.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let mut ticks: u64 = 0;
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = deliver_outbox_once(&storage, &config, &client).await {
            warn!(error = %e, "outbox delivery pass failed");
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(OUTBOX_GC_EVERY) {
            if let Err(e) = storage.gc_outbox(config.retention_secs).await {
                warn!(error = %e, "outbox GC failed");
            }
        }
    }
}

/// One iteration of the approval SLA sweep (V5): re-read the vault, advance every
/// open request (escalate / expire) atomically, and re-ping the notifiers for
/// those that newly escalated. Free-standing so either the web or MCP process can
/// drive it over the shared, fd-locked vault.
pub async fn run_approval_sweep(
    storage: &Arc<dyn StorageBackend>,
    notifiers: &[Arc<dyn ApprovalNotifier>],
    public_base_url: Option<&str>,
) -> Result<crate::storage::ApprovalSweep, crate::storage::StorageError> {
    storage.reload().await?;
    let sweep = storage.sweep_approval_lifecycle().await?;
    for approval in &sweep.escalated {
        notify_escalation(notifiers, public_base_url, approval).await;
    }
    if !sweep.escalated.is_empty() || !sweep.expired.is_empty() {
        info!(
            escalated = sweep.escalated.len(),
            expired = sweep.expired.len(),
            "approval SLA sweep advanced lifecycle"
        );
    }
    Ok(sweep)
}

/// Re-notify the configured channels that an approval escalated (V5). The
/// plaintext decision token is not stored, so an escalation re-ping carries only
/// the panel link — the approver decides in the panel. The notifiers key their
/// payload off the request's `Escalated` status (e.g. webhook emits
/// `approval.escalated`), so this is not mislabelled as a fresh request.
async fn notify_escalation(
    notifiers: &[Arc<dyn ApprovalNotifier>],
    public_base_url: Option<&str>,
    approval: &ApprovalRequest,
) {
    if notifiers.is_empty() {
        return;
    }
    let base = public_base_url.unwrap_or("");
    let links = ApprovalLinks {
        approve_url: String::new(),
        deny_url: String::new(),
        panel_url: format!("{}/approvals", base.trim_end_matches('/')),
    };
    for notifier in notifiers {
        if let Err(e) = notifier.notify(approval, &links).await {
            warn!(
                channel = notifier.channel(),
                approval_id = %approval.id,
                error = %e,
                "Failed to deliver escalation notification"
            );
        }
    }
}

/// Background loop that periodically advances open approvals through their SLA
/// lifecycle (V5): escalate those past their first window, expire those past
/// their final deadline, and re-ping notifiers on escalation. Lazy advancement
/// also happens on each agent poll, so this loop is what drives escalation/expiry
/// for requests nobody is actively polling. Safe to run in more than one process
/// over the shared vault: the lifecycle advance is atomic under the fd lock, so
/// only the process that wins the escalation transition re-notifies.
pub async fn sweep_approvals_periodically(
    storage: Arc<dyn StorageBackend>,
    notifiers: Vec<Arc<dyn ApprovalNotifier>>,
    public_base_url: Option<String>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = run_approval_sweep(&storage, &notifiers, public_base_url.as_deref()).await {
            warn!(error = %e, "periodic approval SLA sweep failed");
        }
    }
}

/// Background loop that periodically re-reads the vault from disk and reloads
/// the policy engine from the union of config + stored policies.
///
/// This is how a long-running process that does **not** serve the admin API
/// (notably the MCP server, and a second web replica) picks up policies pushed
/// via the admin API on another process — bounded by `interval`, rather than
/// only at restart. The web process that serves the admin API reloads
/// synchronously on each write, so it is always current.
///
/// Note: this gives policy changes *bounded-staleness* propagation, not instant.
/// For an **immediate** kill, revoke the use token — that is storage-
/// authoritative and re-checked under the lock on every gated call.
pub async fn refresh_policies_periodically(
    storage: Arc<dyn StorageBackend>,
    engine: Arc<PolicyEngine>,
    config_policies: Vec<crate::policy::Policy>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = refresh_policies_once(&storage, &engine, &config_policies).await {
            warn!(error = %e, "periodic policy refresh failed");
        }
    }
}

/// One iteration of the cross-process policy refresh: re-read the vault from
/// disk and reload the engine from the config+stored union. Separated from the
/// loop for testability.
pub async fn refresh_policies_once(
    storage: &Arc<dyn StorageBackend>,
    engine: &PolicyEngine,
    config_policies: &[crate::policy::Policy],
) -> Result<(), crate::storage::StorageError> {
    storage.reload().await?;
    let stored = storage.list_stored_policies().await?;
    engine.load_policies(merge_policies(config_policies, stored));
    Ok(())
}

/// Merge static config policies with admin-managed stored policies into the
/// engine's policy set: config first, then stored.
///
/// We deliberately do **not** dedup by id. Dropping a policy on an id collision
/// could silently drop a stored `Deny` — fail-open in a default-deny system.
/// The evaluator already handles multiple matching policies, so keeping both is
/// safe; and the admin API manages stored policies by id independently (a config
/// policy that coincidentally shares an id is config-managed and unaffected by
/// an API delete/PUT). Order is preserved since evaluation is order-sensitive.
pub fn merge_policies(
    config_policies: &[crate::policy::Policy],
    stored: Vec<crate::policy::Policy>,
) -> Vec<crate::policy::Policy> {
    let mut all = Vec::with_capacity(config_policies.len() + stored.len());
    all.extend_from_slice(config_policies);
    all.extend(stored);
    all
}

/// The startup warning (if any) for a given enforcement posture and whether any
/// policies are configured. Extracted as a pure function so the decision is
/// unit-testable without capturing log output. Both zero-policy postures are
/// dangerous misconfigurations worth surfacing loudly.
fn zero_policy_enforcement_warning(default_deny: bool, has_policies: bool) -> Option<&'static str> {
    if has_policies {
        return None;
    }
    Some(if default_deny {
        "enforcement default_action is 'deny' but no policies are configured — ALL credential \
         use will be denied until an allow policy is added (via config or the admin API). Set \
         `[enforcement] default_action = \"allow\"` to opt into the legacy fail-open behavior."
    } else {
        "enforcement default_action is 'allow' and no policies are configured — FAIL-OPEN: every \
         credential is usable by any principal with execute access, with no per-credential \
         restriction. Add allow/deny policies, or set `[enforcement] default_action = \"deny\"` \
         for the secure default."
    })
}

/// Parse action string into plugin name and action name
/// Format: "plugin.action" or just "action" (defaults to http plugin)
fn parse_action(action: &str) -> Result<(&str, &str), VultrinoError> {
    if let Some((plugin, action)) = action.split_once('.') {
        Ok((plugin, action))
    } else {
        // Default to http plugin
        Ok(("http", action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_action() {
        let (plugin, action) = parse_action("http.request").unwrap();
        assert_eq!(plugin, "http");
        assert_eq!(action, "request");

        let (plugin, action) = parse_action("crypto.sign").unwrap();
        assert_eq!(plugin, "crypto");
        assert_eq!(action, "sign");

        // Default to http
        let (plugin, action) = parse_action("request").unwrap();
        assert_eq!(plugin, "http");
        assert_eq!(action, "request");
    }

    #[test]
    fn test_merge_policies_keeps_both_never_drops_stored() {
        use crate::policy::Policy;
        let mut c = Policy::allow_all("cfg", "*");
        c.id = "shared".to_string();
        let mut s_dup = Policy::deny_all("stored-dup", "*");
        s_dup.id = "shared".to_string(); // same id as config — must NOT be dropped
        let s_new = Policy::deny_all("stored-new", "x-*");

        let merged = merge_policies(&[c], vec![s_dup, s_new]);
        // Nothing is dropped on an id collision — a stored Deny is never silently
        // lost (that would be fail-open). Config comes first; order preserved.
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].name, "cfg");
        assert!(merged.iter().any(|p| p.name == "stored-dup"));
        assert!(merged.iter().any(|p| p.name == "stored-new"));
    }

    #[test]
    fn test_zero_policy_enforcement_warning() {
        // Deny + no policies → "everything denied" warning.
        assert!(zero_policy_enforcement_warning(true, false)
            .unwrap()
            .contains("will be denied"));
        // Allow + no policies → fail-open warning.
        assert!(zero_policy_enforcement_warning(false, false)
            .unwrap()
            .contains("FAIL-OPEN"));
        // With policies configured, no warning regardless of posture.
        assert!(zero_policy_enforcement_warning(true, true).is_none());
        assert!(zero_policy_enforcement_warning(false, true).is_none());
    }
}
