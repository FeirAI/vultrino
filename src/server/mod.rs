//! Vultrino server implementation
//!
//! Provides JSON API mode for execute requests.

use crate::approval::{
    ApprovalNotifier, ApprovalRequest, ApprovalStatus, NewApproval, RequesterInfo,
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

        // Resolve credential and normalize the action.
        let credential = self.resolver.resolve(&request.credential).await?;
        let (plugin_name, action_name) = parse_action(&request.action)?;
        let full_action = format!("{}.{}", plugin_name, action_name);

        // Authoritative use-token scope enforcement at the seam where the token
        // is actually spent — both credential and action scope, so the token's
        // single-action restriction is defended in depth rather than only at the
        // (MCP/HTTP) edge.
        if let Some(token) = &exec_auth.use_token {
            if !token.allows_credential(&credential.alias) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to credential '{}'",
                    credential.alias
                )));
            }
            if !token.allows_action(&full_action) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to action '{}'",
                    full_action
                )));
            }
        }

        // Evaluate policy (URL / method / rate limits). A `Prompt` decision
        // routes into the approval flow rather than failing.
        let url = request.params.get("url").and_then(|v| v.as_str());
        let method = request.params.get("method").and_then(|v| v.as_str());
        let decision = self
            .policy_engine
            .evaluate(&credential.alias, url, method, &context);

        let mut needs_approval = exec_auth.force_approval;
        match decision {
            crate::policy::PolicyDecision::Allow => {}
            crate::policy::PolicyDecision::Deny(reason) => {
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
            // reserved when the approved action actually runs.
            let (approval, decision_token) = ApprovalRequest::open(NewApproval {
                credential: credential.alias.clone(),
                action: full_action.clone(),
                params: request.params.clone(),
                requester: exec_auth.requester.clone(),
                use_token_id: exec_auth.use_token.as_ref().map(|t| t.id.clone()),
                ttl: self.approval_config.ttl(),
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

        let plugin_request = crate::plugins::PluginRequest {
            credential,
            action: action_name.to_string(),
            params,
            context,
        };

        // Point of no return: the action may now have side effects.
        let response = plugin
            .execute(plugin_request)
            .await
            .map_err(|e| RunError::committed(e.into()))?;

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
        if let crate::policy::PolicyDecision::Deny(reason) =
            self.policy_engine
                .evaluate_readonly(&credential.alias, url, method)
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

        let mut approval = self
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

        // Auto-expire stale pending requests.
        if approval.expire_if_due() {
            let _ = self.storage.update_approval(&approval).await;
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

    /// Whether the approval subsystem is enabled.
    pub fn approvals_enabled(&self) -> bool {
        self.approval_config.enabled
    }

    /// Get a reference to the storage backend
    pub fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
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
