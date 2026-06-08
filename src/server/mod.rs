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
    committed: bool,
    error: VultrinoError,
}

impl RunError {
    fn preflight(error: VultrinoError) -> Self {
        Self { committed: false, error }
    }
    fn committed(error: VultrinoError) -> Self {
        Self { committed: true, error }
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

        // By default, don't require auth in local mode
        let require_auth = config.server.mode == crate::config::ServerMode::Server;

        // Build approval subsystem from config
        let approval_config = config.approval.clone();
        let notifiers = crate::approval::build_notifiers(&approval_config);

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
            self.storage.store_approval(&approval).await?;
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
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
            RunError::preflight(VultrinoError::Plugin(
                crate::plugins::PluginError::NotFound(plugin_name.to_string()),
            ))
        })?;
        plugin
            .validate_params(action_name, &params)
            .map_err(|e| RunError::preflight(e.into()))?;

        // Reserve the use token atomically, fail-closed, just before the side
        // effect. A failure here (exhausted/expired/revoked) is still preflight —
        // nothing has run.
        if let Some(tid) = use_token_id {
            self.storage.consume_use_token(tid).await.map_err(|e| {
                RunError::preflight(VultrinoError::PolicyDenied(format!(
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
        let credential = self
            .resolver
            .resolve(&approval.credential)
            .await
            .map_err(RunError::preflight)?;
        let (plugin_name, action_name) =
            parse_action(&approval.action).map_err(RunError::preflight)?;
        let context = RequestContext::new();
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
                    match self.resume_approved(&claimed).await {
                        Ok(resp) => {
                            claimed.result_status = Some(resp.status);
                            claimed.result_body =
                                Some(String::from_utf8_lossy(&resp.body).to_string());
                            claimed.result_error = None;
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        Err(re) if re.committed => {
                            // The plugin ran (or may have); the action may have had
                            // side effects. Terminal — do not retry.
                            claimed.result_error = Some(re.error.to_string());
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        Err(re) => {
                            // Preflight failure (plugin not loaded, bad params,
                            // unusable token) — nothing ran. Release the claim and
                            // leave it un-executed so a later poll can retry.
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
}
