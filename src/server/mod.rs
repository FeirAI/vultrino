//! Vultrino server implementation
//!
//! Provides JSON API mode for execute requests.

use crate::auth::{AuthManager, AuthResult, Permission, UseToken};
use crate::config::Config;
use crate::plugins::PluginRegistry;
use crate::policy::PolicyEngine;
use crate::router::CredentialResolver;
use crate::storage::StorageBackend;
use crate::{Credential, ExecuteRequest, ExecuteResponse, RequestContext, VultrinoError};
use std::sync::Arc;
use tracing::{info, warn};

/// Authentication context for an execution.
///
/// Carries the permission/scope source (`auth`) and, when a use token is driving
/// the request, the **whole token** so the server can authoritatively enforce
/// its credential *and* action scope at the seam where the token is spent, and
/// consume it by id — a single source of truth rather than a separate id field.
#[derive(Default)]
pub struct ExecAuth {
    /// Real (API key) or synthesized (use token) auth result. `None` = local.
    pub auth: Option<AuthResult>,
    /// The use token driving this request, if any.
    pub use_token: Option<UseToken>,
}

impl ExecAuth {
    /// Build an `ExecAuth` for an API-key-authenticated request.
    pub fn from_api_key(auth: AuthResult) -> Self {
        Self {
            auth: Some(auth),
            use_token: None,
        }
    }

    /// Build an `ExecAuth` for a use-token-authenticated request. Derives both
    /// the synthesized auth and the consume target from the one token, so they
    /// cannot diverge.
    pub fn from_use_token(token: UseToken) -> Self {
        Self {
            auth: Some(AuthResult::for_use_token(&token)),
            use_token: Some(token),
        }
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

        Self {
            config,
            resolver,
            plugins,
            policy_engine,
            storage,
            auth_manager,
            require_auth,
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
        use crate::plugins::{PluginInstaller, PluginLoader};

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
    pub async fn execute(&self, request: ExecuteRequest) -> Result<ExecuteResponse, VultrinoError> {
        self.execute_with_auth(request, None).await
    }

    /// Execute a request with optional API-key authentication.
    pub async fn execute_with_auth(
        &self,
        request: ExecuteRequest,
        auth: Option<&AuthResult>,
    ) -> Result<ExecuteResponse, VultrinoError> {
        let exec_auth = match auth {
            Some(a) => ExecAuth::from_api_key(a.clone()),
            None => ExecAuth::default(),
        };
        self.execute_gated(request, exec_auth).await
    }

    /// Execute a request with a full auth context.
    ///
    /// Checks permission + credential scope, evaluates policy, and runs the
    /// action. When the auth context carries a use token, the token is consumed
    /// (reserved, fail-closed) just before the action runs.
    pub async fn execute_gated(
        &self,
        request: ExecuteRequest,
        exec_auth: ExecAuth,
    ) -> Result<ExecuteResponse, VultrinoError> {
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

        // Resolve credential and parse the action.
        let credential = self.resolver.resolve(&request.credential).await?;
        let (plugin_name, action_name) = parse_action(&request.action)?;

        // Authoritative use-token scope enforcement at the seam where the token
        // is actually spent — both credential and action scope, so the token's
        // single-action restriction is defended in depth rather than only at the
        // (MCP/HTTP) edge.
        if let Some(token) = &exec_auth.use_token {
            let full_action = format!("{}.{}", plugin_name, action_name);
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

        // Evaluate policy (URL / method / rate limits).
        let url = request.params.get("url").and_then(|v| v.as_str());
        let method = request.params.get("method").and_then(|v| v.as_str());
        let decision = self
            .policy_engine
            .evaluate(&credential.alias, url, method, &context);

        match decision {
            crate::policy::PolicyDecision::Allow => {}
            crate::policy::PolicyDecision::Deny(reason) => {
                return Err(VultrinoError::PolicyDenied(reason));
            }
            crate::policy::PolicyDecision::Prompt => {
                return Err(VultrinoError::PolicyDenied(
                    "Request requires user approval (not implemented)".to_string(),
                ));
            }
        }

        self.run_action(
            credential,
            plugin_name,
            action_name,
            request.params.clone(),
            context,
            exec_auth.use_token.as_ref().map(|t| t.id.as_str()),
        )
        .await
    }

    /// Run a plugin action against a resolved credential.
    ///
    /// The plugin is resolved and params validated *before* the use token is
    /// consumed, so a not-loaded plugin or bad params never burns a use. The
    /// token is then reserved (fail-closed) immediately before the action runs.
    async fn run_action(
        &self,
        credential: Credential,
        plugin_name: &str,
        action_name: &str,
        params: serde_json::Value,
        context: RequestContext,
        use_token_id: Option<&str>,
    ) -> Result<ExecuteResponse, VultrinoError> {
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
            VultrinoError::Plugin(crate::plugins::PluginError::NotFound(plugin_name.to_string()))
        })?;

        // Validate params for the action.
        plugin.validate_params(action_name, &params)?;

        // Reserve the use token atomically, fail-closed, before the side effect.
        if let Some(tid) = use_token_id {
            self.storage.consume_use_token(tid).await.map_err(|e| {
                VultrinoError::PolicyDenied(format!("Use token cannot be used: {}", e))
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

        let response = plugin.execute(plugin_request).await?;

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
