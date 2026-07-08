//! Plugin system for Vultrino
//!
//! Plugins handle different types of credential operations:
//! - HTTP: API authentication (API keys, OAuth, Basic Auth)
//! - Crypto: Transaction signing (future)
//! - SSH: Key operations (future)
//!
//! The plugin system supports both built-in plugins (like HttpPlugin)
//! and dynamically loaded WASM plugins installed from git repos,
//! local paths, or URLs.

mod ecdsa;
mod hmac;
mod http;
pub mod installer;
pub mod loader;
mod postgres;
mod ssh;
pub mod types;
pub mod wasm;

pub use ecdsa::EcdsaPlugin;
pub use hmac::HmacPlugin;
pub(crate) use http::{build_guarded_client, read_body_capped, REQUEST_TIMEOUT};
pub use http::HttpPlugin;
pub use installer::PluginInstaller;
pub use loader::{PluginLoader, PluginRegistryExt};
pub use postgres::PostgresPlugin;
pub use ssh::SshPlugin;
pub use types::{
    ActionDefinition, ActionParameterDefinition, CredentialFieldDefinition,
    CredentialTypeDefinition, FieldType, InstalledPluginInfo, McpToolDefinition, PluginFormat,
    PluginInfo, PluginManifest,
};

use crate::{Credential, CredentialData, CredentialType, ExecuteResponse, RequestContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Plugin-related errors
#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("Unsupported action: {0}")]
    UnsupportedAction(String),

    #[error("Unsupported credential type: {0}")]
    UnsupportedCredentialType(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("WASM error: {0}")]
    Wasm(String),

    #[error("Manifest error: {0}")]
    Manifest(#[from] types::ManifestError),

    #[error("Installation error: {0}")]
    Installation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Request to a plugin
#[derive(Debug, Clone)]
pub struct PluginRequest {
    /// The credential to use
    pub credential: Credential,
    /// The action to perform
    pub action: String,
    /// Action-specific parameters
    pub params: serde_json::Value,
    /// Request context
    pub context: RequestContext,
}

/// Trait for Vultrino plugins
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Unique identifier for this plugin
    fn name(&self) -> &str;

    /// Credential types this plugin can handle
    fn supported_credential_types(&self) -> Vec<CredentialType>;

    /// Actions this plugin supports
    fn supported_actions(&self) -> Vec<&str>;

    /// Execute an action with the credential
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError>;

    /// Execute an action, delivering the response body **incrementally**
    /// (connector M1, streaming LLM proxy).
    ///
    /// Only a plugin that can stream (today: [`HttpPlugin`]) overrides this. The
    /// default buffers via [`Plugin::execute`] and wraps the whole body as a
    /// single-chunk [`StreamingResponse`] — so every existing plugin
    /// (hmac/ecdsa/ssh/postgres/WASM) satisfies the streaming contract unchanged,
    /// and the server's streaming path never has to special-case a non-streaming
    /// plugin. The server applies the incremental egress scrub + V13b usage tap to
    /// the returned `body`; this method returns the **raw** upstream bytes.
    async fn execute_streaming(
        &self,
        request: PluginRequest,
    ) -> Result<crate::StreamingResponse, PluginError> {
        let resp = self.execute(request).await?;
        Ok(crate::StreamingResponse::from_buffered(resp))
    }

    /// Validate that params are correct for this action
    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError>;

    /// URL patterns this plugin can auto-match (for route-based detection)
    fn url_patterns(&self) -> Vec<&str> {
        vec![]
    }

    /// Get the plugin manifest (for WASM plugins)
    fn manifest(&self) -> Option<&PluginManifest> {
        None
    }

    /// Get credential type definitions provided by this plugin
    fn credential_type_definitions(&self) -> Vec<CredentialTypeDefinition> {
        vec![]
    }

    /// Get MCP tool definitions provided by this plugin
    fn mcp_tool_definitions(&self) -> Vec<McpToolDefinition> {
        vec![]
    }

    /// Parse form data into CredentialData for a custom credential type
    ///
    /// This is called when creating credentials of types defined by this plugin.
    /// The form HashMap contains field names mapped to their string values.
    fn parse_credential_data(
        &self,
        type_name: &str,
        form: &HashMap<String, String>,
    ) -> Result<CredentialData, PluginError> {
        // Default implementation for plugins that don't define custom credential types
        let _ = type_name;
        let _ = form;
        Err(PluginError::UnsupportedCredentialType(
            "This plugin does not support custom credential types".to_string(),
        ))
    }

    /// Check if this plugin handles a specific credential type name
    fn handles_credential_type(&self, type_name: &str) -> bool {
        self.credential_type_definitions()
            .iter()
            .any(|ct| ct.name == type_name)
    }

    /// Get the display name for a credential type
    fn credential_type_display_name(&self, type_name: &str) -> Option<String> {
        self.credential_type_definitions()
            .iter()
            .find(|ct| ct.name == type_name)
            .map(|ct| ct.display_name.clone())
    }

    /// Whether this plugin is a built-in plugin
    fn is_builtin(&self) -> bool {
        true
    }

    /// Plugin version string
    fn version(&self) -> &str {
        "0.0.0"
    }

    /// Plugin description
    fn description(&self) -> Option<&str> {
        None
    }
}

/// Registry of available plugins
pub struct PluginRegistry {
    plugins: RwLock<HashMap<String, Arc<dyn Plugin>>>,
}

impl PluginRegistry {
    /// Create a new registry with default plugins
    pub fn new() -> Self {
        let registry = Self {
            plugins: RwLock::new(HashMap::new()),
        };

        // Register default plugins
        registry.register(Arc::new(HttpPlugin::new()));
        registry.register(Arc::new(HmacPlugin::new()));
        registry.register(Arc::new(EcdsaPlugin::new()));
        registry.register(Arc::new(SshPlugin::new()));
        registry.register(Arc::new(PostgresPlugin::new()));

        registry
    }

    /// Register a plugin
    pub fn register(&self, plugin: Arc<dyn Plugin>) {
        let mut plugins = self.plugins.write();
        plugins.insert(plugin.name().to_string(), plugin);
    }

    /// Unregister a plugin by name
    pub fn unregister(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        let mut plugins = self.plugins.write();
        plugins.remove(name)
    }

    /// Get a plugin by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        let plugins = self.plugins.read();
        plugins.get(name).cloned()
    }

    /// Find a plugin that supports the given credential type
    pub fn find_by_credential_type(&self, cred_type: &CredentialType) -> Option<Arc<dyn Plugin>> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .find(|p| p.supported_credential_types().contains(cred_type))
            .cloned()
    }

    /// Find a plugin that handles a custom credential type name
    ///
    /// This is used for plugin-defined credential types (e.g., "plugin:pgp-signing:pgp_key")
    pub fn find_by_credential_type_name(&self, type_name: &str) -> Option<Arc<dyn Plugin>> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .find(|p| p.handles_credential_type(type_name))
            .cloned()
    }

    /// Find a plugin that matches the given URL pattern
    pub fn find_by_url(&self, url: &str) -> Option<Arc<dyn Plugin>> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .find(|p| {
                p.url_patterns()
                    .iter()
                    .any(|pattern| url_matches(url, pattern))
            })
            .cloned()
    }

    /// List all registered plugin names
    pub fn list(&self) -> Vec<String> {
        let plugins = self.plugins.read();
        plugins.keys().cloned().collect()
    }

    /// Get all plugins (for iteration)
    pub fn all(&self) -> Vec<Arc<dyn Plugin>> {
        let plugins = self.plugins.read();
        plugins.values().cloned().collect()
    }

    /// Get all credential type definitions from all plugins
    ///
    /// Returns tuples of (plugin_name, credential_type_definition)
    pub fn all_credential_types(&self) -> Vec<(String, CredentialTypeDefinition)> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .flat_map(|p| {
                let name = p.name().to_string();
                p.credential_type_definitions()
                    .into_iter()
                    .map(move |ct| (name.clone(), ct))
            })
            .collect()
    }

    /// Get all MCP tool definitions from all plugins
    ///
    /// Returns tuples of (plugin_name, mcp_tool_definition)
    pub fn all_mcp_tools(&self) -> Vec<(String, McpToolDefinition)> {
        let plugins = self.plugins.read();
        plugins
            .values()
            .flat_map(|p| {
                let name = p.name().to_string();
                p.mcp_tool_definitions()
                    .into_iter()
                    .map(move |tool| (name.clone(), tool))
            })
            .collect()
    }

    /// Parse form data into CredentialData for a plugin credential type
    ///
    /// The type_name can be in the format "plugin:plugin_name:type_name" or just "type_name"
    pub fn parse_credential_data(
        &self,
        type_name: &str,
        form: &HashMap<String, String>,
    ) -> Result<CredentialData, PluginError> {
        // Parse plugin:plugin_name:type_name format
        let (plugin_name, cred_type_name) = if type_name.starts_with("plugin:") {
            let parts: Vec<&str> = type_name.splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err(PluginError::InvalidParams(format!(
                    "Invalid credential type format: {}",
                    type_name
                )));
            }
            (Some(parts[1]), parts[2])
        } else {
            (None, type_name)
        };

        let plugins = self.plugins.read();

        // Find the plugin that handles this credential type
        let plugin = if let Some(name) = plugin_name {
            plugins
                .get(name)
                .ok_or_else(|| PluginError::NotFound(format!("Plugin not found: {}", name)))?
        } else {
            plugins
                .values()
                .find(|p| p.handles_credential_type(cred_type_name))
                .ok_or_else(|| {
                    PluginError::UnsupportedCredentialType(format!(
                        "No plugin handles credential type: {}",
                        cred_type_name
                    ))
                })?
        };

        plugin.parse_credential_data(cred_type_name, form)
    }

    /// Check if any plugin handles a credential type
    pub fn has_credential_type(&self, type_name: &str) -> bool {
        let plugins = self.plugins.read();
        plugins
            .values()
            .any(|p| p.handles_credential_type(type_name))
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a URL matches a pattern (simple glob-style matching)
fn url_matches(url: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        url.starts_with(prefix)
    } else {
        url == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_matching() {
        assert!(url_matches(
            "https://api.github.com/user",
            "https://api.github.com/*"
        ));
        assert!(url_matches(
            "https://api.github.com/repos/foo/bar",
            "https://api.github.com/*"
        ));
        assert!(!url_matches(
            "https://api.example.com/user",
            "https://api.github.com/*"
        ));
    }

    #[test]
    fn test_registry_default_plugins() {
        let registry = PluginRegistry::new();
        assert!(registry.get("http").is_some());
    }

    #[test]
    fn test_registry_unregister() {
        let registry = PluginRegistry::new();
        assert!(registry.get("http").is_some());
        registry.unregister("http");
        assert!(registry.get("http").is_none());
    }

    #[test]
    fn test_registry_all() {
        let registry = PluginRegistry::new();
        let all = registry.all();
        assert!(!all.is_empty());
        assert!(all.iter().any(|p| p.name() == "http"));
    }

    #[test]
    fn test_registry_list() {
        let registry = PluginRegistry::new();
        let names = registry.list();
        assert!(names.contains(&"http".to_string()));
    }

    #[test]
    fn test_registry_exposes_builtin_mcp_tools() {
        // Regression guard: MCP agents can only reach a built-in plugin's
        // tools if `all_mcp_tools()` surfaces them. The mcp/server.rs layer
        // walks this list when building tools/list and dispatching
        // tools/call. If this assertion breaks, the named tools will
        // silently disappear from agent tool lists.
        let registry = PluginRegistry::new();
        let pairs = registry.all_mcp_tools();
        let lookup = |plugin: &str| -> Vec<String> {
            pairs
                .iter()
                .filter(|(p, _)| p == plugin)
                .map(|(_, t)| t.name.clone())
                .collect()
        };

        let ssh_tools = lookup("ssh");
        assert!(
            ssh_tools.contains(&"deploy".to_string()) && ssh_tools.contains(&"run".to_string()),
            "ssh plugin must expose 'deploy' and 'run' MCP tools; got {:?}",
            ssh_tools
        );

        let pg_tools = lookup("postgres");
        assert!(
            pg_tools.contains(&"run_sql".to_string()) && pg_tools.contains(&"backup".to_string()),
            "postgres plugin must expose 'run_sql' and 'backup' MCP tools; got {:?}",
            pg_tools
        );
    }

    /// A buffered-only plugin (no `execute_streaming` override) — exercises the
    /// trait's DEFAULT streaming impl, the contract every non-http plugin relies on.
    struct BufferedOnlyPlugin;

    #[async_trait]
    impl Plugin for BufferedOnlyPlugin {
        fn name(&self) -> &str {
            "buffered_only"
        }
        fn supported_credential_types(&self) -> Vec<CredentialType> {
            vec![CredentialType::ApiKey]
        }
        fn supported_actions(&self) -> Vec<&str> {
            vec!["echo"]
        }
        async fn execute(&self, _req: PluginRequest) -> Result<ExecuteResponse, PluginError> {
            Ok(ExecuteResponse {
                status: 207,
                headers: HashMap::from([("x-test".to_string(), "1".to_string())]),
                body: b"hello-buffered-body".to_vec(),
                updated_credential: None,
            })
        }
        fn validate_params(
            &self,
            _action: &str,
            _params: &serde_json::Value,
        ) -> Result<(), PluginError> {
            Ok(())
        }
    }

    fn echo_request() -> PluginRequest {
        PluginRequest {
            credential: Credential::new(
                "c".to_string(),
                CredentialData::ApiKey {
                    key: crate::Secret::new("k-some-key-123"),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            ),
            action: "echo".to_string(),
            params: serde_json::json!({}),
            context: RequestContext::new(),
        }
    }

    #[tokio::test]
    async fn default_execute_streaming_matches_execute() {
        use futures::StreamExt;
        let plugin = BufferedOnlyPlugin;

        let buffered = plugin.execute(echo_request()).await.unwrap();
        let streamed = plugin.execute_streaming(echo_request()).await.unwrap();

        // Head is identical: status + headers known up front.
        assert_eq!(streamed.status, buffered.status);
        assert_eq!(streamed.headers, buffered.headers);

        // The default streaming impl yields the whole body as one chunk — byte-for-byte
        // identical to the buffered body. (P0 acceptance: no plugin behavior changes.)
        let mut collected = Vec::new();
        let mut body = streamed.body;
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(
            collected, buffered.body,
            "default execute_streaming must yield the same bytes as execute"
        );
    }
}
