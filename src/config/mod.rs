//! Configuration system for Vultrino
//!
//! Loads configuration from TOML files and environment variables.

mod types;

pub use types::*;

use crate::policy::Policy;
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),

    #[error("Failed to read configuration: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse configuration: {0}")]
    ParseError(String),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Main Vultrino configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security policies
    pub policies: Vec<Policy>,
    /// MCP server configuration
    pub mcp: McpConfig,
    /// Action approval configuration
    pub approval: crate::approval::ApprovalConfig,
    /// Engine-level enforcement defaults (V2: default-deny mode).
    pub enforcement: EnforcementConfig,
    /// Amount-extraction rules for SpendCap policies (V3).
    pub spend_extractors: Vec<crate::policy::SpendExtractor>,
    /// Egress classification rules (V7).
    pub egress: Vec<crate::egress::EgressRule>,
    /// govder action-label → canonical plugin.action map (V8).
    pub action_labels: std::collections::HashMap<String, String>,
    /// Signed event-outbox delivery config (V9).
    pub outbox: crate::outbox::OutboxConfig,
    /// Per-tenant enforcement mode (V11): a tenant absent here uses
    /// [`TenantMode::Enforce`]. Lets one team run enforce while another observes.
    pub tenants: std::collections::HashMap<String, TenantMode>,
}

/// How a tenant's policy denials are handled (V11 multi-tenancy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenantMode {
    /// A policy `Deny` blocks the action (the secure default).
    #[default]
    Enforce,
    /// A policy `Deny` is **logged and emitted but not blocked** — the action
    /// runs anyway. Lets a team onboard in observe-only mode while another team
    /// on the same vultrino enforces.
    Observe,
}

impl Config {
    /// The enforcement mode for a principal's tenant (V11). Untenanted principals
    /// and tenants not listed default to [`TenantMode::Enforce`] (fail-closed).
    pub fn tenant_mode(&self, tenant: Option<&str>) -> TenantMode {
        match tenant {
            Some(t) => self.tenants.get(t).copied().unwrap_or_default(),
            None => TenantMode::Enforce,
        }
    }
}

impl Config {
    /// Resolve a presented action: if it is a configured govder label, return
    /// `(canonical_plugin_action, Some(label))`; otherwise it is already a
    /// canonical `plugin.action`, so `(presented, None)` (V8).
    pub fn resolve_action(&self, presented: &str) -> (String, Option<String>) {
        match self.action_labels.get(presented) {
            Some(canonical) => (canonical.clone(), Some(presented.to_string())),
            None => (presented.to_string(), None),
        }
    }
}

/// Whether `s` is a well-formed canonical `plugin.action` — a non-empty plugin
/// and a non-empty action separated by a `.`. Used to validate `action_labels`
/// targets at config load so a typo can't silently route to a default plugin.
fn is_well_formed_action(s: &str) -> bool {
    matches!(s.split_once('.'), Some((plugin, action)) if !plugin.is_empty() && !action.is_empty())
}

/// Engine-level enforcement configuration.
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// What the policy engine decides for a credential that matches **no**
    /// policy. Defaults to [`EnforcementDefault::Deny`] (fail-closed).
    pub default_action: EnforcementDefault,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        // Fail-closed by default: an un-policied credential is denied. This is
        // the govder enforcement posture and closes the historical fail-open
        // gap. Operators who want the legacy behavior opt in with
        // `[enforcement] default_action = "allow"`.
        Self {
            default_action: EnforcementDefault::Deny,
        }
    }
}

/// Policy-engine decision for a credential that matches no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDefault {
    /// Allow un-policied credentials (legacy fail-open).
    Allow,
    /// Deny un-policied credentials (fail-closed; default).
    Deny,
}

impl Config {
    /// Load configuration from a file
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path).await?;
        let raw: RawConfig =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        Self::from_raw(raw)
    }

    /// Load configuration from a string
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        Self::from_raw(raw)
    }

    /// Convert from raw TOML config to validated config
    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let server = raw.server.unwrap_or_default().into();
        let storage = raw.storage.unwrap_or_default().try_into()?;
        let logging = raw.logging.unwrap_or_default().into();
        let mcp = raw.mcp.unwrap_or_default().into();
        let approval = raw.approvals.map(TryInto::try_into).transpose()?.unwrap_or_default();
        let enforcement = raw
            .enforcement
            .map(EnforcementConfig::try_from)
            .transpose()?
            .unwrap_or_default();
        let spend_extractors = raw
            .spend_extractors
            .into_iter()
            .map(Into::into)
            .collect();
        let egress = raw
            .egress
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        // Validate action-label mappings at load (fail-closed): a malformed or
        // ambiguous mapping is an operator error we surface now, rather than a
        // deferred footgun that only fails at request time.
        let mut action_labels = std::collections::HashMap::new();
        for a in raw.action_labels {
            let label = a.label.trim().to_string();
            let action = a.action.trim().to_string();
            if label.is_empty() || action.is_empty() {
                return Err(ConfigError::Invalid(
                    "action_labels: label and action must both be non-empty".to_string(),
                ));
            }
            // The canonical target must be a well-formed `plugin.action`, so a
            // typo can't silently route to the default `http` plugin later.
            if !is_well_formed_action(&action) {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: action '{}' for label '{}' is not a well-formed 'plugin.action'",
                    action, label
                )));
            }
            // A label that equals its own target, or shadows another label's
            // target, would make resolution ambiguous/circular — reject it.
            if label == action {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: label '{}' must differ from its canonical action",
                    label
                )));
            }
            if action_labels.insert(label.clone(), action).is_some() {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: duplicate label '{}'",
                    label
                )));
            }
        }
        // A label must not shadow another mapping's canonical target (which would
        // make `resolve_action` order-dependent on that target).
        for canonical in action_labels.values() {
            if action_labels.contains_key(canonical) {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: '{}' is both a label and a canonical action target",
                    canonical
                )));
            }
        }

        let policies = raw
            .policies
            .into_iter()
            .map(|p| p.try_into())
            .collect::<Result<Vec<Policy>, _>>()?;
        // Validate spend-cap structural invariants (fail-closed, no nesting).
        for p in &policies {
            p.validate().map_err(ConfigError::Invalid)?;
        }

        let outbox = raw.outbox.map(TryInto::try_into).transpose()?.unwrap_or_default();

        // Per-tenant enforcement mode (V11).
        let mut tenants = std::collections::HashMap::new();
        for t in raw.tenants {
            let mode = match t.mode.as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref() {
                Some("observe") => TenantMode::Observe,
                Some("enforce") | None | Some("") => TenantMode::Enforce,
                Some(other) => {
                    return Err(ConfigError::Invalid(format!(
                        "tenant '{}': unknown mode '{}' (expected enforce|observe)",
                        t.id, other
                    )))
                }
            };
            // Trim the id so a padded `" team-a "` matches the (trimmed-at-mint)
            // principal tenant rather than silently falling back to Enforce.
            let id = t.id.trim().to_string();
            if id.is_empty() {
                return Err(ConfigError::Invalid("tenant id must not be empty".to_string()));
            }
            if tenants.insert(id.clone(), mode).is_some() {
                return Err(ConfigError::Invalid(format!("duplicate tenant '{}'", id)));
            }
        }

        Ok(Self {
            server,
            storage,
            logging,
            policies,
            mcp,
            approval,
            enforcement,
            spend_extractors,
            egress,
            action_labels,
            outbox,
            tenants,
        })
    }

    /// Create a default configuration
    pub fn default_config() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            policies: vec![],
            mcp: McpConfig::default(),
            approval: crate::approval::ApprovalConfig::default(),
            enforcement: EnforcementConfig::default(),
            spend_extractors: vec![],
            egress: vec![],
            action_labels: std::collections::HashMap::new(),
            outbox: crate::outbox::OutboxConfig::default(),
            tenants: std::collections::HashMap::new(),
        }
    }

    /// Get the default config file path
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vultrino")
            .join("config.toml")
    }

    /// Get the default storage path
    pub fn default_storage_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vultrino")
            .join("credentials.enc")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to
    pub bind: String,
    /// Server mode: "local" or "server"
    pub mode: ServerMode,
    /// TLS configuration (optional)
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7878".to_string(),
            mode: ServerMode::Local,
            tls: None,
        }
    }
}

/// Server operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMode {
    /// Local mode - single user, localhost only
    Local,
    /// Server mode - multi-user, network accessible
    Server,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackendType,
    /// Path for file storage
    pub file_path: Option<PathBuf>,
    /// Vault configuration
    pub vault: Option<VaultConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackendType::File,
            file_path: Some(Config::default_storage_path()),
            vault: None,
        }
    }
}

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendType {
    /// Encrypted file storage
    File,
    /// OS keychain (macOS Keychain, Windows Credential Manager)
    Keychain,
    /// HashiCorp Vault
    Vault,
}

/// HashiCorp Vault configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server address
    pub address: String,
    /// Authentication method
    pub auth_method: VaultAuthMethod,
}

/// Vault authentication method
#[derive(Debug, Clone)]
pub enum VaultAuthMethod {
    /// Token authentication
    Token(SecretString),
    /// AppRole authentication
    AppRole {
        role_id: String,
        secret_id: SecretString,
    },
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Format: "json" or "pretty"
    pub format: LogFormat,
    /// Path to audit log file
    pub audit_file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            audit_file: None,
        }
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable format
    Pretty,
    /// JSON format
    Json,
}

/// MCP server configuration
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Whether MCP server is enabled
    pub enabled: bool,
    /// Transport type
    pub transport: McpTransport,
    /// Unix socket path (for socket transport)
    pub socket_path: Option<PathBuf>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: McpTransport::Stdio,
            socket_path: None,
        }
    }
}

/// MCP transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    /// Standard input/output
    Stdio,
    /// Unix socket
    Socket,
}
