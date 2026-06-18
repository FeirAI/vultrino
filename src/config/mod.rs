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
        let approval = raw.approvals.map(Into::into).unwrap_or_default();
        let enforcement = raw
            .enforcement
            .map(EnforcementConfig::try_from)
            .transpose()?
            .unwrap_or_default();

        let policies = raw
            .policies
            .into_iter()
            .map(|p| p.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            server,
            storage,
            logging,
            policies,
            mcp,
            approval,
            enforcement,
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
