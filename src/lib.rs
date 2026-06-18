//! Vultrino - A credential proxy for the AI era
//!
//! Vultrino enables AI agents to use credentials without seeing them.
//! It acts as a secure proxy that injects authentication into requests
//! while keeping the actual credentials hidden from the AI.

pub mod approval;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod egress;
pub mod mcp;
pub mod plugins;
pub mod policy;
pub mod router;
pub mod server;
pub mod storage;
pub mod web;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

/// Core error types for Vultrino
#[derive(Error, Debug)]
pub enum VultrinoError {
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("Plugin error: {0}")]
    Plugin(#[from] plugins::PluginError),

    #[error("Policy error: {0}")]
    Policy(#[from] policy::PolicyError),

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Request denied by policy: {0}")]
    PolicyDenied(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// The type of credential stored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Simple API key (e.g., `Authorization: Bearer xxx`)
    ApiKey,
    /// OAuth2 credentials with token refresh
    OAuth2,
    /// HTTP Basic Authentication
    BasicAuth,
    /// Private key for signing (SSH, crypto)
    PrivateKey,
    /// Certificate for mTLS
    Certificate,
    /// HMAC-signed API key (e.g., Binance, AsterDex)
    HmacApiKey,
    /// ECDSA private key for signing (e.g., Ethereum, Hyperliquid)
    EcdsaKey,
    /// SSH connection with password authentication
    SshPassword,
    /// PostgreSQL connection credentials
    Postgres,
    /// Custom credential type
    Custom(String),
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::ApiKey => write!(f, "api_key"),
            CredentialType::OAuth2 => write!(f, "oauth2"),
            CredentialType::BasicAuth => write!(f, "basic_auth"),
            CredentialType::PrivateKey => write!(f, "private_key"),
            CredentialType::Certificate => write!(f, "certificate"),
            CredentialType::HmacApiKey => write!(f, "hmac_api_key"),
            CredentialType::EcdsaKey => write!(f, "ecdsa_key"),
            CredentialType::SshPassword => write!(f, "ssh_password"),
            CredentialType::Postgres => write!(f, "postgres"),
            CredentialType::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// A serializable secret string wrapper
#[derive(Debug, Clone)]
pub struct Secret(SecretString);

impl Secret {
    /// Create a new secret from a string
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// Expose the secret value
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Get the inner SecretString
    pub fn inner(&self) -> &SecretString {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.expose_secret().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

/// The actual credential data (encrypted at rest)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialData {
    /// API key authentication
    ApiKey {
        /// The API key value
        key: Secret,
        /// Header name to use (default: "Authorization")
        #[serde(default = "default_auth_header")]
        header_name: String,
        /// Header value prefix (default: "Bearer ")
        #[serde(default = "default_bearer_prefix")]
        header_prefix: String,
    },

    /// OAuth2 credentials
    OAuth2 {
        client_id: String,
        client_secret: Secret,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<Secret>,
        #[serde(skip_serializing_if = "Option::is_none")]
        access_token: Option<Secret>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        token_url: String,
        /// OAuth2 scopes for token requests
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
    },

    /// HTTP Basic Authentication
    BasicAuth {
        username: String,
        password: Secret,
    },

    /// Private key for signing operations
    PrivateKey {
        key_pem: Secret,
        #[serde(skip_serializing_if = "Option::is_none")]
        passphrase: Option<Secret>,
    },

    /// Certificate for mTLS
    Certificate {
        cert_pem: String,
        key_pem: Secret,
    },

    /// HMAC-signed API key (e.g., Binance, AsterDex)
    HmacApiKey {
        /// API key (sent in header)
        api_key: String,
        /// API secret (used for HMAC signing)
        api_secret: Secret,
        /// Header name for API key (default: "X-MBX-APIKEY")
        #[serde(default = "default_hmac_header")]
        header_name: String,
        /// Receive window in milliseconds (default: 5000)
        #[serde(default = "default_recv_window")]
        recv_window: u64,
    },

    /// ECDSA private key for signing (e.g., Ethereum, Hyperliquid)
    EcdsaKey {
        /// Private key in hex (with/without 0x prefix)
        private_key: Secret,
        /// Optional main wallet address (for agent wallet model)
        #[serde(skip_serializing_if = "Option::is_none")]
        api_address: Option<String>,
        /// Use testnet endpoints
        #[serde(default)]
        testnet: bool,
    },

    /// SSH connection with password authentication
    SshPassword {
        /// Hostname or IP address of the SSH server
        host: String,
        /// SSH port (default: 22)
        #[serde(default = "default_ssh_port")]
        port: u16,
        /// SSH username
        user: String,
        /// SSH password (required by sshpass)
        password: Secret,
    },

    /// PostgreSQL connection credentials
    Postgres {
        /// Hostname or IP address of the Postgres server
        host: String,
        /// Postgres port (default: 5432)
        #[serde(default = "default_postgres_port")]
        port: u16,
        /// Database name
        database: String,
        /// Postgres role / username
        user: String,
        /// Database password (passed to psql/pg_dump via PGPASSWORD env)
        password: Secret,
        /// libpq sslmode: disable, allow, prefer (default), require, verify-ca, verify-full
        #[serde(default = "default_postgres_sslmode")]
        sslmode: String,
    },

    /// Custom credential data
    Custom(HashMap<String, Secret>),
}

fn default_auth_header() -> String {
    "Authorization".to_string()
}

fn default_bearer_prefix() -> String {
    "Bearer ".to_string()
}

fn default_hmac_header() -> String {
    "X-MBX-APIKEY".to_string()
}

fn default_recv_window() -> u64 {
    5000
}

fn default_ssh_port() -> u16 {
    22
}

fn default_postgres_port() -> u16 {
    5432
}

fn default_postgres_sslmode() -> String {
    "prefer".to_string()
}

impl CredentialData {
    /// The exposed secret strings this credential injects or uses, for **egress
    /// redaction** (V7): if a proxied endpoint reflects the credential's own
    /// secret back in its response, the server scrubs these before returning the
    /// body to the agent — the read-back defense (REVIEW H2/F2). Includes derived
    /// forms (e.g. the base64 the http plugin sends for basic auth).
    pub fn secret_material(&self) -> Vec<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        match self {
            CredentialData::ApiKey { key, .. } => vec![key.expose().to_string()],
            CredentialData::BasicAuth { username, password } => {
                let raw = format!("{}:{}", username, password.expose());
                vec![password.expose().to_string(), STANDARD.encode(raw.as_bytes())]
            }
            CredentialData::OAuth2 {
                client_secret,
                refresh_token,
                access_token,
                ..
            } => {
                let mut v = vec![client_secret.expose().to_string()];
                if let Some(t) = access_token {
                    v.push(t.expose().to_string());
                }
                if let Some(r) = refresh_token {
                    v.push(r.expose().to_string());
                }
                v
            }
            CredentialData::HmacApiKey { api_secret, .. } => vec![api_secret.expose().to_string()],
            CredentialData::EcdsaKey { private_key, .. } => vec![private_key.expose().to_string()],
            CredentialData::SshPassword { password, .. } => vec![password.expose().to_string()],
            CredentialData::Postgres { password, .. } => vec![password.expose().to_string()],
            CredentialData::PrivateKey { key_pem, passphrase } => {
                let mut v = vec![key_pem.expose().to_string()];
                if let Some(p) = passphrase {
                    v.push(p.expose().to_string());
                }
                v
            }
            CredentialData::Certificate { key_pem, .. } => vec![key_pem.expose().to_string()],
            CredentialData::Custom(map) => map.values().map(|s| s.expose().to_string()).collect(),
        }
    }

    /// Get the credential type for this data
    pub fn credential_type(&self) -> CredentialType {
        match self {
            CredentialData::ApiKey { .. } => CredentialType::ApiKey,
            CredentialData::OAuth2 { .. } => CredentialType::OAuth2,
            CredentialData::BasicAuth { .. } => CredentialType::BasicAuth,
            CredentialData::PrivateKey { .. } => CredentialType::PrivateKey,
            CredentialData::Certificate { .. } => CredentialType::Certificate,
            CredentialData::HmacApiKey { .. } => CredentialType::HmacApiKey,
            CredentialData::EcdsaKey { .. } => CredentialType::EcdsaKey,
            CredentialData::SshPassword { .. } => CredentialType::SshPassword,
            CredentialData::Postgres { .. } => CredentialType::Postgres,
            CredentialData::Custom(_) => CredentialType::Custom("custom".to_string()),
        }
    }
}

/// A stored credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Unique identifier
    pub id: String,
    /// Human-readable alias (e.g., "github-api")
    pub alias: String,
    /// Type of credential
    pub credential_type: CredentialType,
    /// The actual credential data
    pub data: CredentialData,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// When the credential was created
    pub created_at: DateTime<Utc>,
    /// When the credential was last updated
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    /// Create a new credential with generated ID and timestamps
    pub fn new(alias: String, data: CredentialData) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            alias,
            credential_type: data.credential_type(),
            data,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add metadata to the credential
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Credential metadata (without sensitive data) for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub alias: String,
    pub credential_type: CredentialType,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Credential> for CredentialMetadata {
    fn from(cred: &Credential) -> Self {
        Self {
            id: cred.id.clone(),
            alias: cred.alias.clone(),
            credential_type: cred.credential_type.clone(),
            metadata: cred.metadata.clone(),
            created_at: cred.created_at,
            updated_at: cred.updated_at,
        }
    }
}

/// Context for a request being processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Unique request identifier
    pub request_id: String,
    /// When the request was received
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// User agent string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// API key ID (if authenticated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
    /// API key name (if authenticated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_name: Option<String>,
    /// Role name (if authenticated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    /// Agent label bound to the presenting key/token (V4), for principal_pattern
    /// matching via the legacy `evaluate` path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
}

impl RequestContext {
    /// Create a new request context with generated ID
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_ip: None,
            user_agent: None,
            api_key_id: None,
            api_key_name: None,
            role_name: None,
            agent_label: None,
        }
    }

    /// Set authentication info from an auth result
    pub fn with_auth(mut self, auth: &auth::AuthResult) -> Self {
        self.api_key_id = Some(auth.api_key.id.clone());
        self.api_key_name = Some(auth.api_key.name.clone());
        self.role_name = Some(auth.role.name.clone());
        self.agent_label = auth.api_key.agent_label.clone();
        self
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to execute a plugin action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// Credential alias or ID
    pub credential: String,
    /// Action to perform (e.g., "http.request", "crypto.sign")
    pub action: String,
    /// Action-specific parameters
    pub params: serde_json::Value,
}

/// Response from executing a plugin action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// HTTP status code (or equivalent)
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    /// Updated credential data (e.g., after OAuth2 token refresh)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_credential: Option<CredentialData>,
}

impl ExecuteResponse {
    /// Create a success response
    pub fn success(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body: body.into(),
            updated_credential: None,
        }
    }

    /// Create an error response
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: message.into().into_bytes(),
            updated_credential: None,
        }
    }

    /// Set updated credential data
    pub fn with_updated_credential(mut self, credential: CredentialData) -> Self {
        self.updated_credential = Some(credential);
        self
    }
}

/// Outcome of a (possibly approval-gated) execution.
///
/// Most callers run an action and get a [`ExecuteResponse`] back. But when an
/// action requires human approval, the action does *not* run yet — the caller
/// receives a [`ExecutionOutcome::Pending`] carrying the open
/// [`approval::ApprovalRequest`] so it can tell the agent how to check back.
// `Completed` is the hot path and is kept inline; `Pending` (the rare gated
// path) is boxed so it doesn't bloat the enum. The residual size gap between the
// inline `Completed` and the boxed pointer is intentional.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ExecutionOutcome {
    /// The action ran and produced a response.
    Completed(ExecuteResponse),
    /// The action is gated on human approval; nothing has run yet.
    /// Boxed because an `ApprovalRequest` is much larger than `ExecuteResponse`.
    Pending(Box<approval::ApprovalRequest>),
}

impl ExecutionOutcome {
    /// Collapse to an [`ExecuteResponse`], rendering a `Pending` outcome as a
    /// `202 Accepted` body describing the open approval (so callers that only
    /// understand responses still surface the pending state to the agent).
    pub fn into_response(self) -> ExecuteResponse {
        match self {
            ExecutionOutcome::Completed(resp) => resp,
            ExecutionOutcome::Pending(approval) => {
                let body = serde_json::json!({
                    "outcome": "pending_approval",
                    "approval_id": approval.id,
                    "message": format!(
                        "This action requires human approval before it runs. It has NOT executed. \
                         To get the result, poll this approval by its approval_id '{id}' — \
                         e.g. `vultrino approval status {id}` (CLI), the `check_approval` tool (MCP), \
                         or GET /api/v1/approvals/{id} (HTTP API). It stays pending until approved \
                         or it expires at {expires}.",
                        id = approval.id,
                        expires = approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
                    ),
                    "summary": approval.summary,
                    "expires_at": approval.expires_at,
                });
                ExecuteResponse {
                    status: 202,
                    headers: HashMap::new(),
                    body: serde_json::to_vec(&body).unwrap_or_default(),
                    updated_credential: None,
                }
            }
        }
    }
}

/// Helper module for base64 encoding of bytes in serde
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_creation() {
        let cred = Credential::new(
            "test-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("secret-key"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );

        assert_eq!(cred.alias, "test-api");
        assert_eq!(cred.credential_type, CredentialType::ApiKey);
        assert!(!cred.id.is_empty());
    }

    #[test]
    fn test_credential_metadata() {
        let cred = Credential::new(
            "test".to_string(),
            CredentialData::BasicAuth {
                username: "user".to_string(),
                password: Secret::new("pass"),
            },
        )
        .with_metadata("description", "Test credential");

        let meta = CredentialMetadata::from(&cred);
        assert_eq!(meta.alias, "test");
        assert_eq!(meta.metadata.get("description"), Some(&"Test credential".to_string()));
    }

    #[test]
    fn test_secret_serialization() {
        let cred = CredentialData::ApiKey {
            key: Secret::new("my-secret-key"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        };

        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("my-secret-key")); // Serialized for storage

        let parsed: CredentialData = serde_json::from_str(&json).unwrap();
        if let CredentialData::ApiKey { key, .. } = parsed {
            assert_eq!(key.expose(), "my-secret-key");
        } else {
            panic!("Wrong variant");
        }
    }
}
