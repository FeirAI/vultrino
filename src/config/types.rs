//! Raw configuration types for TOML parsing

use super::*;
use crate::egress::EgressRule;
use crate::policy::{Policy, PolicyAction, PolicyCondition, PolicyRule, SpendExtractor};
use serde::Deserialize;

/// Raw configuration as parsed from TOML
#[derive(Debug, Deserialize)]
pub struct RawConfig {
    pub server: Option<RawServerConfig>,
    pub storage: Option<RawStorageConfig>,
    pub logging: Option<RawLoggingConfig>,
    pub mcp: Option<RawMcpConfig>,
    #[serde(default)]
    pub policies: Vec<RawPolicy>,
    pub approvals: Option<RawApprovalConfig>,
    pub enforcement: Option<RawEnforcementConfig>,
    /// Amount-extraction rules for SpendCap policies (V3).
    #[serde(default)]
    pub spend_extractors: Vec<RawSpendExtractor>,
    /// Egress classification rules (V7).
    #[serde(default)]
    pub egress: Vec<RawEgressRule>,
    /// govder action-label → canonical plugin.action mappings (V8).
    #[serde(default)]
    pub action_labels: Vec<RawActionLabel>,
}

/// Raw action-label mapping (V8): a govder business verb (e.g. "payments.refund")
/// that resolves to a canonical `plugin.action` (e.g. "http.request").
#[derive(Debug, Deserialize)]
pub struct RawActionLabel {
    pub label: String,
    pub action: String,
}

/// Raw egress classification rule (V7).
#[derive(Debug, Deserialize)]
pub struct RawEgressRule {
    pub credential_pattern: String,
    #[serde(default = "default_action_pattern")]
    pub action_pattern: String,
    /// Withhold the response body+headers entirely (secret-bearing endpoint).
    #[serde(default)]
    pub block: bool,
    /// Extra regexes to redact from the body when not blocked.
    #[serde(default)]
    pub redact_patterns: Vec<String>,
}

fn default_action_pattern() -> String {
    "*".to_string()
}

impl TryFrom<RawEgressRule> for EgressRule {
    type Error = ConfigError;

    fn try_from(raw: RawEgressRule) -> Result<Self, Self::Error> {
        // A rule that neither blocks nor redacts is a no-op — almost certainly a
        // mistake (an operator expecting it to do something).
        if !raw.block && raw.redact_patterns.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "egress rule for '{}' does nothing: set block = true or add redact_patterns",
                raw.credential_pattern
            )));
        }
        // Compile globs at load so a malformed pattern fails fast rather than
        // silently degrading to exact-match (a block rule that never matches
        // would be fail-open).
        let credential_pattern = glob::Pattern::new(&raw.credential_pattern).map_err(|e| {
            ConfigError::Invalid(format!(
                "invalid egress credential_pattern '{}': {}",
                raw.credential_pattern, e
            ))
        })?;
        let action_pattern = glob::Pattern::new(&raw.action_pattern).map_err(|e| {
            ConfigError::Invalid(format!(
                "invalid egress action_pattern '{}': {}",
                raw.action_pattern, e
            ))
        })?;
        let redact_patterns = raw
            .redact_patterns
            .iter()
            .map(|p| {
                regex::Regex::new(p).map_err(|e| {
                    ConfigError::Invalid(format!("invalid egress redact_pattern '{}': {}", p, e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            credential_pattern,
            action_pattern,
            block: raw.block,
            redact_patterns,
        })
    }
}

/// Raw amount-extraction rule (V3). Reads an amount (minor units, integer) from
/// a JSON pointer into the request params, plus an asset (literal or pointer).
#[derive(Debug, Deserialize)]
pub struct RawSpendExtractor {
    pub action_pattern: String,
    pub credential_pattern: String,
    pub amount_pointer: String,
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(default)]
    pub asset_pointer: Option<String>,
}

impl From<RawSpendExtractor> for SpendExtractor {
    fn from(raw: RawSpendExtractor) -> Self {
        Self {
            action_pattern: raw.action_pattern,
            credential_pattern: raw.credential_pattern,
            amount_pointer: raw.amount_pointer,
            asset: raw.asset,
            asset_pointer: raw.asset_pointer,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct RawEnforcementConfig {
    /// Engine decision for a credential that matches no policy: `deny`
    /// (fail-closed, default) or `allow` (fail-open, legacy).
    pub default_action: Option<String>,
}

impl TryFrom<RawEnforcementConfig> for EnforcementConfig {
    type Error = ConfigError;

    fn try_from(raw: RawEnforcementConfig) -> Result<Self, Self::Error> {
        let default_action = match raw.default_action.as_deref() {
            Some("deny") | None => EnforcementDefault::Deny,
            Some("allow") => EnforcementDefault::Allow,
            Some(other) => {
                return Err(ConfigError::Invalid(format!(
                    "Unknown enforcement default_action: {} (expected 'deny' or 'allow')",
                    other
                )))
            }
        };
        Ok(Self { default_action })
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct RawServerConfig {
    pub bind: Option<String>,
    pub mode: Option<String>,
    pub tls: Option<RawTlsConfig>,
}

impl From<RawServerConfig> for ServerConfig {
    fn from(raw: RawServerConfig) -> Self {
        Self {
            bind: raw.bind.unwrap_or_else(|| "127.0.0.1:7878".to_string()),
            mode: match raw.mode.as_deref() {
                Some("server") => ServerMode::Server,
                _ => ServerMode::Local,
            },
            tls: raw.tls.map(|t| TlsConfig {
                cert_path: PathBuf::from(t.cert_path),
                key_path: PathBuf::from(t.key_path),
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RawTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct RawStorageConfig {
    pub backend: Option<String>,
    pub file: Option<RawFileStorageConfig>,
    pub vault: Option<RawVaultConfig>,
}

impl TryFrom<RawStorageConfig> for StorageConfig {
    type Error = ConfigError;

    fn try_from(raw: RawStorageConfig) -> Result<Self, Self::Error> {
        let backend = match raw.backend.as_deref() {
            Some("file") | None => StorageBackendType::File,
            Some("keychain") => StorageBackendType::Keychain,
            Some("vault") => StorageBackendType::Vault,
            Some(other) => {
                return Err(ConfigError::Invalid(format!(
                    "Unknown storage backend: {}",
                    other
                )))
            }
        };

        let file_path = raw.file.and_then(|f| {
            f.path.map(|p| {
                // Expand ~ to home directory
                if let Some(rest) = p.strip_prefix("~/") {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(rest)
                } else {
                    PathBuf::from(p)
                }
            })
        });

        let vault = raw.vault.map(|v| VaultConfig {
            address: v.address,
            auth_method: match v.auth_method.as_deref() {
                Some("token") => VaultAuthMethod::Token(secrecy::SecretString::from(
                    v.token.unwrap_or_default(),
                )),
                _ => VaultAuthMethod::AppRole {
                    role_id: v.role_id.unwrap_or_default(),
                    secret_id: secrecy::SecretString::from(v.secret_id.unwrap_or_default()),
                },
            },
        });

        Ok(Self {
            backend,
            file_path,
            vault,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RawFileStorageConfig {
    pub path: Option<String>,
    pub key_derivation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawVaultConfig {
    pub address: String,
    pub auth_method: Option<String>,
    pub token: Option<String>,
    pub role_id: Option<String>,
    pub secret_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RawLoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub audit_file: Option<String>,
}

impl From<RawLoggingConfig> for LoggingConfig {
    fn from(raw: RawLoggingConfig) -> Self {
        Self {
            level: raw.level.unwrap_or_else(|| "info".to_string()),
            format: match raw.format.as_deref() {
                Some("json") => LogFormat::Json,
                _ => LogFormat::Pretty,
            },
            audit_file: raw.audit_file.map(|p| {
                if let Some(rest) = p.strip_prefix("~/") {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(rest)
                } else {
                    PathBuf::from(p)
                }
            }),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct RawMcpConfig {
    pub enabled: Option<bool>,
    pub transport: Option<String>,
    pub socket_path: Option<String>,
}

impl From<RawMcpConfig> for McpConfig {
    fn from(raw: RawMcpConfig) -> Self {
        Self {
            enabled: raw.enabled.unwrap_or(true),
            transport: match raw.transport.as_deref() {
                Some("socket") => McpTransport::Socket,
                _ => McpTransport::Stdio,
            },
            socket_path: raw.socket_path.map(PathBuf::from),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct RawApprovalConfig {
    pub enabled: Option<bool>,
    pub ttl_secs: Option<u64>,
    pub public_base_url: Option<String>,
    pub telegram: Option<RawTelegramConfig>,
    pub webhook: Option<RawWebhookConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RawTelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RawWebhookConfig {
    pub url: String,
    pub auth_header: Option<String>,
}

impl From<RawApprovalConfig> for crate::approval::ApprovalConfig {
    fn from(raw: RawApprovalConfig) -> Self {
        // A telegram/webhook section being present implies approvals are enabled
        // unless explicitly disabled.
        let has_channel = raw.telegram.is_some() || raw.webhook.is_some();
        Self {
            enabled: raw.enabled.unwrap_or(has_channel),
            ttl_secs: raw.ttl_secs.unwrap_or(3600),
            public_base_url: raw.public_base_url,
            telegram: raw.telegram.map(|t| crate::approval::TelegramConfig {
                bot_token: t.bot_token,
                chat_id: t.chat_id,
            }),
            webhook: raw.webhook.map(|w| crate::approval::WebhookConfig {
                url: w.url,
                auth_header: w.auth_header,
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RawPolicy {
    pub name: String,
    pub credential_pattern: String,
    /// Optional glob over the presenting principal (V4).
    #[serde(default)]
    pub principal_pattern: Option<String>,
    #[serde(default)]
    pub rules: Vec<RawPolicyRule>,
    pub default_action: Option<String>,
}

impl TryFrom<RawPolicy> for Policy {
    type Error = ConfigError;

    fn try_from(raw: RawPolicy) -> Result<Self, Self::Error> {
        let rules = raw
            .rules
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let default_action = match raw.default_action.as_deref() {
            Some("allow") => PolicyAction::Allow,
            Some("deny") | None => PolicyAction::Deny,
            Some("prompt") => PolicyAction::Prompt,
            Some(other) => {
                return Err(ConfigError::Invalid(format!(
                    "Unknown policy action: {}",
                    other
                )))
            }
        };

        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: raw.name,
            credential_pattern: raw.credential_pattern,
            principal_pattern: raw.principal_pattern,
            rules,
            default_action,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RawPolicyRule {
    pub condition: RawPolicyCondition,
    pub action: String,
}

impl TryFrom<RawPolicyRule> for PolicyRule {
    type Error = ConfigError;

    fn try_from(raw: RawPolicyRule) -> Result<Self, Self::Error> {
        let condition = raw.condition.try_into()?;
        let action = match raw.action.as_str() {
            "allow" => PolicyAction::Allow,
            "deny" => PolicyAction::Deny,
            "prompt" => PolicyAction::Prompt,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "Unknown policy action: {}",
                    other
                )))
            }
        };

        Ok(Self { condition, action })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawPolicyCondition {
    UrlMatch {
        url_match: String,
    },
    MethodMatch {
        method_match: Vec<String>,
    },
    RateLimit {
        rate_limit: RawRateLimit,
    },
    SpendCap {
        spend_cap: RawSpendCap,
    },
    And {
        and: Vec<RawPolicyCondition>,
    },
    Or {
        or: Vec<RawPolicyCondition>,
    },
}

#[derive(Debug, Deserialize)]
pub struct RawRateLimit {
    pub max: u32,
    pub window_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct RawSpendCap {
    pub asset: String,
    #[serde(default)]
    pub per_action_max: Option<u64>,
    #[serde(default)]
    pub cumulative_max: Option<u64>,
    pub window_secs: u64,
}

impl TryFrom<RawPolicyCondition> for PolicyCondition {
    type Error = ConfigError;

    fn try_from(raw: RawPolicyCondition) -> Result<Self, Self::Error> {
        match raw {
            RawPolicyCondition::UrlMatch { url_match } => Ok(PolicyCondition::UrlMatch(url_match)),
            RawPolicyCondition::MethodMatch { method_match } => {
                Ok(PolicyCondition::MethodMatch(method_match))
            }
            RawPolicyCondition::RateLimit { rate_limit } => Ok(PolicyCondition::RateLimit {
                max: rate_limit.max,
                window_secs: rate_limit.window_secs,
            }),
            RawPolicyCondition::SpendCap { spend_cap } => Ok(PolicyCondition::SpendCap {
                asset: spend_cap.asset,
                per_action_max: spend_cap.per_action_max,
                cumulative_max: spend_cap.cumulative_max,
                window_secs: spend_cap.window_secs,
            }),
            RawPolicyCondition::And { and } => {
                let conditions = and
                    .into_iter()
                    .map(|c| c.try_into())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyCondition::And(conditions))
            }
            RawPolicyCondition::Or { or } => {
                let conditions = or
                    .into_iter()
                    .map(|c| c.try_into())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyCondition::Or(conditions))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
[server]
bind = "127.0.0.1:7878"
mode = "local"

[storage]
backend = "file"

[storage.file]
path = "~/.vultrino/credentials.enc"

[logging]
level = "info"
audit_file = "~/.vultrino/audit.log"

[[policies]]
name = "github-readonly"
credential_pattern = "github-*"
default_action = "deny"

[[policies.rules]]
condition = { url_match = "https://api.github.com/*" }
action = "allow"

[[policies.rules]]
condition = { method_match = ["POST", "PUT", "DELETE"] }
action = "deny"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:7878");
        assert_eq!(config.server.mode, ServerMode::Local);
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].name, "github-readonly");
        assert_eq!(config.policies[0].rules.len(), 2);
    }

    #[test]
    fn test_minimal_config() {
        let toml = "";
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:7878");
    }

    #[test]
    fn test_enforcement_default_is_deny_when_omitted() {
        // Fail-closed is the built-in default when no [enforcement] section.
        let config = Config::parse("").unwrap();
        assert_eq!(config.enforcement.default_action, EnforcementDefault::Deny);
    }

    #[test]
    fn test_enforcement_parses_allow_and_deny() {
        let allow = Config::parse("[enforcement]\ndefault_action = \"allow\"").unwrap();
        assert_eq!(allow.enforcement.default_action, EnforcementDefault::Allow);
        let deny = Config::parse("[enforcement]\ndefault_action = \"deny\"").unwrap();
        assert_eq!(deny.enforcement.default_action, EnforcementDefault::Deny);
        // Section present but key omitted → deny.
        let bare = Config::parse("[enforcement]").unwrap();
        assert_eq!(bare.enforcement.default_action, EnforcementDefault::Deny);
    }

    #[test]
    fn test_action_label_resolution() {
        let cfg = Config::parse(
            "[[action_labels]]\nlabel = \"payments.refund\"\naction = \"http.request\"",
        )
        .unwrap();
        assert_eq!(
            cfg.resolve_action("payments.refund"),
            ("http.request".to_string(), Some("payments.refund".to_string()))
        );
        // A canonical (non-label) action passes through unchanged.
        assert_eq!(
            cfg.resolve_action("postgres.run_sql"),
            ("postgres.run_sql".to_string(), None)
        );
    }

    #[test]
    fn test_egress_rule_validation() {
        // A no-op rule (neither blocks nor redacts) is rejected.
        assert!(Config::parse("[[egress]]\ncredential_pattern = \"x\"").is_err());
        // A malformed glob fails at load (no silent degrade to exact-match).
        assert!(Config::parse("[[egress]]\ncredential_pattern = \"[unclosed\"\nblock = true").is_err());
        assert!(Config::parse("[[egress]]\ncredential_pattern = \"sts-*\"\naction_pattern = \"[bad\"\nblock = true").is_err());
        // A bad redact regex fails at load.
        assert!(Config::parse("[[egress]]\ncredential_pattern = \"*\"\nredact_patterns = [\"(unclosed\"]").is_err());
        // A valid block rule parses.
        assert!(Config::parse("[[egress]]\ncredential_pattern = \"sts-*\"\nblock = true").is_ok());
    }

    #[test]
    fn test_enforcement_invalid_action_is_hard_error() {
        // Unknown value errors rather than silently falling back. Config enums
        // are lowercase-exact across vultrino, so wrong case also errors.
        assert!(Config::parse("[enforcement]\ndefault_action = \"permit\"").is_err());
        assert!(Config::parse("[enforcement]\ndefault_action = \"Deny\"").is_err());
    }
}
