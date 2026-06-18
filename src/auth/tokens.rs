//! Use tokens — narrow, ephemeral grants for AI agents.
//!
//! Where an [`ApiKey`](super::types::ApiKey) is a long-lived credential tied to a
//! role, a **use token** is a single-purpose grant: it authorizes *one specific
//! kind of action* against *one credential (or glob of credentials)*, optionally
//! limited to a fixed number of uses and/or a time window.
//!
//! This lets you hand an agent exactly enough authority to, say, "POST to the
//! deploy webhook once, in the next 10 minutes" without minting a durable key.
//!
//! Tokens are presented in the same place an API key is (the `api_key`
//! argument of an MCP tool, or the `Authorization: Bearer` header) and are
//! distinguished by their `vut_` prefix (**v**ultrino **u**se **t**oken).
//!
//! Consumption is **fail-closed / reserve-on-execute**: the use is counted the
//! moment the action runs, even if the downstream call errors, so a token can
//! never drive more than `max_uses` executions. The atomic check-and-increment
//! lives in the storage backend (`consume_use_token`) so a single-use token is
//! safe against concurrent calls within a process.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prefix that identifies a use token (vs. an `vk_` API key).
pub const USE_TOKEN_PREFIX: &str = "vut_";

/// Length of the random portion of a use token.
const TOKEN_RANDOM_LENGTH: usize = 32;

/// A narrow, ephemeral grant authorizing a specific action on a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseToken {
    /// Unique identifier (for storage / management). Format: `ut_<uuid>`.
    pub id: String,
    /// Display prefix (`vut_xxxxxxxx`), safe to show in listings.
    pub token_prefix: String,
    /// SHA-256 hash of the full token (the plaintext is shown only once).
    pub token_hash: String,
    /// Human-readable label.
    pub name: String,
    /// Credential alias or glob pattern this token may act on (e.g. `github-*`).
    /// `*` allows any credential.
    pub credential_scope: String,
    /// Optional action restriction. `None` allows any action; otherwise an exact
    /// action (`http.request`) or a `plugin.*` / `plugin.action` glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_scope: Option<String>,
    /// Maximum number of times this token may drive an execution.
    /// `None` = unlimited within the time window; `Some(1)` = single-use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// How many uses have been consumed so far.
    #[serde(default)]
    pub uses: u32,
    /// If true, every action driven by this token requires human approval
    /// before it executes (see the `approval` module).
    #[serde(default)]
    pub require_approval: bool,
    /// Optional expiry. `None` = never expires (only `max_uses` bounds it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
    /// When the token was last used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether the token has been manually revoked.
    #[serde(default)]
    pub revoked: bool,
}

/// Why a use token is not currently usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseTokenInvalid {
    /// The token was revoked by an administrator.
    Revoked,
    /// The token's time window has passed.
    Expired,
    /// The token has been used the maximum number of times.
    Exhausted,
}

impl std::fmt::Display for UseTokenInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UseTokenInvalid::Revoked => write!(f, "use token has been revoked"),
            UseTokenInvalid::Expired => write!(f, "use token has expired"),
            UseTokenInvalid::Exhausted => write!(f, "use token has no remaining uses"),
        }
    }
}

/// Parameters for minting a new use token.
#[derive(Debug, Clone)]
pub struct NewUseToken {
    pub name: String,
    pub credential_scope: String,
    pub action_scope: Option<String>,
    pub max_uses: Option<u32>,
    pub require_approval: bool,
    pub expires_in: Option<Duration>,
}

impl NewUseToken {
    /// Validate the parameters before minting, so footguns fail loudly at
    /// creation rather than producing a silently-useless token:
    /// - an empty credential scope (use `*` for "any"),
    /// - `max_uses == 0` (immediately exhausted),
    /// - a scope glob that does not compile (which would otherwise silently
    ///   degrade to exact-string match and never match anything).
    pub fn validate(&self) -> Result<(), String> {
        if self.credential_scope.trim().is_empty() {
            return Err("credential scope must not be empty (use '*' for any credential)".to_string());
        }
        if self.max_uses == Some(0) {
            return Err("max uses must be at least 1".to_string());
        }
        if matches!(self.expires_in, Some(d) if d <= Duration::zero()) {
            return Err("expiry must be positive (a non-positive lifetime would mint an already-expired token)".to_string());
        }
        glob::Pattern::new(&self.credential_scope).map_err(|e| {
            format!("invalid credential scope pattern '{}': {}", self.credential_scope, e)
        })?;
        if let Some(action) = &self.action_scope {
            glob::Pattern::new(action)
                .map_err(|e| format!("invalid action scope pattern '{}': {}", action, e))?;
        }
        Ok(())
    }
}

impl UseToken {
    /// Mint a new use token, returning the plaintext token (shown once) and the
    /// stored record. The plaintext never touches disk — only its hash is kept.
    pub fn create(params: NewUseToken) -> (String, UseToken) {
        let (full_token, prefix) = generate_token();
        let token_hash = hash_token(&full_token);
        let now = Utc::now();

        let token = UseToken {
            id: format!("ut_{}", uuid::Uuid::new_v4()),
            token_prefix: prefix,
            token_hash,
            name: params.name,
            credential_scope: params.credential_scope,
            action_scope: params.action_scope,
            max_uses: params.max_uses,
            uses: 0,
            require_approval: params.require_approval,
            expires_at: params.expires_in.map(|d| now + d),
            created_at: now,
            last_used_at: None,
            revoked: false,
        };

        (full_token, token)
    }

    /// Hash a presented plaintext token for lookup/comparison.
    pub fn hash(token: &str) -> String {
        hash_token(token)
    }

    /// Whether `token` looks like a use token (correct prefix).
    pub fn looks_like_token(token: &str) -> bool {
        token.starts_with(USE_TOKEN_PREFIX)
    }

    /// Number of uses still available, if bounded.
    pub fn remaining_uses(&self) -> Option<u32> {
        self.max_uses.map(|m| m.saturating_sub(self.uses))
    }

    /// True once the use count has reached `max_uses`.
    pub fn is_exhausted(&self) -> bool {
        matches!(self.max_uses, Some(max) if self.uses >= max)
    }

    /// True once the token's time window has passed.
    pub fn is_expired(&self) -> bool {
        matches!(self.expires_at, Some(exp) if Utc::now() >= exp)
    }

    /// Validate the token for use right now, surfacing the specific reason it is
    /// not usable. A return of `Ok(())` means the token may currently drive an
    /// execution (the use is reserved atomically at execution time).
    pub fn check_usable(&self) -> Result<(), UseTokenInvalid> {
        if self.revoked {
            return Err(UseTokenInvalid::Revoked);
        }
        if self.is_expired() {
            return Err(UseTokenInvalid::Expired);
        }
        if self.is_exhausted() {
            return Err(UseTokenInvalid::Exhausted);
        }
        Ok(())
    }

    /// Whether this token is allowed to act on the given credential alias.
    pub fn allows_credential(&self, alias: &str) -> bool {
        pattern_matches(&self.credential_scope, alias)
    }

    /// Whether this token is allowed to perform the given fully-qualified action
    /// (`plugin.action`, e.g. `http.request`). `None` action_scope allows all.
    pub fn allows_action(&self, action: &str) -> bool {
        match &self.action_scope {
            None => true,
            Some(scope) => pattern_matches(scope, action),
        }
    }
}

/// Metadata view of a use token (never includes the hash), safe for listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseTokenMetadata {
    pub id: String,
    pub token_prefix: String,
    pub name: String,
    pub credential_scope: String,
    pub action_scope: Option<String>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub remaining_uses: Option<u32>,
    pub require_approval: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

impl From<&UseToken> for UseTokenMetadata {
    fn from(t: &UseToken) -> Self {
        Self {
            id: t.id.clone(),
            token_prefix: t.token_prefix.clone(),
            name: t.name.clone(),
            credential_scope: t.credential_scope.clone(),
            action_scope: t.action_scope.clone(),
            max_uses: t.max_uses,
            uses: t.uses,
            remaining_uses: t.remaining_uses(),
            require_approval: t.require_approval,
            expires_at: t.expires_at,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            revoked: t.revoked,
        }
    }
}

/// Generate a `(full_token, display_prefix)` pair.
fn generate_token() -> (String, String) {
    let mut random_bytes = [0u8; TOKEN_RANDOM_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let random_part: String = STANDARD
        .encode(random_bytes)
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(TOKEN_RANDOM_LENGTH)
        .collect();

    let full = format!("{}{}", USE_TOKEN_PREFIX, random_part);
    let prefix = format!("{}{}", USE_TOKEN_PREFIX, &random_part[..8]);
    (full, prefix)
}

/// SHA-256 of a token, base64-encoded (mirrors API-key hashing).
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    STANDARD.encode(hasher.finalize())
}

/// Glob-style match used for both credential and action scopes.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Ok(glob) = glob::Pattern::new(pattern) {
        glob.matches(value)
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(params: NewUseToken) -> UseToken {
        UseToken::create(params).1
    }

    #[test]
    fn test_create_token_shape() {
        let (full, t) = UseToken::create(NewUseToken {
            name: "deploy-once".to_string(),
            credential_scope: "deploy-*".to_string(),
            action_scope: Some("ssh.deploy".to_string()),
            max_uses: Some(1),
            require_approval: false,
            expires_in: Some(Duration::minutes(10)),
        });

        assert!(full.starts_with("vut_"));
        assert!(t.token_prefix.starts_with("vut_"));
        assert_eq!(UseToken::hash(&full), t.token_hash);
        assert_eq!(t.uses, 0);
        assert_eq!(t.remaining_uses(), Some(1));
        assert!(!t.is_exhausted());
        assert!(!t.is_expired());
    }

    #[test]
    fn test_scope_matching() {
        let t = token(NewUseToken {
            name: "scoped".to_string(),
            credential_scope: "github-*".to_string(),
            action_scope: Some("http.request".to_string()),
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });

        assert!(t.allows_credential("github-api"));
        assert!(!t.allows_credential("aws-prod"));
        assert!(t.allows_action("http.request"));
        assert!(!t.allows_action("postgres.run_sql"));
    }

    #[test]
    fn test_action_glob_and_any() {
        let glob = token(NewUseToken {
            name: "pg".to_string(),
            credential_scope: "*".to_string(),
            action_scope: Some("postgres.*".to_string()),
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });
        assert!(glob.allows_action("postgres.run_sql"));
        assert!(glob.allows_action("postgres.backup"));
        assert!(!glob.allows_action("http.request"));
        assert!(glob.allows_credential("anything"));

        let any = token(NewUseToken {
            name: "any".to_string(),
            credential_scope: "*".to_string(),
            action_scope: None,
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });
        assert!(any.allows_action("anything.at_all"));
    }

    #[test]
    fn test_check_usable_states() {
        let mut t = token(NewUseToken {
            name: "single".to_string(),
            credential_scope: "*".to_string(),
            action_scope: None,
            max_uses: Some(1),
            require_approval: false,
            expires_in: None,
        });
        assert!(t.check_usable().is_ok());

        t.uses = 1;
        assert_eq!(t.check_usable(), Err(UseTokenInvalid::Exhausted));
        assert!(t.is_exhausted());

        t.uses = 0;
        t.revoked = true;
        assert_eq!(t.check_usable(), Err(UseTokenInvalid::Revoked));

        t.revoked = false;
        t.expires_at = Some(Utc::now() - Duration::hours(1));
        assert_eq!(t.check_usable(), Err(UseTokenInvalid::Expired));
    }

    #[test]
    fn test_looks_like_token() {
        assert!(UseToken::looks_like_token("vut_abc123"));
        assert!(!UseToken::looks_like_token("vk_abc123"));
    }
}
