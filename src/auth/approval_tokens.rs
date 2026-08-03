//! Approval tokens — narrow grants for delegate agents to decide approvals.
//!
//! Where a [`UseToken`](super::tokens::UseToken) authorizes credential actions,
//! an **approval token** authorizes a delegate agent to approve or deny a pending
//! approval on behalf of a human delegator. Tokens are presented as
//! `Authorization: Bearer vap_…` on the delegate-decision API and are
//! distinguished by their `vap_` prefix (**v**ultrino **ap**proval token).

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::delegation::DelegationGrantScope;

/// Prefix that identifies an approval token (vs. `vk_` API keys or `vut_` use tokens).
pub const APPROVAL_TOKEN_PREFIX: &str = "vap_";

/// Length of the random portion of an approval token.
const TOKEN_RANDOM_LENGTH: usize = 32;

/// A narrow grant authorizing a delegate agent to decide approvals under a
/// delegation grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Unique identifier (for storage / management). Format: `apt_<uuid>`.
    pub id: String,
    /// Display prefix (`vap_xxxxxxxx`), safe to show in listings.
    pub token_prefix: String,
    /// SHA-256 hash of the full token (the plaintext is shown only once).
    pub token_hash: String,
    /// Govder DelegationGrant id this token is bound to.
    pub delegation_grant_ref: String,
    /// Snapshot of grant caps consulted at delegate decide (plan 031 D3).
    #[serde(default)]
    pub grant_scope: DelegationGrantScope,
    /// Delegate agent label (V4), for audit and SoD attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    /// Human delegator identity (OIDC subject / directory id).
    pub delegator_identity: String,
    /// Optional tenant/team this token belongs to (V11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Whether the token has been manually revoked.
    #[serde(default)]
    pub revoked: bool,
    /// Optional expiry. `None` = never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the token was created.
    pub created_at: DateTime<Utc>,
}

/// Why an approval token is not currently usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalTokenInvalid {
    /// The token was revoked by an administrator.
    Revoked,
    /// The token's time window has passed.
    Expired,
}

impl std::fmt::Display for ApprovalTokenInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalTokenInvalid::Revoked => write!(f, "approval token has been revoked"),
            ApprovalTokenInvalid::Expired => write!(f, "approval token has expired"),
        }
    }
}

/// Parameters for minting a new approval token.
#[derive(Debug, Clone)]
pub struct NewApprovalToken {
    pub delegation_grant_ref: String,
    pub grant_scope: DelegationGrantScope,
    pub agent_label: Option<String>,
    pub delegator_identity: String,
    pub tenant: Option<String>,
    pub expires_in: Option<Duration>,
}

impl NewApprovalToken {
    /// Validate parameters before minting.
    pub fn validate(&self) -> Result<(), String> {
        if self.delegation_grant_ref.trim().is_empty() {
            return Err("delegation_grant_ref must not be empty".to_string());
        }
        self.grant_scope.validate()?;
        if self.delegator_identity.trim().is_empty() {
            return Err("delegator_identity must not be empty".to_string());
        }
        if let Some(label) = &self.agent_label {
            super::validate_agent_label(label)?;
        }
        if matches!(self.expires_in, Some(d) if d <= Duration::zero()) {
            return Err(
                "expiry must be positive (a non-positive lifetime would mint an already-expired token)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

impl ApprovalToken {
    /// Mint a new approval token, returning the plaintext token (shown once) and
    /// the stored record. The plaintext never touches disk — only its hash is kept.
    pub fn create(params: NewApprovalToken) -> (String, ApprovalToken) {
        let (full_token, prefix) = generate_token();
        let token_hash = hash_token(&full_token);
        let now = Utc::now();

        let token = ApprovalToken {
            id: format!("apt_{}", uuid::Uuid::new_v4()),
            token_prefix: prefix,
            token_hash,
            delegation_grant_ref: params.delegation_grant_ref,
            grant_scope: params.grant_scope,
            agent_label: params.agent_label,
            delegator_identity: params.delegator_identity,
            tenant: params.tenant,
            revoked: false,
            expires_at: params.expires_in.map(|d| now + d),
            created_at: now,
        };

        (full_token, token)
    }

    /// Hash a presented plaintext token for lookup/comparison.
    pub fn hash(token: &str) -> String {
        hash_token(token)
    }

    /// Whether `token` looks like an approval token (correct prefix).
    pub fn looks_like_token(token: &str) -> bool {
        token.starts_with(APPROVAL_TOKEN_PREFIX)
    }

    /// True once the token's time window has passed.
    pub fn is_expired(&self) -> bool {
        matches!(self.expires_at, Some(exp) if Utc::now() >= exp)
    }

    /// Validate the token for use right now.
    pub fn check_usable(&self) -> Result<(), ApprovalTokenInvalid> {
        if self.revoked {
            return Err(ApprovalTokenInvalid::Revoked);
        }
        if self.is_expired() {
            return Err(ApprovalTokenInvalid::Expired);
        }
        Ok(())
    }

    /// Stable approver identity recorded on delegate decisions.
    pub fn approver_identity(&self) -> String {
        self.agent_label
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("vap:{}", self.id))
    }
}

/// Metadata view of an approval token (never includes the hash), safe for listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTokenMetadata {
    pub id: String,
    pub token_prefix: String,
    pub delegation_grant_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    pub delegator_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

impl From<&ApprovalToken> for ApprovalTokenMetadata {
    fn from(t: &ApprovalToken) -> Self {
        Self {
            id: t.id.clone(),
            token_prefix: t.token_prefix.clone(),
            delegation_grant_ref: t.delegation_grant_ref.clone(),
            agent_label: t.agent_label.clone(),
            delegator_identity: t.delegator_identity.clone(),
            tenant: t.tenant.clone(),
            expires_at: t.expires_at,
            created_at: t.created_at,
            revoked: t.revoked,
        }
    }
}

fn generate_token() -> (String, String) {
    let mut random_bytes = [0u8; TOKEN_RANDOM_LENGTH];
    rand::rngs::SysRng.try_fill_bytes(&mut random_bytes).expect("SysRng failure");

    let random_part: String = STANDARD
        .encode(random_bytes)
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(TOKEN_RANDOM_LENGTH)
        .collect();

    let full = format!("{}{}", APPROVAL_TOKEN_PREFIX, random_part);
    let prefix = format!("{}{}", APPROVAL_TOKEN_PREFIX, &random_part[..8]);
    (full, prefix)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    STANDARD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_token_shape() {
        let (full, t) = ApprovalToken::create(NewApprovalToken {
            delegation_grant_ref: "grant_abc".to_string(),
            grant_scope: DelegationGrantScope::default(),
            agent_label: Some("refund-bot".to_string()),
            delegator_identity: "alice@corp".to_string(),
            tenant: Some("acme".to_string()),
            expires_in: Some(Duration::hours(1)),
        });

        assert!(full.starts_with("vap_"));
        assert!(t.token_prefix.starts_with("vap_"));
        assert_eq!(ApprovalToken::hash(&full), t.token_hash);
        assert!(!t.is_expired());
        assert_eq!(t.approver_identity(), "refund-bot");
    }

    #[test]
    fn test_check_usable_states() {
        let mut t = ApprovalToken::create(NewApprovalToken {
            delegation_grant_ref: "g1".to_string(),
            grant_scope: DelegationGrantScope::default(),
            agent_label: None,
            delegator_identity: "bob".to_string(),
            tenant: None,
            expires_in: None,
        })
        .1;
        assert!(t.check_usable().is_ok());

        t.revoked = true;
        assert_eq!(t.check_usable(), Err(ApprovalTokenInvalid::Revoked));

        t.revoked = false;
        t.expires_at = Some(Utc::now() - Duration::hours(1));
        assert_eq!(t.check_usable(), Err(ApprovalTokenInvalid::Expired));
    }

    #[test]
    fn test_looks_like_token() {
        assert!(ApprovalToken::looks_like_token("vap_abc123"));
        assert!(!ApprovalToken::looks_like_token("vut_abc123"));
        assert!(!ApprovalToken::looks_like_token("vk_abc123"));
    }
}
