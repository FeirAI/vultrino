//! Ordered, replayable, signed event outbox (V9).
//!
//! govder's webhook contract promises per-subject ordering, a monotonic
//! sequence, gap-free replay from a cursor, a dead-letter queue, and an HMAC
//! signature on every delivery. This module is the durable backbone:
//!
//! - **Append-only log.** Each event gets a process-global monotonic
//!   [`OutboxEvent::sequence`] (assigned atomically under the storage lock), so a
//!   consumer can replay strictly after its last-seen sequence with **no gaps and
//!   no dupes** (the [replay API](crate::web)).
//! - **Per-subject ordering.** The delivery worker delivers in sequence order and
//!   never delivers a later event for a `subject` while an earlier one for that
//!   same subject is still undelivered (head-of-line), so a consumer sees a
//!   subject's events in order.
//! - **Dead-letter queue.** An event that fails delivery `max_attempts` times is
//!   parked as [`DeliveryState::DeadLettered`] (so it stops blocking its subject)
//!   and can be replayed by an operator.
//! - **Signed.** Every delivery carries `Govder-Signature: sha256=<hex>` =
//!   HMAC-SHA256(secret, body), so a consumer verifies authenticity.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ===== Event type constants (the govder event taxonomy) =====
pub const EVENT_APPROVAL_REQUESTED: &str = "approval.requested";
pub const EVENT_APPROVAL_APPROVED: &str = "approval.approved";
pub const EVENT_APPROVAL_DENIED: &str = "approval.denied";
pub const EVENT_APPROVAL_ESCALATED: &str = "approval.escalated";
pub const EVENT_APPROVAL_EXPIRED: &str = "approval.expired";
pub const EVENT_AGENT_HALTED: &str = "agent.halted";
pub const EVENT_POLICY_CHANGED: &str = "policy.changed";
pub const EVENT_CREDENTIAL_ROTATED: &str = "credential.rotated";
/// A policy denial that an observe-only tenant did NOT enforce (V11).
pub const EVENT_POLICY_OBSERVED_DENIAL: &str = "policy.observed_denial";

/// Delivery state of an outbox event (V9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Not yet delivered (or failed but still under the retry budget).
    Pending,
    /// Successfully delivered and acknowledged (2xx) by the consumer.
    Delivered,
    /// Failed `max_attempts` times; parked in the dead-letter queue.
    DeadLettered,
}

/// One event in the outbox (V9). Carries no secrets — payloads are built from
/// already-redacted, agent-safe summaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEvent {
    /// Process-global monotonic sequence — the replay cursor.
    pub sequence: u64,
    /// Ordering key: events with the same subject are delivered in order (e.g.
    /// an approval id, an agent label).
    pub subject: String,
    /// Event type (see the `EVENT_*` constants).
    pub event_type: String,
    /// Event body (agent-safe; no secrets).
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    #[serde(default = "default_pending")]
    pub delivery: DeliveryState,
    #[serde(default)]
    pub attempts: u32,
    /// While set and in the future, this event is **claimed** for delivery by some
    /// process (or is in a post-failure backoff) and won't be re-claimed (V9). A
    /// lease in the past is stale (its owner likely crashed) and may be re-taken —
    /// this is what makes delivery exclusive across the web+MCP processes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leased_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

fn default_pending() -> DeliveryState {
    DeliveryState::Pending
}

impl OutboxEvent {
    /// The JSON body delivered to a consumer (and the bytes the signature covers).
    pub fn delivery_body(&self) -> serde_json::Value {
        serde_json::json!({
            "sequence": self.sequence,
            "subject": self.subject,
            "event": self.event_type,
            "payload": self.payload,
            "created_at": self.created_at,
        })
    }
}

/// Compute the `Govder-Signature` header value for a delivery body (V9):
/// `sha256=<hex(HMAC-SHA256(secret, body))>`. A consumer recomputes this over the
/// raw body bytes with the shared secret to verify authenticity.
pub fn sign_body(secret: &str, body: &[u8]) -> String {
    // `new_from_slice` accepts any key length for HMAC, so this never errors.
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Configuration for the signed delivery outbox (V9). `Debug` is hand-written to
/// **redact `hmac_secret`** so a config dump can never leak the signing key.
#[derive(Clone)]
pub struct OutboxConfig {
    /// Whether push delivery is enabled. When false, events are still appended to
    /// the log (and replayable via the API) but not actively pushed.
    pub enabled: bool,
    /// Destination URL for push delivery.
    pub url: Option<String>,
    /// Shared HMAC secret for `Govder-Signature`. Required to push.
    pub hmac_secret: Option<String>,
    /// Max delivery attempts before an event is dead-lettered.
    pub max_attempts: u32,
    /// Retention for **delivered** events, in seconds (replay window). Pending and
    /// dead-lettered events are retained until resolved.
    pub retention_secs: u64,
}

impl std::fmt::Debug for OutboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            // Never print the signing secret; only whether one is set.
            .field("hmac_secret", &self.hmac_secret.as_ref().map(|_| "<redacted>"))
            .field("max_attempts", &self.max_attempts)
            .field("retention_secs", &self.retention_secs)
            .finish()
    }
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            hmac_secret: None,
            max_attempts: 8,
            retention_secs: 7 * 24 * 3600, // 7 days
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_body_is_stable_and_keyed() {
        let body = br#"{"sequence":1}"#;
        let a = sign_body("secret", body);
        assert!(a.starts_with("sha256="));
        // Deterministic for the same key+body.
        assert_eq!(a, sign_body("secret", body));
        // Different key → different signature.
        assert_ne!(a, sign_body("other", body));
        // Different body → different signature.
        assert_ne!(a, sign_body("secret", br#"{"sequence":2}"#));
        // Matches an independent HMAC-SHA256 computation.
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(body);
        assert_eq!(a, format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
    }

    #[test]
    fn test_delivery_body_shape() {
        let e = OutboxEvent {
            sequence: 7,
            subject: "appr_1".to_string(),
            event_type: EVENT_APPROVAL_APPROVED.to_string(),
            payload: serde_json::json!({"k": "v"}),
            created_at: Utc::now(),
            delivery: DeliveryState::Pending,
            attempts: 0,
            leased_until: None,
            last_attempt_at: None,
            last_error: None,
        };
        let body = e.delivery_body();
        assert_eq!(body["sequence"], 7);
        assert_eq!(body["subject"], "appr_1");
        assert_eq!(body["event"], "approval.approved");
        assert_eq!(body["payload"]["k"], "v");
    }

    #[test]
    fn test_debug_redacts_hmac_secret() {
        let cfg = OutboxConfig {
            enabled: true,
            url: Some("https://x".to_string()),
            hmac_secret: Some("super-secret-signing-key".to_string()),
            max_attempts: 3,
            retention_secs: 10,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("super-secret-signing-key"), "secret must not appear: {dbg}");
        assert!(dbg.contains("redacted"));
    }
}
