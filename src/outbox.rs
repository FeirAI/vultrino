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
/// A credential revoke that was **propagated** to the resource side (R5/V7): an
/// OAuth2 credential's access/refresh token was revoked at its RFC 7009
/// revocation endpoint on delete, not just left to expire.
pub const EVENT_CREDENTIAL_REVOKED: &str = "credential.revoked";
/// A policy denial that an observe-only tenant did NOT enforce (V11).
pub const EVENT_POLICY_OBSERVED_DENIAL: &str = "policy.observed_denial";
/// An enforce-mode denial — a DETECT signal (R3/V12a). Its `created_at` is the
/// per-incident `detected_at`, to pair with a later [`EVENT_AGENT_HALTED`]
/// `contained_at` (same subject) for an MTTD/MTTC measurement.
pub const EVENT_POLICY_DENIED: &str = "policy.denied";
/// A per-admitted-action usage observation for the leria metering plane (V13a).
///
/// Emitted on the response path of every **admitted** `/execute` (policy allow +
/// credential injection happened), exactly once, carrying `asset=api-calls,
/// amount=1` — a count of one metered call. leria is the `gateway-observed`
/// `cost_source`; vultrino emits the raw observation only (ids + a count) and
/// holds **no** cumulative spend state. A denied action emits none.
///
/// The payload is a [`MeterEvent`]-shaped body (snake_case fields, kebab-case
/// enum values) matching leria's MeterEvent ingest schema; it carries **no**
/// body/prompt/secret. The event rides the existing V9 signed outbox (per-subject
/// monotonic sequence, `Govder-Signature` HMAC, gap-free replay) so leria can
/// poll it gap-free by sequence via `GET /api/v1/events?after=N` (the v1
/// subscriber decision: leria POLLS — no push fan-out, the single outbox push
/// slot stays govder's).
pub const EVENT_METER_OBSERVED: &str = "meter.observed";

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

/// Build the [`EVENT_METER_OBSERVED`] (V13a) payload — a `MeterEvent`-shaped body
/// for the leria metering plane, carrying **only ids + a count** (never a body,
/// prompt, or the injected credential secret).
///
/// Field/enum vocabulary matches leria's MeterEvent ingest schema (fields
/// `snake_case`, enum values `kebab-case`):
///
/// - `event_id` — the `/execute` `request_id`; leria's producer-supplied dedup
///   key (namespaced `(authenticated_source_id, event_id)`), so a replay of the
///   same request dedups. This IS leria's wire field name (`WireEvent.event_id`,
///   hard-required); an earlier handoff draft called it `idempotency_key`, which
///   leria's strict (`DisallowUnknownFields`) decoder would reject — the canonical
///   contract §3.1 + leria's code win.
/// - `correlation_id` — the same `request_id`; leria's per-occurrence join key
///   threaded onto provider/invoice rows for occurrence-level reconciliation.
/// - `principal` — the consuming agent: the V4 `agent_label`, falling back to the
///   `vk_`/`vut_` principal id (the same subject vultrino uses for its outbox
///   events). Caller resolves the fallback before calling.
/// - `asset` — constant `api-calls`; `amount` — constant `1` (integer minor
///   units: one metered call). No body knowledge needed.
/// - `cost_source` — constant `gateway-observed` (vultrino's tier).
/// - `confidence` — constant `low` (the gateway-observed data-quality band per
///   leria's source table; leria also defaults an absent value to `low`).
/// - `occurred_at` — the action timestamp (the bucketing clock).
/// - `dims` — an attribution snapshot: `tenant` (V11), `credential` alias, and
///   `model` **if** already known without parsing. Keys that are `None` are
///   omitted (no phantom keys).
///
/// `tenant` and `principal` are attribution-authoritative on leria's side (bound
/// to the authenticated source), so they ride as top-level / dims fields here but
/// leria re-derives authority from the signed feed — this payload is the snapshot.
pub fn meter_observed_payload(
    request_id: &str,
    principal: &str,
    occurred_at: DateTime<Utc>,
    tenant: Option<&str>,
    credential_alias: &str,
    model: Option<&str>,
) -> serde_json::Value {
    let mut dims = serde_json::Map::new();
    // Omit keys we don't have (no phantom dims), per leria's schema.
    if let Some(t) = tenant {
        dims.insert("tenant".to_string(), serde_json::Value::String(t.to_string()));
    }
    dims.insert(
        "credential".to_string(),
        serde_json::Value::String(credential_alias.to_string()),
    );
    if let Some(m) = model {
        dims.insert("model".to_string(), serde_json::Value::String(m.to_string()));
    }
    serde_json::json!({
        "event_id": request_id,
        "correlation_id": request_id,
        "principal": principal,
        "asset": "api-calls",
        "amount": 1,
        "cost_source": "gateway-observed",
        "confidence": "low",
        "occurred_at": occurred_at,
        "dims": serde_json::Value::Object(dims),
    })
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
    fn test_meter_observed_payload_shape() {
        // V13a: the MeterEvent body matches leria's ingest schema, carries ids +
        // a count of 1 only, and omits dims it doesn't have (no phantom keys).
        let ts = "2026-06-19T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let p = super::meter_observed_payload(
            "req-123",
            "agent_refund_bot_v3",
            ts,
            Some("acme"),
            "vk_prod",
            None,
        );
        assert_eq!(p["event_id"], "req-123");
        assert_eq!(p["correlation_id"], "req-123");
        assert_eq!(p["principal"], "agent_refund_bot_v3");
        assert_eq!(p["asset"], "api-calls");
        assert_eq!(p["amount"], 1);
        assert_eq!(p["cost_source"], "gateway-observed");
        assert_eq!(p["confidence"], "low");
        assert_eq!(p["dims"]["tenant"], "acme");
        assert_eq!(p["dims"]["credential"], "vk_prod");
        // model omitted (V13a doesn't parse the body); amount is an integer.
        assert!(p["dims"].get("model").is_none());
        assert!(p["amount"].is_u64() || p["amount"].is_i64(), "amount must be an integer, not a float");

        // Untenanted → tenant key omitted entirely.
        let p2 = super::meter_observed_payload("r", "id", ts, None, "cred", None);
        assert!(p2["dims"].get("tenant").is_none(), "no tenant ⇒ omit the key");
        // model present when known.
        let p3 = super::meter_observed_payload("r", "id", ts, None, "cred", Some("gpt-4o"));
        assert_eq!(p3["dims"]["model"], "gpt-4o");
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
