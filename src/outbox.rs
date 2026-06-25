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
/// A connector capability (named MCP tool) was created/replaced/deleted (M1).
pub const EVENT_CAPABILITY_CHANGED: &str = "capability.changed";
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
    /// Internal idempotency key for the INTENT-STAGING drain (D1, v6→v7): an event staged in the
    /// vault and drained to the outbox store carries a stable id so a crash between the outbox append
    /// and clearing the vault intent can't duplicate it on re-drain (the store dedups on this). `None`
    /// for ordinary direct appends. NOT part of `delivery_body` — never delivered to the consumer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_id: Option<String>,
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

/// A provider-reported token usage split parsed from an LLM response body (V13b).
///
/// vultrino emits the raw **counts** only — never dollars. leria's rate card mints
/// the usd amount from `(input, output)` + `dims.model_ref`; vultrino holds no
/// pricing logic and no cumulative state (the V3 boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenUsage {
    /// Prompt / input tokens (OpenAI `prompt_tokens`, Anthropic `input_tokens`).
    pub input_tokens: u64,
    /// Completion / output tokens (OpenAI `completion_tokens`, Anthropic
    /// `output_tokens`).
    pub output_tokens: u64,
}

/// Parse a provider `usage` block from a **non-streamed** LLM response body
/// (V13b). Best-effort: returns `None` for any body that isn't a JSON object
/// carrying a recognized `usage` shape (a streamed response without a usage
/// trailer, or a non-LLM action) — the caller then emits only the V13a
/// `api-calls=1` event.
///
/// Two provider shapes are recognized (both nested under top-level `usage`):
///
/// - **OpenAI-style:** `{"usage": {"prompt_tokens": N, "completion_tokens": M,
///   "total_tokens": …}}` — input = `prompt_tokens`, output = `completion_tokens`.
/// - **Anthropic-style:** `{"usage": {"input_tokens": N, "output_tokens": M}}` —
///   input = `input_tokens`, output = `output_tokens`.
///
/// # The raw-body contract (V13b Gate 2)
///
/// This MUST be called on the **raw** response body, **before**
/// [`crate::egress::scrub_response`]. Scrub redacts / withholds / replaces the
/// body, so a usage read placed after it would see redacted bytes and
/// **under-count** — and under-counting is the dangerous direction (a low token
/// count keeps leria's cumulative ceiling below its limit, so budgets never fire →
/// unbounded spend). Reading pre-scrub yields the correct count regardless of what
/// egress later does to the bytes the agent receives.
///
/// # v1 limitation — non-streamed responses only
///
/// vultrino buffers response bodies whole and has no SSE/streaming awareness, and
/// OpenAI omits the `usage` object from a streamed completion unless the client
/// sets `stream_options.include_usage`. So for a streamed LLM call this returns
/// `None` and the call falls back to the V13a `api-calls=1` event; leria treats
/// token-level confidence for that call as non-streaming-only.
///
/// Counts only — no prompt/body text is retained.
pub fn parse_token_usage(raw_body: &[u8]) -> Option<TokenUsage> {
    let json: serde_json::Value = serde_json::from_slice(raw_body).ok()?;
    let usage = json.get("usage")?.as_object()?;

    // A JSON number can exceed u64 or be negative/float; clamp non-negative
    // integers only (a count is a whole, non-negative quantity). `as_u64` already
    // returns None for negatives and non-integers.
    let read = |key: &str| usage.get(key).and_then(serde_json::Value::as_u64);

    // OpenAI-style first (prompt/completion), then Anthropic-style (input/output).
    // A response that carries neither pair has no parseable token usage.
    if let (Some(input), Some(output)) = (read("prompt_tokens"), read("completion_tokens")) {
        return Some(TokenUsage { input_tokens: input, output_tokens: output });
    }
    if let (Some(input), Some(output)) = (read("input_tokens"), read("output_tokens")) {
        return Some(TokenUsage { input_tokens: input, output_tokens: output });
    }
    None
}

/// Extract the model identifier for a metered LLM call (V13b): prefer the model
/// echoed in the **response** body (the model the provider actually served),
/// falling back to a `model` field in the **request** params. Returns `None` if
/// neither carries a string `model` — the token event still emits, just without
/// `dims.model_ref` (leria then fails the usd pricing closed for that call and the
/// caller may re-post against a known model). Counts only; no body text retained.
pub fn extract_model(raw_body: &[u8], request_params: &serde_json::Value) -> Option<String> {
    let from_response = serde_json::from_slice::<serde_json::Value>(raw_body)
        .ok()
        .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string));
    from_response.or_else(|| {
        request_params
            .get("model")
            .and_then(|m| m.as_str())
            .map(str::to_string)
    })
}

/// Force `stream_options.include_usage = true` on an OpenAI-chat streaming request
/// body so the provider emits a terminal usage chunk (V13b token metering on a
/// streamed turn). Only acts when the request is actually streaming
/// (`stream == true`). `include_usage` is GATEWAY-OWNED: a client must NOT be able to
/// opt out of the token trailer by sending `include_usage:false` (that would evade
/// token metering while still receiving the completion), so an explicit client `false`
/// is OVERWRITTEN to `true`. A non-object `stream_options` (invalid for OpenAI anyway)
/// is replaced with one carrying `include_usage:true`; sibling object fields the client
/// set are preserved. The mutation is structural (never string concat), so it can't
/// smuggle or drop sibling fields. The caller gates this on the request being
/// OpenAI-chat-shaped (Anthropic / responses report usage natively and must not receive
/// a `stream_options` field). Returns whether it changed the body.
pub fn maybe_inject_stream_usage(body: &mut serde_json::Value) -> bool {
    let Some(obj) = body.as_object_mut() else {
        return false;
    };
    if obj.get("stream").and_then(serde_json::Value::as_bool) != Some(true) {
        return false;
    }
    let so = obj
        .entry("stream_options")
        .or_insert_with(|| serde_json::json!({}));
    if !so.is_object() {
        // A non-object stream_options is invalid for OpenAI; the gateway owns the usage
        // trailer, so replace it with a well-formed object that forces include_usage.
        *so = serde_json::json!({ "include_usage": true });
        return true;
    }
    // Panic-free (is_object was checked above, but don't `.expect()` on a request-driven path): if it
    // somehow isn't an object, fail SAFE by forcing a fresh metering object.
    let so_obj = match so.as_object_mut() {
        Some(o) => o,
        None => {
            *so = serde_json::json!({ "include_usage": true });
            return true;
        }
    };
    let already_true =
        so_obj.get("include_usage").and_then(serde_json::Value::as_bool) == Some(true);
    // FORCE true even over an explicit client false — the client cannot disable metering.
    so_obj.insert("include_usage".to_string(), serde_json::Value::Bool(true));
    !already_true
}

/// Incremental token-usage accumulator for a **streamed** LLM response (V13b on
/// streams). Fed the RAW (pre-scrub) SSE bytes, it line-buffers across chunk
/// boundaries and extracts ONLY token counts + the model from the top level of each
/// recognized `data:` JSON event — never a substring scan (so a prompt that
/// literally contains `"usage":{…}` can't forge a count) and never any prompt /
/// content text. [`Self::finish`] yields the final `(usage, model)`.
///
/// Tolerates all three wire shapes:
/// - **OpenAI chat** (`stream_options.include_usage`): a terminal `data:` event with
///   top-level `usage.{prompt_tokens, completion_tokens}` and `choices: []`.
/// - **OpenAI responses**: `response.completed` data carries
///   `response.usage.{input_tokens, output_tokens}`.
/// - **Anthropic messages**: `message_start` → `message.usage.input_tokens`;
///   `message_delta` → `usage.output_tokens` (**cumulative** → last-writer-wins, so
///   the final delta is authoritative; never summed).
pub struct UsageAccumulator {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    model: Option<String>,
    /// Carry for a partial trailing SSE line split across chunks.
    line_buf: Vec<u8>,
    /// Hard cap on a single un-delimited line; past it we stop accumulating (the
    /// call just meters V13a-only — safe) rather than buffer unbounded.
    max_line: usize,
    capped: bool,
}

impl UsageAccumulator {
    pub fn new(max_line: usize) -> Self {
        Self {
            input_tokens: None,
            output_tokens: None,
            model: None,
            line_buf: Vec::new(),
            max_line,
            capped: false,
        }
    }

    /// Feed one RAW upstream chunk (pre-scrub). Parses every complete line it
    /// completes; a trailing partial line is carried to the next chunk.
    pub fn push(&mut self, chunk: &[u8]) {
        if self.capped {
            return;
        }
        for &b in chunk {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line_buf);
                self.process_line(&line);
            } else {
                self.line_buf.push(b);
                if self.line_buf.len() > self.max_line {
                    // A delimiter-less giant line: stop accumulating (fail safe to
                    // V13a-only), don't OOM.
                    self.capped = true;
                    self.line_buf.clear();
                    return;
                }
            }
        }
    }

    /// Flush any trailing partial line and return the final `(usage, model)`. A
    /// usage split is returned only when BOTH input and output counts were seen.
    pub fn finish(&mut self) -> (Option<TokenUsage>, Option<String>) {
        if !self.line_buf.is_empty() {
            let line = std::mem::take(&mut self.line_buf);
            self.process_line(&line);
        }
        let usage = match (self.input_tokens, self.output_tokens) {
            (Some(input_tokens), Some(output_tokens)) => Some(TokenUsage {
                input_tokens,
                output_tokens,
            }),
            _ => None,
        };
        (usage, self.model.take())
    }

    /// A NON-consuming peek at the usage parsed so far: `Some` only when BOTH token
    /// counts have been seen (the same completeness rule as [`Self::finish`]). The
    /// stream finalizer records this after each chunk so a client disconnect or upstream
    /// error AFTER the usage trailer arrived (but before clean EOF) still meters V13b
    /// instead of under-counting — under-counting is the dangerous direction (it keeps
    /// leria's cumulative ceiling below its limit). Unlike `finish` it does not flush the
    /// partial line buffer or take the model (it clones it), so it is safe to call every
    /// chunk; a complete split only materializes once the trailer line is fully parsed.
    pub fn snapshot(&self) -> Option<(TokenUsage, Option<String>)> {
        match (self.input_tokens, self.output_tokens) {
            (Some(input_tokens), Some(output_tokens)) => Some((
                TokenUsage {
                    input_tokens,
                    output_tokens,
                },
                self.model.clone(),
            )),
            _ => None,
        }
    }

    fn process_line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else {
            return;
        };
        let text = text.trim_end_matches('\r').trim();
        // Only `data:` lines carry the JSON payload; `event:`/`id:`/comments are
        // framing. A `[DONE]` sentinel is not JSON.
        let Some(rest) = text.strip_prefix("data:") else {
            return;
        };
        let rest = rest.trim();
        if rest.is_empty() || rest == "[DONE]" {
            return;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(rest) else {
            return;
        };
        self.absorb(&value);
    }

    /// Pull token counts + model from the TOP LEVEL of a parsed event (or the
    /// `message`/`response` envelope), never from nested content.
    fn absorb(&mut self, v: &serde_json::Value) {
        if self.model.is_none() {
            let model = v
                .get("model")
                .and_then(|m| m.as_str())
                .or_else(|| v.get("message").and_then(|m| m.get("model")).and_then(|m| m.as_str()))
                .or_else(|| v.get("response").and_then(|r| r.get("model")).and_then(|m| m.as_str()));
            if let Some(m) = model {
                self.model = Some(m.to_string());
            }
        }
        // Recognized usage carriers: top-level, message.usage, response.usage.
        let carriers = [
            v.get("usage"),
            v.get("message").and_then(|m| m.get("usage")),
            v.get("response").and_then(|r| r.get("usage")),
        ];
        for usage in carriers.into_iter().flatten() {
            let Some(obj) = usage.as_object() else { continue };
            // INPUT tokens: FIRST-wins. The prompt count is reported once and early
            // (OpenAI's terminal usage chunk; Anthropic's `message_start`); a stray
            // `input_tokens` in a later event must not clobber the real prompt count.
            if self.input_tokens.is_none() {
                if let Some(p) = obj.get("prompt_tokens").and_then(serde_json::Value::as_u64) {
                    self.input_tokens = Some(p);
                } else if let Some(i) = obj.get("input_tokens").and_then(serde_json::Value::as_u64) {
                    self.input_tokens = Some(i);
                }
            }
            // OUTPUT tokens: LAST-wins. Anthropic's `output_tokens` is cumulative
            // across `message_delta` events, so the final value is authoritative
            // (never summed); OpenAI reports it once.
            if let Some(c) = obj.get("completion_tokens").and_then(serde_json::Value::as_u64) {
                self.output_tokens = Some(c);
            }
            if let Some(o) = obj.get("output_tokens").and_then(serde_json::Value::as_u64) {
                self.output_tokens = Some(o);
            }
        }
    }
}

/// Build the V13b token meter event payload — a second `MeterEvent`-shaped body
/// emitted for a non-streamed LLM call alongside the V13a `api-calls=1` event for
/// the **same** call (same `event_id`/`correlation_id`/`principal`/`dims`).
///
/// **Shape leria PRICES (verified against `internal/ingest/pipeline.go`
/// `WireEvent` + `internal/ratecard/ratecard.go`):** vultrino sends token
/// **counts**, NOT dollars. leria mints usd from the counts via its RateCard, so:
///
/// - `asset` — constant `usd`. (leria's `resolveAmount` only prices a
///   `gateway-observed` event whose `asset == usd` and that carries a `tokens`
///   split; `asset:tokens` would NOT trigger pricing.)
/// - `tokens` — `{input_tokens, output_tokens}` as **integers**. This is the
///   priced input; leria converts `(input,output) → usd-micros` and pins the
///   `rate_card_version`.
/// - **No `amount`** — a priced token event must NOT also carry an amount
///   (leria rejects `ambiguous_amount` otherwise); leria mints the amount from the
///   tokens. The `amount` key is omitted entirely (its absence decodes to 0).
/// - `dims.model_ref` — selects the rate card. (leria also accepts the `model`
///   dim spelling, but `model_ref` is the canonical selector.)
/// - `event_id` / `correlation_id` — the SAME `request_id` as the V13a event, so
///   leria threads both observations onto the same occurrence. (The token event's
///   own dedup is namespaced `(source, event_id)`; pairing it with the api-calls
///   event is via `correlation_id`.)
/// - `cost_source` — `gateway-observed`; `confidence` — `low` (the gateway band).
/// - `dims` — `tenant` (V11) + `credential` alias + `model_ref`, omitting absent
///   keys (no phantom dims).
///
/// No currency field is set: leria's v1 is single-base-currency (usd) and rejects
/// a non-usd currency; an empty currency is the usd default. Counts + ids only —
/// no prompt/body/secret rides the event.
pub fn meter_tokens_payload(
    request_id: &str,
    principal: &str,
    occurred_at: DateTime<Utc>,
    tenant: Option<&str>,
    credential_alias: &str,
    model: Option<&str>,
    usage: TokenUsage,
) -> serde_json::Value {
    let mut dims = serde_json::Map::new();
    if let Some(t) = tenant {
        dims.insert("tenant".to_string(), serde_json::Value::String(t.to_string()));
    }
    dims.insert(
        "credential".to_string(),
        serde_json::Value::String(credential_alias.to_string()),
    );
    // leria selects the rate card by `dims.model_ref` (it also accepts `model`);
    // emit the canonical `model_ref`. Omitted when unknown (no phantom dim).
    if let Some(m) = model {
        dims.insert(
            "model_ref".to_string(),
            serde_json::Value::String(m.to_string()),
        );
    }
    // DISTINCT dedup key from the V13a api-calls event (which uses request_id as its
    // event_id). The two events share the same OCCURRENCE via correlation_id, but a
    // colliding event_id carrying a DIFFERENT resolved amount would be classified a
    // dup-mismatch (disputed) and dropped by leria's namespaced dedup. Suffix it.
    let token_event_id = format!("{request_id}:tokens");
    serde_json::json!({
        "event_id": token_event_id,
        "correlation_id": request_id,
        "principal": principal,
        // asset=usd + a tokens split ⇒ leria prices via the rate card; NO amount
        // (a priced token event must not carry one — leria mints it).
        "asset": "usd",
        "tokens": {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
        },
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
            dedup_id: None,
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
    fn test_parse_token_usage_openai_style() {
        // OpenAI-style: usage.{prompt_tokens, completion_tokens, total_tokens}.
        let body = br#"{"id":"cmpl-1","model":"gpt-4o","choices":[{"text":"hi"}],
            "usage":{"prompt_tokens":120,"completion_tokens":34,"total_tokens":154}}"#;
        let u = super::parse_token_usage(body).expect("openai usage parses");
        assert_eq!(u.input_tokens, 120);
        assert_eq!(u.output_tokens, 34);
    }

    #[test]
    fn test_parse_token_usage_anthropic_style() {
        // Anthropic-style: usage.{input_tokens, output_tokens} (no total).
        let body = br#"{"id":"msg_1","model":"claude-opus-4","content":[{"type":"text","text":"hi"}],
            "usage":{"input_tokens":2048,"output_tokens":512}}"#;
        let u = super::parse_token_usage(body).expect("anthropic usage parses");
        assert_eq!(u.input_tokens, 2048);
        assert_eq!(u.output_tokens, 512);
    }

    #[test]
    fn test_parse_token_usage_none_for_no_usage_block() {
        // No usage block (streamed response without a usage trailer, or a non-LLM
        // action) → None → caller emits only the V13a api-calls=1 event.
        assert!(super::parse_token_usage(br#"{"hello":"world"}"#).is_none());
        // A streamed-style SSE body is not a JSON object → None.
        assert!(super::parse_token_usage(b"data: {\"delta\":\"hi\"}\n\n").is_none());
        // Empty / non-JSON body → None (never panics).
        assert!(super::parse_token_usage(b"").is_none());
        assert!(super::parse_token_usage(b"not json").is_none());
        // A usage block missing a recognized count pair → None (no half-counts).
        assert!(super::parse_token_usage(br#"{"usage":{"total_tokens":10}}"#).is_none());
        // Negative / float counts are rejected by as_u64 → None.
        assert!(super::parse_token_usage(br#"{"usage":{"prompt_tokens":-1,"completion_tokens":2}}"#).is_none());
        assert!(super::parse_token_usage(br#"{"usage":{"prompt_tokens":1.5,"completion_tokens":2}}"#).is_none());
    }

    #[test]
    fn test_parse_token_usage_prefers_openai_pair_when_both_keys_present() {
        // A body carrying both spellings (unusual) takes the OpenAI pair first;
        // the result is deterministic and still a valid (input,output) split.
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":20,
            "input_tokens":999,"output_tokens":888}}"#;
        let u = super::parse_token_usage(body).unwrap();
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 20);
    }

    #[test]
    fn test_extract_model_prefers_response_then_request() {
        let resp = br#"{"model":"gpt-4o-2024","usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        let req = serde_json::json!({"model": "gpt-4o-alias"});
        // Response model wins (the model the provider actually served).
        assert_eq!(super::extract_model(resp, &req).as_deref(), Some("gpt-4o-2024"));
        // No response model → fall back to the request model.
        let resp_no_model = br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        assert_eq!(super::extract_model(resp_no_model, &req).as_deref(), Some("gpt-4o-alias"));
        // Neither → None (token event still emits, just without model_ref).
        assert!(super::extract_model(resp_no_model, &serde_json::Value::Null).is_none());
    }

    #[test]
    fn test_meter_tokens_payload_shape_is_what_leria_prices() {
        // V13b: the token meter event is the shape leria PRICES — asset=usd + a
        // tokens{input,output} split + dims.model_ref, NO amount (leria mints usd
        // from the tokens via the rate card). SAME correlation_id as V13a (the
        // occurrence handle), but a DISTINCT event_id (request_id + ":tokens") so it
        // is not a dup-mismatch of the api-calls=1 event under leria's dedup.
        let ts = "2026-06-19T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let p = super::meter_tokens_payload(
            "req-123",
            "agent_refund_bot_v3",
            ts,
            Some("acme"),
            "vk_prod",
            Some("gpt-4o"),
            super::TokenUsage { input_tokens: 120, output_tokens: 34 },
        );
        assert_eq!(p["event_id"], "req-123:tokens", "distinct dedup key from the api-calls event");
        assert_eq!(p["correlation_id"], "req-123", "same correlation_id as the V13a event");
        assert_eq!(p["principal"], "agent_refund_bot_v3");
        // The pricing trigger: asset=usd + a tokens split (NOT asset=tokens).
        assert_eq!(p["asset"], "usd");
        assert_eq!(p["tokens"]["input_tokens"], 120);
        assert_eq!(p["tokens"]["output_tokens"], 34);
        // No amount: leria rejects ambiguous_amount on a priced token event.
        assert!(p.get("amount").is_none(), "a priced token event must NOT carry an amount");
        // Token counts are integers, never floats on the wire.
        assert!(p["tokens"]["input_tokens"].is_u64() || p["tokens"]["input_tokens"].is_i64());
        assert!(p["tokens"]["output_tokens"].is_u64() || p["tokens"]["output_tokens"].is_i64());
        assert_eq!(p["cost_source"], "gateway-observed");
        assert_eq!(p["confidence"], "low");
        // dims.model_ref selects the rate card; tenant + credential present.
        assert_eq!(p["dims"]["model_ref"], "gpt-4o");
        assert_eq!(p["dims"]["tenant"], "acme");
        assert_eq!(p["dims"]["credential"], "vk_prod");
        // No currency field (usd is the single-base default; a non-usd value would
        // be rejected by leria).
        assert!(p.get("currency").is_none());

        // Unknown model → model_ref omitted (no phantom dim); event still emits.
        let p2 = super::meter_tokens_payload(
            "r", "id", ts, None, "cred", None,
            super::TokenUsage { input_tokens: 1, output_tokens: 2 },
        );
        assert!(p2["dims"].get("model_ref").is_none(), "no model ⇒ omit model_ref");
        assert!(p2["dims"].get("tenant").is_none(), "no tenant ⇒ omit the key");
        assert_eq!(p2["tokens"]["input_tokens"], 1);
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

    // --- UsageAccumulator (streamed token metering, V13b) ------------------

    fn accumulate(chunks: &[&[u8]]) -> (Option<super::TokenUsage>, Option<String>) {
        let mut acc = super::UsageAccumulator::new(1 << 20);
        for c in chunks {
            acc.push(c);
        }
        acc.finish()
    }

    #[test]
    fn usage_accumulator_openai_chat_terminal_chunk() {
        let (usage, model) = accumulate(&[
            b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":57,\"completion_tokens\":13}}\n\n",
            b"data: [DONE]\n\n",
        ]);
        assert_eq!(usage, Some(super::TokenUsage { input_tokens: 57, output_tokens: 13 }));
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn usage_accumulator_handles_usage_split_across_chunks() {
        // The usage JSON line is split mid-token across two pushes.
        let (usage, _) = accumulate(&[
            b"data: {\"choices\":[],\"usage\":{\"prompt_to",
            b"kens\":100,\"completion_tokens\":200}}\n\n",
        ]);
        assert_eq!(usage, Some(super::TokenUsage { input_tokens: 100, output_tokens: 200 }));
    }

    #[test]
    fn usage_accumulator_anthropic_cumulative_output_last_wins() {
        // input from message_start; output is CUMULATIVE across message_delta events
        // → the LAST value is authoritative (must NOT be summed: 5+15 != 15).
        let (usage, model) = accumulate(&[
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-3-5-sonnet\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\n",
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ]);
        assert_eq!(usage, Some(super::TokenUsage { input_tokens: 25, output_tokens: 15 }));
        assert_eq!(model.as_deref(), Some("claude-3-5-sonnet"));
    }

    #[test]
    fn usage_accumulator_responses_api_completed_event() {
        let (usage, _) = accumulate(&[
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n\n",
        ]);
        assert_eq!(usage, Some(super::TokenUsage { input_tokens: 7, output_tokens: 9 }));
    }

    #[test]
    fn usage_accumulator_none_without_usage_trailer() {
        let (usage, _) = accumulate(&[
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
            b"data: [DONE]\n\n",
        ]);
        assert_eq!(usage, None);
    }

    #[test]
    fn usage_accumulator_ignores_forged_usage_in_content() {
        // A prompt/content that literally contains a usage object must NOT be counted
        // — only the TOP LEVEL of a data event is read, never nested content.
        let (usage, _) = accumulate(&[
            b"data: {\"choices\":[{\"delta\":{\"content\":\"\\\"usage\\\":{\\\"prompt_tokens\\\":999,\\\"completion_tokens\\\":999}\"}}]}\n\n",
        ]);
        assert_eq!(usage, None, "nested/forged usage must not be metered");
    }

    #[test]
    fn usage_accumulator_input_is_first_wins() {
        // input_tokens is reported once + early; a stray later value must NOT clobber
        // the real prompt count (output stays last-wins / cumulative).
        let (usage, _) = accumulate(&[
            b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":42,\"output_tokens\":1}}}\n\n",
            b"data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":9,\"output_tokens\":30}}\n\n",
        ]);
        assert_eq!(usage, Some(super::TokenUsage { input_tokens: 42, output_tokens: 30 }));
    }

    #[test]
    fn usage_accumulator_only_input_or_only_output_yields_none() {
        // A half-usage (only input, or only output) is not a complete split.
        let (usage, _) = accumulate(&[b"data: {\"usage\":{\"prompt_tokens\":5}}\n\n"]);
        assert_eq!(usage, None);
    }

    #[test]
    fn usage_accumulator_snapshot_is_some_only_when_complete() {
        // snapshot() is the non-consuming peek the finalizer records so a disconnect
        // AFTER the trailer still meters V13b. It is None until BOTH counts are seen, and
        // Some (without consuming) once the complete trailer is parsed.
        let mut acc = super::UsageAccumulator::new(1 << 20);
        acc.push(b"data: {\"model\":\"gpt-4o\",\"choices\":[]}\n\n");
        assert!(acc.snapshot().is_none(), "no trailer yet → None");
        acc.push(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":22}}\n\n");
        let (usage, model) = acc.snapshot().expect("complete trailer → Some");
        assert_eq!(usage.input_tokens, 11);
        assert_eq!(usage.output_tokens, 22);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
        // Non-consuming: finish() still returns the same complete split afterward.
        let (again, _) = acc.finish();
        assert_eq!(again.map(|u| u.output_tokens), Some(22));
    }

    // --- maybe_inject_stream_usage -----------------------------------------

    #[test]
    fn inject_adds_include_usage_when_absent_and_streaming() {
        let mut body = serde_json::json!({ "model": "gpt-4o", "stream": true });
        assert!(super::maybe_inject_stream_usage(&mut body));
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn inject_forces_include_usage_true_over_client_false() {
        // GATEWAY-OWNED: an explicit client `false` is OVERWRITTEN to true (a client must
        // not be able to opt out of the V13b token trailer and evade metering).
        let mut body =
            serde_json::json!({ "stream": true, "stream_options": { "include_usage": false } });
        assert!(super::maybe_inject_stream_usage(&mut body)); // changed false -> true
        assert_eq!(body["stream_options"]["include_usage"], true);
        // Explicit true is already correct → left as-is, reports no change.
        let mut body2 =
            serde_json::json!({ "stream": true, "stream_options": { "include_usage": true } });
        assert!(!super::maybe_inject_stream_usage(&mut body2));
        assert_eq!(body2["stream_options"]["include_usage"], true);
    }

    #[test]
    fn inject_replaces_non_object_stream_options() {
        // A non-object stream_options is invalid for OpenAI; the gateway forces a
        // well-formed object so the usage trailer is always requested.
        let mut body = serde_json::json!({ "stream": true, "stream_options": "garbage" });
        assert!(super::maybe_inject_stream_usage(&mut body));
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn inject_noop_when_not_streaming() {
        let mut body = serde_json::json!({ "model": "gpt-4o" });
        assert!(!super::maybe_inject_stream_usage(&mut body));
        assert!(body.get("stream_options").is_none());
        // stream:false also no-ops.
        let mut body2 = serde_json::json!({ "stream": false });
        assert!(!super::maybe_inject_stream_usage(&mut body2));
    }

    #[test]
    fn inject_preserves_sibling_stream_options() {
        let mut body = serde_json::json!({
            "stream": true,
            "stream_options": { "some_other_flag": "x" }
        });
        assert!(super::maybe_inject_stream_usage(&mut body));
        assert_eq!(body["stream_options"]["some_other_flag"], "x");
        assert_eq!(body["stream_options"]["include_usage"], true);
    }
}
