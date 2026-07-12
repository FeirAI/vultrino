//! The outbox's PURE in-memory state machine, extracted out of [`super::outbox_store`] so a second
//! persistence layer can reuse it verbatim (plan 088 D0: the averin USE queue, `super::averin_queue`).
//!
//! WHAT moved here: the [`OutboxCache`] model, the monotonic-sequence `push_event` insert, the
//! per-subject head-of-line `earliest_pending_per_subject` scan, and the `record_delivery_transition`
//! success/backoff/dead-letter arithmetic. These are ALL pure functions/data over an in-memory map —
//! no I/O, no locking, no encryption. `OutboxStore` still owns every byte of PERSISTENCE (the
//! whole-file serde+encrypt+tmp+fsync+rename dance) and delegates ONLY the state-machine step to the
//! functions here; behavior is byte-for-byte unchanged (this is a mechanical extraction — see the
//! `outbox_store.rs` call sites and its test suite, which is not touched by this move).
//!
//! WHY a shared module and not a trait/generic: both consumers want the EXACT SAME struct
//! (`BTreeMap<u64, OutboxEvent>` keyed by monotonic sequence, gap-free replay, one-pending-per-subject
//! ordering, exponential-backoff-then-dead-letter delivery semantics) — there is no behavioral axis
//! that varies between the govder outbox and the averin queue, only the PERSISTENCE strategy (whole-
//! file rewrite vs. an append-only delta journal, `docs/dev/OUTBOX-OUT-OF-VAULT-MIGRATION.md §D2` vs
//! plan 088 §D0). A shared plain-data module is simpler than a trait for a model with no behavioral
//! variation.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::outbox::{DeliveryState, OutboxEvent};

/// The in-memory + (when owned by `OutboxStore`) on-disk-serialized outbox state. Reused verbatim as
/// the averin queue's in-memory model (plan 088 D0): "the reused `OutboxCache` map (`BTreeMap<seq,
/// OutboxEvent>`)". Field visibility is `pub(crate)` so both storage-layer consumers can read/mutate
/// directly (mirroring the field access `outbox_store.rs` already did on its own private type before
/// this extraction — no behavior change, only a visibility widening scoped to `crate::storage`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct OutboxCache {
    /// Events keyed by monotonic sequence (BTreeMap → gap-free cursor replay order).
    #[serde(default)]
    pub(crate) outbox: BTreeMap<u64, OutboxEvent>,
    /// The last assigned sequence (monotonic; survives restart so the broker cursor never rewinds).
    #[serde(default)]
    pub(crate) outbox_seq: u64,
}

/// Increment the sequence and insert a fresh Pending event (with an optional intent-drain dedup id).
/// Relocated verbatim from `outbox_store.rs` (originally lifted from `FileStorage`, plus the dedup_id
/// for the v6→v7 intent-staging) — byte-identical logic, only the enclosing module changed.
pub(crate) fn push_event(
    cache: &mut OutboxCache,
    subject: &str,
    event_type: &str,
    payload: serde_json::Value,
    dedup_id: Option<String>,
) -> u64 {
    cache.outbox_seq += 1;
    let seq = cache.outbox_seq;
    cache.outbox.insert(
        seq,
        OutboxEvent {
            sequence: seq,
            subject: subject.to_string(),
            event_type: event_type.to_string(),
            payload,
            created_at: Utc::now(),
            delivery: DeliveryState::Pending,
            attempts: 0,
            leased_until: None,
            last_attempt_at: None,
            last_error: None,
            dedup_id,
        },
    );
    seq
}

/// Earliest still-pending event per subject (per-subject ordering: a later event is withheld until
/// its earlier sibling delivers; a leased earlier event still blocks). Relocated verbatim.
pub(crate) fn earliest_pending_per_subject(
    outbox: &BTreeMap<u64, OutboxEvent>,
    limit: usize,
    respect_lease: bool,
    now: DateTime<Utc>,
) -> Vec<OutboxEvent> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for e in outbox.values() {
        if e.delivery != DeliveryState::Pending {
            continue;
        }
        if !seen.insert(e.subject.as_str()) {
            continue;
        }
        if respect_lease && e.leased_until.is_some_and(|t| t > now) {
            continue;
        }
        out.push(e.clone());
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Apply a delivery outcome to `sequence`'s event in the map: success → `Delivered`; failure →
/// attempts++ with exponential backoff capped at 300s, dead-lettering at `max_attempts`. Only a
/// `Pending` event accepts an outcome — `Delivered`/`DeadLettered` are terminal, so a late/duplicate
/// outcome can't un-deliver or resurrect them. Relocated verbatim from `OutboxStore::record_delivery`'s
/// closure body (`outbox_store.rs:253-281` pre-extraction): identical arithmetic, now taking the map
/// directly instead of closing over `&mut OutboxCache` (both callers pass `&mut cache.outbox`).
///
/// Returns `(dead_lettered_this_call, mutated)` — `mutated` is `false` (no state change) when the
/// sequence is absent or already terminal, matching the pre-extraction "no mutation → no write"
/// contract; `dead_lettered_this_call` is `true` only on the call that actually transitions to
/// `DeadLettered` (never on success or a still-retrying failure), so a caller can log the terminal
/// state exactly once without re-deriving the max-attempts arithmetic.
pub(crate) fn record_delivery_transition(
    outbox: &mut BTreeMap<u64, OutboxEvent>,
    sequence: u64,
    success: bool,
    error: Option<String>,
    max_attempts: u32,
) -> (bool, bool) {
    let Some(e) = outbox.get_mut(&sequence) else {
        return (false, false);
    };
    if e.delivery != DeliveryState::Pending {
        return (false, false);
    }
    e.attempts += 1;
    e.last_attempt_at = Some(Utc::now());
    if success {
        e.delivery = DeliveryState::Delivered;
        e.leased_until = None;
        e.last_error = None;
        return (false, true);
    }
    e.last_error = error;
    if e.attempts >= max_attempts {
        e.delivery = DeliveryState::DeadLettered;
        e.leased_until = None;
        (true, true)
    } else {
        // Exponential-ish backoff lease, capped at 5 min (same as v6).
        let backoff = (10u64.saturating_mul(1 << e.attempts.min(5))).min(300);
        e.leased_until = Some(Utc::now() + chrono::Duration::seconds(backoff as i64));
        (false, true)
    }
}
