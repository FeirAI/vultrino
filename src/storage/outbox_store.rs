//! Outbox store — the signed event log in its OWN encrypted file, split out of the secrets vault
//! (storage v6→v7; design: docs/dev/OUTBOX-OUT-OF-VAULT-MIGRATION.md).
//!
//! WHY this exists: in v6 the outbox lived inside `credentials.enc`, so EVERY event append (frequent)
//! read+decrypted+re-encrypted+rewrote the ENTIRE secrets vault — append/poll cost was O(secrets-vault
//! size) (the throughput cliff). Here the event log gets its own file, so appending an event never
//! touches the secrets file, and a broker poll decrypts only the (retention-bounded) outbox.
//!
//! WHAT it is NOT: the credentials never move and are never exposed — only the agent-safe event log
//! (credential *aliases*/metadata, never secret values) lives here, and per D2 it is ALSO encrypted
//! (same AES-256-GCM master key as the vault — a fresh nonce per write; nothing in plaintext).
//!
//! D3 (sharded per tenant): in the per-tenant-vultrino-shard deployment each vultrino owns ONE outbox
//! file = that tenant's. This store is therefore not partitioned by tenant WITHIN a vultrino (a shared
//! multi-tenant vultrino would add per-tenant files + per-tenant broker cursors — the documented
//! shared-vultrino follow-on, not needed for the sharded path).
//!
//! It reuses the vault's proven persistence: serde_json + `encrypt`/`decrypt` + an exclusive
//! cross-process fd-lock + tmp+atomic-rename + the (mtime,len) read-cache token. The full outbox
//! contract is preserved verbatim: monotonic gap-free sequence, per-subject ordering, lease-based
//! cross-process claim, attempts/backoff/dead-letter, explicit replay, and prefix GC.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use crate::outbox::{DeliveryState, OutboxEvent};
use crate::storage::outbox_model::{
    earliest_pending_per_subject, push_event, record_delivery_transition, OutboxCache,
};
use crate::storage::StorageError;

/// On-disk format version for the OUTBOX file (independent of the vault's STORAGE_VERSION). v1 is the
/// first split-out format. A newer file is refused (binary downgrade guard), mirroring the vault.
const OUTBOX_FILE_VERSION: u32 = 1;

/// The encrypted on-disk envelope. No salt: the key is the vault's already-derived master key
/// (shared via Arc), so the outbox file is decrypted with it directly — no separate KDF.
#[derive(Debug, Serialize, Deserialize)]
struct OutboxFile {
    version: u32,
    data: EncryptedData,
}

/// The signed-outbox store, backed by its own encrypted file.
pub struct OutboxStore {
    path: PathBuf,
    master_key: Arc<MasterKey>,
    cache: RwLock<OutboxCache>,
    /// (mtime,len) of the file as of this process's last decrypt — lets `reload` skip a redundant
    /// decrypt when the file is byte-unchanged (the broker polls frequently). Mirrors FileStorage.
    last_loaded: Mutex<Option<(SystemTime, u64)>>,
    /// Failed appends not yet announced by a gap marker (VUL-02).
    loss: Mutex<LossState>,
    lost_total: AtomicU64,
    markers_emitted: AtomicU64,
    /// Events pruned by the count cap since this process started (never reset).
    cap_pruned_total: AtomicU64,
    /// The subset of those that were not Delivered, i.e. not acked by the push target (govder). In
    /// poll-only mode (`outbox.enabled = false`) nothing is ever Delivered, so every prune counts
    /// here. Vultrino cannot tell whether a poller (leria) read an event; a Delivered event may
    /// still be unread by leria.
    cap_pruned_undelivered_total: AtomicU64,
    /// GC passes in which the cap wanted to prune but its oldest event was protected by a staged
    /// intent, so it pruned less than the excess (or nothing).
    cap_blocked_total: AtomicU64,
    /// True once this process has read the outbox file (or written it) successfully, so the
    /// retention snapshot is not the empty never-loaded cache.
    loaded_once: AtomicBool,
}

/// What one GC pass pruned.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcOutcome {
    /// Delivered events pruned by the retention window.
    pub age_pruned: usize,
    /// Events pruned by the count cap.
    pub cap: CapPruned,
    /// The cap wanted to prune more than it could because the oldest remaining event is
    /// protected by a staged intent that was not cleared.
    pub cap_blocked: bool,
}

impl GcOutcome {
    pub fn total(&self) -> usize {
        self.age_pruned + self.cap.pruned
    }
}

/// Events pruned by the count cap in one pass, counted by delivery state and event type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CapPruned {
    pub pruned: usize,
    /// Keys: `pending`, `delivered`, `dead_lettered`.
    pub by_state: std::collections::BTreeMap<String, u64>,
    pub by_type: std::collections::BTreeMap<String, u64>,
}

impl CapPruned {
    fn record(&mut self, e: &OutboxEvent) {
        self.pruned += 1;
        let state = match e.delivery {
            DeliveryState::Pending => "pending",
            DeliveryState::Delivered => "delivered",
            DeliveryState::DeadLettered => "dead_lettered",
        };
        *self.by_state.entry(state.to_string()).or_insert(0) += 1;
        *self.by_type.entry(e.event_type.clone()).or_insert(0) += 1;
    }

    /// Pruned events the push target had not acked (not Delivered). This is a delivery state, not
    /// a read state: vultrino cannot tell whether a poller read an event.
    pub fn undelivered(&self) -> usize {
        self.pruned
            .saturating_sub(self.by_state.get("delivered").copied().unwrap_or(0) as usize)
    }
}

/// Failed appends waiting for the next successful append to carry a `meter.lost` marker.
#[derive(Default, Clone)]
struct LossState {
    count: u64,
    first: Option<chrono::DateTime<Utc>>,
    last: Option<chrono::DateTime<Utc>>,
    types: std::collections::BTreeSet<String>,
}

impl LossState {
    fn absorb(&mut self, other: LossState) {
        self.count += other.count;
        self.first = match (self.first, other.first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.last = match (self.last, other.last) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.types.extend(other.types);
    }
}

impl OutboxStore {
    /// Open (lazily) an outbox store at `path`, encrypting with the shared vault master key. The file
    /// is created on first write; an absent file reads as empty.
    pub fn new(path: PathBuf, master_key: Arc<MasterKey>) -> Self {
        Self {
            path,
            master_key,
            cache: RwLock::new(OutboxCache::default()),
            last_loaded: Mutex::new(None),
            loss: Mutex::new(LossState::default()),
            lost_total: AtomicU64::new(0),
            markers_emitted: AtomicU64::new(0),
            cap_pruned_total: AtomicU64::new(0),
            cap_pruned_undelivered_total: AtomicU64::new(0),
            cap_blocked_total: AtomicU64::new(0),
            loaded_once: AtomicBool::new(false),
        }
    }

    /// Count one failed append (VUL-02). Called for every `Err` from an event append, so a
    /// full disk is a number on `/api/v1/health` and `/api/v1/posture`, not a log line.
    fn record_loss(&self, event_type: &str) {
        let now = Utc::now();
        self.lost_total.fetch_add(1, Ordering::Relaxed);
        let mut loss = self.loss.lock();
        loss.count += 1;
        loss.first.get_or_insert(now);
        loss.last = Some(now);
        if loss.types.len() < crate::outbox::METER_LOST_MAX_TYPES {
            loss.types.insert(event_type.to_string());
        }
    }

    /// After a successful append, announce any unannounced failures with one `meter.lost`
    /// event. If the marker append itself fails the counts are put back (and are not
    /// counted a second time), so the next success retries it.
    async fn flush_loss_marker(&self) {
        let taken = {
            let mut loss = self.loss.lock();
            if loss.count == 0 {
                return;
            }
            std::mem::take(&mut *loss)
        };
        let (Some(first), Some(last)) = (taken.first, taken.last) else {
            return;
        };
        let types: Vec<String> = taken.types.iter().cloned().collect();
        let payload = crate::outbox::meter_lost_payload(taken.count, first, last, &types);
        let result = self
            .locked_mutate(move |c| {
                Ok((
                    push_event(c, "meter", crate::outbox::EVENT_METER_LOST, payload, None),
                    true,
                ))
            })
            .await;
        match result {
            Ok(_) => {
                self.markers_emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to append meter.lost gap marker; will retry on the next successful append");
                self.loss.lock().absorb(taken);
            }
        }
    }

    /// Point-in-time append-loss counters.
    pub fn loss_snapshot(&self) -> crate::outbox::MeterLossSnapshot {
        let loss = self.loss.lock();
        crate::outbox::MeterLossSnapshot {
            lost_total: self.lost_total.load(Ordering::Relaxed),
            gap_pending: loss.count,
            markers_emitted: self.markers_emitted.load(Ordering::Relaxed),
            last_lost_at: loss.last,
        }
    }

    // ---- public API (the relocated outbox contract; FileStorage delegates the trait methods here) ----

    /// Append a NEW event under the lock, assigning the next monotonic sequence; return it.
    pub async fn append(
        &self,
        subject: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StorageError> {
        let subject = subject.to_string();
        let event_type = event_type.to_string();
        let ty = event_type.clone();
        // A fresh append always mutates.
        let result = self
            .locked_mutate(move |c| Ok((push_event(c, &subject, &event_type, payload, None), true)))
            .await;
        match &result {
            Ok(_) => self.flush_loss_marker().await,
            Err(_) => self.record_loss(&ty),
        }
        result
    }

    /// Append an event drained from the vault's intent staging (D1), IDEMPOTENTLY: if an event with
    /// this `dedup_id` already exists (a re-drain after a crash between the append and clearing the
    /// vault intent), return its existing sequence WITHOUT inserting a duplicate. Otherwise append a
    /// fresh event tagged with the id. This is what makes the two-store (vault↔outbox) drain
    /// exactly-once despite the lack of a cross-store transaction.
    pub async fn append_deduped(
        &self,
        dedup_id: &str,
        subject: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StorageError> {
        let dedup_id = dedup_id.to_string();
        let subject = subject.to_string();
        let event_type = event_type.to_string();
        self.locked_mutate(move |c| {
            // Scan for a prior event with this dedup id (only the rare drained-event path pays this;
            // ordinary appends carry no dedup_id). The outbox is retention-bounded, so the scan is small.
            if let Some(e) = c
                .outbox
                .values()
                .find(|e| e.dedup_id.as_deref() == Some(dedup_id.as_str()))
            {
                return Ok((e.sequence, false)); // already drained → idempotent no-op, no write
            }
            Ok((
                push_event(c, &subject, &event_type, payload, Some(dedup_id)),
                true,
            ))
        })
        .await
    }

    /// Insert an event that ALREADY has a sequence (the v6→v7 migration: in-vault events keep their
    /// original sequence so the broker cursor doesn't rewind/gap). `outbox_seq` advances to the max
    /// so subsequent appends stay monotonic. Idempotent on the sequence (re-drain is safe).
    pub async fn insert_event(&self, event: OutboxEvent) -> Result<(), StorageError> {
        self.locked_mutate(move |c| {
            c.outbox_seq = c.outbox_seq.max(event.sequence);
            c.outbox.entry(event.sequence).or_insert(event);
            // Migration/idempotent insert — persist unconditionally (safe over-report of dirty).
            Ok(((), true))
        })
        .await
    }

    /// Batch variant of [`insert_event`] for the v6→v7 migration: RESERVES the whole legacy sequence
    /// range up front — it advances `outbox_seq` to the batch max in the SAME locked write that inserts
    /// the events, BEFORE any insert. This closes the (D4-out-of-scope) multi-process-open-of-a-v6-vault
    /// race where, if the events were inserted one-at-a-time, a concurrent direct `append` between two
    /// inserts could allocate a sequence a not-yet-migrated legacy event still owns — and `entry().
    /// or_insert` would then silently DROP that legacy event. With the range reserved first, a
    /// concurrent append always allocates strictly above the migrated range. Idempotent on each
    /// sequence, and a single re-encrypt+write instead of one per event.
    pub async fn insert_events_preserving_seq(
        &self,
        events: Vec<OutboxEvent>,
    ) -> Result<(), StorageError> {
        if events.is_empty() {
            return Ok(());
        }
        self.locked_mutate(move |c| {
            for ev in &events {
                c.outbox_seq = c.outbox_seq.max(ev.sequence);
            }
            for ev in events {
                c.outbox.entry(ev.sequence).or_insert(ev);
            }
            // Migration batch (guarded by the empty-check above) — always persist.
            Ok(((), true))
        })
        .await
    }

    /// Events with sequence > `after`, ascending, up to `limit` — the gap-free replay cursor.
    pub async fn list_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<OutboxEvent>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(c.outbox
            .range((after + 1)..)
            .take(limit)
            .map(|(_, e)| e.clone())
            .collect())
    }

    /// [`Self::list_after`] plus the retention snapshot, both taken from ONE read of the cache, so
    /// the unsigned hints on the events envelope cannot be skewed against the page by a concurrent
    /// append or GC in this process.
    pub async fn list_after_with_retention(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<OutboxEvent>, crate::outbox::OutboxRetentionSnapshot), StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        let page = c
            .outbox
            .range((after + 1)..)
            .take(limit)
            .map(|(_, e)| e.clone())
            .collect();
        Ok((page, self.snapshot_of(&c)))
    }

    /// Earliest-pending event per subject (read-only peek; no claim).
    pub async fn deliverable(&self, limit: usize) -> Result<Vec<OutboxEvent>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(earliest_pending_per_subject(
            &c.outbox,
            limit,
            false,
            Utc::now(),
        ))
    }

    /// Claim the earliest-pending event per subject for delivery, stamping a lease so a sibling
    /// process won't double-deliver. Atomic claim+lease under the fd-lock.
    pub async fn claim(
        &self,
        limit: usize,
        lease_secs: u64,
    ) -> Result<Vec<OutboxEvent>, StorageError> {
        self.locked_mutate(move |c| {
            let now = Utc::now();
            let claimed = earliest_pending_per_subject(&c.outbox, limit, true, now);
            // No claim → no lease stamped → nothing mutated → skip the file write (vultrino#1: the
            // common every-5s delivery-tick no-op on an empty/all-delivered outbox).
            let dirty = !claimed.is_empty();
            // Floor at 1s + CLAMP, never panic (mirror gc's overflow-safe pattern): a 0 lease would stamp
            // leased_until==now, which earliest_pending_per_subject (t > now) treats as already-expired →
            // a sibling re-claims the same event = double delivery. A huge lease_secs must NOT panic
            // (chrono::Duration::seconds + DateTime add both panic out of range) — clamp to ~1 year and
            // fall back to `now` only if even that overflows. The lease is the ONLY cross-process
            // at-most-once guard, so it must always produce a valid future instant.
            let secs = lease_secs.clamp(1, 31_556_952) as i64; // [1s, ~1y]
            let lease_until = chrono::Duration::try_seconds(secs)
                .and_then(|d| now.checked_add_signed(d))
                .unwrap_or(now);
            for e in &claimed {
                if let Some(stored) = c.outbox.get_mut(&e.sequence) {
                    stored.leased_until = Some(lease_until);
                }
            }
            // Return the claimed events with the lease reflected (callers don't re-read the lease).
            let out: Vec<OutboxEvent> = claimed
                .into_iter()
                .map(|mut e| {
                    e.leased_until = Some(lease_until);
                    e
                })
                .collect();
            Ok((out, dirty))
        })
        .await
    }

    /// Record a delivery attempt: success → Delivered; failure → retry-with-backoff or dead-letter at
    /// max_attempts. Only a Pending (claimed) event accepts an outcome (Delivered/DeadLettered are
    /// terminal — a late/duplicate outcome can't un-deliver or resurrect them).
    ///
    /// Returns whether THIS call transitioned the event to `DeadLettered` (observability item 4 / #3),
    /// so the caller can log the terminal state exactly once, at the call site, without re-deriving the
    /// max-attempts arithmetic (keeps logging out of the storage layer per that item's design).
    pub async fn record_delivery(
        &self,
        sequence: u64,
        success: bool,
        error: Option<String>,
        max_attempts: u32,
    ) -> Result<bool, StorageError> {
        self.locked_mutate(move |c| {
            // Not found, or a late outcome against an already-terminal event → no mutation, no write.
            // (record_delivery_transition, extracted verbatim to `outbox_model` — plan 088 D0 — so the
            // averin durable queue reuses the identical success/backoff/dead-letter arithmetic.)
            let (dead_lettered, dirty) =
                record_delivery_transition(&mut c.outbox, sequence, success, error, max_attempts);
            Ok((dead_lettered, dirty))
        })
        .await
    }

    /// Dead-lettered events (read-only).
    pub async fn list_dead_letter(&self, limit: usize) -> Result<Vec<OutboxEvent>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(c.outbox
            .values()
            .filter(|e| e.delivery == DeliveryState::DeadLettered)
            .take(limit)
            .cloned()
            .collect())
    }

    /// Re-queue a dead-lettered event to Pending (operator-initiated replay). Returns whether it acted.
    pub async fn replay_dead_letter(&self, sequence: u64) -> Result<bool, StorageError> {
        self.locked_mutate(move |c| match c.outbox.get_mut(&sequence) {
            Some(e) if e.delivery == DeliveryState::DeadLettered => {
                e.delivery = DeliveryState::Pending;
                e.attempts = 0;
                e.last_error = None;
                e.leased_until = None;
                Ok((true, true))
            }
            // Not dead-lettered (or absent) → no change, no write.
            _ => Ok((false, false)),
        })
        .await
    }

    /// Age-only GC (no count cap): see [`Self::gc_capped`]. Kept for callers and tests that
    /// exercise the delivered-age prune on its own. Returns the count pruned.
    pub async fn gc(
        &self,
        retention_secs: u64,
        protected_dedup_ids: &HashSet<String>,
    ) -> Result<usize, StorageError> {
        Ok(self
            .gc_capped(retention_secs, usize::MAX, protected_dedup_ids)
            .await?
            .total())
    }

    /// Prune a contiguous PREFIX of events (by sequence, so the retained suffix is gap-free
    /// regardless of clock skew), in two stages inside ONE locked write:
    ///
    /// 1. Age: events older than the retention window that are Delivered (below the cap, an
    ///    undelivered event is never pruned: vultrino#4, fail-closed).
    /// 2. Cap: if more than `max_retained` events remain, the OLDEST ones beyond the cap are
    ///    pruned whatever their delivery state. This bounds the per-operation cost, which is
    ///    O(retained) because every mutation rewrites the whole file. The loss is counted by state
    ///    and type, logged at ERROR, and visible to a poller as a sequence hole.
    ///
    /// `protected_dedup_ids` are the dedup_ids of vault-side intents NOT yet cleared: an outbox event
    /// carrying such a dedup_id is NEVER pruned by either stage (the prefix prune STOPS below it), so
    /// its dedup record outlives the intent. Without that, a re-drain would re-append the same
    /// logical event with a fresh sequence (a phantom duplicate).
    pub async fn gc_capped(
        &self,
        retention_secs: u64,
        max_retained: usize,
        protected_dedup_ids: &HashSet<String>,
    ) -> Result<GcOutcome, StorageError> {
        // Overflow-safe: a huge retention_secs would panic `Utc::now() - Duration::seconds(secs)`
        // (chrono DateTime add overflow). Use checked arithmetic; an un-representable cutoff means
        // "the window is effectively infinite" -> the age stage prunes nothing (the cap still applies).
        let secs = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        let cutoff =
            chrono::Duration::try_seconds(secs).and_then(|d| Utc::now().checked_sub_signed(d));
        // Clone into the (move) closure; the protected set is small (only undrained intents, normally 0).
        let protected = protected_dedup_ids.clone();
        let outcome = self
            .locked_mutate(move |c| {
                let is_protected =
                    |e: &OutboxEvent| e.dedup_id.as_deref().is_some_and(|d| protected.contains(d));
                let mut out = GcOutcome::default();

                if let Some(cutoff) = cutoff {
                    // Stage 1: stop at the first event that is young, NOT YET DELIVERED, or still
                    // protected by a staged intent. Retention is the *delivered*-replay window.
                    let prune_below = c
                        .outbox
                        .iter()
                        .take_while(|(_, e)| {
                            e.created_at < cutoff
                                && e.delivery == DeliveryState::Delivered
                                && !is_protected(e)
                        })
                        .map(|(seq, _)| *seq)
                        .last();

                    // Bounded-growth alarm: events retained PAST the window solely because they are
                    // undelivered (delivery stalled; the cap below bounds the growth).
                    let stuck_undelivered = c
                        .outbox
                        .values()
                        .filter(|e| e.created_at < cutoff && e.delivery != DeliveryState::Delivered)
                        .count();
                    if stuck_undelivered > 0 {
                        tracing::warn!(
                            count = stuck_undelivered,
                            "outbox retains events older than the retention window because they are undelivered \
                             (pending/dead-lettered); delivery may be stalled and the log grows until the retention cap"
                        );
                    }
                    if let Some(below) = prune_below {
                        let before = c.outbox.len();
                        c.outbox.retain(|seq, _| *seq > below);
                        out.age_pruned = before - c.outbox.len();
                    }
                }

                // Stage 2: the count cap, over what the age stage left.
                let excess = c.outbox.len().saturating_sub(max_retained);
                if excess > 0 {
                    let doomed: Vec<u64> = c
                        .outbox
                        .iter()
                        .take(excess)
                        .take_while(|(_, e)| !is_protected(e))
                        .map(|(seq, _)| *seq)
                        .collect();
                    out.cap_blocked = doomed.len() < excess;
                    for seq in doomed {
                        if let Some(e) = c.outbox.remove(&seq) {
                            out.cap.record(&e);
                        }
                    }
                }
                let dirty = out.total() > 0;
                Ok((out, dirty))
            })
            .await?;
        if outcome.cap_blocked {
            self.cap_blocked_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                max_retained,
                pruned = outcome.cap.pruned,
                "outbox retention cap could not prune to the cap: the oldest retained event is protected \
                 by a staged intent that was never cleared, so the outbox keeps growing; check the vault-side \
                 intent clear (retained_events above max_retained_events in posture)"
            );
        }
        if outcome.cap.pruned > 0 {
            self.cap_pruned_total
                .fetch_add(outcome.cap.pruned as u64, Ordering::Relaxed);
            self.cap_pruned_undelivered_total
                .fetch_add(outcome.cap.undelivered() as u64, Ordering::Relaxed);
            let undelivered = outcome.cap.undelivered();
            if undelivered > 0 {
                tracing::error!(
                    pruned = outcome.cap.pruned,
                    undelivered,
                    max_retained,
                    by_state = ?outcome.cap.by_state,
                    by_type = ?outcome.cap.by_type,
                    "outbox retention cap pruned events the push target had not acked (in poll-only mode \
                     every prune counts as undelivered); a consumer that had not read them sees a sequence hole"
                );
            } else {
                tracing::info!(
                    pruned = outcome.cap.pruned,
                    max_retained,
                    by_type = ?outcome.cap.by_type,
                    "outbox retention cap pruned delivered events (acked by the push target); a poller that \
                     had not read them sees a sequence hole"
                );
            }
        }
        Ok(outcome)
    }

    /// Retention view for posture, metrics and the events envelope. Reads the in-memory cache
    /// (refreshed by every operation of this process and by the delivery loop). A process that has
    /// not yet touched the outbox (the file opens lazily) loads it once here, so the view is not a
    /// healthy-looking empty cache; if that load fails, `loaded` is false and the other fields are
    /// not to be trusted.
    pub fn retention_snapshot(&self) -> crate::outbox::OutboxRetentionSnapshot {
        if !self.loaded_once.load(Ordering::Acquire) {
            use tokio::runtime::{Handle, RuntimeFlavor};
            let r = match Handle::try_current().map(|h| h.runtime_flavor()) {
                Ok(RuntimeFlavor::MultiThread) => {
                    tokio::task::block_in_place(|| self.reload_blocking())
                }
                _ => self.reload_blocking(),
            };
            if let Err(e) = r {
                tracing::warn!(error = %e, "outbox retention snapshot could not load the outbox file");
            }
        }
        let c = self.cache.read();
        self.snapshot_of(&c)
    }

    fn snapshot_of(&self, c: &OutboxCache) -> crate::outbox::OutboxRetentionSnapshot {
        crate::outbox::OutboxRetentionSnapshot {
            loaded: self.loaded_once.load(Ordering::Acquire),
            retained_events: c.outbox.len() as u64,
            oldest_sequence: c.outbox.keys().next().copied(),
            last_sequence: c.outbox_seq,
            cap_pruned_total: self.cap_pruned_total.load(Ordering::Relaxed),
            cap_pruned_undelivered_total: self.cap_pruned_undelivered_total.load(Ordering::Relaxed),
            cap_blocked_total: self.cap_blocked_total.load(Ordering::Relaxed),
        }
    }

    // ---- internal persistence (mirrors FileStorage's locked_mutate / reload on the outbox file) ----

    /// The closure returns `(value, dirty)`: `dirty` MUST be true whenever it mutated the cache in a
    /// way that needs persisting, and may be false for a genuine no-op (nothing claimed / pruned /
    /// found). Only a dirty result writes the file — this kills the every-tick no-op whole-file
    /// re-encrypt+fsync that claim()/gc() otherwise did each delivery/GC pass with nothing to do
    /// (vultrino#1 stopgap). Over-reporting dirty is always safe (a redundant durable write);
    /// under-reporting would silently drop a mutation, so any uncertain path returns `true`.
    ///
    /// This is a STOPGAP for the whole-file write amplification, NOT the O(1) append: a real append
    /// still re-encrypts the entire retention-bounded outbox. True per-row append is a deferred
    /// design item — it re-opens the settled D2 "outbox.enc, not per-row/SQLite" decision (see
    /// docs/dev/OUTBOX-OUT-OF-VAULT-MIGRATION.md §D2), so it is an architecture change, not this fix.
    async fn locked_mutate<T>(
        &self,
        f: impl FnOnce(&mut OutboxCache) -> Result<(T, bool), StorageError>,
    ) -> Result<T, StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.locked_mutate_blocking(f),
            _ => tokio::task::block_in_place(|| self.locked_mutate_blocking(f)),
        }
    }

    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut OutboxCache) -> Result<(T, bool), StorageError>,
    ) -> Result<T, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        let mut cache = self.read_from_disk()?;
        let (result, dirty) = f(&mut cache)?;
        // Skip the write ENTIRELY on a no-op (no re-encrypt, no tmp+fsync, no rename) — a real
        // mutation still takes the full crash-durable write path below. The in-memory cache is
        // refreshed either way (we just re-read authoritative disk state under the lock).
        if dirty {
            self.write_to_disk(&cache)?;
        }
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
        self.loaded_once.store(true, Ordering::Release);
        Ok(result)
    }

    /// Refresh the in-memory cache from disk (picks up a sibling process's appends). Skips the
    /// decrypt when the file is byte-unchanged since this process last loaded it. Takes the SAME
    /// exclusive lock as locked_mutate so a committed write is never clobbered by a stale read.
    async fn reload(&self) -> Result<(), StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.reload_blocking(),
            _ => tokio::task::block_in_place(|| self.reload_blocking()),
        }
    }

    fn reload_blocking(&self) -> Result<(), StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        if let Some(token) = self.file_change_token() {
            if *self.last_loaded.lock() == Some(token) {
                self.loaded_once.store(true, Ordering::Release);
                return Ok(());
            }
        }
        let cache = self.read_from_disk()?;
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
        self.loaded_once.store(true, Ordering::Release);
        Ok(())
    }

    fn lock_file_exclusive(&self) -> Result<fd_lock::RwLock<std::fs::File>, StorageError> {
        let lock_path = self.path.with_extension("lock");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        // Owner-only sidecar (0600), consistent with the data file it guards.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let lock_file = opts.open(&lock_path)?;
        Ok(fd_lock::RwLock::new(lock_file))
    }

    fn read_from_disk(&self) -> Result<OutboxCache, StorageError> {
        if !self.path.exists() {
            return Ok(OutboxCache::default());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let file: OutboxFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        if file.version > OUTBOX_FILE_VERSION {
            return Err(StorageError::UnsupportedVersion {
                found: file.version,
                supported: OUTBOX_FILE_VERSION,
            });
        }
        let plaintext = decrypt(&file.data, &self.master_key)?;
        serde_json::from_slice(&plaintext).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    fn write_to_disk(&self, cache: &OutboxCache) -> Result<(), StorageError> {
        // Create the parent dir lazily (self-contained: don't assume the vault's FileStorage::new ran
        // first — it usually has in the shared-dir deployment, but the outbox file may be on its own PVC).
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data =
            serde_json::to_vec(cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, &self.master_key)?;
        let file = OutboxFile {
            version: OUTBOX_FILE_VERSION,
            data: encrypted,
        };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let temp_path = self.path.with_extension("tmp");
        // fsync the tmp BEFORE the rename: the rename gives crash-ATOMICITY of the directory entry (a
        // reader sees the old OR the new file, never a torn one), but only sync_all guarantees the
        // CONTENTS are durable — without it a power-loss can make the rename visible while the tmp bytes
        // are not yet flushed, leaving a corrupt outbox.enc. This path runs on EVERY append, so the crash
        // window matters here far more than for the rare vault writes.
        {
            // 0600: the outbox is encrypted but is a sensitive signed record — don't
            // leave it group/world-readable. The temp's mode carries to the final file
            // through the rename below.
            let f = create_private_file(&temp_path)?;
            use std::io::Write;
            let mut w = std::io::BufWriter::new(f);
            w.write_all(content.as_bytes())?;
            w.flush()?;
            w.into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?
                .sync_all()?;
        }
        std::fs::rename(&temp_path, &self.path)?;
        // Make the rename crash-DURABLE (not just crash-atomic). A REAL fsync error is PROPAGATED so the
        // caller treats the append as failed and does NOT clear the vault-side intent over a non-durable
        // write (which would lose the signed event on a power-loss). See fsync_parent_dir.
        fsync_parent_dir(&self.path)?;
        Ok(())
    }

    fn file_change_token(&self) -> Option<(SystemTime, u64)> {
        let meta = std::fs::metadata(&self.path).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }

    // ---- offline vault re-key (FileStorage::rekey delegates the outbox half here) ----

    /// Prepare the outbox half of an offline vault re-key: under the outbox fd-lock, decrypt the file
    /// with the CURRENT (shared) master key and write a `.rekey.tmp` re-encrypted with `new_key`,
    /// fsynced but NOT yet renamed. Returns the tmp path for the caller to commit (via
    /// [`Self::rekey_commit`]) so the vault + outbox renames run back-to-back — shrinking the two-file
    /// non-atomicity window. Returns `Ok(None)` when no outbox file exists yet (nothing to re-encrypt).
    /// [`OUTBOX_FILE_VERSION`] is PRESERVED — a re-key rotates the key, never the format. On any error
    /// the live outbox file is left untouched (fail-closed).
    pub(super) fn rekey_prepare(
        &self,
        new_key: &MasterKey,
    ) -> Result<Option<PathBuf>, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        if !self.path.exists() {
            return Ok(None); // no outbox yet → nothing to re-encrypt
        }
        // Decrypt with the OLD (shared) master key still held by this process.
        let cache = self.read_from_disk()?;
        let data =
            serde_json::to_vec(&cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, new_key)?;
        let file = OutboxFile {
            version: OUTBOX_FILE_VERSION, // PRESERVED — key changes, format does not
            data: encrypted,
        };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let tmp = self.path.with_extension("rekey.tmp");
        // fsync the tmp BEFORE returning so the re-encrypted bytes are durable before the caller's
        // rename makes them visible (same crash discipline as write_to_disk).
        {
            let f = create_private_file(&tmp)?;
            use std::io::Write;
            let mut w = std::io::BufWriter::new(f);
            w.write_all(content.as_bytes())?;
            w.flush()?;
            w.into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?
                .sync_all()?;
        }
        Ok(Some(tmp))
    }

    /// Commit the outbox half of an offline vault re-key: atomically rename the `.rekey.tmp` from
    /// [`Self::rekey_prepare`] over the live outbox file and fsync the parent directory.
    pub(super) fn rekey_commit(&self, tmp: &Path) -> Result<(), StorageError> {
        std::fs::rename(tmp, &self.path)?;
        fsync_parent_dir(&self.path)?;
        Ok(())
    }
}

/// fsync the parent directory of `path` after an atomic rename, making the new directory entry
/// crash-DURABLE (rename alone is only crash-atomic — a power-loss right after it can revert the entry
/// to the old file). A REAL fsync failure is RETURNED so the caller does not treat a non-durable write
/// as committed (clearing a vault intent after a non-durable outbox append loses the signed event). Only
/// an explicitly-unsupported directory fsync (some filesystems return ENOTSUP/EINVAL) is downgraded to a
/// loud warning, since on those filesystems the durability cannot be upgraded anyway. Shared by the
/// outbox + vault write paths (see file.rs::write_cache_to_disk_sync).
pub(super) fn fsync_parent_dir(path: &Path) -> Result<(), StorageError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // Opening a directory HANDLE that fails (e.g. Windows std, which does not pass
    // FILE_FLAG_BACKUP_SEMANTICS, returns PermissionDenied) is best-effort: a dir we cannot open we
    // cannot fsync — identical to an unsupported dir fsync, and propagating it would hard-fail every
    // write on such a platform for ZERO durability gain. Only a real sync_all I/O error (EIO) propagates.
    let dir = match std::fs::File::open(parent) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(dir = %parent.display(), error = %e,
                "could not open the parent directory to fsync it — the renamed file is crash-atomic but not crash-durable on this platform");
            return Ok(());
        }
    };
    match dir.sync_all() {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
            ) =>
        {
            tracing::warn!(dir = %parent.display(), error = %e,
                "parent-directory fsync unsupported on this filesystem — the renamed file is crash-atomic but not crash-durable");
            Ok(())
        }
        Err(e) => Err(StorageError::Io(e)),
    }
}

/// Create (or truncate) `path` for writing with **owner-only** permissions
/// (`0600`) on Unix, so the encrypted vault (`credentials.enc` — holds the salt
/// for offline Argon2 attack) and the signed outbox (`outbox.enc`) are never
/// left group/world-readable under a permissive umask (022 → 0644). The mode is
/// applied at CREATE time via `OpenOptions.mode`, so the bits are correct from the
/// first byte written — there is no window where a fresh file exists world-readable
/// before a later chmod. Because these files are persisted via a temp-file +
/// atomic rename, the renamed temp's `0600` becomes the final file's mode (rename
/// carries the source inode's perms), tightening even a pre-existing loose file on
/// the next save. On non-Unix platforms this is a plain create (Windows ACLs are
/// not modeled here). Semantics otherwise match `std::fs::File::create`.
pub(super) fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;

    fn store() -> (OutboxStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        (OutboxStore::new(dir.path().join("outbox.enc"), key), dir)
    }

    #[tokio::test]
    async fn monotonic_append_gapfree_replay_and_survives_reopen() {
        let (s, dir) = store();
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let s1 = s
            .append("a", "t", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        let s2 = s
            .append("b", "t", serde_json::json!({"n": 2}))
            .await
            .unwrap();
        let s3 = s
            .append("a", "t", serde_json::json!({"n": 3}))
            .await
            .unwrap();
        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(
            s.list_after(0, 100)
                .await
                .unwrap()
                .iter()
                .map(|e| e.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            s.list_after(2, 100)
                .await
                .unwrap()
                .iter()
                .map(|e| e.sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(s.list_after(0, 1).await.unwrap().len(), 1);
        // A FRESH store on the SAME file (restart) replays everything — the seq does not rewind.
        let s2store = OutboxStore::new(dir.path().join("outbox.enc"), key);
        assert_eq!(s2store.list_after(0, 100).await.unwrap().len(), 3);
        let s4 = s2store
            .append("c", "t", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(s4, 4, "seq continues monotonically after a reopen");
    }

    #[tokio::test]
    async fn per_subject_ordering_withholds_later_events() {
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap();
        s.append("B", "t", serde_json::json!({})).await.unwrap();
        s.append("A", "t", serde_json::json!({})).await.unwrap(); // A's 2nd, withheld
        let d = s.deliverable(10).await.unwrap();
        let subjects: Vec<_> = d.iter().map(|e| e.subject.as_str()).collect();
        assert_eq!(
            subjects,
            vec!["A", "B"],
            "one per subject; A's 2nd withheld"
        );
        assert_eq!(d[0].sequence, 1);
    }

    #[tokio::test]
    async fn claim_leases_and_blocks_re_claim() {
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap();
        let first = s.claim(10, 100).await.unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].leased_until.is_some());
        // A second claim sees the live lease and returns nothing (no double-delivery).
        assert_eq!(s.claim(10, 100).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn dead_letter_after_max_then_replay() {
        let (s, _d) = store();
        let seq = s.append("A", "t", serde_json::json!({})).await.unwrap();
        // record_delivery targets by sequence + acts on any Pending event (it does NOT consult the
        // backoff lease), so 3 straight failures reach DeadLettered with no lease-clearing needed.
        // Its bool return (observability item 4 / #3) is false for the first two (still retrying)
        // and true only on the call that actually transitions to DeadLettered.
        for i in 0..3 {
            let dead_lettered = s
                .record_delivery(seq, false, Some("boom".into()), 3)
                .await
                .unwrap();
            assert_eq!(
                dead_lettered,
                i == 2,
                "dead-letter transition reported only on the 3rd (max-attempts) call"
            );
        }
        assert_eq!(
            s.list_dead_letter(10).await.unwrap().len(),
            1,
            "dead-lettered after 3 attempts"
        );
        assert!(s.replay_dead_letter(seq).await.unwrap());
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 0);
        assert_eq!(
            s.deliverable(10).await.unwrap().len(),
            1,
            "replayed → pending again"
        );
    }

    #[tokio::test]
    async fn record_success_marks_delivered_terminal() {
        let (s, _d) = store();
        let seq = s.append("A", "t", serde_json::json!({})).await.unwrap();
        s.record_delivery(seq, true, None, 8).await.unwrap();
        assert_eq!(
            s.deliverable(10).await.unwrap().len(),
            0,
            "delivered → not deliverable"
        );
        // A late duplicate outcome cannot un-deliver it.
        s.record_delivery(seq, false, Some("late".into()), 8)
            .await
            .unwrap();
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn gc_prunes_old_prefix() {
        let (s, _d) = store();
        let a = s.append("A", "t", serde_json::json!({})).await.unwrap();
        let b = s.append("B", "t", serde_json::json!({})).await.unwrap();
        // Deliver both: retention only prunes DELIVERED events now (undelivered are kept, #4).
        s.record_delivery(a, true, None, 8).await.unwrap();
        s.record_delivery(b, true, None, 8).await.unwrap();
        assert_eq!(
            s.gc(0, &HashSet::new()).await.unwrap(),
            2,
            "retention 0 prunes all delivered"
        );
        assert_eq!(s.list_after(0, 100).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn gc_protects_staged_dedup_ids_and_keeps_suffix_gapfree() {
        // F2: an event whose dedup_id is still staged in the vault must NOT be pruned (else a re-drain
        // after the prune would duplicate it). The prefix prune stops BELOW the first protected event,
        // keeping the retained suffix gap-free.
        let (s, _d) = store();
        let s1 = s.append("A", "t", serde_json::json!({})).await.unwrap(); // seq 1, no dedup
        let s2 = s
            .append_deduped("d2", "B", "t", serde_json::json!({}))
            .await
            .unwrap(); // seq 2, dedup d2
        let s3 = s.append("C", "t", serde_json::json!({})).await.unwrap(); // seq 3, no dedup
                                                                           // Deliver all three so age-based pruning is eligible (undelivered are never pruned, #4); the
                                                                           // protected-dedup stop is orthogonal to delivery state.
        s.record_delivery(s1, true, None, 8).await.unwrap();
        s.record_delivery(s2, true, None, 8).await.unwrap();
        s.record_delivery(s3, true, None, 8).await.unwrap();
        let mut protected = HashSet::new();
        protected.insert("d2".to_string());
        // retention 0 would prune all, but d2 (seq 2) is protected → only seq 1 prunes.
        assert_eq!(
            s.gc(0, &protected).await.unwrap(),
            1,
            "prune stops below the protected event"
        );
        let remaining: Vec<u64> = s
            .list_after(0, 100)
            .await
            .unwrap()
            .iter()
            .map(|e| e.sequence)
            .collect();
        assert_eq!(
            remaining,
            vec![2, 3],
            "protected event + suffix retained, gap-free"
        );
        // Once the intent clears (no longer protected), the next GC prunes it.
        assert_eq!(
            s.gc(0, &HashSet::new()).await.unwrap(),
            2,
            "unprotected → pruned"
        );
    }

    #[tokio::test]
    async fn gc_below_the_cap_never_prunes_an_undelivered_pending_event() {
        // Below the count cap (`gc` is the age stage alone, no cap).
        // vultrino#4 (fail-closed): retention is the DELIVERED replay window. An old still-Pending
        // event carries an unshipped signed record, so the prefix prune must STOP below it — and the
        // gap-free suffix behind it (even later delivered events) is retained too.
        let (s, _d) = store();
        let s1 = s.append("A", "t", serde_json::json!({})).await.unwrap(); // seq 1
        let s2 = s.append("B", "t", serde_json::json!({})).await.unwrap(); // seq 2 (stays pending)
        let s3 = s.append("C", "t", serde_json::json!({})).await.unwrap(); // seq 3
        s.record_delivery(s1, true, None, 8).await.unwrap(); // seq 1 delivered
        s.record_delivery(s3, true, None, 8).await.unwrap(); // seq 3 delivered
                                                             // retention 0 would prune all by age, but the prune stops below the undelivered seq 2.
        let pruned = s.gc(0, &HashSet::new()).await.unwrap();
        assert_eq!(
            pruned, 1,
            "only the delivered head (seq 1) prunes; seq 2 blocks the rest"
        );
        let remaining: Vec<u64> = s
            .list_after(0, 100)
            .await
            .unwrap()
            .iter()
            .map(|e| e.sequence)
            .collect();
        assert_eq!(
            remaining,
            vec![2, 3],
            "undelivered seq 2 survives GC + the gap-free suffix (seq 3) is retained"
        );
        let _ = s2;
    }

    #[tokio::test]
    async fn gc_below_the_cap_never_prunes_a_dead_lettered_event() {
        // Below the count cap (`gc` is the age stage alone, no cap).
        // vultrino#4: a dead-lettered event is also "undelivered" — it must survive GC so an operator
        // can still replay it, even past the retention window.
        let (s, _d) = store();
        let s1 = s.append("A", "t", serde_json::json!({})).await.unwrap();
        let s2 = s.append("B", "t", serde_json::json!({})).await.unwrap();
        s.record_delivery(s1, true, None, 8).await.unwrap(); // delivered
        s.record_delivery(s2, false, Some("boom".into()), 1)
            .await
            .unwrap(); // max_attempts=1 → dead-lettered
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 1);
        let pruned = s.gc(0, &HashSet::new()).await.unwrap();
        assert_eq!(
            pruned, 1,
            "the delivered head prunes; the dead-lettered event is kept"
        );
        let remaining: Vec<u64> = s
            .list_after(0, 100)
            .await
            .unwrap()
            .iter()
            .map(|e| e.sequence)
            .collect();
        assert_eq!(remaining, vec![2], "dead-lettered seq 2 survives GC");
    }

    #[tokio::test]
    async fn noop_claim_and_gc_do_not_rewrite_the_file() {
        // vultrino#1: a delivery/GC tick that claims/prunes NOTHING must not re-encrypt+rewrite the
        // whole outbox file. Every real write uses a fresh nonce, so byte-equality of outbox.enc is a
        // deterministic (mtime-granularity-immune) proof that no write happened.
        let (s, dir) = store();
        let path = dir.path().join("outbox.enc");
        let seq = s.append("A", "t", serde_json::json!({})).await.unwrap();
        s.record_delivery(seq, true, None, 8).await.unwrap(); // nothing left pending to claim

        let before = std::fs::read(&path).unwrap();
        let claimed = s.claim(10, 30).await.unwrap();
        assert!(claimed.is_empty(), "nothing is pending");
        assert_eq!(
            before,
            std::fs::read(&path).unwrap(),
            "a no-op claim must not rewrite outbox.enc"
        );

        // A GC with a huge retention finds nothing old enough to prune → also a no-op.
        let pruned = s.gc(1_000_000, &HashSet::new()).await.unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(
            before,
            std::fs::read(&path).unwrap(),
            "a no-op GC must not rewrite outbox.enc"
        );

        // Positive control: a REAL append DOES rewrite the file (proves the check can detect a write).
        s.append("B", "t", serde_json::json!({})).await.unwrap();
        assert_ne!(
            before,
            std::fs::read(&path).unwrap(),
            "a genuine append must rewrite outbox.enc"
        );
    }

    #[tokio::test]
    async fn insert_event_preserves_sequence_for_migration() {
        let (s, _d) = store();
        // A migrated v6 event with an existing sequence must keep it (broker cursor stability).
        let migrated = OutboxEvent {
            sequence: 42,
            subject: "old".into(),
            event_type: "t".into(),
            payload: serde_json::json!({}),
            created_at: Utc::now(),
            delivery: DeliveryState::Pending,
            attempts: 0,
            leased_until: None,
            last_attempt_at: None,
            last_error: None,
            dedup_id: None,
        };
        s.insert_event(migrated).await.unwrap();
        let all = s.list_after(0, 100).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sequence, 42);
        // A new append continues AFTER the migrated max, never re-using a migrated seq.
        assert_eq!(
            s.append("new", "t", serde_json::json!({})).await.unwrap(),
            43
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn works_under_the_multi_thread_runtime_block_in_place_path() {
        // Exercise the block_in_place arm of locked_mutate/reload (the other tests run on the
        // current-thread runtime, which takes the inline arm).
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({"n": 1}))
            .await
            .unwrap();
        s.append("A", "t", serde_json::json!({"n": 2}))
            .await
            .unwrap();
        assert_eq!(s.list_after(0, 10).await.unwrap().len(), 2);
        let claimed = s.claim(10, 30).await.unwrap();
        assert_eq!(claimed.len(), 1);
        s.record_delivery(claimed[0].sequence, true, None, 8)
            .await
            .unwrap();
        assert_eq!(
            s.deliverable(10).await.unwrap().len(),
            1,
            "A's 2nd is now deliverable"
        );
    }

    #[tokio::test]
    async fn on_disk_bytes_are_ciphertext_not_plaintext() {
        // D2: the event log is encrypted at rest — a unique marker in the payload must NOT appear in
        // the raw file bytes (and the file must NOT be a readable JSON of the cache).
        let (s, dir) = store();
        let marker = "PLAINTEXT_MARKER_e9f1c2";
        s.append("subj", "t", serde_json::json!({ "secretish": marker }))
            .await
            .unwrap();
        let raw = std::fs::read(dir.path().join("outbox.enc")).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "event payload leaked in plaintext on disk"
        );
        // ...but decrypting it back recovers the event (round-trip).
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let s2 = OutboxStore::new(dir.path().join("outbox.enc"), key);
        let got = s2.list_after(0, 10).await.unwrap();
        assert_eq!(got[0].payload["secretish"], marker);
    }

    #[tokio::test]
    async fn append_deduped_is_idempotent_on_redrain() {
        let (s, _d) = store();
        // First drain of intent "evt-abc" inserts a new event.
        let s1 = s
            .append_deduped(
                "evt-abc",
                "appr-1",
                "approval.approved",
                serde_json::json!({"x": 1}),
            )
            .await
            .unwrap();
        // A re-drain (crash between the append and clearing the vault intent) returns the SAME seq,
        // does NOT insert a duplicate.
        let s2 = s
            .append_deduped(
                "evt-abc",
                "appr-1",
                "approval.approved",
                serde_json::json!({"x": 1}),
            )
            .await
            .unwrap();
        assert_eq!(
            s1, s2,
            "re-drain of the same dedup_id must return the original seq"
        );
        assert_eq!(
            s.list_after(0, 100).await.unwrap().len(),
            1,
            "no duplicate event"
        );
        // A DIFFERENT dedup id is a distinct event.
        let s3 = s
            .append_deduped(
                "evt-def",
                "appr-2",
                "approval.denied",
                serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(s1, s3);
        assert_eq!(s.list_after(0, 100).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn refuses_a_newer_file_version() {
        let (s, dir) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap();
        // Hand-write a future-version envelope; a downgrade must refuse it.
        let p = dir.path().join("outbox.enc");
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["version"] = serde_json::json!(OUTBOX_FILE_VERSION + 1);
        std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let s2 = OutboxStore::new(p, key);
        assert!(matches!(
            s2.list_after(0, 10).await,
            Err(StorageError::UnsupportedVersion { .. })
        ));
    }

    // ---- the count cap (max_retained_events) ----

    /// Retention so long the age stage cannot fire: only the cap acts.
    const NO_AGE: u64 = u64::MAX;

    async fn seqs(s: &OutboxStore) -> Vec<u64> {
        s.list_after(0, 1000)
            .await
            .unwrap()
            .iter()
            .map(|e| e.sequence)
            .collect()
    }

    #[tokio::test]
    async fn cap_prunes_oldest_beyond_max_even_when_undelivered() {
        let (s, _d) = store();
        for subj in ["A", "B", "C", "D", "E", "F"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        // seq 1 stays pending, seq 2 is dead-lettered, seq 3 is delivered, 4..6 pending.
        s.record_delivery(2, false, Some("boom".into()), 1)
            .await
            .unwrap();
        s.record_delivery(3, true, None, 8).await.unwrap();
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 1);

        let out = s.gc_capped(NO_AGE, 3, &HashSet::new()).await.unwrap();
        assert_eq!(out.age_pruned, 0);
        assert_eq!(out.cap.pruned, 3, "the 3 oldest beyond the cap go");
        assert_eq!(
            seqs(&s).await,
            vec![4, 5, 6],
            "a contiguous suffix is kept, the pending and dead-lettered heads are gone"
        );
        assert!(s.list_dead_letter(10).await.unwrap().is_empty());
        // At or under the cap nothing is pruned and nothing is written.
        let again = s.gc_capped(NO_AGE, 3, &HashSet::new()).await.unwrap();
        assert_eq!(again.total(), 0);
        assert_eq!(seqs(&s).await, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn cap_stops_at_a_staged_intent() {
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap(); // 1
        s.append_deduped("d2", "B", "t", serde_json::json!({}))
            .await
            .unwrap(); // 2, staged intent
        for subj in ["C", "D", "E"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap(); // 3..5
        }
        let mut protected = HashSet::new();
        protected.insert("d2".to_string());
        // Cap 2 would prune 1..3, but the prune never passes the protected seq 2.
        let out = s.gc_capped(NO_AGE, 2, &protected).await.unwrap();
        assert_eq!(out.cap.pruned, 1, "only seq 1, below the staged intent");
        assert_eq!(seqs(&s).await, vec![2, 3, 4, 5]);
        // Once the intent is cleared the cap proceeds.
        let out = s.gc_capped(NO_AGE, 2, &HashSet::new()).await.unwrap();
        assert_eq!(out.cap.pruned, 2);
        assert_eq!(seqs(&s).await, vec![4, 5]);
    }

    #[tokio::test]
    async fn cap_counts_pruned_by_state_and_type() {
        let (s, _d) = store();
        s.append("A", "meter.observed", serde_json::json!({}))
            .await
            .unwrap(); // 1 pending
        s.append("B", "approval.requested", serde_json::json!({}))
            .await
            .unwrap(); // 2 dead-lettered
        s.append("C", "meter.observed", serde_json::json!({}))
            .await
            .unwrap(); // 3 delivered
        s.append("D", "policy.denied", serde_json::json!({}))
            .await
            .unwrap(); // 4 kept
        s.append("E", "meter.observed", serde_json::json!({}))
            .await
            .unwrap(); // 5 kept
        s.record_delivery(2, false, Some("x".into()), 1)
            .await
            .unwrap();
        s.record_delivery(3, true, None, 8).await.unwrap();

        let before = s.retention_snapshot();
        assert_eq!(before.cap_pruned_total, 0);
        let out = s.gc_capped(NO_AGE, 2, &HashSet::new()).await.unwrap();
        assert_eq!(out.cap.pruned, 3);
        assert_eq!(out.cap.by_state.get("pending"), Some(&1));
        assert_eq!(out.cap.by_state.get("dead_lettered"), Some(&1));
        assert_eq!(out.cap.by_state.get("delivered"), Some(&1));
        assert_eq!(out.cap.by_type.get("meter.observed"), Some(&2));
        assert_eq!(out.cap.by_type.get("approval.requested"), Some(&1));
        assert_eq!(out.cap.undelivered(), 2);
        let snap = s.retention_snapshot();
        assert_eq!(snap.cap_pruned_total, 3);
        assert_eq!(snap.cap_pruned_undelivered_total, 2);
        assert_eq!(snap.retained_events, 2);
        assert_eq!(snap.oldest_sequence, Some(4));
        assert_eq!(snap.last_sequence, 5);
    }

    #[tokio::test]
    async fn last_sequence_survives_the_age_stage_emptying_the_outbox() {
        // The age stage prunes every delivered event: nothing is retained, but the highest
        // assigned sequence still reads N (a poller at N-1 must not look "caught up" on a 0).
        let (s, _d) = store();
        for subj in ["A", "B", "C"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        for seq in 1..=3 {
            s.record_delivery(seq, true, None, 8).await.unwrap();
        }
        let out = s.gc_capped(0, usize::MAX, &HashSet::new()).await.unwrap();
        assert_eq!(out.age_pruned, 3);
        let snap = s.retention_snapshot();
        assert_eq!(snap.retained_events, 0);
        assert_eq!(snap.oldest_sequence, None);
        assert_eq!(
            snap.last_sequence, 3,
            "last_sequence is outbox_seq, not the highest retained key"
        );
        let (page, hints) = s.list_after_with_retention(2, 100).await.unwrap();
        assert!(page.is_empty());
        assert_eq!(
            hints.last_sequence, 3,
            "an empty page with last_sequence > cursor is the hole rule"
        );
    }

    #[tokio::test]
    async fn cap_counters_tell_delivered_from_undelivered_prunes() {
        let (s, _d) = store();
        for subj in ["A", "B", "C", "D"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        s.record_delivery(1, true, None, 8).await.unwrap(); // seq 1 delivered, 2 and 3 pending
        let out = s.gc_capped(NO_AGE, 1, &HashSet::new()).await.unwrap();
        assert_eq!(out.cap.pruned, 3);
        assert_eq!(out.cap.undelivered(), 2);
        let snap = s.retention_snapshot();
        assert_eq!(snap.cap_pruned_total, 3);
        assert_eq!(
            snap.cap_pruned_undelivered_total, 2,
            "the delivered one is not counted"
        );
    }

    #[tokio::test]
    async fn cap_blocked_by_a_staged_intent_is_counted() {
        let (s, _d) = store();
        s.append_deduped("d1", "A", "t", serde_json::json!({}))
            .await
            .unwrap(); // 1, staged intent that is never cleared
        for subj in ["B", "C", "D"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        let mut protected = HashSet::new();
        protected.insert("d1".to_string());
        let out = s.gc_capped(NO_AGE, 2, &protected).await.unwrap();
        assert_eq!(out.cap.pruned, 0);
        assert!(out.cap_blocked);
        assert_eq!(s.retention_snapshot().cap_blocked_total, 1);
        // Within the cap nothing is blocked.
        let out = s.gc_capped(NO_AGE, 10, &protected).await.unwrap();
        assert!(!out.cap_blocked);
        assert_eq!(s.retention_snapshot().cap_blocked_total, 1);
    }

    #[tokio::test]
    async fn a_process_that_never_touched_the_outbox_reports_the_real_retention() {
        let (s, dir) = store();
        for subj in ["A", "B", "C"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        // A second store over the same file has not opened it yet (the file opens lazily).
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let fresh = OutboxStore::new(dir.path().join("outbox.enc"), key);
        let snap = fresh.retention_snapshot();
        assert!(snap.loaded);
        assert_eq!(snap.retained_events, 3, "not a healthy-looking empty cache");
        assert_eq!(snap.oldest_sequence, Some(1));
        assert_eq!(snap.last_sequence, 3);
    }

    #[tokio::test]
    async fn the_first_page_after_a_restart_reloads_the_file() {
        let (s, dir) = store();
        for subj in ["A", "B", "C"] {
            s.append(subj, "t", serde_json::json!({})).await.unwrap();
        }
        // A fresh store over the existing file (a restart before the delivery loop has run).
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let fresh = OutboxStore::new(dir.path().join("outbox.enc"), key);
        let (page, snap) = fresh.list_after_with_retention(0, 100).await.unwrap();
        assert_eq!(
            page.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "not an empty page from a never-loaded cache"
        );
        assert_eq!(snap.last_sequence, 3);
        assert_eq!(snap.oldest_sequence, Some(1));
        assert!(snap.loaded);
    }

    #[tokio::test]
    async fn a_snapshot_over_an_unreadable_outbox_file_reports_not_loaded() {
        let (s, dir) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap();
        // Corrupt the file (not a valid ciphertext) and open a fresh store over it.
        std::fs::write(dir.path().join("outbox.enc"), b"not an encrypted outbox").unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let fresh = OutboxStore::new(dir.path().join("outbox.enc"), key);
        let snap = fresh.retention_snapshot();
        assert!(
            !snap.loaded,
            "the load failed, the other fields are not to be trusted"
        );
    }

    #[tokio::test]
    async fn a_poller_behind_the_cap_sees_a_hole() {
        let (s, _d) = store();
        for i in 0..5 {
            s.append("A", "meter.observed", serde_json::json!({ "i": i }))
                .await
                .unwrap();
        }
        // The poller has read seq 1 and is about to ask for seq 2.
        let cursor = s.list_after(0, 1).await.unwrap()[0].sequence;
        assert_eq!(cursor, 1);
        s.gc_capped(NO_AGE, 2, &HashSet::new()).await.unwrap();
        let page = s.list_after(cursor, 100).await.unwrap();
        let first = page[0].sequence;
        assert_eq!(first, 4, "retained suffix starts at 4");
        assert!(first > cursor + 1, "seq 2 and 3 are a visible hole");
        // The retained suffix itself is contiguous.
        assert_eq!(
            page.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![4, 5]
        );
        let snap = s.retention_snapshot();
        assert_eq!(snap.oldest_sequence, Some(4));
        assert_eq!(snap.last_sequence, 5);
    }

    #[tokio::test]
    async fn the_cap_applies_when_the_age_window_is_unrepresentable() {
        // A huge retention_secs makes the age cutoff un-representable (age stage off); the cap must
        // still bound the outbox.
        let (s, _d) = store();
        for _ in 0..4 {
            s.append("A", "t", serde_json::json!({})).await.unwrap();
        }
        assert_eq!(s.gc(u64::MAX, &HashSet::new()).await.unwrap(), 0);
        assert_eq!(
            s.gc_capped(u64::MAX, 1, &HashSet::new())
                .await
                .unwrap()
                .total(),
            3
        );
    }
}
