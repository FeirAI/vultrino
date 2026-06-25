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

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use crate::outbox::{DeliveryState, OutboxEvent};
use crate::storage::StorageError;

/// On-disk format version for the OUTBOX file (independent of the vault's STORAGE_VERSION). v1 is the
/// first split-out format. A newer file is refused (binary downgrade guard), mirroring the vault.
const OUTBOX_FILE_VERSION: u32 = 1;

/// The in-memory + on-disk outbox state (serialized as the file body, then encrypted).
#[derive(Debug, Default, Serialize, Deserialize)]
struct OutboxCache {
    /// Events keyed by monotonic sequence (BTreeMap → gap-free cursor replay order).
    #[serde(default)]
    outbox: BTreeMap<u64, OutboxEvent>,
    /// The last assigned sequence (monotonic; survives restart so the broker cursor never rewinds).
    #[serde(default)]
    outbox_seq: u64,
}

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
        self.locked_mutate(move |c| Ok(push_event(c, &subject, &event_type, payload, None)))
            .await
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
                return Ok(e.sequence); // already drained → idempotent no-op
            }
            Ok(push_event(c, &subject, &event_type, payload, Some(dedup_id)))
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
            Ok(())
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
            Ok(())
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

    /// Earliest-pending event per subject (read-only peek; no claim).
    pub async fn deliverable(&self, limit: usize) -> Result<Vec<OutboxEvent>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(earliest_pending_per_subject(&c.outbox, limit, false, Utc::now()))
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
            Ok(claimed
                .into_iter()
                .map(|mut e| {
                    e.leased_until = Some(lease_until);
                    e
                })
                .collect())
        })
        .await
    }

    /// Record a delivery attempt: success → Delivered; failure → retry-with-backoff or dead-letter at
    /// max_attempts. Only a Pending (claimed) event accepts an outcome (Delivered/DeadLettered are
    /// terminal — a late/duplicate outcome can't un-deliver or resurrect them).
    pub async fn record_delivery(
        &self,
        sequence: u64,
        success: bool,
        error: Option<String>,
        max_attempts: u32,
    ) -> Result<(), StorageError> {
        self.locked_mutate(move |c| {
            if let Some(e) = c.outbox.get_mut(&sequence) {
                if e.delivery != DeliveryState::Pending {
                    return Ok(());
                }
                e.attempts += 1;
                e.last_attempt_at = Some(Utc::now());
                if success {
                    e.delivery = DeliveryState::Delivered;
                    e.leased_until = None;
                    e.last_error = None;
                } else {
                    e.last_error = error;
                    if e.attempts >= max_attempts {
                        e.delivery = DeliveryState::DeadLettered;
                        e.leased_until = None;
                    } else {
                        // Exponential-ish backoff lease, capped at 5 min (same as v6).
                        let backoff = (10u64.saturating_mul(1 << e.attempts.min(5))).min(300);
                        e.leased_until =
                            Some(Utc::now() + chrono::Duration::seconds(backoff as i64));
                    }
                }
            }
            Ok(())
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
                Ok(true)
            }
            _ => Ok(false),
        })
        .await
    }

    /// Prune a contiguous PREFIX of events older than the retention window (by sequence, so the
    /// retained suffix is gap-free regardless of clock skew). `protected_dedup_ids` are the dedup_ids of
    /// vault-side intents NOT yet cleared: an outbox event carrying such a dedup_id is NEVER pruned (the
    /// prefix prune STOPS below it), so its dedup record outlives the intent. This ENFORCES the
    /// no-duplicate invariant against the GC-vs-redrain window — without it, a delivered event could be
    /// pruned while its intent lingered, and a later re-drain would re-append the same logical event with
    /// a fresh sequence (a phantom duplicate). Returns the count pruned; warns if a pruned event was
    /// never Delivered (the window is the delivery/dead-letter SLA).
    pub async fn gc(
        &self,
        retention_secs: u64,
        protected_dedup_ids: &HashSet<String>,
    ) -> Result<usize, StorageError> {
        // Overflow-safe: a huge retention_secs would panic `Utc::now() - Duration::seconds(secs)`
        // (chrono DateTime add overflow). Use checked arithmetic; an un-representable cutoff means
        // "the window is effectively infinite" → prune nothing.
        let secs = i64::try_from(retention_secs).unwrap_or(i64::MAX);
        let cutoff = match chrono::Duration::try_seconds(secs)
            .and_then(|d| Utc::now().checked_sub_signed(d))
        {
            Some(c) => c,
            None => return Ok(0),
        };
        // Clone into the (move) closure; the protected set is small (only undrained intents, normally 0).
        let protected = protected_dedup_ids.clone();
        self.locked_mutate(move |c| {
            // Stop the prefix prune at the first event that is either young OR still protected by a
            // staged intent, keeping the retained suffix gap-free AND the dedup record alive.
            let prune_below = c
                .outbox
                .iter()
                .take_while(|(_, e)| {
                    e.created_at < cutoff
                        && !e.dedup_id.as_deref().is_some_and(|d| protected.contains(d))
                })
                .map(|(seq, _)| *seq)
                .last();
            let Some(prune_below) = prune_below else {
                return Ok(0);
            };
            let mut pruned = 0usize;
            let mut undelivered_dropped = 0usize;
            c.outbox.retain(|seq, e| {
                if *seq <= prune_below {
                    pruned += 1;
                    if e.delivery != DeliveryState::Delivered {
                        undelivered_dropped += 1;
                    }
                    false
                } else {
                    true
                }
            });
            if undelivered_dropped > 0 {
                tracing::warn!(
                    count = undelivered_dropped,
                    "outbox GC dropped events that were never delivered (older than the retention window)"
                );
            }
            Ok(pruned)
        })
        .await
    }

    // ---- internal persistence (mirrors FileStorage's locked_mutate / reload on the outbox file) ----

    async fn locked_mutate<T>(
        &self,
        f: impl FnOnce(&mut OutboxCache) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.locked_mutate_blocking(f),
            _ => tokio::task::block_in_place(|| self.locked_mutate_blocking(f)),
        }
    }

    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut OutboxCache) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        let mut cache = self.read_from_disk()?;
        let result = f(&mut cache)?;
        self.write_to_disk(&cache)?;
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
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
                return Ok(());
            }
        }
        let cache = self.read_from_disk()?;
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
        Ok(())
    }

    fn lock_file_exclusive(&self) -> Result<fd_lock::RwLock<std::fs::File>, StorageError> {
        let lock_path = self.path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
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
        let data = serde_json::to_vec(cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
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
            let f = std::fs::File::create(&temp_path)?;
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

/// Increment the sequence and insert a fresh Pending event (with an optional intent-drain dedup id).
/// Relocated from FileStorage (+ the dedup_id for the v6→v7 intent-staging).
fn push_event(
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
fn earliest_pending_per_subject(
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
        let s1 = s.append("a", "t", serde_json::json!({"n": 1})).await.unwrap();
        let s2 = s.append("b", "t", serde_json::json!({"n": 2})).await.unwrap();
        let s3 = s.append("a", "t", serde_json::json!({"n": 3})).await.unwrap();
        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(
            s.list_after(0, 100).await.unwrap().iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            s.list_after(2, 100).await.unwrap().iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(s.list_after(0, 1).await.unwrap().len(), 1);
        // A FRESH store on the SAME file (restart) replays everything — the seq does not rewind.
        let s2store = OutboxStore::new(dir.path().join("outbox.enc"), key);
        assert_eq!(s2store.list_after(0, 100).await.unwrap().len(), 3);
        let s4 = s2store.append("c", "t", serde_json::json!({})).await.unwrap();
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
        assert_eq!(subjects, vec!["A", "B"], "one per subject; A's 2nd withheld");
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
        for _ in 0..3 {
            s.record_delivery(seq, false, Some("boom".into()), 3).await.unwrap();
        }
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 1, "dead-lettered after 3 attempts");
        assert!(s.replay_dead_letter(seq).await.unwrap());
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 0);
        assert_eq!(s.deliverable(10).await.unwrap().len(), 1, "replayed → pending again");
    }

    #[tokio::test]
    async fn record_success_marks_delivered_terminal() {
        let (s, _d) = store();
        let seq = s.append("A", "t", serde_json::json!({})).await.unwrap();
        s.record_delivery(seq, true, None, 8).await.unwrap();
        assert_eq!(s.deliverable(10).await.unwrap().len(), 0, "delivered → not deliverable");
        // A late duplicate outcome cannot un-deliver it.
        s.record_delivery(seq, false, Some("late".into()), 8).await.unwrap();
        assert_eq!(s.list_dead_letter(10).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn gc_prunes_old_prefix() {
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap();
        s.append("B", "t", serde_json::json!({})).await.unwrap();
        assert_eq!(s.gc(0, &HashSet::new()).await.unwrap(), 2, "retention 0 prunes all");
        assert_eq!(s.list_after(0, 100).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn gc_protects_staged_dedup_ids_and_keeps_suffix_gapfree() {
        // F2: an event whose dedup_id is still staged in the vault must NOT be pruned (else a re-drain
        // after the prune would duplicate it). The prefix prune stops BELOW the first protected event,
        // keeping the retained suffix gap-free.
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({})).await.unwrap(); // seq 1, no dedup
        s.append_deduped("d2", "B", "t", serde_json::json!({})).await.unwrap(); // seq 2, dedup d2
        s.append("C", "t", serde_json::json!({})).await.unwrap(); // seq 3, no dedup
        let mut protected = HashSet::new();
        protected.insert("d2".to_string());
        // retention 0 would prune all, but d2 (seq 2) is protected → only seq 1 prunes.
        assert_eq!(s.gc(0, &protected).await.unwrap(), 1, "prune stops below the protected event");
        let remaining: Vec<u64> = s.list_after(0, 100).await.unwrap().iter().map(|e| e.sequence).collect();
        assert_eq!(remaining, vec![2, 3], "protected event + suffix retained, gap-free");
        // Once the intent clears (no longer protected), the next GC prunes it.
        assert_eq!(s.gc(0, &HashSet::new()).await.unwrap(), 2, "unprotected → pruned");
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
        assert_eq!(s.append("new", "t", serde_json::json!({})).await.unwrap(), 43);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn works_under_the_multi_thread_runtime_block_in_place_path() {
        // Exercise the block_in_place arm of locked_mutate/reload (the other tests run on the
        // current-thread runtime, which takes the inline arm).
        let (s, _d) = store();
        s.append("A", "t", serde_json::json!({"n": 1})).await.unwrap();
        s.append("A", "t", serde_json::json!({"n": 2})).await.unwrap();
        assert_eq!(s.list_after(0, 10).await.unwrap().len(), 2);
        let claimed = s.claim(10, 30).await.unwrap();
        assert_eq!(claimed.len(), 1);
        s.record_delivery(claimed[0].sequence, true, None, 8).await.unwrap();
        assert_eq!(s.deliverable(10).await.unwrap().len(), 1, "A's 2nd is now deliverable");
    }

    #[tokio::test]
    async fn on_disk_bytes_are_ciphertext_not_plaintext() {
        // D2: the event log is encrypted at rest — a unique marker in the payload must NOT appear in
        // the raw file bytes (and the file must NOT be a readable JSON of the cache).
        let (s, dir) = store();
        let marker = "PLAINTEXT_MARKER_e9f1c2";
        s.append("subj", "t", serde_json::json!({ "secretish": marker })).await.unwrap();
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
        let s1 = s.append_deduped("evt-abc", "appr-1", "approval.approved", serde_json::json!({"x": 1}))
            .await
            .unwrap();
        // A re-drain (crash between the append and clearing the vault intent) returns the SAME seq,
        // does NOT insert a duplicate.
        let s2 = s.append_deduped("evt-abc", "appr-1", "approval.approved", serde_json::json!({"x": 1}))
            .await
            .unwrap();
        assert_eq!(s1, s2, "re-drain of the same dedup_id must return the original seq");
        assert_eq!(s.list_after(0, 100).await.unwrap().len(), 1, "no duplicate event");
        // A DIFFERENT dedup id is a distinct event.
        let s3 = s.append_deduped("evt-def", "appr-2", "approval.denied", serde_json::json!({}))
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
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["version"] = serde_json::json!(OUTBOX_FILE_VERSION + 1);
        std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![7u8; 32]).unwrap());
        let s2 = OutboxStore::new(p, key);
        assert!(matches!(
            s2.list_after(0, 10).await,
            Err(StorageError::UnsupportedVersion { .. })
        ));
    }
}
