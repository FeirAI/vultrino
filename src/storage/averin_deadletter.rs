//! The averin USE queue's dead-letter QUARANTINE (plan 088 D4): a separate, low-volume, whole-file
//! AES-256-GCM store (control-plane frequency — same proven shape as `OutboxStore`/`PopKeyStore`:
//! serialize -> encrypt -> tmp -> `sync_all` -> atomic rename -> fsync the parent dir ->
//! `create_private_file` 0600 -> a file-version downgrade guard) that a dead-lettered `averin.use`
//! event moves INTO once it exhausts `max_attempts` in the active queue (`averin_queue.rs`).
//!
//! # Why a separate store, not a frozen prefix (D4)
//!
//! `OutboxStore::gc` prunes only a CONTIGUOUS delivered prefix: its `take_while` stops at the first
//! event that is not `Delivered`, so a single `DeadLettered` event freezes the prune and retains
//! itself + every LATER event for every subject forever. For the averin queue that would mean later
//! uses' raw `params` (possibly PII/secret — averin recomputes the commitment from the raw bytes) are
//! retained indefinitely, and one bad subject blocks GC/compaction of every subject behind it. This
//! store exists so a dead-letter transition can MOVE the failed record out of the active queue (which
//! then advances/reclaims normally) into quarantine, which is retention-bounded INDEPENDENTLY (see
//! [`AverinDeadLetterStore::purge_expired_params`]).
//!
//! **This module builds the store + its operator API only.** Wiring the active queue's dead-letter
//! transition to actually MOVE a record here is plan 088 Step 3b's delivery-worker integration, not
//! this step — nothing calls [`AverinDeadLetterStore::quarantine`] from production code yet.
//!
//! # Operator lifecycle
//!
//! - [`AverinDeadLetterStore::list`] — everything currently quarantined (any status).
//! - [`AverinDeadLetterStore::ack`] — acknowledge a record as permanently lost (kept for audit, never
//!   replayed again).
//! - [`AverinDeadLetterStore::abandon`] — give up on a SUBJECT (all its quarantined records): this is
//!   what finally lets plan 088 D2's `PopKeyStore::evict_resolved` release the subject's PoP seed for
//!   a grant that never delivered (D2's rule (a), the `abandoned` flag).
//! - [`AverinDeadLetterStore::purge`] — delete a record entirely (operator-forced, no audit trail
//!   kept).
//! - [`AverinDeadLetterStore::replay`] — for a transient averin outage that outlived `max_attempts`:
//!   removes the record from quarantine and hands back the [`crate::outbox::OutboxEvent`] so a caller
//!   (plan 088 Step 3b's worker) can re-enqueue it into the active queue under a FRESH sequence. Fails
//!   closed (a clear [`StorageError::Conflict`]) on anything other than an `Open` record whose raw
//!   `params` have not yet been purged — replaying a redacted record would inject a hole where
//!   `params` should be, corrupting the eventual re-delivered use. An `averin.grant` record is ALWAYS
//!   rejected too (R3-B Codex 3rd-pass M5), regardless of status/purge state: a dead-lettered grant's
//!   subject is marked `abandoned` and its PoP seed released for GC on dead-letter (see the worker's
//!   `quarantine_and_reclaim_dead_letter`), so the grant is permanently terminal — re-enqueuing it
//!   would fail to rebuild its proof-of-possession.
//!
//! # Bounded sensitive-data retention
//!
//! [`AverinDeadLetterStore::purge_expired_params`] is the OTHER half of D4: a background purge (a
//! later step's periodic tick calls it, mirroring the active queue's own GC tick) drops a quarantined
//! record's raw `params` after a bounded window, keeping only redacted metadata (`event_type`,
//! `subject`, `attempts`, `last_error`, timestamps) for the audit trail — the record itself is
//! retained (for `list`/`ack`/`abandon`) until an operator `purge`s it outright.
//!
//! # At-rest threat model
//!
//! A quarantined `averin.use` record's payload carries the SAME raw `params` the active queue does
//! (plan 088 D1) — same posture as every other averin store: AES-256-GCM under the shared vault
//! master key (`crate::crypto::{encrypt, decrypt}`, no separate KDF), `0600`, never logged. `Debug` is
//! hand-written to redact the payload's `params` field (mirrors `PopKeyEntry`'s redacting `Debug`,
//! `popkey_store.rs`) — everything else (sequence, subject, event_type, attempts, timestamps) is not
//! sensitive and prints normally.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use crate::outbox::OutboxEvent;
use crate::storage::outbox_store::{create_private_file, fsync_parent_dir};
use crate::storage::StorageError;

/// On-disk format version for the quarantine file (independent of the vault's/outbox's/queue's own
/// version counters). A newer file is refused (downgrade guard, mirroring every other store here).
const DEADLETTER_FILE_VERSION: u32 = 1;

/// The encrypted on-disk envelope. No salt: the key is the vault's already-derived master key
/// (shared via `Arc`), so this file decrypts with it directly — no separate KDF.
#[derive(Debug, Serialize, Deserialize)]
struct DeadLetterFile {
    version: u32,
    data: EncryptedData,
}

/// The in-memory cache, keyed by the dead-lettered event's OWN `sequence` (globally unique within
/// one averin queue directory, plan 088 D0/D1's cross-process sequence-reservation fix) — the natural,
/// already-unique id this store's operator API (`ack`/`abandon`/`purge`/`replay`) addresses records by.
#[derive(Default, Serialize, Deserialize)]
struct DeadLetterCache {
    entries: BTreeMap<u64, QuarantineRecord>,
}

/// The operator-visible lifecycle state of one quarantined record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    /// Awaiting an operator decision; eligible for [`AverinDeadLetterStore::replay`].
    Open,
    /// Operator acknowledged this record as permanently lost. Kept for audit; never replayed again.
    Acknowledged,
    /// Operator abandoned the SUBJECT this record belongs to (releases D2's PoP-seed eviction
    /// blocker). Kept for audit; never replayed again.
    Abandoned,
}

/// One quarantined dead-lettered `averin.use` (or `averin.grant`) record (plan 088 D4).
#[derive(Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// The event exactly as it looked when the active queue dead-lettered it — including its
    /// FROZEN `attempts`/`last_error` from the queue's own bookkeeping. `event.sequence` is this
    /// store's key. `event.payload` carries the SENSITIVE raw `params` until
    /// [`AverinDeadLetterStore::purge_expired_params`] redacts it (see `params_purged`).
    pub event: OutboxEvent,
    /// When the active queue's dead-letter transition moved this record here.
    pub dead_lettered_at: DateTime<Utc>,
    /// Set once [`AverinDeadLetterStore::purge_expired_params`] has redacted `event.payload`'s raw
    /// `params` field (D4's bounded sensitive-data-retention window). [`AverinDeadLetterStore::replay`]
    /// refuses a record with this set — see its doc.
    pub params_purged: bool,
    pub status: QuarantineStatus,
}

impl std::fmt::Debug for QuarantineRecord {
    /// Hand-written to redact `event.payload`'s raw `params` field (D4: a quarantined `averin.use`
    /// carries the agent's raw `/execute` body, possibly PII/secret — see the module doc). Mirrors
    /// `PopKeyEntry`'s redacting `Debug` (`popkey_store.rs`). Every other field is not sensitive and
    /// prints normally.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineRecord")
            .field("sequence", &self.event.sequence)
            .field("subject", &self.event.subject)
            .field("event_type", &self.event.event_type)
            .field("payload", &redact_params(&self.event.payload))
            .field("attempts", &self.event.attempts)
            .field("last_error", &self.event.last_error)
            .field("dead_lettered_at", &self.dead_lettered_at)
            .field("params_purged", &self.params_purged)
            .field("status", &self.status)
            .finish()
    }
}

/// Redact a payload's `params` field (if present and the payload is a JSON object) for `Debug` and
/// for [`AverinDeadLetterStore::purge_expired_params`]'s durable redaction alike — one place decides
/// what "redacted" looks like.
fn redact_params(payload: &serde_json::Value) -> serde_json::Value {
    match payload {
        serde_json::Value::Object(map) if map.contains_key("params") => {
            let mut copy = map.clone();
            copy.insert(
                "params".to_string(),
                serde_json::Value::String("[redacted; retention window expired]".to_string()),
            );
            serde_json::Value::Object(copy)
        }
        other => other.clone(),
    }
}

/// The encrypted, durable dead-letter quarantine (plan 088 D4). See the module doc for the lifecycle
/// and at-rest threat model.
pub struct AverinDeadLetterStore {
    path: PathBuf,
    master_key: Arc<MasterKey>,
    cache: RwLock<DeadLetterCache>,
    /// (mtime,len) of the file as of this process's last decrypt — skips a redundant decrypt when
    /// the file is byte-unchanged. Mirrors `OutboxStore`/`PopKeyStore`/`FileStorage`.
    last_loaded: Mutex<Option<(SystemTime, u64)>>,
}

impl AverinDeadLetterStore {
    /// Open (lazily) a quarantine store at `path`, encrypting with the shared vault master key. The
    /// file is created on first write; an absent file reads as empty.
    pub fn new(path: PathBuf, master_key: Arc<MasterKey>) -> Self {
        Self {
            path,
            master_key,
            cache: RwLock::new(DeadLetterCache::default()),
            last_loaded: Mutex::new(None),
        }
    }

    // ---- operator API ----

    /// Move a dead-lettered event into quarantine (an UPSERT keyed by `event.sequence` — idempotent
    /// if a caller retries the same move after a crash). Not yet called by any production code path
    /// (plan 088 Step 3b's worker wires the active queue's dead-letter transition to this) — Step 3a
    /// only builds the store.
    pub async fn quarantine(
        &self,
        event: OutboxEvent,
        dead_lettered_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let sequence = event.sequence;
        let record = QuarantineRecord {
            event,
            dead_lettered_at,
            params_purged: false,
            status: QuarantineStatus::Open,
        };
        self.locked_mutate(move |c| {
            c.entries.insert(sequence, record);
            Ok(((), true))
        })
        .await
    }

    /// Every currently-quarantined record (any status), ordered by sequence.
    pub async fn list(&self) -> Result<Vec<QuarantineRecord>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(c.entries.values().cloned().collect())
    }

    /// Acknowledge `sequence` as permanently lost: `Open`/`Abandoned` -> `Acknowledged` (idempotent —
    /// already-`Acknowledged` is a no-op). Kept for audit; never replayed again. Returns `false` if
    /// `sequence` is unknown.
    pub async fn ack(&self, sequence: u64) -> Result<bool, StorageError> {
        self.locked_mutate(move |c| match c.entries.get_mut(&sequence) {
            Some(r) if r.status != QuarantineStatus::Acknowledged => {
                r.status = QuarantineStatus::Acknowledged;
                Ok((true, true))
            }
            Some(_) => Ok((true, false)), // already acknowledged — no-op, no write
            None => Ok((false, false)),
        })
        .await
    }

    /// Abandon every quarantined record for `subject` (releases plan 088 D2's PoP-seed eviction
    /// blocker for a grant that permanently dead-lettered and never delivered). Idempotent. Returns
    /// the count of records newly marked abandoned (already-abandoned/acknowledged records are left
    /// as-is and not counted).
    pub async fn abandon(&self, subject: &str) -> Result<usize, StorageError> {
        let subject = subject.to_string();
        self.locked_mutate(move |c| {
            let mut changed = 0usize;
            for r in c.entries.values_mut() {
                if r.event.subject == subject && r.status == QuarantineStatus::Open {
                    r.status = QuarantineStatus::Abandoned;
                    changed += 1;
                }
            }
            Ok((changed, changed > 0))
        })
        .await
    }

    /// Delete `sequence` entirely — no audit trail kept. Returns `false` if unknown.
    pub async fn purge(&self, sequence: u64) -> Result<bool, StorageError> {
        self.locked_mutate(move |c| Ok((c.entries.remove(&sequence).is_some(), true)))
            .await
    }

    /// Re-queue a quarantined use: removes it from quarantine and returns the
    /// [`crate::outbox::OutboxEvent`] for a caller (plan 088 Step 3b's worker) to re-append into the
    /// active queue under a FRESH sequence. Fails closed with [`StorageError::Conflict`] (never a
    /// silent `None`) when the record is not `Open` (an operator already acknowledged/abandoned it),
    /// its raw `params` were already purged (replaying a redacted payload would corrupt the
    /// re-delivered use — see [`Self::purge_expired_params`]), or the record is an `averin.grant` (R3-B
    /// Codex 3rd-pass M5 — a dead-lettered grant's subject is abandoned and its PoP seed released for
    /// GC at dead-letter time, so the grant is permanently terminal regardless of its `Open`/unpurged
    /// status; re-enqueuing it would fail to rebuild its proof-of-possession). Returns
    /// [`StorageError::NotFound`] when `sequence` is unknown.
    pub async fn replay(&self, sequence: u64) -> Result<OutboxEvent, StorageError> {
        self.locked_mutate(move |c| {
            let Some(record) = c.entries.get(&sequence) else {
                return Err(StorageError::NotFound(format!(
                    "no quarantined averin record for sequence {sequence}"
                )));
            };
            if record.event.event_type == "averin.grant" {
                return Err(StorageError::Conflict(format!(
                    "quarantined averin record {sequence} is an averin.grant — grant subjects are \
                     abandoned and their PoP seed released on dead-letter, so the grant is terminal \
                     and NOT replayable (re-enqueue would fail to rebuild its proof-of-possession)"
                )));
            }
            if record.status != QuarantineStatus::Open {
                return Err(StorageError::Conflict(format!(
                    "quarantined averin record {sequence} is {:?}, not Open — not replayable",
                    record.status
                )));
            }
            if record.params_purged {
                return Err(StorageError::Conflict(format!(
                    "quarantined averin record {sequence}'s params were already purged (retention \
                     window expired) — not replayable"
                )));
            }
            let event = record.event.clone();
            c.entries.remove(&sequence);
            Ok((event, true))
        })
        .await
    }

    /// D4's bounded sensitive-data retention: for every `Open`-or-terminal record dead-lettered
    /// before `before` whose params are not already redacted, replace `event.payload`'s raw `params`
    /// field with a redaction marker (keeping every other field — `event_type`, `subject`,
    /// `attempts`, `last_error`, timestamps — for the audit trail) and mark `params_purged`. Returns
    /// the count of records redacted. A record already purged, or dead-lettered at/after `before`, is
    /// left untouched (idempotent — safe to call on every periodic tick).
    pub async fn purge_expired_params(&self, before: DateTime<Utc>) -> Result<usize, StorageError> {
        self.locked_mutate(move |c| {
            let mut purged = 0usize;
            for r in c.entries.values_mut() {
                if r.params_purged || r.dead_lettered_at >= before {
                    continue;
                }
                r.event.payload = redact_params(&r.event.payload);
                r.params_purged = true;
                purged += 1;
            }
            Ok((purged, purged > 0))
        })
        .await
    }

    /// Number of retained records, any status (test/ops introspection).
    pub async fn entry_count(&self) -> Result<usize, StorageError> {
        self.reload().await?;
        Ok(self.cache.read().entries.len())
    }

    /// Whether `sequence` currently has ANY quarantine record (any status). Plan 088 Step 6a's GC-tick
    /// retry-sweep uses this to avoid re-calling [`Self::quarantine`] (an UPSERT) for a record already
    /// durably quarantined — re-quarantining it would silently reset an operator's
    /// `Acknowledged`/`Abandoned` decision, or a since-set `params_purged` flag, back to a fresh
    /// `Open`/unpurged record. The sweep calls this FIRST and only quarantines when it answers `false`.
    pub async fn contains(&self, sequence: u64) -> Result<bool, StorageError> {
        self.reload().await?;
        Ok(self.cache.read().entries.contains_key(&sequence))
    }

    /// Plan 088 D2's `subject_has_replayable_dead_letter` cross-store predicate for
    /// `PopKeyStore::evict_resolved`'s GC tick: does `subject` have at least one quarantined record
    /// that is still [`Self::replay`]-eligible (`Open` and its raw `params` not yet purged) — the
    /// EXACT same gate `replay` itself enforces, so this answers "would `replay` succeed for this
    /// subject right now" without duplicating that method's rejection arms. An `Acknowledged`/
    /// `Abandoned` record, or one whose params already expired ([`Self::purge_expired_params`]),
    /// never blocks eviction — the seed it might have needed to re-sign a replay is no longer usable
    /// for that purpose anyway.
    pub async fn has_replayable_for_subject(&self, subject: &str) -> Result<bool, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(c.entries
            .values()
            .any(|r| r.event.subject == subject && r.status == QuarantineStatus::Open && !r.params_purged))
    }

    // ---- internal persistence (mirrors PopKeyStore's locked_mutate / reload on its own file) ----

    async fn locked_mutate<T>(
        &self,
        f: impl FnOnce(&mut DeadLetterCache) -> Result<(T, bool), StorageError>,
    ) -> Result<T, StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.locked_mutate_blocking(f),
            _ => tokio::task::block_in_place(|| self.locked_mutate_blocking(f)),
        }
    }

    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut DeadLetterCache) -> Result<(T, bool), StorageError>,
    ) -> Result<T, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        let mut cache = self.read_from_disk()?;
        let (result, dirty) = f(&mut cache)?;
        if dirty {
            self.write_to_disk(&cache)?;
        }
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
        Ok(result)
    }

    /// Refresh the in-memory cache from disk (picks up a sibling process's writes). Skips the
    /// decrypt when the file is byte-unchanged since this process last loaded it. Takes the SAME
    /// exclusive lock as `locked_mutate` so a committed write is never clobbered by a stale read.
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

    fn read_from_disk(&self) -> Result<DeadLetterCache, StorageError> {
        if !self.path.exists() {
            return Ok(DeadLetterCache::default());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let file: DeadLetterFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        if file.version > DEADLETTER_FILE_VERSION {
            return Err(StorageError::UnsupportedVersion {
                found: file.version,
                supported: DEADLETTER_FILE_VERSION,
            });
        }
        let plaintext = decrypt(&file.data, &self.master_key)?;
        serde_json::from_slice(&plaintext).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    fn write_to_disk(&self, cache: &DeadLetterCache) -> Result<(), StorageError> {
        // Create the parent dir lazily (self-contained: don't assume the vault's FileStorage::new
        // ran first).
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data =
            serde_json::to_vec(cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, &self.master_key)?;
        let file = DeadLetterFile {
            version: DEADLETTER_FILE_VERSION,
            data: encrypted,
        };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let temp_path = self.path.with_extension("tmp");
        // fsync the tmp BEFORE the rename (same discipline as OutboxStore::write_to_disk): the
        // rename gives crash-ATOMICITY, only sync_all gives crash-DURABILITY of the contents.
        {
            // 0600: quarantined records carry the same raw params the active queue does — never
            // leave this file group/world-readable even though it is encrypted.
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
        fsync_parent_dir(&self.path)?;
        Ok(())
    }

    fn file_change_token(&self) -> Option<(SystemTime, u64)> {
        let meta = std::fs::metadata(&self.path).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }

    // ---- offline vault re-key (FileStorage::rekey delegates the quarantine half here; D8) ----

    /// Prepare the quarantine half of an offline vault re-key: under this store's fd-lock, decrypt
    /// the file with the CURRENT (shared) master key and write a `.rekey.tmp` re-encrypted with
    /// `new_key`, fsynced but NOT yet renamed. Returns the tmp path for the caller to commit (via
    /// [`Self::rekey_commit`]) so this file's rename lands back-to-back with the vault's/outbox's/
    /// other averin stores' — see `FileStorage::rekey_blocking`'s crash-ordering doc (D8: averin
    /// files + outbox rename FIRST, the authoritative vault LAST). Returns `Ok(None)` when no
    /// quarantine file exists yet (nothing to re-encrypt). [`DEADLETTER_FILE_VERSION`] is PRESERVED
    /// — a re-key rotates the key, never the format. On any error the live file is left untouched
    /// (fail-closed). Mirrors `OutboxStore::rekey_prepare` exactly.
    pub(super) fn rekey_prepare(&self, new_key: &MasterKey) -> Result<Option<PathBuf>, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        if !self.path.exists() {
            return Ok(None); // no quarantine file yet -> nothing to re-encrypt
        }
        // Decrypt with the OLD (shared) master key still held by this process.
        let cache = self.read_from_disk()?;
        let data =
            serde_json::to_vec(&cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, new_key)?;
        let file = DeadLetterFile {
            version: DEADLETTER_FILE_VERSION, // PRESERVED — key changes, format does not
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

    /// Commit the quarantine half of an offline vault re-key: atomically rename the `.rekey.tmp`
    /// from [`Self::rekey_prepare`] over the live quarantine file and fsync the parent directory.
    pub(super) fn rekey_commit(&self, tmp: &Path) -> Result<(), StorageError> {
        std::fs::rename(tmp, &self.path)?;
        fsync_parent_dir(&self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::DeliveryState;

    fn store() -> (AverinDeadLetterStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![13u8; 32]).unwrap());
        (
            AverinDeadLetterStore::new(dir.path().join("averin-deadletter.enc"), key),
            dir,
        )
    }

    fn use_event(sequence: u64, subject: &str, params_marker: &str) -> OutboxEvent {
        OutboxEvent {
            sequence,
            subject: subject.to_string(),
            event_type: "averin.use".to_string(),
            payload: serde_json::json!({
                "params": params_marker,
                "nonce": "n1",
                "params_nonce": "pn1",
                "request_id": "req-1",
                "use_sequence_number": 1,
            }),
            created_at: Utc::now(),
            delivery: DeliveryState::DeadLettered,
            attempts: 8,
            leased_until: None,
            last_attempt_at: Some(Utc::now()),
            last_error: Some("averin unreachable".to_string()),
            dedup_id: None,
        }
    }

    /// Same shape as [`use_event`] but `event_type: "averin.grant"` — for the R3-B/M5 tests exercising
    /// `replay`'s grant-rejection.
    fn grant_event(sequence: u64, subject: &str) -> OutboxEvent {
        let mut event = use_event(sequence, subject, "grant-params-unused");
        event.event_type = "averin.grant".to_string();
        event
    }

    #[tokio::test]
    async fn quarantine_list_and_round_trip_through_reopen() {
        let (s, dir) = store();
        let now = Utc::now();
        s.quarantine(use_event(1, "tok-a", "PLAINTEXT_MARKER_dl1"), now)
            .await
            .unwrap();

        let listed = s.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].event.sequence, 1);
        assert_eq!(listed[0].status, QuarantineStatus::Open);
        assert!(!listed[0].params_purged);

        let key = Arc::new(MasterKey::from_bytes(vec![13u8; 32]).unwrap());
        let reopened = AverinDeadLetterStore::new(dir.path().join("averin-deadletter.enc"), key);
        let listed2 = reopened.list().await.unwrap();
        assert_eq!(listed2.len(), 1);
        assert_eq!(listed2[0].event.payload["params"], "PLAINTEXT_MARKER_dl1");
    }

    #[tokio::test]
    async fn on_disk_bytes_are_ciphertext_not_plaintext() {
        let (s, dir) = store();
        let marker = "PLAINTEXT_MARKER_averin_dl_9f1a";
        s.quarantine(use_event(1, "tok-a", marker), Utc::now())
            .await
            .unwrap();
        let raw = std::fs::read(dir.path().join("averin-deadletter.enc")).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "quarantined params leaked in plaintext on disk"
        );
    }

    #[test]
    fn debug_redacts_params_but_shows_everything_else() {
        let record = QuarantineRecord {
            event: use_event(1, "tok-a", "SUPER_SECRET_PARAMS"),
            dead_lettered_at: Utc::now(),
            params_purged: false,
            status: QuarantineStatus::Open,
        };
        let dbg = format!("{record:?}");
        assert!(
            !dbg.contains("SUPER_SECRET_PARAMS"),
            "Debug output must not print raw params: {dbg}"
        );
        assert!(dbg.contains("tok-a"), "non-sensitive fields must still print: {dbg}");
        assert!(dbg.contains("redacted"), "must show the redaction marker: {dbg}");
    }

    #[tokio::test]
    async fn ack_marks_acknowledged_and_is_idempotent() {
        let (s, _d) = store();
        s.quarantine(use_event(1, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        assert!(s.ack(1).await.unwrap());
        assert_eq!(s.list().await.unwrap()[0].status, QuarantineStatus::Acknowledged);
        // Idempotent: already-acknowledged re-ack is a no-op, still returns true (found).
        assert!(s.ack(1).await.unwrap());
        assert!(!s.ack(999).await.unwrap(), "unknown sequence is false, not an error");
    }

    #[tokio::test]
    async fn abandon_only_affects_the_targeted_subject_and_open_records() {
        let (s, _d) = store();
        s.quarantine(use_event(1, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        s.quarantine(use_event(2, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        s.quarantine(use_event(3, "tok-b", "p"), Utc::now())
            .await
            .unwrap();
        s.ack(2).await.unwrap(); // already acknowledged -> abandon must not touch it

        let changed = s.abandon("tok-a").await.unwrap();
        assert_eq!(changed, 1, "only the still-Open tok-a record is newly abandoned");

        let by_seq: std::collections::HashMap<u64, QuarantineStatus> = s
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.event.sequence, r.status))
            .collect();
        assert_eq!(by_seq[&1], QuarantineStatus::Abandoned);
        assert_eq!(by_seq[&2], QuarantineStatus::Acknowledged, "untouched by abandon");
        assert_eq!(by_seq[&3], QuarantineStatus::Open, "different subject, untouched");
    }

    #[tokio::test]
    async fn purge_deletes_the_record_entirely() {
        let (s, _d) = store();
        s.quarantine(use_event(1, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        assert!(s.purge(1).await.unwrap());
        assert_eq!(s.entry_count().await.unwrap(), 0);
        assert!(!s.purge(1).await.unwrap(), "already gone -- false, not an error");
    }

    #[tokio::test]
    async fn replay_removes_and_returns_the_event_when_open_and_unpurged() {
        let (s, _d) = store();
        s.quarantine(use_event(7, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        let event = s.replay(7).await.unwrap();
        assert_eq!(event.sequence, 7);
        assert_eq!(event.subject, "tok-a");
        // Removed from quarantine by the replay.
        assert_eq!(s.entry_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn replay_fails_closed_on_unknown_abandoned_acknowledged_or_purged() {
        let (s, _d) = store();
        assert!(matches!(
            s.replay(1).await,
            Err(StorageError::NotFound(_))
        ));

        s.quarantine(use_event(2, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        s.ack(2).await.unwrap();
        assert!(matches!(s.replay(2).await, Err(StorageError::Conflict(_))));

        s.quarantine(use_event(3, "tok-b", "p"), Utc::now())
            .await
            .unwrap();
        s.abandon("tok-b").await.unwrap();
        assert!(matches!(s.replay(3).await, Err(StorageError::Conflict(_))));

        s.quarantine(use_event(4, "tok-c", "p"), Utc::now())
            .await
            .unwrap();
        let cutoff = Utc::now() + chrono::Duration::seconds(1);
        s.purge_expired_params(cutoff).await.unwrap();
        assert!(matches!(s.replay(4).await, Err(StorageError::Conflict(_))));
    }

    /// R3-B (Codex 3rd-pass M5): a quarantined `averin.grant` is NEVER replayable, even while it is
    /// `Open` and unpurged (the exact state that would otherwise pass every other `replay` gate) —
    /// its subject was abandoned and its PoP seed released for GC at dead-letter time (see the
    /// worker's `quarantine_and_reclaim_dead_letter`), so re-enqueuing it could never rebuild a valid
    /// proof-of-possession. An `averin.use` quarantined in the identical (Open, unpurged) state must
    /// still replay normally — this fix is grant-specific, not a broader regression.
    #[tokio::test]
    async fn replay_rejects_a_quarantined_grant_even_when_open_and_unpurged() {
        let (s, _d) = store();
        s.quarantine(grant_event(10, "tok-grant"), Utc::now())
            .await
            .unwrap();
        assert!(
            matches!(s.replay(10).await, Err(StorageError::Conflict(_))),
            "a dead-lettered averin.grant must never be reported as replayable"
        );
        // Rejected, not removed: the quarantine record must still be there afterward.
        assert_eq!(s.entry_count().await.unwrap(), 1);

        s.quarantine(use_event(11, "tok-use", "p"), Utc::now())
            .await
            .unwrap();
        let event = s.replay(11).await.unwrap();
        assert_eq!(event.sequence, 11, "an averin.use in the same Open/unpurged state still replays");
    }

    #[tokio::test]
    async fn purge_expired_params_redacts_only_records_past_the_window_once() {
        let (s, _d) = store();
        let old = Utc::now() - chrono::Duration::days(30);
        let recent = Utc::now();
        s.quarantine(use_event(1, "tok-old", "OLD_SECRET"), old)
            .await
            .unwrap();
        s.quarantine(use_event(2, "tok-new", "NEW_SECRET"), recent)
            .await
            .unwrap();

        let cutoff = Utc::now() - chrono::Duration::days(7);
        let purged = s.purge_expired_params(cutoff).await.unwrap();
        assert_eq!(purged, 1, "only the record dead-lettered before the cutoff is redacted");

        let by_seq: std::collections::HashMap<u64, QuarantineRecord> = s
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.event.sequence, r))
            .collect();
        assert!(by_seq[&1].params_purged);
        assert_ne!(by_seq[&1].event.payload["params"], "OLD_SECRET");
        assert!(!by_seq[&2].params_purged);
        assert_eq!(by_seq[&2].event.payload["params"], "NEW_SECRET");

        // Idempotent: running it again over the SAME cutoff doesn't re-purge (already purged) or
        // touch the still-recent record.
        let purged_again = s.purge_expired_params(cutoff).await.unwrap();
        assert_eq!(purged_again, 0);
    }

    #[tokio::test]
    async fn contains_reflects_presence_regardless_of_status() {
        let (s, _d) = store();
        assert!(!s.contains(1).await.unwrap());
        s.quarantine(use_event(1, "tok-a", "p"), Utc::now()).await.unwrap();
        assert!(s.contains(1).await.unwrap());
        s.ack(1).await.unwrap();
        assert!(s.contains(1).await.unwrap(), "Acknowledged is still present, not gone");
        assert!(s.purge(1).await.unwrap());
        assert!(!s.contains(1).await.unwrap(), "purge actually removes it");
    }

    // ---- D2 cross-store predicate: `has_replayable_for_subject` ----

    #[tokio::test]
    async fn has_replayable_for_subject_true_only_for_an_open_unpurged_record() {
        let (s, _d) = store();
        assert!(
            !s.has_replayable_for_subject("tok-a").await.unwrap(),
            "no quarantined record at all -> not replayable"
        );

        s.quarantine(use_event(1, "tok-a", "p"), Utc::now()).await.unwrap();
        assert!(
            s.has_replayable_for_subject("tok-a").await.unwrap(),
            "a fresh Open, unpurged record IS replayable"
        );
        assert!(
            !s.has_replayable_for_subject("tok-b").await.unwrap(),
            "a different subject is unaffected"
        );

        // Acknowledged -> no longer replayable.
        s.ack(1).await.unwrap();
        assert!(!s.has_replayable_for_subject("tok-a").await.unwrap());

        // Abandoned -> no longer replayable either.
        s.quarantine(use_event(2, "tok-c", "p"), Utc::now()).await.unwrap();
        s.abandon("tok-c").await.unwrap();
        assert!(!s.has_replayable_for_subject("tok-c").await.unwrap());

        // Open but past its params-purge window -> no longer replayable (mirrors `replay`'s own gate).
        s.quarantine(use_event(3, "tok-d", "p"), Utc::now()).await.unwrap();
        let cutoff = Utc::now() + chrono::Duration::seconds(1);
        s.purge_expired_params(cutoff).await.unwrap();
        assert!(!s.has_replayable_for_subject("tok-d").await.unwrap());
    }

    #[tokio::test]
    async fn refuses_a_newer_file_version() {
        let (s, dir) = store();
        s.quarantine(use_event(1, "tok-a", "p"), Utc::now())
            .await
            .unwrap();
        let p = dir.path().join("averin-deadletter.enc");
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["version"] = serde_json::json!(DEADLETTER_FILE_VERSION + 1);
        std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![13u8; 32]).unwrap());
        let s2 = AverinDeadLetterStore::new(p, key);
        assert!(matches!(
            s2.list().await,
            Err(StorageError::UnsupportedVersion { .. })
        ));
    }
}
