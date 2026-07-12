//! The encrypted PoP-key store (plan 088 D2): `token.id -> PopKeyEntry`, holding the durable
//! Ed25519 PoP-key SEED the averin durable-seal delivery worker needs to (re)sign a grant/use
//! after a crash or restart. Whole-file AES-256-GCM persistence — the SAME proven shape as
//! `OutboxStore` (serialize -> encrypt -> tmp -> `sync_all` -> atomic rename -> fsync the parent
//! dir -> `create_private_file` 0600 -> a file-version downgrade guard) is correct here because
//! this store is written at CONTROL-PLANE frequency (mint, grant-delivery write-back, GC
//! eviction), never on the `/execute` hot path — the O(1) append requirement (D0) applies ONLY
//! to the averin USE queue (`averin_queue.rs`), not this store.
//!
//! # At-rest threat model (D2 — resolve, do not re-open)
//!
//! `pop_seed` is the ONLY non-averin PRIVATE key this store persists (`docs/dev/averin-sealing.md
//! §1`): same posture as `credentials.enc`'s secrets — AES-256-GCM under the shared vault master
//! key, `0600`, never logged, never in an error `Display`, never in a config dump, and (this
//! module) never in `Debug` (see [`PopKeyEntry`]'s hand-written impl, mirroring `OutboxConfig`'s
//! redacting `Debug`, `src/outbox.rs:715-729`). This is NOT a new key primitive: it reuses
//! `crate::crypto::{encrypt, decrypt}` + the same shared `Arc<MasterKey>` exactly.
//!
//! # Eviction — the REWRITTEN rule (D2, adversarial finding #6)
//!
//! The draft's rule ("evict once `minted_at + grant_ttl` elapsed AND events terminal") was wrong
//! three ways: a dead-lettered use still needs its seed to replay; `minted_at` is the wrong clock
//! (a grant that sat in a backlog past `grant_ttl_secs` before delivering would be evicted the
//! moment it landed, before its use could deliver); and a lone `gc(now)` had no view of the
//! queue/quarantine subject state. The rule here is: **retain the seed until the subject is fully
//! resolved.** [`PopKeyStore::evict_resolved`] evicts `token.id` IFF:
//!   (a) the grant is terminal-delivered (`grant_delivered_at.is_some()`) OR the subject is
//!       `abandoned`, AND
//!   (b) no pending/leased use exists for `subject == token.id`, AND
//!   (c) no replayable dead-lettered use exists for that subject.
//!
//! `minted_at` is retained for audit ONLY and is NEVER an eviction trigger; `grant_expires_at`
//! only informs operators, never eviction. Because the averin USE queue (D0) and the dead-letter
//! quarantine (D4) are separate stores not wired until later steps, (b) and (c) are INJECTED
//! predicates/closures — the caller decides how to answer them (a later step passes the real
//! queue/quarantine lookups). The cross-store query FAILS CLOSED TOWARD RETENTION (D2): a
//! predicate that cannot be evaluated must answer `true` ("still blocking") — over-retention (a
//! resolved subject's seed lingers one extra tick) is harmless; under-retention (evicting a seed
//! a live/replayable use still needs) is a correctness bug and must never happen. See
//! [`PopKeyStore::evict_resolved`]'s doc for the exact contract.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use crate::storage::outbox_store::{create_private_file, fsync_parent_dir};
use crate::storage::StorageError;

/// On-disk format version for the POPKEY file (independent of the vault's/outbox's own version
/// counters). v1 is the first format. A newer file is refused (binary downgrade guard, mirroring
/// `OutboxStore`/the vault).
const POPKEY_FILE_VERSION: u32 = 1;

/// The encrypted on-disk envelope. No salt: the key is the vault's already-derived master key
/// (shared via `Arc`), so this file decrypts with it directly — no separate KDF.
#[derive(Debug, Serialize, Deserialize)]
struct PopKeyFile {
    version: u32,
    data: EncryptedData,
}

/// The in-memory cache, keyed by `token.id`. A `BTreeMap` gives deterministic on-disk key order
/// (mirrors `OutboxCache`'s `BTreeMap<seq, OutboxEvent>`), so re-serializing an unchanged map is
/// byte-identical — useful for the no-op-write style tests elsewhere in this crate.
#[derive(Default, Serialize, Deserialize)]
struct PopKeyCache {
    entries: BTreeMap<String, PopKeyEntry>,
}

/// One PoP-key lifecycle record, keyed externally by `token.id` (plan 088 D2's exact shape).
#[derive(Clone, Serialize, Deserialize)]
pub struct PopKeyEntry {
    /// The Ed25519 `SigningKey` seed (32 bytes, `PopKeypair::seed_bytes`) — the SENSITIVE field.
    /// Reconstruct the signing keypair with `PopKeypair::from_seed_bytes`. NEVER logged, NEVER in
    /// `Debug` (see the hand-written impl below), NEVER in an `AverinError` `Display`.
    pub pop_seed: [u8; 32],
    /// The grant's action (the use must present the same one).
    pub action: String,
    pub scope: String,
    pub use_limit: Option<u32>,
    /// Filled in when the GRANT delivers (D3's `GrantResolved` write-back).
    pub capability: Option<String>,
    /// Filled in when the GRANT delivers (D3's `GrantResolved` write-back).
    pub grant_id: Option<String>,
    /// Control/audit only — NEVER an eviction trigger (see the module doc / `evict_resolved`).
    pub minted_at: DateTime<Utc>,
    /// Set when the grant actually delivers; `Some` is this entry's "terminal-delivered" signal
    /// for eviction rule (a).
    pub grant_delivered_at: Option<DateTime<Utc>>,
    /// averin's grant validity end (from the grant response / delivered_at + ttl). Operator-info
    /// only — never consulted by eviction.
    pub grant_expires_at: Option<DateTime<Utc>>,
    /// Operator-set: the subject is being purged (D4's abandon/purge releases it). `true` is the
    /// OTHER way eviction rule (a) can be satisfied, independent of `grant_delivered_at` (e.g. a
    /// grant that permanently dead-lettered and never delivered).
    pub abandoned: bool,
}

impl std::fmt::Debug for PopKeyEntry {
    /// Hand-written to REDACT `pop_seed` — mirrors `OutboxConfig`'s redacting `Debug`
    /// (`src/outbox.rs:715-729`). The seed must never appear in `Debug`, logs, or any error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PopKeyEntry")
            .field("pop_seed", &"[redacted; 32 bytes]")
            .field("action", &self.action)
            .field("scope", &self.scope)
            .field("use_limit", &self.use_limit)
            .field("capability", &self.capability)
            .field("grant_id", &self.grant_id)
            .field("minted_at", &self.minted_at)
            .field("grant_delivered_at", &self.grant_delivered_at)
            .field("grant_expires_at", &self.grant_expires_at)
            .field("abandoned", &self.abandoned)
            .finish()
    }
}

/// The encrypted, durable PoP-key store (plan 088 D2). See the module doc for the at-rest threat
/// model and the eviction rule.
pub struct PopKeyStore {
    path: PathBuf,
    master_key: Arc<MasterKey>,
    cache: RwLock<PopKeyCache>,
    /// (mtime,len) of the file as of this process's last decrypt — skips a redundant decrypt when
    /// the file is byte-unchanged. Mirrors `OutboxStore`/`FileStorage`.
    last_loaded: Mutex<Option<(SystemTime, u64)>>,
}

impl PopKeyStore {
    /// Open (lazily) a PoP-key store at `path`, encrypting with the shared vault master key. The
    /// file is created on first write; an absent file reads as empty.
    pub fn new(path: PathBuf, master_key: Arc<MasterKey>) -> Self {
        Self {
            path,
            master_key,
            cache: RwLock::new(PopKeyCache::default()),
            last_loaded: Mutex::new(None),
        }
    }

    // ---- public API ----

    /// Insert (or idempotently overwrite) the entry for `token_id` — the mint-time write (D2:
    /// "written ONLY at mint... at grant-delivery write-back... and on GC eviction"). A retry of
    /// the SAME mint after a crash re-inserts the same fields, which is harmless (whole-file
    /// persistence, control-plane frequency — not the hot path).
    pub async fn insert(&self, token_id: &str, entry: PopKeyEntry) -> Result<(), StorageError> {
        let token_id = token_id.to_string();
        self.locked_mutate(move |c| {
            c.entries.insert(token_id, entry);
            Ok(((), true))
        })
        .await
    }

    /// Look up the entry for `token_id`.
    pub async fn get(&self, token_id: &str) -> Result<Option<PopKeyEntry>, StorageError> {
        self.reload().await?;
        let c = self.cache.read();
        Ok(c.entries.get(token_id).cloned())
    }

    /// The D3 `GrantResolved` write-back: when the GRANT delivers, record averin's response
    /// (`capability`, `grant_id`) plus `grant_delivered_at` (+ `grant_expires_at`) into the
    /// existing entry. Returns `false` if `token_id` is unknown (no-op, no write).
    pub async fn grant_resolved(
        &self,
        token_id: &str,
        capability: String,
        grant_id: String,
        delivered_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<bool, StorageError> {
        let token_id = token_id.to_string();
        self.locked_mutate(move |c| match c.entries.get_mut(&token_id) {
            Some(e) => {
                e.capability = Some(capability);
                e.grant_id = Some(grant_id);
                e.grant_delivered_at = Some(delivered_at);
                e.grant_expires_at = expires_at;
                Ok((true, true))
            }
            None => Ok((false, false)),
        })
        .await
    }

    /// Operator-initiated: mark the subject abandoned (D4's abandon/purge releases it), which is
    /// the OTHER way eviction rule (a) can be satisfied — e.g. for a grant that permanently
    /// dead-lettered and so never sets `grant_delivered_at`. Returns `false` if `token_id` is
    /// unknown.
    pub async fn mark_abandoned(&self, token_id: &str) -> Result<bool, StorageError> {
        let token_id = token_id.to_string();
        self.locked_mutate(move |c| match c.entries.get_mut(&token_id) {
            Some(e) if !e.abandoned => {
                e.abandoned = true;
                Ok((true, true))
            }
            Some(_) => Ok((true, false)), // already abandoned — no-op, no write
            None => Ok((false, false)),
        })
        .await
    }

    /// The D2 rewritten eviction rule. Evicts `token_id` IFF (a) the grant is terminal-delivered
    /// (`grant_delivered_at.is_some()`) OR the subject is `abandoned`, AND (b)
    /// `subject_has_live_use(token_id)` returns `false`, AND (c)
    /// `subject_has_replayable_dead_letter(token_id)` returns `false`. `minted_at`/
    /// `grant_expires_at` are NEVER consulted (audit/operator-info only, per the module doc).
    ///
    /// **Fail-closed contract (load-bearing):** both predicates answer a plain `bool`, but the
    /// CALLER MUST return `true` ("still blocking") whenever the answer cannot be determined —
    /// e.g. the queue/quarantine store is unreachable, or the cross-store query itself failed.
    /// Returning `false` ("safe to evict") on an ambiguous/unknown case would let this method
    /// delete a seed a live or replayable use might still need — a correctness bug, not a merely
    /// degraded read. Over-retention (a resolved subject's seed lingers one extra GC tick because
    /// a caller was conservative) is always the safe failure mode; under-retention never is.
    ///
    /// Both closures are called once per resolved candidate while this store's own write lock is
    /// held; a real implementation of these predicates (a later step) is expected to do its own
    /// locking against the queue/quarantine stores — that is a DIFFERENT lock, so no cycle, as
    /// long as those stores never call back into this one while holding theirs (they don't: the
    /// queue/quarantine GC ticks run strictly before this store's, per the module doc).
    ///
    /// Returns the number of entries evicted.
    pub async fn evict_resolved(
        &self,
        subject_has_live_use: impl Fn(&str) -> bool,
        subject_has_replayable_dead_letter: impl Fn(&str) -> bool,
    ) -> Result<usize, StorageError> {
        self.locked_mutate(move |c| {
            let candidates: Vec<String> = c
                .entries
                .iter()
                .filter(|(_, e)| e.grant_delivered_at.is_some() || e.abandoned)
                .map(|(id, _)| id.clone())
                .collect();
            let mut evicted = 0usize;
            for token_id in candidates {
                if subject_has_live_use(&token_id) {
                    continue; // (b): a pending/leased use still needs this seed
                }
                if subject_has_replayable_dead_letter(&token_id) {
                    continue; // (c): a replayable dead-lettered use still needs this seed
                }
                c.entries.remove(&token_id);
                evicted += 1;
            }
            Ok((evicted, evicted > 0))
        })
        .await
    }

    /// Number of retained entries (test/ops introspection).
    pub async fn entry_count(&self) -> Result<usize, StorageError> {
        self.reload().await?;
        Ok(self.cache.read().entries.len())
    }

    // ---- internal persistence (mirrors OutboxStore's locked_mutate / reload on its own file) ----

    /// The closure returns `(value, dirty)`, matching `OutboxStore::locked_mutate`'s contract:
    /// `dirty` must be true whenever the cache was mutated in a way that needs persisting.
    async fn locked_mutate<T>(
        &self,
        f: impl FnOnce(&mut PopKeyCache) -> Result<(T, bool), StorageError>,
    ) -> Result<T, StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.locked_mutate_blocking(f),
            _ => tokio::task::block_in_place(|| self.locked_mutate_blocking(f)),
        }
    }

    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut PopKeyCache) -> Result<(T, bool), StorageError>,
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

    fn read_from_disk(&self) -> Result<PopKeyCache, StorageError> {
        if !self.path.exists() {
            return Ok(PopKeyCache::default());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let file: PopKeyFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        if file.version > POPKEY_FILE_VERSION {
            return Err(StorageError::UnsupportedVersion {
                found: file.version,
                supported: POPKEY_FILE_VERSION,
            });
        }
        let plaintext = decrypt(&file.data, &self.master_key)?;
        serde_json::from_slice(&plaintext).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    fn write_to_disk(&self, cache: &PopKeyCache) -> Result<(), StorageError> {
        // Create the parent dir lazily (self-contained: don't assume the vault's FileStorage::new
        // ran first).
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data =
            serde_json::to_vec(cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, &self.master_key)?;
        let file = PopKeyFile {
            version: POPKEY_FILE_VERSION,
            data: encrypted,
        };
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let temp_path = self.path.with_extension("tmp");
        // fsync the tmp BEFORE the rename (same discipline as OutboxStore::write_to_disk): the
        // rename gives crash-ATOMICITY, only sync_all gives crash-DURABILITY of the contents.
        {
            // 0600: this file holds the ONLY non-averin private key in the flow — never leave it
            // group/world-readable even though it is encrypted (same posture as outbox.enc /
            // credentials.enc).
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
        // Make the rename crash-DURABLE, not just crash-atomic; a real fsync error propagates so
        // the caller does not treat a non-durable write as committed.
        fsync_parent_dir(&self.path)?;
        Ok(())
    }

    fn file_change_token(&self) -> Option<(SystemTime, u64)> {
        let meta = std::fs::metadata(&self.path).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (PopKeyStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![9u8; 32]).unwrap());
        (
            PopKeyStore::new(dir.path().join("averin-popkeys.enc"), key),
            dir,
        )
    }

    fn entry(seed: [u8; 32]) -> PopKeyEntry {
        PopKeyEntry {
            pop_seed: seed,
            action: "db.query:orders-ro".to_string(),
            scope: "read:orders".to_string(),
            use_limit: Some(3),
            capability: None,
            grant_id: None,
            minted_at: Utc::now(),
            grant_delivered_at: None,
            grant_expires_at: None,
            abandoned: false,
        }
    }

    #[tokio::test]
    async fn insert_get_and_grant_resolved_write_back_round_trip() {
        let (s, _d) = store();
        let seed = [7u8; 32];
        s.insert("tok-1", entry(seed)).await.unwrap();

        let got = s.get("tok-1").await.unwrap().unwrap();
        assert_eq!(got.pop_seed, seed);
        assert_eq!(got.action, "db.query:orders-ro");
        assert!(got.grant_delivered_at.is_none());

        let now = Utc::now();
        let updated = s
            .grant_resolved(
                "tok-1",
                "cap-token".to_string(),
                "grant-1".to_string(),
                now,
                Some(now),
            )
            .await
            .unwrap();
        assert!(updated);

        let got = s.get("tok-1").await.unwrap().unwrap();
        assert_eq!(got.capability.as_deref(), Some("cap-token"));
        assert_eq!(got.grant_id.as_deref(), Some("grant-1"));
        assert_eq!(got.grant_delivered_at, Some(now));

        // Unknown token_id is a no-op, not an error.
        assert!(!s
            .grant_resolved("nope", "c".into(), "g".into(), now, None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn survives_reopen_on_the_same_file() {
        let (s, dir) = store();
        let key = Arc::new(MasterKey::from_bytes(vec![9u8; 32]).unwrap());
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();

        let reopened = PopKeyStore::new(dir.path().join("averin-popkeys.enc"), key);
        let got = reopened.get("tok-1").await.unwrap().unwrap();
        assert_eq!(got.pop_seed, [1u8; 32]);
    }

    #[tokio::test]
    async fn on_disk_bytes_are_ciphertext_not_plaintext() {
        // D2: the seed (and the rest of the entry) must be encrypted at rest — neither the raw
        // seed bytes nor a plaintext marker in another field may appear in the file's raw bytes.
        let (s, dir) = store();
        let seed = [0x42u8; 32]; // a distinctive, repeated byte pattern
        let mut e = entry(seed);
        e.action = "PLAINTEXT_MARKER_a1b2c3".to_string();
        s.insert("tok-1", e).await.unwrap();

        let raw = std::fs::read(dir.path().join("averin-popkeys.enc")).unwrap();
        assert!(
            !raw.windows(seed.len()).any(|w| w == seed),
            "pop_seed leaked in plaintext on disk"
        );
        let marker = "PLAINTEXT_MARKER_a1b2c3";
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "entry payload leaked in plaintext on disk"
        );

        // ...but decrypting it back recovers the entry (round-trip).
        let key = Arc::new(MasterKey::from_bytes(vec![9u8; 32]).unwrap());
        let s2 = PopKeyStore::new(dir.path().join("averin-popkeys.enc"), key);
        let got = s2.get("tok-1").await.unwrap().unwrap();
        assert_eq!(got.pop_seed, seed);
        assert_eq!(got.action, marker);
    }

    #[test]
    fn debug_never_prints_the_seed() {
        let seed = [0x99u8; 32];
        let e = entry(seed);
        let dbg = format!("{:?}", e);
        // What an UN-redacted `#[derive(Debug)]` would have printed for the array — assert its
        // exact absence (rather than a coincidental substring like a decimal byte value, which
        // could spuriously appear inside an unrelated timestamp field).
        let raw_array_debug = format!("{:?}", seed);
        assert!(
            !dbg.contains(&raw_array_debug),
            "Debug output must not print the raw seed bytes: {dbg}"
        );
        assert!(
            dbg.contains("[redacted; 32 bytes]"),
            "Debug output must contain the redaction marker: {dbg}"
        );
    }

    #[tokio::test]
    async fn refuses_a_newer_file_version() {
        let (s, dir) = store();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        let p = dir.path().join("averin-popkeys.enc");
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["version"] = serde_json::json!(POPKEY_FILE_VERSION + 1);
        std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
        let key = Arc::new(MasterKey::from_bytes(vec![9u8; 32]).unwrap());
        let s2 = PopKeyStore::new(p, key);
        assert!(matches!(
            s2.get("tok-1").await,
            Err(StorageError::UnsupportedVersion { .. })
        ));
    }

    // ---- eviction (D2 rewritten rule) ----

    #[tokio::test]
    async fn eviction_skips_an_unresolved_subject_regardless_of_predicates() {
        let (s, _d) = store();
        s.insert("tok-pending", entry([1u8; 32])).await.unwrap(); // grant never delivered, not abandoned
        let evicted = s.evict_resolved(|_| false, |_| false).await.unwrap();
        assert_eq!(evicted, 0, "an unresolved subject is never evicted");
        assert_eq!(s.entry_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn eviction_retains_a_resolved_subject_with_a_live_use() {
        let (s, _d) = store();
        let now = Utc::now();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        s.grant_resolved("tok-1", "cap".into(), "grant-1".into(), now, None)
            .await
            .unwrap();
        // Resolved, but a pending/leased use still exists for the subject → must NOT evict.
        let evicted = s
            .evict_resolved(|subj| subj == "tok-1", |_| false)
            .await
            .unwrap();
        assert_eq!(evicted, 0, "a live use blocks eviction (D2 rule b)");
        assert_eq!(s.entry_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn eviction_retains_a_resolved_subject_with_a_replayable_dead_letter() {
        let (s, _d) = store();
        let now = Utc::now();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        s.grant_resolved("tok-1", "cap".into(), "grant-1".into(), now, None)
            .await
            .unwrap();
        // Resolved, no live use, but a replayable dead-lettered use still exists → must NOT evict.
        let evicted = s
            .evict_resolved(|_| false, |subj| subj == "tok-1")
            .await
            .unwrap();
        assert_eq!(
            evicted, 0,
            "a replayable dead-letter blocks eviction (D2 rule c)"
        );
        assert_eq!(s.entry_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn eviction_removes_a_fully_resolved_subject() {
        let (s, _d) = store();
        let now = Utc::now();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        s.grant_resolved("tok-1", "cap".into(), "grant-1".into(), now, None)
            .await
            .unwrap();
        let evicted = s.evict_resolved(|_| false, |_| false).await.unwrap();
        assert_eq!(
            evicted, 1,
            "grant delivered + no live use + no replayable dead-letter → evict"
        );
        assert!(s.get("tok-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eviction_via_abandoned_does_not_require_grant_delivery() {
        // A grant that permanently dead-lettered never sets grant_delivered_at; the operator
        // abandon path is the ONLY way rule (a) is satisfied for it.
        let (s, _d) = store();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        assert_eq!(
            s.evict_resolved(|_| false, |_| false).await.unwrap(),
            0,
            "not resolved yet — neither delivered nor abandoned"
        );
        assert!(s.mark_abandoned("tok-1").await.unwrap());
        let evicted = s.evict_resolved(|_| false, |_| false).await.unwrap();
        assert_eq!(evicted, 1, "abandoned satisfies rule (a) without a delivered grant");
    }

    #[tokio::test]
    async fn eviction_only_removes_the_targeted_subject() {
        let (s, _d) = store();
        let now = Utc::now();
        for id in ["a", "b", "c"] {
            s.insert(id, entry([1u8; 32])).await.unwrap();
            s.grant_resolved(id, "cap".into(), "g".into(), now, None)
                .await
                .unwrap();
        }
        // Only "b" has a live use; "a" and "c" fully resolve.
        let evicted = s
            .evict_resolved(|subj| subj == "b", |_| false)
            .await
            .unwrap();
        assert_eq!(evicted, 2);
        assert!(s.get("a").await.unwrap().is_none());
        assert!(s.get("b").await.unwrap().is_some(), "b retained: live use");
        assert!(s.get("c").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fail_closed_toward_retention_when_a_predicate_is_conservative() {
        // Models the "cannot be evaluated" case from the module doc: a caller that cannot
        // determine an answer MUST return `true` (blocking) rather than `false` (safe to evict).
        // This test demonstrates that a conservative `true` answer retains the seed, i.e. the
        // fail-closed contract, if honored by the caller, is enforced by this method.
        let (s, _d) = store();
        let now = Utc::now();
        s.insert("tok-1", entry([1u8; 32])).await.unwrap();
        s.grant_resolved("tok-1", "cap".into(), "g".into(), now, None)
            .await
            .unwrap();
        let unknown_is_blocking = |_subj: &str| true; // conservative "cannot evaluate" answer
        let evicted = s
            .evict_resolved(unknown_is_blocking, |_| false)
            .await
            .unwrap();
        assert_eq!(evicted, 0, "an unevaluable predicate must retain, never evict");
    }
}
