//! Encrypted file-based storage backend
//!
//! Stores credentials in an encrypted JSON file on disk.

use super::{IdempotencyState, StorageBackend, StorageError};
use crate::approval::ApprovalRequest;
use crate::auth::{ApiKey, Role, UseToken};
use crate::capability::Capability;
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, EncryptedData, MasterKey};
use crate::policy::Policy;
use crate::{Credential, CredentialMetadata};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use super::outbox_store::OutboxStore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

/// An approval whose execution claim is older than this is considered stale
/// (the claiming process likely crashed) and may be re-claimed.
const STALE_EXECUTING_SECS: i64 = 120;

/// Highest on-disk storage format version this build understands. A vault whose
/// recorded version is greater than this was written by a newer vultrino; we
/// refuse to open it rather than silently round-trip (and drop) fields we don't
/// know about.
///
/// v4 (V1 admin API): adds the `policies` and `idempotency` maps. New fields use
/// `#[serde(default)]`, so a v4 binary reads older vaults fine; an older binary
/// is correctly refused a v4 vault by [`check_version`] rather than silently
/// dropping admin-managed policies on its next write.
///
/// v6 (connector M1): adds the `capabilities` map (named-MCP-tool definitions).
/// `#[serde(default)]`, so a v6 binary reads older vaults; an older binary is
/// refused a v6 vault rather than silently dropping capabilities on its next write.
const STORAGE_VERSION: u32 = 7; // v7: the signed outbox moved OUT of the vault into its own encrypted file

/// A reservation older than this (seconds) is assumed orphaned by a crashed
/// request and may be re-reserved, so a single failed admin call can't block a
/// given Idempotency-Key forever.
const STALE_IDEMPOTENCY_RESERVATION_SECS: i64 = 60;

/// Completed idempotency records older than this (seconds) are garbage-collected
/// opportunistically so the map can't grow without bound.
const IDEMPOTENCY_RETENTION_SECS: i64 = 24 * 60 * 60;

/// Whether an approval has a pending SLA/reauth transition at `now` (V5): an open
/// request past its final deadline (expire) or, when Pending, past its first
/// window (escalate); or an approved-but-unrun grant whose reauth window lapsed.
/// Shared by the `poll_refresh_approval` pre-check and the sweep's `any_due` gate
/// so those two cheap fast-path pre-checks stay in lock-step with each other. The
/// authoritative transition under the lock still uses `advance_lifecycle()` /
/// `needs_reauth()`; this only gates whether to take that locked path.
fn approval_is_due(a: &ApprovalRequest, now: DateTime<Utc>) -> bool {
    use crate::approval::ApprovalStatus;
    (a.status.is_open()
        && (now >= a.expires_at
            || (a.status == ApprovalStatus::Pending && now >= a.escalate_at)))
        || a.needs_reauth()
}

/// Upper bound on the vault's staged-but-undrained outbox intents. If the split outbox file is
/// persistently unwritable, `pending_events` would otherwise grow without limit — and because it lives
/// IN the secrets vault, every new coupled emit re-encrypts an ever-larger vault (re-opening the
/// O(vault-size) cliff the v6→v7 split removed). At the cap, staging FAILS CLOSED: a new
/// security-sensitive decision is refused rather than committed-but-undeliverable, bounding the vault
/// churn. Generous — only reached after the outbox has been dead for a long time under heavy decision
/// load (the periodic reconciler clears the backlog within a tick in the normal/transient case).
const MAX_PENDING_EVENTS: usize = 10_000;

/// Stage an outbox event in the vault for the intent drain (D1) — written atomically with the state
/// change that produced it, inside the SAME locked_mutate. The caller drains it to the split outbox
/// file after the lock releases (drain_pending_events). A fresh dedup_id makes the later drain
/// idempotent. Returns an error (so the enclosing locked_mutate ABORTS the state change too) when the
/// undrained backlog has hit MAX_PENDING_EVENTS — fail-closed back-pressure on a stuck outbox.
fn stage_event(
    cache: &mut StorageCache,
    subject: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), StorageError> {
    if cache.pending_events.len() >= MAX_PENDING_EVENTS {
        return Err(StorageError::Unavailable(format!(
            "outbox unwritable: {} signed events staged-but-undelivered (cap {}); refusing the coupled \
             state change to bound secrets-vault churn (fail-closed — resolve the outbox, then retry)",
            cache.pending_events.len(),
            MAX_PENDING_EVENTS
        )));
    }
    cache.pending_events.push(StagedEvent {
        dedup_id: uuid::Uuid::new_v4().to_string(),
        subject: subject.to_string(),
        event_type: event_type.to_string(),
        payload,
    });
    Ok(())
}

/// The agent-safe outbox payload for an approval decision/lifecycle event (V9).
fn approval_event_payload(a: &ApprovalRequest) -> serde_json::Value {
    serde_json::json!({
        "approval_id": a.id,
        "status": a.status.to_string(),
        "credential": a.credential,
        "action": a.action,
        "summary": a.summary,
        "decided_by": a.decided_by,
        "approver_identity": a.approver_identity,
    })
}

/// Refuse to open a vault written by a newer binary.
fn check_version(found: u32) -> Result<(), StorageError> {
    if found > STORAGE_VERSION {
        Err(StorageError::UnsupportedVersion {
            found,
            supported: STORAGE_VERSION,
        })
    } else {
        Ok(())
    }
}

/// File-based storage with AES-256-GCM encryption
pub struct FileStorage {
    /// Path to the storage file
    path: PathBuf,
    /// Master encryption key (Arc so the OutboxStore shares the SAME derived key — D2: the outbox
    /// file is encrypted with it, no separate KDF).
    master_key: Arc<MasterKey>,
    /// The signed event outbox in its OWN encrypted file (v7: split out of the secrets vault so an
    /// event append no longer rewrites all secrets). The vault delegates all outbox trait methods to
    /// it; coupled emits (approval decisions) stage an intent in the vault then drain to it.
    outbox: OutboxStore,
    /// In-memory cache of credentials
    cache: RwLock<StorageCache>,
    /// Salt used for key derivation (stored in file)
    salt: Vec<u8>,
    /// Change token (mtime, len) of the on-disk vault as of the last decrypt INTO
    /// `cache` by THIS process. `reload` skips the (expensive) whole-vault decrypt when
    /// the file is byte-unchanged since then — so a broker poll that finds no new outbox
    /// events doesn't re-decrypt every secret. `None` until the first load. Per-instance:
    /// a sibling process's write bumps the file mtime, which this process detects on its
    /// next reload. (STOPGAP for the read path — subsumed once the outbox moves to its own
    /// store; see docs/dev/OUTBOX-OUT-OF-VAULT-MIGRATION.md.)
    last_loaded: parking_lot::Mutex<Option<(std::time::SystemTime, u64)>>,
}

/// The outbox file lives alongside the vault (credentials.enc → outbox.enc), in the same data dir
/// (its own PVC in k8s). Its `.lock`/`.tmp` sidecars don't collide with the vault's.
fn outbox_path(vault: &Path) -> PathBuf {
    vault.with_file_name("outbox.enc")
}

/// An outbox event STAGED in the vault (intent-staging, D1): written atomically with the state change
/// that produced it (an approval decision), then drained to the split outbox file. `dedup_id` (a fresh
/// UUID per stage) makes the drain idempotent — a crash between the outbox append and clearing this
/// intent re-drains without duplicating the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StagedEvent {
    dedup_id: String,
    subject: String,
    event_type: String,
    payload: serde_json::Value,
}

/// A record of an idempotent admin-API mutation: a reservation taken under the
/// storage lock, later completed with the response to replay on a repeated key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdempotencyRecord {
    /// True once the operation finished and `status`/`response` are populated.
    done: bool,
    /// Hash of the request body this key was first used with. A later request
    /// reusing the key with a different body is a `Mismatch`, never a replay.
    #[serde(default)]
    body_hash: String,
    /// Stored HTTP status to replay on a repeated key.
    #[serde(default)]
    status: u16,
    /// Stored JSON body to replay on a repeated key.
    #[serde(default)]
    response: String,
    /// When the key was first reserved (for stale-reservation recovery and GC).
    created_at: DateTime<Utc>,
}

/// In-memory cache of all storage data
#[derive(Debug, Default, Serialize, Deserialize)]
struct StorageCache {
    /// Credentials by ID
    credentials: HashMap<String, Credential>,
    /// Roles by ID
    #[serde(default)]
    roles: HashMap<String, Role>,
    /// API keys by ID
    #[serde(default)]
    api_keys: HashMap<String, ApiKey>,
    /// Use tokens by ID
    #[serde(default)]
    use_tokens: HashMap<String, UseToken>,
    /// Approval requests by ID
    #[serde(default)]
    approvals: HashMap<String, ApprovalRequest>,
    /// Policies pushed via the admin API (V1), keyed by policy id. The server
    /// merges these with the static config policies into the live engine.
    #[serde(default)]
    policies: HashMap<String, Policy>,
    /// Capabilities (named-MCP-tool definitions) pushed via the admin API
    /// (connector M1), keyed by capability id. The MCP server reads these to
    /// expose per-principal named tools. They carry no secret (a credential_ref
    /// alias only).
    #[serde(default)]
    capabilities: HashMap<String, Capability>,
    /// Idempotency records for admin-API mutations, keyed by Idempotency-Key.
    #[serde(default)]
    idempotency: HashMap<String, IdempotencyRecord>,
    /// LEGACY (v6): the signed event outbox used to live IN the vault. v7 moved it to its own file
    /// (OutboxStore). These two fields are retained ONLY so a v6 vault's outbox can be READ and
    /// drained on first v7 open (migrate_v6_outbox); they stay empty thereafter. Do not append here.
    #[serde(default)]
    outbox: std::collections::BTreeMap<u64, crate::outbox::OutboxEvent>,
    #[serde(default)]
    outbox_seq: u64,
    /// Intent-staging (v7, D1): outbox events written ATOMICALLY with the state change that produced
    /// them (e.g. an approval decision), pending a drain to the split outbox file. Empty in steady
    /// state; a crash leaves entries here that the next startup reconciles. Each carries a dedup_id so
    /// the drain is idempotent.
    #[serde(default)]
    pending_events: Vec<StagedEvent>,

    // Secondary indexes for O(1) lookups (not serialized, rebuilt on load)
    /// Index: credential alias -> credential ID
    #[serde(skip)]
    alias_index: HashMap<String, String>,
    /// Index: role name -> role ID
    #[serde(skip)]
    role_name_index: HashMap<String, String>,
    /// Index: API key hash -> API key ID
    #[serde(skip)]
    api_key_hash_index: HashMap<String, String>,
    /// Index: use token hash -> use token ID
    #[serde(skip)]
    use_token_hash_index: HashMap<String, String>,
}

impl StorageCache {
    /// Rebuild all secondary indexes from primary data
    fn rebuild_indexes(&mut self) {
        // Clear existing indexes
        self.alias_index.clear();
        self.role_name_index.clear();
        self.api_key_hash_index.clear();
        self.use_token_hash_index.clear();

        // Rebuild credential alias index
        for (id, cred) in &self.credentials {
            self.alias_index.insert(cred.alias.clone(), id.clone());
        }

        // Rebuild role name index
        for (id, role) in &self.roles {
            self.role_name_index.insert(role.name.clone(), id.clone());
        }

        // Rebuild API key hash index
        for (id, key) in &self.api_keys {
            self.api_key_hash_index.insert(key.key_hash.clone(), id.clone());
        }

        // Rebuild use token hash index
        for (id, token) in &self.use_tokens {
            self.use_token_hash_index.insert(token.token_hash.clone(), id.clone());
        }
    }

    /// Drop idempotency records that can no longer be useful so the map can't
    /// grow without bound: completed records past the retention window, and
    /// orphaned in-flight reservations (a crash between reserve and complete)
    /// past the stale-reservation window.
    fn gc_idempotency(&mut self) {
        let now = Utc::now();
        self.idempotency.retain(|_, rec| {
            let age = (now - rec.created_at).num_seconds();
            if rec.done {
                age < IDEMPOTENCY_RETENTION_SECS
            } else {
                age < STALE_IDEMPOTENCY_RESERVATION_SECS
            }
        });
    }
}

/// On-disk format for the storage file
#[derive(Debug, Serialize, Deserialize)]
struct StorageFile {
    /// Version for future migrations
    version: u32,
    /// Salt for key derivation
    salt: String,
    /// Encrypted data (credentials, roles, api_keys)
    #[serde(alias = "credentials")]
    data: EncryptedData,
}

impl FileStorage {
    /// Create a new file storage, loading existing data if present
    pub async fn new(path: impl AsRef<Path>, password: &SecretString) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Check if file exists
        if path.exists() {
            // Load existing storage
            Self::load(path, password).await
        } else {
            // Create new storage
            Self::create(path, password).await
        }
    }

    /// Create a new storage file
    async fn create(path: PathBuf, password: &SecretString) -> Result<Self, StorageError> {
        let salt = generate_salt();
        let master_key = Arc::new(derive_key(password, &salt)?);
        let outbox = OutboxStore::new(outbox_path(&path), Arc::clone(&master_key));

        let storage = Self {
            path,
            master_key,
            outbox,
            cache: RwLock::new(StorageCache::default()),
            salt,
            last_loaded: parking_lot::Mutex::new(None),
        };

        // Write initial empty storage (through the cross-process lock).
        storage.locked_mutate(|_| Ok(())).await?;

        Ok(storage)
    }

    /// Load an existing storage file
    async fn load(path: PathBuf, password: &SecretString) -> Result<Self, StorageError> {
        let content = fs::read_to_string(&path).await?;
        let storage_file: StorageFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        check_version(storage_file.version)?;

        // Decode salt
        let salt = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &storage_file.salt,
        )
        .map_err(|e| StorageError::Serialization(format!("Invalid salt: {}", e)))?;

        // Derive key from password
        let master_key = Arc::new(derive_key(password, &salt)?);

        // Decrypt + parse (tolerates the legacy credentials-only format)
        let decrypted = decrypt(&storage_file.data, &master_key)?;
        let cache = Self::parse_cache(&decrypted)?;

        let outbox = OutboxStore::new(outbox_path(&path), Arc::clone(&master_key));
        let storage = Self {
            path,
            master_key,
            outbox,
            cache: RwLock::new(cache),
            salt,
            last_loaded: parking_lot::Mutex::new(None),
        };
        // Seed the change token so the first reload can skip a redundant decrypt of the
        // file we just loaded (unless a write bumps its mtime first).
        *storage.last_loaded.lock() = storage.file_change_token();

        // v6→v7 migration (D4, best-effort): a v6 vault carried the outbox INSIDE it. Drain those
        // events into the new outbox file (preserving their sequence so the broker cursor doesn't
        // rewind), then clear them from the vault. Idempotent: insert_event is keyed by sequence, and
        // a partial migration re-runs cleanly on the next open. Fresh v7 vaults have an empty outbox.
        storage.migrate_v6_outbox().await?;
        // Reconcile any intent-staged events a prior crash left undrained (D1) — drain them to the
        // outbox before serving so a coupled emit (an approval decision) is never lost.
        storage.drain_pending_events().await?;
        Ok(storage)
    }

    /// Drain a v6 in-vault outbox into the split-out outbox file (one-time, on first v7 open).
    async fn migrate_v6_outbox(&self) -> Result<(), StorageError> {
        let legacy: Vec<crate::outbox::OutboxEvent> = {
            let c = self.cache.read();
            if c.outbox.is_empty() {
                return Ok(()); // fresh v7 (or already migrated)
            }
            c.outbox.values().cloned().collect()
        };
        let count = legacy.len();
        let migrated_seqs: std::collections::HashSet<u64> =
            legacy.iter().map(|e| e.sequence).collect();
        // Reserve the whole legacy sequence range up front (one locked write) so a concurrent direct
        // append in the out-of-scope multi-process v6-open case can't grab a not-yet-migrated seq and
        // cause an or_insert no-op (silent legacy-event drop). Idempotent on re-run.
        self.outbox.insert_events_preserving_seq(legacy).await?;
        // Clear from the vault ONLY the entries we actually migrated — NOT a blind clear(). If an old v6
        // writer appended a NEW in-vault outbox entry after our snapshot but before this lock (the
        // out-of-scope rolling-v6 window), a blind clear would drop it un-migrated = a lost event. Retain
        // anything we didn't migrate so the next open migrates it too.
        let leftover = self
            .locked_mutate(move |c| {
                c.outbox.retain(|seq, _| !migrated_seqs.contains(seq));
                let leftover = c.outbox.len();
                if leftover == 0 {
                    c.outbox_seq = 0;
                }
                Ok(leftover)
            })
            .await?;
        if leftover > 0 {
            tracing::warn!(
                leftover,
                "v6 outbox entries appeared after the migration snapshot; left in the vault for the next open's migration"
            );
        }
        tracing::info!(count, "migrated v6 in-vault outbox events into the split outbox file (v7)");
        Ok(())
    }

    /// Drain intent-staged events (the vault's `pending_events`) to the outbox store IDEMPOTENTLY
    /// (each carries a dedup_id so a crash between the append and clearing the intent can't duplicate
    /// it), then clear the drained intents from the vault. Called after every coupled emit + once at
    /// startup (D1 intent-staging — keeps a state-change and its event effectively atomic across the
    /// two files: the vault commits the change + the intent together, the outbox gets the event after).
    async fn drain_pending_events(&self) -> Result<(), StorageError> {
        let pending: Vec<StagedEvent> = {
            let c = self.cache.read();
            if c.pending_events.is_empty() {
                return Ok(());
            }
            c.pending_events.clone()
        };
        let mut drained: Vec<String> = Vec::with_capacity(pending.len());
        for ev in &pending {
            self.outbox
                .append_deduped(&ev.dedup_id, &ev.subject, &ev.event_type, ev.payload.clone())
                .await?;
            drained.push(ev.dedup_id.clone());
        }
        // Clear ONLY the intents we drained (a concurrent stage may have added more).
        self.locked_mutate(move |c| {
            c.pending_events.retain(|e| !drained.contains(&e.dedup_id));
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Parse decrypted bytes into a `StorageCache`, tolerating the legacy
    /// "just a map of credentials" format, and rebuild secondary indexes.
    fn parse_cache(decrypted: &[u8]) -> Result<StorageCache, StorageError> {
        let mut cache: StorageCache = serde_json::from_slice(decrypted).or_else(|_| {
            let credentials: HashMap<String, Credential> = serde_json::from_slice(decrypted)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            Ok::<_, StorageError>(StorageCache {
                credentials,
                ..Default::default()
            })
        })?;
        cache.rebuild_indexes();
        Ok(cache)
    }

    /// Read and decrypt the authoritative on-disk cache (blocking).
    fn read_cache_from_disk_sync(&self) -> Result<StorageCache, StorageError> {
        if !self.path.exists() {
            return Ok(StorageCache::default());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let storage_file: StorageFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        check_version(storage_file.version)?;
        let decrypted = decrypt(&storage_file.data, &self.master_key)?;
        Self::parse_cache(&decrypted)
    }

    /// Encrypt and atomically write a cache to disk (blocking).
    fn write_cache_to_disk_sync(&self, cache: &StorageCache) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(cache).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt(&data, &self.master_key)?;
        let storage_file = StorageFile {
            version: STORAGE_VERSION,
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.salt),
            data: encrypted,
        };
        let content = serde_json::to_string_pretty(&storage_file)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let temp_path = self.path.with_extension("tmp");
        // fsync the tmp BEFORE the rename so the contents are durable, not just the directory entry —
        // else a power-loss can expose the rename while the bytes are unflushed, corrupting the vault
        // (catastrophic: every subsequent read fails). Lock-step with OutboxStore::write_to_disk.
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
        // Make the rename crash-DURABLE (not just crash-atomic): fsync the parent dir, propagating a real
        // error so a non-durable vault write fails loudly rather than silently committing. Lock-step with
        // the outbox store's write path (an unsupported dir-fsync is downgraded to a warning there).
        super::outbox_store::fsync_parent_dir(&self.path)?;
        Ok(())
    }

    /// Perform a **cross-process atomic** read-modify-write of the storage file.
    ///
    /// Acquires an exclusive advisory lock on a sidecar `.lock` file, then reads
    /// the authoritative on-disk state, applies `f`, persists the result, and
    /// refreshes the in-memory cache — all while holding the lock. This is what
    /// makes the single-use-token check-and-increment and the approval
    /// execution-claim atomic even though the web and MCP servers run as
    /// separate processes sharing one encrypted file.
    ///
    /// The lock acquisition + decrypt/encrypt + file I/O are all *blocking*. On a
    /// multi-thread runtime (the web and MCP servers) we run them inside
    /// [`tokio::task::block_in_place`], which hands the worker's other tasks to a
    /// replacement thread so a held lock can't stall unrelated requests. On a
    /// current-thread runtime (unit tests) `block_in_place` would panic, so we
    /// run inline. The closure operates purely on the in-memory snapshot read
    /// from disk and must not perform I/O.
    async fn locked_mutate<T>(
        &self,
        f: impl FnOnce(&mut StorageCache) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.locked_mutate_blocking(f),
            _ => tokio::task::block_in_place(|| self.locked_mutate_blocking(f)),
        }
    }

    /// Acquire the exclusive cross-process advisory lock on the sidecar `.lock`
    /// file (blocking). Returned guard releases the lock on drop. Shared by the
    /// read-modify-write path ([`Self::locked_mutate_blocking`]) and the
    /// read-into-cache reload path ([`Self::reload_blocking`]) so the two are
    /// serialized against each other.
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

    /// The blocking read-modify-write body of [`Self::locked_mutate`]. Holds the
    /// advisory file lock for the whole cycle; must only be called off the async
    /// reactor (via `block_in_place` or a current-thread runtime).
    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut StorageCache) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        // Blocks until no other process/thread holds the lock.
        let _guard = flock.write().map_err(StorageError::Io)?;

        // Authoritative read from disk (not the possibly-stale in-memory cache).
        let mut cache = self.read_cache_from_disk_sync()?;
        let result = f(&mut cache)?;
        self.write_cache_to_disk_sync(&cache)?;
        *self.cache.write() = cache;
        // Record the just-written file's change token so a following reload (which would
        // see the new mtime) recognizes the cache is already current and skips a redundant
        // decrypt of the state we just wrote.
        *self.last_loaded.lock() = self.file_change_token();
        Ok(result)
        // `_guard` dropped here releases the lock.
    }

    /// A cheap change token for the on-disk vault: `(mtime, len)`. `None` if the file
    /// can't be stat'd (e.g. not yet created) — callers then always reload. Any write
    /// goes through tmp + atomic rename, so a real change always bumps mtime; the target
    /// filesystems (container ext4/overlayfs) have sub-second mtime resolution, so a
    /// distinct write is never collapsed into an unchanged token.
    fn file_change_token(&self) -> Option<(std::time::SystemTime, u64)> {
        let meta = std::fs::metadata(&self.path).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    }

    /// The blocking body of [`Self::reload`]: read the authoritative on-disk
    /// state into the in-memory cache.
    ///
    /// This takes the **same** exclusive advisory lock as
    /// [`Self::locked_mutate_blocking`]. That serialization is load-bearing, not
    /// incidental: without it, `reload`'s lock-free read-disk-then-assign-cache
    /// could lose a concurrent mutation's update. Concretely — `reload` reads the
    /// OLD disk snapshot, a `store_policy` (under the lock) then atomically
    /// renames the new file into place and updates `self.cache`, and finally
    /// `reload` overwrites `self.cache` with its stale snapshot. The just-stored
    /// policy vanishes from the in-memory cache (it's still durable on disk) until
    /// the next mutation or reload re-reads disk — exactly the "admin Deny bites
    /// only intermittently" flicker under the periodic policy refresh. Holding the
    /// lock makes the read-disk + assign-cache atomic w.r.t. any mutation, so a
    /// committed write is never reverted.
    fn reload_blocking(&self) -> Result<(), StorageError> {
        let mut flock = self.lock_file_exclusive()?;
        let _guard = flock.write().map_err(StorageError::Io)?;
        // Read-cache: under the lock (so no write can race the stat→read), skip the
        // whole-vault decrypt when the file is byte-unchanged (same mtime + len) since
        // THIS process last loaded it — the in-memory cache is then already current. A
        // broker poll that finds no new outbox events avoids decrypting every secret.
        // Correctness: any mutation (append/store) bumps the file mtime (tmp + atomic
        // rename) and goes through the SAME fd-lock, so a committed change is never
        // skipped; an unchanged file means our cache already reflects it (we loaded it),
        // so not overwriting it cannot revert anything (the invariant reload upholds).
        if let Some(token) = self.file_change_token() {
            if *self.last_loaded.lock() == Some(token) {
                return Ok(());
            }
        }
        let cache = self.read_cache_from_disk_sync()?;
        *self.cache.write() = cache;
        *self.last_loaded.lock() = self.file_change_token();
        Ok(())
        // `_guard` dropped here releases the lock.
    }

    /// Reload data from disk (for picking up external changes).
    ///
    /// Takes the cross-process advisory lock for the read so a committed
    /// mutation's in-memory update can't be clobbered by a stale snapshot — see
    /// [`Self::reload_blocking`]. Like [`Self::locked_mutate`], the lock + I/O are
    /// blocking, so we run them under `block_in_place` on a multi-thread runtime
    /// (web/MCP servers) and inline on a current-thread runtime (unit tests).
    pub async fn reload(&self) -> Result<(), StorageError> {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::current().runtime_flavor() {
            RuntimeFlavor::CurrentThread => self.reload_blocking(),
            _ => tokio::task::block_in_place(|| self.reload_blocking()),
        }
    }
}

#[async_trait]
impl StorageBackend for FileStorage {
    async fn store(&self, credential: &Credential) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(existing_id) = cache.alias_index.get(&credential.alias) {
                if existing_id != &credential.id {
                    return Err(StorageError::AlreadyExists(credential.alias.clone()));
                }
            }
            cache.alias_index.insert(credential.alias.clone(), credential.id.clone());
            cache.credentials.insert(credential.id.clone(), credential.clone());
            Ok(())
        })
            .await
    }

    async fn get(&self, id: &str) -> Result<Option<Credential>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.credentials.get(id).cloned())
    }

    async fn get_by_alias(&self, alias: &str) -> Result<Option<Credential>, StorageError> {
        let cache = self.cache.read();
        if let Some(id) = cache.alias_index.get(alias) {
            Ok(cache.credentials.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list(&self) -> Result<Vec<CredentialMetadata>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.credentials.values().map(CredentialMetadata::from).collect())
    }

    async fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(cred) = cache.credentials.remove(id) {
                cache.alias_index.remove(&cred.alias);
                Ok(())
            } else {
                Err(StorageError::NotFound(id.to_string()))
            }
        })
            .await
    }

    async fn update(&self, credential: &Credential) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            let old_cred = cache
                .credentials
                .get(&credential.id)
                .ok_or_else(|| StorageError::NotFound(credential.id.clone()))?
                .clone();

            if let Some(existing_id) = cache.alias_index.get(&credential.alias) {
                if existing_id != &credential.id {
                    return Err(StorageError::AlreadyExists(credential.alias.clone()));
                }
            }

            if old_cred.alias != credential.alias {
                cache.alias_index.remove(&old_cred.alias);
                cache
                    .alias_index
                    .insert(credential.alias.clone(), credential.id.clone());
            }

            cache.credentials.insert(credential.id.clone(), credential.clone());
            Ok(())
        })
            .await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        if !self.path.exists() {
            return Err(StorageError::Unavailable(
                "Storage file does not exist".to_string(),
            ));
        }
        fs::metadata(&self.path).await?;
        Ok(())
    }

    // ==================== Auth Storage ====================

    async fn store_role(&self, role: &Role) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(existing_id) = cache.role_name_index.get(&role.name) {
                if existing_id != &role.id {
                    return Err(StorageError::RoleAlreadyExists(role.name.clone()));
                }
            }
            cache.role_name_index.insert(role.name.clone(), role.id.clone());
            cache.roles.insert(role.id.clone(), role.clone());
            Ok(())
        })
            .await
    }

    async fn get_role(&self, id: &str) -> Result<Option<Role>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.roles.get(id).cloned())
    }

    async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, StorageError> {
        let cache = self.cache.read();
        if let Some(id) = cache.role_name_index.get(name) {
            Ok(cache.roles.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_roles(&self) -> Result<Vec<Role>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.roles.values().cloned().collect())
    }

    async fn delete_role(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(role) = cache.roles.remove(id) {
                cache.role_name_index.remove(&role.name);
                Ok(())
            } else {
                Err(StorageError::RoleNotFound(id.to_string()))
            }
        })
            .await
    }

    async fn delete_role_if_unreferenced(&self, id: &str) -> Result<(), StorageError> {
        let id = id.to_string();
        self.locked_mutate(move |cache| {
            // Referential-integrity check and delete in one locked section, so a
            // key minted between a check and the delete can't be orphaned.
            if cache.api_keys.values().any(|k| k.role_id == id) {
                return Err(StorageError::Conflict(format!(
                    "role '{}' is still referenced by an API key",
                    id
                )));
            }
            if let Some(role) = cache.roles.remove(&id) {
                cache.role_name_index.remove(&role.name);
                Ok(())
            } else {
                Err(StorageError::RoleNotFound(id.clone()))
            }
        })
        .await
    }

    async fn store_api_key(&self, key: &ApiKey) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            cache.api_key_hash_index.insert(key.key_hash.clone(), key.id.clone());
            cache.api_keys.insert(key.id.clone(), key.clone());
            Ok(())
        })
            .await
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> Result<Option<ApiKey>, StorageError> {
        let cache = self.cache.read();
        if let Some(id) = cache.api_key_hash_index.get(hash) {
            Ok(cache.api_keys.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKey>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.api_keys.values().cloned().collect())
    }

    async fn delete_api_key(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(key) = cache.api_keys.remove(id) {
                cache.api_key_hash_index.remove(&key.key_hash);
                Ok(())
            } else {
                Err(StorageError::ApiKeyNotFound(id.to_string()))
            }
        })
            .await
    }

    async fn update_api_key_last_used(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(key) = cache.api_keys.get_mut(id) {
                key.last_used_at = Some(Utc::now());
                Ok(())
            } else {
                Err(StorageError::ApiKeyNotFound(id.to_string()))
            }
        })
            .await
    }

    // ==================== Use Token Storage ====================

    async fn store_use_token(&self, token: &UseToken) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            cache
                .use_token_hash_index
                .insert(token.token_hash.clone(), token.id.clone());
            cache.use_tokens.insert(token.id.clone(), token.clone());
            Ok(())
        })
            .await
    }

    async fn get_use_token(&self, id: &str) -> Result<Option<UseToken>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.use_tokens.get(id).cloned())
    }

    async fn get_use_token_by_hash(&self, hash: &str) -> Result<Option<UseToken>, StorageError> {
        let cache = self.cache.read();
        if let Some(id) = cache.use_token_hash_index.get(hash) {
            Ok(cache.use_tokens.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn list_use_tokens(&self) -> Result<Vec<UseToken>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.use_tokens.values().cloned().collect())
    }

    async fn delete_use_token(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(token) = cache.use_tokens.remove(id) {
                cache.use_token_hash_index.remove(&token.token_hash);
                Ok(())
            } else {
                Err(StorageError::UseTokenNotFound(id.to_string()))
            }
        })
            .await
    }

    async fn consume_use_token(&self, id: &str) -> Result<UseToken, StorageError> {
        // Authoritative check-and-increment under the cross-process lock, against
        // the on-disk state — so a single-use token can never drive two
        // executions even across the web/MCP process split.
        self.locked_mutate(|cache| {
            let token = cache
                .use_tokens
                .get_mut(id)
                .ok_or_else(|| StorageError::UseTokenNotFound(id.to_string()))?;
            token
                .check_usable()
                .map_err(|e| StorageError::UseTokenUnusable(e.to_string()))?;
            token.uses += 1;
            token.last_used_at = Some(Utc::now());
            Ok(token.clone())
        })
            .await
    }

    async fn set_use_token_revoked(&self, id: &str) -> Result<UseToken, StorageError> {
        self.locked_mutate(|cache| {
            let token = cache
                .use_tokens
                .get_mut(id)
                .ok_or_else(|| StorageError::UseTokenNotFound(id.to_string()))?;
            token.revoked = true;
            Ok(token.clone())
        })
            .await
    }

    // ==================== Approval Storage ====================

    async fn store_approval(&self, approval: &ApprovalRequest) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            cache.approvals.insert(approval.id.clone(), approval.clone());
            Ok(())
        })
            .await
    }

    async fn store_approval_reserving(
        &self,
        approval: &ApprovalRequest,
        token_id: &str,
        max_uses: u32,
    ) -> Result<(), StorageError> {
        use crate::approval::ApprovalStatus;
        // Count pending + read uses + insert, all under one fd-lock against the
        // authoritative on-disk state — so two concurrent opens (web + MCP) for
        // the same single-use token can't both slip past a stale count.
        self.locked_mutate(|cache| {
            let uses = cache.use_tokens.get(token_id).map(|t| t.uses).unwrap_or(0);
            let pending = cache
                .approvals
                .values()
                .filter(|a| {
                    a.status == ApprovalStatus::Pending
                        && !a.is_past_ttl()
                        && a.use_token_id.as_deref() == Some(token_id)
                })
                .count() as u32;
            if uses + pending >= max_uses {
                return Err(StorageError::Conflict(
                    "use token has no remaining capacity for a new pending approval".to_string(),
                ));
            }
            cache.approvals.insert(approval.id.clone(), approval.clone());
            Ok(())
        })
            .await
    }

    async fn get_approval(&self, id: &str) -> Result<Option<ApprovalRequest>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.approvals.get(id).cloned())
    }

    async fn list_approvals(&self) -> Result<Vec<ApprovalRequest>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.approvals.values().cloned().collect())
    }

    async fn update_approval(&self, approval: &ApprovalRequest) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if !cache.approvals.contains_key(&approval.id) {
                return Err(StorageError::ApprovalNotFound(approval.id.clone()));
            }
            cache.approvals.insert(approval.id.clone(), approval.clone());
            Ok(())
        })
            .await
    }

    async fn delete_approval(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if cache.approvals.remove(id).is_none() {
                return Err(StorageError::ApprovalNotFound(id.to_string()));
            }
            Ok(())
        })
            .await
    }

    async fn decide_approval(
        &self,
        id: &str,
        approve: bool,
        channel: &str,
        approver_identity: &str,
        enforce_sod: bool,
        note: Option<String>,
    ) -> Result<ApprovalRequest, StorageError> {
        use crate::approval::Decision;
        let decided = self
            .locked_mutate(|cache| {
                let approval = cache
                    .approvals
                    .get_mut(id)
                    .ok_or_else(|| StorageError::ApprovalNotFound(id.to_string()))?;
                // Advance the SLA lifecycle first so a decision raced against the
                // final deadline is rejected as expired, not silently accepted.
                approval.advance_lifecycle();
                let decision = Decision::new(channel, approver_identity)
                    .with_note(note)
                    .enforcing_sod(enforce_sod);
                let result = if approve {
                    approval.approve(decision)
                } else {
                    approval.deny(decision)
                };
                result.map_err(|e| StorageError::Conflict(e.to_string()))?;
                let decided = approval.clone();
                // V9: emit the decision event atomically with the decision.
                let event_type = if approve {
                    crate::outbox::EVENT_APPROVAL_APPROVED
                } else {
                    crate::outbox::EVENT_APPROVAL_DENIED
                };
                stage_event(cache, &decided.id, event_type, approval_event_payload(&decided))?;
                Ok(decided)
            })
            .await?;
        // Drain the staged decision event to the split outbox file (D1). The vault has ALREADY committed
        // the decision + the intent atomically, so a drain failure here must NOT be reported to the human
        // approver as "decision not recorded" — the decision is durable and the periodic/startup
        // reconciler will deliver the event. Best-effort: log and return Ok with the committed decision.
        if let Err(e) = self.drain_pending_events().await {
            tracing::warn!(approval_id = %decided.id, error = %e,
                "approval decision committed but the staged-event drain failed; the periodic reconciler will deliver it");
        }
        // Surface a separation-of-duty violation (V5) even when not hard-enforced,
        // so a self-approval is always observable.
        if decided.sod_violation == Some(true) {
            tracing::warn!(
                approval_id = %decided.id,
                approver = %approver_identity,
                "separation-of-duty: approver is the requesting agent (self-approval)"
            );
        }
        Ok(decided)
    }

    async fn poll_refresh_approval(&self, id: &str) -> Result<ApprovalRequest, StorageError> {
        // Cheap pre-check on the (caller-reloaded) in-memory cache: only take the
        // lock + re-encrypt + write path when this request actually has a pending
        // transition, so a steady-state poll doesn't rewrite the vault every tick.
        // The authoritative re-check happens under the lock below. (The cache is
        // always complete for FileStorage, so a miss is a genuine not-found.)
        {
            let now = Utc::now();
            let cache = self.cache.read();
            match cache.approvals.get(id) {
                None => return Err(StorageError::ApprovalNotFound(id.to_string())),
                Some(a) if !approval_is_due(a, now) => return Ok(a.clone()),
                Some(_) => {}
            }
        }
        let refreshed = self.locked_mutate(|cache| {
            use crate::approval::LifecycleChange;
            let (clone, event) = {
                let approval = cache
                    .approvals
                    .get_mut(id)
                    .ok_or_else(|| StorageError::ApprovalNotFound(id.to_string()))?;
                // Escalate / expire as due.
                let mut event = match approval.advance_lifecycle() {
                    LifecycleChange::Escalated => Some(crate::outbox::EVENT_APPROVAL_ESCALATED),
                    LifecycleChange::Expired => Some(crate::outbox::EVENT_APPROVAL_EXPIRED),
                    LifecycleChange::None => None,
                };
                // A still-approved-but-unrun grant gone stale must be re-approved:
                // flip it to expired (preserving the original approver) so the agent
                // resubmits rather than running on a decision nobody re-confirmed.
                if event.is_none() && approval.needs_reauth() {
                    approval.expire_reauth_lapsed();
                    event = Some(crate::outbox::EVENT_APPROVAL_EXPIRED);
                }
                let event = event.map(|et| (approval.id.clone(), et, approval_event_payload(approval)));
                (approval.clone(), event)
            };
            // V9: stage the lifecycle event atomically with the transition (drained after the lock).
            if let Some((subj, et, payload)) = event {
                stage_event(cache, &subj, et, payload)?;
            }
            Ok(clone)
        })
        .await?;
        // Best-effort drain (D1): the lifecycle transition is already committed; a drain failure must
        // not fail the poll. The periodic/startup reconciler delivers the staged event.
        if let Err(e) = self.drain_pending_events().await {
            tracing::warn!(approval_id = %refreshed.id, error = %e,
                "approval lifecycle transition committed but the staged-event drain failed; the periodic reconciler will deliver it");
        }
        Ok(refreshed)
    }

    async fn sweep_approval_lifecycle(&self) -> Result<crate::storage::ApprovalSweep, StorageError> {
        use crate::approval::LifecycleChange;
        // Cheap pre-check on the (freshly reloaded) in-memory cache: if nothing
        // is due, skip the lock + re-encrypt + disk write entirely so an idle
        // sweep doesn't churn the vault every tick. The authoritative re-check
        // happens under the lock below.
        let any_due = {
            let now = Utc::now();
            let cache = self.cache.read();
            cache.approvals.values().any(|a| approval_is_due(a, now))
        };
        if !any_due {
            return Ok(crate::storage::ApprovalSweep::default());
        }
        let sweep = self.locked_mutate(|cache| {
            let mut sweep = crate::storage::ApprovalSweep::default();
            // Collect events during the &mut iteration; push them after (can't
            // borrow `cache` again while iterating its approvals).
            let mut events: Vec<(String, &'static str, serde_json::Value)> = Vec::new();
            for approval in cache.approvals.values_mut() {
                match approval.advance_lifecycle() {
                    LifecycleChange::Escalated => {
                        sweep.escalated.push(approval.clone());
                        events.push((approval.id.clone(), crate::outbox::EVENT_APPROVAL_ESCALATED, approval_event_payload(approval)));
                    }
                    LifecycleChange::Expired => {
                        sweep.expired.push(approval.id.clone());
                        events.push((approval.id.clone(), crate::outbox::EVENT_APPROVAL_EXPIRED, approval_event_payload(approval)));
                    }
                    LifecycleChange::None => {
                        // Also expire an approved-but-unrun grant whose continuous
                        // reauth window lapsed, so an abandoned stale grant doesn't
                        // linger as `Approved` in the panel (it must be re-approved).
                        // Preserves the original approver attribution.
                        if approval.needs_reauth() {
                            approval.expire_reauth_lapsed();
                            sweep.expired.push(approval.id.clone());
                            events.push((approval.id.clone(), crate::outbox::EVENT_APPROVAL_EXPIRED, approval_event_payload(approval)));
                        }
                    }
                }
            }
            // V9: stage lifecycle events atomically with the sweep's transitions (drained after).
            for (subj, et, payload) in events {
                stage_event(cache, &subj, et, payload)?;
            }
            Ok(sweep)
        })
        .await?;
        // Best-effort drain (D1): the sweep's transitions are already committed; a drain failure must
        // not suppress the caller's escalation notifications (run_approval_sweep notifies AFTER this
        // returns Ok). The periodic/startup reconciler delivers the staged events.
        if let Err(e) = self.drain_pending_events().await {
            tracing::warn!(error = %e,
                "approval sweep transitions committed but the staged-event drain failed; the periodic reconciler will deliver them");
        }
        Ok(sweep)
    }

    async fn claim_approval_for_execution(
        &self,
        id: &str,
    ) -> Result<Option<ApprovalRequest>, StorageError> {
        use crate::approval::ApprovalStatus;
        self.locked_mutate(|cache| {
            let approval = match cache.approvals.get_mut(id) {
                Some(a) => a,
                None => return Err(StorageError::ApprovalNotFound(id.to_string())),
            };
            // A claim already held by another worker is only honored if it is
            // recent; a stale claim (its owner likely crashed) may be re-taken.
            let stale = approval.executing
                && approval
                    .executing_since
                    .map(|t| (Utc::now() - t).num_seconds() > STALE_EXECUTING_SECS)
                    .unwrap_or(true);
            if approval.status != ApprovalStatus::Approved
                || approval.executed
                || (approval.executing && !stale)
                // Defense-in-depth (V5): never claim a grant whose continuous
                // re-auth window lapsed — it must be re-approved, not run on a
                // stale decision. The poll path expires it; this guards the race.
                || approval.needs_reauth()
            {
                Ok(None)
            } else {
                approval.executing = true;
                approval.executing_since = Some(Utc::now());
                Ok(Some(approval.clone()))
            }
        })
            .await
    }

    async fn heartbeat_approval(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if let Some(approval) = cache.approvals.get_mut(id) {
                if approval.executing && !approval.executed {
                    approval.executing_since = Some(Utc::now());
                }
            }
            Ok(())
        })
            .await
    }

    // ==================== Event outbox (V9) ====================

    async fn append_event(
        &self,
        subject: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StorageError> {
        // v7: the outbox lives in its own file — delegate (the vault no longer holds events). This is
        // the direct-append path (e.g. meter events); coupled emits go through intent-staging instead.
        self.outbox.append(subject, event_type, payload).await
    }

    async fn list_events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        self.outbox.list_after(after, limit).await
    }

    async fn deliverable_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        self.outbox.deliverable(limit).await
    }

    async fn claim_deliverable_events(
        &self,
        limit: usize,
        lease_secs: u64,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        self.outbox.claim(limit, lease_secs).await
    }

    async fn record_event_delivery(
        &self,
        sequence: u64,
        success: bool,
        error: Option<String>,
        max_attempts: u32,
    ) -> Result<(), StorageError> {
        self.outbox
            .record_delivery(sequence, success, error, max_attempts)
            .await
    }

    async fn list_dead_letter_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        self.outbox.list_dead_letter(limit).await
    }

    async fn replay_dead_letter_event(&self, sequence: u64) -> Result<bool, StorageError> {
        self.outbox.replay_dead_letter(sequence).await
    }

    async fn gc_outbox(&self, retention_secs: u64) -> Result<usize, StorageError> {
        // Protect the dedup_ids of any still-staged intents from GC: an outbox event must not be pruned
        // while its vault-side intent is uncleared, or a re-drain after the prune would duplicate it
        // (enforces the no-duplicate invariant, not just bounds the window).
        let protected: std::collections::HashSet<String> = {
            let c = self.cache.read();
            c.pending_events.iter().map(|e| e.dedup_id.clone()).collect()
        };
        self.outbox.gc(retention_secs, &protected).await
    }

    /// Periodic safety-net reconcile of intent-staged events (D1) — delegates to the inherent
    /// drain_pending_events. Bounds an orphaned intent's lifetime to one tick when an inline drain
    /// failed, so a committed approval decision's signed event is delivered without waiting for a
    /// restart (and the intent never outlives the outbox retention window — closing the dedup-vs-GC
    /// duplicate window, since append_deduped's memory is the live outbox).
    async fn reconcile_pending_events(&self) -> Result<(), StorageError> {
        self.drain_pending_events().await
    }

    async fn pending_event_count(&self) -> Result<usize, StorageError> {
        Ok(self.cache.read().pending_events.len())
    }

    // ==================== Policy Storage (admin API, V1) ====================

    async fn store_policy(&self, policy: &Policy) -> Result<(), StorageError> {
        let policy = policy.clone();
        self.locked_mutate(move |cache| {
            cache.policies.insert(policy.id.clone(), policy);
            Ok(())
        })
        .await
    }

    async fn get_policy(&self, id: &str) -> Result<Option<Policy>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.policies.get(id).cloned())
    }

    async fn list_stored_policies(&self) -> Result<Vec<Policy>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.policies.values().cloned().collect())
    }

    async fn delete_policy(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if cache.policies.remove(id).is_none() {
                return Err(StorageError::PolicyNotFound(id.to_string()));
            }
            Ok(())
        })
        .await
    }

    // ==================== Capability Storage (connector M1) ====================

    async fn store_capability(&self, capability: &Capability) -> Result<(), StorageError> {
        let capability = capability.clone();
        self.locked_mutate(move |cache| {
            cache.capabilities.insert(capability.id.clone(), capability);
            Ok(())
        })
        .await
    }

    async fn get_capability(&self, id: &str) -> Result<Option<Capability>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.capabilities.get(id).cloned())
    }

    async fn list_capabilities(&self) -> Result<Vec<Capability>, StorageError> {
        let cache = self.cache.read();
        Ok(cache.capabilities.values().cloned().collect())
    }

    async fn delete_capability(&self, id: &str) -> Result<(), StorageError> {
        self.locked_mutate(|cache| {
            if cache.capabilities.remove(id).is_none() {
                return Err(StorageError::CapabilityNotFound(id.to_string()));
            }
            Ok(())
        })
        .await
    }

    // ==================== Idempotency (admin API, V1) ====================

    async fn idempotency_check_or_reserve(
        &self,
        key: &str,
        body_hash: &str,
    ) -> Result<IdempotencyState, StorageError> {
        let (key, body_hash) = (key.to_string(), body_hash.to_string());
        self.locked_mutate(move |cache| {
            let now = Utc::now();
            // Clone the small record so we can mutate the map below without a
            // borrow conflict.
            let existing = cache.idempotency.get(&key).cloned();
            let reserve = |cache: &mut StorageCache| {
                cache.gc_idempotency();
                cache.idempotency.insert(
                    key.clone(),
                    IdempotencyRecord {
                        done: false,
                        body_hash: body_hash.clone(),
                        status: 0,
                        response: String::new(),
                        created_at: now,
                    },
                );
                IdempotencyState::Fresh
            };
            let state = match existing {
                None => reserve(cache),
                Some(rec) => {
                    let stale = !rec.done
                        && (now - rec.created_at).num_seconds()
                            > STALE_IDEMPOTENCY_RESERVATION_SECS;
                    if stale {
                        // Orphaned reservation (crashed mid-op) → reclaim it for
                        // this caller regardless of the prior body.
                        reserve(cache)
                    } else if rec.body_hash != body_hash {
                        // Live record (completed or in-flight) for a *different*
                        // body → never replay the wrong response. (All records
                        // carry a non-empty hash: reserve and complete both set
                        // it, so this also rejects any hashless legacy record.)
                        IdempotencyState::Mismatch
                    } else if rec.done {
                        IdempotencyState::Done { status: rec.status, body: rec.response.clone() }
                    } else {
                        // In-flight, same body, not yet stale → back off.
                        IdempotencyState::Pending
                    }
                }
            };
            Ok(state)
        })
        .await
    }

    async fn idempotency_complete(
        &self,
        key: &str,
        body_hash: &str,
        status: u16,
        body: &str,
    ) -> Result<(), StorageError> {
        let (key, body_hash, body) = (key.to_string(), body_hash.to_string(), body.to_string());
        self.locked_mutate(move |cache| {
            match cache.idempotency.get_mut(&key) {
                // Our own reservation → complete it (keep its reservation time).
                Some(rec) if rec.body_hash == body_hash => {
                    rec.done = true;
                    rec.status = status;
                    rec.response = body;
                }
                // A *different* request re-reserved this key while our op ran
                // (we are the stale one, our reservation was GC'd then re-taken).
                // Drop our completion rather than clobber the live reservation.
                Some(_) => {}
                None => {
                    // Reservation was GC'd because the op outran the stale window
                    // and nothing re-took the key: re-create a completed record
                    // WITH the body hash, so a same-body retry replays (no
                    // duplicate side effect) and a different body mismatches.
                    // (created_at resets — the original reservation time is gone.)
                    cache.idempotency.insert(
                        key.clone(),
                        IdempotencyRecord {
                            done: true,
                            body_hash,
                            status,
                            response: body,
                            created_at: Utc::now(),
                        },
                    );
                }
            }
            Ok(())
        })
        .await
    }

    async fn idempotency_release(&self, key: &str) -> Result<(), StorageError> {
        let key = key.to_string();
        self.locked_mutate(move |cache| {
            // Only drop a still-pending reservation; never clobber a completed
            // record (a late release after another request completed it).
            if matches!(cache.idempotency.get(&key), Some(rec) if !rec.done) {
                cache.idempotency.remove(&key);
            }
            Ok(())
        })
        .await
    }

    async fn reload(&self) -> Result<(), StorageError> {
        FileStorage::reload(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Permission;
    use crate::{CredentialData, Secret};
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    fn stage_event_fails_closed_at_the_pending_cap() {
        // F4: when the undrained backlog hits the cap, staging a new coupled emit must FAIL (so the
        // enclosing locked_mutate aborts the state change too) — bounding secrets-vault churn under a
        // persistently-stuck outbox, rather than committing-but-undeliverable forever.
        let mut cache = StorageCache::default();
        for i in 0..MAX_PENDING_EVENTS {
            cache.pending_events.push(StagedEvent {
                dedup_id: i.to_string(),
                subject: "s".into(),
                event_type: "t".into(),
                payload: serde_json::json!({}),
            });
        }
        let err = stage_event(&mut cache, "s", "t", serde_json::json!({}))
            .expect_err("at the cap, staging must fail closed");
        assert!(matches!(err, StorageError::Unavailable(_)), "got {err:?}");
        // Below the cap it succeeds.
        cache.pending_events.clear();
        assert!(stage_event(&mut cache, "s", "t", serde_json::json!({})).is_ok());
    }

    #[test]
    fn test_version_gate() {
        // Current and older versions open; a newer version is refused.
        assert!(check_version(STORAGE_VERSION).is_ok());
        assert!(check_version(STORAGE_VERSION - 1).is_ok());
        assert!(matches!(
            check_version(STORAGE_VERSION + 1),
            Err(StorageError::UnsupportedVersion { .. })
        ));
    }

    #[tokio::test]
    async fn intent_staged_events_drain_to_outbox_idempotently() {
        // D1: an event staged in the vault (a coupled emit) drains to the split outbox file, and a
        // re-drain (crash between the outbox append and clearing the intent) does NOT duplicate it.
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let storage = FileStorage::new(&path, &SecretString::from("pw")).await.unwrap();
        let stage = |dedup: &str, subj: &str| StagedEvent {
            dedup_id: dedup.to_string(),
            subject: subj.to_string(),
            event_type: "approval.approved".to_string(),
            payload: serde_json::json!({}),
        };
        storage
            .locked_mutate(|c| {
                c.pending_events.push(stage("d1", "appr-1"));
                c.pending_events.push(stage("d2", "appr-2"));
                Ok(())
            })
            .await
            .unwrap();
        storage.drain_pending_events().await.unwrap();
        assert_eq!(storage.list_events_after(0, 100).await.unwrap().len(), 2, "both staged events drained");
        assert!(storage.cache.read().pending_events.is_empty(), "drained intents cleared");
        // Re-stage d1 (simulating a crash that left it undrained) and drain again — no duplicate.
        storage.locked_mutate(|c| { c.pending_events.push(stage("d1", "appr-1")); Ok(()) }).await.unwrap();
        storage.drain_pending_events().await.unwrap();
        assert_eq!(storage.list_events_after(0, 100).await.unwrap().len(), 2, "re-drain of d1 must not duplicate");
    }

    #[tokio::test]
    async fn migrates_v6_in_vault_outbox_to_the_split_file() {
        // v7 migration: a v6 vault held the outbox INSIDE it; on first v7 open it drains to the split
        // file preserving the sequence (broker cursor stability) + clears it from the vault.
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let pw = SecretString::from("pw");
        {
            let s = FileStorage::new(&path, &pw).await.unwrap();
            // Simulate a v6 vault: events living in the vault cache.outbox (the legacy location).
            s.locked_mutate(|c| {
                c.outbox.insert(
                    7,
                    crate::outbox::OutboxEvent {
                        sequence: 7,
                        subject: "s".into(),
                        event_type: "t".into(),
                        payload: serde_json::json!({}),
                        created_at: Utc::now(),
                        delivery: crate::outbox::DeliveryState::Pending,
                        attempts: 0,
                        leased_until: None,
                        last_attempt_at: None,
                        last_error: None,
                        dedup_id: None,
                    },
                );
                c.outbox_seq = 7;
                Ok(())
            })
            .await
            .unwrap();
        }
        // Reopen → load runs migrate_v6_outbox.
        let s2 = FileStorage::new(&path, &pw).await.unwrap();
        let evs = s2.list_events_after(0, 100).await.unwrap();
        assert_eq!(evs.len(), 1, "the legacy in-vault event migrated to the split outbox");
        assert_eq!(evs[0].sequence, 7, "sequence preserved (broker cursor must not rewind)");
        assert!(s2.cache.read().outbox.is_empty(), "vault outbox cleared post-migration");
        // A new append continues after the migrated max (no seq reuse).
        assert_eq!(s2.append_event("new", "t", serde_json::json!({})).await.unwrap(), 8);
    }

    #[tokio::test]
    async fn migrates_a_literal_version6_on_disk_vault() {
        // Unlike the test above (which round-trips v7 bytes), this hand-writes a GENUINE version:6 file:
        // the outbox lives INSIDE the vault, the OutboxEvent carries NO dedup_id, and there is NO
        // pending_events key — exactly the v6 on-disk shape. It pins the actual downgrade-read contract:
        // check_version accepts found=6, and the serde defaults for the v7-only fields (dedup_id /
        // pending_events) hold when reading real v6 bytes; then the events migrate, sequence preserved.
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let pw = SecretString::from("pw");

        // Build a v6-shaped cache via the real structs (so every field's serde form is authentic),
        // then strip the v7-only `pending_events` key to mimic a true v6 file. `dedup_id: None` is
        // already omitted on the wire (skip_serializing_if = Option::is_none).
        let mut cache = StorageCache::default();
        cache.outbox.insert(
            5,
            crate::outbox::OutboxEvent {
                sequence: 5,
                subject: "appr-9".into(),
                event_type: "approval.approved".into(),
                payload: serde_json::json!({}),
                created_at: Utc::now(),
                delivery: crate::outbox::DeliveryState::Pending,
                attempts: 0,
                leased_until: None,
                last_attempt_at: None,
                last_error: None,
                dedup_id: None,
            },
        );
        cache.outbox_seq = 5;
        let mut v = serde_json::to_value(&cache).unwrap();
        v.as_object_mut().unwrap().remove("pending_events"); // v6 predates intent-staging
        assert!(
            !v.to_string().contains("dedup_id"),
            "v6 outbox events must not carry dedup_id on the wire"
        );
        let bytes = serde_json::to_vec(&v).unwrap();
        // Sanity: the v6 bytes parse via the same path load() uses (serde defaults fill the new fields).
        FileStorage::parse_cache(&bytes).unwrap();

        // Encrypt + write a StorageFile stamped version:6 (the actual on-disk envelope).
        let salt = generate_salt();
        let master_key = derive_key(&pw, &salt).unwrap();
        let encrypted = encrypt(&bytes, &master_key).unwrap();
        let file = StorageFile {
            version: 6,
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
            data: encrypted,
        };
        std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        // Open via the real load path → check_version(6) accepts + migrate_v6_outbox runs.
        let s = FileStorage::new(&path, &pw).await.unwrap();
        let evs = s.list_events_after(0, 100).await.unwrap();
        assert_eq!(evs.len(), 1, "the literal-v6 in-vault event migrated to the split outbox");
        assert_eq!(evs[0].sequence, 5, "sequence preserved (broker cursor stability)");
        assert!(evs[0].dedup_id.is_none(), "v6 event had no dedup_id (serde default = None)");
        assert!(s.cache.read().outbox.is_empty(), "vault outbox cleared post-migration");
        assert!(s.cache.read().pending_events.is_empty(), "no pending_events in v6 (serde default)");
        // The vault is rewritten as v7 on disk.
        let reread: StorageFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reread.version, STORAGE_VERSION, "reopened vault rewritten as v7");
        // A new append continues strictly after the migrated max.
        assert_eq!(s.append_event("new", "t", serde_json::json!({})).await.unwrap(), 6);
    }

    #[tokio::test]
    async fn outbox_append_is_decoupled_from_the_secrets_vault_size() {
        // Acceptance gate (§7, decoupling proof): the v6 cliff was that EVERY outbox append re-encrypted
        // the whole secrets vault (O(vault-size)). We prove the v7 split removed it DETERMINISTICALLY
        // (not via flaky latency timing): age the secrets vault with many credentials, snapshot the exact
        // bytes of credentials.enc, append an outbox event, and assert credentials.enc is BYTE-FOR-BYTE
        // unchanged (an append must touch only outbox.enc). Byte-equality is immune to mtime granularity
        // AND stronger than a size check — any re-encrypt changes the per-write nonce, so a rewrite is
        // always detectable. (The proof is rewrite-ABSENCE, so it holds at any vault size; the aging just
        // exercises the realistic large-vault case the gate targets.)
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.enc");
        let pw = SecretString::from("pw");
        let storage = FileStorage::new(&path, &pw).await.unwrap();

        // Age the SECRETS vault so credentials.enc is large.
        for i in 0..200 {
            let cred = Credential::new(
                format!("api-{i}"),
                CredentialData::ApiKey {
                    key: Secret::new(format!("secret-{i}")),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            );
            storage.store(&cred).await.unwrap();
        }
        let vault_before = std::fs::read(&path).unwrap();
        assert!(vault_before.len() > 1000, "the aged secrets vault should be non-trivially large");

        // Append outbox events — these must NOT rewrite the secrets vault.
        for i in 0..5 {
            let seq = storage
                .append_event("subj", "evt", serde_json::json!({ "i": i }))
                .await
                .unwrap();
            assert_eq!(seq, i + 1);
        }

        let vault_after = std::fs::read(&path).unwrap();
        assert_eq!(
            vault_before, vault_after,
            "outbox append re-wrote credentials.enc — the O(secrets-vault-size) cliff is NOT decoupled"
        );
        // The events landed in the split outbox.enc and read back without touching the vault.
        assert!(path.with_file_name("outbox.enc").exists(), "events went to the split outbox.enc");
        assert_eq!(storage.list_events_after(0, 100).await.unwrap().len(), 5);
        // Sanity: the secrets vault still holds all 200 credentials after the appends (untouched, intact).
        assert_eq!(storage.list().await.unwrap().len(), 200);
    }

    #[tokio::test]
    async fn test_file_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test-password");

        // Create storage and add credential
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = Credential::new(
                "test-api".to_string(),
                CredentialData::ApiKey {
                    key: Secret::new("secret-key-123"),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            );

            storage.store(&cred).await.unwrap();
        }

        // Reload and verify
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = storage.get_by_alias("test-api").await.unwrap();
            assert!(cred.is_some());

            let cred = cred.unwrap();
            assert_eq!(cred.alias, "test-api");
        }
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");

        // Create with one password
        {
            let password = SecretString::from("password1");
            let storage = FileStorage::new(&path, &password).await.unwrap();

            let cred = Credential::new(
                "test".to_string(),
                CredentialData::BasicAuth {
                    username: "user".to_string(),
                    password: Secret::new("pass"),
                },
            );
            storage.store(&cred).await.unwrap();
        }

        // Try to load with wrong password
        let password = SecretString::from("password2");
        let result = FileStorage::new(&path, &password).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_duplicate_alias_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let cred1 = Credential::new(
            "my-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("key1"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );

        let cred2 = Credential::new(
            "my-api".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("key2"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );

        storage.store(&cred1).await.unwrap();
        let result = storage.store(&cred2).await;
        assert!(matches!(result, Err(StorageError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        for i in 0..3 {
            let cred = Credential::new(
                format!("api-{}", i),
                CredentialData::ApiKey {
                    key: Secret::new(format!("key-{}", i)),
                    header_name: "Authorization".to_string(),
                    header_prefix: "Bearer ".to_string(),
                },
            );
            storage.store(&cred).await.unwrap();
        }

        let list = storage.list().await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_role_storage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let mut permissions = HashSet::new();
        permissions.insert(Permission::Read);
        permissions.insert(Permission::Execute);

        let role = Role {
            id: "role-1".to_string(),
            name: "test-role".to_string(),
            description: Some("Test role".to_string()),
            permissions,
            credential_scopes: vec!["github-*".to_string()],
            created_at: Utc::now(),
        };

        storage.store_role(&role).await.unwrap();

        let loaded = storage.get_role_by_name("test-role").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "test-role");
    }

    #[tokio::test]
    async fn test_api_key_storage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let storage = FileStorage::new(&path, &password).await.unwrap();

        let key = ApiKey {
            id: "key-1".to_string(),
            key_prefix: "vk_abc12".to_string(),
            key_hash: "hash123".to_string(),
            name: "test-key".to_string(),
            role_id: "role-1".to_string(),
            expires_at: None,
            created_at: Utc::now(),
            last_used_at: None,
            agent_label: None,
            owner_identity: None,
            tenant: None,
            workload_id: None,
        };

        storage.store_api_key(&key).await.unwrap();

        let loaded = storage.get_api_key_by_hash("hash123").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "test-key");

        // Test update last used
        storage.update_api_key_last_used("key-1").await.unwrap();
        let updated = storage.get_api_key_by_hash("hash123").await.unwrap().unwrap();
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_policy_storage_crud_and_persistence() {
        use crate::policy::Policy;
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");

        let policy = Policy::allow_all("p1", "github-*");
        let id = policy.id.clone();
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();
            storage.store_policy(&policy).await.unwrap();
            assert_eq!(storage.list_stored_policies().await.unwrap().len(), 1);
            assert_eq!(storage.get_policy(&id).await.unwrap().unwrap().name, "p1");
        }
        // Survives a reopen (persisted under v4).
        {
            let storage = FileStorage::new(&path, &password).await.unwrap();
            assert_eq!(storage.get_policy(&id).await.unwrap().unwrap().credential_pattern, "github-*");
            storage.delete_policy(&id).await.unwrap();
            assert!(storage.get_policy(&id).await.unwrap().is_none());
            assert!(matches!(
                storage.delete_policy(&id).await,
                Err(StorageError::PolicyNotFound(_))
            ));
        }
    }

    #[tokio::test]
    async fn test_idempotency_reserve_complete_replay_release() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let password = SecretString::from("test");
        let storage = FileStorage::new(&path, &password).await.unwrap();

        // First reservation is Fresh; a concurrent second one (same body) Pending.
        assert_eq!(
            storage.idempotency_check_or_reserve("k1", "hashA").await.unwrap(),
            IdempotencyState::Fresh
        );
        assert_eq!(
            storage.idempotency_check_or_reserve("k1", "hashA").await.unwrap(),
            IdempotencyState::Pending
        );
        // Same key with a DIFFERENT body hash → Mismatch (never a wrong replay).
        assert_eq!(
            storage.idempotency_check_or_reserve("k1", "hashB").await.unwrap(),
            IdempotencyState::Mismatch
        );

        // Completing the op stores the response; subsequent checks replay it.
        storage.idempotency_complete("k1", "hashA", 201, "{\"ok\":true}").await.unwrap();
        assert_eq!(
            storage.idempotency_check_or_reserve("k1", "hashA").await.unwrap(),
            IdempotencyState::Done { status: 201, body: "{\"ok\":true}".to_string() }
        );
        // Completing a key whose reservation was GC'd re-creates a hash-bound
        // record: same body replays, different body mismatches.
        storage.idempotency_complete("gone", "hashG", 200, "{}").await.unwrap();
        assert_eq!(
            storage.idempotency_check_or_reserve("gone", "hashG").await.unwrap(),
            IdempotencyState::Done { status: 200, body: "{}".to_string() }
        );
        assert_eq!(
            storage.idempotency_check_or_reserve("gone", "different").await.unwrap(),
            IdempotencyState::Mismatch
        );
        // A mismatched body still refuses to replay even after completion.
        assert_eq!(
            storage.idempotency_check_or_reserve("k1", "hashB").await.unwrap(),
            IdempotencyState::Mismatch
        );

        // Release only drops a pending reservation, never a completed record.
        assert_eq!(
            storage.idempotency_check_or_reserve("k2", "h").await.unwrap(),
            IdempotencyState::Fresh
        );
        storage.idempotency_release("k2").await.unwrap();
        assert_eq!(
            storage.idempotency_check_or_reserve("k2", "h").await.unwrap(),
            IdempotencyState::Fresh,
            "released key should be re-reservable"
        );
        // Releasing a completed key is a no-op (still replays).
        storage.idempotency_release("k1").await.unwrap();
        assert!(matches!(
            storage.idempotency_check_or_reserve("k1", "hashA").await.unwrap(),
            IdempotencyState::Done { .. }
        ));

        // A stale completion (different body) must NOT clobber a live reservation
        // that re-used the key for a different request (GC-race safety).
        assert_eq!(
            storage.idempotency_check_or_reserve("race", "live").await.unwrap(),
            IdempotencyState::Fresh
        );
        storage.idempotency_complete("race", "stale", 200, "{}").await.unwrap();
        assert_eq!(
            storage.idempotency_check_or_reserve("race", "live").await.unwrap(),
            IdempotencyState::Pending,
            "a stale completion must not turn the live reservation into a Done replay"
        );
    }
}
