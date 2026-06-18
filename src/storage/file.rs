//! Encrypted file-based storage backend
//!
//! Stores credentials in an encrypted JSON file on disk.

use super::{IdempotencyState, StorageBackend, StorageError};
use crate::approval::ApprovalRequest;
use crate::auth::{ApiKey, Role, UseToken};
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, EncryptedData, MasterKey};
use crate::policy::Policy;
use crate::{Credential, CredentialMetadata};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
const STORAGE_VERSION: u32 = 5;

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

/// Append an outbox event into a cache under the lock (V9), assigning the next
/// monotonic sequence. Used both by the public `append_event` and by the
/// state-change methods (decide/expire/escalate) so an event is emitted
/// **atomically** with the state transition it describes — no lost or duplicated
/// events on a crash between the two.
fn push_event(
    cache: &mut StorageCache,
    subject: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> u64 {
    cache.outbox_seq += 1;
    let seq = cache.outbox_seq;
    cache.outbox.insert(
        seq,
        crate::outbox::OutboxEvent {
            sequence: seq,
            subject: subject.to_string(),
            event_type: event_type.to_string(),
            payload,
            created_at: Utc::now(),
            delivery: crate::outbox::DeliveryState::Pending,
            attempts: 0,
            last_attempt_at: None,
            last_error: None,
        },
    );
    seq
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
    /// Master encryption key
    master_key: MasterKey,
    /// In-memory cache of credentials
    cache: RwLock<StorageCache>,
    /// Salt used for key derivation (stored in file)
    salt: Vec<u8>,
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
    /// Idempotency records for admin-API mutations, keyed by Idempotency-Key.
    #[serde(default)]
    idempotency: HashMap<String, IdempotencyRecord>,
    /// Signed event outbox (V9), keyed by monotonic sequence. `BTreeMap` keeps it
    /// ordered for gap-free cursor replay.
    #[serde(default)]
    outbox: std::collections::BTreeMap<u64, crate::outbox::OutboxEvent>,
    /// Monotonic sequence counter for the outbox (V9): the last assigned sequence.
    #[serde(default)]
    outbox_seq: u64,

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
        let master_key = derive_key(password, &salt)?;

        let storage = Self {
            path,
            master_key,
            cache: RwLock::new(StorageCache::default()),
            salt,
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
        let master_key = derive_key(password, &salt)?;

        // Decrypt + parse (tolerates the legacy credentials-only format)
        let decrypted = decrypt(&storage_file.data, &master_key)?;
        let cache = Self::parse_cache(&decrypted)?;

        Ok(Self {
            path,
            master_key,
            cache: RwLock::new(cache),
            salt,
        })
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
        std::fs::write(&temp_path, &content)?;
        std::fs::rename(&temp_path, &self.path)?;
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

    /// The blocking read-modify-write body of [`Self::locked_mutate`]. Holds the
    /// advisory file lock for the whole cycle; must only be called off the async
    /// reactor (via `block_in_place` or a current-thread runtime).
    fn locked_mutate_blocking<T>(
        &self,
        f: impl FnOnce(&mut StorageCache) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let lock_path = self.path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        let mut flock = fd_lock::RwLock::new(lock_file);
        // Blocks until no other process/thread holds the lock.
        let _guard = flock.write().map_err(StorageError::Io)?;

        // Authoritative read from disk (not the possibly-stale in-memory cache).
        let mut cache = self.read_cache_from_disk_sync()?;
        let result = f(&mut cache)?;
        self.write_cache_to_disk_sync(&cache)?;
        *self.cache.write() = cache;
        Ok(result)
        // `_guard` dropped here releases the lock.
    }

    /// Reload data from disk (for picking up external changes)
    pub async fn reload(&self) -> Result<(), StorageError> {
        let content = fs::read_to_string(&self.path).await?;
        let storage_file: StorageFile = serde_json::from_str(&content)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        check_version(storage_file.version)?;
        let decrypted = decrypt(&storage_file.data, &self.master_key)?;
        let cache = Self::parse_cache(&decrypted)?;
        *self.cache.write() = cache;
        Ok(())
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
                push_event(cache, &decided.id, event_type, approval_event_payload(&decided));
                Ok(decided)
            })
            .await?;
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
        self.locked_mutate(|cache| {
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
            // V9: emit the lifecycle event atomically with the transition.
            if let Some((subj, et, payload)) = event {
                push_event(cache, &subj, et, payload);
            }
            Ok(clone)
        })
            .await
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
        self.locked_mutate(|cache| {
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
            // V9: emit lifecycle events atomically with the sweep's transitions.
            for (subj, et, payload) in events {
                push_event(cache, &subj, et, payload);
            }
            Ok(sweep)
        })
            .await
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
        let subject = subject.to_string();
        let event_type = event_type.to_string();
        // The next monotonic sequence is assigned under the lock — authoritative
        // and gap-free even across the web+MCP processes sharing the vault.
        self.locked_mutate(move |cache| Ok(push_event(cache, &subject, &event_type, payload)))
            .await
    }

    async fn list_events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        // Authoritative read: pick up events appended by the other process.
        self.reload().await?;
        let cache = self.cache.read();
        Ok(cache
            .outbox
            .range((after + 1)..)
            .take(limit)
            .map(|(_, e)| e.clone())
            .collect())
    }

    async fn deliverable_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        use crate::outbox::DeliveryState;
        self.reload().await?;
        let cache = self.cache.read();
        // The earliest still-pending event per subject (ascending by sequence), so
        // per-subject ordering holds: a later event for a subject is withheld until
        // its earlier one is delivered. A dead-lettered event is not Pending, so it
        // doesn't block — the DLQ is the head-of-line release valve.
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for e in cache.outbox.values() {
            if e.delivery != DeliveryState::Pending {
                continue;
            }
            if seen.insert(e.subject.clone()) {
                out.push(e.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    async fn record_event_delivery(
        &self,
        sequence: u64,
        success: bool,
        error: Option<String>,
        max_attempts: u32,
    ) -> Result<(), StorageError> {
        use crate::outbox::DeliveryState;
        self.locked_mutate(move |cache| {
            if let Some(e) = cache.outbox.get_mut(&sequence) {
                e.attempts += 1;
                e.last_attempt_at = Some(Utc::now());
                if success {
                    e.delivery = DeliveryState::Delivered;
                    e.last_error = None;
                } else {
                    e.last_error = error;
                    if e.attempts >= max_attempts {
                        e.delivery = DeliveryState::DeadLettered;
                    }
                }
            }
            Ok(())
        })
        .await
    }

    async fn list_dead_letter_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::outbox::OutboxEvent>, StorageError> {
        use crate::outbox::DeliveryState;
        self.reload().await?;
        let cache = self.cache.read();
        Ok(cache
            .outbox
            .values()
            .filter(|e| e.delivery == DeliveryState::DeadLettered)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn replay_dead_letter_event(&self, sequence: u64) -> Result<bool, StorageError> {
        use crate::outbox::DeliveryState;
        self.locked_mutate(move |cache| {
            match cache.outbox.get_mut(&sequence) {
                Some(e) if e.delivery == DeliveryState::DeadLettered => {
                    e.delivery = DeliveryState::Pending;
                    e.attempts = 0;
                    e.last_error = None;
                    Ok(true)
                }
                _ => Ok(false),
            }
        })
        .await
    }

    async fn gc_outbox(&self, retention_secs: u64) -> Result<usize, StorageError> {
        let cutoff = Utc::now() - chrono::Duration::seconds(retention_secs as i64);
        self.locked_mutate(move |cache| {
            let before = cache.outbox.len();
            // Prune every event older than the retention window, regardless of
            // delivery state. Because sequence increases with time, this removes
            // the oldest *prefix* — so the retained suffix stays gap-free (the
            // replay no-gaps guarantee holds within the window) and the log can't
            // grow without bound even when push delivery is disabled. A consumer
            // (or a dead-letter) therefore has `retention_secs` to be replayed.
            cache.outbox.retain(|_, e| e.created_at >= cutoff);
            Ok(before - cache.outbox.len())
        })
        .await
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
