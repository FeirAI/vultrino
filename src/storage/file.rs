//! Encrypted file-based storage backend
//!
//! Stores credentials in an encrypted JSON file on disk.

use super::{StorageBackend, StorageError};
use crate::approval::ApprovalRequest;
use crate::auth::{ApiKey, Role, UseToken};
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, EncryptedData, MasterKey};
use crate::{Credential, CredentialMetadata};
use async_trait::async_trait;
use chrono::Utc;
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
const STORAGE_VERSION: u32 = 3;

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
        by: &str,
        note: Option<String>,
    ) -> Result<ApprovalRequest, StorageError> {
        self.locked_mutate(|cache| {
            let approval = cache
                .approvals
                .get_mut(id)
                .ok_or_else(|| StorageError::ApprovalNotFound(id.to_string()))?;
            let result = if approve {
                approval.approve(by, note)
            } else {
                approval.deny(by, note)
            };
            result.map_err(|e| StorageError::Conflict(e.to_string()))?;
            Ok(approval.clone())
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
}
