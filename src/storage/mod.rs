//! Storage backends for credential persistence
//!
//! Provides traits and implementations for storing credentials securely.

mod file;

pub use file::FileStorage;

use crate::approval::ApprovalRequest;
use crate::auth::{ApiKey, Role, UseToken};
use crate::{Credential, CredentialMetadata};
use async_trait::async_trait;
use thiserror::Error;

/// Storage-related errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("Credential already exists: {0}")]
    AlreadyExists(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Role already exists: {0}")]
    RoleAlreadyExists(String),

    #[error("API key not found: {0}")]
    ApiKeyNotFound(String),

    #[error("Use token not found: {0}")]
    UseTokenNotFound(String),

    #[error("Use token cannot be used: {0}")]
    UseTokenUnusable(String),

    #[error("Approval request not found: {0}")]
    ApprovalNotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Encryption error: {0}")]
    Encryption(#[from] crate::crypto::CryptoError),

    #[error("Storage backend unavailable: {0}")]
    Unavailable(String),

    #[error("Invalid storage configuration: {0}")]
    InvalidConfig(String),
}

/// Trait for credential storage backends
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a credential
    async fn store(&self, credential: &Credential) -> Result<(), StorageError>;

    /// Retrieve a credential by ID
    async fn get(&self, id: &str) -> Result<Option<Credential>, StorageError>;

    /// Retrieve a credential by alias
    async fn get_by_alias(&self, alias: &str) -> Result<Option<Credential>, StorageError>;

    /// List all credentials (metadata only, not secrets)
    async fn list(&self) -> Result<Vec<CredentialMetadata>, StorageError>;

    /// Delete a credential by ID
    async fn delete(&self, id: &str) -> Result<(), StorageError>;

    /// Update an existing credential
    async fn update(&self, credential: &Credential) -> Result<(), StorageError>;

    /// Check if the storage backend is available and healthy
    async fn health_check(&self) -> Result<(), StorageError>;

    // ==================== Auth Storage ====================

    /// Store a role
    async fn store_role(&self, role: &Role) -> Result<(), StorageError>;

    /// Get a role by ID
    async fn get_role(&self, id: &str) -> Result<Option<Role>, StorageError>;

    /// Get a role by name
    async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, StorageError>;

    /// List all roles
    async fn list_roles(&self) -> Result<Vec<Role>, StorageError>;

    /// Delete a role by ID
    async fn delete_role(&self, id: &str) -> Result<(), StorageError>;

    /// Store an API key
    async fn store_api_key(&self, key: &ApiKey) -> Result<(), StorageError>;

    /// Get an API key by hash
    async fn get_api_key_by_hash(&self, hash: &str) -> Result<Option<ApiKey>, StorageError>;

    /// List all API keys
    async fn list_api_keys(&self) -> Result<Vec<ApiKey>, StorageError>;

    /// Delete an API key by ID
    async fn delete_api_key(&self, id: &str) -> Result<(), StorageError>;

    /// Update an API key's last used timestamp
    async fn update_api_key_last_used(&self, id: &str) -> Result<(), StorageError>;

    // ==================== Use Token Storage ====================
    //
    // Use tokens are narrow, ephemeral grants (see `auth::UseToken`). The default
    // implementations are no-ops/empty so backends that don't support them (and
    // test doubles) still compile; `FileStorage` overrides all of them.

    /// Store (create or replace) a use token.
    async fn store_use_token(&self, _token: &UseToken) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "use tokens not supported by this storage backend".to_string(),
        ))
    }

    /// Get a use token by its id.
    async fn get_use_token(&self, _id: &str) -> Result<Option<UseToken>, StorageError> {
        Ok(None)
    }

    /// Get a use token by the SHA-256 hash of its plaintext value.
    async fn get_use_token_by_hash(&self, _hash: &str) -> Result<Option<UseToken>, StorageError> {
        Ok(None)
    }

    /// List all use tokens.
    async fn list_use_tokens(&self) -> Result<Vec<UseToken>, StorageError> {
        Ok(vec![])
    }

    /// Delete a use token by id.
    async fn delete_use_token(&self, _id: &str) -> Result<(), StorageError> {
        Err(StorageError::UseTokenNotFound(_id.to_string()))
    }

    /// Atomically reserve one use of a token: validate it is usable, increment
    /// its use count, stamp `last_used_at`, persist, and return the updated
    /// token. This is the authoritative single-use gate — the check and the
    /// increment happen under the backend's lock so a single-use token can never
    /// drive two executions within a process. Fail-closed: the use is reserved
    /// even if the caller's downstream action later errors.
    async fn consume_use_token(&self, _id: &str) -> Result<UseToken, StorageError> {
        Err(StorageError::Unavailable(
            "use tokens not supported by this storage backend".to_string(),
        ))
    }

    /// Atomically mark a use token revoked, returning the updated token.
    async fn set_use_token_revoked(&self, _id: &str) -> Result<UseToken, StorageError> {
        Err(StorageError::UseTokenNotFound(_id.to_string()))
    }

    // ==================== Approval Storage ====================

    /// Store (create or replace) an approval request.
    async fn store_approval(&self, _approval: &ApprovalRequest) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "approvals not supported by this storage backend".to_string(),
        ))
    }

    /// Get an approval request by id.
    async fn get_approval(&self, _id: &str) -> Result<Option<ApprovalRequest>, StorageError> {
        Ok(None)
    }

    /// List all approval requests.
    async fn list_approvals(&self) -> Result<Vec<ApprovalRequest>, StorageError> {
        Ok(vec![])
    }

    /// Update an existing approval request.
    async fn update_approval(&self, _approval: &ApprovalRequest) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "approvals not supported by this storage backend".to_string(),
        ))
    }

    /// Atomically approve or deny a pending approval (read-modify-write under the
    /// backend's lock), returning the updated request. Errors with
    /// [`StorageError::Conflict`] if it is no longer pending.
    async fn decide_approval(
        &self,
        _id: &str,
        _approve: bool,
        _by: &str,
        _note: Option<String>,
    ) -> Result<ApprovalRequest, StorageError> {
        Err(StorageError::ApprovalNotFound(_id.to_string()))
    }

    /// Delete an approval request by id.
    async fn delete_approval(&self, _id: &str) -> Result<(), StorageError> {
        Err(StorageError::ApprovalNotFound(_id.to_string()))
    }

    /// Atomically claim an approved request for execution. Returns the request
    /// (with `executing` set) only if it is `Approved` and not yet executing or
    /// executed; otherwise returns `None`. This keeps two concurrent agent polls
    /// from running the same approved action twice.
    async fn claim_approval_for_execution(
        &self,
        _id: &str,
    ) -> Result<Option<ApprovalRequest>, StorageError> {
        Ok(None)
    }

    /// Reload data from underlying storage
    /// Default implementation does nothing (for in-memory stores)
    async fn reload(&self) -> Result<(), StorageError> {
        Ok(())
    }
}
