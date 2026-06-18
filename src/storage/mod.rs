//! Storage backends for credential persistence
//!
//! Provides traits and implementations for storing credentials securely.

mod file;

pub use file::FileStorage;

use crate::approval::{ApprovalRequest, ApprovalStatus};
use crate::auth::{ApiKey, Role, UseToken};
use crate::policy::Policy;
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

    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Storage file version {found} is newer than this build supports (max {supported}); upgrade vultrino")]
    UnsupportedVersion { found: u32, supported: u32 },

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

/// Outcome of reserving an [`Idempotency-Key`](StorageBackend::idempotency_check_or_reserve)
/// for an admin-API mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyState {
    /// No prior record (or a stale, orphaned reservation) — the caller has now
    /// reserved the key and should perform the operation, then call
    /// [`StorageBackend::idempotency_complete`] (or `idempotency_release` on
    /// failure).
    Fresh,
    /// A concurrent request holds a fresh reservation for this key; the caller
    /// should not perform the operation (typically returns HTTP 409).
    Pending,
    /// The operation already completed under this key — replay this response.
    Done { status: u16, body: String },
    /// The key was already used with a *different* request body. The caller
    /// must not perform the operation and should return HTTP 409 — replaying the
    /// original response for a different request would be wrong.
    Mismatch,
}

/// The outcome of an SLA lifecycle sweep (V5): which open approvals newly
/// escalated (the caller should re-notify) and which newly expired.
#[derive(Debug, Clone, Default)]
pub struct ApprovalSweep {
    pub escalated: Vec<ApprovalRequest>,
    pub expired: Vec<String>,
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

    /// Delete a role only if **no API key references it**, performing the
    /// referential-integrity check and the delete atomically (so a key minted
    /// concurrently can't be orphaned). Returns [`StorageError::Conflict`] if
    /// referenced. The default impl is a non-atomic fallback; real backends
    /// (e.g. [`FileStorage`]) override it under their lock.
    async fn delete_role_if_unreferenced(&self, id: &str) -> Result<(), StorageError> {
        if self
            .list_api_keys()
            .await
            .unwrap_or_default()
            .iter()
            .any(|k| k.role_id == id)
        {
            return Err(StorageError::Conflict(format!(
                "role '{}' is still referenced by an API key",
                id
            )));
        }
        self.delete_role(id).await
    }

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

    /// Atomically store a new pending approval that *reserves capacity* on a use
    /// token: it is persisted only if `token.uses + outstanding_pending(token) <
    /// max_uses`, with the count and the insert performed under the backend's
    /// lock. Returns [`StorageError::Conflict`] when there is no remaining
    /// capacity. This closes the check-then-insert TOCTOU that a separate
    /// `list_approvals` + `store_approval` would leave open across the web/MCP
    /// process split.
    ///
    /// The default implementation is a non-atomic fallback for lock-free
    /// backends; real backends (e.g. [`FileStorage`]) override it.
    async fn store_approval_reserving(
        &self,
        approval: &ApprovalRequest,
        token_id: &str,
        max_uses: u32,
    ) -> Result<(), StorageError> {
        let pending = self
            .list_approvals()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| {
                a.status == ApprovalStatus::Pending
                    && !a.is_past_ttl()
                    && a.use_token_id.as_deref() == Some(token_id)
            })
            .count() as u32;
        let uses = self
            .get_use_token(token_id)
            .await
            .ok()
            .flatten()
            .map(|t| t.uses)
            .unwrap_or(0);
        if uses + pending >= max_uses {
            return Err(StorageError::Conflict(
                "use token has no remaining capacity for a new pending approval".to_string(),
            ));
        }
        self.store_approval(approval).await
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

    /// Refresh the execution-claim timestamp of an in-flight approval (a
    /// liveness heartbeat). Keeps a slow-but-alive worker from having its claim
    /// judged stale and re-taken by another process. No-op if the approval is no
    /// longer executing.
    async fn heartbeat_approval(&self, _id: &str) -> Result<(), StorageError> {
        Ok(())
    }

    /// Atomically approve or deny an open approval (read-modify-write under the
    /// backend's lock), returning the updated request. `channel` is the decision
    /// channel and `approver_identity` the authenticated approver (V5; required —
    /// a blank identity is rejected). When `enforce_sod` is set, a self-approval
    /// is rejected with [`StorageError::Conflict`]; either way the SoD outcome is
    /// recorded on the request. Errors with [`StorageError::Conflict`] if it is no
    /// longer open.
    async fn decide_approval(
        &self,
        _id: &str,
        _approve: bool,
        _channel: &str,
        _approver_identity: &str,
        _enforce_sod: bool,
        _note: Option<String>,
    ) -> Result<ApprovalRequest, StorageError> {
        Err(StorageError::ApprovalNotFound(_id.to_string()))
    }

    /// Atomically advance one approval through its SLA lifecycle and apply a
    /// continuous-reauth lapse, under the backend's lock, returning the updated
    /// request (V5). Unlike a read-then-`update_approval`, this re-reads the
    /// authoritative on-disk state and mutates in place, so it can never clobber
    /// a decision committed concurrently by another process.
    ///
    /// The default advances the lifecycle on a fetched copy (so the returned
    /// state is correct) without persisting — backends that support approvals
    /// **must** override it with an atomic read-modify-write (as `FileStorage`
    /// does). Note the default `claim_approval_for_execution` returns `None`, so a
    /// backend on these defaults can never execute, hence cannot fail open.
    async fn poll_refresh_approval(&self, id: &str) -> Result<ApprovalRequest, StorageError> {
        let mut approval = self
            .get_approval(id)
            .await?
            .ok_or_else(|| StorageError::ApprovalNotFound(id.to_string()))?;
        approval.advance_lifecycle();
        if approval.needs_reauth() {
            approval.expire_reauth_lapsed();
        }
        Ok(approval)
    }

    /// Advance every open approval through its SLA lifecycle (V5): escalate those
    /// past their first window, expire those past their final deadline, under the
    /// backend's lock. Returns the ids that newly escalated (so the caller can
    /// re-notify) and those that newly expired. No-op backends return empty.
    async fn sweep_approval_lifecycle(&self) -> Result<ApprovalSweep, StorageError> {
        Ok(ApprovalSweep::default())
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

    // ==================== Policy Storage (admin API, V1) ====================
    //
    // Policies pushed at runtime via the admin API. Distinct from the static
    // config policies; the server merges both into the live engine. Default
    // impls are no-ops/empty so non-file backends and test doubles still compile.

    /// Store (create or replace) a policy by its id.
    async fn store_policy(&self, _policy: &Policy) -> Result<(), StorageError> {
        Err(StorageError::Unavailable(
            "policy storage not supported by this storage backend".to_string(),
        ))
    }

    /// Get a stored policy by id.
    async fn get_policy(&self, _id: &str) -> Result<Option<Policy>, StorageError> {
        Ok(None)
    }

    /// List all admin-API-managed policies (not the static config policies).
    async fn list_stored_policies(&self) -> Result<Vec<Policy>, StorageError> {
        Ok(vec![])
    }

    /// Delete a stored policy by id.
    async fn delete_policy(&self, id: &str) -> Result<(), StorageError> {
        Err(StorageError::PolicyNotFound(id.to_string()))
    }

    // ==================== Idempotency (admin API, V1) ====================

    /// Atomically check for / reserve an `Idempotency-Key`, binding it to a hash
    /// of the request body so a key reused with a *different* body is rejected
    /// (`Mismatch`) rather than silently replaying the wrong response. See
    /// [`IdempotencyState`]. The default impl is non-persistent and always
    /// returns `Fresh` (no idempotency), which is safe but not deduplicating.
    async fn idempotency_check_or_reserve(
        &self,
        _key: &str,
        _body_hash: &str,
    ) -> Result<IdempotencyState, StorageError> {
        Ok(IdempotencyState::Fresh)
    }

    /// Record the completed response for a reserved key (bound to `body_hash`),
    /// to replay on repeats. Re-creates the record with the hash even if the
    /// reservation was GC'd during a long op, so a same-body retry replays (no
    /// duplicate execution) while a different body still mismatches. The default
    /// impl is a no-op (this backend provides no idempotency); concrete backends
    /// such as [`FileStorage`] override it.
    async fn idempotency_complete(
        &self,
        _key: &str,
        _body_hash: &str,
        _status: u16,
        _body: &str,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    /// Release a still-pending reservation (e.g. the operation failed) so the
    /// key can be retried. Must not clobber an already-completed record.
    async fn idempotency_release(&self, _key: &str) -> Result<(), StorageError> {
        Ok(())
    }

    /// Reload data from underlying storage
    /// Default implementation does nothing (for in-memory stores)
    async fn reload(&self) -> Result<(), StorageError> {
        Ok(())
    }
}
