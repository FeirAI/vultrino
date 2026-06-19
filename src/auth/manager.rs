//! Authentication manager for Vultrino RBAC
//!
//! Handles creation, validation, and management of API keys and roles.

use super::types::{
    admin_role, executor_role, read_only_role, ApiKey, ApiKeyMetadata, Permission, Role,
    ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use parking_lot::RwLock;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// API key prefix
const KEY_PREFIX: &str = "vk_";

/// Length of the random part of the key (32 chars)
const KEY_RANDOM_LENGTH: usize = 32;

/// Authentication manager errors
#[derive(Error, Debug)]
pub enum AuthManagerError {
    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Role already exists: {0}")]
    RoleAlreadyExists(String),

    #[error("Cannot delete predefined role: {0}")]
    CannotDeletePredefined(String),

    #[error("API key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid API key")]
    InvalidKey,

    #[error("API key expired")]
    KeyExpired,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type for auth manager operations
pub type AuthResult<T> = Result<T, AuthManagerError>;

/// Manages API keys and roles
pub struct AuthManager {
    /// Roles by ID
    roles: RwLock<HashMap<String, Role>>,
    /// Roles by name (for lookup)
    roles_by_name: RwLock<HashMap<String, String>>,
    /// API keys by hash
    keys_by_hash: RwLock<HashMap<String, ApiKey>>,
    /// API keys by ID (for management)
    keys_by_id: RwLock<HashMap<String, String>>,
}

impl AuthManager {
    /// Create a new auth manager with predefined roles
    pub fn new() -> Self {
        let manager = Self {
            roles: RwLock::new(HashMap::new()),
            roles_by_name: RwLock::new(HashMap::new()),
            keys_by_hash: RwLock::new(HashMap::new()),
            keys_by_id: RwLock::new(HashMap::new()),
        };

        // Add predefined roles
        manager.add_role_internal(admin_role());
        manager.add_role_internal(read_only_role());
        manager.add_role_internal(executor_role());

        manager
    }

    /// Create from existing data (for loading from storage)
    pub fn from_data(roles: Vec<Role>, keys: Vec<ApiKey>) -> Self {
        let manager = Self::new();

        // Add custom roles (predefined are already added)
        for role in roles {
            if !manager.is_predefined_role(&role.name) {
                manager.add_role_internal(role);
            }
        }

        // Add keys
        for key in keys {
            manager.add_key_internal(key);
        }

        manager
    }

    /// Check if a role name is predefined
    fn is_predefined_role(&self, name: &str) -> bool {
        matches!(name, ROLE_ADMIN | ROLE_READ_ONLY | ROLE_EXECUTOR)
    }

    /// Add a role to internal storage
    fn add_role_internal(&self, role: Role) {
        let mut roles = self.roles.write();
        let mut by_name = self.roles_by_name.write();
        by_name.insert(role.name.clone(), role.id.clone());
        roles.insert(role.id.clone(), role);
    }

    /// Add a key to internal storage
    fn add_key_internal(&self, key: ApiKey) {
        let mut by_hash = self.keys_by_hash.write();
        let mut by_id = self.keys_by_id.write();
        by_id.insert(key.id.clone(), key.key_hash.clone());
        by_hash.insert(key.key_hash.clone(), key);
    }

    // ==================== Role Management ====================

    /// Create a new role
    pub fn create_role(
        &self,
        name: impl Into<String>,
        permissions: HashSet<Permission>,
        scopes: Vec<String>,
        description: Option<String>,
    ) -> AuthResult<Role> {
        let name = name.into();

        // Check for existing role with same name
        {
            let by_name = self.roles_by_name.read();
            if by_name.contains_key(&name) {
                return Err(AuthManagerError::RoleAlreadyExists(name));
            }
        }

        let mut role = Role::new(name, permissions).with_scopes(scopes);
        if let Some(desc) = description {
            role = role.with_description(desc);
        }

        self.add_role_internal(role.clone());
        Ok(role)
    }

    /// Get a role by ID or name
    pub fn get_role(&self, id_or_name: &str) -> Option<Role> {
        let roles = self.roles.read();

        // Try by ID first
        if let Some(role) = roles.get(id_or_name) {
            return Some(role.clone());
        }

        // Try by name
        let by_name = self.roles_by_name.read();
        if let Some(id) = by_name.get(id_or_name) {
            return roles.get(id).cloned();
        }

        None
    }

    /// Get a role by name
    pub fn get_role_by_name(&self, name: &str) -> Option<Role> {
        let by_name = self.roles_by_name.read();
        let roles = self.roles.read();
        by_name.get(name).and_then(|id| roles.get(id).cloned())
    }

    /// List all roles
    pub fn list_roles(&self) -> Vec<Role> {
        let roles = self.roles.read();
        roles.values().cloned().collect()
    }

    /// Delete a role
    pub fn delete_role(&self, id_or_name: &str) -> AuthResult<()> {
        // Find the role
        let role = self
            .get_role(id_or_name)
            .ok_or_else(|| AuthManagerError::RoleNotFound(id_or_name.to_string()))?;

        // Check if predefined
        if self.is_predefined_role(&role.name) {
            return Err(AuthManagerError::CannotDeletePredefined(role.name));
        }

        // Remove from storage
        let mut roles = self.roles.write();
        let mut by_name = self.roles_by_name.write();
        roles.remove(&role.id);
        by_name.remove(&role.name);

        Ok(())
    }

    // ==================== API Key Management ====================

    /// Generate a new API key
    fn generate_key() -> (String, String) {
        let mut random_bytes = [0u8; KEY_RANDOM_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);

        // Use URL-safe base64 encoding, trimmed to desired length
        let random_part: String = STANDARD
            .encode(random_bytes)
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(KEY_RANDOM_LENGTH)
            .collect();

        let full_key = format!("{}{}", KEY_PREFIX, random_part);
        let prefix = format!("{}{}", KEY_PREFIX, &random_part[..8]);

        (full_key, prefix)
    }

    /// Hash an API key
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        STANDARD.encode(result)
    }

    /// Create a new API key
    /// Returns the full key (shown only once) and the key metadata
    pub fn create_api_key(
        &self,
        name: impl Into<String>,
        role_name: &str,
        expires_in: Option<Duration>,
    ) -> AuthResult<(String, ApiKey)> {
        // Validate role exists
        let role = self
            .get_role(role_name)
            .ok_or_else(|| AuthManagerError::RoleNotFound(role_name.to_string()))?;

        let (full_key, prefix) = Self::generate_key();
        let key_hash = Self::hash_key(&full_key);

        let expires_at = expires_in.map(|d| Utc::now() + d);

        let api_key = ApiKey {
            id: uuid::Uuid::new_v4().to_string(),
            key_prefix: prefix,
            key_hash: key_hash.clone(),
            name: name.into(),
            role_id: role.id,
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
            agent_label: None,
            owner_identity: None,
            tenant: None,
            workload_id: None,
        };

        self.add_key_internal(api_key.clone());

        Ok((full_key, api_key))
    }

    /// Validate an API key and return its associated data
    pub fn validate_key(&self, key: &str) -> AuthResult<(ApiKey, Role)> {
        // Check key format
        if !key.starts_with(KEY_PREFIX) {
            return Err(AuthManagerError::InvalidKey);
        }

        let key_hash = Self::hash_key(key);

        let by_hash = self.keys_by_hash.read();
        let api_key = by_hash
            .get(&key_hash)
            .ok_or(AuthManagerError::InvalidKey)?;

        // Check expiration
        if api_key.is_expired() {
            return Err(AuthManagerError::KeyExpired);
        }

        // Get associated role
        let role = self
            .get_role(&api_key.role_id)
            .ok_or_else(|| AuthManagerError::RoleNotFound(api_key.role_id.clone()))?;

        Ok((api_key.clone(), role))
    }

    /// Update last used timestamp for a key
    pub fn update_key_last_used(&self, key_hash: &str) {
        let mut by_hash = self.keys_by_hash.write();
        if let Some(key) = by_hash.get_mut(key_hash) {
            key.last_used_at = Some(Utc::now());
        }
    }

    /// List all API keys (metadata only, no hashes)
    pub fn list_api_keys(&self) -> Vec<ApiKeyMetadata> {
        let by_hash = self.keys_by_hash.read();
        by_hash.values().map(ApiKeyMetadata::from).collect()
    }

    /// Get an API key by ID
    pub fn get_api_key(&self, id: &str) -> Option<ApiKeyMetadata> {
        let by_id = self.keys_by_id.read();
        let by_hash = self.keys_by_hash.read();

        by_id
            .get(id)
            .and_then(|hash| by_hash.get(hash))
            .map(ApiKeyMetadata::from)
    }

    /// Revoke (delete) an API key
    pub fn revoke_api_key(&self, id: &str) -> AuthResult<()> {
        let hash = {
            let by_id = self.keys_by_id.read();
            by_id
                .get(id)
                .cloned()
                .ok_or_else(|| AuthManagerError::KeyNotFound(id.to_string()))?
        };

        let mut by_hash = self.keys_by_hash.write();
        let mut by_id = self.keys_by_id.write();

        by_hash.remove(&hash);
        by_id.remove(id);

        Ok(())
    }

    // ==================== Permission Checking ====================

    /// Check if a role has permission to perform an action on a credential
    pub fn check_permission(
        &self,
        role: &Role,
        permission: Permission,
        credential_alias: Option<&str>,
    ) -> AuthResult<()> {
        // Check if role has the required permission
        if !role.has_permission(permission) {
            return Err(AuthManagerError::PermissionDenied);
        }

        // Check credential scope if specified
        if let Some(alias) = credential_alias {
            if !role.can_access_credential(alias) {
                return Err(AuthManagerError::PermissionDenied);
            }
        }

        Ok(())
    }

    // ==================== Data Export (for storage) ====================

    /// Get all roles (for persistence)
    pub fn export_roles(&self) -> Vec<Role> {
        let roles = self.roles.read();
        roles
            .values()
            .filter(|r| !self.is_predefined_role(&r.name))
            .cloned()
            .collect()
    }

    /// Get all API keys (for persistence)
    pub fn export_keys(&self) -> Vec<ApiKey> {
        let by_hash = self.keys_by_hash.read();
        by_hash.values().cloned().collect()
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predefined_roles() {
        let manager = AuthManager::new();

        let admin = manager.get_role_by_name(ROLE_ADMIN).unwrap();
        assert!(admin.has_permission(Permission::Read));
        assert!(admin.has_permission(Permission::Write));
        assert!(admin.has_permission(Permission::Delete));
        assert!(admin.has_permission(Permission::Execute));

        let read_only = manager.get_role_by_name(ROLE_READ_ONLY).unwrap();
        assert!(read_only.has_permission(Permission::Read));
        assert!(!read_only.has_permission(Permission::Write));
    }

    #[test]
    fn test_create_custom_role() {
        let manager = AuthManager::new();

        let role = manager
            .create_role(
                "github-executor",
                [Permission::Read, Permission::Execute].into_iter().collect(),
                vec!["github-*".to_string()],
                Some("Execute GitHub credentials".to_string()),
            )
            .unwrap();

        assert_eq!(role.name, "github-executor");
        assert!(role.can_access_credential("github-api"));
        assert!(!role.can_access_credential("aws-prod"));
    }

    #[test]
    fn test_cannot_delete_predefined_role() {
        let manager = AuthManager::new();
        let result = manager.delete_role(ROLE_ADMIN);
        assert!(matches!(
            result,
            Err(AuthManagerError::CannotDeletePredefined(_))
        ));
    }

    #[test]
    fn test_api_key_creation_and_validation() {
        let manager = AuthManager::new();

        let (full_key, key_meta) = manager
            .create_api_key("test-key", ROLE_ADMIN, None)
            .unwrap();

        assert!(full_key.starts_with("vk_"));
        assert_eq!(key_meta.name, "test-key");

        // Validate the key
        let (validated_key, role) = manager.validate_key(&full_key).unwrap();
        assert_eq!(validated_key.id, key_meta.id);
        assert_eq!(role.name, ROLE_ADMIN);
    }

    #[test]
    fn test_invalid_key_rejected() {
        let manager = AuthManager::new();

        // Wrong prefix
        let result = manager.validate_key("invalid_key");
        assert!(matches!(result, Err(AuthManagerError::InvalidKey)));

        // Correct prefix but unknown
        let result = manager.validate_key("vk_notarealkey12345678901234567");
        assert!(matches!(result, Err(AuthManagerError::InvalidKey)));
    }

    #[test]
    fn test_expired_key_rejected() {
        let manager = AuthManager::new();

        // Create a key that expires in -1 hour (already expired)
        let (full_key, _) = manager
            .create_api_key("expired-key", ROLE_ADMIN, Some(Duration::hours(-1)))
            .unwrap();

        let result = manager.validate_key(&full_key);
        assert!(matches!(result, Err(AuthManagerError::KeyExpired)));
    }

    #[test]
    fn test_revoke_api_key() {
        let manager = AuthManager::new();

        let (full_key, key_meta) = manager.create_api_key("to-revoke", ROLE_ADMIN, None).unwrap();

        // Key should be valid
        assert!(manager.validate_key(&full_key).is_ok());

        // Revoke it
        manager.revoke_api_key(&key_meta.id).unwrap();

        // Key should now be invalid
        assert!(matches!(
            manager.validate_key(&full_key),
            Err(AuthManagerError::InvalidKey)
        ));
    }

    #[test]
    fn test_permission_checking() {
        let manager = AuthManager::new();

        let role = manager
            .create_role(
                "github-reader",
                [Permission::Read].into_iter().collect(),
                vec!["github-*".to_string()],
                None,
            )
            .unwrap();

        // Should allow read on github credentials
        assert!(manager
            .check_permission(&role, Permission::Read, Some("github-api"))
            .is_ok());

        // Should deny write
        assert!(manager
            .check_permission(&role, Permission::Write, Some("github-api"))
            .is_err());

        // Should deny access to non-github credentials
        assert!(manager
            .check_permission(&role, Permission::Read, Some("aws-prod"))
            .is_err());
    }
}
