//! Authentication middleware for request validation
//!
//! Provides functions for:
//! - Extracting API keys from requests
//! - Validating keys and loading roles
//! - Checking permissions for operations

use super::manager::AuthManager;
use super::tokens::UseToken;
use super::types::{ApiKey, Permission, Role};
use thiserror::Error;

/// Authentication errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Missing authentication: Authorization header required")]
    MissingAuth,

    #[error("Invalid authentication scheme: expected 'Bearer'")]
    InvalidScheme,

    #[error("Invalid API key")]
    InvalidKey,

    #[error("API key expired")]
    KeyExpired,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Access denied to credential: {0}")]
    CredentialAccessDenied(String),
}

/// Result of successful authentication
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// The validated API key
    pub api_key: ApiKey,
    /// The role associated with the key
    pub role: Role,
}

impl AuthResult {
    /// Build an ephemeral [`AuthResult`] representing a use token: a one-off role
    /// granting `read` + `execute` scoped to exactly the token's credential
    /// scope. The token's action restriction (which no role can express) is
    /// enforced separately by the caller.
    pub fn for_use_token(token: &UseToken) -> Self {
        let role = Role {
            id: format!("use-token-role:{}", token.id),
            name: format!("use-token:{}", token.name),
            description: Some("Ephemeral grant backing a use token".to_string()),
            permissions: [Permission::Read, Permission::Execute].into_iter().collect(),
            credential_scopes: vec![token.credential_scope.clone()],
            created_at: token.created_at,
        };
        let api_key = ApiKey {
            id: token.id.clone(),
            key_prefix: token.token_prefix.clone(),
            key_hash: token.token_hash.clone(),
            name: token.name.clone(),
            role_id: role.id.clone(),
            expires_at: token.expires_at,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
        };
        Self { api_key, role }
    }

    /// Check if the authenticated user has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.role.has_permission(permission)
    }

    /// Check if the authenticated user can access a specific credential
    pub fn can_access_credential(&self, alias: &str) -> bool {
        self.role.can_access_credential(alias)
    }

    /// Require a specific permission, returning an error if not granted
    pub fn require_permission(&self, permission: Permission) -> Result<(), AuthError> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied(format!(
                "requires '{}' permission",
                permission
            )))
        }
    }

    /// Require access to a specific credential, returning an error if not granted
    pub fn require_credential_access(&self, alias: &str) -> Result<(), AuthError> {
        if self.can_access_credential(alias) {
            Ok(())
        } else {
            Err(AuthError::CredentialAccessDenied(alias.to_string()))
        }
    }

    /// Require both a permission and access to a credential
    pub fn require_permission_for_credential(
        &self,
        permission: Permission,
        alias: &str,
    ) -> Result<(), AuthError> {
        self.require_permission(permission)?;
        self.require_credential_access(alias)
    }
}

/// Extract API key from Authorization header
///
/// Expected format: `Authorization: Bearer vk_...`
pub fn extract_api_key(auth_header: Option<&str>) -> Result<String, AuthError> {
    let header = auth_header.ok_or(AuthError::MissingAuth)?;

    // Check for Bearer scheme
    let parts: Vec<&str> = header.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Err(AuthError::InvalidScheme);
    }

    if !parts[0].eq_ignore_ascii_case("bearer") {
        return Err(AuthError::InvalidScheme);
    }

    let key = parts[1].trim();
    if key.is_empty() {
        return Err(AuthError::InvalidKey);
    }

    Ok(key.to_string())
}

/// Validate an API key and return the authentication result
pub fn validate_request(
    auth_manager: &AuthManager,
    api_key: &str,
) -> Result<AuthResult, AuthError> {
    let (key, role) = auth_manager
        .validate_key(api_key)
        .map_err(|e| match e {
            super::manager::AuthManagerError::InvalidKey => AuthError::InvalidKey,
            super::manager::AuthManagerError::KeyExpired => AuthError::KeyExpired,
            _ => AuthError::InvalidKey,
        })?;

    // Update last used timestamp
    auth_manager.update_key_last_used(&key.key_hash);

    Ok(AuthResult {
        api_key: key,
        role,
    })
}

/// Full authentication flow: extract key from header and validate
pub fn authenticate(
    auth_manager: &AuthManager,
    auth_header: Option<&str>,
) -> Result<AuthResult, AuthError> {
    let api_key = extract_api_key(auth_header)?;
    validate_request(auth_manager, &api_key)
}

/// Map permission requirements to operations
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    /// List credentials
    ListCredentials,
    /// Get credential info
    GetCredentialInfo,
    /// Add a new credential
    AddCredential,
    /// Update an existing credential
    UpdateCredential,
    /// Delete a credential
    DeleteCredential,
    /// Execute a request using a credential
    ExecuteRequest,
}

impl Operation {
    /// Get the required permission for this operation
    pub fn required_permission(&self) -> Permission {
        match self {
            Operation::ListCredentials => Permission::Read,
            Operation::GetCredentialInfo => Permission::Read,
            Operation::AddCredential => Permission::Write,
            Operation::UpdateCredential => Permission::Update,
            Operation::DeleteCredential => Permission::Delete,
            Operation::ExecuteRequest => Permission::Execute,
        }
    }
}

/// Check if an authenticated user can perform an operation
#[allow(dead_code)]
pub fn check_operation(
    auth: &AuthResult,
    operation: Operation,
    credential_alias: Option<&str>,
) -> Result<(), AuthError> {
    let permission = operation.required_permission();

    if let Some(alias) = credential_alias {
        auth.require_permission_for_credential(permission, alias)
    } else {
        auth.require_permission(permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ROLE_ADMIN;

    #[test]
    fn test_extract_api_key_valid() {
        let key = extract_api_key(Some("Bearer vk_abc123")).unwrap();
        assert_eq!(key, "vk_abc123");
    }

    #[test]
    fn test_extract_api_key_case_insensitive() {
        let key = extract_api_key(Some("bearer vk_abc123")).unwrap();
        assert_eq!(key, "vk_abc123");

        let key = extract_api_key(Some("BEARER vk_abc123")).unwrap();
        assert_eq!(key, "vk_abc123");
    }

    #[test]
    fn test_extract_api_key_missing() {
        let result = extract_api_key(None);
        assert!(matches!(result, Err(AuthError::MissingAuth)));
    }

    #[test]
    fn test_extract_api_key_wrong_scheme() {
        let result = extract_api_key(Some("Basic abc123"));
        assert!(matches!(result, Err(AuthError::InvalidScheme)));
    }

    #[test]
    fn test_extract_api_key_no_scheme() {
        let result = extract_api_key(Some("vk_abc123"));
        assert!(matches!(result, Err(AuthError::InvalidScheme)));
    }

    #[test]
    fn test_validate_request() {
        let manager = AuthManager::new();
        let (full_key, _) = manager.create_api_key("test", ROLE_ADMIN, None).unwrap();

        let result = validate_request(&manager, &full_key).unwrap();
        assert!(result.has_permission(Permission::Read));
        assert!(result.has_permission(Permission::Execute));
    }

    #[test]
    fn test_auth_result_permissions() {
        let manager = AuthManager::new();

        // Create a role with limited permissions
        let role = manager
            .create_role(
                "limited",
                [Permission::Read, Permission::Execute].into_iter().collect(),
                vec!["github-*".to_string()],
                None,
            )
            .unwrap();

        let (full_key, _) = manager.create_api_key("test", &role.name, None).unwrap();
        let auth = validate_request(&manager, &full_key).unwrap();

        // Should have read and execute
        assert!(auth.require_permission(Permission::Read).is_ok());
        assert!(auth.require_permission(Permission::Execute).is_ok());

        // Should not have write
        assert!(auth.require_permission(Permission::Write).is_err());

        // Should access github credentials
        assert!(auth.require_credential_access("github-api").is_ok());

        // Should not access aws credentials
        assert!(auth.require_credential_access("aws-prod").is_err());
    }

    #[test]
    fn test_operation_permissions() {
        assert_eq!(Operation::ListCredentials.required_permission(), Permission::Read);
        assert_eq!(Operation::AddCredential.required_permission(), Permission::Write);
        assert_eq!(Operation::ExecuteRequest.required_permission(), Permission::Execute);
        assert_eq!(Operation::DeleteCredential.required_permission(), Permission::Delete);
    }
}
