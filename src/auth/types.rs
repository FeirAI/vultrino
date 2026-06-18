//! Authentication and authorization types for Vultrino RBAC
//!
//! Provides:
//! - Permission enum for access control
//! - Role struct for grouping permissions
//! - ApiKey struct for programmatic access

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Permissions that can be granted to roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// List credentials (metadata only)
    Read,
    /// Create new credentials
    Write,
    /// Modify existing credentials
    Update,
    /// Remove credentials
    Delete,
    /// Use credentials to make authenticated requests
    Execute,
    /// Administer the enforcement plane at runtime: create/update/delete
    /// policies, mint/revoke tokens, manage roles and credential metadata via
    /// the admin API (V1). This is strictly more powerful than the others and is
    /// held only by the admin role (or roles an operator explicitly grants it).
    Admin,
}

impl Permission {
    /// Get all possible permissions
    pub fn all() -> HashSet<Permission> {
        [
            Permission::Read,
            Permission::Write,
            Permission::Update,
            Permission::Delete,
            Permission::Execute,
            Permission::Admin,
        ]
        .into_iter()
        .collect()
    }

    /// Parse a permission from string
    pub fn parse(s: &str) -> Option<Permission> {
        match s.to_lowercase().as_str() {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "update" => Some(Permission::Update),
            "delete" => Some(Permission::Delete),
            "execute" => Some(Permission::Execute),
            "admin" => Some(Permission::Admin),
            _ => None,
        }
    }

    /// Parse multiple permissions from comma-separated string
    pub fn parse_many(s: &str) -> Result<HashSet<Permission>, String> {
        let mut permissions = HashSet::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match Permission::parse(part) {
                Some(p) => {
                    permissions.insert(p);
                }
                None => {
                    return Err(format!("Unknown permission: {}", part));
                }
            }
        }
        Ok(permissions)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Write => write!(f, "write"),
            Permission::Update => write!(f, "update"),
            Permission::Delete => write!(f, "delete"),
            Permission::Execute => write!(f, "execute"),
            Permission::Admin => write!(f, "admin"),
        }
    }
}

/// A role that defines a set of permissions and credential scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier
    pub id: String,
    /// Human-readable name (e.g., "read-only", "github-executor")
    pub name: String,
    /// Description of what this role is for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Permissions granted by this role
    pub permissions: HashSet<Permission>,
    /// Credential patterns this role can access (glob patterns)
    /// Empty means access to all credentials
    #[serde(default)]
    pub credential_scopes: Vec<String>,
    /// When this role was created
    pub created_at: DateTime<Utc>,
}

impl Role {
    /// Create a new role with the given name and permissions
    pub fn new(name: impl Into<String>, permissions: HashSet<Permission>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            description: None,
            permissions,
            credential_scopes: Vec::new(),
            created_at: Utc::now(),
        }
    }

    /// Create a role with a specific ID (for predefined roles with stable IDs)
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Add a description to the role
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add credential scopes to the role
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.credential_scopes = scopes;
        self
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Check if this role can access a credential by its alias
    pub fn can_access_credential(&self, alias: &str) -> bool {
        // Empty scopes means access to all credentials
        if self.credential_scopes.is_empty() {
            return true;
        }

        // Check if any scope pattern matches
        for pattern in &self.credential_scopes {
            if credential_matches_pattern(pattern, alias) {
                return true;
            }
        }
        false
    }
}

/// Check if a credential alias matches a pattern (glob-style)
fn credential_matches_pattern(pattern: &str, alias: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Ok(glob) = glob::Pattern::new(pattern) {
        glob.matches(alias)
    } else {
        pattern == alias
    }
}

/// An API key for programmatic access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier (for storage/deletion)
    pub id: String,
    /// The key prefix for display (first 8 chars, e.g., "vk_abc12...")
    pub key_prefix: String,
    /// Hashed key value (SHA-256)
    pub key_hash: String,
    /// Human-readable name for this key
    pub name: String,
    /// Role ID assigned to this key
    pub role_id: String,
    /// Optional expiration timestamp (None = never expires)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When this key was created
    pub created_at: DateTime<Utc>,
    /// When this key was last used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional agent identity (V4) bound to this key, for `principal_pattern`
    /// matching (so a per-agent policy can target it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
}

impl ApiKey {
    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() >= expires,
            None => false,
        }
    }

    /// Get a display-safe version of the key (prefix only)
    pub fn display_key(&self) -> String {
        format!("{}...", self.key_prefix)
    }
}

/// Metadata for an API key (safe for display, excludes hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMetadata {
    pub id: String,
    pub key_prefix: String,
    pub name: String,
    pub role_id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
}

impl From<&ApiKey> for ApiKeyMetadata {
    fn from(key: &ApiKey) -> Self {
        Self {
            id: key.id.clone(),
            key_prefix: key.key_prefix.clone(),
            name: key.name.clone(),
            role_id: key.role_id.clone(),
            expires_at: key.expires_at,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            agent_label: key.agent_label.clone(),
        }
    }
}

/// Predefined role names (also used as stable IDs)
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_READ_ONLY: &str = "read-only";
pub const ROLE_EXECUTOR: &str = "executor";

/// Create the predefined admin role (full access)
pub fn admin_role() -> Role {
    Role::new(ROLE_ADMIN, Permission::all())
        .with_id(ROLE_ADMIN) // Use name as stable ID
        .with_description("Full administrative access to all credentials")
}

/// Create the predefined read-only role
pub fn read_only_role() -> Role {
    Role::new(ROLE_READ_ONLY, [Permission::Read].into_iter().collect())
        .with_id(ROLE_READ_ONLY) // Use name as stable ID
        .with_description("Read-only access to credential metadata")
}

/// Create the predefined executor role
pub fn executor_role() -> Role {
    Role::new(
        ROLE_EXECUTOR,
        [Permission::Read, Permission::Execute].into_iter().collect(),
    )
    .with_id(ROLE_EXECUTOR) // Use name as stable ID
    .with_description("Execute credentials without management access")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_parsing() {
        assert_eq!(Permission::parse("read"), Some(Permission::Read));
        assert_eq!(Permission::parse("WRITE"), Some(Permission::Write));
        assert_eq!(Permission::parse("invalid"), None);
    }

    #[test]
    fn test_permission_parse_many() {
        let perms = Permission::parse_many("read, write, execute").unwrap();
        assert!(perms.contains(&Permission::Read));
        assert!(perms.contains(&Permission::Write));
        assert!(perms.contains(&Permission::Execute));
        assert!(!perms.contains(&Permission::Delete));
    }

    #[test]
    fn test_role_permissions() {
        let role = Role::new("test", [Permission::Read, Permission::Execute].into_iter().collect());
        assert!(role.has_permission(Permission::Read));
        assert!(role.has_permission(Permission::Execute));
        assert!(!role.has_permission(Permission::Write));
    }

    #[test]
    fn test_role_credential_scopes() {
        let role = Role::new("github-only", [Permission::Execute].into_iter().collect())
            .with_scopes(vec!["github-*".to_string()]);

        assert!(role.can_access_credential("github-api"));
        assert!(role.can_access_credential("github-token"));
        assert!(!role.can_access_credential("aws-prod"));
    }

    #[test]
    fn test_empty_scopes_allows_all() {
        let role = Role::new("all-access", [Permission::Execute].into_iter().collect());
        assert!(role.can_access_credential("anything"));
        assert!(role.can_access_credential("github-api"));
    }

    #[test]
    fn test_predefined_roles() {
        let admin = admin_role();
        assert!(admin.has_permission(Permission::Read));
        assert!(admin.has_permission(Permission::Write));
        assert!(admin.has_permission(Permission::Delete));

        let read_only = read_only_role();
        assert!(read_only.has_permission(Permission::Read));
        assert!(!read_only.has_permission(Permission::Write));

        let executor = executor_role();
        assert!(executor.has_permission(Permission::Execute));
        assert!(!executor.has_permission(Permission::Write));
    }

    #[test]
    fn test_api_key_expiration() {
        let key = ApiKey {
            id: "test".to_string(),
            key_prefix: "vk_abc12".to_string(),
            key_hash: "hash".to_string(),
            name: "test-key".to_string(),
            role_id: "role".to_string(),
            expires_at: None,
            created_at: Utc::now(),
            last_used_at: None,
            agent_label: None,
        };
        assert!(!key.is_expired());

        let expired_key = ApiKey {
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            ..key.clone()
        };
        assert!(expired_key.is_expired());
    }
}
