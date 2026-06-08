//! Askama HTML templates for the web UI

use askama::Template;
use crate::auth::Role;
use crate::plugins::CredentialTypeDefinition;

/// Flash message for displaying notifications
#[derive(Debug, Clone)]
pub struct FlashMessage {
    pub kind: FlashKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum FlashKind {
    Success,
    Error,
    Info,
}

impl FlashKind {
    pub fn as_class(&self) -> &'static str {
        match self {
            FlashKind::Success => "flash-success",
            FlashKind::Error => "flash-error",
            FlashKind::Info => "flash-info",
        }
    }
}

// ============== Login Page ==============

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

// ============== Dashboard ==============

#[derive(Debug, Clone)]
pub struct DashboardStats {
    pub total_credentials: usize,
    pub total_roles: usize,
    pub total_api_keys: usize,
    pub recent_requests: usize,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub username: String,
    pub stats: DashboardStats,
    pub flash: Option<FlashMessage>,
}

// ============== Credentials ==============

/// Simplified credential display for templates
#[derive(Debug, Clone)]
pub struct CredentialDisplay {
    pub id: String,
    pub alias: String,
    pub credential_type: String,
    pub description: String,
    pub created_at: String,
}

impl From<&crate::CredentialMetadata> for CredentialDisplay {
    fn from(cred: &crate::CredentialMetadata) -> Self {
        Self {
            id: cred.id.clone(),
            alias: cred.alias.clone(),
            credential_type: cred.credential_type.to_string(),
            description: cred.metadata.get("description").cloned().unwrap_or_else(|| "-".to_string()),
            created_at: cred.created_at.format("%Y-%m-%d").to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "credentials/list.html")]
pub struct CredentialsListTemplate {
    pub username: String,
    pub credentials: Vec<CredentialDisplay>,
    pub flash: Option<FlashMessage>,
    /// CSRF token for delete forms
    pub csrf_token: String,
}

/// Plugin credential type display for template
#[derive(Debug, Clone)]
pub struct PluginCredentialType {
    /// Full type value (e.g., "plugin:pgp-signing:pgp_key")
    pub value: String,
    /// Display name (e.g., "PGP/GPG Key")
    pub display_name: String,
    /// Plugin name
    pub plugin_name: String,
    /// Fields for this credential type
    pub fields: Vec<PluginCredentialField>,
}

impl PluginCredentialType {
    pub fn from_plugin_type(plugin_name: &str, cred_type: &CredentialTypeDefinition) -> Self {
        Self {
            value: format!("plugin:{}:{}", plugin_name, cred_type.name),
            display_name: cred_type.display_name.clone(),
            plugin_name: plugin_name.to_string(),
            fields: cred_type
                .fields
                .iter()
                .map(|f| PluginCredentialField {
                    name: f.name.clone(),
                    label: f.label.clone(),
                    field_type: format!("{:?}", f.field_type).to_lowercase(),
                    required: f.required,
                    secret: f.secret,
                    help_text: f.help_text.clone(),
                    placeholder: f.placeholder.clone(),
                })
                .collect(),
        }
    }
}

/// Field definition for plugin credential types
#[derive(Debug, Clone)]
pub struct PluginCredentialField {
    pub name: String,
    pub label: String,
    pub field_type: String,
    pub required: bool,
    #[allow(dead_code)]
    pub secret: bool,
    pub help_text: Option<String>,
    pub placeholder: Option<String>,
}

impl PluginCredentialField {
    /// Get placeholder or empty string for template
    pub fn placeholder_or_empty(&self) -> &str {
        self.placeholder.as_deref().unwrap_or("")
    }
}

#[derive(Template)]
#[template(path = "credentials/new.html")]
pub struct CredentialNewTemplate {
    pub username: String,
    pub error: Option<String>,
    /// Plugin credential types available
    pub plugin_types: Vec<PluginCredentialType>,
    /// CSRF token for form protection
    pub csrf_token: String,
}

// ============== Roles ==============

/// Simplified role display for templates
#[derive(Debug, Clone)]
pub struct RoleDisplay {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub scopes: String,
    pub created_at: String,
    pub is_builtin: bool,
}

impl From<&Role> for RoleDisplay {
    fn from(role: &Role) -> Self {
        Self {
            id: role.id.clone(),
            name: role.name.clone(),
            description: role.description.clone().unwrap_or_default(),
            permissions: role.permissions.iter().map(|p| p.to_string()).collect(),
            scopes: if role.credential_scopes.is_empty() {
                "All credentials".to_string()
            } else {
                role.credential_scopes.join(", ")
            },
            created_at: role.created_at.format("%Y-%m-%d").to_string(),
            is_builtin: matches!(role.name.as_str(), "admin" | "read-only" | "executor"),
        }
    }
}

#[derive(Template)]
#[template(path = "roles/list.html")]
pub struct RolesListTemplate {
    pub username: String,
    pub roles: Vec<RoleDisplay>,
    pub flash: Option<FlashMessage>,
    /// CSRF token for delete forms
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "roles/new.html")]
pub struct RoleNewTemplate {
    pub username: String,
    pub error: Option<String>,
    /// CSRF token for form protection
    pub csrf_token: String,
}

// ============== API Keys ==============

#[derive(Debug, Clone)]
pub struct ApiKeyDisplay {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub role_name: String,
    pub expires: String,
    pub last_used: String,
    pub created_at: String,
}

impl ApiKeyDisplay {
    pub fn from_key_and_role(key: &crate::auth::ApiKey, role: Option<&Role>) -> Self {
        Self {
            id: key.id.clone(),
            name: key.name.clone(),
            key_prefix: format!("{}...", key.key_prefix),
            role_name: role.map(|r| r.name.clone()).unwrap_or_else(|| key.role_id.clone()),
            expires: key
                .expires_at
                .map(|e| e.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Never".to_string()),
            last_used: key
                .last_used_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
            created_at: key.created_at.format("%Y-%m-%d").to_string(),
        }
    }
}

#[derive(Template)]
#[template(path = "keys/list.html")]
pub struct KeysListTemplate {
    pub username: String,
    pub keys: Vec<ApiKeyDisplay>,
    pub flash: Option<FlashMessage>,
    /// New key that was just created (shown once)
    pub new_key: Option<String>,
    /// CSRF token for delete forms
    pub csrf_token: String,
}

/// Simplified role for key creation form
#[derive(Debug, Clone)]
pub struct RoleOption {
    pub name: String,
    pub description: String,
}

impl From<&Role> for RoleOption {
    fn from(role: &Role) -> Self {
        Self {
            name: role.name.clone(),
            description: role.description.clone().unwrap_or_default(),
        }
    }
}

#[derive(Template)]
#[template(path = "keys/new.html")]
pub struct KeyNewTemplate {
    pub username: String,
    pub roles: Vec<RoleOption>,
    pub error: Option<String>,
    /// CSRF token for form protection
    pub csrf_token: String,
}

// ============== Use Tokens ==============

/// Use token row for the listing table.
#[derive(Debug, Clone)]
pub struct UseTokenDisplay {
    pub id: String,
    pub name: String,
    pub token_prefix: String,
    pub credential_scope: String,
    pub action_scope: String,
    pub uses_display: String,
    pub expires: String,
    pub last_used: String,
    pub status: String,
    pub revoked: bool,
}

impl From<&crate::auth::UseToken> for UseTokenDisplay {
    fn from(t: &crate::auth::UseToken) -> Self {
        let uses_display = match t.max_uses {
            Some(max) => format!("{} / {}", t.uses, max),
            None => format!("{} / \u{221E}", t.uses),
        };
        let status = if t.revoked {
            "revoked".to_string()
        } else if t.is_expired() {
            "expired".to_string()
        } else if t.is_exhausted() {
            "exhausted".to_string()
        } else {
            "active".to_string()
        };
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            token_prefix: format!("{}...", t.token_prefix),
            credential_scope: t.credential_scope.clone(),
            action_scope: t.action_scope.clone().unwrap_or_else(|| "any action".to_string()),
            uses_display,
            expires: t
                .expires_at
                .map(|e| e.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
            last_used: t
                .last_used_at
                .map(|e| e.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
            status,
            revoked: t.revoked,
        }
    }
}

#[derive(Template)]
#[template(path = "tokens/list.html")]
pub struct UseTokensListTemplate {
    pub username: String,
    pub tokens: Vec<UseTokenDisplay>,
    pub flash: Option<FlashMessage>,
    /// Newly-minted token, shown once.
    pub new_token: Option<String>,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "tokens/new.html")]
pub struct UseTokenNewTemplate {
    pub username: String,
    pub error: Option<String>,
    pub csrf_token: String,
}

// ============== Audit Log ==============

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub credential: String,
    pub api_key: String,
    pub status: String,
    pub details: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditLogTemplate {
    pub username: String,
    pub entries: Vec<AuditEntry>,
    pub flash: Option<FlashMessage>,
}

// ============== Error Pages ==============

#[derive(Template)]
#[template(path = "error.html")]
#[allow(dead_code)]
pub struct ErrorTemplate {
    pub status_code: u16,
    pub message: String,
}
