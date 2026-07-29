//! Askama HTML templates for the web UI

use crate::auth::Role;
use crate::plugins::CredentialTypeDefinition;
use askama::Template;

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
            description: cred
                .metadata
                .get("description")
                .cloned()
                .unwrap_or_else(|| "-".to_string()),
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
            role_name: role
                .map(|r| r.name.clone())
                .unwrap_or_else(|| key.role_id.clone()),
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
    pub require_approval: bool,
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
            action_scope: t
                .action_scope
                .clone()
                .unwrap_or_else(|| "any action".to_string()),
            uses_display,
            require_approval: t.require_approval,
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

// ============== Approvals ==============

/// Approval row / detail for the approvals page.
#[derive(Debug, Clone)]
pub struct ApprovalDisplay {
    pub id: String,
    pub status: String,
    pub status_class: String,
    pub summary: String,
    pub credential: String,
    pub action: String,
    pub requested_by: String,
    pub created_at: String,
    pub expires_at: String,
    pub is_pending: bool,
    pub decided_by: String,
    pub result_summary: String,
    pub params_pretty: String,
}

impl From<&crate::approval::ApprovalRequest> for ApprovalDisplay {
    fn from(a: &crate::approval::ApprovalRequest) -> Self {
        use crate::approval::ApprovalStatus;
        let status_class = match a.status() {
            ApprovalStatus::Pending => "badge-pending",
            ApprovalStatus::Escalated => "badge-warning",
            ApprovalStatus::Approved => "badge-success",
            ApprovalStatus::Denied => "badge-danger",
            ApprovalStatus::Expired => "badge-muted",
        };
        let result_summary = if let Some(err) = &a.result_error {
            format!("execution error: {}", err)
        } else if let Some(status) = a.result_status {
            format!("executed, status {}", status)
        } else if a.status() == ApprovalStatus::Approved {
            "approved, awaiting agent poll to execute".to_string()
        } else {
            String::new()
        };
        let params_pretty = serde_json::to_string_pretty(&a.params).unwrap_or_default();
        Self {
            id: a.id.clone(),
            status: a.status().to_string(),
            status_class: status_class.to_string(),
            summary: a.summary.clone(),
            credential: a.credential.clone(),
            action: a.action.clone(),
            requested_by: a.requester.describe(),
            created_at: a.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            expires_at: a.expires_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            // Open (Pending or Escalated) and not past deadline → still decidable.
            is_pending: a.status().is_open() && !a.is_past_ttl(),
            // Show the channel plus the authenticated approver identity (V5).
            decided_by: match (&a.decided_by, &a.approver_identity) {
                (Some(ch), Some(id)) => format!("{} ({})", ch, id),
                (Some(ch), None) => ch.clone(),
                _ => String::new(),
            },
            result_summary,
            params_pretty,
        }
    }
}

#[derive(Template)]
#[template(path = "approvals/list.html")]
pub struct ApprovalsListTemplate {
    pub username: String,
    pub approvals: Vec<ApprovalDisplay>,
    pub flash: Option<FlashMessage>,
    pub csrf_token: String,
}

/// Confirmation page shown when an out-of-band (token) link is opened, so a
/// link prefetch can't silently approve/deny — the human must click Confirm.
#[derive(Template)]
#[template(path = "approvals/confirm.html")]
pub struct ApprovalConfirmTemplate {
    pub id: String,
    pub token: String,
    pub decision: String,
    pub decision_word: String,
    pub summary: String,
}

/// Simple standalone confirmation page for out-of-band (token) decisions.
#[derive(Template)]
#[template(path = "approvals/decided.html")]
pub struct ApprovalDecidedTemplate {
    pub title: String,
    pub message: String,
    pub ok: bool,
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

// (removed dead `ErrorTemplate` — error paths return error_response()/redirects, never this template.)
