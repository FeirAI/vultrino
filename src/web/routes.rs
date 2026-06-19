//! Route handlers for the web UI

use askama::Template;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;
use tower_sessions::Session;

/// Constant-time byte comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still do a comparison to keep timing consistent
        let _ = a.ct_eq(&vec![0u8; a.len()]);
        return false;
    }
    a.ct_eq(b).into()
}

/// Extract client IP from request, considering X-Forwarded-For for reverse proxy setups
fn get_client_ip(headers: &HeaderMap, socket_addr: &SocketAddr) -> IpAddr {
    // Check X-Forwarded-For header first (for reverse proxy setups)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain (original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header (nginx)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fall back to direct connection IP
    socket_addr.ip()
}

use crate::approval::ApprovalStatus;
use crate::auth::{NewUseToken, Permission, UseToken};
use crate::plugins::PluginInstaller;
use crate::{Credential, CredentialData, Secret};

use super::api::refresh_auth_data;
use super::auth::{clear_session, get_or_create_csrf_token, regenerate_csrf_token, set_authenticated_session, validate_csrf_token, RequireAuth};
use super::server::AppState;
use super::templates::{
    ApprovalConfirmTemplate, ApprovalDecidedTemplate, ApprovalDisplay, ApprovalsListTemplate,
    AuditLogTemplate, ApiKeyDisplay, CredentialDisplay, CredentialNewTemplate,
    CredentialsListTemplate, DashboardStats, DashboardTemplate, FlashKind, FlashMessage,
    KeyNewTemplate, KeysListTemplate, LoginTemplate, PluginCredentialType, RoleDisplay,
    RoleNewTemplate, RoleOption, RolesListTemplate, UseTokenDisplay, UseTokenNewTemplate,
    UseTokensListTemplate,
};

// ============== Login/Logout ==============

pub async fn login_page() -> impl IntoResponse {
    let template = LoginTemplate { error: None };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    // Get client IP for rate limiting
    let client_ip = get_client_ip(&headers, &addr);
    let rate_limiter = &state.rate_limiter;

    // Check rate limit before processing
    if let Err(remaining_secs) = rate_limiter.check_rate_limit(&client_ip).await {
        let minutes = remaining_secs / 60;
        let error_msg = if minutes > 0 {
            format!("Too many login attempts. Please try again in {} minute(s).", minutes + 1)
        } else {
            format!("Too many login attempts. Please try again in {} seconds.", remaining_secs)
        };

        let template = LoginTemplate {
            error: Some(error_msg),
        };
        return Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response();
    }

    let admin_auth = &state.admin_auth;

    // Verify credentials using constant-time comparison to prevent timing attacks
    // Always verify password regardless of username match to prevent username enumeration
    let password_valid = admin_auth.verify_password(&form.password);
    let username_valid = constant_time_eq(form.username.as_bytes(), admin_auth.username().as_bytes());

    if username_valid && password_valid {
        // Clear rate limit attempts on successful login
        rate_limiter.clear_attempts(&client_ip).await;

        // Set session
        if set_authenticated_session(&session, &form.username).await.is_ok() {
            return Redirect::to("/dashboard").into_response();
        }
    }

    // Record failed attempt for rate limiting
    rate_limiter.record_failed_attempt(&client_ip).await;

    // Failed login
    let template = LoginTemplate {
        error: Some("Invalid username or password".to_string()),
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

pub async fn logout(session: Session) -> impl IntoResponse {
    let _ = clear_session(&session).await;
    Redirect::to("/login")
}

// ============== Dashboard ==============

pub async fn dashboard(
    State(state): State<AppState>,
    auth: RequireAuth,
) -> impl IntoResponse {
    let storage = &state.storage;

    // Get stats
    let credentials = storage.list().await.unwrap_or_default();
    let roles = storage.list_roles().await.unwrap_or_default();
    let api_keys = storage.list_api_keys().await.unwrap_or_default();

    let stats = DashboardStats {
        total_credentials: credentials.len(),
        total_roles: roles.len() + 3, // Include built-in roles
        total_api_keys: api_keys.len(),
        recent_requests: 0, // TODO: Implement audit logging
    };

    let template = DashboardTemplate {
        username: auth.session.username,
        stats,
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

// ============== Credentials ==============

pub async fn credentials_list(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    let credentials = state.storage.list().await.unwrap_or_default();
    let credential_displays: Vec<CredentialDisplay> = credentials.iter().map(|c| c.into()).collect();

    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = CredentialsListTemplate {
        username: auth.session.username,
        credentials: credential_displays,
        flash: None,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn credential_new(session: Session, auth: RequireAuth) -> impl IntoResponse {
    // Load plugin credential types
    let plugin_types = get_plugin_credential_types().await;

    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = CredentialNewTemplate {
        username: auth.session.username,
        error: None,
        plugin_types,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// Get all credential types defined by installed plugins
async fn get_plugin_credential_types() -> Vec<PluginCredentialType> {
    let installer = PluginInstaller::default();
    let installed = installer.list().await.unwrap_or_default();

    let mut plugin_types = Vec::new();
    for info in installed {
        if !info.enabled {
            continue;
        }
        for cred_type in &info.manifest.credential_types {
            plugin_types.push(PluginCredentialType::from_plugin_type(
                &info.manifest.plugin.name,
                cred_type,
            ));
        }
    }
    plugin_types
}

#[derive(Deserialize)]
pub struct CredentialForm {
    alias: String,
    credential_type: String,
    description: Option<String>,
    // API Key fields
    api_key: Option<String>,
    header_name: Option<String>,
    header_prefix: Option<String>,
    // Basic Auth fields
    username: Option<String>,
    password: Option<String>,
    // OAuth2 fields
    client_id: Option<String>,
    client_secret: Option<String>,
    token_url: Option<String>,
    scopes: Option<String>,
    refresh_token: Option<String>,
    // HMAC API Key fields
    hmac_api_key: Option<String>,
    hmac_api_secret: Option<String>,
    hmac_header_name: Option<String>,
    hmac_recv_window: Option<String>,
    // ECDSA Key fields
    ecdsa_private_key: Option<String>,
    ecdsa_api_address: Option<String>,
    ecdsa_testnet: Option<String>,
    // Plugin credential fields (dynamic)
    #[serde(flatten)]
    plugin_fields: HashMap<String, String>,
    // CSRF token
    csrf_token: String,
}

pub async fn credential_create(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Form(form): Form<CredentialForm>,
) -> Response {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return render_credential_new_error_with_session(&session, auth, "Invalid security token. Please try again.")
            .await
            .into_response();
    }
    // Build credential data based on type
    let data = match form.credential_type.as_str() {
        "api_key" => {
            let key = match form.api_key {
                Some(k) if !k.is_empty() => k,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "API key is required")
                        .await
                        .into_response();
                }
            };
            CredentialData::ApiKey {
                key: Secret::new(key),
                header_name: form.header_name.unwrap_or_else(|| "Authorization".to_string()),
                header_prefix: form.header_prefix.unwrap_or_else(|| "Bearer ".to_string()),
            }
        }
        "basic_auth" => {
            let username = match form.username {
                Some(u) if !u.is_empty() => u,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Username is required")
                        .await
                        .into_response();
                }
            };
            let password = match form.password {
                Some(p) if !p.is_empty() => p,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Password is required")
                        .await
                        .into_response();
                }
            };
            CredentialData::BasicAuth {
                username,
                password: Secret::new(password),
            }
        }
        "oauth2" => {
            let client_id = match form.client_id {
                Some(id) if !id.is_empty() => id,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Client ID is required")
                        .await
                        .into_response();
                }
            };
            let client_secret = match form.client_secret {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Client Secret is required")
                        .await
                        .into_response();
                }
            };
            let token_url = match form.token_url {
                Some(url) if !url.is_empty() => {
                    // Validate token URL - must be https for security
                    if !url.starts_with("https://") {
                        return render_credential_new_error_with_session(&session, auth, "Token URL must use HTTPS")
                            .await
                            .into_response();
                    }
                    url
                }
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Token URL is required")
                        .await
                        .into_response();
                }
            };

            // Parse scopes from comma-separated string
            let scopes: Vec<String> = form
                .scopes
                .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();

            // Optional refresh token (some providers give it upfront)
            let refresh_token = form.refresh_token.filter(|s| !s.is_empty()).map(Secret::new);

            CredentialData::OAuth2 {
                client_id,
                client_secret: Secret::new(client_secret),
                refresh_token,
                access_token: None, // Will be fetched on first use
                expires_at: None,
                token_url,
                scopes,
            }
        }
        "hmac_api_key" => {
            let api_key = match form.hmac_api_key {
                Some(k) if !k.is_empty() => k,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "API Key is required")
                        .await
                        .into_response();
                }
            };
            let api_secret = match form.hmac_api_secret {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "API Secret is required")
                        .await
                        .into_response();
                }
            };
            let header_name = form.hmac_header_name.unwrap_or_else(|| "X-MBX-APIKEY".to_string());
            let recv_window: u64 = form
                .hmac_recv_window
                .and_then(|s| s.parse().ok())
                .unwrap_or(5000);

            CredentialData::HmacApiKey {
                api_key,
                api_secret: Secret::new(api_secret),
                header_name,
                recv_window,
            }
        }
        "ecdsa_key" => {
            let private_key = match form.ecdsa_private_key {
                Some(k) if !k.is_empty() => k,
                _ => {
                    return render_credential_new_error_with_session(&session, auth, "Private Key is required")
                        .await
                        .into_response();
                }
            };
            let api_address = form.ecdsa_api_address.filter(|s| !s.is_empty());
            let testnet = form.ecdsa_testnet.map(|s| s == "true" || s == "1" || s == "on").unwrap_or(false);

            CredentialData::EcdsaKey {
                private_key: Secret::new(private_key),
                api_address,
                testnet,
            }
        }
        cred_type if cred_type.starts_with("plugin:") => {
            // Handle plugin credential types
            match parse_plugin_credential(&form).await {
                Ok(data) => data,
                Err(e) => {
                    return render_credential_new_error_with_session(&session, auth, &e).await.into_response();
                }
            }
        }
        _ => {
            return render_credential_new_error_with_session(&session, auth, "Invalid credential type")
                .await
                .into_response();
        }
    };

    // Create and store credential
    let mut credential = Credential::new(form.alias, data);
    if let Some(desc) = form.description {
        if !desc.is_empty() {
            credential = credential.with_metadata("description", desc);
        }
    }

    // Store plugin type in metadata for plugin credentials
    if form.credential_type.starts_with("plugin:") {
        credential = credential.with_metadata("plugin_type", form.credential_type);
    }

    if let Err(e) = state.storage.store(&credential).await {
        return render_credential_new_error_with_session(&session, auth, &format!("Failed to save: {}", e))
            .await
            .into_response();
    }

    Redirect::to("/credentials").into_response()
}

/// Parse plugin credential form data
async fn parse_plugin_credential(form: &CredentialForm) -> Result<CredentialData, String> {
    // Parse plugin:plugin_name:type_name format
    let parts: Vec<&str> = form.credential_type.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("Invalid plugin credential type format".to_string());
    }

    let plugin_name = parts[1];
    let type_name = parts[2];

    // Load the plugin
    let installer = PluginInstaller::default();
    let plugin_info = installer
        .get(plugin_name)
        .await
        .map_err(|e| format!("Failed to load plugin: {}", e))?
        .ok_or_else(|| format!("Plugin '{}' not found", plugin_name))?;

    // Find the credential type definition
    let cred_type = plugin_info
        .manifest
        .credential_types
        .iter()
        .find(|ct| ct.name == type_name)
        .ok_or_else(|| format!("Credential type '{}' not found in plugin", type_name))?;

    // Build form data from the CredentialForm
    // Note: Plugin fields are expected to be in form.plugin_fields
    let plugin_fields = &form.plugin_fields;

    // Validate required fields
    for field in cred_type.required_fields() {
        if !plugin_fields.contains_key(&field.name)
            || plugin_fields.get(&field.name).map(|v| v.is_empty()).unwrap_or(true)
        {
            return Err(format!("Missing required field: {}", field.label));
        }
    }

    // Build credential data as Custom HashMap
    let mut data = std::collections::HashMap::new();
    for field in &cred_type.fields {
        if let Some(value) = plugin_fields.get(&field.name) {
            if !value.is_empty() {
                data.insert(field.name.clone(), Secret::new(value.clone()));
            }
        }
    }

    Ok(CredentialData::Custom(data))
}

async fn render_credential_new_error_with_session(session: &Session, auth: RequireAuth, error: &str) -> impl IntoResponse {
    let plugin_types = get_plugin_credential_types().await;
    let csrf_token = get_or_create_csrf_token(session).await.unwrap_or_default();
    let template = CredentialNewTemplate {
        username: auth.session.username,
        error: Some(error.to_string()),
        plugin_types,
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf_token: String,
}

pub async fn credential_delete(
    State(state): State<AppState>,
    session: Session,
    _auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/credentials").into_response();
    }
    let _ = state.storage.delete(&id).await;
    // Regenerate CSRF token after successful action
    let _ = regenerate_csrf_token(&session).await;
    Redirect::to("/credentials").into_response()
}

// ============== Roles ==============

pub async fn roles_list(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    // Add stored custom roles
    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_displays: Vec<RoleDisplay> = roles.iter().map(|r| r.into()).collect();
    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = RolesListTemplate {
        username: auth.session.username,
        roles: role_displays,
        flash: None,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn role_new(session: Session, auth: RequireAuth) -> impl IntoResponse {
    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();
    let template = RoleNewTemplate {
        username: auth.session.username,
        error: None,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct RoleForm {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    scopes: Option<String>,
    csrf_token: String,
}

pub async fn role_create(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Form(form): Form<RoleForm>,
) -> Response {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return render_role_new_error_with_session(&session, auth, "Invalid security token. Please try again.").await.into_response();
    }

    // Parse permissions
    let permissions: std::collections::HashSet<Permission> = form
        .permissions
        .iter()
        .filter_map(|p| match p.as_str() {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "update" => Some(Permission::Update),
            "delete" => Some(Permission::Delete),
            "execute" => Some(Permission::Execute),
            _ => None,
        })
        .collect();

    if permissions.is_empty() {
        return render_role_new_error_with_session(&session, auth, "At least one permission is required").await.into_response();
    }

    // Parse scopes
    let credential_scopes: Vec<String> = form
        .scopes
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    // Create the role
    let auth_manager = state.auth_manager.write().await;
    let role = match auth_manager.create_role(&form.name, permissions, credential_scopes, form.description) {
        Ok(r) => r,
        Err(e) => {
            return render_role_new_error_with_session(&session, auth, &format!("Failed to create role: {}", e)).await.into_response();
        }
    };

    // Store the role
    if let Err(e) = state.storage.store_role(&role).await {
        return render_role_new_error_with_session(&session, auth, &format!("Failed to save: {}", e)).await.into_response();
    }

    // Refresh auth data to update the cached AuthManager
    let _ = refresh_auth_data(&state).await;

    Redirect::to("/roles").into_response()
}

async fn render_role_new_error_with_session(session: &Session, auth: RequireAuth, error: &str) -> impl IntoResponse {
    let csrf_token = get_or_create_csrf_token(session).await.unwrap_or_default();
    let template = RoleNewTemplate {
        username: auth.session.username,
        error: Some(error.to_string()),
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn role_delete(
    State(state): State<AppState>,
    session: Session,
    _auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/roles").into_response();
    }

    // Don't allow deleting built-in roles
    let auth_manager = state.auth_manager.read().await;
    if let Some(role) = auth_manager.get_role(&id) {
        if matches!(role.name.as_str(), "admin" | "read-only" | "executor") {
            return Redirect::to("/roles").into_response();
        }
    }
    drop(auth_manager);

    let _ = state.storage.delete_role(&id).await;

    // Refresh auth data to update the cached AuthManager
    let _ = refresh_auth_data(&state).await;

    let _ = regenerate_csrf_token(&session).await;
    Redirect::to("/roles").into_response()
}

// ============== API Keys ==============

pub async fn keys_list(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    let keys = state.storage.list_api_keys().await.unwrap_or_default();
    let auth_manager = state.auth_manager.read().await;

    let key_displays: Vec<ApiKeyDisplay> = keys
        .iter()
        .map(|k| {
            let role = auth_manager.get_role(&k.role_id);
            ApiKeyDisplay::from_key_and_role(k, role.as_ref())
        })
        .collect();

    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = KeysListTemplate {
        username: auth.session.username,
        keys: key_displays,
        flash: None,
        new_key: None,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn key_new(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    // Add stored custom roles
    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_options: Vec<RoleOption> = roles.iter().map(|r| r.into()).collect();
    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = KeyNewTemplate {
        username: auth.session.username,
        roles: role_options,
        error: None,
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct KeyForm {
    name: String,
    role: String,
    expires: Option<String>,
    csrf_token: String,
}

pub async fn key_create(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Form(form): Form<KeyForm>,
) -> Response {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return render_key_new_error_with_session(&state, &session, auth, "Invalid security token. Please try again.").await.into_response();
    }
    // Parse expiration
    let expires_in = match form.expires.as_deref() {
        Some("never") | Some("") | None => None,
        Some(s) => {
            match parse_duration(s) {
                Ok(d) => d,
                Err(e) => {
                    return render_key_new_error_with_session(&state, &session, auth, &e).await.into_response();
                }
            }
        }
    };

    let auth_manager = state.auth_manager.write().await;

    // Verify role exists
    if auth_manager.get_role_by_name(&form.role).is_none() {
        return render_key_new_error_with_session(&state, &session, auth, &format!("Role '{}' not found", form.role))
            .await
            .into_response();
    }

    // Create the key
    let (full_key, api_key) = match auth_manager.create_api_key(&form.name, &form.role, expires_in) {
        Ok(k) => k,
        Err(e) => {
            return render_key_new_error_with_session(&state, &session, auth, &format!("Failed to create key: {}", e))
                .await
                .into_response();
        }
    };

    // Store the key
    if let Err(e) = state.storage.store_api_key(&api_key).await {
        return render_key_new_error_with_session(&state, &session, auth, &format!("Failed to save: {}", e))
            .await
            .into_response();
    }

    // Refresh auth data to update the cached AuthManager
    let _ = refresh_auth_data(&state).await;

    // Need to re-acquire the read lock after refresh
    let auth_manager = state.auth_manager.read().await;

    // Show the key list with the new key displayed once
    let keys = state.storage.list_api_keys().await.unwrap_or_default();
    let key_displays: Vec<ApiKeyDisplay> = keys
        .iter()
        .map(|k| {
            let role = auth_manager.get_role(&k.role_id);
            ApiKeyDisplay::from_key_and_role(k, role.as_ref())
        })
        .collect();

    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = KeysListTemplate {
        username: auth.session.username,
        keys: key_displays,
        flash: Some(FlashMessage {
            kind: FlashKind::Success,
            message: "API key created successfully".to_string(),
        }),
        new_key: Some(full_key),
        csrf_token,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

async fn render_key_new_error_with_session(state: &AppState, session: &Session, auth: RequireAuth, error: &str) -> impl IntoResponse {
    let auth_manager = state.auth_manager.read().await;
    let mut roles = auth_manager.list_roles();

    if let Ok(stored_roles) = state.storage.list_roles().await {
        for role in stored_roles {
            if !roles.iter().any(|r| r.name == role.name) {
                roles.push(role);
            }
        }
    }

    let role_options: Vec<RoleOption> = roles.iter().map(|r| r.into()).collect();
    let csrf_token = get_or_create_csrf_token(session).await.unwrap_or_default();

    let template = KeyNewTemplate {
        username: auth.session.username,
        roles: role_options,
        error: Some(error.to_string()),
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn key_revoke(
    State(state): State<AppState>,
    session: Session,
    _auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    // Validate CSRF token
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/keys").into_response();
    }
    let _ = state.storage.delete_api_key(&id).await;

    // Refresh auth data to update the cached AuthManager
    let _ = refresh_auth_data(&state).await;

    let _ = regenerate_csrf_token(&session).await;
    Redirect::to("/keys").into_response()
}

// ============== Audit Log ==============

pub async fn audit_log(auth: RequireAuth) -> impl IntoResponse {
    // TODO: Implement audit logging
    let template = AuditLogTemplate {
        username: auth.session.username,
        entries: vec![],
        flash: None,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

// ============== Use Tokens ==============

/// Render the use-token listing (optionally surfacing a freshly-minted token).
async fn render_tokens_list(
    state: &AppState,
    session: &tower_sessions::Session,
    username: String,
    new_token: Option<String>,
    flash: Option<FlashMessage>,
) -> Html<String> {
    let _ = state.storage.reload().await;
    let mut tokens = state.storage.list_use_tokens().await.unwrap_or_default();
    // Newest first.
    tokens.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let token_displays: Vec<UseTokenDisplay> = tokens.iter().map(UseTokenDisplay::from).collect();
    let csrf_token = get_or_create_csrf_token(session).await.unwrap_or_default();

    let template = UseTokensListTemplate {
        username,
        tokens: token_displays,
        flash,
        new_token,
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn tokens_list(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    render_tokens_list(&state, &session, auth.session.username, None, None).await
}

pub async fn token_new(session: Session, auth: RequireAuth) -> impl IntoResponse {
    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();
    let template = UseTokenNewTemplate {
        username: auth.session.username,
        error: None,
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

#[derive(Deserialize)]
pub struct UseTokenForm {
    name: String,
    credential_scope: String,
    action_scope: Option<String>,
    max_uses: Option<String>,
    expires: Option<String>,
    require_approval: Option<String>,
    csrf_token: String,
}

pub async fn token_create(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Form(form): Form<UseTokenForm>,
) -> Response {
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return render_token_new_error(&session, auth, "Invalid security token. Please try again.")
            .await
            .into_response();
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_token_new_error(&session, auth, "Name is required").await.into_response();
    }
    let credential_scope = form.credential_scope.trim().to_string();
    if credential_scope.is_empty() {
        return render_token_new_error(&session, auth, "Credential scope is required (use * for any)")
            .await
            .into_response();
    }
    let action_scope = form
        .action_scope
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let max_uses = match form.max_uses.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => match s.parse::<u32>() {
            Ok(n) if n >= 1 => Some(n),
            _ => {
                return render_token_new_error(&session, auth, "Max uses must be a positive whole number")
                    .await
                    .into_response();
            }
        },
    };

    let expires_in = match form.expires.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => match parse_short_duration(s) {
            Ok(d) => d,
            Err(e) => return render_token_new_error(&session, auth, &e).await.into_response(),
        },
    };

    let require_approval = matches!(form.require_approval.as_deref(), Some("true") | Some("on") | Some("1"));

    let params = NewUseToken {
        name,
        credential_scope,
        action_scope,
        max_uses,
        require_approval,
        expires_in,
    };
    if let Err(e) = params.validate() {
        return render_token_new_error(&session, auth, &e).await.into_response();
    }
    let (full_token, token) = UseToken::create(params);

    if let Err(e) = state.storage.store_use_token(&token).await {
        return render_token_new_error(&session, auth, &format!("Failed to save token: {}", e))
            .await
            .into_response();
    }

    render_tokens_list(
        &state,
        &session,
        auth.session.username,
        Some(full_token),
        Some(FlashMessage {
            kind: FlashKind::Success,
            message: "Use token created".to_string(),
        }),
    )
    .await
    .into_response()
}

async fn render_token_new_error(session: &Session, auth: RequireAuth, error: &str) -> impl IntoResponse {
    let csrf_token = get_or_create_csrf_token(session).await.unwrap_or_default();
    let template = UseTokenNewTemplate {
        username: auth.session.username,
        error: Some(error.to_string()),
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn token_revoke(
    State(state): State<AppState>,
    session: Session,
    _auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/tokens").into_response();
    }
    // Mark revoked (preserve the audit trail) rather than hard-deleting.
    let _ = state.storage.set_use_token_revoked(&id).await;
    let _ = regenerate_csrf_token(&session).await;
    Redirect::to("/tokens").into_response()
}

// ============== Approvals ==============

pub async fn approvals_list(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
) -> impl IntoResponse {
    let _ = state.storage.reload().await;
    // R4: the panel admin is a global console (no tenant) so it lists every
    // tenant's approvals; routing through the scoped method keeps the partition
    // mechanism uniform (a future tenant-scoped session would pass its tenant).
    let mut approvals = state.server.list_approvals_for_tenant(None).await.unwrap_or_default();
    // Pending first, then most recent.
    approvals.sort_by(|a, b| {
        let pending = |s: &ApprovalStatus| *s == ApprovalStatus::Pending;
        pending(&b.status)
            .cmp(&pending(&a.status))
            .then(b.created_at.cmp(&a.created_at))
    });
    let approval_displays: Vec<ApprovalDisplay> = approvals.iter().map(ApprovalDisplay::from).collect();
    let csrf_token = get_or_create_csrf_token(&session).await.unwrap_or_default();

    let template = ApprovalsListTemplate {
        username: auth.session.username,
        approvals: approval_displays,
        flash: None,
        csrf_token,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

pub async fn approval_approve(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/approvals").into_response();
    }
    // Atomic decision under the storage lock (no reload+get+update window). The
    // panel approver's identity is the authenticated session user (V5).
    let enforce_sod = state.config.approval.enforce_separation_of_duty;
    // R4: decide through the tenant-scoped guard (global panel admin = None).
    let result = state
        .server
        .decide_approval_scoped(&id, true, "admin panel", &auth.session.username, enforce_sod, None, None)
        .await;
    let _ = regenerate_csrf_token(&session).await;
    // Surface a rejected decision (e.g. a separation-of-duty self-approval, or an
    // already-decided/expired request) rather than silently redirecting (V5).
    match result {
        Ok(_) => Redirect::to("/approvals").into_response(),
        Err(e) => render_decided("Could not approve", &format!("The approval was not recorded: {}", e), false),
    }
}

pub async fn approval_deny(
    State(state): State<AppState>,
    session: Session,
    auth: RequireAuth,
    Path(id): Path<String>,
    Form(form): Form<DeleteForm>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &form.csrf_token).await {
        return Redirect::to("/approvals").into_response();
    }
    // A denial is always allowed regardless of SoD (only approval self-grants are
    // the concern), but pass the flag through for consistent attribution.
    let enforce_sod = state.config.approval.enforce_separation_of_duty;
    // R4: decide through the tenant-scoped guard (global panel admin = None).
    let result = state
        .server
        .decide_approval_scoped(&id, false, "admin panel", &auth.session.username, enforce_sod, None, None)
        .await;
    let _ = regenerate_csrf_token(&session).await;
    match result {
        Ok(_) => Redirect::to("/approvals").into_response(),
        Err(e) => render_decided("Could not deny", &format!("The denial was not recorded: {}", e), false),
    }
}

/// Query/form parameters for an out-of-band decision link.
#[derive(Deserialize)]
pub struct DecideParams {
    token: String,
    decision: String,
}

fn render_decided(title: &str, message: &str, ok: bool) -> Response {
    let template = ApprovalDecidedTemplate {
        title: title.to_string(),
        message: message.to_string(),
        ok,
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// GET handler for the Telegram/webhook/email approve|deny link. To prevent a
/// link prefetch from silently deciding, this only renders a confirmation page
/// with a POST button — the actual decision happens in [`approval_decide_submit`].
pub async fn approval_decide_confirm(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<DecideParams>,
) -> Response {
    let _ = state.storage.reload().await;
    let approval = match state.storage.get_approval(&id).await {
        Ok(Some(a)) => a,
        _ => return render_decided("Not found", "No such approval request.", false),
    };
    if !approval.verify_decision_token(&params.token) {
        return render_decided("Invalid link", "This approval link is invalid or has been tampered with.", false);
    }
    if params.decision != "approve" && params.decision != "deny" {
        return render_decided("Invalid decision", "Unknown decision.", false);
    }

    let template = ApprovalConfirmTemplate {
        id,
        token: params.token,
        decision: params.decision.clone(),
        decision_word: if params.decision == "approve" { "Approve".to_string() } else { "Deny".to_string() },
        summary: approval.summary.clone(),
    };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e))).into_response()
}

/// POST handler that actually records the out-of-band decision, authorized by
/// the capability token (no session required).
pub async fn approval_decide_submit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Form(params): Form<DecideParams>,
) -> Response {
    let _ = state.storage.reload().await;
    let approval = match state.storage.get_approval(&id).await {
        Ok(Some(a)) => a,
        _ => return render_decided("Not found", "No such approval request.", false),
    };
    if !approval.verify_decision_token(&params.token) {
        return render_decided("Invalid link", "This approval link is invalid or has been tampered with.", false);
    }
    let approve = match params.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return render_decided("Invalid decision", "Unknown decision.", false),
    };

    // The OOB link must be bound to a NAMED approver identity (V5/R2) so the
    // verdict is attributable — separation of duty is meaningless against an
    // anonymous channel label. With no named identity bound at open time, refuse
    // rather than record an unattributable "out-of-band" verdict; config load also
    // rejects a notifier without `oob_approver_identity`, so a correctly-configured
    // deployment never reaches this fail-closed branch.
    let approver_identity = match approval
        .oob_identity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(id) => id,
        None => {
            return render_decided(
                "Not available",
                "This approval has no named out-of-band approver identity, so it can \
                 only be decided in the admin panel.",
                false,
            )
        }
    };
    let enforce_sod = state.config.approval.enforce_separation_of_duty;
    match state
        .storage
        .decide_approval(&id, approve, "out-of-band link", approver_identity, enforce_sod, None)
        .await
    {
        Ok(_) => {
            if approve {
                render_decided(
                    "Approved",
                    "The action has been approved. The agent will run it on its next check and receive the result.",
                    true,
                )
            } else {
                render_decided("Denied", "The action has been denied and will not run.", true)
            }
        }
        Err(e) => render_decided("Already decided", &format!("This request could not be updated: {}", e), false),
    }
}

// ============== API Endpoints ==============

pub async fn api_stats(
    State(state): State<AppState>,
    _auth: RequireAuth,
) -> impl IntoResponse {
    let credentials = state.storage.list().await.unwrap_or_default();
    let roles = state.storage.list_roles().await.unwrap_or_default();
    let api_keys = state.storage.list_api_keys().await.unwrap_or_default();

    axum::Json(serde_json::json!({
        "credentials": credentials.len(),
        "roles": roles.len() + 3,
        "api_keys": api_keys.len(),
        "recent_requests": 0
    }))
}

// ============== Helpers ==============

/// Parse a short-lived duration for use tokens. Unlike [`parse_duration`] (used
/// for API keys, where `m` means months), here `m` means **minutes** because use
/// tokens are typically scoped to seconds/minutes/hours. Units: s, m, h, d, w.
fn parse_short_duration(s: &str) -> Result<Option<chrono::Duration>, String> {
    let s = s.trim().to_lowercase();
    if s.is_empty() || s == "never" {
        return Ok(None);
    }
    // Split off the trailing unit char on a UTF-8 boundary (a byte index split
    // would panic on multibyte input like "30€").
    let unit_ch = s.chars().last().unwrap();
    let num_str = &s[..s.len() - unit_ch.len_utf8()];
    let unit_string = unit_ch.to_string();
    let unit = unit_string.as_str();
    let n: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid duration '{}'. Use e.g. 30m, 24h, 7d.", s))?;
    let duration = match unit {
        "s" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        "w" => chrono::Duration::weeks(n),
        _ => return Err(format!("Invalid duration unit in '{}'. Use s, m, h, d, or w.", s)),
    };
    if duration <= chrono::Duration::zero() {
        return Err("Duration must be positive".to_string());
    }
    Ok(Some(duration))
}

fn parse_duration(s: &str) -> Result<Option<chrono::Duration>, String> {
    let s = s.trim().to_lowercase();
    if s == "never" || s.is_empty() {
        return Ok(None);
    }

    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len() - 1], "d")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('w') {
        (&s[..s.len() - 1], "w")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('y') {
        (&s[..s.len() - 1], "y")
    } else {
        return Err(format!("Invalid duration format: {}. Use '30d', '24h', '1w'", s));
    };

    let num: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number: {}", num_str))?;

    let duration = match unit {
        "h" => chrono::Duration::hours(num),
        "d" => chrono::Duration::days(num),
        "w" => chrono::Duration::weeks(num),
        "m" => chrono::Duration::days(num * 30),
        "y" => chrono::Duration::days(num * 365),
        _ => unreachable!(),
    };

    Ok(Some(duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"password123", b"password123"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"a", b"a"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"password123", b"password124"));
        assert!(!constant_time_eq(b"password123", b"password12"));
        assert!(!constant_time_eq(b"a", b"b"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_eq(b"admin", b"administrator"));
    }

    #[test]
    fn test_parse_duration_valid() {
        assert!(parse_duration("30d").unwrap().is_some());
        assert!(parse_duration("24h").unwrap().is_some());
        assert!(parse_duration("1w").unwrap().is_some());
        assert!(parse_duration("6m").unwrap().is_some());
        assert!(parse_duration("1y").unwrap().is_some());
    }

    #[test]
    fn test_parse_duration_empty() {
        assert!(parse_duration("").unwrap().is_none());
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("30x").is_err());
    }
}
