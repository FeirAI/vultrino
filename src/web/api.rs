//! JSON API handlers with API key authentication
//!
//! These endpoints allow CLI and external applications to interact with
//! Vultrino using API keys instead of session-based authentication.

use axum::{
    extract::{Json, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::approval::ApprovalStatus;
use crate::auth::{AuthResult, Permission, UseToken};
use crate::router::CredentialResolver;
use crate::server::{ExecAuth, VultrinoServer};
use crate::{ExecuteRequest, ExecutionOutcome};

use super::server::AppState;

use crate::auth::ApiKey;
use crate::auth::Role;

/// Extract API key from Authorization header
fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Validate the API key using the cached AuthManager
/// Auth data is refreshed when keys/roles are modified through the web UI
async fn validate_api_key(state: &AppState, api_key: &str) -> Result<(ApiKey, Role), String> {
    let auth_manager = state.auth_manager.read().await;
    auth_manager
        .validate_key(api_key)
        .map_err(|e| e.to_string())
}

/// Refresh auth data from storage (called after key/role modifications)
pub async fn refresh_auth_data(state: &AppState) -> Result<(), String> {
    // Reload storage to get latest data
    state.storage.reload().await.map_err(|e| format!("Failed to reload storage: {}", e))?;

    // Get fresh keys and roles
    let stored_keys = state.storage.list_api_keys().await.unwrap_or_default();
    let stored_roles = state.storage.list_roles().await.unwrap_or_default();

    // Update auth manager with fresh data
    let mut auth_manager = state.auth_manager.write().await;
    *auth_manager = crate::auth::AuthManager::from_data(stored_roles, stored_keys);

    Ok(())
}

/// API error response
#[derive(Serialize)]
struct ApiError {
    error: String,
    code: String,
}

impl ApiError {
    fn new(code: &str, error: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            error: error.into(),
        }
    }
}

fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(ApiError::new(code, message))).into_response()
}

// ============== Execute Request ==============

#[derive(Deserialize)]
pub struct ExecuteApiRequest {
    /// Credential alias to use
    pub credential: String,
    /// HTTP method
    pub method: String,
    /// Target URL
    pub url: String,
    /// Request headers (optional)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Request body (optional)
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Query parameters (optional)
    #[serde(default)]
    pub query: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct ExecuteApiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Resolve a bearer secret (API key `vk_` or use token `vut_`) into an
/// [`ExecAuth`]. A use token's credential/action scope is enforced
/// authoritatively in the server (`execute_gated`); here we only authenticate
/// and fail fast on an unusable token.
async fn resolve_exec_auth(state: &AppState, secret: &str) -> Result<ExecAuth, Response> {
    if UseToken::looks_like_token(secret) {
        let _ = state.storage.reload().await;
        let token = match state.storage.get_use_token_by_hash(&UseToken::hash(secret)).await {
            Ok(Some(t)) => t,
            _ => return Err(error_response(StatusCode::UNAUTHORIZED, "invalid_token", "Invalid use token")),
        };
        if let Err(e) = token.check_usable() {
            return Err(error_response(StatusCode::FORBIDDEN, "token_unusable", e.to_string()));
        }
        Ok(ExecAuth::from_use_token(token))
    } else {
        let (key, role) = match validate_api_key(state, secret).await {
            Ok(kr) => kr,
            Err(e) => return Err(error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", e)),
        };
        Ok(ExecAuth::from_api_key(AuthResult { api_key: key, role }))
    }
}

/// Authenticate a caller and return its principal id (without action scoping),
/// for read-only operations like polling an approval.
async fn resolve_caller_id(state: &AppState, secret: &str) -> Result<String, Response> {
    if UseToken::looks_like_token(secret) {
        let _ = state.storage.reload().await;
        match state.storage.get_use_token_by_hash(&UseToken::hash(secret)).await {
            // Polling is read-only, so an exhausted/expired token still
            // authenticates — but a revoked token is rejected.
            Ok(Some(t)) if !t.revoked => Ok(t.id),
            Ok(Some(_)) => Err(error_response(
                StatusCode::FORBIDDEN,
                "token_revoked",
                "Use token has been revoked",
            )),
            _ => Err(error_response(StatusCode::UNAUTHORIZED, "invalid_token", "Invalid use token")),
        }
    } else {
        match validate_api_key(state, secret).await {
            Ok((key, _role)) => Ok(key.id),
            Err(e) => Err(error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", e)),
        }
    }
}

/// Execute an authenticated HTTP request
pub async fn api_execute(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ExecuteApiRequest>,
) -> Response {
    // Extract bearer secret (API key or use token).
    let secret = match extract_api_key(&headers) {
        Some(key) => key,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_api_key",
                "Authorization header with Bearer token required",
            )
        }
    };

    let exec_auth = match resolve_exec_auth(&state, &secret).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Build the execute request
    let execute_request = ExecuteRequest {
        credential: request.credential,
        action: "http.request".to_string(),
        params: serde_json::json!({
            "method": request.method.to_uppercase(),
            "url": request.url,
            "headers": request.headers,
            "body": request.body,
            "query": request.query,
        }),
    };

    // Create a VultrinoServer to execute the request
    let resolver = CredentialResolver::new(state.storage.clone());
    let server = VultrinoServer::new(state.config.clone(), state.storage.clone(), resolver);

    // Load plugins
    if let Err(e) = server.load_plugins().await {
        tracing::warn!("Failed to load plugins: {}", e);
    }

    // Execute, gating on approval when required.
    match server.execute_gated(execute_request, exec_auth).await {
        Ok(ExecutionOutcome::Completed(response)) => {
            let body_str = String::from_utf8_lossy(&response.body).to_string();
            let headers: HashMap<String, String> = response
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            (
                StatusCode::OK,
                Json(ExecuteApiResponse {
                    status: response.status,
                    headers,
                    body: body_str,
                }),
            )
                .into_response()
        }
        Ok(ExecutionOutcome::Pending(approval)) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "outcome": "pending_approval",
                "approval_id": approval.id,
                "message": format!(
                    "This action requires human approval before it runs. It has NOT executed. \
                     Poll GET /api/v1/approvals/{} with your bearer token to retrieve the result \
                     once a human approves.",
                    approval.id
                ),
                "summary": approval.summary,
                "expires_at": approval.expires_at,
            })),
        )
            .into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, "execute_error", e.to_string()),
    }
}

/// Poll an approval request and, once approved, run the action and return its
/// result. The caller may only poll approvals it requested.
pub async fn api_check_approval(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let secret = match extract_api_key(&headers) {
        Some(key) => key,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_api_key",
                "Authorization header with Bearer token required",
            )
        }
    };

    let principal_id = match resolve_caller_id(&state, &secret).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let resolver = CredentialResolver::new(state.storage.clone());
    let server = VultrinoServer::new(state.config.clone(), state.storage.clone(), resolver);
    if let Err(e) = server.load_plugins().await {
        tracing::warn!("Failed to load plugins: {}", e);
    }

    // Ownership is enforced inside check_and_resume_approval BEFORE any
    // execution, so a non-owner can never trigger another principal's action.
    let approval = match server
        .check_and_resume_approval(&id, Some(&principal_id))
        .await
    {
        Ok(a) => a,
        Err(crate::VultrinoError::PolicyDenied(msg)) => {
            return error_response(StatusCode::FORBIDDEN, "not_authorized", msg)
        }
        Err(e) => return error_response(StatusCode::NOT_FOUND, "approval_not_found", e.to_string()),
    };

    let mut body = serde_json::json!({
        "approval_id": approval.id,
        "status": approval.status.to_string(),
        "summary": approval.summary,
        "executed": approval.executed,
    });
    // Per-status guidance, mirroring the MCP `check_approval` tool so the two
    // transports present the same contract to an agent.
    match approval.status {
        ApprovalStatus::Pending => {
            body["message"] = serde_json::json!(
                "Awaiting human approval. The action has NOT run. Poll this endpoint again \
                 every ~10-30 seconds with your bearer token."
            );
            body["expires_at"] = serde_json::json!(approval.expires_at);
        }
        ApprovalStatus::Denied => {
            body["message"] = serde_json::json!(
                "This approval was denied; the action did not run. Do not retry."
            );
            if let Some(note) = &approval.decision_note {
                body["decision_note"] = serde_json::json!(note);
            }
        }
        ApprovalStatus::Expired => {
            body["message"] = serde_json::json!(
                "This approval expired before a human decided; the action did not run. Submit a \
                 fresh request if you still need it."
            );
        }
        ApprovalStatus::Approved => {
            if !approval.executed {
                body["message"] = serde_json::json!(
                    "Approved; the action is being executed now. Poll again in ~10-30 seconds to \
                     get the result."
                );
            } else if let Some(err) = &approval.result_error {
                body["message"] = serde_json::json!("Approved, but the action failed to execute.");
                body["error"] = serde_json::json!(err);
            } else {
                body["message"] = serde_json::json!("Approved and executed.");
                body["result"] = serde_json::json!({
                    "status": approval.result_status,
                    "body": approval.result_body,
                });
            }
        }
    }

    (StatusCode::OK, Json(body)).into_response()
}

// ============== List Credentials ==============

#[derive(Serialize)]
pub struct CredentialInfo {
    pub alias: String,
    pub credential_type: String,
    pub description: Option<String>,
}

#[derive(Serialize)]
pub struct ListCredentialsResponse {
    pub credentials: Vec<CredentialInfo>,
}

/// List available credentials
pub async fn api_list_credentials(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Extract and validate API key
    let api_key = match extract_api_key(&headers) {
        Some(key) => key,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_api_key",
                "Authorization header with Bearer token required",
            )
        }
    };

    // Reload auth manager from storage to pick up any new keys
    let (key, role) = match validate_api_key(&state, &api_key).await {
        Ok((k, r)) => (k, r),
        Err(e) => {
            return error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", e)
        }
    };

    let auth_result = AuthResult {
        api_key: key,
        role: role.clone(),
    };

    // Check read permission
    if !auth_result.has_permission(Permission::Read) {
        return error_response(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "API key does not have 'read' permission",
        );
    }

    // List credentials
    let credentials = state.storage.list().await.unwrap_or_default();

    // Filter by scope and convert to API response
    let filtered: Vec<CredentialInfo> = credentials
        .into_iter()
        .filter(|c| auth_result.can_access_credential(&c.alias))
        .map(|c| CredentialInfo {
            alias: c.alias,
            credential_type: format!("{:?}", c.credential_type).to_lowercase(),
            description: c.metadata.get("description").cloned(),
        })
        .collect();

    (StatusCode::OK, Json(ListCredentialsResponse { credentials: filtered })).into_response()
}

// ============== Health Check ==============

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Health check endpoint (no auth required)
pub async fn api_health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_api_key_valid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer vk_test_key_123".parse().unwrap(),
        );

        let result = extract_api_key(&headers);
        assert_eq!(result, Some("vk_test_key_123".to_string()));
    }

    #[test]
    fn test_extract_api_key_missing() {
        let headers = axum::http::HeaderMap::new();
        let result = extract_api_key(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_api_key_invalid_format() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );

        let result = extract_api_key(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_api_key_no_token() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );

        let result = extract_api_key(&headers);
        assert_eq!(result, Some("".to_string()));
    }

    #[test]
    fn test_api_error_serialization() {
        let error = ApiError::new("test_code", "Test error message");
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"code\":\"test_code\""));
        assert!(json.contains("\"error\":\"Test error message\""));
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "ok".to_string(),
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
    }

    #[test]
    fn test_execute_request_deserialization() {
        let json = r#"{
            "credential": "github-api",
            "method": "GET",
            "url": "https://api.github.com/user"
        }"#;

        let request: ExecuteApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.credential, "github-api");
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://api.github.com/user");
        assert!(request.headers.is_empty());
        assert!(request.body.is_none());
    }

    #[test]
    fn test_execute_request_with_body() {
        let json = r#"{
            "credential": "stripe-api",
            "method": "POST",
            "url": "https://api.stripe.com/v1/customers",
            "headers": {"Content-Type": "application/json"},
            "body": {"email": "test@example.com"}
        }"#;

        let request: ExecuteApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.credential, "stripe-api");
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers.get("Content-Type"), Some(&"application/json".to_string()));
        assert!(request.body.is_some());
    }

    #[test]
    fn test_credential_info_serialization() {
        let info = CredentialInfo {
            alias: "test-cred".to_string(),
            credential_type: "api_key".to_string(),
            description: Some("Test credential".to_string()),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"alias\":\"test-cred\""));
        assert!(json.contains("\"credential_type\":\"api_key\""));
        assert!(json.contains("\"description\":\"Test credential\""));
    }

    #[test]
    fn test_list_credentials_response() {
        let response = ListCredentialsResponse {
            credentials: vec![
                CredentialInfo {
                    alias: "cred1".to_string(),
                    credential_type: "api_key".to_string(),
                    description: None,
                },
                CredentialInfo {
                    alias: "cred2".to_string(),
                    credential_type: "basic_auth".to_string(),
                    description: Some("Second cred".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"credentials\":["));
        assert!(json.contains("\"alias\":\"cred1\""));
        assert!(json.contains("\"alias\":\"cred2\""));
    }
}
