//! JSON API handlers with API key authentication
//!
//! These endpoints allow CLI and external applications to interact with
//! Vultrino using API keys instead of session-based authentication.

use axum::{
    extract::{FromRequestParts, Json, Path, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::approval::ApprovalStatus;
use crate::auth::{AuthResult, NewUseToken, Permission, UseToken, UseTokenMetadata};
use crate::server::ExecAuth;
use crate::{ExecuteRequest, ExecutionOutcome};

use super::server::AppState;

use crate::auth::ApiKey;
use crate::auth::{Role, ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY};
use crate::policy::{Policy, PolicyAction, PolicyRule};
use crate::storage::IdempotencyState;
use crate::{Credential, CredentialData, CredentialMetadata};
use chrono::Duration;
use sha2::{Digest, Sha256};

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

/// Resolve the `action` for a typed `/api/v1/execute` request (V8): an omitted
/// *or* explicitly blank action falls back to the default `http.request`, rather
/// than passing `""`/whitespace through to `parse_action`.
fn resolve_execute_action(action: Option<String>) -> String {
    action
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http.request".to_string())
}

#[derive(Deserialize)]
pub struct ExecuteApiRequest {
    /// Credential alias to use
    pub credential: String,
    /// Action to perform (V8): a canonical `plugin.action` or a govder action
    /// label. Defaults to `http.request` (the only action whose params this
    /// typed endpoint shapes); other actions are typically driven via MCP.
    #[serde(default)]
    pub action: Option<String>,
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

    // Build the execute request (action no longer hardcoded — V8).
    let execute_request = ExecuteRequest {
        credential: request.credential,
        action: resolve_execute_action(request.action),
        params: serde_json::json!({
            "method": request.method.to_uppercase(),
            "url": request.url,
            "headers": request.headers,
            "body": request.body,
            "query": request.query,
        }),
    };

    // Execute on the shared server (plugins already loaded), gating on approval.
    match state.server.execute_gated(execute_request, exec_auth).await {
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

    // Ownership is enforced inside check_and_resume_approval BEFORE any
    // execution, so a non-owner can never trigger another principal's action.
    let approval = match state
        .server
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
    // V12: surface dual-control (M-of-N) progress so the agent knows it's awaiting
    // additional distinct approvers, not stalled — only while still open (a denied
    // or expired request isn't "awaiting" anyone).
    let required = approval.effective_required_approvals();
    if required > 1 && approval.status.is_open() {
        body["required_approvals"] = serde_json::json!(required);
        body["approvals_received"] = serde_json::json!(approval.signoffs.len());
        body["approvals_remaining"] = serde_json::json!(approval.approvals_remaining());
    }
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
        ApprovalStatus::Escalated => {
            // V5: still awaiting a decision, now in the second (escalated) SLA
            // window. From the agent's side the contract is identical to Pending.
            body["message"] = serde_json::json!(
                "Still awaiting human approval (escalated to a second reviewer window). \
                 The action has NOT run. Keep polling every ~10-30 seconds."
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

    // Validate against the in-memory auth manager (refreshed from storage only
    // after key/role mutations via refresh_auth_data, not on every read).
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

// ============================================================================
// Admin API (V1) — runtime config-write surface for the enforcement plane.
//
// All endpoints require an API key (vk_) whose role holds `Permission::Admin`;
// use tokens are rejected outright. Mutations persist to storage and take effect
// on the next request without a restart. Creates/mints honor an optional
// `Idempotency-Key` header so a retried request never double-creates.
// ============================================================================

/// Extractor that authenticates an admin caller from request headers **before**
/// the request body is read. Placing it ahead of the `Json<T>` body extractor
/// ensures an unauthenticated request is rejected with 401/403 rather than a
/// 422 body-parse error (which would otherwise leak that auth wasn't checked
/// first and give inconsistent status codes).
pub struct AdminApiAuth(#[allow(dead_code)] pub AuthResult);

impl FromRequestParts<AppState> for AdminApiAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = require_admin(state, &parts.headers).await?;
        // Audit every authorized admin request with the acting key id and the
        // method/path, so admin mutations are traceable for forensics. (This is
        // structured tracing, not yet the tamper-evident ledger of F1/V12.)
        tracing::info!(
            caller_key_id = %auth.api_key.id,
            method = %parts.method,
            path = %parts.uri.path(),
            "admin API request authorized"
        );
        Ok(AdminApiAuth(auth))
    }
}

/// Authenticate an admin caller: an API key with `Permission::Admin`. Use tokens
/// can never reach the admin surface.
async fn require_admin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<AuthResult, Response> {
    let secret = extract_api_key(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "missing_api_key",
            "Authorization header with Bearer API key required",
        )
    })?;
    if UseToken::looks_like_token(&secret) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "not_admin",
            "Use tokens cannot access the admin API; an API key with 'admin' permission is required",
        ));
    }
    // Generic message — don't reveal whether the key was unknown vs. expired
    // vs. role-missing (avoid an enumeration oracle on the admin surface).
    let (key, role) = validate_api_key(state, &secret)
        .await
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", "Invalid API key"))?;
    let auth = AuthResult { api_key: key, role };
    if !auth.has_permission(Permission::Admin) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "API key does not have 'admin' permission",
        ));
    }
    Ok(auth)
}

/// Upper bound on a use-token lifetime accepted by the admin API (~10 years),
/// guarding `chrono::Duration::seconds` from an overflowing input.
const MAX_TOKEN_LIFETIME_SECS: i64 = 10 * 365 * 24 * 60 * 60;

/// Read the optional `Idempotency-Key` request header.
fn extract_idempotency_key(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
}

/// Rebuild a stored JSON response (status + body) for an idempotent replay.
fn replay_json(status: u16, body: String) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Stable hash of a request body, used to bind an `Idempotency-Key` to the
/// exact request it was first used with. Canonicalizes via `serde_json::Value`
/// first: its object map is a `BTreeMap` (default features), so keys serialize
/// in sorted order — a `HashMap` field (e.g. credential metadata) therefore
/// hashes deterministically across retries regardless of iteration order.
/// (These request types always serialize; the fallback is unreachable.)
fn idempotency_body_hash<T: Serialize>(req: &T) -> String {
    let canonical = serde_json::to_value(req)
        .and_then(|v| serde_json::to_vec(&v))
        .unwrap_or_default();
    // sha256 hex is always 64 chars, so this is never "" — even on the
    // (unreachable here) serialization failure it is sha256(b""). Every record's
    // body_hash is therefore non-empty, which the reserve/complete/mismatch
    // logic relies on (a "" stored hash could never equal a real request hash).
    hex::encode(Sha256::digest(&canonical))
}

/// The replay body persisted for an idempotent mint must never contain the
/// plaintext token (the vault must not retain it). Strip a top-level `token`
/// field, leaving a note; the live first response still returns the real token.
fn redact_for_replay(body: &serde_json::Value) -> serde_json::Value {
    let mut stored = body.clone();
    if let Some(obj) = stored.as_object_mut() {
        if obj.remove("token").is_some() {
            obj.insert("token".to_string(), serde_json::Value::Null);
            // The "shown only once" warning no longer applies to a replay.
            obj.remove("warning");
            obj.insert(
                "token_note".to_string(),
                serde_json::json!(
                    "The plaintext token is only returned on the original request and is not \
                     retained. If you lost it, revoke this token and mint a new one."
                ),
            );
        }
    }
    stored
}

/// Run an admin mutation under optional `Idempotency-Key` dedup, bound to
/// `body_hash`. On a repeated key with the same body it replays the stored 2xx
/// response (409 while in flight, 409 on a body mismatch); non-success responses
/// release the reservation so the client can retry.
///
/// **Crash semantics:** the reserve → operate → complete sequence is three
/// separate atomic storage writes, not one transaction. If the process crashes
/// after the operation persists but before completion is recorded, a retry after
/// the stale-reservation window re-runs the operation (at-least-once, not
/// exactly-once). True exactly-once would require transactional storage.
async fn idempotent<F, Fut>(
    state: &AppState,
    key: Option<String>,
    body_hash: String,
    op: F,
) -> Response
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = (StatusCode, serde_json::Value)>,
{
    let Some(key) = key else {
        let (status, body) = op().await;
        return (status, Json(body)).into_response();
    };
    match state.storage.idempotency_check_or_reserve(&key, &body_hash).await {
        Ok(IdempotencyState::Done { status, body }) => return replay_json(status, body),
        Ok(IdempotencyState::Pending) => {
            return error_response(
                StatusCode::CONFLICT,
                "idempotency_in_progress",
                "A request with this Idempotency-Key is already in progress",
            )
        }
        Ok(IdempotencyState::Mismatch) => {
            return error_response(
                StatusCode::CONFLICT,
                "idempotency_key_reused",
                "This Idempotency-Key was already used with a different request body",
            )
        }
        Ok(IdempotencyState::Fresh) => {}
        Err(e) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string())
        }
    }
    let (status, body) = op().await;
    if status.is_success() {
        let body_str = serde_json::to_string(&redact_for_replay(&body)).unwrap_or_default();
        if let Err(e) = state.storage.idempotency_complete(&key, &body_hash, status.as_u16(), &body_str).await {
            // Completion not recorded → a retry may re-run the op (at-least-once).
            tracing::warn!(error = %e, idempotency_key = %key, "failed to record idempotency completion");
        }
    } else {
        // Don't pin a failed attempt to the key — let the client retry it.
        if let Err(e) = state.storage.idempotency_release(&key).await {
            tracing::warn!(error = %e, idempotency_key = %key, "failed to release idempotency reservation");
        }
    }
    (status, Json(body)).into_response()
}

// -------- Policies --------

/// Body for creating/replacing a policy. On `POST` the id is always
/// server-generated (create); on `PUT` the path id is used (create-or-replace).
#[derive(Serialize, Deserialize)]
pub struct PolicyUpsertRequest {
    pub name: String,
    pub credential_pattern: String,
    /// Optional principal glob (V4) — e.g. a per-agent Deny (kill-leg W3) is
    /// `POST /policies` with `principal_pattern` set to the agent label.
    #[serde(default)]
    pub principal_pattern: Option<String>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyAction,
}

/// Build a validated `Policy` from a request, forcing the id on PUT or
/// generating a fresh one on POST.
fn build_policy(req: PolicyUpsertRequest, forced_id: Option<String>) -> Result<Policy, String> {
    if req.name.trim().is_empty() {
        return Err("policy name must not be empty".to_string());
    }
    // Fail loud on a credential_pattern that doesn't compile, rather than
    // storing a policy whose glob silently degrades to never matching.
    glob::Pattern::new(&req.credential_pattern)
        .map_err(|e| format!("invalid credential_pattern '{}': {}", req.credential_pattern, e))?;
    // Use the builder so new optional Policy fields get their defaults.
    let mut policy = Policy::deny_all(req.name, req.credential_pattern);
    policy.id = forced_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    policy.principal_pattern = req.principal_pattern;
    policy.default_action = req.default_action;
    policy.rules = req.rules;
    // Reject misconfigured spend caps (nested / no caps / not fail-closed).
    policy.validate()?;
    Ok(policy)
}

/// Persist a policy and hot-reload the engine, returning the canonical object.
async fn store_and_reload_policy(state: &AppState, policy: &Policy, created: bool) -> (StatusCode, serde_json::Value) {
    if let Err(e) = state.storage.store_policy(policy).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"code": "storage_error", "error": e.to_string()}),
        );
    }
    if let Err(e) = state.server.reload_policies().await {
        // The policy persisted but the live engine didn't pick it up. For a deny
        // policy this is a fail-open window, so keep storage and the engine
        // consistent: roll back a fresh create; a replace can't restore the
        // prior version, so surface that the change is stored-but-not-active.
        tracing::error!(error = %e, policy_id = %policy.id, created, "policy stored but engine reload failed");
        if created {
            let _ = state.storage.delete_policy(&policy.id).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"code": "reload_error", "error": format!("engine reload failed; the new policy was rolled back: {}", e)}),
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"code": "reload_error", "error": format!("policy stored but the immediate engine reload failed; it will be applied within the policy refresh window (~{}s): {}", crate::server::POLICY_REFRESH_SECS, e)}),
        );
    }
    // V9: emit a policy-change event to the signed outbox.
    state
        .server
        .emit_event(
            &policy.id,
            crate::outbox::EVENT_POLICY_CHANGED,
            serde_json::json!({
                "policy_id": policy.id,
                "name": policy.name,
                "credential_pattern": policy.credential_pattern,
                "change": if created { "created" } else { "replaced" },
            }),
        )
        .await;
    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    (status, serde_json::to_value(policy).unwrap_or_default())
}

/// `POST /api/v1/policies` — create a policy (id generated if omitted).
pub async fn api_create_policy(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PolicyUpsertRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        match build_policy(req, None) {
            Ok(policy) => store_and_reload_policy(&st, &policy, true).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_policy", "error": e}),
            ),
        }
    })
    .await
}

/// `PUT /api/v1/policies/{id}` — create or replace the policy with this id.
pub async fn api_put_policy(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PolicyUpsertRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    // Bind the hash to the path id, so the same body PUT to a *different* id
    // under the same Idempotency-Key isn't replayed as the first id's result.
    let body_hash = idempotency_body_hash(&(id.as_str(), &req));
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        match build_policy(req, Some(id)) {
            Ok(policy) => store_and_reload_policy(&st, &policy, false).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_policy", "error": e}),
            ),
        }
    })
    .await
}

/// `DELETE /api/v1/policies/{id}` — remove a stored (admin-managed) policy.
pub async fn api_delete_policy(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.storage.delete_policy(&id).await {
        Ok(()) => {
            if let Err(e) = state.server.reload_policies().await {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "reload_error", e.to_string());
            }
            (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response()
        }
        Err(crate::storage::StorageError::PolicyNotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "policy_not_found", format!("No stored policy with id '{}'", id))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

// -------- Use tokens --------

#[derive(Serialize, Deserialize)]
pub struct TokenCreateRequest {
    pub name: String,
    pub credential_scope: String,
    #[serde(default)]
    pub action_scope: Option<String>,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub require_approval: bool,
    /// Lifetime in seconds from now (optional).
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
    /// Optional agent identity to bind this token to (V4), so a policy's
    /// `principal_pattern` can target this one agent.
    #[serde(default)]
    pub agent_label: Option<String>,
    /// Optional strictness (V8) that compiles to enforced settings:
    /// `direct` = single-use + require_approval + dual_control; `checkpoint` =
    /// require_approval (multi-use). Overrides max_uses/require_approval.
    #[serde(default)]
    pub strictness: Option<String>,
    /// Optional human/directory owner of this NHI (V10): the IdP-resolvable owner
    /// (OIDC `sub` / SCIM id), so this `vut_` maps to a directory identity for
    /// separation-of-duty and audit.
    #[serde(default)]
    pub owner_identity: Option<String>,
    /// Optional tenant/team this token belongs to (V11).
    #[serde(default)]
    pub tenant: Option<String>,
}

/// `POST /api/v1/tokens` — mint a use token; the plaintext is returned once.
pub async fn api_create_token(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TokenCreateRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        // Bound the raw seconds before converting, so a huge value can't panic
        // chrono's Duration::seconds (admin-triggerable). NewUseToken::validate
        // also rejects a non-positive lifetime as a second guard.
        let expires_in = match req.expires_in_secs {
            None => None,
            Some(v) if (1..=MAX_TOKEN_LIFETIME_SECS).contains(&v) => Some(Duration::seconds(v)),
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": "invalid_token", "error": "expires_in_secs must be between 1 and ~10 years"}),
                );
            }
        };
        // Compile strictness (V8) into enforced settings. `direct` is single-use
        // + approval + dual-control; `checkpoint` is approval + multi-use.
        let (max_uses, require_approval, dual_control) = match req.strictness.as_deref() {
            None => (req.max_uses, req.require_approval, false),
            Some("direct") => (Some(1), true, true),
            Some("checkpoint") => (req.max_uses, true, false),
            Some(other) => {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": "invalid_strictness", "error": format!("unknown strictness '{}' (expected 'direct' or 'checkpoint')", other)}),
                );
            }
        };
        let params = NewUseToken {
            name: req.name,
            credential_scope: req.credential_scope,
            action_scope: req.action_scope,
            max_uses,
            require_approval,
            expires_in,
        };
        if let Err(e) = params.validate() {
            return (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_token", "error": e}),
            );
        }
        // Validate the agent label against the centralized allowlist (feeds
        // principal_pattern glob matching and the spend-ledger key).
        if let Some(label) = &req.agent_label {
            if let Err(e) = crate::auth::validate_agent_label(label) {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": "invalid_agent_label", "error": e}),
                );
            }
        }
        let (full_token, mut token) = UseToken::create(params);
        // Bind the agent identity (V4), dual-control flag (V8), and human owner
        // (V10) post-create; these fields are not moved into `params` above.
        token.agent_label = req.agent_label;
        token.dual_control = dual_control;
        token.owner_identity =
            req.owner_identity.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        token.tenant = req.tenant.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if let Err(e) = st.storage.store_use_token(&token).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"code": "storage_error", "error": e.to_string()}),
            );
        }
        (
            StatusCode::CREATED,
            serde_json::json!({
                "token": full_token,
                "warning": "This is the only time the token is shown. Store it securely.",
                "metadata": UseTokenMetadata::from(&token),
            }),
        )
    })
    .await
}

/// `POST /api/v1/tokens/{id}/revoke` — revoke a use token.
pub async fn api_revoke_token(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.storage.set_use_token_revoked(&id).await {
        Ok(token) => (StatusCode::OK, Json(serde_json::json!({
            "revoked": true,
            "metadata": UseTokenMetadata::from(&token),
        })))
            .into_response(),
        Err(crate::storage::StorageError::UseTokenNotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "token_not_found", format!("No use token with id '{}'", id))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

// -------- Agent halt / sessions (V6) --------

/// `POST /api/v1/agents/{label}/halt` — kill switch for an agent: revoke its use
/// tokens, install an authoritative per-agent kill policy, and fire abort
/// callbacks for its in-flight sessions. Idempotent under the storage lock.
pub async fn api_halt_agent(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(label): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&label);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        match st.server.halt_agent(&label).await {
            Ok(outcome) => (StatusCode::OK, serde_json::to_value(outcome).unwrap_or_default()),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "halt_failed", "error": e.to_string()}),
            ),
        }
    })
    .await
}

/// `DELETE /api/v1/agents/{label}/halt` — lift a halt (remove the kill policy).
/// Already-revoked tokens stay revoked.
pub async fn api_unhalt_agent(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(label): Path<String>,
) -> Response {
    match state.server.unhalt_agent(&label).await {
        Ok(removed) => (
            StatusCode::OK,
            Json(serde_json::json!({ "agent_label": label, "halt_lifted": removed })),
        )
            .into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, "unhalt_failed", e.to_string()),
    }
}

/// `GET /api/v1/sessions` — the in-flight execution registry for **this process**
/// (per-process and in-memory, like the rate-limit/spend ledgers).
pub async fn api_list_sessions(_admin: AdminApiAuth, State(state): State<AppState>) -> Response {
    let sessions = state.server.sessions().list();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "sessions": sessions, "process_scope": true })),
    )
        .into_response()
}

// -------- Metrics read-back (V12) --------

/// `GET /api/v1/metrics` — structured read-back of the metrics govder computes
/// (V12): unauthorized-tool-call attempts, approval counts by state, and approval
/// latency percentiles. Per-process, point-in-time (the event stream — the signed
/// outbox — is the durable history).
pub async fn api_metrics(_admin: AdminApiAuth, State(state): State<AppState>) -> Response {
    let approvals = state.storage.list_approvals().await.unwrap_or_default();

    let mut by_status: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut latencies_secs: Vec<i64> = Vec::new();
    let mut dual_control_awaiting = 0u64;
    for a in &approvals {
        *by_status.entry(a.status.to_string()).or_default() += 1;
        // Decision latency for decided requests (approved or denied).
        if let Some(decided) = a.decided_at {
            if matches!(a.status, ApprovalStatus::Approved | ApprovalStatus::Denied) {
                latencies_secs.push((decided - a.created_at).num_seconds().max(0));
            }
        }
        if a.effective_required_approvals() > 1 && a.status.is_open() {
            dual_control_awaiting += 1;
        }
    }
    latencies_secs.sort_unstable();
    let pct = |p: f64| -> Option<i64> {
        if latencies_secs.is_empty() {
            return None;
        }
        // Nearest-rank percentile.
        let idx = (((p / 100.0) * latencies_secs.len() as f64).ceil() as usize)
            .saturating_sub(1)
            .min(latencies_secs.len() - 1);
        Some(latencies_secs[idx])
    };
    let avg = if latencies_secs.is_empty() {
        None
    } else {
        Some(latencies_secs.iter().sum::<i64>() / latencies_secs.len() as i64)
    };

    let body = serde_json::json!({
        "unauthorized_attempts": state.server.unauthorized_attempts(),
        "approvals": {
            "total": approvals.len(),
            "by_status": by_status,
            "dual_control_awaiting": dual_control_awaiting,
        },
        "approval_latency_secs": {
            "count": latencies_secs.len(),
            "avg": avg,
            "p50": pct(50.0),
            "p95": pct(95.0),
            "max": latencies_secs.last().copied(),
        },
    });
    (StatusCode::OK, Json(body)).into_response()
}

// -------- Event outbox replay (V9) --------

/// Query for the event replay cursor.
#[derive(Deserialize)]
pub struct EventsQuery {
    /// Return events with `sequence > after` (the consumer's last-seen cursor).
    #[serde(default)]
    pub after: u64,
    /// Max events to return (default 100, capped at 1000).
    pub limit: Option<usize>,
}

/// `GET /api/v1/events?after=N&limit=M` — replay events strictly after a cursor,
/// in monotonic sequence order, gap-free (V9). A consumer that dropped offline
/// resumes from its last-seen `sequence` with no gaps and no dupes.
pub async fn api_list_events(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(100).min(1000);
    match state.storage.list_events_after(q.after, limit).await {
        Ok(events) => {
            // The next cursor is the highest sequence returned (or the request's
            // `after` if none) — what the consumer persists for the next poll.
            let next = events.last().map(|e| e.sequence).unwrap_or(q.after);
            // Return the same envelope a pushed delivery carries (so a consumer
            // processes replayed and pushed events identically), and — when a
            // signing secret is configured — the matching `Govder-Signature` over
            // each body, so a replayed event is verifiable exactly like a pushed one.
            let secret = state.config.outbox.hmac_secret.as_deref();
            let bodies: Vec<serde_json::Value> = events
                .iter()
                .map(|e| {
                    let body = e.delivery_body();
                    match secret {
                        Some(s) => {
                            let bytes = serde_json::to_vec(&body).unwrap_or_default();
                            serde_json::json!({ "body": body, "signature": crate::outbox::sign_body(s, &bytes) })
                        }
                        None => serde_json::json!({ "body": body }),
                    }
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "events": bodies, "next_cursor": next })),
            )
                .into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

/// `GET /api/v1/events/dead` — the dead-letter queue (events that exhausted their
/// delivery retries) (V9).
pub async fn api_list_dead_letters(_admin: AdminApiAuth, State(state): State<AppState>) -> Response {
    match state.storage.list_dead_letter_events(1000).await {
        Ok(events) => (StatusCode::OK, Json(serde_json::json!({ "dead_letters": events }))).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

/// `POST /api/v1/events/{sequence}/replay` — requeue a dead-lettered event for
/// re-delivery (V9).
pub async fn api_replay_dead_letter(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(sequence): Path<u64>,
) -> Response {
    match state.storage.replay_dead_letter_event(sequence).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "requeued": true, "sequence": sequence }))).into_response(),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            "not_dead_lettered",
            format!("no dead-lettered event with sequence {sequence}"),
        ),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

// -------- Roles --------

#[derive(Serialize, Deserialize)]
pub struct RoleCreateRequest {
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub credential_scopes: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /api/v1/roles` — create a role.
pub async fn api_create_role(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RoleCreateRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        if req.name.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, serde_json::json!({"code":"invalid_role","error":"role name must not be empty"}));
        }
        let mut perms = std::collections::HashSet::new();
        for p in &req.permissions {
            match Permission::parse(p) {
                Some(perm) => {
                    perms.insert(perm);
                }
                None => {
                    return (StatusCode::BAD_REQUEST, serde_json::json!({"code":"invalid_permission","error":format!("unknown permission '{}'", p)}));
                }
            }
        }
        let mut role = Role::new(req.name, perms).with_scopes(req.credential_scopes);
        if let Some(desc) = req.description {
            role = role.with_description(desc);
        }
        // store_role enforces name uniqueness atomically under the storage lock,
        // so two concurrent creates with the same name can't both succeed (no
        // TOCTOU): the loser gets RoleAlreadyExists → 409.
        match st.storage.store_role(&role).await {
            Ok(()) => {}
            Err(crate::storage::StorageError::RoleAlreadyExists(_)) => {
                return (StatusCode::CONFLICT, serde_json::json!({"code":"role_exists","error":format!("a role named '{}' already exists", role.name)}));
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({"code":"storage_error","error":e.to_string()}));
            }
        }
        // Make the new role visible to this process's auth manager immediately.
        let _ = refresh_auth_data(&st).await;
        (StatusCode::CREATED, serde_json::to_value(&role).unwrap_or_default())
    })
    .await
}

/// `DELETE /api/v1/roles/{id}` — delete a custom role.
pub async fn api_delete_role(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    // Never delete a predefined role (consistency with the web UI and CLI guards).
    if matches!(id.as_str(), ROLE_ADMIN | ROLE_READ_ONLY | ROLE_EXECUTOR) {
        return error_response(
            StatusCode::FORBIDDEN,
            "predefined_role",
            "Predefined roles (admin, read-only, executor) cannot be deleted",
        );
    }
    // Referential integrity + delete in one atomic storage op, so a key minted
    // concurrently referencing this role can't be orphaned.
    match state.storage.delete_role_if_unreferenced(&id).await {
        Ok(()) => {
            let _ = refresh_auth_data(&state).await;
            (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response()
        }
        Err(crate::storage::StorageError::Conflict(msg)) => {
            error_response(StatusCode::CONFLICT, "role_in_use", msg)
        }
        Err(crate::storage::StorageError::RoleNotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "role_not_found", format!("No role with id '{}'", id))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

// -------- Credentials (metadata; secret material is write-only) --------

#[derive(Serialize, Deserialize)]
pub struct CredentialCreateRequest {
    pub alias: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Tagged credential data (e.g. {"type":"api_key","key":"...",...}). Stored
    /// encrypted; never returned by any endpoint.
    pub data: CredentialData,
}

/// `POST /api/v1/credentials` — store a credential. The response carries only
/// metadata; the secret material is never echoed back.
pub async fn api_create_credential(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CredentialCreateRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        if req.alias.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, serde_json::json!({"code":"invalid_credential","error":"alias must not be empty"}));
        }
        let mut cred = Credential::new(req.alias, req.data);
        cred.metadata = req.metadata;
        // Warn if a secret is below the egress redaction floor: its reflection
        // would not be auto-scrubbed (use an egress `block` rule for it).
        if crate::egress::has_unredactable_secret(&cred.data.secret_material()) {
            tracing::warn!(
                credential = %cred.alias,
                "credential has a secret shorter than the egress redaction floor; a reflected \
                 copy would not be auto-redacted — consider an [[egress]] block rule"
            );
        }
        if let Err(e) = st.storage.store(&cred).await {
            // Duplicate alias is a client error, not a 500.
            if let crate::storage::StorageError::AlreadyExists(_) = e {
                return (StatusCode::CONFLICT, serde_json::json!({"code":"credential_exists","error":e.to_string()}));
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({"code":"storage_error","error":e.to_string()}));
        }
        // Return metadata only — never the secret.
        (StatusCode::CREATED, serde_json::to_value(CredentialMetadata::from(&cred)).unwrap_or_default())
    })
    .await
}

/// `DELETE /api/v1/credentials/{id}` — delete a credential by id.
pub async fn api_delete_credential(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.storage.delete(&id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response(),
        Err(crate::storage::StorageError::NotFound(_)) => {
            error_response(StatusCode::NOT_FOUND, "credential_not_found", format!("No credential with id '{}'", id))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_execute_action_defaults() {
        // Omitted, empty, and whitespace-only all fall back to the default.
        assert_eq!(resolve_execute_action(None), "http.request");
        assert_eq!(resolve_execute_action(Some(String::new())), "http.request");
        assert_eq!(resolve_execute_action(Some("   ".to_string())), "http.request");
        // A real action (canonical or label) is preserved verbatim.
        assert_eq!(resolve_execute_action(Some("postgres.run_sql".to_string())), "postgres.run_sql");
        assert_eq!(resolve_execute_action(Some("payments.refund".to_string())), "payments.refund");
    }

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
