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
use crate::auth::{
    ApprovalToken, ApprovalTokenMetadata, AuthResult, NewApprovalToken, NewUseToken, Permission,
    UseToken, UseTokenMetadata,
};
use crate::server::ExecAuth;
use crate::{ExecuteRequest, ExecutionOutcome};

use super::server::AppState;

use crate::auth::ApiKey;
use crate::auth::{Role, ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY};
use crate::capability::{Capability, CapabilityMetadata, CapabilityTarget};
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
    state
        .storage
        .reload()
        .await
        .map_err(|e| format!("Failed to reload storage: {}", e))?;

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
        let token = match state
            .storage
            .get_use_token_by_hash(&UseToken::hash(secret))
            .await
        {
            Ok(Some(t)) => t,
            _ => {
                return Err(error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Invalid use token",
                ))
            }
        };
        if let Err(e) = token.check_usable() {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "token_unusable",
                e.to_string(),
            ));
        }
        Ok(ExecAuth::from_use_token(token))
    } else {
        let (key, role) = match validate_api_key(state, secret).await {
            Ok(kr) => kr,
            Err(e) => {
                return Err(error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_api_key",
                    e,
                ))
            }
        };
        Ok(ExecAuth::from_api_key(AuthResult { api_key: key, role }))
    }
}

/// V10/R6: resolve an inbound workload identity from the request, if a resolver
/// is wired and the request carries its configured header (an already
/// transport-verified SVID/OIDC document). The deployment is responsible for
/// terminating mTLS / verifying the token at the edge and passing the verified
/// document in that header. Returns `None` when not configured/present/valid, in
/// which case the caller keeps its static `vk_`/`vut_` principal (fail-safe — a
/// bad document can only fail to refine the principal, never elevate it).
fn resolve_inbound_principal(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<crate::identity::WorkloadIdentity> {
    let header_name = state.server.identity_header()?;
    let value = headers.get(header_name)?.to_str().ok()?;
    state.server.resolve_identity(value)
}

/// Authenticate a caller and return its principal id (without action scoping),
/// for read-only operations like polling an approval.
async fn resolve_caller_id(state: &AppState, secret: &str) -> Result<String, Response> {
    if UseToken::looks_like_token(secret) {
        let _ = state.storage.reload().await;
        match state
            .storage
            .get_use_token_by_hash(&UseToken::hash(secret))
            .await
        {
            // Polling is read-only, so an exhausted/expired token still
            // authenticates — but a revoked token is rejected.
            Ok(Some(t)) if !t.revoked => Ok(t.id),
            Ok(Some(_)) => Err(error_response(
                StatusCode::FORBIDDEN,
                "token_revoked",
                "Use token has been revoked",
            )),
            _ => Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid use token",
            )),
        }
    } else {
        match validate_api_key(state, secret).await {
            Ok((key, _role)) => Ok(key.id),
            Err(e) => Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_api_key",
                e,
            )),
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

    let mut exec_auth = match resolve_exec_auth(&state, &secret).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // V10/R6: if a verified workload-identity document was presented inbound,
    // resolve it and refine the principal evaluated by policy — the subject is
    // carried as an ADDITIONAL match dimension (workload_id), and the owner binds
    // for SoD. The static vk_/vut_ id is deliberately preserved as the halt /
    // ownership anchor, so a halt keyed on it can never be escaped by presenting a
    // workload identity (and a policy/halt can still target the SVID via the
    // resolved subject).
    if let Some(identity) = resolve_inbound_principal(&state, &headers) {
        if let Some(auth) = exec_auth.auth.as_mut() {
            auth.api_key.workload_id = Some(identity.subject);
            if identity.owner.is_some() {
                auth.api_key.owner_identity = identity.owner;
            }
        }
    }

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
    // R6: ownership keys on the credential id (the halt/ownership anchor), NOT the
    // resolved workload identity — so the open and poll sides agree regardless of
    // whether the SVID header is re-presented on the poll. The resolved identity
    // only refines policy matching (snapshotted on the approval for resume re-eval).

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
        Err(e) => {
            return error_response(StatusCode::NOT_FOUND, "approval_not_found", e.to_string())
        }
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

// ============================================================================
// Approvals JSON API (A3/A4) — the admin-key surface a product aggregator drives
// to render the approvals inbox and record human decisions. Distinct from the
// HTML console (session+CSRF) and from `api_check_approval` (the agent's own
// poll-by-id). Both endpoints below authenticate with an admin `vk_` and are
// **tenant-partitioned** via the acting key's tenant — the aggregator's per-tenant
// admin key can only ever see and decide its own tenant's (and untenanted/shared)
// approvals, exactly like `api_metrics`.
// ============================================================================

/// One approval projected for the JSON list/decision API. Field semantics mirror
/// `ApprovalDisplay::from` (the HTML projection) so the two surfaces agree, but
/// this is a deliberately reduced, machine-friendly shape: ISO-8601 timestamps
/// (not the panel's pretty-printed strings) and no internal-only fields
/// (params/decision-token/execution-claim bookkeeping are withheld).
#[derive(Serialize)]
pub struct ApprovalSummary {
    /// `appr_<uuid>` — the id A4 decides with.
    pub id: String,
    /// Lifecycle state: `pending` | `escalated` | `approved` | `denied` | `expired`.
    pub status: String,
    /// Human one-liner describing the gated action.
    pub summary: String,
    /// Business-verb label (V8) when present, else the canonical `plugin.action`.
    pub action: String,
    /// Credential alias the action would use.
    pub credential: String,
    /// Agent label of the requesting principal, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    /// Short description of who requested it (e.g. `api key "deploy-agent"`).
    pub requested_by: String,
    /// RFC-3339 / ISO-8601 creation time.
    pub created_at: String,
    /// RFC-3339 / ISO-8601 final deadline.
    pub expires_at: String,
    /// Distinct approvers required before the action runs (1 = single approval).
    pub required_approvals: u32,
    /// Distinct approvals recorded so far.
    pub approvals_received: u32,
    /// Whether the request is still open (pending/escalated) and within its TTL —
    /// i.e. a decision can still be recorded.
    pub is_open: bool,
    /// Tenant this approval belongs to (snapshotted at open from the requesting
    /// principal's tenant); `null` = untenanted (shared, visible to every admin).
    /// Always emitted so a downstream aggregator (muntin) can backstop-filter by
    /// tenant as defense-in-depth — an explicit `null` unambiguously means
    /// "untenanted/shared", which an omitted field could not distinguish.
    pub tenant: Option<String>,
    /// `human` or `delegate-agent` when a terminal decision was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_kind: Option<String>,
    /// Govder DelegationGrant id when decided by a delegate agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_grant_ref: Option<String>,
    /// Channel / identity that decided the approval (human panel, delegate-agent, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub veto_until: Option<String>,
}

impl From<&crate::approval::ApprovalRequest> for ApprovalSummary {
    fn from(a: &crate::approval::ApprovalRequest) -> Self {
        let last = a.signoffs.last();
        ApprovalSummary {
            id: a.id.clone(),
            status: a.status.to_string(),
            summary: a.summary.clone(),
            // Same display precedence as ApprovalDisplay: the business verb when
            // present, otherwise the canonical action.
            action: a.action_label.clone().unwrap_or_else(|| a.action.clone()),
            credential: a.credential.clone(),
            agent_label: a.agent_label.clone(),
            requested_by: a.requester.describe(),
            created_at: a.created_at.to_rfc3339(),
            expires_at: a.expires_at.to_rfc3339(),
            required_approvals: a.effective_required_approvals(),
            approvals_received: a.signoffs.len() as u32,
            is_open: a.status.is_open() && !a.is_past_ttl(),
            tenant: a.tenant.clone(),
            approver_kind: last.map(|s| s.approver_kind.clone()).or_else(|| {
                if a.status.is_open() {
                    None
                } else {
                    a.decided_by.as_ref().map(|_| "human".to_string())
                }
            }),
            delegation_grant_ref: last.and_then(|s| s.delegation_grant_ref.clone()).or(None),
            // The product field answers WHO, not which transport channel handled
            // the decision. The channel remains on the underlying signoff/event.
            decided_by: last
                .map(|s| s.approver_identity.clone())
                .or_else(|| a.approver_identity.clone())
                .or_else(|| a.decided_by.clone()),
            veto_until: a.delegate_veto_until.map(|t| t.to_rfc3339()),
        }
    }
}

/// Optional query filter for the approvals list.
#[derive(Deserialize)]
pub struct ApprovalsQuery {
    /// Filter by lifecycle status (`pending` | `escalated` | `approved` |
    /// `denied` | `expired`). Omitted → all. `pending` matches only Pending
    /// (use no filter, or the explicit status, for escalated/decided requests).
    #[serde(default)]
    pub status: Option<String>,
}

/// Maximum approvals returned by a single `GET /api/v1/approvals` response. The
/// list is sorted (pending first, then newest) BEFORE truncating, so the cap
/// keeps the most relevant rows; the response carries `truncated: true` when more
/// exist. A hard upper bound on body size / memory until the API grows real
/// pagination.
const MAX_APPROVALS_LIST: usize = 500;

/// Sentinel operator recorded when the aggregator supplies no `approver` on a JSON
/// decision, so the identity is STILL namespaced as `agg:<key-id>:-` (never the
/// bare key id). This keeps every signoff from one key under the same
/// `agg:<key-id>:` prefix the same-key M-of-N guards key on. `-` can't be a real
/// operator (no owner email is `-`), so it never collides with a requester
/// identity in the self-approval SoD check.
const NO_OPERATOR_SENTINEL: &str = "-";

/// Require the acting admin key to be tenant-scoped on the product-aggregator
/// approvals surface, returning its tenant. A `None`-tenant key is a global
/// admin — a deliberately SEPARATE surface (the HTML console), not this one — so
/// it is rejected with a flat 403 rather than being silently treated as the
/// untenanted partition (which would let a global key drive the per-tenant JSON
/// API). The error reveals nothing about any approval's existence.
// `async` to match the sibling auth helpers (`require_admin` / `resolve_caller_id`):
// an `async fn`'s immediate return type is `impl Future<Output = Result<..>>`, not
// the `Result` itself, so clippy's `result_large_err` (which inspects the immediate
// return type) does not fire on it — keeping the shared "return a Response on error"
// idiom without boxing or an explicit allow.
async fn require_tenant_scoped(admin: &AdminApiAuth) -> Result<&str, Response> {
    admin.0.api_key.tenant.as_deref().ok_or_else(|| {
        error_response(
            StatusCode::FORBIDDEN,
            "tenant_required",
            "This endpoint requires a tenant-scoped admin key; a global (untenanted) \
             key must use the admin console instead.",
        )
    })
}

/// `GET /api/v1/approvals` — list approvals visible to the acting admin's tenant
/// (A3). Admin-gated; tenant-partitioned by the SAME verb the HTML list and
/// `api_metrics` use (`list_approvals_for_tenant`), so vultrino enforces the
/// per-tenant `visible_to_tenant` partition. Pending first, then most recent —
/// matching the panel's ordering. Optional `?status=` filter.
pub async fn api_list_approvals(
    admin: AdminApiAuth,
    State(state): State<AppState>,
    Query(q): Query<ApprovalsQuery>,
) -> Response {
    // SECURITY: this is the per-tenant product-aggregator surface. A key whose
    // tenant is None is a GLOBAL-authority admin — passed to
    // list_approvals_for_tenant(None) it would return the UNTENANTED partition
    // only, but the contract of this route is "the aggregator's own tenant", so a
    // global key has no legitimate use here. Reject it with a flat 403 (a clear
    // error, no enumeration oracle) and steer it to the global HTML console.
    let acting_tenant = match require_tenant_scoped(&admin).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // Reload so the in-memory cache reflects decisions/lifecycle transitions
    // committed by other processes (mirrors the HTML list + api_check_approval).
    // A backend failure must surface as a 5xx, never a misleading empty 200 — an
    // aggregator would read {approvals:[]} as "nothing to review" (a fail-open
    // inbox) when in fact the store was unreadable.
    if let Err(e) = state.storage.reload().await {
        tracing::error!(error = %e, "approvals list: storage reload failed");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "Failed to load approvals",
        );
    }
    let mut approvals = match state
        .server
        .list_approvals_for_tenant(Some(acting_tenant))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "approvals list: backend list failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "Failed to load approvals",
            );
        }
    };
    // Optional status filter (cheap, in-memory). An unrecognized value matches
    // nothing rather than erroring — the contract is "filter to this status".
    if let Some(status) = q.status.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let want = status.to_ascii_lowercase();
        approvals.retain(|a| a.status.to_string() == want);
    }
    // Pending first, then most recent — same ordering as the admin panel list.
    approvals.sort_by(|a, b| {
        let pending = |s: &ApprovalStatus| *s == ApprovalStatus::Pending;
        pending(&b.status)
            .cmp(&pending(&a.status))
            .then(b.created_at.cmp(&a.created_at))
    });
    // Bound the response so a tenant with a huge backlog can't return an
    // unbounded body (memory + latency). We sort BEFORE truncating, so the cap
    // keeps the most relevant rows (pending first, then newest). `truncated` tells
    // the aggregator there are more than were returned (it should narrow by
    // ?status= or page through as the API grows pagination).
    let total = approvals.len();
    let truncated = total > MAX_APPROVALS_LIST;
    approvals.truncate(MAX_APPROVALS_LIST);
    let items: Vec<ApprovalSummary> = approvals.iter().map(ApprovalSummary::from).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "approvals": items,
            "truncated": truncated,
            "returned": items.len(),
        })),
    )
        .into_response()
}

/// Body for the JSON approve/deny decision (A4).
#[derive(Deserialize)]
pub struct DecideReq {
    /// `true` to approve, `false` to deny.
    pub approve: bool,
    /// Optional free-text note recorded with the decision.
    #[serde(default)]
    pub note: Option<String>,
    /// The human operator the aggregator attributes this decision to (their
    /// email/sub). Used as the approver identity so separation-of-duty stays
    /// meaningful; falls back to the acting api-key id when absent/blank.
    #[serde(default)]
    pub approver: Option<String>,
}

/// `POST /api/v1/approvals/{id}/decision` — approve or deny an approval over JSON
/// (A4). Admin-gated AND tenant-partitioned: unlike the global HTML console, this
/// path FIRST verifies the approval is `visible_to_tenant(acting tenant)` and
/// returns 404 otherwise (never revealing a cross-tenant approval's existence) —
/// without this check the endpoint would be a fail-open cross-tenant decision bug.
/// The decision itself goes through the SAME atomic verb the HTML handlers use
/// (`storage.decide_approval`).
pub async fn api_decide_approval(
    admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<DecideReq>,
) -> Response {
    // SECURITY: this is the per-tenant aggregator surface — a global (untenanted)
    // admin key has no business deciding here (it would be able to decide ANY
    // tenant's approval). Reject it 403 before any lookup, so it can't even probe
    // for an id's existence. Mirrors api_list_approvals.
    let acting_tenant = match require_tenant_scoped(&admin).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Reload so the existence/visibility check sees the authoritative state.
    let _ = state.storage.reload().await;

    // SECURITY: enforce the tenant partition before deciding. The HTML console is
    // a global surface and skips visible_to_tenant; this JSON path must not. Look
    // the approval up and gate on the acting admin key's tenant — a 404 for a
    // not-found OR cross-tenant id, so we never reveal another tenant's approval.
    let existing = match state.storage.get_approval(&id).await {
        Ok(Some(a)) if a.visible_to_tenant(Some(acting_tenant)) => a,
        Ok(_) => {
            // Not found OR not visible to this tenant — identical 404, no oracle.
            return error_response(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                format!("No approval with id '{}'", id),
            );
        }
        Err(e) => {
            // Log the detail; return a generic message (don't echo internals).
            tracing::error!(error = %e, approval_id = %id, "decide: get_approval failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "Failed to load approval",
            );
        }
    };

    // Attribute the decision to the human operator the aggregator passed, but
    // record it as an AGGREGATOR-ASSERTED identity — vultrino must not present a
    // caller-supplied string as a verified identity. The recorded approver is
    // ALWAYS `agg:<acting-api-key-id>:<operator>`, which (a) keeps the human-
    // readable operator for audit, and (b) makes the asserting key explicit. The
    // operator part is a CLAIM the aggregator (muntin) makes — vultrino trusts
    // muntin to pass the real authenticated operator, but the namespace records
    // WHICH key made that claim, so a decision is never mistaken for a first-party
    // identity.
    //
    // SECURITY: the namespace MUST be applied unconditionally. When no operator is
    // supplied we use a sentinel (`agg:<key-id>:-`) rather than the bare key id —
    // a bare `<key-id>` would NOT carry the `agg:<key-id>:` prefix, so both same-
    // key M-of-N guards (prefix-based) would fail to recognize it and one key
    // could satisfy a 2-of-N by mixing a no-approver call with an approver call.
    // The sentinel `-` can never collide with a requester identity (no owner email
    // is `-`), so it doesn't spuriously trip the self-approval SoD check either.
    let operator = body
        .approver
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(NO_OPERATOR_SENTINEL);
    let approver = format!("agg:{}:{}", admin.0.api_key.id, operator);

    let enforce_sod = state.config.approval.enforce_separation_of_duty;

    // Idempotency (#4/#14) — checked BEFORE the same-key M-of-N guard so a retry of
    // an ALREADY-RECORDED sign-off replays instead of being mistaken for a fresh
    // second same-key sign-off. A network timeout after a committed decision can
    // make the aggregator retry; treat a retry as a no-op success (return the
    // current summary) when the approval is already decided, the outcome matches,
    // AND the incoming approver already appears among the recorded sign-offs —
    // matching ANY signoff (not just the finalizing approver_identity) so a
    // legitimate CO-APPROVER's retry on an already-granted M-of-N also replays
    // idempotently rather than 409-ing. (Only fires when !is_open, so it never
    // short-circuits a genuine fresh sign-off on a still-open request.)
    if !existing.status.is_open() {
        let same_outcome = matches!(
            (existing.status, body.approve),
            (ApprovalStatus::Approved, true) | (ApprovalStatus::Denied, false)
        );
        let approver_already_signed = existing
            .signoffs
            .iter()
            .any(|s| s.approver_identity.eq_ignore_ascii_case(&approver));
        if same_outcome && approver_already_signed {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": existing.id,
                    "status": existing.status.to_string(),
                    "executed": existing.executed,
                    "required_approvals": existing.effective_required_approvals(),
                    "approvals_received": existing.signoffs.len(),
                    "idempotent_replay": true,
                })),
            )
                .into_response();
        }
    }

    // M-of-N hardening (#2/#7): when separation-of-duty is hard-enforced, a single
    // aggregator key must NOT be able to satisfy a dual-control threshold by
    // inventing two distinct operator names. Distinctness across DIFFERENT human
    // approvers on one aggregator key is a CLAIM the aggregator makes; we cannot
    // verify it, so under hard SoD a SECOND sign-off from the SAME api key (the
    // `agg:<key-id>:` prefix) is rejected before it can satisfy threshold M.
    //
    // This is a FAST-FAIL on the (reloaded) read snapshot for a clean 409; the
    // AUTHORITATIVE, TOCTOU-safe enforcement is inside `transition()` under the
    // storage write lock (ApprovalError::SameAggregatorKey → Conflict → 409), so
    // two concurrent same-key requests can't both pass this pre-check and double-
    // sign. (Without hard SoD this is left to the aggregator's own dual-control.)
    // Runs AFTER the idempotency check so a co-approver's legitimate retry isn't
    // caught here as a same-key duplicate.
    if enforce_sod && existing.effective_required_approvals() > 1 {
        let key_prefix = format!("agg:{}:", admin.0.api_key.id);
        if existing
            .signoffs
            .iter()
            .any(|s| s.approver_identity.starts_with(&key_prefix))
        {
            return error_response(
                StatusCode::CONFLICT,
                "separation_of_duty",
                "Separation of duty: this approval already has a sign-off from this \
                 aggregator key; a distinct co-approver must use a different key.",
            );
        }
    }

    match state
        .storage
        .decide_approval(
            &id,
            body.approve,
            "json-api",
            &approver,
            enforce_sod,
            body.note,
            None,
            None,
        )
        .await
    {
        Ok(decided) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": decided.id,
                "status": decided.status.to_string(),
                "executed": decided.executed,
                // Dual-control progress, so the caller knows whether a denial took
                // effect immediately or an approval is still awaiting co-approvers.
                "required_approvals": decided.effective_required_approvals(),
                "approvals_received": decided.signoffs.len(),
            })),
        )
            .into_response(),
        // decide_approval returns Conflict for an already-decided/expired request
        // AND for a hard-enforced separation-of-duty self-approval. 409 conveys
        // "not actionable in the current state"; the message distinguishes them.
        Err(crate::storage::StorageError::Conflict(msg)) => {
            error_response(StatusCode::CONFLICT, "approval_not_decidable", msg)
        }
        // Raced away between the visibility check and the decide (e.g. deleted).
        Err(crate::storage::StorageError::ApprovalNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "approval_not_found",
            format!("No approval with id '{}'", id),
        ),
        // Don't echo raw internal error strings to the client; log them server-side.
        Err(e) => {
            tracing::error!(error = %e, approval_id = %id, "decide: decide_approval failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "Failed to record decision",
            )
        }
    }
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
        Err(e) => return error_response(StatusCode::UNAUTHORIZED, "invalid_api_key", e),
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

    (
        StatusCode::OK,
        Json(ListCredentialsResponse {
            credentials: filtered,
        }),
    )
        .into_response()
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
    if UseToken::looks_like_token(&secret) || ApprovalToken::looks_like_token(&secret) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "not_admin",
            "Use tokens and approval tokens cannot access the admin API; an API key with 'admin' permission is required",
        ));
    }
    // Generic message — don't reveal whether the key was unknown vs. expired
    // vs. role-missing (avoid an enumeration oracle on the admin surface).
    let (key, role) = validate_api_key(state, &secret).await.map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "Invalid API key",
        )
    })?;
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

/// Extractor that authenticates a **read** caller from request headers before the
/// body is read — the least-privilege counterpart of [`AdminApiAuth`]. It backs
/// only the inventory GETs (`/api/v1/tokens`, `/api/v1/policies`) so a reconcile
/// key can enumerate state without holding the admin authority that mints/revokes
/// tokens or rewrites/deletes policies. An admin key still passes (admin holds
/// `Permission::Read`); a `read-only` key passes the GETs but not the mutating
/// admin routes; use tokens are rejected exactly as on the admin surface.
pub struct ReadApiAuth(#[allow(dead_code)] pub AuthResult);

impl FromRequestParts<AppState> for ReadApiAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = require_read(state, &parts.headers).await?;
        tracing::info!(
            caller_key_id = %auth.api_key.id,
            method = %parts.method,
            path = %parts.uri.path(),
            "read API request authorized"
        );
        Ok(ReadApiAuth(auth))
    }
}

/// Authenticate a read caller: an API key with `Permission::Read` (which admin
/// keys also hold). Use tokens can never reach the inventory surface. Mirrors
/// [`require_admin`] in every respect except the permission demanded.
async fn require_read(
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
            "Use tokens cannot access the admin API; an API key with 'read' permission is required",
        ));
    }
    // Generic message — same enumeration-oracle hygiene as the admin surface.
    let (key, role) = validate_api_key(state, &secret).await.map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_api_key",
            "Invalid API key",
        )
    })?;
    let auth = AuthResult { api_key: key, role };
    if !auth.has_permission(Permission::Read) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "API key does not have 'read' permission",
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
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
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
    match state
        .storage
        .idempotency_check_or_reserve(&key, &body_hash)
        .await
    {
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
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                e.to_string(),
            )
        }
    }
    let (status, body) = op().await;
    if status.is_success() {
        let body_str = serde_json::to_string(&redact_for_replay(&body)).unwrap_or_default();
        if let Err(e) = state
            .storage
            .idempotency_complete(&key, &body_hash, status.as_u16(), &body_str)
            .await
        {
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
    /// **Kill switch** (V6): when true, this policy is an *authoritative*
    /// unconditional Deny for every principal+credential it matches, evaluated
    /// **before** all non-kill policies — so a halt can't be overridden by an
    /// allow rule ordered first. This makes the kill-triad's W3 leg a true
    /// independent containment leg: govder authors a `kill=true` per-agent Deny
    /// and the evaluator short-circuits it ahead of any matching allow rule.
    /// Defaults to `false` (omitted) — ordinary policy POSTs keep parsing
    /// unchanged. Admin-gated: the policy routes already require an admin key.
    #[serde(default)]
    pub kill: bool,
}

/// Build a validated `Policy` from a request, forcing the id on PUT or
/// generating a fresh one on POST.
fn build_policy(req: PolicyUpsertRequest, forced_id: Option<String>) -> Result<Policy, String> {
    if req.name.trim().is_empty() {
        return Err("policy name must not be empty".to_string());
    }
    // Fail loud on a credential_pattern that doesn't compile, rather than
    // storing a policy whose glob silently degrades to never matching.
    glob::Pattern::new(&req.credential_pattern).map_err(|e| {
        format!(
            "invalid credential_pattern '{}': {}",
            req.credential_pattern, e
        )
    })?;
    // Use the builder so new optional Policy fields get their defaults.
    let mut policy = Policy::deny_all(req.name, req.credential_pattern);
    policy.id = forced_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    policy.principal_pattern = req.principal_pattern;
    policy.default_action = req.default_action;
    policy.rules = req.rules;
    // V6: an admin may author an authoritative kill policy. A kill policy with
    // default_action = deny + a principal_pattern is the expected shape (the
    // kill-triad W3 leg); it is NOT rejected here — validate only guards spend
    // caps. The kill flag makes the evaluator short-circuit this policy ahead of
    // any matching allow rule (src/policy/mod.rs ~283).
    policy.kill = req.kill;
    // Reject misconfigured spend caps (nested / no caps / not fail-closed).
    policy.validate()?;
    Ok(policy)
}

/// Persist a policy and hot-reload the engine, returning the canonical object.
async fn store_and_reload_policy(
    state: &AppState,
    policy: &Policy,
    created: bool,
) -> (StatusCode, serde_json::Value) {
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
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    // Echo the canonical policy plus its semantic `content_hash` (additive — the
    // existing `id`/`name`/... fields are intact) so the authoring caller (govder)
    // captures the expected hash at author time to later diff against the list. The
    // hash is keyed by the server secret (same function the list uses) so the two
    // paths produce the same value; empty when no secret is configured.
    let mut body = serde_json::to_value(policy).unwrap_or_default();
    if let Some(obj) = body.as_object_mut() {
        let content_hash = policy_content_hash(policy, state.config.policy_hash_secret.as_deref());
        obj.insert("content_hash".to_string(), serde_json::json!(content_hash));
    }
    (status, body)
}

/// Canonical, order-stable projection of a policy's **semantic** content, hashed
/// to detect drift across planes. Field names/shape here define the hash preimage,
/// so they must stay byte-stable: changing this struct changes every policy's
/// `content_hash`. `principal_pattern` is kept as `Option` (not flattened to "")
/// so `None` and `Some("")` hash differently — a present-but-empty glob is a
/// distinct policy from an absent one.
#[derive(Serialize)]
struct CanonicalPolicy<'a> {
    credential_pattern: &'a str,
    principal_pattern: &'a Option<String>,
    default_action: PolicyAction,
    kill: bool,
    rules: &'a [PolicyRule],
}

/// Self-describing hash scheme label. The value is `hmac-sha256:<hexlowercase>`
/// when a server secret keys the digest, so the scheme is legible on the wire and
/// can't be confused with the old unkeyed `sha256:` form.
const POLICY_HASH_PREFIX: &str = "hmac-sha256:";

type PolicyHmac = hmac::Hmac<Sha256>;

/// Deterministic KEYED digest over a policy's semantic content (credential_pattern,
/// principal_pattern distinguishing None vs Some, default_action, kill, and the
/// ORDERED rules). Identity (`id`/`name`) is excluded — a rename is not a semantic
/// change. The digest is **HMAC-SHA256(secret, canonical-bytes)**, not a bare hash:
/// the canonical preimage is low-entropy (a handful of globs/enums/rules), so a bare
/// SHA-256 would let a compromised read-only key brute-force the reduced DTO back
/// into the full enforcement topology offline. Keying it removes that oracle.
///
/// When no secret is configured we return an EMPTY string — never a bare unkeyed
/// digest (that's the oracle we're removing). govder treats an empty `content_hash`
/// as "drift detection unavailable" and skips it (presence checks still work).
///
/// govder captures this value at author time (in the create/replace response) and
/// re-checks it for EQUALITY against the listed value; it never recomputes the hash
/// itself, so switching to a keyed scheme is transparent to govder as long as the
/// list and the create/replace paths use this one function with the same secret.
/// Identical content + same secret always yields the same digest, so an idempotent
/// re-PUT of the same policy never registers as false drift.
fn policy_content_hash(policy: &Policy, secret: Option<&str>) -> String {
    // No secret → no hash (graceful degradation; do NOT fall back to a bare digest).
    let Some(secret) = secret else {
        return String::new();
    };
    let canonical = CanonicalPolicy {
        credential_pattern: &policy.credential_pattern,
        principal_pattern: &policy.principal_pattern,
        default_action: policy.default_action,
        kill: policy.kill,
        rules: &policy.rules,
    };
    // serde_json over this fixed-field struct is order-stable (struct fields
    // serialize in declaration order; rules keep their Vec order). Any change to a
    // hashed field changes the bytes and thus the digest.
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    // `new_from_slice` accepts any key length for HMAC, so this never errors.
    let mut mac = <PolicyHmac as hmac::Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    hmac::Mac::update(&mut mac, &bytes);
    format!(
        "{}{}",
        POLICY_HASH_PREFIX,
        hex::encode(hmac::Mac::finalize(mac).into_bytes())
    )
}

/// Reduced, secret-free projection of a policy for the inventory list. Deliberately
/// omits rules / patterns / default_action so a compromised read key cannot read
/// the enforcement topology out of the list; govder's reconciler consumes only
/// id/name/kill/content_hash (semantic-drift via the hash). The full policy is
/// never exposed by the list — only the create/replace responses echo the author's
/// canonical view (with content_hash) back to the authoring admin. `content_hash`
/// is the keyed digest (empty when no server secret is configured).
#[derive(Serialize)]
struct PolicyListItem {
    id: String,
    name: String,
    kill: bool,
    content_hash: String,
}

impl PolicyListItem {
    /// Build the reduced item, keying `content_hash` with the server secret (empty
    /// when `secret` is `None`). Not a `From` impl because it needs the secret.
    fn new(p: &Policy, secret: Option<&str>) -> Self {
        PolicyListItem {
            id: p.id.clone(),
            name: p.name.clone(),
            kill: p.kill,
            content_hash: policy_content_hash(p, secret),
        }
    }
}

/// `GET /api/v1/policies` — list the live (enforced) policy set. Read-gated
/// (least privilege: a reconcile key reads inventory without admin write power).
/// Returns the in-engine policies (config + stored, merged) — the authoritative
/// *enforced* state, not just what's persisted — sorted by id, as a REDUCED DTO
/// (`id`, `name`, `kill`, `content_hash`) that carries no secrets AND no
/// enforcement topology (rules/patterns/default_action are withheld). Backs the
/// govder cross-plane reconciliation sweep: govder compares this against its
/// tracked provision records to flag an orphan policy (enforced but untracked), a
/// missing one (tracked but not enforced — a containment gap), or a semantic drift
/// (content_hash != the value captured at author time).
pub async fn api_list_policies(_read: ReadApiAuth, State(state): State<AppState>) -> Response {
    let mut policies = state.server.policy_engine().list_policies();
    policies.sort_by(|a, b| a.id.cmp(&b.id));
    let secret = state.config.policy_hash_secret.as_deref();
    let items: Vec<PolicyListItem> = policies
        .iter()
        .map(|p| PolicyListItem::new(p, secret))
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "policies": items })),
    )
        .into_response()
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
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "reload_error",
                    e.to_string(),
                );
            }
            (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response()
        }
        Err(crate::storage::StorageError::PolicyNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "policy_not_found",
            format!("No stored policy with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

// -------- Capabilities (named MCP tools) --------

/// Body for creating/replacing a capability. On `POST` the id is server-generated
/// (create); on `PUT` the path id is used (create-or-replace). Mirrors the policy
/// admin handlers (Admin-gated, Idempotency-Key honored).
#[derive(Serialize, Deserialize)]
pub struct CapabilityUpsertRequest {
    /// The MCP tool name the LLM sees (e.g. `send_email`).
    pub tool_name: String,
    /// Description shown to the LLM in tools/list.
    #[serde(default)]
    pub description: String,
    /// The action this capability performs: a canonical `plugin.action` or a
    /// govder action label (V8).
    pub action: String,
    /// The vultrino plugin backing the action (informational).
    #[serde(default)]
    pub plugin: Option<String>,
    /// Target scope (url glob + methods, or fixed plugin params).
    #[serde(default)]
    pub target: CapabilityTarget,
    /// The vault credential alias this capability injects.
    pub credential_ref: String,
    /// JSON Schema the LLM fills (the action's own args; `api_key` is added
    /// dynamically at tools/list time).
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// Reversibility class (`reversible` | `partially-reversible` | `irreversible`).
    #[serde(default)]
    pub reversibility: Option<String>,
    /// When set, marks this as an LLM-proxy capability (backs `POST /llm` rather
    /// than appearing as a named MCP tool). Carries the provider base URL.
    #[serde(default)]
    pub llm: Option<crate::capability::LlmProxy>,
}

/// Build a validated `Capability` from a request, forcing the id on PUT or
/// generating a fresh one on POST.
fn build_capability(
    req: CapabilityUpsertRequest,
    forced_id: Option<String>,
) -> Result<Capability, String> {
    let capability = Capability {
        id: forced_id.unwrap_or_else(|| format!("cap-{}", uuid::Uuid::new_v4())),
        tool_name: req.tool_name.trim().to_string(),
        description: req.description,
        action: req.action.trim().to_string(),
        plugin: req
            .plugin
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        target: req.target,
        credential_ref: req.credential_ref.trim().to_string(),
        input_schema: req.input_schema,
        reversibility: req
            .reversibility
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("reversible")
            .to_string(),
        llm: req.llm,
    };
    capability.validate()?;
    Ok(capability)
}

/// Persist a capability, emit an event, and return the canonical metadata.
async fn store_capability_and_emit(
    state: &AppState,
    capability: &Capability,
    created: bool,
) -> (StatusCode, serde_json::Value) {
    if let Err(e) = state.storage.store_capability(capability).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"code": "storage_error", "error": e.to_string()}),
        );
    }
    // Observable capability-change event on the signed outbox, so govder/feir see
    // the connector catalog mutate (mirrors the policy-change emit).
    state
        .server
        .emit_event(
            &capability.id,
            crate::outbox::EVENT_CAPABILITY_CHANGED,
            serde_json::json!({
                "capability_id": capability.id,
                "tool_name": capability.tool_name,
                "action": capability.action,
                "credential_ref": capability.credential_ref,
                "change": if created { "created" } else { "replaced" },
            }),
        )
        .await;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (
        status,
        serde_json::to_value(CapabilityMetadata::from(capability)).unwrap_or_default(),
    )
}

/// `POST /api/v1/capabilities` — create a capability (id generated).
pub async fn api_create_capability(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CapabilityUpsertRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        match build_capability(req, None) {
            Ok(capability) => store_capability_and_emit(&st, &capability, true).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_capability", "error": e}),
            ),
        }
    })
    .await
}

/// `PUT /api/v1/capabilities/{id}` — create or replace the capability with this id.
pub async fn api_put_capability(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CapabilityUpsertRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    // Bind the hash to the path id (same as policies) so the same body PUT to a
    // different id under one Idempotency-Key isn't replayed as the first.
    let body_hash = idempotency_body_hash(&(id.as_str(), &req));
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
        match build_capability(req, Some(id)) {
            Ok(capability) => store_capability_and_emit(&st, &capability, false).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_capability", "error": e}),
            ),
        }
    })
    .await
}

/// `GET /api/v1/capabilities` — list all stored capabilities (metadata; no secret).
pub async fn api_list_capabilities(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
) -> Response {
    match state.storage.list_capabilities().await {
        Ok(mut caps) => {
            caps.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
            let metadata: Vec<CapabilityMetadata> =
                caps.iter().map(CapabilityMetadata::from).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "capabilities": metadata })),
            )
                .into_response()
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

/// `DELETE /api/v1/capabilities/{id}` — remove a stored capability.
pub async fn api_delete_capability(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.storage.delete_capability(&id).await {
        Ok(()) => {
            state
                .server
                .emit_event(
                    &id,
                    crate::outbox::EVENT_CAPABILITY_CHANGED,
                    serde_json::json!({ "capability_id": id, "change": "deleted" }),
                )
                .await;
            (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response()
        }
        Err(crate::storage::StorageError::CapabilityNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "capability_not_found",
            format!("No stored capability with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
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

/// `GET /api/v1/tokens` — list all use tokens as non-secret metadata
/// (`UseTokenMetadata`: id, prefix, name, scopes, agent_label, use/expiry/revoke
/// state) sorted by id — NEVER the token hash or plaintext. Read-gated (least
/// privilege: a reconcile key reads inventory without admin write power). Backs the
/// govder cross-plane reconciliation sweep: govder enumerates live tokens and
/// flags any whose id has no governance index row (an orphan token = an
/// uncontainable agent → revoke fail-closed + alert).
pub async fn api_list_tokens(_read: ReadApiAuth, State(state): State<AppState>) -> Response {
    match state.storage.list_use_tokens().await {
        Ok(mut tokens) => {
            tokens.sort_by(|a, b| a.id.cmp(&b.id));
            let metadata: Vec<UseTokenMetadata> =
                tokens.iter().map(UseTokenMetadata::from).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "tokens": metadata })),
            )
                .into_response()
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
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
        // principal_pattern glob matching).
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
        Ok(token) => (
            StatusCode::OK,
            Json(serde_json::json!({
            "revoked": true,
            "metadata": UseTokenMetadata::from(&token),
            })),
        )
            .into_response(),
        Err(crate::storage::StorageError::UseTokenNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "token_not_found",
            format!("No use token with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

// -------- Agent token resolve (plan 031 agent-initiated spawn) --------

/// Optional query filter for agent token resolve.
#[derive(Deserialize)]
pub struct AgentResolveQuery {
    /// When set (e.g. `agent.spawn`), the token's `action_scope` must match.
    #[serde(default)]
    pub required_action: Option<String>,
}

/// `GET /api/v1/auth/agent` — resolve a Bearer `vut_` use token to the bound
/// agent label + tenant. Read-only; used by muntin broker for agent-initiated spawn.
pub async fn api_resolve_agent_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<AgentResolveQuery>,
) -> Response {
    let secret = match extract_api_key(&headers) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_token",
                "Authorization header with Bearer use token required",
            )
        }
    };
    if !UseToken::looks_like_token(&secret) {
        return error_response(
            StatusCode::FORBIDDEN,
            "not_use_token",
            "Agent resolve requires a vut_ use token",
        );
    }
    let _ = state.storage.reload().await;
    let token = match state
        .storage
        .get_use_token_by_hash(&UseToken::hash(&secret))
        .await
    {
        Ok(Some(t)) => t,
        _ => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid use token",
            )
        }
    };
    if let Err(e) = token.check_usable() {
        return error_response(StatusCode::FORBIDDEN, "token_unusable", e.to_string());
    }
    if let Some(required) = query
        .required_action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !token.allows_action(required) {
            return error_response(
                StatusCode::FORBIDDEN,
                "token_scope_denied",
                format!(
                    "Use token action_scope {:?} does not permit required action {required:?}",
                    token.action_scope
                ),
            );
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token_id": token.id,
            "agent_label": token.agent_label,
            "tenant": token.tenant,
            "token_prefix": token.token_prefix,
            "action_scope": token.action_scope,
            "max_uses": token.max_uses,
            "uses": token.uses,
            "require_approval": token.require_approval,
        })),
    )
        .into_response()
}

/// `POST /api/v1/auth/agent/consume` — atomically authorize and consume one
/// agent-facing action use. Unlike the read-only resolver, this is suitable for
/// side effects such as sub-agent spawn: max_uses is load-bearing and tokens
/// that require the approval workflow fail closed here.
pub async fn api_consume_agent_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<AgentResolveQuery>,
) -> Response {
    let secret = match extract_api_key(&headers) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_token",
                "Authorization header with Bearer use token required",
            )
        }
    };
    if !UseToken::looks_like_token(&secret) {
        return error_response(
            StatusCode::FORBIDDEN,
            "not_use_token",
            "Agent action requires a vut_ use token",
        );
    }
    let _ = state.storage.reload().await;
    let token = match state
        .storage
        .get_use_token_by_hash(&UseToken::hash(&secret))
        .await
    {
        Ok(Some(t)) => t,
        _ => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid use token",
            )
        }
    };
    if let Err(e) = token.check_usable() {
        return error_response(StatusCode::FORBIDDEN, "token_unusable", e.to_string());
    }
    let required = query
        .required_action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(required) = required else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "required_action",
            "required_action is mandatory for token consumption",
        );
    };
    if !token.allows_action(required) {
        return error_response(
            StatusCode::FORBIDDEN,
            "token_scope_denied",
            format!("Use token does not permit required action {required:?}"),
        );
    }
    if token.require_approval {
        return error_response(
            StatusCode::FORBIDDEN,
            "token_approval_required",
            "This token requires the governed approval execution path; direct agent action consumption is denied",
        );
    }
    let agent_label = token
        .agent_label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let tenant = token
        .tenant
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if agent_label.is_none() || tenant.is_none() {
        return error_response(
            StatusCode::FORBIDDEN,
            "token_identity_missing",
            "Agent action token must bind both agent_label and tenant",
        );
    }
    let consumed = match state.storage.consume_use_token(&token.id).await {
        Ok(t) => t,
        Err(e) => return error_response(StatusCode::FORBIDDEN, "token_unusable", e.to_string()),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token_id": consumed.id,
            "agent_label": consumed.agent_label,
            "tenant": consumed.tenant,
            "token_prefix": consumed.token_prefix,
            "action_scope": consumed.action_scope,
            "max_uses": consumed.max_uses,
            "uses": consumed.uses,
            "require_approval": consumed.require_approval,
        })),
    )
        .into_response()
}

// -------- Approval tokens (delegate-agent authority, plan 031) --------

#[derive(Serialize, Deserialize)]
pub struct ApprovalTokenCreateRequest {
    pub delegation_grant_ref: String,
    /// Ignored when govder is configured — scope is snapshotted from govder SoR.
    #[serde(default)]
    pub grant_scope: Option<crate::delegation::DelegationGrantScope>,
    #[serde(default)]
    pub agent_label: Option<String>,
    pub delegator_identity: String,
    #[serde(default)]
    pub tenant: Option<String>,
    /// Lifetime in seconds from now (optional).
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}

/// `POST /api/v1/approval-tokens` — mint an approval token; plaintext returned once.
pub async fn api_create_approval_token(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ApprovalTokenCreateRequest>,
) -> Response {
    let key = extract_idempotency_key(&headers);
    let body_hash = idempotency_body_hash(&req);
    let st = state.clone();
    idempotent(&state, key, body_hash, move || async move {
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
        let govder = match &st.govder {
            Some(c) => c,
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "code": "govder_not_configured",
                        "error": "Delegation approval tokens require govder (GOVDER_BASE_URL + GOVDER_TENANT_ASSERTION_SECRET)"
                    }),
                );
            }
        };
        let tenant = req
            .tenant
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let tenant = match tenant {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({
                        "code": "tenant_required",
                        "error": "tenant is required to validate delegation_grant_ref against govder"
                    }),
                );
            }
        };
        let (grant, grant_scope) = match govder
            .lookup_grant(
                &tenant,
                req.delegation_grant_ref.trim(),
                req.agent_label.as_deref(),
            )
            .await
        {
            Ok(pair) => pair,
            Err(crate::govder::GovderError::Policy(msg)) => {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": "invalid_grant_ref", "error": msg}),
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "approval token mint: govder grant lookup failed");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "code": "govder_unavailable",
                        "error": "Failed to validate delegation grant against govder (fail-closed)"
                    }),
                );
            }
        };
        let agent_label = req.agent_label.or_else(|| grant.delegate_agent_ep.clone());
        let params = NewApprovalToken {
            delegation_grant_ref: req.delegation_grant_ref,
            grant_scope,
            agent_label,
            delegator_identity: req.delegator_identity,
            tenant: req.tenant.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            expires_in,
        };
        if let Err(e) = params.validate() {
            return (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code": "invalid_token", "error": e}),
            );
        }
        if let Some(label) = &params.agent_label {
            if let Err(e) = crate::auth::validate_agent_label(label) {
                return (
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({"code": "invalid_agent_label", "error": e}),
                );
            }
        }
        let (full_token, token) = ApprovalToken::create(params);
        if let Err(e) = st.storage.store_approval_token(&token).await {
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
                "metadata": ApprovalTokenMetadata::from(&token),
            }),
        )
    })
    .await
}

/// `POST /api/v1/approval-tokens/{id}/revoke` — revoke an approval token.
pub async fn api_revoke_approval_token(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.storage.set_approval_token_revoked(&id).await {
        Ok(token) => (
            StatusCode::OK,
            Json(serde_json::json!({
            "revoked": true,
            "metadata": ApprovalTokenMetadata::from(&token),
            })),
        )
            .into_response(),
        Err(crate::storage::StorageError::ApprovalTokenNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "token_not_found",
            format!("No approval token with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

/// `POST /api/v1/approvals/{id}/delegate-decision` — approve or deny via a `vap_`
/// delegate-agent token (plan 031). Bearer auth only; records channel
/// `delegate-agent` and the token's delegation grant ref on the sign-off.
pub async fn api_delegate_decide_approval(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DecideReq>,
) -> Response {
    let secret = match extract_api_key(&headers) {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "missing_token",
                "Authorization header with Bearer approval token required",
            )
        }
    };
    if !ApprovalToken::looks_like_token(&secret) {
        return error_response(
            StatusCode::FORBIDDEN,
            "not_approval_token",
            "Delegate decisions require a vap_ approval token",
        );
    }

    let _ = state.storage.reload().await;
    let token = match state
        .storage
        .get_approval_token_by_hash(&ApprovalToken::hash(&secret))
        .await
    {
        Ok(Some(t)) => t,
        _ => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid approval token",
            )
        }
    };
    if let Err(e) = token.check_usable() {
        return error_response(StatusCode::FORBIDDEN, "token_unusable", e.to_string());
    }

    let existing = match state.storage.get_approval(&id).await {
        Ok(Some(a)) if a.visible_to_tenant(token.tenant.as_deref()) => a,
        Ok(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "approval_not_found",
                format!("No approval with id '{}'", id),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, approval_id = %id, "delegate decide: get_approval failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "Failed to load approval",
            );
        }
    };

    if !existing.status.is_open() {
        return error_response(
            StatusCode::CONFLICT,
            "approval_not_decidable",
            format!("Approval is already {}", existing.status),
        );
    }

    let approver = token.approver_identity();
    let grant_ref = token.delegation_grant_ref.clone();
    let enforce_sod = state.config.approval.enforce_separation_of_duty;

    let govder = match &state.govder {
        Some(c) => c,
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "govder_not_configured",
                "Delegate decisions require govder (GOVDER_BASE_URL + GOVDER_TENANT_ASSERTION_SECRET)",
            );
        }
    };
    let tenant = token
        .tenant
        .as_deref()
        .or(existing.tenant.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let tenant = match tenant {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                "tenant_required",
                "Approval and token must carry tenant for govder delegate evaluation (fail-closed)",
            );
        }
    };
    let requester_agent_id = existing
        .agent_label
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("");
    if requester_agent_id.is_empty() {
        return error_response(
            StatusCode::FORBIDDEN,
            "requester_required",
            "Approval must carry requester agent_label for delegate evaluation (fail-closed)",
        );
    }
    let eval = match govder
        .evaluate_delegate_decision(crate::govder::EvaluateInput {
            tenant,
            decision_id: &existing.id,
            grant_id: &grant_ref,
            delegate_agent_id: &approver,
            requester_agent_id,
            action_class: &existing.action,
            risk_tier: existing.criticality.to_govder_risk_tier(),
            irreversible: crate::approval::approval_irreversible(&existing),
            approve: body.approve,
            spend_amount_minor: existing.trusted_spend_amount_minor,
            spend_asset: existing.trusted_spend_asset.as_deref(),
        })
        .await
    {
        Ok(r) => r,
        Err(crate::govder::GovderError::Policy(msg)) => {
            return error_response(StatusCode::FORBIDDEN, "delegate_decision_denied", msg);
        }
        Err(e) => {
            tracing::error!(error = %e, approval_id = %id, "delegate decide: govder evaluate failed");
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "govder_unavailable",
                "Failed to evaluate delegate decision against govder (fail-closed)",
            );
        }
    };
    if !eval.permitted {
        return error_response(
            StatusCode::FORBIDDEN,
            "delegate_decision_denied",
            eval.reason,
        );
    }
    const MAX_DELEGATE_VETO_SECS: u64 = 7 * 24 * 60 * 60;
    if eval.veto_window_secs > MAX_DELEGATE_VETO_SECS {
        tracing::error!(approval_id = %id, veto_window_secs = eval.veto_window_secs,
            "delegate decide: govder returned an out-of-bounds veto window");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "govder_invalid_response",
            "Govder returned an invalid delegate veto window (fail-closed)",
        );
    }
    let veto_until = if body.approve && eval.veto_window_secs > 0 {
        let seconds = i64::try_from(eval.veto_window_secs).unwrap_or(i64::MAX);
        Some(chrono::Utc::now() + chrono::Duration::seconds(seconds))
    } else {
        None
    };

    match state
        .storage
        .decide_delegate_approval(
            &id,
            body.approve,
            &approver,
            enforce_sod,
            body.note,
            &grant_ref,
            veto_until,
        )
        .await
    {
        Ok(decided) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": decided.id,
                "status": decided.status.to_string(),
                "executed": decided.executed,
                "required_approvals": decided.effective_required_approvals(),
                "approvals_received": decided.signoffs.len(),
                "delegation_grant_ref": grant_ref,
                "veto_until": decided.delegate_veto_until.map(|t| t.to_rfc3339()),
            })),
        )
            .into_response(),
        Err(crate::storage::StorageError::Conflict(msg)) => {
            error_response(StatusCode::CONFLICT, "approval_not_decidable", msg)
        }
        Err(crate::storage::StorageError::ApprovalNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "approval_not_found",
            format!("No approval with id '{}'", id),
        ),
        Err(e) => {
            tracing::error!(error = %e, approval_id = %id, "delegate decide: decide_approval failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                "Failed to record decision",
            )
        }
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
            Ok(outcome) => (
                StatusCode::OK,
                serde_json::to_value(outcome).unwrap_or_default(),
            ),
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
/// (per-process and in-memory, like the rate-limit counters).
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
pub async fn api_metrics(admin: AdminApiAuth, State(state): State<AppState>) -> Response {
    // R4: approval counts are scoped to the acting admin's tenant — a tenant
    // admin sees only its own (+ untenanted/shared) approvals; a global admin
    // (no tenant) sees all. (`unauthorized_attempts` stays a global per-process
    // counter — it is not partitioned by tenant.)
    let acting_tenant = admin.0.api_key.tenant.clone();
    let approvals = state
        .server
        .list_approvals_for_tenant(acting_tenant.as_deref())
        .await
        .unwrap_or_default();

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
        "tenant_scope": acting_tenant,
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
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

/// `GET /api/v1/events/dead` — the dead-letter queue (events that exhausted their
/// delivery retries) (V9).
pub async fn api_list_dead_letters(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
) -> Response {
    match state.storage.list_dead_letter_events(1000).await {
        Ok(events) => (
            StatusCode::OK,
            Json(serde_json::json!({ "dead_letters": events })),
        )
            .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
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
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "requeued": true, "sequence": sequence })),
        )
            .into_response(),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            "not_dead_lettered",
            format!("no dead-lettered event with sequence {sequence}"),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
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
        Err(crate::storage::StorageError::RoleNotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "role_not_found",
            format!("No role with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
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
            return (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"code":"invalid_credential","error":"alias must not be empty"}),
            );
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
                return (
                    StatusCode::CONFLICT,
                    serde_json::json!({"code":"credential_exists","error":e.to_string()}),
                );
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"code":"storage_error","error":e.to_string()}),
            );
        }
        // Return metadata only — never the secret.
        (
            StatusCode::CREATED,
            serde_json::to_value(CredentialMetadata::from(&cred)).unwrap_or_default(),
        )
    })
    .await
}

/// `DELETE /api/v1/credentials/{id}` — delete a credential by id.
pub async fn api_delete_credential(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    // R5/V7: propagate a downstream revoke before deleting an OAuth2 credential
    // that exposes a revocation endpoint, so an already-issued token is actively
    // revoked at the provider rather than left to expire. Best-effort, but a read
    // error is logged (not silently swallowed) so a skipped propagation is visible.
    match state.storage.get(&id).await {
        Ok(Some(cred)) => {
            crate::revocation::propagate_revoke(
                &crate::revocation::HttpRevocationClient::new(),
                &*state.storage,
                &cred,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, credential_id = %id, "could not load credential for revoke-propagation before delete")
        }
    }
    match state.storage.delete(&id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"deleted": id}))).into_response(),
        Err(crate::storage::StorageError::NotFound(_)) => error_response(
            StatusCode::NOT_FOUND,
            "credential_not_found",
            format!("No credential with id '{}'", id),
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_policy_kill_defaults_false_when_omitted() {
        // Back-compat: a body WITHOUT a `kill` field (every pre-V13 admin POST)
        // still parses and yields a non-kill policy. `#[serde(default)]` on the
        // new field guarantees existing callers are unaffected.
        let json = r#"{
            "name": "github-readonly",
            "credential_pattern": "github-*",
            "rules": [],
            "default_action": "deny"
        }"#;
        let req: PolicyUpsertRequest = serde_json::from_str(json).unwrap();
        assert!(!req.kill, "kill must default to false when omitted");
        let policy = build_policy(req, Some("p1".to_string())).unwrap();
        assert!(
            !policy.kill,
            "a normal compiled policy must not be a kill policy"
        );
        assert_eq!(policy.default_action, PolicyAction::Deny);
    }

    #[test]
    fn test_build_policy_kill_true_overrides_allow_rule() {
        // The kill-triad W3 leg: an admin authors a per-agent Deny with
        // `kill:true` via the API path (build_policy). The constructed Policy must
        // carry kill=true so vultrino's evaluator short-circuits it AHEAD of any
        // matching allow rule — even one ordered first. This is the fix that makes
        // W3 a true independent containment leg (previously an ordinary kill=false
        // deny could be skipped when an allow rule matched first).
        use crate::policy::{EvalInput, PolicyCondition, PolicyDecision, PolicyEngine, Principal};

        // The W3 body govder pushes: default-deny, principal-scoped, kill=true.
        let json = r#"{
            "name": "kill-bot-7-k1",
            "credential_pattern": "*",
            "principal_pattern": "bot-7",
            "rules": [],
            "default_action": "deny",
            "kill": true
        }"#;
        let req: PolicyUpsertRequest = serde_json::from_str(json).unwrap();
        assert!(req.kill, "kill:true must parse off the wire");
        let kill_policy = build_policy(req, Some("kill-bot-7".to_string())).unwrap();
        assert!(
            kill_policy.kill,
            "build_policy must propagate kill=true to the Policy"
        );

        let engine = PolicyEngine::new();
        engine.set_default_deny(false);
        // Ordered FIRST: a broad allow whose allow RULE matches the request. Pre-fix
        // an ordinary deny added after this would never be reached for the agent.
        engine.add_policy(Policy::allow_all("allow-all", "*").with_rule(
            PolicyCondition::UrlMatch("*".to_string()),
            PolicyAction::Allow,
        ));
        // Then the admin-authored kill policy (added AFTER the allow on purpose).
        engine.add_policy(kill_policy);

        let halted = Principal {
            id: "k1".to_string(),
            agent_label: Some("bot-7".to_string()),
            owner: None,
            workload_id: None,
        };
        let decision = engine.evaluate_full(&EvalInput {
            credential_alias: "github-prod",
            url: Some("https://api.github.com/x"),
            method: Some("GET"),
            action: None,
            principal: Some(&halted),
            spend: None,
        });
        match decision {
            PolicyDecision::Deny(r) => assert!(r.contains("halted"), "reason: {r}"),
            other => {
                panic!("an admin-authored kill policy must override the allow rule, got {other:?}")
            }
        }

        // A different agent is unaffected → the allow rule still applies (the kill
        // is principal-scoped, not a blanket halt).
        let other = Principal {
            id: "k2".to_string(),
            agent_label: Some("bot-9".to_string()),
            owner: None,
            workload_id: None,
        };
        let decision = engine.evaluate_full(&EvalInput {
            credential_alias: "github-prod",
            url: Some("https://api.github.com/x"),
            method: Some("GET"),
            action: None,
            principal: Some(&other),
            spend: None,
        });
        assert_eq!(
            decision,
            PolicyDecision::Allow,
            "non-halted agent still allowed"
        );
    }

    #[test]
    fn test_resolve_execute_action_defaults() {
        // Omitted, empty, and whitespace-only all fall back to the default.
        assert_eq!(resolve_execute_action(None), "http.request");
        assert_eq!(resolve_execute_action(Some(String::new())), "http.request");
        assert_eq!(
            resolve_execute_action(Some("   ".to_string())),
            "http.request"
        );
        // A real action (canonical or label) is preserved verbatim.
        assert_eq!(
            resolve_execute_action(Some("postgres.run_sql".to_string())),
            "postgres.run_sql"
        );
        assert_eq!(
            resolve_execute_action(Some("payments.refund".to_string())),
            "payments.refund"
        );
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
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());

        let result = extract_api_key(&headers);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_api_key_no_token() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());

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
        assert_eq!(
            request.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
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
