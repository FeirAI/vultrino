//! Networked HTTP MCP transport (connector M1).
//!
//! vultrino holds the secrets, so it must **never be co-located** with an agent
//! harness in production. This endpoint is how an agent on another host reaches
//! vultrino's MCP server: a JSON-RPC request is POSTed to `/mcp` with a Bearer
//! **use-token (`vut_`)** (or an API key / one-time secret) in the
//! `Authorization` header. This is the URL a hermes `config.yaml` points at:
//!
//! ```yaml
//! mcp_servers:
//!   vultrino:
//!     url: "https://vultrino.internal/mcp"
//!     headers:
//!       Authorization: "Bearer vut_..."
//! ```
//!
//! ## Why the header token both authenticates AND scopes
//! The Bearer token resolves to an [`McpPrincipal`] whose policy gates BOTH
//! `tools/list` (the principal only sees its granted named tools) and
//! `tools/call` (the action runs through the same default-deny `execute_gated`
//! path). Authentication and authorization are the same token — so a remote
//! agent can only ever see and use exactly the tools it was granted.
//!
//! ## Same handler as stdio (no logic fork)
//! The existing stdio MCP handler reads the caller's secret from the JSON-RPC
//! body (`params.api_key` for `tools/list`, `params.arguments.api_key` for
//! `tools/call`). Rather than fork that gating logic, this transport **injects
//! the header Bearer token into those body fields** (overwriting any
//! caller-supplied value) and then dispatches through the SAME
//! [`McpServer::handle_jsonrpc`]. Overwriting is the security boundary: a remote
//! agent cannot smuggle a *different* principal's token in the JSON body — the
//! header is authoritative, so the token that authenticates the request is also
//! the token that scopes it.
//!
//! ## Transport auth gate vs. inner per-method semantics
//! The transport rejects a **missing / unknown / revoked / expired** token with
//! `401` before any dispatch (a bad token never reaches the handler). An
//! *exhausted* single-use token is deliberately **not** rejected here: the inner
//! handler is read-vs-execute aware — `tools/list` (a read) still works with an
//! exhausted token, while `tools/call` consumes through `execute_gated` and
//! fails closed on its own. The transport never consumes the token; consumption
//! stays inside `execute_gated`, identical to stdio.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::auth::UseToken;
use crate::mcp::McpServer;

use super::server::AppState;

/// Outcome of resolving the inbound `Authorization` Bearer at the transport
/// boundary. We only need a pass/fail gate here — the authoritative scope check
/// happens inside `execute_gated` once the handler runs.
enum BearerGate {
    /// Token authenticated and is usable enough to dispatch (note: an exhausted
    /// single-use token still passes the gate so `tools/list` works; the inner
    /// `tools/call` fails closed on its own).
    Ok,
    /// Reject with `401` — missing, unknown, revoked, or expired.
    Reject(&'static str),
}

/// Extract the Bearer secret from the `Authorization` header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Authenticate the inbound Bearer at the transport boundary. A `vut_` use token
/// is resolved from storage (revoked/expired ⇒ reject; exhausted ⇒ pass, the
/// inner handler is read/execute aware); any other secret is validated as an API
/// key. The token is **not** consumed here — consumption stays in
/// `execute_gated`, exactly as on stdio.
async fn gate_bearer(state: &AppState, secret: &str) -> BearerGate {
    if UseToken::looks_like_token(secret) {
        // Reload so a token minted by another process (the admin API mint flow,
        // i.e. govder's provisioner) is visible.
        let _ = state.storage.reload().await;
        let token = match state
            .storage
            .get_use_token_by_hash(&UseToken::hash(secret))
            .await
        {
            Ok(Some(t)) => t,
            Ok(None) => return BearerGate::Reject("unknown use token"),
            Err(_) => return BearerGate::Reject("storage error resolving use token"),
        };
        // Revoked / expired are hard rejects at the boundary (a revoked token is
        // the W2 kill leg — it must never dispatch). An exhausted single-use
        // token still authenticates: `tools/list` is a read, and `tools/call`
        // fails closed inside execute_gated.
        if token.revoked {
            return BearerGate::Reject("use token has been revoked");
        }
        if token.is_expired() {
            return BearerGate::Reject("use token has expired");
        }
        BearerGate::Ok
    } else {
        // API key (or one-time secret presented as a key). Validate against the
        // live auth manager.
        let manager = state.auth_manager.read().await;
        match manager.validate_key(secret) {
            Ok(_) => BearerGate::Ok,
            Err(_) => BearerGate::Reject("invalid API key"),
        }
    }
}

/// Inject the transport's authoritative Bearer secret into the JSON-RPC body so
/// the shared stdio handler — which reads the caller's secret from the body —
/// scopes the call to exactly this principal. The header token is authoritative:
/// any `api_key`/`token` the remote agent put in the body is OVERWRITTEN, so it
/// cannot act as a principal other than the one its header identifies.
///
/// - `tools/list`: secret goes in `params.api_key`.
/// - `tools/call`: secret goes in `params.arguments.api_key`.
/// - everything else (`initialize`, `ping`, notifications): left untouched.
fn inject_bearer(message: &mut serde_json::Value, secret: &str) {
    let Some(method) = message.get("method").and_then(|m| m.as_str()) else {
        return;
    };
    match method {
        "tools/list" => {
            let params = ensure_object(message, "params");
            params.insert("api_key".to_string(), serde_json::Value::String(secret.to_string()));
        }
        "tools/call" => {
            let params = ensure_object(message, "params");
            let args = params
                .entry("arguments")
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            if !args.is_object() {
                *args = serde_json::Value::Object(Default::default());
            }
            if let Some(obj) = args.as_object_mut() {
                obj.insert("api_key".to_string(), serde_json::Value::String(secret.to_string()));
            }
        }
        _ => {}
    }
}

/// Get (creating if needed) the named object field of `message`, returning a
/// mutable handle to its map.
fn ensure_object<'a>(
    message: &'a mut serde_json::Value,
    field: &str,
) -> &'a mut serde_json::Map<String, serde_json::Value> {
    let obj = message
        .as_object_mut()
        .expect("JSON-RPC message is a JSON object");
    let entry = obj
        .entry(field.to_string())
        .or_insert_with(|| serde_json::Value::Object(Default::default()));
    if !entry.is_object() {
        *entry = serde_json::Value::Object(Default::default());
    }
    entry.as_object_mut().expect("field was just set to an object")
}

/// A JSON-RPC `401`-style transport rejection, returned as an HTTP 401 with a
/// JSON-RPC error body so an MCP client surfaces it cleanly. The id is echoed
/// when present.
fn unauthorized(id: serde_json::Value, reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                // -32001: implementation-defined server error (MCP auth).
                "code": -32001,
                "message": format!("Unauthorized: {}", reason),
            }
        })),
    )
        .into_response()
}

/// `POST /mcp` — the networked JSON-RPC MCP endpoint.
///
/// Authenticates the caller via the `Authorization: Bearer …` header, scopes the
/// call to that principal by injecting the header token into the JSON-RPC body,
/// and dispatches through the SAME MCP handler used by stdio. A missing /
/// invalid / revoked / expired token is rejected `401` BEFORE any dispatch — it
/// is never bypassed.
pub async fn mcp_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Parse the JSON-RPC envelope first so we can echo its id on an auth error.
    let mut message: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                })),
            )
                .into_response();
        }
    };
    if !message.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": { "code": -32600, "message": "Invalid Request: expected a JSON object" }
            })),
        )
            .into_response();
    }
    let id = message.get("id").cloned().unwrap_or(serde_json::Value::Null);

    // Authenticate the inbound Bearer at the transport boundary (401 gate).
    let secret = match extract_bearer(&headers) {
        Some(s) => s,
        None => {
            return unauthorized(
                id,
                "Authorization header with a Bearer use-token (vut_) or API key is required",
            )
        }
    };
    if let BearerGate::Reject(reason) = gate_bearer(&state, &secret).await {
        return unauthorized(id, reason);
    }

    // Scope the call to this principal: the header token is authoritative and
    // overwrites any token the agent put in the body.
    inject_bearer(&mut message, &secret);

    // Vault-enumeration gate (GLM review #3). `resources/list` returns EVERY
    // credential's alias+description with no scope/tenant filter; `resources/read`
    // exposes a credential resource. A governed use-token (`vut_`) holds named
    // capabilities, not vault-enumeration rights — so block both for use-tokens at
    // the transport (the principal is known here from the Bearer). An admin API key
    // (`vk_`) keeps full access. (Matches UseToken::looks_like_token's `vut_`
    // prefix.)
    if secret.starts_with("vut_") {
        if let Some(method) = message.get("method").and_then(|m| m.as_str()) {
            match method {
                "resources/list" => {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "resources": [] }
                        })),
                    )
                        .into_response();
                }
                "resources/read" => {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32001, "message": "resource access is not permitted for a use-token (use your named tools)" }
                        })),
                    )
                        .into_response();
                }
                _ => {}
            }
        }
    }

    // Dispatch through the SAME handler stdio uses, off the web process's shared
    // execution server. `McpServer` is a cheap wrapper over the shared `Arc`s, so
    // building one per request is fine; the only mutable state it carries is the
    // `initialized` handshake flag, which the HTTP transport does not rely on.
    let mut mcp = McpServer::new(Arc::clone(&state.server), Arc::clone(&state.auth_manager));
    let message_str = message.to_string();
    match mcp.handle_jsonrpc(&message_str).await {
        // A normal JSON-RPC response (success OR a JSON-RPC error like a denied
        // tools/call) is HTTP 200 with the JSON-RPC body — the transport
        // succeeded; the JSON-RPC layer carries the per-call outcome.
        Some(response) => (StatusCode::OK, Json(response)).into_response(),
        // A notification (e.g. `initialized`) produces no response — 202 Accepted
        // with an empty body, per JSON-RPC-over-HTTP convention.
        None => StatusCode::ACCEPTED.into_response(),
    }
}
