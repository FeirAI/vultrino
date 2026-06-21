//! Networked LLM proxy (connector M1, decision 5).
//!
//! A harness's model endpoint (hermes `config.yaml` `model.base_url`) is pointed
//! at vultrino's `POST /llm` so the **provider model key never leaves the vault**
//! and token spend is **metered** (V13). The harness keeps speaking the
//! OpenAI-compatible wire protocol; vultrino is a transparent reverse proxy that:
//!
//! 1. **authenticates** the inbound `Authorization: Bearer <vut_|vk_>` (the same
//!    use-token the harness uses for `/mcp`),
//! 2. resolves the principal's single **LLM-proxy capability**
//!    ([`crate::capability::Capability::is_llm_proxy`]) — the bound model channel,
//! 3. forwards the request body to `provider_base` + the inbound path (e.g.
//!    `/v1/chat/completions`), **injecting the vault credential** referenced by the
//!    capability via the SAME enforced path the named tools use
//!    ([`crate::server::VultrinoServer::execute_gated`] → `run_action`):
//!    default-deny policy, single-use token consumption, V7 egress scrub (so no
//!    model key ever reflects back to the agent), and the V13a/V13b leria emits,
//! 4. returns the provider's response body + status **verbatim** so the harness's
//!    OpenAI client sees a normal completion.
//!
//! ## Why metering "just works"
//! [`crate::server::VultrinoServer`]'s `run_action` already reads the provider
//! `usage` block from the RAW response body (pre-scrub) and emits BOTH the V13a
//! `api-calls=1` event and — for a non-streamed response carrying a usage split —
//! the V13b `asset=usd` + `tokens{input,output}` + `dims.model_ref` event that
//! leria PRICES. The proxy only has to drive that path with the agent's body; the
//! token accounting is automatic and identical to any other metered action.
//!
//! ## Honest non-streaming caveat (carried, not hidden)
//! vultrino buffers the upstream response whole (no SSE/streaming on the LLM
//! path). A streamed completion (`{"stream": true}`) omits the `usage` object
//! unless the client sets `stream_options.include_usage`, so for a streamed turn
//! ONLY the V13a `api-calls=1` event fires (token counts are non-streaming-only).
//! This is the documented v1 limitation (decision 5 / ARCHITECTURE caveats):
//! prefer non-streamed for metered agents. The proxy still works for a streamed
//! request — it buffers and returns the body — it just can't count tokens on it.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;

use crate::auth::UseToken;
use crate::server::ExecAuth;
use crate::{ExecuteRequest, ExecutionOutcome};

use super::server::AppState;

/// Extract the Bearer secret (use token `vut_` or API key `vk_`) from the
/// `Authorization` header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A JSON error response shaped like an OpenAI API error so the harness's model
/// client surfaces it cleanly rather than as an opaque transport failure.
fn llm_error(status: StatusCode, kind: &str, message: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "error": {
                "type": kind,
                "message": message,
            }
        })),
    )
        .into_response()
}

/// Resolve the inbound Bearer to an [`ExecAuth`] (authenticate only; the
/// capability's credential/action scope is enforced authoritatively inside
/// `execute_gated`). A `vut_` is resolved from storage (reloaded so a token
/// minted by govder's provisioner in the admin process is visible); anything else
/// is validated as an API key.
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
                return Err(llm_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_request_error",
                    "Invalid use token",
                ))
            }
        };
        if let Err(e) = token.check_usable() {
            return Err(llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!("Use token cannot be used: {e}"),
            ));
        }
        Ok(ExecAuth::from_use_token(token))
    } else {
        let manager = state.auth_manager.read().await;
        match manager.validate_key(secret) {
            Ok((key, role)) => Ok(ExecAuth::from_api_key(crate::auth::AuthResult {
                api_key: key,
                role,
            })),
            Err(e) => Err(llm_error(
                StatusCode::UNAUTHORIZED,
                "invalid_request_error",
                &format!("Invalid API key: {e}"),
            )),
        }
    }
}

/// `POST /llm` — the metered LLM proxy with no extra path (the provider URL is
/// the capability's `provider_base` verbatim). Delegates to [`llm_proxy_impl`].
pub async fn llm_proxy_root(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, String::new(), headers, body).await
}

/// `POST /llm/{*path}` — the metered LLM proxy.
///
/// The harness points its model `base_url` at `https://vultrino.../llm`; its
/// OpenAI client appends the route path (e.g. `/v1/chat/completions`), which is
/// captured as `path` and joined onto the bound capability's `provider_base`. The
/// request body is forwarded verbatim with the vault key injected; the response
/// is returned verbatim (post egress-scrub); token spend is metered.
pub async fn llm_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, path, headers, body).await
}

/// Shared implementation for both `/llm` and `/llm/{*path}`.
async fn llm_proxy_impl(
    state: AppState,
    path: String,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. Authenticate the inbound Bearer (the harness's use token / API key).
    let secret = match extract_bearer(&headers) {
        Some(s) => s,
        None => {
            return llm_error(
                StatusCode::UNAUTHORIZED,
                "invalid_request_error",
                "Authorization header with a Bearer use-token (vut_) or API key is required",
            )
        }
    };
    let exec_auth = match resolve_exec_auth(&state, &secret).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // 2. Resolve the principal's bound LLM-proxy capability — the model channel.
    //    Reuses the SAME default-deny enforcement the named tools use, so an agent
    //    can only route model traffic through a capability it is actually granted.
    let capability = match state
        .server
        .resolve_llm_proxy_for(exec_auth.auth.as_ref())
        .await
    {
        Some(c) => c,
        None => {
            return llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                "No LLM-proxy capability is provisioned for this principal",
            )
        }
    };

    // 3. Build the upstream provider URL (provider_base + inbound path). A query
    //    string on the original request is preserved by appending it to the path.
    let upstream = match capability.llm_upstream_url(&path) {
        Some(u) => u,
        None => {
            return llm_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "LLM-proxy capability has no valid provider URL",
            )
        }
    };

    // 4. Parse the agent's request body as JSON (OpenAI-compatible). An empty body
    //    is allowed (some endpoints take none); a non-JSON body is rejected so we
    //    never forward garbage upstream with the vault key attached.
    let request_body: Option<serde_json::Value> = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => Some(v),
            Err(e) => {
                return llm_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("Request body must be valid JSON: {e}"),
                )
            }
        }
    };

    // Forward Content-Type only; the credential (Authorization / API-key header)
    // is injected by the http plugin from the vault. The agent's own
    // Authorization header is the vultrino Bearer — it must NOT be forwarded
    // upstream (the http plugin sets the provider auth header itself), so we do
    // not copy inbound headers.
    let mut fwd_headers: HashMap<String, String> = HashMap::new();
    fwd_headers.insert("Content-Type".to_string(), "application/json".to_string());

    // 5. Drive the action through the SAME enforced path the named tools use. The
    //    capability's action label (V8) is enforced + resolved by execute_gated;
    //    the http plugin injects the vault credential, scrubs the response, and
    //    run_action emits the V13a/V13b meter events from the RAW provider body.
    let execute_request = ExecuteRequest {
        credential: capability.credential_ref.clone(),
        action: capability.action.clone(),
        params: serde_json::json!({
            "method": "POST",
            "url": upstream,
            "headers": fwd_headers,
            "body": request_body,
            "query": {},
        }),
    };

    match state.server.execute_gated(execute_request, exec_auth).await {
        Ok(ExecutionOutcome::Completed(response)) => {
            // Return the provider body + status verbatim (post egress-scrub, so no
            // model key ever reflects back). Preserve the provider Content-Type so
            // the harness's OpenAI client parses it correctly.
            let status =
                StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "application/json".to_string());
            (
                status,
                [(header::CONTENT_TYPE, content_type)],
                response.body,
            )
                .into_response()
        }
        // An LLM call should never be approval-gated in practice, but if a policy
        // routes it to approval, surface that honestly rather than silently
        // dropping the turn.
        Ok(ExecutionOutcome::Pending(approval)) => llm_error(
            StatusCode::FORBIDDEN,
            "permission_error",
            &format!(
                "This model request requires human approval and did not run (approval {})",
                approval.id
            ),
        ),
        Err(e) => {
            // Do NOT echo the upstream error detail to the agent: on a plugin Err
            // the egress scrub (which runs on the Ok path) has NOT run, so a
            // secret-bearing upstream body (e.g. an OAuth token-endpoint error that
            // echoes the token) could leak through `{e}`. Log the detail
            // server-side; return a generic message. (GLM review #6.)
            tracing::warn!(error = %e, "LLM proxy upstream request failed");
            llm_error(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "LLM proxy upstream request failed (see server logs)",
            )
        }
    }
}
