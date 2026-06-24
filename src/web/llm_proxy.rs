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
//! ## Streaming (SSE)
//! A `{"stream": true}` request is forwarded **incrementally** as
//! `text/event-stream` (connector M1 streaming), engaged purely on the wire flag
//! and the operator kill-switch (`[llm_proxy] streaming_enabled`, default on; when
//! off, the stream flags are stripped and the turn is served buffered). The same
//! gate runs ([`crate::server::VultrinoServer::execute_gated_streaming`] shares
//! [`crate::server::VultrinoServer`]'s decision step with the buffered path), and
//! the streamed body passes through an INCREMENTAL egress scrub (a secret split
//! across SSE chunks is still caught) before reaching the agent.
//!
//! Metering on a streamed turn: V13a `api-calls=1` always fires (even on a halt or
//! disconnect); the V13b token event fires whenever a complete usage trailer was
//! parsed — including a client disconnect or upstream error AFTER the trailer arrived
//! (the parsed usage is carried into the finalizer's Drop), not only on a clean EOF.
//! For OpenAI-chat requests vultrino FORCES `stream_options.include_usage = true`
//! (gateway-owned — a client cannot opt out by sending `include_usage:false`) so the
//! provider emits that trailer; Anthropic `/v1/messages` and OpenAI `/v1/responses`
//! report usage natively. Honest residuals: a capability with an operator `block`/
//! `redact_patterns` egress rule, or a compressed response, is served BUFFERED
//! (incremental scrub can't honor those); a stream that is truncated/halted BEFORE the
//! usage trailer arrives meters V13a only.

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

/// Inbound request headers vultrino forwards verbatim to the provider. This is a
/// strict ALLOWLIST (not a denylist) so a new SDK header can never accidentally
/// smuggle the agent's vultrino Bearer, `Host`, `Content-Length`, or
/// `Accept-Encoding` upstream — only these named provider-protocol headers ride
/// along. Lower-cased for case-insensitive matching.
///
/// - `anthropic-version` is **required** by the Anthropic Messages API (a request
///   without it 400s), so dropping it (as the pre-streaming proxy did) made the
///   Anthropic provider unusable. `anthropic-beta` opts into beta features.
/// - `openai-beta` / `openai-organization` / `openai-project` route/scope an
///   OpenAI request when the SDK sets them.
const FORWARDED_PROVIDER_HEADERS: &[&str] = &[
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
    "openai-organization",
    "openai-project",
];

/// Copy the allowlisted provider-protocol headers from the inbound request into
/// the forwarded header map. Never copies auth/transport headers (the allowlist
/// excludes them by construction); the vault credential is injected downstream by
/// the http plugin.
fn forward_provider_headers(inbound: &HeaderMap, fwd: &mut HashMap<String, String>) {
    for &name in FORWARDED_PROVIDER_HEADERS {
        if let Some(value) = inbound.get(name).and_then(|v| v.to_str().ok()) {
            let value = value.trim();
            if !value.is_empty() {
                fwd.insert(name.to_string(), value.to_string());
            }
        }
    }
}

/// Whether the inbound proxy path targets an OpenAI **chat/completions**-style
/// endpoint (so `stream_options.include_usage` injection is appropriate). Matches
/// `…/chat/completions` and the legacy `…/completions`; excludes `/v1/responses`
/// and Anthropic `/v1/messages`, which report streamed usage natively.
fn is_openai_chat_path(path: &str) -> bool {
    path.trim_end_matches('/').ends_with("/completions")
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

/// Clamp the request body's `max_tokens` to `ceiling` — `min(requested, ceiling)`,
/// or SET it to `ceiling` when the request omits it (so the provider default can't
/// exceed the per-call output bound). v1 handles only the OpenAI-compatible
/// top-level `max_tokens` field; a non-object body is left untouched.
fn clamp_max_output_tokens(body: &mut serde_json::Value, ceiling: u64) {
    if let Some(obj) = body.as_object_mut() {
        let clamped = obj
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .map_or(ceiling, |req| req.min(ceiling));
        obj.insert("max_tokens".to_string(), serde_json::json!(clamped));
    }
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

    // 3. Build the upstream provider URL (provider_base + inbound path). NOTE (v1):
    //    the inbound query string is NOT forwarded — axum's {*path} captures only the
    //    path, and `query` is sent as {} below. (Earlier docs wrongly claimed query
    //    preservation; corrected per review. Forwarding query is a future enhancement
    //    and would re-run the same scheme/host/port + prefix containment.)
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
    let mut request_body: Option<serde_json::Value> = if body.is_empty() {
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

    // 4b. Per-model enforcement (connector P1-1): when the capability restricts
    //     models (non-empty allowed_models), the request body's `model` must be in
    //     the allowlist. An EMPTY allowlist permits any model (per-provider scope
    //     only). An allowlisted channel whose request carries NO parseable `model`
    //     fails CLOSED (default-deny symmetry) — we never forward an unverifiable
    //     model upstream with the vault key attached. This is the PEP for govder's
    //     `llm.allowed_models`; the deny happens BEFORE any upstream call. It runs
    //     ABOVE the streaming decision (4d) so a `stream:true` request can NOT evade
    //     the model allowlist — buffered and streaming enforce identically.
    let requested_model = request_body
        .as_ref()
        .and_then(|b| b.get("model"))
        .and_then(|m| m.as_str());
    if !capability.llm_model_allowed(requested_model) {
        return llm_error(
            StatusCode::FORBIDDEN,
            "permission_error",
            &format!(
                "Model {} is not permitted for this LLM-proxy capability",
                requested_model
                    .map(|m| format!("'{m}'"))
                    .unwrap_or_else(|| "(unspecified)".to_string()),
            ),
        );
    }

    // 4c. Per-call output-token ceiling (rate_companion per-call leg, P1-8): clamp the
    //     request body's `max_tokens` to the capability's ceiling — `min(requested,
    //     ceiling)`, and SET it to the ceiling when the request omits it so the
    //     provider default can't exceed it. This bounds per-call output tokens (hence
    //     per-call cost), the enforceable substitute for a SpendCap (which fails closed
    //     on an LLM request that carries no request-time spend). Only the common
    //     OpenAI-compatible `max_tokens` field is handled in v1. Runs ABOVE the
    //     streaming decision (4d) + usage injection, so it clamps the body BOTH the
    //     buffered and streaming paths forward — `stream:true` can NOT evade the cap.
    if let Some(ceiling) = capability.llm_max_output_tokens() {
        if let Some(body) = request_body.as_mut() {
            clamp_max_output_tokens(body, ceiling);
        }
    }

    // 4d. Decide buffered vs streaming. Streaming engages purely on the wire flag
    //     `{"stream": true}` and the operator kill-switch. When streaming is
    //     DISABLED but the client asked for it, strip the stream flags so the
    //     upstream returns a single JSON body served on the buffered path — never a
    //     buffered `text/event-stream` blob, which would break the client's SSE
    //     parser. Runs AFTER 4b/4c so the model allowlist + max_output_tokens clamp
    //     already applied to the body that the streaming path forwards.
    let streaming_requested = request_body
        .as_ref()
        .and_then(|b| b.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    let streaming_enabled = state.config.llm_proxy.streaming_enabled;
    let use_streaming = streaming_requested && streaming_enabled;
    if streaming_requested && !streaming_enabled {
        if let Some(obj) = request_body.as_mut().and_then(|b| b.as_object_mut()) {
            obj.remove("stream");
            obj.remove("stream_options");
        }
    }
    // When streaming an OpenAI-chat request, force `stream_options.include_usage = true`
    // so the provider emits a terminal usage chunk and a streamed turn still meters V13b
    // token counts. include_usage is GATEWAY-OWNED — a client cannot opt out of the token
    // trailer (sending `include_usage:false` would otherwise evade token metering), so
    // maybe_inject_stream_usage overwrites a client false. Anthropic `/v1/messages` and
    // OpenAI `/v1/responses` report usage natively, so they are excluded (an unknown
    // `stream_options` field could be rejected).
    if use_streaming && state.config.llm_proxy.inject_stream_usage && is_openai_chat_path(&path) {
        if let Some(b) = request_body.as_mut() {
            crate::outbox::maybe_inject_stream_usage(b);
        }
    }

    // Forward Content-Type plus a curated ALLOWLIST of provider protocol headers
    // (e.g. Anthropic's REQUIRED `anthropic-version`). The credential
    // (Authorization / API-key header) is injected by the http plugin from the
    // vault. The agent's own Authorization header is the vultrino Bearer — it must
    // NOT be forwarded upstream — so we copy only the named protocol headers and
    // never a blanket set. See [`forward_provider_headers`].
    let mut fwd_headers: HashMap<String, String> = HashMap::new();
    fwd_headers.insert("Content-Type".to_string(), "application/json".to_string());
    forward_provider_headers(&headers, &mut fwd_headers);

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

    // 6. Streaming path: forward the upstream SSE body incrementally. The gate is
    //    identical to the buffered path; only the response body delivery differs.
    if use_streaming {
        return match state
            .server
            .execute_gated_streaming(execute_request, exec_auth)
            .await
        {
            Ok(crate::server::StreamingOutcome::Streaming(exec)) => {
                let status =
                    StatusCode::from_u16(exec.status).unwrap_or(StatusCode::BAD_GATEWAY);
                // Preserve the provider Content-Type (e.g. text/event-stream) so the
                // client's SSE parser engages; default to event-stream for a streamed
                // turn that didn't echo one.
                let content_type = exec
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "text/event-stream".to_string());
                (
                    status,
                    [(header::CONTENT_TYPE, content_type)],
                    axum::body::Body::from_stream(exec.body),
                )
                    .into_response()
            }
            Ok(crate::server::StreamingOutcome::Pending(approval)) => llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!(
                    "This model request requires human approval and did not run (approval {})",
                    approval.id
                ),
            ),
            Err(e) => {
                // Same no-leak posture as the buffered Err path: the scrub hasn't run
                // on a pre-stream Err, so never echo the upstream detail to the agent.
                tracing::warn!(error = %e, "LLM proxy upstream stream failed");
                llm_error(
                    StatusCode::BAD_GATEWAY,
                    "api_error",
                    "LLM proxy upstream request failed (see server logs)",
                )
            }
        };
    }

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

#[cfg(test)]
mod tests {
    use super::clamp_max_output_tokens;
    use serde_json::json;

    #[test]
    fn clamps_an_over_ceiling_request_down() {
        let mut body = json!({ "model": "gpt-4o", "max_tokens": 5000 });
        clamp_max_output_tokens(&mut body, 1000);
        assert_eq!(body["max_tokens"], json!(1000));
    }

    #[test]
    fn leaves_an_under_ceiling_request_unchanged() {
        let mut body = json!({ "model": "gpt-4o", "max_tokens": 200 });
        clamp_max_output_tokens(&mut body, 1000);
        assert_eq!(body["max_tokens"], json!(200));
    }

    #[test]
    fn sets_the_ceiling_when_the_request_omits_max_tokens() {
        // The dangerous case: an absent max_tokens lets the provider default (often
        // very large) blow the per-call cost bound. We must SET it to the ceiling.
        let mut body = json!({ "model": "gpt-4o", "messages": [] });
        clamp_max_output_tokens(&mut body, 1000);
        assert_eq!(body["max_tokens"], json!(1000));
    }

    #[test]
    fn ignores_a_non_object_body() {
        let mut body = json!("not an object");
        clamp_max_output_tokens(&mut body, 1000);
        assert_eq!(body, json!("not an object"));
    }
}
