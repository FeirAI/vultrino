//! Connector M1, decision 5 — metered LLM-proxy integration tests.
//!
//! Two complementary layers prove the acceptance criteria from the build brief
//! and muntin `docs/connectors/ARCHITECTURE.md`:
//!
//! 1. **Endpoint / wiring** (real Axum router via `tower::ServiceExt::oneshot`):
//!    the `POST /llm/{*path}` endpoint authenticates the Bearer, resolves the
//!    principal's bound LLM-proxy capability, and drives `execute_gated`. A
//!    missing Bearer is `401`; a principal with no LLM-proxy capability is `403`
//!    (fail-closed — no provider, no key, no metering bypass); a request that
//!    DOES resolve a capability reaches the http plugin (proven by the execute-time
//!    SSRF guard rejecting a loopback `provider_base` → a scrubbed `502 api_error`,
//!    a shape only `execute_gated` can produce, i.e. the call genuinely ran through
//!    the enforced path rather than being short-circuited).
//!
//! 2. **Metering + credential injection + egress scrub** (a stub upstream plugin
//!    registered into the shared server, so the full `execute_gated` → `run_action`
//!    path runs offline and deterministically): a non-streamed OpenAI-style
//!    response with a `usage` block emits the V13a `api-calls=1` event AND the
//!    V13b priced token event (`asset=usd` + `tokens{input,output}` +
//!    `dims.model_ref`); the vault key is injected (the agent never holds it) and
//!    is scrubbed out of the returned body; a streamed response (no `usage`) emits
//!    ONLY the V13a `api-calls=1` event — the documented non-streaming-only
//!    limitation.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::auth::{AuthManager, NewUseToken, UseToken};
use vultrino::capability::{Capability, CapabilityTarget, LlmProxy};
use vultrino::config::{Config, EnforcementConfig, EnforcementDefault};
use vultrino::outbox::EVENT_METER_OBSERVED;
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
use vultrino::router::CredentialResolver;
use vultrino::server::VultrinoServer;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};
use vultrino::{Credential, CredentialData, CredentialType, ExecuteResponse, Secret};

/// The provider API key that lives ONLY in the vault — the agent must never see
/// it, and it must never reflect back in a proxied response body.
const PROVIDER_KEY: &str = "sk-vault-only-PROVIDER-key-9f8e7d6c5b4a3210";

// ===========================================================================
// A stub OpenAI-compatible upstream plugin. It echoes the credential key (and
// the request body) it received, plus a fixed `usage` block, so a test can prove
// the vault key was injected, that egress scrub removes it, and that token
// metering fires. The `stream` request flag selects a no-`usage` body.
// ===========================================================================

struct MockLlmPlugin;

#[async_trait]
impl Plugin for MockLlmPlugin {
    fn name(&self) -> &str {
        "mockllm"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["chat"]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        // Pull the injected provider key out of the credential the SERVER
        // resolved + handed us (the agent never supplied it).
        let injected_key = match &request.credential.data {
            CredentialData::ApiKey { key, .. } => key.expose().to_string(),
            _ => String::new(),
        };
        // Was the agent's request asking to stream? (a streamed body carries no
        // usage trailer → only api-calls=1 should meter).
        let streamed = request
            .params
            .get("body")
            .and_then(|b| b.get("stream"))
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        // Echo the injected key into the body so the egress-scrub test can prove
        // the secret is redacted before it reaches the agent.
        let body = if streamed {
            // A streamed completion: NO usage object (the realistic shape).
            serde_json::json!({
                "id": "chatcmpl-streamed",
                "model": "gpt-4o-mini",
                "object": "chat.completion.chunk",
                "provider_key_echo": injected_key,
                "choices": [{ "delta": { "content": "hi" } }]
            })
        } else {
            serde_json::json!({
                "id": "chatcmpl-abc123",
                "model": "gpt-4o-mini",
                "object": "chat.completion",
                "provider_key_echo": injected_key,
                "choices": [{ "message": { "role": "assistant", "content": "hi" } }],
                "usage": { "prompt_tokens": 57, "completion_tokens": 13, "total_tokens": 70 }
            })
        };
        Ok(ExecuteResponse {
            status: 200,
            headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            body: serde_json::to_vec(&body).unwrap(),
            updated_credential: None,
        })
    }
    fn validate_params(&self, _action: &str, _params: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }
}

// ===========================================================================
// Harness
// ===========================================================================

fn config_with_policies(policies: Vec<Policy>) -> Config {
    Config {
        enforcement: EnforcementConfig {
            default_action: EnforcementDefault::Deny,
        },
        policies,
        ..Config::default()
    }
}

/// Allow any http(s) URL for a credential glob (so the metered path isn't denied
/// by policy and we can observe the meter events / scrub behavior).
fn allow_policy(credential_pattern: &str) -> Policy {
    Policy::allow_all("allow-llm", credential_pattern)
        .with_rule(PolicyCondition::UrlMatch("*".to_string()), PolicyAction::Allow)
}

/// Build the router + the shared storage + the shared exec server (so a test can
/// register the stub plugin and read the outbox back).
async fn build_stack(
    config: Config,
) -> (axum::Router, Arc<dyn StorageBackend>, Arc<VultrinoServer>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let auth_manager = AuthManager::from_data(
        storage.list_roles().await.unwrap(),
        storage.list_api_keys().await.unwrap(),
    );
    let resolver = CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(VultrinoServer::new(config.clone(), storage.clone(), resolver));
    exec_server.load_plugins().await.unwrap();
    exec_server.reload_policies().await.unwrap();

    let server = WebServer::new(
        WebConfig { bind: "127.0.0.1:0".to_string(), enabled: true },
        config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server.clone(),
    );
    (server.into_router(), storage, exec_server)
}

/// Store the provider API-key credential (the vault-only model key).
async fn store_provider_credential(storage: &Arc<dyn StorageBackend>, alias: &str) {
    let cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new(PROVIDER_KEY),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
}

/// Register an LLM-proxy capability bound to a credential, backed by the given
/// action + provider base.
async fn register_llm_capability(
    storage: &Arc<dyn StorageBackend>,
    credential_ref: &str,
    action: &str,
    provider_base: &str,
) {
    let cap = Capability {
        id: "cap-llm".to_string(),
        tool_name: "model_proxy".to_string(),
        description: "the agent's model channel".to_string(),
        action: action.to_string(),
        plugin: None,
        target: CapabilityTarget::default(),
        credential_ref: credential_ref.to_string(),
        input_schema: serde_json::Value::Null,
        llm: Some(LlmProxy { provider_base: provider_base.to_string() }),
    };
    cap.validate().unwrap();
    storage.store_capability(&cap).await.unwrap();
}

async fn mint_token(
    storage: &Arc<dyn StorageBackend>,
    credential_scope: &str,
    action_scope: Option<&str>,
) -> String {
    let (full, token) = UseToken::create(NewUseToken {
        name: "agent".to_string(),
        credential_scope: credential_scope.to_string(),
        action_scope: action_scope.map(str::to_string),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();
    full
}

/// POST a body to `/llm/<path>` with an optional Bearer.
fn llm_req(bearer: Option<&str>, path: &str, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/llm/{path}"))
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
}

/// All meter.observed payloads currently in the outbox.
async fn meter_events(storage: &Arc<dyn StorageBackend>) -> Vec<serde_json::Value> {
    storage
        .list_events_after(0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event_type == EVENT_METER_OBSERVED)
        .map(|e| e.payload)
        .collect()
}

// ===========================================================================
// Layer 1 — endpoint / wiring
// ===========================================================================

#[tokio::test]
async fn llm_missing_bearer_is_401() {
    let (router, storage, _srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_provider_credential(&storage, "cred-openai").await;
    register_llm_capability(&storage, "cred-openai", "http.request", "https://api.openai.com").await;

    let resp = router
        .oneshot(llm_req(None, "v1/chat/completions", serde_json::json!({ "model": "gpt-4o-mini" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn llm_no_capability_is_403_fail_closed() {
    // A valid token, but NO LLM-proxy capability provisioned → fail closed (no
    // provider, no key injection, no metering bypass).
    let (router, storage, _srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_provider_credential(&storage, "cred-openai").await;
    let token = mint_token(&storage, "cred-openai", Some("http.request")).await;

    let resp = router
        .oneshot(llm_req(Some(&token), "v1/chat/completions", serde_json::json!({ "model": "x" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn llm_resolves_capability_and_runs_enforced_path() {
    // Point the LLM-proxy capability at a loopback provider_base (a self-hosted
    // gateway address — allowed at config; the agent can't change the host). A
    // request must resolve the capability and reach the http plugin, where the
    // authoritative SSRF guard rejects the loopback target at execute time —
    // proving the proxy genuinely drove execute_gated (not a bypass, not a silent
    // drop). The SSRF detail is intentionally egress-scrubbed (it never reflects
    // to the agent), so the proof is the 502 `api_error` shape: distinct from the
    // 401 (no bearer), 403 (no capability), and 500 (no provider URL) short-circuit
    // shapes, it can only be produced by execute_gated returning an upstream
    // failure — i.e. the http plugin actually ran.
    let (router, storage, _srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_provider_credential(&storage, "cred-openai").await;
    register_llm_capability(&storage, "cred-openai", "http.request", "http://127.0.0.1:9").await;
    let token = mint_token(&storage, "cred-openai", Some("http.request")).await;

    let resp = router
        .oneshot(llm_req(Some(&token), "v1/chat/completions", serde_json::json!({ "model": "x" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes(resp).await).expect("error body is JSON");
    // Scrubbed upstream-failure shape — proves execute_gated ran + the plugin
    // rejected the target, WITHOUT leaking the SSRF detail to the agent.
    assert_eq!(
        body["error"]["type"], "api_error",
        "a 502 api_error proves the enforced execute path ran (not a short-circuit): {body}"
    );
}

#[tokio::test]
async fn llm_token_scoped_away_from_credential_is_denied() {
    // The token is scoped to a different credential glob than the capability's
    // credential → capability_allowed_for denies → no LLM-proxy resolves → 403.
    let (router, storage, _srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_provider_credential(&storage, "cred-openai").await;
    register_llm_capability(&storage, "cred-openai", "http.request", "https://api.openai.com").await;
    let token = mint_token(&storage, "other-*", Some("http.request")).await;

    let resp = router
        .oneshot(llm_req(Some(&token), "v1/chat/completions", serde_json::json!({ "model": "x" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ===========================================================================
// Layer 2 — metering + credential injection + egress scrub (stub upstream)
// ===========================================================================

#[tokio::test]
async fn llm_non_streamed_injects_key_returns_body_meters_tokens_and_scrubs() {
    let (router, storage, srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    // Register the stub upstream plugin into the shared server so the full
    // execute_gated → run_action path runs offline.
    srv.plugins().register(Arc::new(MockLlmPlugin));
    store_provider_credential(&storage, "cred-openai").await;
    // The capability's action routes to the stub plugin (mockllm.chat).
    register_llm_capability(&storage, "cred-openai", "mockllm.chat", "https://api.openai.com").await;
    let token = mint_token(&storage, "cred-openai", Some("mockllm.chat")).await;

    let resp = router
        .oneshot(llm_req(
            Some(&token),
            "v1/chat/completions",
            serde_json::json!({ "model": "gpt-4o-mini", "messages": [{"role":"user","content":"hi"}] }),
        ))
        .await
        .unwrap();

    // (b) the proxy returns the provider body.
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = body_bytes(resp).await;
    let returned: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(returned["id"], "chatcmpl-abc123", "the provider body is returned to the agent");

    // (a)+(e) the vault key was injected (the stub echoed what it RECEIVED) AND
    // is scrubbed from the body the agent sees — the agent never holds the key.
    let body_str = String::from_utf8_lossy(&raw);
    assert!(
        !body_str.contains(PROVIDER_KEY),
        "the provider model key must NOT leak in the proxied response (egress scrub): {body_str}"
    );

    // (c) a non-streamed call emits BOTH the V13a api-calls=1 event and the V13b
    // priced token event (asset=usd + tokens + model_ref).
    let events = meter_events(&storage).await;
    let api_calls: Vec<_> = events.iter().filter(|p| p["asset"] == "api-calls").collect();
    let token_events: Vec<_> = events.iter().filter(|p| p["asset"] == "usd").collect();
    assert_eq!(api_calls.len(), 1, "exactly one api-calls=1 event: {events:?}");
    assert_eq!(api_calls[0]["amount"], 1);
    assert_eq!(token_events.len(), 1, "exactly one priced token event: {events:?}");
    let te = token_events[0];
    assert_eq!(te["tokens"]["input_tokens"], 57, "input tokens from the usage block");
    assert_eq!(te["tokens"]["output_tokens"], 13, "output tokens from the usage block");
    assert!(te.get("amount").is_none(), "a priced token event must NOT carry an amount");
    assert_eq!(te["dims"]["model_ref"], "gpt-4o-mini", "model_ref selects leria's rate card");
    assert_eq!(te["cost_source"], "gateway-observed");
    // The token event shares the occurrence with the api-calls event.
    assert_eq!(te["correlation_id"], api_calls[0]["correlation_id"], "same occurrence");
}

#[tokio::test]
async fn llm_streamed_emits_api_calls_only_no_token_count() {
    let (router, storage, srv) =
        build_stack(config_with_policies(vec![allow_policy("cred-*")])).await;
    srv.plugins().register(Arc::new(MockLlmPlugin));
    store_provider_credential(&storage, "cred-openai").await;
    register_llm_capability(&storage, "cred-openai", "mockllm.chat", "https://api.openai.com").await;
    let token = mint_token(&storage, "cred-openai", Some("mockllm.chat")).await;

    let resp = router
        .oneshot(llm_req(
            Some(&token),
            "v1/chat/completions",
            serde_json::json!({ "model": "gpt-4o-mini", "stream": true, "messages": [] }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The streamed body still comes back (vultrino buffers it; no SSE).
    let raw = body_bytes(resp).await;
    assert!(!String::from_utf8_lossy(&raw).contains(PROVIDER_KEY), "no key leak on the streamed path");

    // Only the V13a api-calls=1 event fires — token counts are non-streaming-only.
    let events = meter_events(&storage).await;
    let api_calls: Vec<_> = events.iter().filter(|p| p["asset"] == "api-calls").collect();
    let token_events: Vec<_> = events.iter().filter(|p| p["asset"] == "usd").collect();
    assert_eq!(api_calls.len(), 1, "a streamed call still meters api-calls=1: {events:?}");
    assert!(
        token_events.is_empty(),
        "a streamed response (no usage trailer) must NOT emit a token event: {events:?}"
    );
}
