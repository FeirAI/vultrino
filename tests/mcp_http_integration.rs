//! Connector M1 — networked HTTP MCP transport integration tests.
//!
//! Exercises the real Axum router's `POST /mcp` endpoint via
//! `tower::ServiceExt::oneshot` (no socket bound), verifying the acceptance
//! criteria from feir-os `docs/connectors/ARCHITECTURE.md`:
//!
//! - an HTTP JSON-RPC `tools/list` with a valid `vut_` Bearer returns ONLY that
//!   principal's granted named tools + `check_approval` (a scoped use-token agent
//!   is not offered vultrino's generic built-in tools — the connector model);
//! - a missing / invalid / revoked / expired token is rejected `401`, never
//!   bypassed;
//! - a `tools/call` over HTTP runs the SAME enforced `execute_gated` path;
//! - the header Bearer is authoritative — a different token smuggled in the JSON
//!   body cannot widen scope (the header token both authenticates AND scopes).
//!
//! `stdio` MCP is covered by `capability_mcp_integration.rs` (the same handler),
//! which proves stdio still works after the transport refactor.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::auth::{AuthManager, NewUseToken, UseToken};
use vultrino::capability::{Capability, CapabilityTarget};
use vultrino::config::{Config, EnforcementConfig, EnforcementDefault};
use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
use vultrino::router::CredentialResolver;
use vultrino::server::VultrinoServer;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};
use vultrino::{Credential, CredentialData, Secret};

/// A default-deny config carrying the given static policies.
fn config_with_policies(policies: Vec<Policy>) -> Config {
    Config {
        enforcement: EnforcementConfig {
            default_action: EnforcementDefault::Deny,
        },
        policies,
        ..Config::default()
    }
}

/// An allow policy admitting a credential glob for any https URL.
fn allow_policy(credential_pattern: &str) -> Policy {
    Policy::allow_all("allow-cap", credential_pattern).with_rule(
        PolicyCondition::UrlMatch("https://*".to_string()),
        PolicyAction::Allow,
    )
}

/// Build a web router whose shared exec server has plugins loaded and the given
/// policies merged into the engine, returning the router plus the shared storage.
async fn build_router_with(config: Config) -> (axum::Router, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the vault alive for the test's lifetime

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let auth_manager = AuthManager::from_data(
        storage.list_roles().await.unwrap(),
        storage.list_api_keys().await.unwrap(),
    );
    let resolver = CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    exec_server.load_plugins().await.unwrap();
    exec_server.reload_policies().await.unwrap();

    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    );
    (server.into_router(), storage)
}

/// Store an api-key credential whose secret is long enough to be egress-scrubbed.
async fn store_credential(storage: &Arc<dyn StorageBackend>, alias: &str) {
    let cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("SG.super-secret-sendgrid-key-1234567890"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
}

/// Register the standard "send_email" HTTP capability against a credential.
async fn register_send_email(storage: &Arc<dyn StorageBackend>, credential_ref: &str) {
    let cap = Capability {
        id: "cap-send-email".to_string(),
        tool_name: "send_email".to_string(),
        description: "Send an email via the provider".to_string(),
        action: "http.request".to_string(),
        plugin: Some("http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("https://api.sendgrid.example/v3/mail/send".to_string()),
            methods: vec!["POST".to_string()],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: credential_ref.to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "body": { "type": "object" } },
            "required": ["body"]
        }),
        reversibility: "reversible".to_string(),
        llm: None,
        approval_preview: None,
    };
    storage.store_capability(&cap).await.unwrap();
}

/// Mint a use token scoped to a credential glob + action; persist it and return
/// the plaintext `vut_…` the agent presents in the Authorization header.
async fn mint_token(
    storage: &Arc<dyn StorageBackend>,
    credential_scope: &str,
    action_scope: Option<&str>,
    expires_in: Option<chrono::Duration>,
    max_uses: Option<u32>,
) -> String {
    let (full, token) = UseToken::create(NewUseToken {
        name: "agent".to_string(),
        credential_scope: credential_scope.to_string(),
        action_scope: action_scope.map(str::to_string),
        max_uses,
        require_approval: false,
        expires_in,
    });
    storage.store_use_token(&token).await.unwrap();
    full
}

/// POST a JSON-RPC message to `/mcp` with an optional `Authorization: Bearer`.
fn mcp_req(bearer: Option<&str>, message: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {}", token));
    }
    builder
        .body(Body::from(serde_json::to_vec(&message).unwrap()))
        .unwrap()
}

async fn body_value(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn http_rejects_unsupported_protocol_version_and_cross_origin_requests() {
    let (router, _) = build_router_with(config_with_policies(vec![])).await;
    // A malformed (non-date-shaped) version header is still rejected outright.
    let mut bad_version = mcp_req(
        None,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    bad_version
        .headers_mut()
        .insert("mcp-protocol-version", "not-a-version".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(bad_version).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    // A well-formed but UNKNOWN (newer) version is negotiated down, not rejected:
    // real SDKs stamp their own LATEST on every request regardless of what
    // initialize negotiated (e.g. the python `mcp` client's 2025-11-25).
    let mut newer_version = mcp_req(
        None,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    newer_version
        .headers_mut()
        .insert("mcp-protocol-version", "2099-01-01".parse().unwrap());
    assert_ne!(
        router.clone().oneshot(newer_version).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let mut hostile_origin = mcp_req(
        None,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    hostile_origin
        .headers_mut()
        .insert("host", "127.0.0.1:7879".parse().unwrap());
    hostile_origin
        .headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    assert_eq!(
        router.oneshot(hostile_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

fn tool_names(value: &serde_json::Value) -> Vec<String> {
    value["result"]["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|t| t["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_tools_list_with_valid_token_returns_principal_tools() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    let names = tool_names(&value);

    assert!(
        names.contains(&"send_email".to_string()),
        "valid vut_ Bearer must surface the principal's granted tool: {names:?}"
    );
    // Connector model: a scoped use-token (vut_) agent sees ONLY its granted named
    // capabilities (+ check_approval) over the networked transport — NOT the generic
    // built-in tools.
    assert!(
        !names.contains(&"http_request".to_string()),
        "a use-token agent must NOT see generic http_request: {names:?}"
    );
    assert!(
        !names.contains(&"list_credentials".to_string()),
        "a use-token agent must NOT see generic list_credentials"
    );
    assert!(
        names.contains(&"check_approval".to_string()),
        "the control tool stays available"
    );
}

#[tokio::test]
async fn http_missing_token_is_401() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;

    let resp = router
        .oneshot(mcp_req(
            None,
            serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "no Authorization header must be 401"
    );
    let value = body_value(resp).await;
    assert_eq!(
        value["id"],
        serde_json::json!(7),
        "the request id is echoed on the 401"
    );
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Unauthorized"));
}

#[tokio::test]
async fn http_invalid_token_is_401_not_bypassed() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;

    // A well-formed-but-unknown vut_ token.
    let resp = router
        .oneshot(mcp_req(
            Some("vut_thisisnotarealtoken000000000000"),
            serde_json::json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A garbage non-vut secret is treated as an API key and also rejected.
    let (router2, _storage2) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    let resp = router2
        .oneshot(mcp_req(
            Some("definitely-not-a-key"),
            serde_json::json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn http_expired_token_is_401() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    // Already-expired token (negative TTL).
    let token = mint_token(
        &storage,
        "cred-sendgrid",
        Some("http.request"),
        Some(chrono::Duration::seconds(-60)),
        None,
    )
    .await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an expired token must be 401"
    );
    let value = body_value(resp).await;
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("expired"));
}

#[tokio::test]
async fn http_revoked_token_is_401() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;
    // Revoke it (the W2 kill leg). set_use_token_revoked keys on the token id.
    let id = storage
        .get_use_token_by_hash(&UseToken::hash(&token))
        .await
        .unwrap()
        .unwrap()
        .id;
    storage.set_use_token_revoked(&id).await.unwrap();

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({ "jsonrpc": "2.0", "id": 11, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a revoked token must be 401"
    );
    let value = body_value(resp).await;
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("revoked"));
}

#[tokio::test]
async fn http_tools_call_runs_enforced_path() {
    // An allowed capability call must get PAST policy into the http plugin. We
    // point the capability at a private URL so the SSRF guard rejects it
    // deterministically offline — proving the request ran through execute_gated
    // (not a policy denial, not a bypass).
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-internal").await;
    let cap = Capability {
        id: "cap-internal".to_string(),
        tool_name: "ping_internal".to_string(),
        description: "ping an internal service".to_string(),
        action: "http.request".to_string(),
        plugin: Some("http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("http://127.0.0.1/health".to_string()),
            methods: vec!["GET".to_string()],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: "cred-internal".to_string(),
        input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        reversibility: "reversible".to_string(),
        llm: None,
        approval_preview: None,
    };
    storage.store_capability(&cap).await.unwrap();
    let token = mint_token(&storage, "cred-*", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "ping_internal", "arguments": {} }
            }),
        ))
        .await
        .unwrap();
    // The transport itself succeeded (200); the JSON-RPC body carries the per-call
    // outcome — here an SSRF/private rejection from the http plugin.
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    assert_eq!(value["result"]["isError"], serde_json::json!(true));
    let text = value["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        text.contains("private") || text.contains("internal") || text.contains("ssrf"),
        "the call must reach the http plugin (proving execute_gated ran): {text}"
    );
    assert!(
        !text.contains("no_policy") && !text.contains("default action"),
        "an allowed call must not be a policy denial: {text}"
    );
}

#[tokio::test]
async fn http_denied_principal_tools_call_is_rejected_not_bypassed() {
    // A token scoped to a different credential glob → execute_gated denies.
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "other-*", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "send_email", "arguments": { "body": { "to": "a@b.com" } } }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    assert_eq!(
        value["result"]["isError"],
        serde_json::json!(true),
        "denied call must be a tool error, not a result"
    );
}

#[tokio::test]
async fn http_header_token_is_authoritative_over_body_token() {
    // The agent's REAL granted token is scoped to "other-*" (cannot touch
    // cred-sendgrid). It tries to smuggle a more-privileged token in the JSON body
    // to widen scope. The header token must win: the body token is overwritten, so
    // the call is gated by the header principal (denied), never the body one.
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;

    // The privileged token (scoped to cred-sendgrid) — what the agent tries to inject.
    let privileged = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;
    // The agent's actual header token — scoped away from cred-sendgrid.
    let header_token = mint_token(&storage, "other-*", Some("http.request"), None, None).await;

    // tools/list with the privileged token smuggled in params: must NOT reveal
    // send_email, because the header (other-*) principal is authoritative.
    let resp = router
        .clone()
        .oneshot(mcp_req(
            Some(&header_token),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/list",
                "params": { "api_key": privileged, "token": privileged }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let names = tool_names(&body_value(resp).await);
    assert!(
        !names.contains(&"send_email".to_string()),
        "a body-smuggled privileged token must not widen scope past the header principal: {names:?}"
    );

    // tools/call with the privileged token smuggled in arguments: must be DENIED,
    // because the header (other-*) principal is the one execute_gated evaluates.
    let resp = router
        .oneshot(mcp_req(
            Some(&header_token),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {
                    "name": "send_email",
                    "arguments": { "api_key": privileged, "body": { "to": "a@b.com" } }
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    assert_eq!(
        value["result"]["isError"],
        serde_json::json!(true),
        "the call must be gated by the header principal (denied), not the smuggled body token"
    );
}

#[tokio::test]
async fn http_no_capabilities_for_unprivileged_default_deny() {
    // Default-deny with NO allow policy: a valid use-token sees no capability tools
    // (policy denies them) AND no generic built-ins (the connector model) — only the
    // check_approval control tool.
    let (router, storage) = build_router_with(config_with_policies(vec![])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let names = tool_names(&body_value(resp).await);
    assert!(
        !names.contains(&"send_email".to_string()),
        "default-deny must hide the capability"
    );
    assert!(
        !names.contains(&"http_request".to_string()),
        "a use-token agent must NOT see generic built-ins"
    );
    assert!(
        names.contains(&"check_approval".to_string()),
        "the control tool stays available"
    );
}

#[tokio::test]
async fn http_resources_list_blocked_for_use_token() {
    // A use-token must NOT enumerate the credential vault via resources/list
    // (GLM review #3). The handler had no principal/scope filter; the HTTP
    // transport now returns an empty resource set for a vut_.
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    store_credential(&storage, "cred-other-secret").await; // must NOT be enumerable
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    let resources = value["result"]["resources"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        resources.is_empty(),
        "a use-token must not enumerate the vault via resources/list: {value:?}"
    );
}

#[tokio::test]
async fn http_tools_call_generic_builtin_blocked_for_use_token() {
    // A use-token surfaces only its named tools at LIST; it must also be unable to
    // CALL a generic built-in by name (GLM review #1 defense-in-depth).
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;

    let resp = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "http_request", "arguments": {
                    "credential": "cred-sendgrid", "method": "GET", "url": "https://api.sendgrid.com/v3/x"
                }}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let value = body_value(resp).await;
    let is_rpc_error = value.get("error").is_some();
    let is_tool_error = value["result"]["isError"].as_bool().unwrap_or(false)
        || value["result"]["is_error"].as_bool().unwrap_or(false);
    assert!(
        is_rpc_error || is_tool_error,
        "a use-token calling the generic http_request built-in must be rejected: {value:?}"
    );
}

#[tokio::test]
async fn http_tools_call_plugin_tool_name_blocked_for_use_token() {
    // ALLOWLIST gate (Codex pass 4): a use-token may call ONLY check_approval +
    // its granted named capabilities. A raw plugin tool name (e.g. ssh_run,
    // postgres_run_sql) that is NOT a denylisted built-in must still be rejected —
    // it must not fall through to try_plugin_tool.
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    store_credential(&storage, "cred-sendgrid").await;
    register_send_email(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request"), None, None).await;

    for tool in [
        "ssh_run",
        "postgres_run_sql",
        "ssh_deploy",
        "totally_made_up",
    ] {
        let resp = router
            .clone()
            .oneshot(mcp_req(
                Some(&token),
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": { "name": tool, "arguments": { "credential": "cred-sendgrid" } }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let value = body_value(resp).await;
        assert!(
            value.get("error").is_some()
                || value["result"]["isError"].as_bool().unwrap_or(false)
                || value["result"]["is_error"].as_bool().unwrap_or(false),
            "use-token calling plugin tool {tool:?} must be rejected (allowlist): {value:?}"
        );
    }
}

#[tokio::test]
async fn official_client_handshake_shape_negotiates_and_accepts_notification_without_id() {
    let (router, storage) =
        build_router_with(config_with_policies(vec![allow_policy("cred-*")])).await;
    let token = mint_token(&storage, "cred-*", Some("http.request"), None, None).await;
    let response = router
        .clone()
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({
                "jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
                    "protocolVersion":"2025-06-18", "capabilities":{},
                    "clientInfo":{"name":"langchain-mcp-adapters","version":"1.x"}
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_value(response).await;
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");

    let notification = router
        .oneshot(mcp_req(
            Some(&token),
            serde_json::json!({
                "jsonrpc":"2.0", "method":"notifications/initialized"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
}
