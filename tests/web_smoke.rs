//! In-process smoke tests for the web admin surface.
//!
//! These exercise the real Axum router (routes + Askama template rendering)
//! without binding a socket or touching the user's home directory, using
//! `tower::ServiceExt::oneshot`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::approval::{
    ApprovalRequest, ApprovalRule, ApproverClass, NewApproval, Recipe, RecipeDecisionMode,
    RecipeTerm, RequesterInfo,
};
use vultrino::auth::{ApprovalToken, AuthManager, NewApprovalToken, NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::delegation::DelegationGrantScope;
use vultrino::govder::GovderConfig;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};

async fn build_router() -> (axum::Router, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the file alive for the test's lifetime

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        AuthManager::new(),
        admin,
        exec_server,
    );
    (server.into_router(), storage)
}

/// Like [`build_router`] but with a caller-supplied `Config` — used by the
/// govder-unreachable 503 tests to configure `config.govder` pointed at a dead
/// port (no admin key is minted, matching `build_router`'s no-auth-fixture shape;
/// tests that need one build it directly against the returned storage).
async fn build_router_with_config(config: Config) -> (axum::Router, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the file alive for the test's lifetime

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        AuthManager::new(),
        admin,
        exec_server,
    );
    (server.into_router(), storage)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

#[tokio::test]
async fn workload_grant_delete_revokes_all_bound_exchange_tokens() {
    let (router, storage, _, key) = build_admin_router().await;
    let grant = serde_json::json!({
        "tenant":"t1", "agent_label":"ep_agent", "issuer":"https://issuer",
        "subject":"workload", "audience":"vultrino", "mcp_credential_scope":"cred-*",
        "mcp_action_scope":"tool.*", "ttl_secs":300
    });
    let response = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            "/api/v1/workload-grants/ep_agent",
            &key,
            grant,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (_, mut bound) = UseToken::create(NewUseToken {
        name: "bound".into(),
        credential_scope: "cred-*".into(),
        action_scope: Some("tool.*".into()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    bound.tenant = Some("t1".into());
    bound.agent_label = Some("ep_agent".into());
    storage.store_use_token(&bound).await.unwrap();
    let (_, mut foreign) = UseToken::create(NewUseToken {
        name: "foreign".into(),
        credential_scope: "cred-*".into(),
        action_scope: Some("tool.*".into()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    foreign.tenant = Some("t2".into());
    foreign.agent_label = Some("ep_agent".into());
    storage.store_use_token(&foreign).await.unwrap();

    let response = router
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/workload-grants/ep_agent?tenant=t1",
            &key,
            serde_json::Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        storage
            .get_use_token(&bound.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        !storage
            .get_use_token(&foreign.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn runtime_control_cancels_after_principal_halt() {
    let (router, storage, server, _key) = build_admin_router().await;
    let (plain, mut token) = UseToken::create(NewUseToken {
        name: "native runtime lease".into(),
        credential_scope: "cred-*".into(),
        action_scope: Some("tool.*".into()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.tenant = Some("t1".into());
    token.agent_label = Some("ep_native".into());
    storage.store_use_token(&token).await.unwrap();
    let request = || {
        Request::builder()
            .uri("/api/v1/runtime/control")
            .header("authorization", format!("Bearer {plain}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        router.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    server.halt_agent("ep_native").await.unwrap();
    assert_eq!(
        router.oneshot(request()).await.unwrap().status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn runtime_control_honors_w3_kill_policy_with_still_live_token() {
    let (router, storage, server, _key) = build_admin_router().await;
    let (plain, mut token) = UseToken::create(NewUseToken {
        name: "native runtime lease".into(),
        credential_scope: "cred-*".into(),
        action_scope: Some("tool.*".into()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.tenant = Some("t1".into());
    token.agent_label = Some("ep_w3".into());
    storage.store_use_token(&token).await.unwrap();
    storage
        .store_policy(&vultrino::policy::Policy::kill_switch("kill-w3", "ep_w3"))
        .await
        .unwrap();
    server.reload_policies().await.unwrap();
    assert!(
        !storage
            .get_use_token(&token.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/runtime/control")
                .header("authorization", format!("Bearer {plain}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// Build a router plus a minted admin API key (vk_) the auth manager recognizes,
/// and a handle to the shared exec server so tests can inspect the live engine.
async fn build_admin_router() -> (
    axum::Router,
    Arc<dyn StorageBackend>,
    Arc<vultrino::server::VultrinoServer>,
    String,
) {
    let (router, storage, exec_server, admin_key, _read_key) = build_admin_router_with_read().await;
    (router, storage, exec_server, admin_key)
}

/// Like [`build_admin_router`] but also mints and returns a least-privilege
/// `read-only` key (Permission::Read only), so tests can assert that the inventory
/// GETs accept it while the mutating admin routes reject it. A stable policy-hash
/// secret is configured so the D2 `content_hash` is a real (keyed) value.
async fn build_admin_router_with_read() -> (
    axum::Router,
    Arc<dyn StorageBackend>,
    Arc<vultrino::server::VultrinoServer>,
    String,
    String,
) {
    build_admin_router_full(Some("test-policy-hash-secret")).await
}

/// Inner builder parameterized by the policy `content_hash` secret (D2). `Some`
/// keys the hash (HMAC) so it is a real value; `None` simulates a deployment with
/// no secret configured, where `content_hash` must be emitted empty (no oracle).
async fn build_admin_router_full(
    policy_hash_secret: Option<&str>,
) -> (
    axum::Router,
    Arc<dyn StorageBackend>,
    Arc<vultrino::server::VultrinoServer>,
    String,
    String,
) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Mint an admin key in the auth manager (and persist it) so the API accepts it.
    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager
        .create_api_key("admin-key", "admin", None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();
    // Mint a read-only key (least privilege: Permission::Read only).
    let (read_key, read_api_key) = auth_manager
        .create_api_key("read-key", vultrino::auth::ROLE_READ_ONLY, None)
        .unwrap();
    storage.store_api_key(&read_api_key).await.unwrap();

    // The web AppState carries the policy-hash secret on its Config — set it here
    // (production sources it from VULTRINO_POLICY_HASH_SECRET at startup).
    let web_config = Config {
        policy_hash_secret: policy_hash_secret.map(|s| s.to_string()),
        ..Config::default()
    };

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        web_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server.clone(),
    );
    (
        server.into_router(),
        storage,
        exec_server,
        admin_key,
        read_key,
    )
}

/// Build a router whose auth manager holds a TENANT-SCOPED admin key, returning
/// the router, storage, and the key's plaintext + its tenant. The per-tenant JSON
/// approvals surface (A3/A4) requires a tenant-scoped key (a global/untenanted key
/// is rejected 403), so the A3/A4 happy-path tests build their key this way.
async fn build_tenant_admin_router(
    tenant: &str,
) -> (axum::Router, Arc<dyn StorageBackend>, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Mint an admin key, then re-seed the auth manager with a tenant-scoped clone
    // (same plaintext/hash, tenant set) — public API only.
    let seed = AuthManager::new();
    let (admin_key_plain, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some(tenant.to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();
    (router, storage, admin_key_plain)
}

fn admin_req(method: &str, uri: &str, key: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", key))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn test_health_endpoint() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("ok"));
}

#[tokio::test]
async fn test_ready_endpoint_healthy() {
    // Observability item 4 / #5: a healthy process reports 200 + "ready", with no
    // failing_components key (omitted, not an empty array — see ReadyResponse's
    // skip_serializing_if) and the outbox_pending backlog (0 for a fresh vault).
    let (router, _storage) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "ready");
    assert!(
        body.get("failing_components").is_none(),
        "no failing_components key on a healthy ready response"
    );
    assert_eq!(body["outbox_pending"], 0);
}

#[tokio::test]
async fn test_ready_endpoint_reports_not_ready_on_broken_storage() {
    // Observability item 4 / #5: storage.health_check() failing (here: the vault
    // file itself is gone) must fail the probe CLOSED — 503, naming "storage" as
    // the failing component — never fail-open. /api/v1/health (liveness), by
    // contrast, stays a hardcoded constant and would still report 200 in this
    // same scenario (that split is the whole point of the two endpoints).
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        AuthManager::new(),
        admin,
        exec_server,
    );
    let router = server.into_router();

    // Break storage read-only, without any vault WRITE — deleting the file
    // underneath the process (a stand-in for the file becoming unreadable/gone).
    std::fs::remove_file(&path).unwrap();

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "not_ready");
    let failing = body["failing_components"].as_array().unwrap();
    assert!(
        failing
            .iter()
            .any(|c| c.as_str().unwrap().starts_with("storage")),
        "expected a storage failure named in failing_components, got {failing:?}"
    );
}

#[tokio::test]
async fn test_login_page_renders() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.to_lowercase().contains("password"));
}

#[tokio::test]
async fn test_decide_link_unknown_approval_renders() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/approvals/appr_missing/decide?token=whatever&decision=approve")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("No such approval") || body.contains("Not found"));
}

#[tokio::test]
async fn test_admin_api_requires_admin() {
    let (router, _storage, _server, _key) = build_admin_router().await;

    // No auth → 401.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A use-token-shaped bearer is rejected as non-admin (403), never reaching
    // the handler.
    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            "vut_sometoken",
            serde_json::json!({"name":"p","credential_pattern":"*","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_policy_crud_hot_reload() {
    let (router, storage, server, key) = build_admin_router().await;

    // Create a policy → 201, and it lands in the live engine without a restart.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &key,
            serde_json::json!({"name":"allow-gh","credential_pattern":"github-*","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(storage.list_stored_policies().await.unwrap().len(), 1);
    assert!(server
        .policy_engine()
        .list_policies()
        .iter()
        .any(|p| p.id == id));

    // PUT replaces by id.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &format!("/api/v1/policies/{}", id),
            &key,
            serde_json::json!({"name":"allow-gh-2","credential_pattern":"github-*","default_action":"deny"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        storage.get_policy(&id).await.unwrap().unwrap().name,
        "allow-gh-2"
    );

    // Invalid glob in credential_pattern → 400.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &key,
            serde_json::json!({"name":"bad","credential_pattern":"[","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // DELETE removes it from storage and the engine.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/policies/{}", id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.list_stored_policies().await.unwrap().len(), 0);
    assert!(!server
        .policy_engine()
        .list_policies()
        .iter()
        .any(|p| p.id == id));
}

#[tokio::test]
async fn test_admin_capability_crud() {
    // Connector M1: the named-MCP-tool admin surface — POST/GET/PUT/DELETE.
    let (router, storage, _server, key) = build_admin_router().await;

    // Create a capability → 201; it persists (no secret in the body).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/capabilities",
            &key,
            serde_json::json!({
                "tool_name": "send_email",
                "description": "Send an email",
                "action": "http.request",
                "plugin": "http",
                "target": { "url_glob": "https://api.sendgrid.example/v3/mail/send", "methods": ["POST"] },
                "credential_ref": "cred-sendgrid",
                "input_schema": { "type": "object", "properties": { "body": { "type": "object" } } }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["tool_name"], "send_email");
    assert_eq!(storage.list_capabilities().await.unwrap().len(), 1);

    // GET lists it (sorted by tool_name).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/capabilities",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(listed["capabilities"].as_array().unwrap().len(), 1);
    assert_eq!(listed["capabilities"][0]["tool_name"], "send_email");

    // PUT replaces by id.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &format!("/api/v1/capabilities/{}", id),
            &key,
            serde_json::json!({
                "tool_name": "send_email_v2",
                "action": "http.request",
                "credential_ref": "cred-sendgrid"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        storage
            .get_capability(&id)
            .await
            .unwrap()
            .unwrap()
            .tool_name,
        "send_email_v2"
    );

    // An invalid tool_name (uppercase) → 400.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/capabilities",
            &key,
            serde_json::json!({ "tool_name": "Send-Email", "action": "http.request", "credential_ref": "c" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A name colliding with a built-in generic tool → 400.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/capabilities",
            &key,
            serde_json::json!({ "tool_name": "http_request", "action": "http.request", "credential_ref": "c" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // DELETE removes it.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/capabilities/{}", id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.list_capabilities().await.unwrap().len(), 0);

    // Deleting again → 404.
    let resp = router
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/capabilities/{}", id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_capabilities_require_admin() {
    let (router, _storage, _server, _key) = build_admin_router().await;
    // No auth → 401.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/capabilities")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A use token can never reach the admin surface → 403.
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/capabilities",
            "vut_sometoken",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_admin_token_mint_idempotent() {
    let (router, storage, _server, key) = build_admin_router().await;

    let mint = |idem: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/tokens")
            .header("authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .header("idempotency-key", idem)
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "name":"deploy","credential_scope":"deploy-*","max_uses":1
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    let resp1 = router.clone().oneshot(mint("k1")).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);
    let body1 = body_string(resp1).await;
    let v1: serde_json::Value = serde_json::from_str(&body1).unwrap();
    let token1 = v1["token"].as_str().unwrap().to_string();
    assert!(token1.starts_with("vut_"));

    // Replay with the SAME idempotency key → no second token, and the plaintext
    // is NOT re-exposed (it was only returned on the original request).
    let resp2 = router.clone().oneshot(mint("k1")).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CREATED);
    let v2: serde_json::Value = serde_json::from_str(&body_string(resp2).await).unwrap();
    assert!(
        v2["token"].is_null(),
        "replay must not re-expose the plaintext token"
    );
    assert_eq!(
        storage.list_use_tokens().await.unwrap().len(),
        1,
        "no duplicate token minted"
    );

    // A different key mints a new, distinct token.
    let resp3 = router.oneshot(mint("k2")).await.unwrap();
    let v3: serde_json::Value = serde_json::from_str(&body_string(resp3).await).unwrap();
    assert_ne!(v3["token"].as_str().unwrap(), token1);
    assert_eq!(storage.list_use_tokens().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_admin_revoked_token_cannot_execute() {
    let (router, storage, _server, key) = build_admin_router().await;

    // Mint a token via the admin API.
    let mint = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({"name":"t","credential_scope":"*"}),
        ))
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body_string(mint).await).unwrap();
    let plaintext = v["token"].as_str().unwrap().to_string();
    let token_id = v["metadata"]["id"].as_str().unwrap().to_string();

    // Revoke it via the admin API.
    let revoke = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/tokens/{}/revoke", token_id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    assert!(
        storage
            .get_use_token(&token_id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );

    // Using the revoked token on /execute is rejected at the auth seam (403),
    // before any credential resolution or upstream call.
    let exec = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/execute")
                .header("authorization", format!("Bearer {}", plaintext))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "credential":"whatever","method":"GET","url":"https://example.com"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec.status(), StatusCode::FORBIDDEN);
    assert!(body_string(exec).await.to_lowercase().contains("revoked"));
}

#[tokio::test]
async fn test_admin_role_create_and_credential_delete_and_put_policy() {
    let (router, storage, _server, key) = build_admin_router().await;

    // Role create happy path.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/roles",
            &key,
            serde_json::json!({"name":"gh-exec","permissions":["read","execute"],"credential_scopes":["github-*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    assert!(storage.get_role_by_name("gh-exec").await.unwrap().is_some());

    // PUT a policy at a chosen id (create-via-PUT).
    let r = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            "/api/v1/policies/my-fixed-id",
            &key,
            serde_json::json!({"name":"p","credential_pattern":"*","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(storage.get_policy("my-fixed-id").await.unwrap().is_some());

    // Create then delete a credential.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/credentials",
            &key,
            serde_json::json!({"alias":"c1","data":{"type":"api_key","key":"k","header_name":"Authorization","header_prefix":"Bearer "}}),
        ))
        .await
        .unwrap();
    let cred: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let cred_id = cred["id"].as_str().unwrap().to_string();
    let r = router
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/credentials/{}", cred_id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(storage.get_by_alias("c1").await.unwrap().is_none());
}

#[tokio::test]
async fn test_admin_crud_emits_audit_events() {
    // Observability item 4 / #17: a successful admin create/delete/revoke emits a
    // signed-outbox audit event — ids-only payload {actor, target_id, verb} (no
    // secret, no role permissions, no token scope) — previously these admin
    // mutations emitted NOTHING to the outbox (a durable audit-completeness gap).
    let (router, storage, _server, key) = build_admin_router().await;

    // Credential create -> credential.created; delete -> credential.deleted.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/credentials",
            &key,
            serde_json::json!({"alias":"audit-cred","data":{"type":"api_key","key":"k","header_name":"Authorization","header_prefix":"Bearer "}}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let cred: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let cred_id = cred["id"].as_str().unwrap().to_string();

    let events = storage.list_events_after(0, 1000).await.unwrap();
    let created = events
        .iter()
        .find(|e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_CREATED)
        .expect("credential.created emitted on successful create");
    assert_eq!(created.subject, "audit-cred");
    assert_eq!(created.payload["target_id"], cred_id);
    assert_eq!(created.payload["verb"], "created");
    assert!(
        created.payload["actor"].is_string()
            && !created.payload["actor"].as_str().unwrap().is_empty(),
        "actor is the acting admin key id, not empty/absent"
    );
    // Ids-only payload (item 4 / #17's contract): exactly {actor, target_id,
    // verb} — no `data`/secret field, no role permissions, no token scope.
    assert_eq!(
        created
            .payload
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::HashSet<String>>(),
        ["actor", "target_id", "verb"]
            .iter()
            .map(|s| s.to_string())
            .collect::<std::collections::HashSet<String>>()
    );

    let r = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/credentials/{}", cred_id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let events = storage.list_events_after(0, 1000).await.unwrap();
    assert!(
        events.iter().any(
            |e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_DELETED
                && e.subject == cred_id
                && e.payload["verb"] == "deleted"
        ),
        "credential.deleted emitted on successful delete"
    );

    // Role create -> role.changed{verb=created}.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/roles",
            &key,
            serde_json::json!({"name":"audit-role","permissions":["read"],"credential_scopes":["*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let events = storage.list_events_after(0, 1000).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == vultrino::outbox::EVENT_ROLE_CHANGED
                && e.subject == "audit-role"
                && e.payload["verb"] == "created"),
        "role.changed(created) emitted on successful role create"
    );

    // Use-token create -> token.changed{verb=created}; revoke -> {verb=revoked}.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({"name":"audit-token","credential_scope":"*"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let tok: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let token_id = tok["metadata"]["id"].as_str().unwrap().to_string();
    let events = storage.list_events_after(0, 1000).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == vultrino::outbox::EVENT_TOKEN_CHANGED
                && e.subject == token_id
                && e.payload["verb"] == "created"),
        "token.changed(created) emitted on successful token mint"
    );

    let r = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/tokens/{}/revoke", token_id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let events = storage.list_events_after(0, 1000).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == vultrino::outbox::EVENT_TOKEN_CHANGED
                && e.subject == token_id
                && e.payload["verb"] == "revoked"),
        "token.changed(revoked) emitted on successful token revoke"
    );
}

#[tokio::test]
async fn test_admin_put_policy_idempotency_bound_to_path() {
    let (router, storage, _server, key) = build_admin_router().await;
    let body = serde_json::json!({"name":"p","credential_pattern":"*","default_action":"allow"});
    let put = |id: &str, idem: &str| {
        Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/policies/{}", id))
            .header("authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .header("idempotency-key", idem)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };
    // Same body + same Idempotency-Key, two different path ids. The hash is bound
    // to the path, so the second is a key/body Mismatch (409) — NOT a verbatim
    // replay of id1's response (which is what the bug would do). id2 is not
    // created as a copy of id1.
    assert_eq!(
        router
            .clone()
            .oneshot(put("id1", "same"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        router.oneshot(put("id2", "same")).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert!(storage.get_policy("id1").await.unwrap().is_some());
    assert!(storage.get_policy("id2").await.unwrap().is_none());
}

#[tokio::test]
async fn test_admin_token_strictness_compiles() {
    let (router, storage, _server, key) = build_admin_router().await;
    let mint = |body: serde_json::Value| admin_req("POST", "/api/v1/tokens", &key, body);

    // direct → single-use + require_approval + dual_control (overrides max_uses).
    let r = router
        .clone()
        .oneshot(mint(serde_json::json!({"name":"d","credential_scope":"*","max_uses":99,"strictness":"direct"})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let id = v["metadata"]["id"].as_str().unwrap();
    let tok = storage.get_use_token(id).await.unwrap().unwrap();
    assert_eq!(tok.max_uses, Some(1));
    assert!(tok.require_approval);
    assert!(tok.dual_control);

    // checkpoint → require_approval + multi-use + no dual_control.
    let r = router
        .clone()
        .oneshot(mint(serde_json::json!({"name":"c","credential_scope":"*","max_uses":5,"strictness":"checkpoint"})))
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let tok = storage
        .get_use_token(v["metadata"]["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tok.max_uses, Some(5));
    assert!(tok.require_approval);
    assert!(!tok.dual_control);

    // Unknown strictness → 400.
    let r = router
        .oneshot(mint(
            serde_json::json!({"name":"x","credential_scope":"*","strictness":"loose"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_agent_action_consume_is_scoped_atomic_and_approval_aware() {
    let (router, storage, _server, key) = build_admin_router().await;
    let mint = |name: &str, require_approval: bool| {
        admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({
                "name": name,
                "credential_scope": "*",
                "action_scope": "agent.spawn",
                "max_uses": 1,
                "require_approval": require_approval,
                "agent_label": "ep_parent",
                "tenant": "acme"
            }),
        )
    };
    let minted = router.clone().oneshot(mint("spawn", false)).await.unwrap();
    assert_eq!(minted.status(), StatusCode::CREATED);
    let body: serde_json::Value = serde_json::from_str(&body_string(minted).await).unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    let id = body["metadata"]["id"].as_str().unwrap().to_string();
    let consume = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/agent/consume?required_action=agent.spawn")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        router.clone().oneshot(consume()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(storage.get_use_token(&id).await.unwrap().unwrap().uses, 1);
    assert_eq!(
        router.clone().oneshot(consume()).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let gated = router
        .clone()
        .oneshot(mint("gated-spawn", true))
        .await
        .unwrap();
    let gated_body: serde_json::Value = serde_json::from_str(&body_string(gated).await).unwrap();
    let gated_token = gated_body["token"].as_str().unwrap();
    let gated_id = gated_body["metadata"]["id"].as_str().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/agent/consume?required_action=agent.spawn")
        .header("Authorization", format!("Bearer {gated_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        storage.get_use_token(gated_id).await.unwrap().unwrap().uses,
        0
    );
}

#[tokio::test]
async fn test_admin_token_agent_label_validation() {
    let (router, _storage, _server, key) = build_admin_router().await;
    let mint = |label: &str| {
        admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({"name":"t","credential_scope":"*","agent_label":label}),
        )
    };
    // Glob metacharacters and the ':' key-prefix separator are rejected.
    assert_eq!(
        router
            .clone()
            .oneshot(mint("bot-*"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        router
            .clone()
            .oneshot(mint("cred:foo"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    // A plain label is accepted.
    assert_eq!(
        router.oneshot(mint("refund-bot")).await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn test_admin_token_expiry_bounds() {
    let (router, _storage, _server, key) = build_admin_router().await;
    let mint = |secs: i64| {
        admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({"name":"t","credential_scope":"*","expires_in_secs":secs}),
        )
    };
    // Non-positive and absurdly-large (overflow-guard) lifetimes are rejected.
    assert_eq!(
        router.clone().oneshot(mint(0)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        router.clone().oneshot(mint(-5)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        router
            .clone()
            .oneshot(mint(i64::MAX))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    // A sane lifetime succeeds.
    assert_eq!(
        router.oneshot(mint(3600)).await.unwrap().status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn test_admin_credential_idempotency_deterministic_metadata() {
    let (router, storage, _server, key) = build_admin_router().await;
    // Multi-key metadata: the body hash must be deterministic across retries
    // (HashMap iteration order must not leak into the hash), so a replay is a
    // replay — not a spurious 409 Mismatch.
    let body = serde_json::json!({
        "alias":"multi",
        "metadata":{"z":"1","a":"2","m":"3","q":"4","b":"5"},
        "data":{"type":"api_key","key":"k","header_name":"Authorization","header_prefix":"Bearer "}
    });
    let make = |idem: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/credentials")
            .header("authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .header("idempotency-key", idem)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };
    let r1 = router.clone().oneshot(make("c-idem")).await.unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = router.oneshot(make("c-idem")).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::CREATED,
        "multi-key metadata must replay, not 409"
    );
    assert_eq!(
        storage.list().await.unwrap().len(),
        1,
        "no duplicate credential"
    );
}

#[tokio::test]
async fn test_admin_delete_role_in_use_conflict() {
    let (router, storage, _server, key) = build_admin_router().await;
    // Create a custom role via the admin API.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/roles",
            &key,
            serde_json::json!({"name":"temp","permissions":["read"]}),
        ))
        .await
        .unwrap();
    let role: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let role_id = role["id"].as_str().unwrap().to_string();

    // Mint an API key referencing it (directly via storage).
    storage
        .store_api_key(&vultrino::auth::ApiKey {
            id: "k-ref".to_string(),
            key_prefix: "vk_ref".to_string(),
            key_hash: "h-ref".to_string(),
            name: "refkey".to_string(),
            role_id: role_id.clone(),
            expires_at: None,
            created_at: chrono::Utc::now(),
            last_used_at: None,
            agent_label: None,
            owner_identity: None,
            tenant: None,
            workload_id: None,
        })
        .await
        .unwrap();

    // Deleting the in-use role is refused atomically with 409.
    let r = router
        .oneshot(admin_req(
            "DELETE",
            &format!("/api/v1/roles/{}", role_id),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(body_string(r).await.contains("role_in_use"));
}

#[tokio::test]
async fn test_admin_put_role_upserts_in_place_and_post_still_conflicts() {
    let (router, storage, _server, key) = build_admin_router().await;

    // Create a role with a narrow credential scope (simulates the provisioner
    // seeding an agent's executor role for its first capability).
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/roles",
            &key,
            serde_json::json!({"name":"govder-exec-agent1","permissions":["read","execute"],"credential_scopes":["github-*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    let original_id = created["id"].as_str().unwrap().to_string();

    // A second POST create with the same name still 409s — POST-create
    // semantics are unchanged by adding the PUT upsert.
    let r = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/roles",
            &key,
            serde_json::json!({"name":"govder-exec-agent1","permissions":["read","execute"],"credential_scopes":["github-*","slack-*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(body_string(r).await.contains("role_exists"));

    // Granting a second capability widens the credential_scopes union. The
    // provisioner now does this via PUT (create-or-replace by name) instead
    // of POST, so it succeeds instead of 409ing.
    let r = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            "/api/v1/roles/govder-exec-agent1",
            &key,
            serde_json::json!({"name":"govder-exec-agent1","permissions":["read","execute"],"credential_scopes":["github-*","slack-*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let updated: serde_json::Value = serde_json::from_str(&body_string(r).await).unwrap();
    assert_eq!(
        updated["id"].as_str().unwrap(),
        original_id,
        "upsert must reuse the existing role's id, not mint a new one"
    );
    assert_eq!(
        updated["credential_scopes"],
        serde_json::json!(["github-*", "slack-*"])
    );

    // The storage-level view (and hence get_role_by_name / list_roles, which
    // is what the auth manager and any subsequent GET use) reflects the
    // widened scopes in place, still under the same id — no duplicate role
    // was created alongside the original.
    let stored = storage
        .get_role_by_name("govder-exec-agent1")
        .await
        .unwrap()
        .expect("role still present");
    assert_eq!(stored.id, original_id);
    assert_eq!(stored.credential_scopes, vec!["github-*", "slack-*"]);
    assert_eq!(
        storage
            .list_roles()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.name == "govder-exec-agent1")
            .count(),
        1,
        "no duplicate role rows for the same name"
    );

    // PUTting a brand-new name (no prior role) behaves like a create.
    let r = router
        .oneshot(admin_req(
            "PUT",
            "/api/v1/roles/govder-exec-agent2",
            &key,
            serde_json::json!({"name":"govder-exec-agent2","permissions":["read"],"credential_scopes":["aws-*"]}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(storage
        .get_role_by_name("govder-exec-agent2")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn test_admin_cannot_delete_builtin_role() {
    let (router, _storage, _server, key) = build_admin_router().await;
    let resp = router
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/roles/admin",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body_string(resp).await.contains("predefined"));
}

#[tokio::test]
async fn test_admin_idempotency_key_body_mismatch() {
    let (router, _storage, _server, key) = build_admin_router().await;
    let mint = |idem: &str, name: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/tokens")
            .header("authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .header("idempotency-key", idem)
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({"name":name,"credential_scope":"*"}))
                    .unwrap(),
            ))
            .unwrap()
    };
    // First use of the key with body A → created.
    let r1 = router.clone().oneshot(mint("m1", "alpha")).await.unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    // Reuse the SAME key with a DIFFERENT body → 409, never a wrong replay.
    let r2 = router.clone().oneshot(mint("m1", "beta")).await.unwrap();
    assert_eq!(r2.status(), StatusCode::CONFLICT);
    assert!(body_string(r2).await.contains("idempotency_key_reused"));
    // A replayed mint must not leak the plaintext token in the stored body.
    let r3 = router.oneshot(mint("m1", "alpha")).await.unwrap();
    let v3: serde_json::Value = serde_json::from_str(&body_string(r3).await).unwrap();
    assert!(
        v3["token"].is_null(),
        "replay must not return the plaintext token"
    );
    assert!(v3.get("token_note").is_some());
}

#[tokio::test]
async fn test_admin_credential_create_no_secret_echo() {
    let (router, storage, _server, key) = build_admin_router().await;

    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/credentials",
            &key,
            serde_json::json!({
                "alias":"gh",
                "metadata":{"description":"github"},
                "data":{"type":"api_key","key":"super-secret-value","header_name":"Authorization","header_prefix":"Bearer "}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_string(resp).await;
    // The response must carry metadata but never the secret material.
    assert!(body.contains("\"alias\":\"gh\""));
    assert!(
        !body.contains("super-secret-value"),
        "secret must not be echoed: {body}"
    );
    // It is, however, persisted (and usable).
    let stored = storage.get_by_alias("gh").await.unwrap().unwrap();
    assert_eq!(stored.alias, "gh");
}

#[tokio::test]
async fn test_out_of_band_decide_flow() {
    let (router, storage) = build_router().await;

    // Open a real approval and keep its plaintext decision token.
    let (approval, token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: Some("oncall".to_string()),
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    storage.store_approval(&approval).await.unwrap();

    // 1. GET the decide link with the valid token -> confirmation page.
    let confirm = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/approvals/{}/decide?token={}&decision=approve",
                    approval.id,
                    urlencoding::encode(&token)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirm.status(), StatusCode::OK);
    assert!(body_string(confirm).await.contains("Confirm"));

    // 2. A wrong token is rejected.
    let bad = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/approvals/{}/decide?token=wrong&decision=approve",
                    approval.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(body_string(bad).await.contains("Invalid link"));

    // 3. POST the confirmation -> the approval flips to approved.
    let form = format!("token={}&decision=approve", urlencoding::encode(&token));
    let submit = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/approvals/{}/decide", approval.id))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(submit.status(), StatusCode::OK);
    assert!(body_string(submit).await.contains("Approved"));

    let stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
    assert_eq!(stored.decided_by.as_deref(), Some("out-of-band link"));
}

#[tokio::test]
async fn test_out_of_band_decide_without_named_identity_is_refused() {
    // R2: an OOB decision link with no named approver identity bound is refused
    // (fail closed) rather than recording an unattributable "out-of-band" verdict.
    let (router, storage) = build_router().await;

    let (approval, token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None, // no named identity bound
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    storage.store_approval(&approval).await.unwrap();

    // POST with the valid token still refuses — there is no attributable approver.
    let form = format!("token={}&decision=approve", urlencoding::encode(&token));
    let submit = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/approvals/{}/decide", approval.id))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(submit.status(), StatusCode::OK);
    assert!(body_string(submit).await.contains("Not available"));

    // The approval was NOT decided.
    let stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert!(stored.decided_by.is_none());
}

#[tokio::test]
async fn test_admin_halt_agent_installs_kill_and_lists_sessions() {
    let (router, storage, server, key) = build_admin_router().await;

    // POST halt for an agent → 200 with a machine-readable outcome.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/agents/bot-7/halt",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let out: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(out["agent_label"], "bot-7");
    assert_eq!(out["deny_policy_id"], "halt:bot-7");

    // The authoritative kill policy landed in the live engine and storage.
    assert!(server
        .policy_engine()
        .list_policies()
        .iter()
        .any(|p| p.id == "halt:bot-7" && p.kill));
    assert!(storage.get_policy("halt:bot-7").await.unwrap().is_some());

    // GET /sessions → 200, per-process scope, empty here (nothing in flight).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/sessions",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["process_scope"], true);
    assert!(body["sessions"].as_array().unwrap().is_empty());

    // DELETE halt → lifts it; the kill policy is gone from the engine.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/agents/bot-7/halt",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!server
        .policy_engine()
        .list_policies()
        .iter()
        .any(|p| p.id == "halt:bot-7"));

    // Unauthenticated halt → 401 (admin-only).
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agents/bot-7/halt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_halt_rejects_glob_label() {
    // V6: a glob halt label is rejected (400) so a halt can't deny a whole fleet.
    let (router, _storage, server, key) = build_admin_router().await;
    // "bot-*" is URL-safe as a path segment; the handler must reject it.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/agents/bot-*/halt",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // No kill policy was installed.
    assert!(!server
        .policy_engine()
        .list_policies()
        .iter()
        .any(|p| p.kill));
}

#[tokio::test]
async fn test_admin_event_replay_api() {
    // V9: events emitted by admin actions are replayable from a cursor.
    let (router, _storage, _server, key) = build_admin_router().await;

    // A halt emits an agent.halted event.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/agents/bot-7/halt",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /api/v1/events?after=0 → the event + a next_cursor.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/events?after=0",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let events = body["events"].as_array().unwrap();
    // Each replayed event is {body, signature?} — the body is what a push carries.
    assert!(events
        .iter()
        .any(|e| e["body"]["event"] == "agent.halted" && e["body"]["subject"] == "bot-7"));
    let cursor = body["next_cursor"].as_u64().unwrap();
    assert!(cursor >= 1);

    // Replaying after the cursor → no more events (no gaps, no dupes).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            &format!("/api/v1/events?after={cursor}"),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert!(body["events"].as_array().unwrap().is_empty());

    // The DLQ endpoint works (empty here).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/events/dead",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Replay is admin-only.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/events?after=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_bulk_dead_letter_replay() {
    // Observability item 4 / #3: POST /api/v1/events/dead/replay requeues EVERY
    // currently dead-lettered event in one call. This also proves the new
    // literal "dead" path segment routes correctly alongside (doesn't collide
    // with) the existing "/api/v1/events/{sequence}/replay" param route.
    let (router, storage, _server, key) = build_admin_router().await;

    // Dead-letter two events directly at the storage layer (bypassing the
    // network-delivery path is timing-independent — see
    // test_dead_letters_after_max_via_record in outbox_integration.rs for why).
    let seq1 = storage
        .append_event("A", "e", serde_json::json!({}))
        .await
        .unwrap();
    let seq2 = storage
        .append_event("B", "e", serde_json::json!({}))
        .await
        .unwrap();
    storage
        .record_event_delivery(seq1, false, Some("boom".to_string()), 1)
        .await
        .unwrap();
    storage
        .record_event_delivery(seq2, false, Some("boom".to_string()), 1)
        .await
        .unwrap();
    assert_eq!(storage.list_dead_letter_events(100).await.unwrap().len(), 2);

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/events/dead/replay",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["total"], 2);
    assert_eq!(
        body["requeued"].as_array().unwrap().len(),
        2,
        "both dead-lettered events requeued"
    );
    assert!(body["failed"].as_array().unwrap().is_empty());
    assert_eq!(
        storage.list_dead_letter_events(100).await.unwrap().len(),
        0,
        "no longer dead-lettered after bulk replay"
    );

    // Admin-only, and unaffected by having zero dead letters left.
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/events/dead/replay")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_metrics_readback() {
    // V12: the metrics endpoint returns the structured read-back, admin-only.
    let (router, _storage, _server, key) = build_admin_router().await;
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/metrics",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["unauthorized_attempts"], 0);
    assert_eq!(body["approvals"]["total"], 0);
    assert!(body["approval_latency_secs"]["count"].is_u64());
    // Observability item 4 / #3: outbox delivery counters, all zero pre-delivery.
    assert_eq!(body["outbox"]["delivered"], 0);
    assert_eq!(body["outbox"]["failed"], 0);
    assert_eq!(body["outbox"]["dead_lettered"], 0);
    assert_eq!(body["outbox"]["last_delivered_sequence"], 0);

    // Admin-only.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_metrics_reflects_outbox_delivery_counters() {
    // Observability item 4 / #3: a successful delivery pass against the SAME
    // VultrinoServer the router shares (`exec_server`, cloned into AppState by
    // WebServer::new) is reflected in the JSON /api/v1/metrics read-back — the
    // counters are shared (Arc) between the background delivery loop and the
    // metrics handler, not two independent copies.
    let (router, storage, exec_server, key) = build_admin_router().await;

    let app = axum::Router::new().route("/hook", axum::routing::post(|| async { StatusCode::OK }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let seq = storage
        .append_event("A", "e", serde_json::json!({}))
        .await
        .unwrap();
    let outbox_cfg = vultrino::outbox::OutboxConfig {
        enabled: true,
        url: Some(format!("http://{addr}/hook")),
        hmac_secret: Some("s".to_string()),
        max_attempts: 3,
        retention_secs: 3600,
    };
    let client = reqwest::Client::new();
    vultrino::server::deliver_outbox_once(
        &storage,
        &outbox_cfg,
        &client,
        &exec_server.outbox_metrics(),
    )
    .await
    .unwrap();

    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/metrics",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["outbox"]["delivered"], 1);
    assert_eq!(body["outbox"]["last_delivered_sequence"], seq);
}

/// Helper: open and store a real approval, optionally tenant-tagged, returning its id.
async fn store_test_approval(
    storage: &Arc<dyn StorageBackend>,
    credential: &str,
    tenant: Option<&str>,
) -> String {
    let (approval, _token) = ApprovalRequest::open(NewApproval {
        credential: credential.to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: tenant.map(|s| s.to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    storage.store_approval(&approval).await.unwrap();
    approval.id
}

#[tokio::test]
async fn test_a3_a4_json_approvals_list_and_decision() {
    // A3/A4: a product aggregator lists approvals and records a human decision
    // over the JSON admin-key surface. The surface requires a TENANT-SCOPED key
    // (a global/untenanted key is rejected 403 — see
    // test_json_approvals_reject_untenanted_key), so the key here is team-a-scoped
    // and the approval is tagged to the same tenant so it's visible to it.
    let (router, storage, key) = build_tenant_admin_router("team-a").await;
    let id = store_test_approval(&storage, "stripe-prod", Some("team-a")).await;

    // A3: GET /api/v1/approvals → the approval with the documented JSON shape.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/approvals",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let items = body["approvals"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let a = &items[0];
    assert_eq!(a["id"], id);
    assert_eq!(a["status"], "pending");
    assert_eq!(a["credential"], "stripe-prod");
    // Business verb takes precedence over the canonical action (mirrors the panel).
    assert_eq!(a["action"], "payments.refund");
    assert_eq!(a["required_approvals"], 1);
    assert_eq!(a["approvals_received"], 0);
    assert_eq!(a["is_open"], true);
    assert!(
        a["created_at"].as_str().unwrap().contains('T'),
        "ISO-8601 timestamp"
    );
    // `tenant` is always emitted (never skipped) so an aggregator can backstop-filter;
    // here the approval is tagged to the acting key's tenant.
    assert!(
        a.as_object().unwrap().contains_key("tenant"),
        "tenant field is always present"
    );
    assert_eq!(
        a["tenant"], "team-a",
        "approval carries its tenant in the JSON list"
    );

    // A3 status filter: a non-matching status yields an empty list.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/approvals?status=denied",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        body["approvals"].as_array().unwrap().len(),
        0,
        "filter excludes non-matching"
    );

    // A4: POST decision (approve) → 200 with the result shape; approval flips.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@example.com", "note": "looks good"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["id"], id);
    assert_eq!(body["status"], "approved");
    assert_eq!(body["approvals_received"], 1);
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
    // The decision is recorded as an AGGREGATOR-ASSERTED identity:
    // `agg:<api-key-id>:<operator>` — the human operator is preserved (and is a
    // CLAIM by the acting key, not a first-party verified identity), namespaced by
    // the asserting key id.
    let recorded = stored.approver_identity.as_deref().unwrap();
    assert!(
        recorded.starts_with("agg:"),
        "approver namespaced as an aggregator claim: {recorded}"
    );
    assert!(
        recorded.ends_with(":alice@example.com"),
        "human operator preserved: {recorded}"
    );
    assert_eq!(stored.decided_by.as_deref(), Some("json-api"));

    // A4: re-deciding an already-decided approval → 409 (not actionable).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // A4: unknown id → 404.
    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/approvals/appr_does_not_exist/decision",
            &key,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_a4_decision_enforces_tenant_partition() {
    // A4 SECURITY: the JSON decision path is tenant-partitioned (unlike the global
    // HTML console). A tenant-A admin key must NOT be able to decide — or even
    // observe the existence of — a tenant-B approval. Build a router whose auth
    // manager holds a tenant-scoped admin key.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Mint an admin key, then re-seed the auth manager with a tenant-A-scoped clone
    // of it (same plaintext/hash, tenant set) — public API only.
    let seed = AuthManager::new();
    let (admin_key_plain, api_key) = seed.create_api_key("agg-team-a", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    // A tenant-B approval and a shared (untenanted) one.
    let b_id = store_test_approval(&storage, "b-cred", Some("team-b")).await;
    let shared_id = store_test_approval(&storage, "shared-cred", None).await;

    // A3: the team-A admin sees ONLY the shared approval, never team-B's.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/approvals",
            &admin_key_plain,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let visible = body["approvals"].as_array().unwrap();
    let ids: Vec<&str> = visible.iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains(&shared_id.as_str()),
        "shared approval is visible"
    );
    assert!(
        !ids.contains(&b_id.as_str()),
        "team-B approval must NOT leak into team-A's list"
    );
    // The one visible approval is the shared/untenanted one — its `tenant` is null,
    // the signal an aggregator uses to recognize a shared (non-tenant-scoped) approval.
    let shared = visible
        .iter()
        .find(|a| a["id"] == shared_id.as_str())
        .unwrap();
    assert!(
        shared["tenant"].is_null(),
        "shared approval carries tenant=null in the JSON list"
    );

    // A4: deciding the team-B approval as team-A → 404 (no cross-tenant oracle),
    // and the approval stays pending (the decision did NOT take effect).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", b_id),
            &admin_key_plain,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant decision must be 404, not allowed"
    );
    let stored = storage.get_approval(&b_id).await.unwrap().unwrap();
    assert_eq!(
        stored.status,
        vultrino::approval::ApprovalStatus::Pending,
        "the cross-tenant approval must remain undecided"
    );

    // A4: the team-A admin CAN decide the shared (untenanted) approval → 200.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", shared_id),
            &admin_key_plain,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "shared approval is decidable by any tenant admin"
    );
}

#[tokio::test]
async fn test_json_approvals_reject_untenanted_key() {
    // SECURITY (#1): the per-tenant aggregator surface must reject a GLOBAL
    // (untenanted) admin key with 403 on BOTH the list and the decision routes —
    // a None-tenant key is the global HTML-console surface, not this one, and
    // letting it through would expose every tenant's approvals. build_admin_router
    // mints a None-tenant admin key.
    let (router, storage, _server, key) = build_admin_router().await;
    let id = store_test_approval(&storage, "stripe-prod", Some("team-a")).await;

    // GET list → 403 (no enumeration, no body of approvals).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/approvals",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "untenanted key cannot list"
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "tenant_required");
    assert!(
        body.get("approvals").is_none(),
        "403 must not leak the approvals list"
    );

    // POST decision → 403 BEFORE any lookup (can't even probe an id's existence),
    // and the approval stays pending.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "untenanted key cannot decide"
    );
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(
        stored.status,
        vultrino::approval::ApprovalStatus::Pending,
        "decision by an untenanted key must not take effect",
    );
}

/// Helper: mint a use token bound to `agent_label` in `tenant`, persist it, and
/// return its id.
async fn store_tenant_use_token(
    storage: &Arc<dyn StorageBackend>,
    name: &str,
    agent_label: &str,
    tenant: Option<&str>,
) -> String {
    let (_plain, mut token) = UseToken::create(NewUseToken {
        name: name.to_string(),
        credential_scope: "cred-*".into(),
        action_scope: Some("tool.*".into()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.tenant = tenant.map(|t| t.to_string());
    token.agent_label = Some(agent_label.to_string());
    storage.store_use_token(&token).await.unwrap();
    token.id
}

/// SECURITY (#0): a TENANT-scoped admin key must never halt, tamper with, or read
/// ANOTHER tenant's state through the admin API. Operator-only surfaces (halt,
/// policy CRUD — no tenant field) reject it 403; tenant-carrying surfaces
/// (use-token revoke) return 404 for a cross-tenant id and leave the resource
/// UNTOUCHED, while self-service on the key's OWN tenant still works. Mirrors the
/// cross-tenant-decide 404 shape.
#[tokio::test]
async fn test_admin_cross_tenant_denied_for_tenant_key() {
    let (router, storage, team_a_key) = build_tenant_admin_router("team-a").await;

    // Seed team-B and team-A resources in the same store the team-A router uses.
    let b_token = store_tenant_use_token(&storage, "b-tok", "ep_team_b", Some("team-b")).await;
    let a_token = store_tenant_use_token(&storage, "a-tok", "ep_team_a", Some("team-a")).await;
    storage
        .store_policy(&vultrino::policy::Policy::kill_switch(
            "kill-b",
            "ep_team_b",
        ))
        .await
        .unwrap();

    // Halt of a team-B agent → 403 operator_key_required (halt is operator-only).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/agents/ep_team_b/halt",
            &team_a_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tenant-scoped key must not halt any agent"
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "operator_key_required");
    // The team-B token is UNTOUCHED (the halt did not run and revoke it).
    assert!(
        !storage
            .get_use_token(&b_token)
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "a refused halt must not revoke the target tenant's token"
    );

    // Delete of a global policy → 403 (policies carry no tenant field).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/policies/kill-b",
            &team_a_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tenant-scoped key must not delete a policy"
    );
    // The policy survives.
    assert!(
        storage
            .list_stored_policies()
            .await
            .unwrap()
            .iter()
            .any(|p| p.id == "kill-b"),
        "a refused policy delete must leave the policy in place"
    );

    // Revoke of a team-B token → 404 (no oracle), token UNTOUCHED.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/tokens/{}/revoke", b_token),
            &team_a_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant token revoke must be 404 (no oracle)"
    );
    assert!(
        !storage
            .get_use_token(&b_token)
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "a refused cross-tenant revoke must leave the token unrevoked"
    );

    // Cross-tenant workload-grant deprovision → 403 (it would delete team-B's grant
    // and revoke its bound tokens). The guard fires before any store lookup.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/workload-grants/ep_team_b?tenant=team-b",
            &team_a_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tenant-scoped key must not deprovision another tenant's workload grant"
    );

    // Self-service on the key's OWN tenant still works → 200, token revoked.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/tokens/{}/revoke", a_token),
            &team_a_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a tenant key may revoke its OWN tenant's token"
    );
    assert!(
        storage
            .get_use_token(&a_token)
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "own-tenant revoke takes effect"
    );
}

/// SECURITY (#0): the GLOBAL operator key (tenant None) is UNAFFECTED by the
/// partition — it still halts, deletes policies, and revokes tokens across
/// tenants (govder's cross-plane kill/revoke path depends on this).
#[tokio::test]
async fn test_admin_global_key_unrestricted_across_tenants() {
    let (router, storage, _server, op_key) = build_admin_router().await;

    let b_token = store_tenant_use_token(&storage, "b-tok", "ep_team_b", Some("team-b")).await;
    storage
        .store_policy(&vultrino::policy::Policy::kill_switch(
            "kill-b",
            "ep_team_b",
        ))
        .await
        .unwrap();

    // Operator revokes a tenant-B token → 200.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/tokens/{}/revoke", b_token),
            &op_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "operator revokes any tenant");
    assert!(
        storage
            .get_use_token(&b_token)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );

    // Operator deletes a policy → 200.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "DELETE",
            "/api/v1/policies/kill-b",
            &op_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "operator deletes any policy");

    // Operator halts a tenant-B agent → 200.
    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/agents/ep_team_b/halt",
            &op_key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "operator halts any agent");
}

#[tokio::test]
async fn test_json_decision_is_idempotent_on_retry() {
    // #4: a retried decision (same operator, same approve/deny outcome) on an
    // already-decided approval returns 200 with the current summary — NOT a 409 —
    // so a network timeout after a committed decision is safe to retry.
    let (router, storage, key) = build_tenant_admin_router("team-a").await;
    let id = store_test_approval(&storage, "stripe-prod", Some("team-a")).await;

    let decide = |approve: bool| {
        admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": approve, "approver": "alice@example.com"}),
        )
    };

    // First approve → 200, status approved.
    let resp = router.clone().oneshot(decide(true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Same operator approving again (the retry) → 200 idempotent replay, NOT 409.
    let resp = router.clone().oneshot(decide(true)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "same-operator same-outcome retry is idempotent"
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");
    assert_eq!(body["idempotent_replay"], true);

    // A CONFLICTING decision (deny after approve) from the same key is still a 409,
    // not silently swallowed.
    let resp = router.oneshot(decide(false)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a different outcome on a decided approval is a conflict"
    );
}

#[tokio::test]
async fn test_json_decision_hard_sod_blocks_same_key_second_signoff() {
    // #2: under hard separation-of-duty, a SINGLE aggregator key must not satisfy a
    // dual-control (M-of-N) threshold by inventing two distinct operator names.
    // The first sign-off records `agg:<key-id>:alice`; the second from the same key
    // (`agg:<key-id>:bob`) is rejected 409 before it can satisfy threshold 2.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let seed = AuthManager::new();
    let (key, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    // Config with hard SoD enforcement on the decision path.
    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    // A dual-control (2-of-N) approval tagged to the acting tenant.
    let (approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: Some("team-a".to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: true,
        criticality: vultrino::approval::CriticalityClass::High,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 2,
        approval_rule: None,
    });
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();

    // First sign-off as "alice" → 200, still awaiting a second distinct approver.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        body["status"], "pending",
        "one of two sign-offs: still open"
    );
    assert_eq!(body["approvals_received"], 1);

    // Second sign-off as a DIFFERENT operator name but the SAME aggregator key →
    // 409. The key cannot fabricate the second distinct approver under hard SoD.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "bob@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "the same aggregator key cannot satisfy M-of-N with a second invented name",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "separation_of_duty");

    // The approval is still pending (not granted by the single key).
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(
        stored.signoffs.len(),
        1,
        "the second same-key sign-off was not recorded"
    );
}

/// Build a tenant-scoped, hard-SoD router + a stored dual-control (2-of-N)
/// approval, returning (router, storage, key, approval-id). Shared by the same-key
/// M-of-N regression tests.
async fn build_hard_sod_dual_control_fixture(
    tenant: &str,
) -> (axum::Router, Arc<dyn StorageBackend>, String, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let seed = AuthManager::new();
    let (key, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some(tenant.to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    let (approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: Some(tenant.to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: true,
        criticality: vultrino::approval::CriticalityClass::High,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 2,
        approval_rule: None,
    });
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();
    (router, storage, key, id)
}

#[tokio::test]
async fn test_json_decision_hard_sod_blocks_same_key_no_operator_then_operator() {
    // [HIGH regression] One key must not satisfy 2-of-N by MIXING a no-`approver`
    // call (recorded `agg:<key>:-`) with an `approver` call (recorded
    // `agg:<key>:op`). Before the fix the no-approver call recorded the BARE key
    // id, which neither prefix-based guard recognized → bypass. Now both share the
    // `agg:<key>:` prefix, so the second is rejected and the request stays Pending.
    let (router, storage, key, id) = build_hard_sod_dual_control_fixture("team-a").await;

    // (1) no operator → recorded agg:<key>:- , 1 of 2, still Pending.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        body["status"], "pending",
        "first (no-operator) sign-off keeps it open"
    );
    assert_eq!(body["approvals_received"], 1);

    // (2) same key, now WITH an operator → must be rejected 409, NOT granted.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "anyone@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "no-operator-then-operator from one key must NOT satisfy 2-of-N",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "separation_of_duty");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(
        stored.signoffs.len(),
        1,
        "the second same-key sign-off was not recorded"
    );
}

/// Build a tenant-scoped, hard-SoD router + a stored RECIPE-gated approval
/// (`dual_control: false, required_approvals: 1` — the exact shape an ordinary
/// require_approval token opens with; a stamped recipe REPLACES the numeric
/// threshold in `transition`, so this is deliberately NOT a dual-control shape).
/// Mirrors `build_hard_sod_dual_control_fixture` but stamps the caller-supplied
/// `ApprovalRule` and an explicit `authoritative_risk_tier`.
///
/// `risk_tier` MUST be passed explicitly (not left as the `NewApproval`-derived
/// default): the default empty `authoritative_risk_tier` is treated as Extreme
/// worst-case and force-coerces `decision_mode` to `DenyOnAnyDeny` regardless of
/// the rule's own setting (see `ApprovalRequest::authoritative_risk_tier` doc),
/// which would silently defeat the `MajorityWithDissentRecorded` matrix cases.
async fn build_hard_sod_recipe_fixture(
    tenant: &str,
    rule: ApprovalRule,
    risk_tier: &str,
) -> (axum::Router, Arc<dyn StorageBackend>, String, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let seed = AuthManager::new();
    let (key, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some(tenant.to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    let (mut approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: Some(tenant.to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::High,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: Some(rule),
    });
    approval.authoritative_risk_tier = risk_tier.to_string();
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();
    (router, storage, key, id)
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_senior_pair_one_key_409() {
    // HTTP-layer mirror of `recipe_hard_sod_senior_cannot_fabricate_teammate_slots_via_one_key`
    // (Senior + Senior on one key): a Senior fills a Teammate slot (senior ⊇
    // teammate), so two Seniors asserted by the SAME aggregator key must not be
    // able to fabricate the two distinct humans a {teammate:2} recipe requires.
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 2,
            }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (router, storage, key, id) = build_hard_sod_recipe_fixture("team-a", rule, "High").await;

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-alice@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["approvals_received"], 1);

    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-bob@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "two seniors asserted by one key must not fabricate two teammate slots",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "separation_of_duty");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(
        stored.signoffs.len(),
        1,
        "the second same-key sign-off was not recorded"
    );
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_senior_then_teammate_one_key_409() {
    // HTTP-layer mirror of the Senior-then-Teammate leg of
    // `recipe_hard_sod_senior_cannot_fabricate_teammate_slots_via_one_key`: the
    // existing senior already contributes a teammate slot, so a differently-classed
    // second sign-off from the SAME key is equally rejected.
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 2,
            }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (router, storage, key, id) = build_hard_sod_recipe_fixture("team-a", rule, "High").await;

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-carol@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-dave@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "senior-then-teammate on one key must not fabricate two teammate slots",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "separation_of_duty");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(stored.signoffs.len(), 1);
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_teammate_then_senior_one_key_409() {
    // HTTP-layer mirror of the REVERSE ordering (Codex RE-REVIEW-6
    // order-independence): a teammate first, then a senior on the same key. The
    // senior would also fill a teammate slot, so this is equally rejected.
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 2,
            }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (router, storage, key, id) = build_hard_sod_recipe_fixture("team-a", rule, "High").await;

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-erin@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "fake-frank@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "teammate-then-senior on one key must not fabricate two teammate slots",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "separation_of_duty");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(stored.signoffs.len(), 1);
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_unsatisfiable_branch_then_senior_allowed() {
    // HTTP-layer mirror of `recipe_hard_sod_unsatisfiable_branch_positive_does_not_poison_key`:
    // rule is `{teammate:1, agent-reviewer:1}` OR `{senior:1}`. The agent-reviewer
    // term is never satisfiable here, so a teammate positive toward that branch
    // fills no VIABLE slot and must not poison the aggregator key for a later
    // senior clearing the other branch.
    let rule = ApprovalRule {
        recipes: vec![
            Recipe {
                terms: vec![
                    RecipeTerm {
                        class: ApproverClass::Teammate,
                        count: 1,
                    },
                    RecipeTerm {
                        class: ApproverClass::AgentReviewer,
                        count: 1,
                    },
                ],
            },
            Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 1,
                }],
            },
        ],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (router, storage, key, id) = build_hard_sod_recipe_fixture("team-a", rule, "High").await;

    // Teammate toward the unsatisfiable branch — recorded, still pending.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "bob@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "pending");

    // Senior on the SAME key clears the {senior:1} branch — must NOT be 409.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a positive toward an unsatisfiable branch must not veto the senior on that key",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_dissent_then_distinct_approve_allowed() {
    // HTTP-layer mirror of `recipe_hard_sod_majority_dissent_does_not_poison_aggregator_key`:
    // a recorded majority-mode DISSENT must not poison the per-tenant aggregator
    // key — Feir OS uses ONE vultrino key per tenant, so a dissent and a later
    // distinct approval routinely share a key.
    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 1,
            }],
        }],
        decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
    };
    // "High" (required): majority-with-dissent semantics are only honored below
    // Extreme — Extreme/irreversible force DenyOnAnyDeny regardless of the rule's
    // own decision_mode, which would make the dissent terminal.
    let (router, storage, key, id) = build_hard_sod_recipe_fixture("team-a", rule, "High").await;

    // Carol dissents through the tenant key — non-terminal at High.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": false, "approver": "carol@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "pending");

    // Alice — a distinct real teammate — approves through the SAME key. Her single
    // positive is all {teammate:1} requires; the recorded dissent must not veto it.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a dissent on the per-tenant key must not veto a distinct approver on that key",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
}

#[tokio::test]
async fn test_json_decision_recipe_hard_sod_two_distinct_keys_allowed() {
    // Proves the fast-fail is KEY-scoped, not a blanket recipe block: a senior via
    // key A then a teammate via a DISTINCT key B legitimately clear a {teammate:2}
    // recipe (a senior is a valid teammate-slot filler — mirrors the "two DISTINCT
    // keys still clear it" tail of
    // `recipe_hard_sod_senior_cannot_fabricate_teammate_slots_via_one_key`).
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Two DISTINCT aggregator admin keys, both scoped to team-a (mirrors the
    // two-key fixture in `test_json_decision_idempotent_for_coapprover_retry_on_granted_mofn`).
    let seed = AuthManager::new();
    let (key_a, api_key_a) = seed.create_api_key("agg-a", "admin", None).unwrap();
    let (key_b, api_key_b) = seed.create_api_key("agg-b", "admin", None).unwrap();
    let mut tk_a = api_key_a.clone();
    tk_a.tenant = Some("team-a".to_string());
    let mut tk_b = api_key_b.clone();
    tk_b.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tk_a.clone(), tk_b.clone()]);
    storage.store_api_key(&tk_a).await.unwrap();
    storage.store_api_key(&tk_b).await.unwrap();

    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    let rule = ApprovalRule {
        recipes: vec![Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 2,
            }],
        }],
        decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
    };
    let (mut approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: Some("team-a".to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::High,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: Some(rule),
    });
    approval.authoritative_risk_tier = "High".to_string();
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();

    // Senior via key A.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key_a,
            serde_json::json!({"approve": true, "approver": "alice@corp", "approver_class": "senior"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "pending");

    // Teammate via a DIFFERENT key B → clears the recipe, no 409.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key_b,
            serde_json::json!({"approve": true, "approver": "bob@corp", "approver_class": "teammate"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a senior + a teammate on DISTINCT keys legitimately fill {{teammate:2}}",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
}

#[tokio::test]
async fn test_json_decision_hard_sod_blocks_same_key_operator_then_no_operator() {
    // [HIGH regression] The reverse ordering: an `approver` call first, then a
    // no-`approver` call (the sentinel) from the same key. Both must count as ONE
    // key — the second is rejected. Also exercises the AUTHORITATIVE in-lock guard:
    // the second decision still goes through transition() (which re-checks under
    // the storage lock), so even if the API fast-fail were bypassed it can't
    // double-sign.
    let (router, storage, key, id) = build_hard_sod_dual_control_fixture("team-a").await;

    // (1) with operator → recorded agg:<key>:alice@ , 1 of 2, Pending.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["approvals_received"], 1);

    // (2) same key, NO operator (sentinel) → rejected 409, stays Pending.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "operator-then-no-operator from one key must NOT satisfy 2-of-N",
    );
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert_eq!(
        stored.signoffs.len(),
        1,
        "the second same-key sign-off was not recorded"
    );
}

#[tokio::test]
async fn test_json_decision_hard_sod_catches_aggregator_self_approval() {
    // [#2 regression] An NHI whose OWNER is alice@ approved by human alice@ through
    // the aggregator (recorded as `agg:<key>:alice@`) is a self-approval. SoD is
    // computed against the BARE operator, so under hard SoD this is rejected 409 —
    // the agg: namespacing must NOT let a self-approval slip past.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let seed = AuthManager::new();
    let (key, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    // An approval whose requesting NHI's OWNER is alice@example.com.
    let (mut approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some("nhi-1".to_string()),
            principal_name: Some("refund-bot".to_string()),
            role: Some("executor".to_string()),
            owner: Some("alice@example.com".to_string()),
        },
        use_token_id: None,
        principal_id: Some("nhi-1".to_string()),
        agent_label: None,
        tenant: Some("team-a".to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    // Make sure the requester owner is what we expect after open().
    approval.requester.owner = Some("alice@example.com".to_string());
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();

    // alice@ approving her own NHI's action via the aggregator → 409, stays pending.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "alice@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "aggregator self-approval (owner == operator) must be caught under hard SoD",
    );
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(
        stored.status,
        vultrino::approval::ApprovalStatus::Pending,
        "the self-approval must not take effect",
    );

    // A DIFFERENT operator (not the owner) is allowed → 200, approved.
    let resp = router
        .oneshot(admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            &key,
            serde_json::json!({"approve": true, "approver": "bob@example.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a distinct operator may approve"
    );
    let stored = storage.get_approval(&id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Approved);
}

#[tokio::test]
async fn test_json_decision_idempotent_for_coapprover_retry_on_granted_mofn() {
    // [#14] After a 2-of-N approval is GRANTED by two distinct aggregator keys, a
    // retry by the FIRST co-approver (not the finalizing one) must replay 200, not
    // 409 — idempotency matches ANY recorded sign-off, not just approver_identity.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Two DISTINCT aggregator admin keys, both scoped to team-a.
    let seed = AuthManager::new();
    let (key_a, api_key_a) = seed.create_api_key("agg-a", "admin", None).unwrap();
    let (key_b, api_key_b) = seed.create_api_key("agg-b", "admin", None).unwrap();
    let mut tk_a = api_key_a.clone();
    tk_a.tenant = Some("team-a".to_string());
    let mut tk_b = api_key_b.clone();
    tk_b.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tk_a.clone(), tk_b.clone()]);
    storage.store_api_key(&tk_a).await.unwrap();
    storage.store_api_key(&tk_b).await.unwrap();

    let mut sod_config = Config::default();
    sod_config.approval.enforce_separation_of_duty = true;

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        sod_config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    let (approval, _token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        requester: RequesterInfo::local(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: Some("team-a".to_string()),
        workload_id: None,
        preview: None,
        action_label: Some("payments.refund".to_string()),
        dual_control: true,
        criticality: vultrino::approval::CriticalityClass::High,
        trusted_irreversible: None,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 2,
        approval_rule: None,
    });
    let id = approval.id.clone();
    storage.store_approval(&approval).await.unwrap();

    let approve = |k: &str, op: &str| {
        admin_req(
            "POST",
            &format!("/api/v1/approvals/{}/decision", id),
            k,
            serde_json::json!({"approve": true, "approver": op}),
        )
    };

    // Key A signs off (1 of 2) → still pending.
    let resp = router
        .clone()
        .oneshot(approve(&key_a, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Key B signs off (2 of 2) → granted.
    let resp = router
        .clone()
        .oneshot(approve(&key_b, "bob@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");

    // The FIRST co-approver (key A / alice) retries on the now-granted approval →
    // 200 idempotent replay (NOT 409), even though alice is not the FINALIZING
    // approver (bob is).
    let resp = router
        .oneshot(approve(&key_a, "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a co-approver's retry on a granted M-of-N is idempotent, not a conflict",
    );
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["status"], "approved");
    assert_eq!(body["idempotent_replay"], true);
}

#[tokio::test]
async fn test_admin_token_mint_trims_owner_identity() {
    // V10: a padded owner_identity is trimmed at the mint (so SoD comparisons match).
    let (router, storage, _server, key) = build_admin_router().await;
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({
                "name": "owned-bot",
                "credential_scope": "pay-*",
                "owner_identity": "  alice@example.com  "
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tokens = storage.list_use_tokens().await.unwrap();
    let t = tokens.iter().find(|t| t.name == "owned-bot").unwrap();
    assert_eq!(
        t.owner_identity.as_deref(),
        Some("alice@example.com"),
        "owner trimmed"
    );
}

#[tokio::test]
async fn test_v10_inbound_svid_resolves_into_evaluated_principal() {
    // R6: a SPIFFE SVID presented inbound (an already transport-verified document
    // in the configured header) is resolved into the principal evaluated by policy
    // — proven by a principal_pattern Deny that only fires when the SVID, not the
    // static vut_ id, is the principal.
    use vultrino::auth::{NewUseToken, UseToken};
    use vultrino::config::{IdentityConfig, IdentityResolverKind};
    use vultrino::policy::Policy;
    use vultrino::{Credential, CredentialData, Secret};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Config: a SPIFFE resolver on `x-spiffe-verified`, plus a Deny scoped to the
    // SVID's trust domain. Allow mode so a non-matching principal isn't denied.
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.identity = Some(IdentityConfig {
        kind: IdentityResolverKind::Spiffe,
        header: "x-spiffe-verified".to_string(),
        allowed: vec!["example.org".to_string()],
    });
    config.policies =
        vec![Policy::deny_all("block-svid", "*").with_principal("spiffe://example.org/*")];

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let web = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        AuthManager::new(),
        admin,
        exec_server,
    );
    let router = web.into_router();

    // A credential + a use token to authenticate the /execute call.
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
    let (secret, token) = UseToken::create(NewUseToken {
        name: "svid-bot".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // 127.0.0.1 fails SSRF fast, so the no-SVID control errors on the plugin, not
    // the policy — keeping the two outcomes cleanly distinguishable.
    let body = serde_json::json!({
        "credential": "api-cred",
        "method": "GET",
        "url": "http://127.0.0.1/x"
    });
    let exec_req = |with_svid: bool| {
        let mut b = Request::builder()
            .method("POST")
            .uri("/api/v1/execute")
            .header("authorization", format!("Bearer {}", secret))
            .header("content-type", "application/json");
        if with_svid {
            b = b.header("x-spiffe-verified", "spiffe://example.org/ns/prod/sa/agent");
        }
        b.body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };

    // WITH the SVID: the resolved principal matches the trust-domain Deny → blocked
    // by that policy specifically (proves the SVID is the evaluated principal).
    let resp = router.clone().oneshot(exec_req(true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_string(resp).await.contains("block-svid"),
        "the inbound SVID must be the evaluated principal (denied by its policy)"
    );

    // WITHOUT the SVID: the principal is the vut_ id, which the SVID policy does
    // NOT match → it proceeds past policy and fails later (SSRF), not by block-svid.
    let resp = router.clone().oneshot(exec_req(false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        !body_string(resp).await.contains("block-svid"),
        "without the SVID the trust-domain policy must not fire"
    );
}

#[tokio::test]
async fn test_v10_inbound_oidc_resolves_subject_and_binds_owner() {
    // R6: the OIDC resolver path (incl. the owner-binding branch, which SPIFFE
    // never exercises since SPIFFE owner is always None) — an inbound OIDC claims
    // doc resolves subject -> Principal.workload_id and a human claim -> owner,
    // observable on the approval it opens.
    use vultrino::auth::{NewUseToken, UseToken};
    use vultrino::config::{IdentityConfig, IdentityResolverKind};
    use vultrino::{Credential, CredentialData, Secret};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.identity = Some(IdentityConfig {
        kind: IdentityResolverKind::Oidc,
        header: "x-oidc-claims".to_string(),
        allowed: vec!["https://idp.example.com".to_string()],
    });

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let web = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        AuthManager::new(),
        admin,
        exec_server,
    );
    let router = web.into_router();

    // A require_approval credential so the call opens an approval we can inspect.
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("require_approval", "true");
    storage.store(&cred).await.unwrap();
    let (secret, token) = UseToken::create(NewUseToken {
        name: "oidc-bot".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let body = serde_json::json!({ "credential": "api-cred", "method": "GET", "url": "https://api.example.com/x" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/execute")
        .header("authorization", format!("Bearer {}", secret))
        .header("content-type", "application/json")
        .header(
            "x-oidc-claims",
            r#"{"sub":"user-7","iss":"https://idp.example.com","email":"alice@example.com"}"#,
        )
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "require_approval opens an approval"
    );

    // The opened approval carries the resolved OIDC subject (workload_id) and the
    // human owner (email) bound from the claims — proving both branches fired.
    let approvals = storage.list_approvals().await.unwrap();
    assert_eq!(approvals.len(), 1);
    let a = &approvals[0];
    assert_eq!(
        a.workload_id.as_deref(),
        Some("user-7"),
        "OIDC subject -> workload_id"
    );
    assert_eq!(
        a.requester.owner.as_deref(),
        Some("alice@example.com"),
        "OIDC email -> owner binding"
    );
}

/// Regression (V13a): an admin-installed per-agent Deny installed via `PUT
/// /api/v1/policies/{id}` must bite on the VERY NEXT `/execute` and on EVERY
/// call across multiple periodic-refresh cycles — never flickering out.
///
/// The bug: the background refresh (`refresh_policies_once` → `storage.reload()`)
/// re-read the vault from disk WITHOUT the cross-process lock, then overwrote the
/// in-memory cache. Interleaved with `store_policy` (which holds the lock to
/// read-disk → rename-new-file → update-cache), `reload` could read the OLD
/// snapshot but assign the cache AFTER the store committed — clobbering the
/// just-stored Deny out of the in-memory cache (still durable on disk) until the
/// next mutation/reload. `list_stored_policies` reads that cache, so the engine
/// dropped the Deny for a window → `/execute` flickered to allowed.
///
/// This test runs the REAL refresh loop at a tight interval against the shared
/// storage+engine and hammers `/execute` past several refresh cycles, asserting
/// every call is denied by *that* policy (its name in the body), with no flicker.
/// Outbox is disabled (no URL/secret in `Config::default()`, no delivery loop).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_admin_deny_does_not_flicker_under_periodic_refresh() {
    use std::time::{Duration, Instant};
    use vultrino::auth::{NewUseToken, UseToken};
    use vultrino::policy::{EvalInput, Principal};
    use vultrino::{Credential, CredentialData, Secret};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // default_action = Allow so that, ABSENT our Deny, the agent's call proceeds
    // PAST policy (and fails later on SSRF) rather than being denied by the
    // engine default — making a flicker (deny → allow) cleanly observable.
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    assert!(
        config.outbox.url.is_none() && config.outbox.hmac_secret.is_none(),
        "this regression must run with the outbox disabled"
    );

    // Mint an admin key so the admin PUT is accepted.
    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager
        .create_api_key("admin-key", "admin", None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let web = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config.clone(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server.clone(),
    );
    let router = web.into_router();

    // A credential + a use token carrying the agent label the Deny targets.
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
    let (secret, mut token) = UseToken::create(NewUseToken {
        name: "halt-bot".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("halt-bot".to_string());
    storage.store_use_token(&token).await.unwrap();

    // Spawn the REAL cross-process refresh against the SAME storage + engine —
    // `refresh_policies_once` (storage.reload() then engine.load_policies(union)),
    // the exact path that clobbered the cache. One loop runs at the production-like
    // 2ms tick to set the cadence; several additional zero-delay loops maximize the
    // chance a reload lands inside the store_and_reload_policy commit→list window
    // (the flicker window), so the regression is hit reliably in-process rather
    // than depending on a single lucky interleaving. A shutdown flag lets the loops
    // exit cleanly before the runtime tears down.
    let refresh_interval = Duration::from_millis(2);
    let refresh_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut refreshers = Vec::new();
    for tight in [false, true, true, true] {
        let storage = storage.clone();
        let engine = Arc::clone(exec_server.policy_engine());
        let config_policies = config.policies.clone();
        let stop = refresh_stop.clone();
        refreshers.push(tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ =
                    vultrino::server::refresh_policies_once(&storage, &engine, &config_policies)
                        .await;
                if tight {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(refresh_interval).await;
                }
            }
        }));
    }

    // Install a per-agent Deny via the admin API (PUT /api/v1/policies/{id}).
    let deny_id = "deny-halt-bot";
    let put = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &format!("/api/v1/policies/{}", deny_id),
            &admin_key,
            serde_json::json!({
                "name": "block-halt-bot",
                "credential_pattern": "*",
                "principal_pattern": "halt-bot",
                "default_action": "deny"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK, "admin PUT Deny must succeed");

    // Drive CONCURRENT admin policy writes (each a locked_mutate store/delete of
    // an UNRELATED policy) so the refresh loop's reload() interleaves with stores.
    // That interleaving is precisely what clobbered a just-stored policy in the
    // buggy lock-free reload: reload reads the pre-store disk snapshot, the store
    // commits (disk + cache), then reload overwrites the cache with its stale
    // snapshot — dropping the admin Deny from the in-memory cache that
    // list_stored_policies feeds the engine. The Deny is durable on disk, so it
    // flickers back on the next clean reload. Without this churn there is no
    // concurrent store to lose, and the race never fires.
    let churn_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let churn = {
        let storage = storage.clone();
        let stop = churn_stop.clone();
        tokio::spawn(async move {
            use vultrino::policy::Policy;
            let mut n = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let p = Policy::deny_all(format!("churn-{n}"), "nonmatch-*");
                let id = p.id.clone();
                let _ = storage.store_policy(&p).await;
                let _ = storage.delete_policy(&id).await;
                n += 1;
                tokio::task::yield_now().await;
            }
        })
    };

    let exec_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/execute")
            .header("authorization", format!("Bearer {}", secret))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "credential": "api-cred",
                    "method": "GET",
                    "url": "http://example.com/x"
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    // The agent's EvalInput, as the engine sees it for this principal/credential.
    let principal = Principal {
        id: token.id.clone(),
        agent_label: Some("halt-bot".to_string()),
        owner: None,
        workload_id: None,
    };
    let eval = || EvalInput {
        credential_alias: "api-cred",
        url: Some("http://example.com/x"),
        method: Some("GET"),
        action: None,
        principal: Some(&principal),
        spend: None,
    };

    // Hammer /execute across well over 2 refresh cycles. EVERY call must be denied
    // by *our* policy (name in body) — never flickering to allowed, and never the
    // engine-default deny. Also probe the engine directly each iteration so a
    // single in-memory clobber is caught even if the HTTP path happened to miss it.
    // Iteration-driven (not wall-clock) so the call count is deterministic; the
    // per-iter sleep + the 2ms refresh interval guarantee we span many cycles.
    const ITERATIONS: u32 = 60;
    let start = Instant::now();
    let mut calls = 0u32;
    let mut crossed_cycles = 0u32;
    let mut last = Instant::now();
    for i in 0..ITERATIONS {
        // Re-PUT the per-agent Deny through the REAL admin path every iteration.
        // This is the load-bearing part of the reproduction: store_and_reload_policy
        // does store_policy (commit) -> reload_policies -> list_stored_policies (reads
        // the in-memory cache). A concurrent refresh reload() that read the pre-store
        // disk snapshot but assigns the cache inside this window clobbers the
        // just-stored Deny out of the cache -> the engine loads a policy set WITHOUT
        // it -> the deny flickers off until the next clean reload. The very next
        // assertions (engine + /execute) must STILL see the Deny: it took effect on
        // the very next call, deterministically.
        let put = router
            .clone()
            .oneshot(admin_req(
                "PUT",
                &format!("/api/v1/policies/{}", deny_id),
                &admin_key,
                serde_json::json!({
                    "name": "block-halt-bot",
                    "credential_pattern": "*",
                    "principal_pattern": "halt-bot",
                    "default_action": "deny"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            put.status(),
            StatusCode::OK,
            "re-PUT #{i} of the Deny must succeed"
        );

        // Engine truth: the per-agent Deny must be present immediately after the PUT.
        match exec_server.policy_engine().evaluate_full(&eval()) {
            vultrino::policy::PolicyDecision::Deny(reason) => {
                assert!(
                    reason.contains("block-halt-bot"),
                    "iter {i}: engine denied but not by the admin policy: {reason}"
                );
            }
            other => panic!("iter {i}: engine flickered — per-agent Deny vanished -> {other:?}"),
        }
        // HTTP truth: /execute denied by our policy (BAD_REQUEST + policy name).
        let resp = router.clone().oneshot(exec_req()).await.unwrap();
        let status = resp.status();
        let body = body_string(resp).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "iter {i}: /execute flickered: expected policy deny, got {status} body={body}"
        );
        assert!(
            body.contains("block-halt-bot"),
            "iter {i}: /execute denied by the wrong reason (flicker/default): {body}"
        );
        calls += 1;
        if last.elapsed() >= refresh_interval {
            crossed_cycles += 1;
            last = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    churn_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = churn.await;
    refresh_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for r in refreshers {
        let _ = r.await;
    }

    assert_eq!(calls, ITERATIONS, "expected to hammer every iteration");
    // The fixed iteration count plus per-iter sleep spans far more than 2 refresh
    // cycles; assert it explicitly (both by counter and elapsed time) so the
    // "across >2 refresh cycles" acceptance criterion is enforced, not assumed.
    assert!(
        crossed_cycles > 2 && start.elapsed() > refresh_interval * 3,
        "test must span more than 2 refresh cycles, spanned ~{crossed_cycles} in {:?}",
        start.elapsed()
    );

    // After all the refresh churn, the Deny is still durable in storage AND live
    // in the engine — proving it was never lost, just consistently enforced.
    assert!(
        storage.get_policy(deny_id).await.unwrap().is_some(),
        "the admin Deny must remain persisted after the refresh churn"
    );
    assert!(
        exec_server
            .policy_engine()
            .list_policies()
            .iter()
            .any(|p| p.id == deny_id),
        "the admin Deny must remain in the live engine after the refresh churn"
    );
}

/// Regression (V13a), deterministic core: the periodic refresh's `storage.reload()`
/// must NOT lose a policy that `store_policy` just committed.
///
/// This pins the exact mechanism behind the intermittent admin-Deny flicker. The
/// admin write path does `store_policy` (commit under the cross-process lock) then
/// `list_stored_policies` (reads the in-memory cache) to load the engine — the same
/// cache the periodic refresh overwrites. Before the fix, `reload()` re-read the
/// vault from disk WITHOUT the lock: it could read the pre-`store_policy` snapshot
/// and then assign that stale snapshot to the cache AFTER the store committed,
/// dropping the just-stored policy from the cache (it stays durable on disk) until
/// the next reload. `store_policy` is followed here by an immediate
/// `list_stored_policies` — exactly what `store_and_reload_policy` does — and any
/// miss is a lost update. With `reload()` taking the same lock, read-disk +
/// assign-cache is atomic w.r.t. the store, so a committed policy is never lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reload_never_loses_a_just_stored_policy() {
    use vultrino::policy::Policy;

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Background reloaders hammer storage.reload() (the refresh loop's first step),
    // racing the stores below. Multiple loops widen the lost-update window.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut reloaders = Vec::new();
    for _ in 0..3 {
        let storage = storage.clone();
        let stop = stop.clone();
        reloaders.push(tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = storage.reload().await;
                tokio::task::yield_now().await;
            }
        }));
    }

    // Repeatedly store a fresh Deny and assert it's visible in the cache on the
    // VERY NEXT read — the lost-update the flicker came from. Delete after each so
    // the disk genuinely oscillates (each store's pre-state lacks that id), which
    // is what lets a stale clobber drop it.
    let mut lost = 0u32;
    for i in 0..3000 {
        let p = Policy::deny_all(format!("deny-{i}"), "*");
        let id = p.id.clone();
        storage.store_policy(&p).await.unwrap();
        // store_and_reload_policy reads the cache here (list_stored_policies) to
        // load the engine; a missing id means the engine would load WITHOUT the Deny.
        if !storage
            .list_stored_policies()
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == id)
        {
            lost += 1;
        }
        let _ = storage.delete_policy(&id).await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for r in reloaders {
        let _ = r.await;
    }

    assert_eq!(
        lost, 0,
        "store_policy was clobbered by a concurrent reload() {lost} times — \
         the admin Deny would flicker out under the periodic refresh"
    );
}

// `GET /api/v1/policies` lists the live (enforced) engine policies, read-gated,
// sorted by id, as a REDUCED DTO (id/name/kill/content_hash) — the read side the
// govder reconciliation sweep diffs against. The list must NOT leak enforcement
// topology (rules/patterns/default_action), and the content_hash must equal the
// value echoed at author time.
#[tokio::test]
async fn test_admin_list_policies() {
    let (router, _storage, server, key) = build_admin_router().await;

    // Two policies created out of id order; the list must come back sorted by id.
    // Capture the content_hash echoed by the create response (the authored value).
    let mut authored_hash: std::collections::HashMap<String, String> = Default::default();
    for name in ["zeta", "alpha"] {
        let resp = router
            .clone()
            .oneshot(admin_req(
                "POST",
                "/api/v1/policies",
                &key,
                serde_json::json!({"name":name,"credential_pattern":"github-*","default_action":"deny"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        // The create response echoes the canonical policy PLUS a content_hash, and
        // keeps the existing id/name fields intact (additive).
        let id = created["id"].as_str().unwrap().to_string();
        assert_eq!(created["name"], name);
        let ch = created["content_hash"].as_str().unwrap();
        // With a secret configured, the hash is a KEYED HMAC (self-describing prefix).
        assert!(
            ch.starts_with("hmac-sha256:"),
            "content_hash must be hmac-sha256:<hex>: {}",
            ch
        );
        assert_eq!(
            ch.len(),
            "hmac-sha256:".len() + 64,
            "hmac-sha256 hex must be 64 chars"
        );
        authored_hash.insert(id, ch.to_string());
    }
    let live = server.policy_engine().list_policies().len();

    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/policies",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = body_string(resp).await;
    let listed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let arr = listed["policies"].as_array().unwrap();
    // The endpoint returns the full live engine set (config + stored), not just
    // what this test created — assert it matches the engine count.
    assert_eq!(arr.len(), live);
    // Sorted by id.
    let ids: Vec<&str> = arr.iter().map(|p| p["id"].as_str().unwrap()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "policies must be sorted by id");

    // REDUCED DTO: only id/name/kill/content_hash; no enforcement topology leaks.
    for item in arr {
        let obj = item.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["content_hash", "id", "kill", "name"],
            "reduced DTO fields only"
        );
        // The listed content_hash equals the value captured at author time.
        let id = obj["id"].as_str().unwrap();
        if let Some(expected) = authored_hash.get(id) {
            assert_eq!(
                obj["content_hash"].as_str().unwrap(),
                expected,
                "listed content_hash must equal the authored value"
            );
        }
    }
    // No enforcement topology anywhere in the serialized list.
    assert!(
        !raw.contains("credential_pattern"),
        "list must not leak credential_pattern"
    );
    assert!(
        !raw.contains("principal_pattern"),
        "list must not leak principal_pattern"
    );
    assert!(
        !raw.contains("default_action"),
        "list must not leak default_action"
    );
    assert!(!raw.contains("\"rules\""), "list must not leak rules");

    // Non-admin (no key) is rejected before any policy data is returned.
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// content_hash changes when the policy's semantic content changes: create →
// capture hash → PUT a DIFFERENT rule set at the same id → the listed hash differs.
#[tokio::test]
async fn test_policy_content_hash_changes_on_rule_edit() {
    let (router, _storage, _server, key) = build_admin_router().await;

    // Create with one rule set.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &key,
            serde_json::json!({
                "name": "h",
                "credential_pattern": "github-*",
                "default_action": "deny",
                "rules": [ { "condition": { "method_match": ["GET"] }, "action": "allow" } ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let hash_v1 = created["content_hash"].as_str().unwrap().to_string();

    // The listed hash equals the create-time hash (same content).
    let listed_hash = |router: axum::Router, id: &str| {
        let id = id.to_string();
        let key = key.clone();
        async move {
            let resp = router
                .oneshot(admin_req(
                    "GET",
                    "/api/v1/policies",
                    &key,
                    serde_json::json!({}),
                ))
                .await
                .unwrap();
            let listed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
            listed["policies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["id"].as_str() == Some(&id))
                .unwrap()["content_hash"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    assert_eq!(listed_hash(router.clone(), &id).await, hash_v1);

    // Idempotent re-PUT of IDENTICAL content → SAME hash (deterministic given the
    // secret; an unchanged policy must never register as false drift).
    let resp = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &format!("/api/v1/policies/{}", id),
            &key,
            serde_json::json!({
                "name": "h",
                "credential_pattern": "github-*",
                "default_action": "deny",
                "rules": [ { "condition": { "method_match": ["GET"] }, "action": "allow" } ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let same: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(
        same["content_hash"].as_str().unwrap(),
        hash_v1,
        "identical content must yield the same hash (no false drift)"
    );

    // PUT a DIFFERENT rule set at the same id → content_hash must change.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "PUT",
            &format!("/api/v1/policies/{}", id),
            &key,
            serde_json::json!({
                "name": "h",
                "credential_pattern": "github-*",
                "default_action": "deny",
                "rules": [ { "condition": { "method_match": ["POST"] }, "action": "allow" } ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let replaced: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let hash_v2 = replaced["content_hash"].as_str().unwrap().to_string();
    assert_ne!(
        hash_v1, hash_v2,
        "content_hash must change when rules change"
    );
    assert_eq!(
        listed_hash(router, &id).await,
        hash_v2,
        "listed hash tracks the new content"
    );
}

// With NO policy-hash secret configured, content_hash must be EMPTY in BOTH the
// create/replace response AND the list — removing the brute-force oracle. govder
// degrades gracefully (it skips drift detection on an empty hash). The hash must
// NOT fall back to a bare unkeyed digest.
#[tokio::test]
async fn test_policy_content_hash_empty_without_secret() {
    // No secret configured (None).
    let (router, _storage, _server, key, _read_key) = build_admin_router_full(None).await;

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &key,
            serde_json::json!({
                "name": "n",
                "credential_pattern": "github-*",
                "default_action": "deny",
                "rules": [ { "condition": { "method_match": ["GET"] }, "action": "allow" } ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    // The field is present (additive contract preserved) but EMPTY — no oracle.
    assert_eq!(
        created["content_hash"].as_str(),
        Some(""),
        "create hash must be empty without a secret"
    );

    // The list item's content_hash is likewise empty, and certainly not a bare digest.
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/policies",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let raw = body_string(resp).await;
    let listed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let item = listed["policies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"].as_str() == Some(&id))
        .expect("policy must be listed");
    assert_eq!(
        item["content_hash"].as_str(),
        Some(""),
        "listed hash must be empty without a secret"
    );
    // No bare-digest fallback anywhere (neither scheme prefix appears).
    assert!(
        !raw.contains("sha256:"),
        "must not emit any sha256/hmac-sha256 digest without a secret"
    );
}

// V1: a least-privilege read-only key can GET the inventory endpoints but is
// rejected by the mutating admin routes; an admin key can do both.
#[tokio::test]
async fn test_read_only_key_inventory_least_privilege() {
    let (router, _storage, _server, admin_key, read_key) = build_admin_router_with_read().await;

    // Read-only key CAN list tokens and policies (200).
    for uri in ["/api/v1/tokens", "/api/v1/policies"] {
        let resp = router
            .clone()
            .oneshot(admin_req("GET", uri, &read_key, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "read key must GET {}", uri);
    }

    // Read-only key CANNOT mutate: POST /policies and POST /tokens → 403.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &read_key,
            serde_json::json!({"name":"p","credential_pattern":"*","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "read key must not POST policies"
    );

    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &read_key,
            serde_json::json!({"name":"t","credential_scope":"*"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "read key must not POST tokens"
    );

    // Admin key CAN do all: GET inventory AND POST.
    for uri in ["/api/v1/tokens", "/api/v1/policies"] {
        let resp = router
            .clone()
            .oneshot(admin_req("GET", uri, &admin_key, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "admin key must GET {}", uri);
    }
    let resp = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/policies",
            &admin_key,
            serde_json::json!({"name":"p","credential_pattern":"*","default_action":"allow"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "admin key must POST policies"
    );

    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &admin_key,
            serde_json::json!({"name":"t","credential_scope":"*"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "admin key must POST tokens"
    );
}

// `GET /api/v1/tokens` lists use tokens as NON-SECRET metadata — id/prefix/scopes,
// never the token hash or plaintext. This is the read side for the govder
// reconciliation sweep's orphan-token detection; the no-secret invariant is the
// security crux (a leaked hash is offline-crackable / a leaked plaintext is a key).
#[tokio::test]
async fn test_admin_list_tokens_is_non_secret() {
    let (router, _storage, _server, key) = build_admin_router().await;

    // Mint a token bound to an agent_label (so the list carries the principal).
    let mint = router
        .clone()
        .oneshot(admin_req(
            "POST",
            "/api/v1/tokens",
            &key,
            serde_json::json!({"name":"t-recon","credential_scope":"cred-*","agent_label":"researcher.v1"}),
        ))
        .await
        .unwrap();
    let minted: serde_json::Value = serde_json::from_str(&body_string(mint).await).unwrap();
    let plaintext = minted["token"].as_str().unwrap().to_string();
    let token_id = minted["metadata"]["id"].as_str().unwrap().to_string();

    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/tokens",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = body_string(resp).await;

    // The minted token is present with the fields the sweep needs (id, agent_label).
    let listed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let tok = listed["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == token_id)
        .expect("minted token must appear in the list");
    assert_eq!(tok["name"], "t-recon");
    assert_eq!(tok["credential_scope"], "cred-*");
    assert_eq!(tok["agent_label"], "researcher.v1");

    // NO-SECRET INVARIANT: neither the hash nor the plaintext may appear anywhere
    // in the response — not as a field, not embedded in any value.
    assert!(
        tok.get("token_hash").is_none(),
        "token_hash must never be listed"
    );
    assert!(
        !raw.contains("token_hash"),
        "no token_hash key anywhere in the response"
    );
    assert!(
        !raw.contains(&plaintext),
        "the token plaintext must never appear in the list"
    );

    // Non-admin is rejected.
    let resp = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/tokens")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Govder-unreachable 503 fail-closed branches (plan 031). These three handlers
// only ever run when govder is either unconfigured or unreachable, so they get
// NO coverage from any feature-gated suite (delegate_approval_integration.rs
// always stands up a live mock govder). Exercised here, in the un-gated
// web-smoke suite, so `cargo test` (no features) always runs them.
// ============================================================================

/// Store a minimal `vap_` approval token directly in storage (bypassing the
/// `POST /api/v1/approval-tokens` mint route, which itself requires govder —
/// these tests need a *usable* token while govder is absent/unreachable).
async fn store_delegate_token(storage: &Arc<dyn StorageBackend>, tenant: Option<&str>) -> String {
    let (plaintext, token) = ApprovalToken::create(NewApprovalToken {
        delegation_grant_ref: "grant_test_001".to_string(),
        grant_scope: DelegationGrantScope::default(),
        agent_label: Some("delegate-bot".to_string()),
        delegator_identity: "alice@corp".to_string(),
        tenant: tenant.map(str::to_string),
        expires_in: None,
    });
    storage.store_approval_token(&token).await.unwrap();
    plaintext
}

/// Open and store a minimal pending approval directly (bypassing the execute
/// path — these tests only need a decidable record for the delegate-decision
/// handler to load before it reaches the govder check).
async fn store_pending_approval(
    storage: &Arc<dyn StorageBackend>,
    tenant: Option<&str>,
) -> ApprovalRequest {
    let (approval, _decision_token) = ApprovalRequest::open(NewApproval {
        credential: "stripe-prod".to_string(),
        action: "http.request".to_string(),
        params: serde_json::json!({"method": "post"}),
        requester: RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some("k1".to_string()),
            principal_name: Some("agent".to_string()),
            role: Some("executor".to_string()),
            owner: None,
        },
        use_token_id: None,
        principal_id: Some("k1".to_string()),
        agent_label: Some("ep_requester_acme".to_string()),
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        trusted_irreversible: Some(false),
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
        tenant: tenant.map(str::to_string),
        workload_id: None,
        preview: None,
    });
    storage.store_approval(&approval).await.unwrap();
    approval
}

#[tokio::test]
async fn test_approval_token_mint_503s_when_govder_not_configured() {
    // build_admin_router's web Config carries no govder (Config::default()).
    let (router, _storage, _exec, admin_key) = build_admin_router().await;

    let resp = router
        .oneshot(admin_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": "grant_test_001",
                "agent_label": "delegate-bot",
                "delegator_identity": "alice@corp",
                "tenant": "acme"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "govder_not_configured");
}

#[tokio::test]
async fn test_delegate_decide_503s_when_govder_not_configured() {
    // build_router's web Config carries no govder (Config::default()).
    let (router, storage) = build_router().await;

    let vap_secret = store_delegate_token(&storage, Some("acme")).await;
    let approval = store_pending_approval(&storage, Some("acme")).await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/approvals/{}/delegate-decision",
                    approval.id
                ))
                .header("authorization", format!("Bearer {}", vap_secret))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"approve": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "govder_not_configured");
}

#[tokio::test]
async fn test_delegate_decide_503s_when_govder_unreachable() {
    // Bind a socket to reserve a free port, then drop it immediately so the
    // port is provably unreachable (connection refused) — no listener stands
    // up at `govder_url` for the whole test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let govder_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);

    let mut config = Config::default();
    config.approval.enabled = true;
    config.govder = Some(GovderConfig {
        base_url: govder_url,
        assertion_secret: "test-govder-assertion-secret".to_string(),
        assertion_ttl: Duration::from_secs(90),
        http_timeout: Duration::from_secs(5),
    });
    let (router, storage) = build_router_with_config(config).await;

    let vap_secret = store_delegate_token(&storage, Some("acme")).await;
    let approval = store_pending_approval(&storage, Some("acme")).await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/approvals/{}/delegate-decision",
                    approval.id
                ))
                .header("authorization", format!("Bearer {}", vap_secret))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"approve": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["code"], "govder_unavailable");
}

// -------- Tenant enforcement-mode read (shadow onboarding phase A) --------

/// Like [`build_tenant_admin_router`] but with tenant modes configured, so the
/// tenant-mode read endpoint has real Observe/Enforce entries to report.
async fn build_tenant_admin_router_with_modes(
    tenant: &str,
    config: Config,
) -> (axum::Router, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let seed = AuthManager::new();
    let (admin_key_plain, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some(tenant.to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();
    (router, admin_key_plain)
}

fn observe_config(tenant: &str) -> Config {
    let mut cfg = Config::default();
    cfg.tenants
        .insert(tenant.to_string(), vultrino::config::TenantMode::Observe);
    cfg.tenants.insert(
        "team-enforce".to_string(),
        vultrino::config::TenantMode::Enforce,
    );
    cfg
}

#[tokio::test]
async fn test_tenant_mode_observe_for_own_tenant() {
    let (router, key) =
        build_tenant_admin_router_with_modes("team-a", observe_config("team-a")).await;
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/tenant-mode",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["tenant"], "team-a");
    assert_eq!(body["mode"], "observe");
    assert_eq!(body["source"], "startup-config");
    assert!(body["loaded_at"].as_str().unwrap().contains('T'));
    // Exactly the four contract fields — never a config dump.
    assert_eq!(body.as_object().unwrap().len(), 4);
}

#[tokio::test]
async fn test_tenant_mode_explicit_and_default_enforce() {
    // Explicit Enforce entry, read by a global (untenanted) admin key.
    let (router, _storage, _srv, key) = build_admin_router().await;
    // build_admin_router uses Config::default() (no tenants) — every tenant
    // defaults to enforce, including unlisted ones.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/tenant-mode?tenant=unlisted-team",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["tenant"], "unlisted-team");
    assert_eq!(body["mode"], "enforce"); // fail-closed default

    // A global key must NAME the tenant.
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/tenant-mode",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_tenant_mode_requires_auth() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenant-mode?tenant=team-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_tenant_mode_cross_tenant_denied() {
    let (router, key) =
        build_tenant_admin_router_with_modes("team-a", observe_config("team-a")).await;
    // A team-a key asking about team-enforce is flatly denied.
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/tenant-mode?tenant=team-enforce",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Naming its OWN tenant explicitly is fine.
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/tenant-mode?tenant=team-a",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tenant_mode_rejects_bad_tenant_ids() {
    let (router, _storage, _srv, key) = build_admin_router().await;
    for bad in ["team%20a!", "a/b", "x%00y"] {
        let resp = router
            .clone()
            .oneshot(admin_req(
                "GET",
                &format!("/api/v1/tenant-mode?tenant={}", bad),
                &key,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "tenant id {:?}",
            bad
        );
    }
}

// -------- Would-deny reports (shadow onboarding phase B) --------

/// Seed observe-mode denial events for two tenants plus an unrelated event, then
/// assert the tenant-scoped read returns ONLY the caller's redacted reports.
#[tokio::test]
async fn test_would_deny_reports_tenant_filtered_and_redacted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Tenant-scoped key for team-a.
    let seed = AuthManager::new();
    let (key, api_key) = seed.create_api_key("agg", "admin", None).unwrap();
    let mut tenant_key = api_key.clone();
    tenant_key.tenant = Some("team-a".to_string());
    let auth_manager = AuthManager::from_data(seed.list_roles(), vec![tenant_key.clone()]);
    storage.store_api_key(&tenant_key).await.unwrap();

    // Would-deny events for team-a (one with an agent_label, one with only a
    // principal_id, one with neither — FU1 must OMIT `agent` rather than
    // fabricate it), plus one for team-b carrying its own agent identity that
    // must never leak into team-a's redacted view.
    for (tenant, action, agent_label, principal_id) in [
        ("team-a", "db.write", Some("checkout-agent"), Some("vk_abc123")),
        ("team-a", "email.send", None, Some("vk_xyz789")),
        ("team-a", "report.export", None, None),
        ("team-b", "money.payout", Some("team-b-secret-agent"), Some("vk_teamb")),
    ] {
        storage
            .append_event(
                "obs",
                "policy.observed_denial",
                serde_json::json!({
                    "tenant": tenant,
                    "credential": "super-secret-alias",
                    "action": action,
                    "reason": "policy denies this action",
                    "would_have": "deny",
                    "outcome": "allowed_observe_mode",
                    "agent_label": agent_label,
                    "principal_id": principal_id,
                }),
            )
            .await
            .unwrap();
    }
    storage
        .append_event(
            "appr_1",
            "approval.approved",
            serde_json::json!({"tenant": "team-a"}),
        )
        .await
        .unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();

    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            "/api/v1/would-deny-reports",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = body_string(resp).await;
    let body: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(body["tenant"], "team-a");
    let reports = body["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 3, "only team-a's would-deny events: {}", raw);
    assert_eq!(reports[0]["action"], "db.write");
    // FU1: agent_label is preferred when the enforcement path stamped one.
    assert_eq!(reports[0]["agent"], "checkout-agent");
    assert_eq!(reports[1]["action"], "email.send");
    // FU1: no agent_label was stamped, so principal_id is the fallback.
    assert_eq!(reports[1]["agent"], "vk_xyz789");
    assert_eq!(reports[2]["action"], "report.export");
    // FU1 fail-closed honesty: neither was stamped, so `agent` is OMITTED
    // entirely — never fabricated as a placeholder.
    assert!(
        reports[2].get("agent").is_none(),
        "agent field must be omitted when the acting agent is unknown: {}",
        raw
    );
    // Redaction: the credential alias and other tenants never cross the wire.
    assert!(
        !raw.contains("super-secret-alias"),
        "credential alias leaked"
    );
    assert!(!raw.contains("team-b"), "another tenant's data leaked");
    assert!(
        !raw.contains("money.payout"),
        "another tenant's action leaked"
    );
    assert!(
        !raw.contains("team-b-secret-agent"),
        "another tenant's agent identity leaked"
    );
    assert!(
        !raw.contains("vk_teamb"),
        "another tenant's principal id leaked"
    );
    // Bounded-retention metadata + cursor are present.
    assert!(body["retention_secs"].as_u64().unwrap() > 0);
    assert!(body["next_after"].as_u64().unwrap() >= 5);
    assert_eq!(body["truncated"], false);

    // Cursor replay: after the last sequence there is nothing new.
    let next = body["next_after"].as_u64().unwrap();
    let resp = router
        .clone()
        .oneshot(admin_req(
            "GET",
            &format!("/api/v1/would-deny-reports?after={}", next),
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["reports"].as_array().unwrap().len(), 0);

    // Cross-tenant request is flatly denied.
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/would-deny-reports?tenant=team-b",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_would_deny_reports_requires_auth_and_tenant() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/would-deny-reports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A global key must name the tenant.
    let (router, _storage, _srv, key) = build_admin_router().await;
    let resp = router
        .oneshot(admin_req(
            "GET",
            "/api/v1/would-deny-reports",
            &key,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// -------- Plan 100 P2 Phase D: govder gate-rule fetch must fail CLOSED --------
//
// `fetch_gate_rule`/`fetch_gate_rule_for_action` distinguish a CONFIRMED "no
// rule" (404, or a 2xx body with `has_rule:false`, or govder simply not
// configured) from a genuine FETCH FAILURE (transport error, a non-2xx/non-404
// status, a body-read error, or a parse error). Only the former may fall back
// to today's numeric-threshold approval; the latter must block the
// approval-open entirely — a transient govder blip must never silently
// downgrade a recipe-gated approval to a weaker numeric one.

/// Store a `require_approval` credential plus a tenant+agent_label-bound use
/// token, then POST `/api/v1/execute` against it — the minimal fixture that
/// drives `prepare_execution` into the `fetch_gate_rule_for_action` call with a
/// non-empty tenant AND agent_id (both required for it to actually consult
/// govder rather than short-circuiting to `Ok(None)`).
async fn execute_against_require_approval_credential(
    router: axum::Router,
    storage: &Arc<dyn StorageBackend>,
) -> axum::response::Response {
    use vultrino::{Credential, CredentialData, Secret};

    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("require_approval", "true");
    storage.store(&cred).await.unwrap();

    let (secret, mut token) = UseToken::create(NewUseToken {
        name: "gate-rule-fixture".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.tenant = Some("acme".to_string());
    token.agent_label = Some("agent-x".to_string());
    storage.store_use_token(&token).await.unwrap();

    let body = serde_json::json!({
        "credential": "api-cred", "method": "GET", "url": "https://api.example.com/x"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/execute")
        .header("authorization", format!("Bearer {}", secret))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    router.oneshot(req).await.unwrap()
}

/// A mock govder that answers `GET /v1/oversight/gates/rule` with a caller-fixed
/// status + JSON body — used to drive both the "confirmed no rule" parity cases
/// (404, or 2xx `has_rule:false`) and (via a 5xx) a genuine fetch failure.
async fn start_mock_govder_gate_rule(status: StatusCode, body: serde_json::Value) -> GovderConfig {
    async fn handler(
        axum::extract::State((status, body)): axum::extract::State<(StatusCode, serde_json::Value)>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        (status, axum::Json(body)).into_response()
    }
    let app = axum::Router::new()
        .route(
            "/v1/oversight/gates/rule",
            axum::routing::get(handler),
        )
        .with_state((status, body));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    GovderConfig {
        base_url: format!("http://{addr}"),
        assertion_secret: "test-govder-assertion-secret".to_string(),
        assertion_ttl: Duration::from_secs(90),
        http_timeout: Duration::from_secs(5),
    }
}

fn approval_open_test_config(govder: GovderConfig) -> Config {
    let mut config = Config::default();
    // Fail-closed default (Deny) would deny before the credential-level
    // require_approval flag is ever consulted — Allow lets it through to the
    // gating branch, exactly like the existing OIDC approval-open test.
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.approval.enabled = true;
    config.govder = Some(govder);
    config
}

/// THE FIX: a genuine govder gate-rule fetch failure (here, connection refused
/// against a dead port — the same "provably unreachable" technique the
/// existing `test_delegate_decide_503s_when_govder_unreachable` test uses) must
/// FAIL THE APPROVAL-OPEN CLOSED. Before the fix, `fetch_gate_rule` swallowed
/// this into `None` and the action opened anyway under the numeric-threshold
/// path — a transient outage silently downgrading the effective oversight
/// requirement. Proven two ways: the HTTP call does not return 202 Accepted,
/// AND (load-bearing) no approval is ever persisted to storage at all.
#[tokio::test]
async fn execute_open_fails_closed_when_gate_rule_fetch_is_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let govder_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener); // provably unreachable: connection refused, no listener ever stands up

    let config = approval_open_test_config(GovderConfig {
        base_url: govder_url,
        assertion_secret: "test-govder-assertion-secret".to_string(),
        assertion_ttl: Duration::from_secs(90),
        http_timeout: Duration::from_secs(5),
    });
    let (router, storage) = build_router_with_config(config).await;

    let resp = execute_against_require_approval_credential(router, &storage).await;
    assert_ne!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a genuine govder gate-rule fetch failure must NOT open an approval"
    );

    assert!(
        storage.list_approvals().await.unwrap().is_empty(),
        "no approval may be persisted when the gate-rule fetch failed — fail-closed means the \
         action is blocked, not silently downgraded to the numeric-threshold path"
    );
}

/// A non-2xx/non-404 govder gate-rule status (a 500 here) is likewise a genuine
/// fetch failure, not a confirmed "no rule" — same fail-closed assertion as the
/// unreachable-transport case above, but exercising the HTTP-status branch of
/// `fetch_gate_rule` instead of the transport-error branch.
#[tokio::test]
async fn execute_open_fails_closed_when_gate_rule_returns_5xx() {
    let govder = start_mock_govder_gate_rule(
        StatusCode::INTERNAL_SERVER_ERROR,
        serde_json::json!({ "error": "boom" }),
    )
    .await;
    let config = approval_open_test_config(govder);
    let (router, storage) = build_router_with_config(config).await;

    let resp = execute_against_require_approval_credential(router, &storage).await;
    assert_ne!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a govder gate-rule 5xx must NOT open an approval"
    );
    assert!(
        storage.list_approvals().await.unwrap().is_empty(),
        "no approval may be persisted when the gate-rule fetch returned a 5xx"
    );
}

/// PARITY (unchanged behavior): a 404 — no gate configured for this
/// agent/action — is a CONFIRMED no-rule answer, so the action must still open
/// via today's numeric-threshold path exactly as if govder weren't configured
/// at all.
#[tokio::test]
async fn execute_open_numeric_path_parity_when_gate_rule_is_404() {
    let govder = start_mock_govder_gate_rule(StatusCode::NOT_FOUND, serde_json::json!({})).await;
    let config = approval_open_test_config(govder);
    let (router, storage) = build_router_with_config(config).await;

    let resp = execute_against_require_approval_credential(router, &storage).await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a 404 (confirmed no gate) must still open via the numeric-threshold path"
    );

    let approvals = storage.list_approvals().await.unwrap();
    assert_eq!(approvals.len(), 1);
    assert!(approvals[0].approval_rule.is_none());
    assert_eq!(approvals[0].required_approvals, 1);
}

/// PARITY (unchanged behavior): a 2xx body with `has_rule:false` — a gate
/// exists but has no rule stamped — is likewise a CONFIRMED no-rule answer.
#[tokio::test]
async fn execute_open_numeric_path_parity_when_gate_has_rule_false() {
    let govder = start_mock_govder_gate_rule(
        StatusCode::OK,
        serde_json::json!({ "has_rule": false }),
    )
    .await;
    let config = approval_open_test_config(govder);
    let (router, storage) = build_router_with_config(config).await;

    let resp = execute_against_require_approval_credential(router, &storage).await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a confirmed has_rule:false must still open via the numeric-threshold path"
    );

    let approvals = storage.list_approvals().await.unwrap();
    assert_eq!(approvals.len(), 1);
    assert!(approvals[0].approval_rule.is_none());
    assert_eq!(approvals[0].required_approvals, 1);
}

/// PARITY (unchanged behavior, pre-existing coverage restated here for
/// discoverability): govder simply not configured (`config.govder = None`,
/// `Config::default()`'s value) is ALSO a confirmed "no rule" — the
/// `fetch_gate_rule_for_action` short-circuit before ever calling govder. This
/// is the same shape `test_v10_inbound_oidc_resolves_subject_and_binds_owner`
/// (above) already exercises; restated as its own test so the three
/// "confirmed no rule" legs (404 / has_rule:false / not-configured) are each
/// independently visible.
#[tokio::test]
async fn execute_open_numeric_path_parity_when_govder_not_configured() {
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.approval.enabled = true;
    assert!(config.govder.is_none());
    let (router, storage) = build_router_with_config(config).await;

    let resp = execute_against_require_approval_credential(router, &storage).await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "no govder configured must still open via the numeric-threshold path"
    );

    let approvals = storage.list_approvals().await.unwrap();
    assert_eq!(approvals.len(), 1);
    assert!(approvals[0].approval_rule.is_none());
    assert_eq!(approvals[0].required_approvals, 1);
}
