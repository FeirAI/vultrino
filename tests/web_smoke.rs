//! In-process smoke tests for the web admin surface.
//!
//! These exercise the real Axum router (routes + Askama template rendering)
//! without binding a socket or touching the user's home directory, using
//! `tower::ServiceExt::oneshot`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::approval::{ApprovalRequest, NewApproval, RequesterInfo};
use vultrino::auth::AuthManager;
use vultrino::config::Config;
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

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Build a router plus a minted admin API key (vk_) the auth manager recognizes,
/// and a handle to the shared exec server so tests can inspect the live engine.
async fn build_admin_router() -> (
    axum::Router,
    Arc<dyn StorageBackend>,
    Arc<vultrino::server::VultrinoServer>,
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
    let (admin_key, api_key) = auth_manager.create_api_key("admin-key", "admin", None).unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig { bind: "127.0.0.1:0".to_string(), enabled: true },
        Config::default(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server.clone(),
    );
    (server.into_router(), storage, exec_server, admin_key)
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
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("ok"));
}

#[tokio::test]
async fn test_login_page_renders() {
    let (router, _) = build_router().await;
    let resp = router
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
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
    assert!(server.policy_engine().list_policies().iter().any(|p| p.id == id));

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
    assert_eq!(storage.get_policy(&id).await.unwrap().unwrap().name, "allow-gh-2");

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
        .oneshot(admin_req("DELETE", &format!("/api/v1/policies/{}", id), &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.list_stored_policies().await.unwrap().len(), 0);
    assert!(!server.policy_engine().list_policies().iter().any(|p| p.id == id));
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
        .oneshot(admin_req("GET", "/api/v1/capabilities", &key, serde_json::json!({})))
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
    assert_eq!(storage.get_capability(&id).await.unwrap().unwrap().tool_name, "send_email_v2");

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
        .oneshot(admin_req("DELETE", &format!("/api/v1/capabilities/{}", id), &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.list_capabilities().await.unwrap().len(), 0);

    // Deleting again → 404.
    let resp = router
        .oneshot(admin_req("DELETE", &format!("/api/v1/capabilities/{}", id), &key, serde_json::json!({})))
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
    assert!(v2["token"].is_null(), "replay must not re-expose the plaintext token");
    assert_eq!(storage.list_use_tokens().await.unwrap().len(), 1, "no duplicate token minted");

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
    assert!(storage.get_use_token(&token_id).await.unwrap().unwrap().revoked);

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
        .oneshot(admin_req("DELETE", &format!("/api/v1/credentials/{}", cred_id), &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(storage.get_by_alias("c1").await.unwrap().is_none());
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
    assert_eq!(router.clone().oneshot(put("id1", "same")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(router.oneshot(put("id2", "same")).await.unwrap().status(), StatusCode::CONFLICT);
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
    let tok = storage.get_use_token(v["metadata"]["id"].as_str().unwrap()).await.unwrap().unwrap();
    assert_eq!(tok.max_uses, Some(5));
    assert!(tok.require_approval);
    assert!(!tok.dual_control);

    // Unknown strictness → 400.
    let r = router
        .oneshot(mint(serde_json::json!({"name":"x","credential_scope":"*","strictness":"loose"})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
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
    assert_eq!(router.clone().oneshot(mint("bot-*")).await.unwrap().status(), StatusCode::BAD_REQUEST);
    assert_eq!(router.clone().oneshot(mint("cred:foo")).await.unwrap().status(), StatusCode::BAD_REQUEST);
    // A plain label is accepted.
    assert_eq!(router.oneshot(mint("refund-bot")).await.unwrap().status(), StatusCode::CREATED);
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
    assert_eq!(router.clone().oneshot(mint(0)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    assert_eq!(router.clone().oneshot(mint(-5)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    assert_eq!(router.clone().oneshot(mint(i64::MAX)).await.unwrap().status(), StatusCode::BAD_REQUEST);
    // A sane lifetime succeeds.
    assert_eq!(router.oneshot(mint(3600)).await.unwrap().status(), StatusCode::CREATED);
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
    assert_eq!(r2.status(), StatusCode::CREATED, "multi-key metadata must replay, not 409");
    assert_eq!(storage.list().await.unwrap().len(), 1, "no duplicate credential");
}

#[tokio::test]
async fn test_admin_delete_role_in_use_conflict() {
    let (router, storage, _server, key) = build_admin_router().await;
    // Create a custom role via the admin API.
    let r = router
        .clone()
        .oneshot(admin_req("POST", "/api/v1/roles", &key, serde_json::json!({"name":"temp","permissions":["read"]})))
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
        .oneshot(admin_req("DELETE", &format!("/api/v1/roles/{}", role_id), &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert!(body_string(r).await.contains("role_in_use"));
}

#[tokio::test]
async fn test_admin_cannot_delete_builtin_role() {
    let (router, _storage, _server, key) = build_admin_router().await;
    let resp = router
        .oneshot(admin_req("DELETE", "/api/v1/roles/admin", &key, serde_json::json!({})))
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
                serde_json::to_vec(&serde_json::json!({"name":name,"credential_scope":"*"})).unwrap(),
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
    assert!(v3["token"].is_null(), "replay must not return the plaintext token");
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
    assert!(!body.contains("super-secret-value"), "secret must not be echoed: {body}");
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
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: Some("oncall".to_string()),
        reauth_interval_secs: None,
        required_approvals: 1,
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
                .uri(format!("/approvals/{}/decide?token=wrong&decision=approve", approval.id))
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
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None, // no named identity bound
        reauth_interval_secs: None,
        required_approvals: 1,
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
        .oneshot(admin_req("POST", "/api/v1/agents/bot-7/halt", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let out: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(out["agent_label"], "bot-7");
    assert_eq!(out["deny_policy_id"], "halt:bot-7");

    // The authoritative kill policy landed in the live engine and storage.
    assert!(server.policy_engine().list_policies().iter().any(|p| p.id == "halt:bot-7" && p.kill));
    assert!(storage.get_policy("halt:bot-7").await.unwrap().is_some());

    // GET /sessions → 200, per-process scope, empty here (nothing in flight).
    let resp = router
        .clone()
        .oneshot(admin_req("GET", "/api/v1/sessions", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["process_scope"], true);
    assert!(body["sessions"].as_array().unwrap().is_empty());

    // DELETE halt → lifts it; the kill policy is gone from the engine.
    let resp = router
        .clone()
        .oneshot(admin_req("DELETE", "/api/v1/agents/bot-7/halt", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!server.policy_engine().list_policies().iter().any(|p| p.id == "halt:bot-7"));

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
        .oneshot(admin_req("POST", "/api/v1/agents/bot-*/halt", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // No kill policy was installed.
    assert!(!server.policy_engine().list_policies().iter().any(|p| p.kill));
}

#[tokio::test]
async fn test_admin_event_replay_api() {
    // V9: events emitted by admin actions are replayable from a cursor.
    let (router, _storage, _server, key) = build_admin_router().await;

    // A halt emits an agent.halted event.
    let resp = router
        .clone()
        .oneshot(admin_req("POST", "/api/v1/agents/bot-7/halt", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /api/v1/events?after=0 → the event + a next_cursor.
    let resp = router
        .clone()
        .oneshot(admin_req("GET", "/api/v1/events?after=0", &key, serde_json::json!({})))
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
        .oneshot(admin_req("GET", &format!("/api/v1/events?after={cursor}"), &key, serde_json::json!({})))
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert!(body["events"].as_array().unwrap().is_empty());

    // The DLQ endpoint works (empty here).
    let resp = router
        .clone()
        .oneshot(admin_req("GET", "/api/v1/events/dead", &key, serde_json::json!({})))
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
async fn test_admin_metrics_readback() {
    // V12: the metrics endpoint returns the structured read-back, admin-only.
    let (router, _storage, _server, key) = build_admin_router().await;
    let resp = router
        .clone()
        .oneshot(admin_req("GET", "/api/v1/metrics", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(body["unauthorized_attempts"], 0);
    assert_eq!(body["approvals"]["total"], 0);
    assert!(body["approval_latency_secs"]["count"].is_u64());

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
    assert_eq!(t.owner_identity.as_deref(), Some("alice@example.com"), "owner trimmed");
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
    config.policies = vec![Policy::deny_all("block-svid", "*").with_principal("spiffe://example.org/*")];

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let web = WebServer::new(
        WebConfig { bind: "127.0.0.1:0".to_string(), enabled: true },
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
        b.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
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
        WebConfig { bind: "127.0.0.1:0".to_string(), enabled: true },
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
    assert_eq!(resp.status(), StatusCode::ACCEPTED, "require_approval opens an approval");

    // The opened approval carries the resolved OIDC subject (workload_id) and the
    // human owner (email) bound from the claims — proving both branches fired.
    let approvals = storage.list_approvals().await.unwrap();
    assert_eq!(approvals.len(), 1);
    let a = &approvals[0];
    assert_eq!(a.workload_id.as_deref(), Some("user-7"), "OIDC subject -> workload_id");
    assert_eq!(a.requester.owner.as_deref(), Some("alice@example.com"), "OIDC email -> owner binding");
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
    assert!(config.outbox.url.is_none() && config.outbox.hmac_secret.is_none(),
        "this regression must run with the outbox disabled");

    // Mint an admin key so the admin PUT is accepted.
    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager.create_api_key("admin-key", "admin", None).unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let web = WebServer::new(
        WebConfig { bind: "127.0.0.1:0".to_string(), enabled: true },
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
                let _ = vultrino::server::refresh_policies_once(&storage, &engine, &config_policies)
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
        method: Some("GET"), action: None,
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
        assert_eq!(put.status(), StatusCode::OK, "re-PUT #{i} of the Deny must succeed");

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
        exec_server.policy_engine().list_policies().iter().any(|p| p.id == deny_id),
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
        if !storage.list_stored_policies().await.unwrap().iter().any(|x| x.id == id) {
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

// `GET /api/v1/policies` lists the live (enforced) engine policies, admin-gated,
// sorted by id — the read side the govder reconciliation sweep diffs against.
#[tokio::test]
async fn test_admin_list_policies() {
    let (router, _storage, server, key) = build_admin_router().await;

    // Two policies created out of id order; the list must come back sorted by id.
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
    }
    let live = server.policy_engine().list_policies().len();

    let resp = router
        .clone()
        .oneshot(admin_req("GET", "/api/v1/policies", &key, serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let arr = listed["policies"].as_array().unwrap();
    // The endpoint returns the full live engine set (config + stored), not just
    // what this test created — assert it matches the engine count.
    assert_eq!(arr.len(), live);
    // Sorted by id.
    let ids: Vec<&str> = arr.iter().map(|p| p["id"].as_str().unwrap()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "policies must be sorted by id");

    // Non-admin is rejected before any policy data is returned.
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
        .oneshot(admin_req("GET", "/api/v1/tokens", &key, serde_json::json!({})))
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
    assert!(tok.get("token_hash").is_none(), "token_hash must never be listed");
    assert!(!raw.contains("token_hash"), "no token_hash key anywhere in the response");
    assert!(!raw.contains(&plaintext), "the token plaintext must never appear in the list");

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
