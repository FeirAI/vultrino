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
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: Some("oncall".to_string()),
        reauth_interval_secs: None,
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
