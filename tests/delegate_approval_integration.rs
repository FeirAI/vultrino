//! Integration test for delegate-agent approval decisions (plan 031 phase 3).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::approval::{NewApproval, RequesterInfo};
use vultrino::auth::AuthManager;
use vultrino::config::Config;
use vultrino::outbox::EVENT_APPROVAL_APPROVED;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};

async fn build_admin_router() -> (axum::Router, Arc<dyn StorageBackend>, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager.create_api_key("admin-key", "admin", None).unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let mut config = Config::default();
    config.approval.enabled = true;

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
        auth_manager,
        admin,
        exec_server,
    );
    (server.into_router(), storage, admin_key)
}

fn bearer_req(method: &str, uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn delegate_approval_records_approver_kind_in_outbox() {
    let (router, storage, admin_key) = build_admin_router().await;

    // Mint a vap_ approval token via the admin API.
    let mint_resp = router
        .clone()
        .oneshot(bearer_req(
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
    assert_eq!(mint_resp.status(), StatusCode::CREATED);
    let mint_body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(mint_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    let vap_secret = mint_body["token"].as_str().unwrap().to_string();
    assert!(vap_secret.starts_with("vap_"));

    // Open a pending approval in the same tenant.
    let (mut approval, _oob) = vultrino::approval::ApprovalRequest::open(NewApproval {
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
        agent_label: None,
        tenant: Some("acme".to_string()),
        workload_id: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
    });
    storage.store_approval(&approval).await.unwrap();

    // Delegate approves via vap_ bearer.
    let decide_resp = router
        .oneshot(bearer_req(
            "POST",
            &format!("/api/v1/approvals/{}/delegate-decision", approval.id),
            &vap_secret,
            serde_json::json!({"approve": true}),
        ))
        .await
        .unwrap();
    assert_eq!(decide_resp.status(), StatusCode::OK);

    approval = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(approval.status, vultrino::approval::ApprovalStatus::Approved);
    assert_eq!(approval.signoffs.len(), 1);
    assert_eq!(approval.signoffs[0].approver_kind, "delegate-agent");
    assert_eq!(
        approval.signoffs[0].delegation_grant_ref.as_deref(),
        Some("grant_test_001")
    );
    assert_eq!(approval.signoffs[0].channel, "delegate-agent");

    let events = storage.list_events_after(0, 100).await.unwrap();
    let approved = events
        .iter()
        .find(|e| e.event_type == EVENT_APPROVAL_APPROVED)
        .expect("approval.approved event in outbox");
    assert_eq!(approved.payload["approver_kind"], "delegate-agent");
    assert_eq!(approved.payload["delegation_grant_ref"], "grant_test_001");
}