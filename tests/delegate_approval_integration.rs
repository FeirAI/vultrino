//! Integration test for delegate-agent approval decisions (plan 031 phase 3).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::Router;
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

/// Mock govder webhook consumer: records every signed delivery vultrino's outbox pushes.
#[derive(Clone, Default)]
struct WebhookCapture(Arc<Mutex<Vec<(String, Vec<u8>)>>>);

async fn mock_govder_webhook(
    State(cap): State<WebhookCapture>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let sig = headers
        .get("Govder-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    cap.0.lock().unwrap().push((sig, body.to_vec()));
    StatusCode::OK
}

#[tokio::test]
async fn delegate_decision_delivers_signed_webhook_to_govder_consumer() {
    const WEBHOOK_SECRET: &str = "govder_v9_secret";

    let capture = WebhookCapture::default();
    let cap_state = capture.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let webhook_url = format!(
        "http://{}/webhooks/vultrino-approvals",
        listener.local_addr().unwrap()
    );
    let mock = Router::new()
        .route(
            "/webhooks/vultrino-approvals",
            post(mock_govder_webhook).with_state(cap_state),
        );
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let (router, storage, admin_key) = build_admin_router().await;

    // Wire outbox push to the mock govder receiver (production deliver_outbox_once path).
    let mut config = Config::default();
    config.approval.enabled = true;
    config.outbox = vultrino::outbox::OutboxConfig {
        enabled: true,
        url: Some(webhook_url),
        hmac_secret: Some(WEBHOOK_SECRET.to_string()),
        max_attempts: 3,
        retention_secs: 3600,
    };

    let mint_resp = router
        .clone()
        .oneshot(bearer_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": "grant_webhook_001",
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

    let (approval, _oob) = vultrino::approval::ApprovalRequest::open(NewApproval {
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

    let client = reqwest::Client::new();
    for _ in 0..8 {
        vultrino::server::deliver_outbox_once(&storage, &config.outbox, &client)
            .await
            .unwrap();
    }

    let deliveries = capture.0.lock().unwrap().clone();
    assert!(
        !deliveries.is_empty(),
        "outbox must POST at least one signed webhook to govder consumer"
    );
    let approved = deliveries
        .iter()
        .find(|(_, body)| {
            serde_json::from_slice::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("event").and_then(|e| e.as_str().map(|s| s.to_string())))
                == Some("approval.approved".to_string())
        })
        .expect("approval.approved delivery must reach govder consumer");
    let (sig, body) = approved;
    let expected_sig = vultrino::outbox::sign_body(WEBHOOK_SECRET, body);
    assert_eq!(*sig, expected_sig, "Govder-Signature must match vultrino sign_body");

    let delivered: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(delivered["event"], "approval.approved");
    assert_eq!(delivered["payload"]["approver_kind"], "delegate-agent");
    assert_eq!(delivered["payload"]["delegation_grant_ref"], "grant_webhook_001");
    assert_eq!(delivered["payload"]["tenant"], "acme");
}