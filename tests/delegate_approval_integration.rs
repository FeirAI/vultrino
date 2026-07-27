//! Integration test for delegate-agent approval decisions (plan 031 phase 3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::approval::{NewApproval, RequesterInfo};
use vultrino::auth::AuthManager;
use vultrino::config::Config;
use vultrino::delegation::{evaluate_delegate_decision, DelegateEvalInput, DelegationGrantScope};
use vultrino::govder::GovderConfig;
use vultrino::outbox::EVENT_APPROVAL_APPROVED;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};

const TEST_GOVDER_SECRET: &str = "test-govder-assertion-secret";

#[derive(Clone)]
struct MockGrant {
    grant_id: String,
    tenant_id: String,
    delegate_agent_id: String,
    delegate_agent_ep: Option<String>,
    scope: DelegationGrantScope,
    revoked: bool,
    expiry: Option<String>,
}

#[derive(Clone, Default)]
struct MockGovderState {
    grants: Arc<HashMap<String, Vec<MockGrant>>>,
    evaluate_hits: Arc<Mutex<usize>>,
}

async fn start_mock_govder(grants: Vec<MockGrant>) -> GovderConfig {
    let mut by_tenant: HashMap<String, Vec<MockGrant>> = HashMap::new();
    for g in grants {
        by_tenant.entry(g.tenant_id.clone()).or_default().push(g);
    }
    let state = MockGovderState {
        grants: Arc::new(by_tenant),
        evaluate_hits: Arc::new(Mutex::new(0)),
    };
    let app = Router::new()
        .route("/v1/delegation/grants", get(mock_list_grants))
        .route(
            "/v1/delegation/evaluate-decision",
            post(mock_evaluate_delegate_decision),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    GovderConfig {
        base_url: format!("http://{addr}"),
        assertion_secret: TEST_GOVDER_SECRET.to_string(),
        assertion_ttl: Duration::from_secs(90),
        http_timeout: Duration::from_secs(5),
    }
}

async fn mock_list_grants(
    State(st): State<MockGovderState>,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    assert!(
        headers.get("X-Govder-Tenant-Assertion").is_some(),
        "mock govder expects tenant assertion"
    );
    // Tests use a single tenant per case; return all grants (lookup filters by id).
    let grants: Vec<_> = st
        .grants
        .values()
        .flatten()
        .map(|g| {
            serde_json::json!({
                "grant_id": g.grant_id,
                "tenant_id": g.tenant_id,
                "delegate_agent_id": g.delegate_agent_id,
                "delegate_agent_ep": g.delegate_agent_ep,
                "scope": {
                    "max_risk_tier": g.scope.max_risk_tier,
                    "action_classes": g.scope.action_classes,
                },
                "revoked": g.revoked,
                "expiry": g.expiry,
            })
        })
        .collect();
    axum::Json(serde_json::json!({ "grants": grants }))
}

async fn mock_evaluate_delegate_decision(
    State(st): State<MockGovderState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    assert!(
        headers.get("X-Govder-Tenant-Assertion").is_some(),
        "mock govder expects tenant assertion on evaluate-decision"
    );
    *st.evaluate_hits.lock().unwrap() += 1;
    let grant_id = body["grant_id"].as_str().unwrap_or("");
    let grant = st
        .grants
        .values()
        .flatten()
        .find(|g| g.grant_id == grant_id)
        .expect("grant must exist in mock govder");
    let eval = evaluate_delegate_decision(DelegateEvalInput {
        grant_scope: &grant.scope,
        delegate_agent_id: body["delegate_agent_id"].as_str().unwrap_or(""),
        action_class: body["action_class"].as_str().unwrap_or(""),
        risk_tier: body["risk_tier"].as_str().unwrap_or(""),
        irreversible: body["irreversible"].as_bool().unwrap_or(false),
        approve: body["approve"].as_bool().unwrap_or(false),
    });
    axum::Json(serde_json::json!({
        "permitted": eval.permitted,
        "gate_verdict": if eval.permitted { "ALLOW" } else { "DENY" },
        "reason": eval.reason,
    }))
}

fn default_mock_grants() -> Vec<MockGrant> {
    let scope = DelegationGrantScope {
        max_risk_tier: "Low".to_string(),
        action_classes: vec!["http.request".to_string()],
    };
    [
        "grant_test_001",
        "grant_webhook_001",
        "grant_high_floor",
        "grant_irr_floor",
    ]
    .into_iter()
    .map(|id| MockGrant {
        grant_id: id.to_string(),
        tenant_id: "acme".to_string(),
        delegate_agent_id: "delegate-bot".to_string(),
        delegate_agent_ep: Some("ep_delegate_bot_acme".to_string()),
        scope: scope.clone(),
        revoked: false,
        expiry: None,
    })
    .chain(std::iter::once(MockGrant {
        grant_id: "grant_cross".to_string(),
        tenant_id: "tenant-a".to_string(),
        delegate_agent_id: "delegate-bot".to_string(),
        delegate_agent_ep: std::env::var("DELEGATION_DELEGATE_EP").ok(),
        scope: scope.clone(),
        revoked: false,
        expiry: None,
    }))
    .collect()
}

async fn build_admin_router() -> (axum::Router, Arc<dyn StorageBackend>, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager
        .create_api_key("admin-key", "admin", None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let mut config = Config::default();
    config.approval.enabled = true;
    config.govder =
        Some(GovderConfig::from_env().unwrap_or(start_mock_govder(default_mock_grants()).await));

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
    let mint_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
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
        agent_label: Some("ep_requester_acme".to_string()),
        tenant: Some("acme".to_string()),
        trusted_irreversible: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
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
    assert_eq!(
        approval.status,
        vultrino::approval::ApprovalStatus::Approved
    );
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
    assert_eq!(approved.payload["risk_tier"], "Low");
    assert_eq!(approved.payload["irreversible"], false);
}

/// One captured delivery: the `X-Vultrino-Signature` header value and the raw body bytes
/// (raw, not parsed — the signature is over the exact bytes).
type CapturedDelivery = (String, Vec<u8>);

/// Mock govder webhook consumer: records every signed delivery vultrino's outbox pushes.
#[derive(Clone, Default)]
struct WebhookCapture(Arc<Mutex<Vec<CapturedDelivery>>>);

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
    let mock = Router::new().route(
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
    let mint_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
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
        agent_label: Some("ep_requester_acme".to_string()),
        tenant: Some("acme".to_string()),
        trusted_irreversible: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
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
    let metrics = vultrino::server::OutboxMetrics::default();
    for _ in 0..8 {
        vultrino::server::deliver_outbox_once(&storage, &config.outbox, &client, &metrics)
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
                .and_then(|v| {
                    v.get("event")
                        .and_then(|e| e.as_str().map(|s| s.to_string()))
                })
                == Some("approval.approved".to_string())
        })
        .expect("approval.approved delivery must reach govder consumer");
    let (sig, body) = approved;
    let expected_sig = vultrino::outbox::sign_body(WEBHOOK_SECRET, body);
    assert_eq!(
        *sig, expected_sig,
        "Govder-Signature must match vultrino sign_body"
    );

    let delivered: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(delivered["event"], "approval.approved");
    assert_eq!(delivered["payload"]["approver_kind"], "delegate-agent");
    assert_eq!(
        delivered["payload"]["delegation_grant_ref"],
        "grant_webhook_001"
    );
    assert_eq!(delivered["payload"]["tenant"], "acme");
}

/// Cross-plane harness entry: invoked by govder
/// `TestDelegateDecision_VultrinoOutboxToGovderReceiver` with GOVDER_WEBHOOK_URL set
/// to a live govder runtime receiver (not a mock). Emits `CROSS_PLANE_APPROVAL_ID=`
/// on stdout for the govder test to assert the sealed record.
#[tokio::test]
async fn delegate_decision_cross_plane_to_govder() {
    let webhook_url = match std::env::var("GOVDER_WEBHOOK_URL") {
        Ok(u) if !u.trim().is_empty() => u,
        _ => {
            eprintln!("GOVDER_WEBHOOK_URL unset — skip (run from govder cross-plane harness)");
            return;
        }
    };
    let secret = std::env::var("GOVDER_SIGNATURE_SECRET")
        .expect("GOVDER_SIGNATURE_SECRET required for cross-plane harness");
    let grant_ref = std::env::var("DELEGATION_GRANT_REF")
        .expect("DELEGATION_GRANT_REF required for cross-plane harness");
    let tenant = std::env::var("DELEGATION_TENANT").unwrap_or_else(|_| "tenant-a".to_string());

    let (router, storage, admin_key) = build_admin_router().await;

    let mint_resp = router
        .clone()
        .oneshot(bearer_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": grant_ref,

                "agent_label": "delegate-bot",
                "delegator_identity": "alice@corp",
                "tenant": tenant
            }),
        ))
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::CREATED);
    let mint_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let vap_secret = mint_body["token"].as_str().unwrap().to_string();

    let requester_ep = std::env::var("DELEGATION_REQUESTER_EP")
        .expect("DELEGATION_REQUESTER_EP required for cross-plane harness");
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
        agent_label: Some(requester_ep),
        tenant: Some(tenant.clone()),
        trusted_irreversible: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    storage.store_approval(&approval).await.unwrap();
    println!("CROSS_PLANE_APPROVAL_ID={}", approval.id);

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

    let outbox_cfg = vultrino::outbox::OutboxConfig {
        enabled: true,
        url: Some(webhook_url),
        hmac_secret: Some(secret),
        max_attempts: 3,
        retention_secs: 3600,
    };
    let client = reqwest::Client::new();
    let metrics = vultrino::server::OutboxMetrics::default();
    for _ in 0..8 {
        vultrino::server::deliver_outbox_once(&storage, &outbox_cfg, &client, &metrics)
            .await
            .unwrap();
    }
}

/// D3 human floor at the PEP: High-risk delegate approve is rejected before
/// status transitions to Approved (no execution, no approval.approved outbox).
#[tokio::test]
async fn delegate_decide_high_risk_blocked_at_pep() {
    let (router, storage, admin_key) = build_admin_router().await;

    let mint_resp = router
        .clone()
        .oneshot(bearer_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": "grant_high_floor",

                "agent_label": "delegate-bot",
                "delegator_identity": "alice@corp",
                "tenant": "acme"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::CREATED);
    let mint_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
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
        agent_label: Some("ep_requester_acme".to_string()),
        tenant: Some("acme".to_string()),
        trusted_irreversible: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::High,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
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
    assert_eq!(decide_resp.status(), StatusCode::FORBIDDEN);

    let stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert!(!stored.executed);
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        !events
            .iter()
            .any(|e| e.event_type == EVENT_APPROVAL_APPROVED),
        "High-risk delegate approve must not emit approval.approved"
    );
}

/// F11: a buggy/malicious govder returning a cross-tenant grant must be rejected
/// at mint time. The mock returns all grants (incl. tenant-a's `grant_cross`);
/// minting a vap_ for `grant_cross` under tenant `acme` must fail with 400
/// invalid_grant_ref rather than bind a cross-tenant grant to a token.
#[tokio::test]
async fn delegate_mint_rejects_cross_tenant_grant() {
    let (router, _storage, admin_key) = build_admin_router().await;

    let mint_resp = router
        .oneshot(bearer_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": "grant_cross",
                "agent_label": "delegate-bot",
                "delegator_identity": "alice@corp",
                "tenant": "acme"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["code"], "invalid_grant_ref");
    let msg = body["error"].as_str().unwrap();
    assert!(
        msg.contains("does not match requested tenant"),
        "expected cross-tenant rejection message, got {msg:?}"
    );
}

/// Irreversible actions require human approval — blocked at delegate decide PEP.
#[tokio::test]
async fn delegate_decide_irreversible_blocked_at_pep() {
    let (router, storage, admin_key) = build_admin_router().await;

    let mint_resp = router
        .clone()
        .oneshot(bearer_req(
            "POST",
            "/api/v1/approval-tokens",
            &admin_key,
            serde_json::json!({
                "delegation_grant_ref": "grant_irr_floor",

                "agent_label": "delegate-bot",
                "delegator_identity": "alice@corp",
                "tenant": "acme"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::CREATED);
    let mint_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(mint_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
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
        agent_label: Some("ep_requester_acme".to_string()),
        tenant: Some("acme".to_string()),
        trusted_irreversible: Some(true),
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
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
    assert_eq!(decide_resp.status(), StatusCode::FORBIDDEN);

    let stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(stored.status, vultrino::approval::ApprovalStatus::Pending);
    assert!(!stored.executed);
}
