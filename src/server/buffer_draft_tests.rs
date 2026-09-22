use super::{ApprovalCaller, ExecAuth, VultrinoServer};
use crate::approval::ApprovalStatus;
use crate::auth::{AuthResult, NewUseToken, UseToken};
use crate::averin::AverinConfig;
use crate::config::{BufferPin, Config};
use crate::govder::GovderConfig;
use crate::plugins::BufferPlugin;
use crate::router::CredentialResolver;
use crate::storage::{FileStorage, NativeDraftKey, StorageBackend};
use crate::{Credential, CredentialData, ExecuteRequest, ExecutionOutcome, Secret};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{routing::any, Router};
use reqwest::Url;
use secrecy::SecretString;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};

#[derive(Clone)]
struct BufferState {
    requests: Arc<Mutex<Vec<Value>>>,
    draft_copy: String,
}

#[derive(Clone)]
struct AverinState {
    requests: Arc<Mutex<Vec<Value>>>,
}

async fn averin_grant(State(state): State<AverinState>, body: axum::Json<Value>) -> Response {
    state.requests.lock().unwrap().push(body.0);
    (
        StatusCode::OK,
        axum::Json(json!({"grant_id": "d8-grant-1", "capability": "Y2Fw.sig"})),
    )
        .into_response()
}

async fn averin_intent(State(state): State<AverinState>, body: axum::Json<Value>) -> Response {
    state.requests.lock().unwrap().push(body.0);
    (
        StatusCode::OK,
        axum::Json(json!({"record": {"record_id": "d8-intent-1"}})),
    )
        .into_response()
}

async fn averin_outcome(State(state): State<AverinState>, body: axum::Json<Value>) -> Response {
    state.requests.lock().unwrap().push(body.0);
    (
        StatusCode::OK,
        axum::Json(json!({"outcome_id": "d8-outcome-1"})),
    )
        .into_response()
}

async fn buffer_fixture_handler(State(state): State<BufferState>, body: Bytes) -> Response {
    let request: Value = serde_json::from_slice(&body).expect("Buffer request is JSON");
    state.requests.lock().unwrap().push(request.clone());
    let query = request["query"].as_str().unwrap_or_default();
    if query.contains("BufferChannel") {
        return (
            StatusCode::OK,
            axum::Json(json!({
                "data": {"channel": {
                    "id": "channel-x",
                    "organizationId": "org-1",
                    "service": "twitter",
                    "serviceId": "service-1",
                    "isDisconnected": false,
                    "isLocked": false
                }}
            })),
        )
            .into_response();
    }
    if query.contains("BufferCreateDraft") {
        let input = &request["variables"]["input"];
        assert_eq!(input["channelId"], "channel-x");
        assert_eq!(input["schedulingType"], "automatic");
        assert_eq!(input["mode"], "addToQueue");
        assert_eq!(input["saveToDraft"], true);
        assert_eq!(input["needsApproval"], false);
        assert_eq!(input["aiAssisted"], true);
        assert_eq!(input["assets"], json!([]));
        assert_eq!(input["text"], state.draft_copy);
        return (
            StatusCode::OK,
            axum::Json(json!({
                "data": {"createPost": {
                    "__typename": "PostActionSuccess",
                    "post": {
                        "id": "post-1",
                        "text": state.draft_copy,
                        "status": "draft",
                        "channelId": "channel-x",
                        "channelService": "twitter",
                        "dueAt": null,
                        "assets": []
                    }
                }}
            })),
        )
            .into_response();
    }
    (StatusCode::BAD_REQUEST, "unexpected Buffer operation").into_response()
}

async fn start_buffer_fixture(draft_copy: &str) -> (Url, Arc<Mutex<Vec<Value>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = BufferState {
        requests: requests.clone(),
        draft_copy: draft_copy.to_string(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .fallback(any(buffer_fixture_handler))
                .with_state(state),
        )
        .await
        .unwrap();
    });
    (Url::parse(&format!("http://{address}")).unwrap(), requests)
}

async fn start_no_rule_govder() -> Url {
    async fn handler() -> Response {
        (StatusCode::OK, axum::Json(json!({"has_rule": false}))).into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/v1/oversight/gates/rule", axum::routing::get(handler)),
        )
        .await
        .unwrap();
    });
    Url::parse(&format!("http://{address}")).unwrap()
}

async fn start_averin_fixture() -> (Url, Arc<Mutex<Vec<Value>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = AverinState {
        requests: requests.clone(),
    };
    let app = Router::new()
        .route("/v2/grants", axum::routing::post(averin_grant))
        .route("/v2/use-intent", axum::routing::post(averin_intent))
        .route("/v2/use-outcome", axum::routing::post(averin_outcome))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (Url::parse(&format!("http://{address}")).unwrap(), requests)
}

fn content_hash(params: &Value) -> String {
    let mut canonical = BTreeMap::new();
    for key in [
        "account_id",
        "asset_hash",
        "asset_url",
        "audience",
        "campaign_id",
        "channel",
        "content_type",
        "draft_copy",
        "media_brief",
        "publish_at",
        "source_ids",
        "variant_id",
    ] {
        canonical.insert(key, params[key].clone());
    }
    hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).expect("draft hash JSON"),
    ))
}

fn draft_params(draft_copy: &str) -> Value {
    let mut params = json!({
        "target_alias": "x",
        "campaign_id": "campaign-1",
        "variant_id": "variant-1",
        "channel": "x",
        "account_id": "account-1",
        "audience": "audience-1",
        "content_type": "text",
        "draft_copy": draft_copy,
        "media_brief": "",
        "asset_url": "",
        "asset_hash": "",
        "publish_at": "",
        "source_ids": ["source-1"],
        "row_version": 1,
    });
    let hash = content_hash(&params);
    params["content_hash"] = Value::String(hash);
    params
}

fn pin() -> BufferPin {
    BufferPin::parse(
        "tenant-a",
        "project-1",
        "buffer-cred",
        "org-1",
        "x",
        "channel-x",
        "service-1",
        "account-1",
    )
    .unwrap()
}

fn token(agent: &str, tenant: &str) -> UseToken {
    let (_, mut token) = UseToken::create(NewUseToken {
        name: format!("{agent}-draft"),
        credential_scope: "buffer-cred".to_string(),
        action_scope: Some("solo.social_draft_create".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some(agent.to_string());
    token.tenant = Some(tenant.to_string());
    token
}

async fn fixture() -> (
    VultrinoServer,
    Arc<dyn StorageBackend>,
    Arc<Mutex<Vec<Value>>>,
    Credential,
    BufferPin,
    TempDir,
) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("buffer-fixture-password"))
            .await
            .unwrap(),
    );
    let draft_copy = "Approved draft";
    let (endpoint, requests) = start_buffer_fixture(draft_copy).await;
    let govder_endpoint = start_no_rule_govder().await;
    let (averin_endpoint, _averin_requests) = start_averin_fixture().await;
    let buffer_pin = pin();
    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = crate::config::EnforcementDefault::Allow;
    config.action_labels.insert(
        "solo.social_draft_create".to_string(),
        "buffer.draft_create".to_string(),
    );
    config.buffer_pins = vec![buffer_pin.clone()];
    config.govder = Some(GovderConfig {
        base_url: govder_endpoint.to_string(),
        assertion_secret: "fixture-govder-secret".to_string(),
        approval_assertion_secret: None,
        assertion_ttl: std::time::Duration::from_secs(90),
        http_timeout: std::time::Duration::from_secs(5),
    });
    config.averin = AverinConfig {
        enabled: true,
        base_url: averin_endpoint.to_string(),
        resource_id: "buffer-resource".to_string(),
        d8_complete_evidence: true,
        ..AverinConfig::default()
    };
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    let client = reqwest::Client::builder().build().unwrap();
    server
        .plugins()
        .register(Arc::new(BufferPlugin::with_client_endpoint(
            client,
            endpoint,
            vec![buffer_pin.clone()],
            storage.clone(),
        )));

    let credential = Credential::new(
        "buffer-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("buffer-secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("tenant", "tenant-a");
    storage.store(&credential).await.unwrap();
    storage
        .store_capability(&crate::capability::Capability {
            id: "cap-solo-social-draft-create".to_string(),
            tool_name: "solo_social_draft_create".to_string(),
            description: "operator-reviewed Buffer draft handoff".to_string(),
            action: "solo.social_draft_create".to_string(),
            plugin: Some("buffer".to_string()),
            target: crate::capability::CapabilityTarget::default(),
            credential_ref: "buffer-cred".to_string(),
            input_schema: json!({"type": "object"}),
            reversibility: "partially-reversible".to_string(),
            llm: None,
            approval_preview: None,
        })
        .await
        .unwrap();
    (server, storage, requests, credential, buffer_pin, dir)
}

async fn open(
    server: &VultrinoServer,
    storage: &Arc<dyn StorageBackend>,
    token: &UseToken,
    params: Value,
) -> crate::approval::ApprovalRequest {
    storage.store_use_token(token).await.unwrap();
    match server
        .execute_gated(
            ExecuteRequest {
                credential: "buffer-cred".to_string(),
                action: "solo.social_draft_create".to_string(),
                params,
            },
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(approval) => *approval,
        ExecutionOutcome::Completed(_) => panic!("human-floor Buffer create executed directly"),
    }
}

async fn approve(storage: &Arc<dyn StorageBackend>, id: &str) {
    storage
        .decide_approval(
            id,
            true,
            "admin panel",
            "reviewer@corp",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn approved_solo_draft_reaches_real_buffer_adapter_once() {
    let (server, storage, requests, credential, buffer_pin, _vault_dir) = fixture().await;
    let params = draft_params("Approved draft");
    let opener = token("solo-agent", "tenant-a");
    let approval = open(&server, &storage, &opener, params.clone()).await;
    assert_eq!(approval.action, "buffer.draft_create");
    assert!(
        requests.lock().unwrap().is_empty(),
        "approval open must not call Buffer"
    );

    approve(&storage, &approval.id).await;
    let foreign = token("other-agent", "tenant-a");
    let foreign_auth = AuthResult::for_use_token(&foreign);
    let foreign_caller = ApprovalCaller::from_auth(&foreign_auth);
    let denied = server
        .check_and_resume_approval(&approval.id, Some(&foreign_caller))
        .await
        .unwrap_err();
    assert!(matches!(denied, crate::VultrinoError::PolicyDenied(_)));
    assert!(
        requests.lock().unwrap().is_empty(),
        "foreign owner must not dispatch"
    );

    let rotated = token("solo-agent", "tenant-a");
    let rotated_auth = AuthResult::for_use_token(&rotated);
    let owner_caller = ApprovalCaller::from_auth(&rotated_auth);
    let executed = server
        .check_and_resume_approval(&approval.id, Some(&owner_caller))
        .await
        .unwrap();
    assert!(executed.executed);
    assert_eq!(executed.status(), ApprovalStatus::Approved);
    assert_eq!(executed.result_status, Some(200));
    assert_eq!(
        requests.lock().unwrap().len(),
        2,
        "one preflight plus one create"
    );

    let receipt: Value = serde_json::from_str(executed.result_body.as_deref().unwrap()).unwrap();
    assert_eq!(receipt["provider"], "buffer");
    assert_eq!(receipt["campaign_id"], "campaign-1");
    assert_eq!(receipt["variant_id"], "variant-1");
    assert_eq!(receipt["row_version"], 1);
    assert_eq!(receipt["content_hash"], params["content_hash"]);
    assert_eq!(receipt["external_id"], "post-1");
    assert_eq!(receipt["external_status"], "draft");
    assert_eq!(receipt["channel_ref"], "x");
    assert_eq!(receipt["approval_id"], approval.id);

    let key = NativeDraftKey {
        tenant: "tenant-a".to_string(),
        project_ref: buffer_pin.project_id.clone(),
        provider: "buffer".to_string(),
        target_alias: "x".to_string(),
        credential_alias: "buffer-cred".to_string(),
        campaign_id: "campaign-1".to_string(),
        variant_id: "variant-1".to_string(),
        row_version: 1,
    };
    let record = storage.get_native_draft(&key).await.unwrap().unwrap();
    assert_eq!(record.metadata.approval_id, approval.id);
    assert!(record.metadata.execution_epoch > 0);
    assert_eq!(record.metadata.principal_id, Some(opener.id.clone()));
    assert_eq!(record.metadata.credential_id, credential.id);
    assert_eq!(
        record.receipt.as_ref().unwrap().external_id.as_deref(),
        Some("post-1")
    );

    // Polling the same approved grant is terminal and cannot call Buffer again.
    let replay = server
        .check_and_resume_approval(&approval.id, Some(&owner_caller))
        .await
        .unwrap();
    assert!(replay.executed);
    assert_eq!(requests.lock().unwrap().len(), 2);

    // A new approved request for the same canonical row gets the durable receipt,
    // but the adapter must not create a second provider draft.
    let second = token("solo-agent", "tenant-a");
    let second_approval = open(&server, &storage, &second, params.clone()).await;
    approve(&storage, &second_approval.id).await;
    let second_run = server
        .check_and_resume_approval(
            &second_approval.id,
            Some(&ApprovalCaller::from_auth(&AuthResult::for_use_token(
                &second,
            ))),
        )
        .await
        .unwrap();
    assert!(second_run.executed);
    assert_eq!(second_run.result_status, Some(200));
    assert_eq!(requests.lock().unwrap().len(), 2);
    let second_receipt: Value =
        serde_json::from_str(second_run.result_body.as_deref().unwrap()).unwrap();
    assert_eq!(
        second_receipt["approval_id"], approval.id,
        "durable receipt stays bound to its first execution"
    );

    // A changed frozen payload collides with the same native row and is terminal,
    // rather than becoming a second provider create.
    let changed = token("solo-agent", "tenant-a");
    let changed_approval = open(
        &server,
        &storage,
        &changed,
        draft_params("Substituted draft"),
    )
    .await;
    approve(&storage, &changed_approval.id).await;
    let changed_run = server
        .check_and_resume_approval(
            &changed_approval.id,
            Some(&ApprovalCaller::from_auth(&AuthResult::for_use_token(
                &changed,
            ))),
        )
        .await
        .unwrap();
    assert!(changed_run.executed);
    assert!(changed_run
        .result_error
        .as_deref()
        .unwrap_or_default()
        .contains("conflict"));
    assert_eq!(requests.lock().unwrap().len(), 2);

    // Credential and action substitution are rejected at the authenticated scope
    // seam, before either can reach the real adapter.
    let substitution = token("solo-agent", "tenant-a");
    storage.store_use_token(&substitution).await.unwrap();
    let credential_error = server
        .execute_gated(
            ExecuteRequest {
                credential: "other-credential".to_string(),
                action: "solo.social_draft_create".to_string(),
                params: params.clone(),
            },
            ExecAuth::from_use_token(substitution.clone()),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        credential_error,
        crate::VultrinoError::PolicyDenied(_)
    ));

    let action_token = token("solo-agent", "tenant-a");
    storage.store_use_token(&action_token).await.unwrap();
    let action_error = server
        .execute_gated(
            ExecuteRequest {
                credential: "buffer-cred".to_string(),
                action: "buffer.draft_read".to_string(),
                params: json!({
                    "target_alias": "x",
                    "campaign_id": "campaign-1",
                    "variant_id": "variant-1",
                    "row_version": 1,
                }),
            },
            ExecAuth::from_use_token(action_token),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        action_error,
        crate::VultrinoError::PolicyDenied(_)
    ));
}
