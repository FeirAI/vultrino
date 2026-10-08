//! Contract fixtures for the typed Buffer connector.
//!
//! These tests deliberately use a real encrypted [`FileStorage`] and a tiny
//! loopback GraphQL server.  No provider credentials or internet access are
//! involved: the server is bound to `127.0.0.1:0`, and every response is
//! controlled by the test.

use super::*;
use crate::config::BufferPin;
use crate::plugins::marketing::{draft_content_hash, DraftHashPayload};
use crate::storage::{DraftSyncStatus, FileStorage, NativeDraftKey, StorageBackend};
use crate::{Credential, CredentialData, RequestContext, Secret};
use axum::body::Body;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use reqwest::{Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;

const CHANNEL_QUERY: &str = "query BufferChannel($input: ChannelInput!) { channel(input: $input) { id organizationId service serviceId isDisconnected isLocked } }";
const CREATE_QUERY: &str = "mutation BufferCreateDraft($input: CreatePostInput!) { createPost(input: $input) { __typename ... on PostActionSuccess { post { id text status channelId channelService dueAt assets { __typename } } } ... on MutationError { message } } }";
/// Buffer reports a LinkedIn channel's serviceId as a LinkedIn URN.
const LINKEDIN_SERVICE_ID: &str = "urn:li:organization:135696968";
const POST_QUERY: &str = "query BufferPost($input: PostInput!) { post(input: $input) { id text status channelId channelService dueAt assets { __typename } } }";

#[derive(Clone)]
enum Reply {
    Json(Value),
    Status(u16, String),
    Raw(u16, String),
    Delay(u64, Box<Reply>),
}

type InvalidCase = (&'static str, Box<dyn Fn(&mut Value)>);

#[derive(Default)]
struct MockState {
    replies: VecDeque<Reply>,
    requests: Vec<Value>,
}

async fn graphql_stub(
    State(state): State<Arc<Mutex<MockState>>>,
    Json(request): Json<Value>,
) -> Response {
    let query = request["query"].as_str().unwrap_or_default().to_string();
    let reply = {
        let mut state = state.lock().expect("mock state lock");
        state.requests.push(request.clone());
        state.replies.pop_front()
    };
    let reply = reply.unwrap_or_else(|| default_reply(&query, &request));
    let reply = match reply {
        Reply::Delay(milliseconds, reply) => {
            tokio::time::sleep(Duration::from_millis(milliseconds)).await;
            *reply
        }
        reply => reply,
    };
    match reply {
        Reply::Json(value) => Json(value).into_response(),
        Reply::Status(status, body) | Reply::Raw(status, body) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() =
                axum::http::StatusCode::from_u16(status).expect("valid mock status");
            response
        }
        Reply::Delay(..) => unreachable!("delayed replies are unwrapped above"),
    }
}

fn default_reply(query: &str, request: &Value) -> Reply {
    if query == CHANNEL_QUERY {
        let id = request["variables"]["input"]["id"]
            .as_str()
            .unwrap_or("channel-x");
        let linkedin = id.contains("linkedin");
        return Reply::Json(json!({
            "data": {"channel": {
                "id": id,
                "organizationId": "org-a",
                "service": if linkedin { "linkedin" } else { "twitter" },
                "serviceId": if linkedin { LINKEDIN_SERVICE_ID } else { "remote-x" },
                "isDisconnected": false,
                "isLocked": false
            }}
        }));
    }
    if query == CREATE_QUERY {
        let input = &request["variables"]["input"];
        let channel = input["channelId"].as_str().unwrap_or("channel-x");
        let linkedin = channel.contains("linkedin");
        return Reply::Json(json!({
            "data": {"createPost": {"__typename": "PostActionSuccess", "post": {
                "id": "post-1",
                "text": input["text"],
                "status": "draft",
                "channelId": channel,
                "channelService": if linkedin { "linkedin" } else { "twitter" },
                "dueAt": null,
                "assets": []
            }}}
        }));
    }
    if query == POST_QUERY {
        return Reply::Json(json!({
            "data": {"post": {
                "id": request["variables"]["input"]["id"],
                "text": "hello from Buffer",
                "status": "draft",
                "channelId": "channel-x",
                "channelService": "twitter",
                "dueAt": null,
                "assets": []
            }}
        }));
    }
    Reply::Raw(500, "unexpected query".into())
}

struct Fixture {
    plugin: Arc<BufferPlugin>,
    state: Arc<Mutex<MockState>>,
    storage: Arc<FileStorage>,
    directory: TempDir,
    password: secrecy::SecretString,
    endpoint: Url,
    pins: Vec<BufferPin>,
    _server: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self._server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let state = Arc::new(Mutex::new(MockState::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback fixture");
        let endpoint =
            Url::parse(&format!("http://{}", listener.local_addr().unwrap())).expect("fixture URL");
        let app = Router::new()
            .route("/", post(graphql_stub))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let directory = tempfile::tempdir().expect("fixture tempdir");
        let password = secrecy::SecretString::from("buffer-fixture-password");
        let storage = Arc::new(
            FileStorage::new(directory.path().join("vault.enc"), &password)
                .await
                .expect("encrypted fixture storage"),
        );
        let pins = vec![
            BufferPin::parse(
                "tenant-a",
                "project-a",
                "buffer-main",
                "org-a",
                "x",
                "channel-x",
                "remote-x",
                "owner-x",
            )
            .unwrap(),
            BufferPin::parse(
                "tenant-a",
                "project-a",
                "buffer-main",
                "org-a",
                "linkedin",
                "channel-linkedin",
                LINKEDIN_SERVICE_ID,
                "owner-linkedin",
            )
            .unwrap(),
        ];
        let plugin = Arc::new(Self::plugin(
            endpoint.clone(),
            pins.clone(),
            storage.clone(),
        ));
        Self {
            plugin,
            state,
            storage,
            directory,
            password,
            endpoint,
            pins,
            _server: server,
        }
    }

    fn plugin(endpoint: Url, pins: Vec<BufferPin>, storage: Arc<FileStorage>) -> BufferPlugin {
        BufferPlugin::with_client_endpoint(
            Client::builder().build().expect("fixture HTTP client"),
            endpoint,
            pins,
            storage,
        )
    }

    fn credential(&self, id: &str) -> Credential {
        let mut credential = Credential::new(
            "buffer-main".into(),
            CredentialData::ApiKey {
                key: Secret::new("fixture-token"),
                header_name: "Authorization".into(),
                header_prefix: "Bearer ".into(),
            },
        );
        credential.id = id.into();
        credential
    }

    fn request(
        &self,
        action: &str,
        params: Value,
        credential_id: &str,
        approved: bool,
    ) -> PluginRequest {
        let mut context = RequestContext::new();
        context.api_key_id = Some("principal-fixture".into());
        context.agent_label = Some("fixture-agent".into());
        context.tenant = Some("tenant-a".into());
        if approved {
            context.approval_id = Some("approval-fixture".into());
            context.approval_execution_epoch = Some(7);
        }
        PluginRequest {
            credential: self.credential(credential_id),
            action: action.into(),
            params,
            context,
        }
    }

    fn queue(&self, replies: impl IntoIterator<Item = Reply>) {
        let mut state = self.state.lock().unwrap();
        state.replies = replies.into_iter().collect();
    }

    fn requests(&self) -> Vec<Value> {
        self.state.lock().unwrap().requests.clone()
    }

    fn clear_requests(&self) {
        self.state.lock().unwrap().requests.clear();
    }

    fn count_query(&self, query: &str) -> usize {
        self.requests()
            .iter()
            .filter(|request| request["query"] == query)
            .count()
    }

    fn params(&self, target: &str, text: &str) -> Value {
        let account = if target == "x" {
            "owner-x"
        } else {
            "owner-linkedin"
        };
        let source_ids = vec!["source-a".to_string(), "source-b".to_string()];
        let mut params = json!({
            "target_alias": target,
            "campaign_id": "campaign-1",
            "variant_id": "variant-1",
            "channel": target,
            "account_id": account,
            "audience": "public",
            "content_type": "text",
            "draft_copy": text,
            "media_brief": "",
            "asset_url": "",
            "asset_hash": "",
            "publish_at": "",
            "source_ids": source_ids,
            "row_version": 1,
            "content_hash": ""
        });
        let content_hash = draft_content_hash(DraftHashPayload {
            campaign_id: "campaign-1",
            variant_id: "variant-1",
            channel: target,
            account_id: account,
            audience: "public",
            content_type: "text",
            draft_copy: text,
            media_brief: "",
            asset_url: "",
            asset_hash: "",
            publish_at: "",
            source_ids: vec!["source-a".into(), "source-b".into()],
        })
        .unwrap();
        params["content_hash"] = Value::String(content_hash);
        params
    }

    fn read_params(&self, target: &str) -> Value {
        json!({
            "target_alias": target,
            "campaign_id": "campaign-1",
            "variant_id": "variant-1",
            "row_version": 1
        })
    }

    fn pin(&self, target: &str) -> BufferPin {
        self.pins
            .iter()
            .find(|pin| pin.target_alias == target)
            .unwrap()
            .clone()
    }
}

fn channel_success(pin: &BufferPin) -> Value {
    json!({
        "data": {"channel": {"id": pin.channel_id, "organizationId": pin.organization_id,
        "service": pin.service(), "serviceId": pin.service_id, "isDisconnected": false,
        "isLocked": false}}
    })
}

/// The URN serviceId is compared byte-exactly: a channel reporting any other
/// LinkedIn URN (another organization, or the same id under another entity
/// kind) is refused before the create is sent.
#[tokio::test]
async fn linkedin_create_refuses_a_channel_with_a_different_urn_service_id() {
    for other in [
        "urn:li:organization:135696969",
        "urn:li:person:135696968",
        "URN:li:organization:135696968",
    ] {
        let fixture = Fixture::new().await;
        let mut channel = channel_success(&fixture.pin("linkedin"));
        channel["data"]["channel"]["serviceId"] = json!(other);
        fixture.queue([Reply::Json(channel)]);
        let (_, response) = create(&fixture, "linkedin").await;
        let error = response.expect_err(other).to_string();
        assert!(
            error.contains("does not match the operator pin"),
            "{other}: {error}"
        );
        assert_eq!(fixture.count_query(CREATE_QUERY), 0, "{other}");
    }
}

async fn create(fixture: &Fixture, target: &str) -> (Value, Result<ExecuteResponse, PluginError>) {
    let params = fixture.params(target, "hello from Buffer");
    let response = fixture
        .plugin
        .execute(fixture.request("draft_create", params.clone(), "credential-1", true))
        .await;
    (params, response)
}

#[tokio::test]
async fn successful_x_create_uses_exact_queries_and_frozen_draft_input() {
    let fixture = Fixture::new().await;
    let (params, response) = create(&fixture, "x").await;
    let response = response.expect("draft create succeeds");
    assert_eq!(response.status, 200);

    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["query"], CHANNEL_QUERY);
    assert_eq!(
        requests[0]["variables"],
        json!({"input": {"id": "channel-x"}})
    );
    assert_eq!(requests[1]["query"], CREATE_QUERY);
    let input = &requests[1]["variables"]["input"];
    assert_eq!(input["text"], params["draft_copy"]);
    assert_eq!(input["channelId"], "channel-x");
    assert_eq!(input["saveToDraft"], true);
    assert_eq!(input["mode"], "addToQueue");
    assert_eq!(input["schedulingType"], "automatic");
    assert_eq!(input["assets"], json!([]));
    assert_eq!(input["needsApproval"], false);
    assert!(input.get("dueAt").is_none());
    for unsafe_field in ["publishAt", "published", "delete", "update", "status"] {
        assert!(
            input.get(unsafe_field).is_none(),
            "unsafe field {unsafe_field}"
        );
    }

    let receipt: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(receipt["external_id"], "post-1");
    assert_eq!(receipt["content_hash"], params["content_hash"]);
    let key = BufferPlugin::native_key(
        "tenant-a",
        &fixture.pin("x"),
        &fixture.credential("credential-1"),
        "campaign-1",
        "variant-1",
        1,
    );
    let expected_operation_key = hex::encode(Sha256::digest(key.storage_key().as_bytes()));
    assert_eq!(receipt["operation_key"], expected_operation_key);
    let record = fixture
        .storage
        .get_native_draft(&key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.metadata.credential_id, "credential-1");
    assert_eq!(record.metadata.content_hash, params["content_hash"]);
    assert_ne!(record.payload_hash, params["content_hash"]);
    assert_eq!(record.status, DraftSyncStatus::Succeeded);
}

#[tokio::test]
async fn successful_linkedin_create_uses_linkedin_channel_service() {
    let fixture = Fixture::new().await;
    let (_, response) = create(&fixture, "linkedin").await;
    assert!(response.is_ok());
    let requests = fixture.requests();
    assert_eq!(requests[0]["query"], CHANNEL_QUERY);
    assert_eq!(requests[1]["query"], CREATE_QUERY);
    let input = &requests[1]["variables"]["input"];
    assert_eq!(input["channelId"], "channel-linkedin");
    assert_eq!(
        serde_json::from_slice::<Value>(&response.unwrap().body).unwrap()["external_id"],
        "post-1"
    );
}

#[tokio::test]
async fn durable_replay_survives_approval_change_restart_and_credential_rotation() {
    let fixture = Fixture::new().await;
    let (params, first) = create(&fixture, "x").await;
    let first = first.unwrap();
    let first_receipt: Value = serde_json::from_slice(&first.body).unwrap();
    fixture.clear_requests();
    fixture.queue([Reply::Status(500, "replay must not call upstream".into())]);

    let storage2 = Arc::new(
        FileStorage::new(
            fixture.directory.path().join("vault.enc"),
            &fixture.password,
        )
        .await
        .unwrap(),
    );
    // A rotated credential UUID with the same operator alias is the same
    // pinned remote authority and must replay without touching Buffer.
    let replay_plugin = BufferPlugin::with_client_endpoint(
        Client::builder().build().unwrap(),
        fixture.endpoint.clone(),
        fixture.pins.clone(),
        storage2,
    );
    let mut request = fixture.request("draft_create", params, "credential-rotated", true);
    request.context.approval_id = Some("approval-new-epoch".into());
    request.context.approval_execution_epoch = Some(8);
    let replay = replay_plugin.execute(request).await.unwrap();
    let replay_receipt: Value = serde_json::from_slice(&replay.body).unwrap();
    assert_eq!(replay_receipt["external_id"], first_receipt["external_id"]);
    assert_eq!(replay_receipt["approval_id"], "approval-fixture");
    assert_eq!(
        fixture.requests().len(),
        0,
        "replay must make no HTTP calls"
    );
}

#[tokio::test]
async fn replay_never_bypasses_the_approval_gate() {
    let fixture = Fixture::new().await;
    let (params, first) = create(&fixture, "x").await;
    first.unwrap();
    fixture.clear_requests();
    let denied = fixture
        .plugin
        .execute(fixture.request("draft_create", params, "credential-1", false))
        .await;
    assert!(
        denied.is_err(),
        "a replay still requires approved execution"
    );
    assert!(
        fixture.requests().is_empty(),
        "denial must happen before storage or HTTP"
    );
}

#[tokio::test]
async fn canonical_source_order_replays_the_same_operation() {
    let fixture = Fixture::new().await;
    let (params, first) = create(&fixture, "x").await;
    first.unwrap();
    let mut permuted = params;
    permuted["source_ids"] = json!(["source-b", "source-a"]);
    fixture.clear_requests();
    let replay = fixture
        .plugin
        .execute(fixture.request("draft_create", permuted, "credential-1", true))
        .await;
    assert!(replay.is_ok(), "source ordering is not operation identity");
    assert!(
        fixture.requests().is_empty(),
        "canonical replay must not call Buffer"
    );
}

#[tokio::test]
async fn concurrent_same_operation_has_one_remote_create() {
    let fixture = Fixture::new().await;
    let params = fixture.params("x", "hello from Buffer");
    let a = fixture.plugin.execute(fixture.request(
        "draft_create",
        params.clone(),
        "credential-a",
        true,
    ));
    let b = fixture
        .plugin
        .execute(fixture.request("draft_create", params, "credential-b", true));
    let (a, b) = tokio::join!(a, b);
    assert_eq!(fixture.count_query(CREATE_QUERY), 1);
    assert!(
        a.is_ok() ^ b.is_ok(),
        "one caller reserves; the other is blocked"
    );
}

#[tokio::test]
async fn invalid_params_are_rejected_before_any_upstream_request() {
    let cases: Vec<InvalidCase> = vec![
        (
            "unknown field",
            Box::new(|p: &mut Value| p["unexpected"] = json!(true)),
        ),
        (
            "url",
            Box::new(|p: &mut Value| p["asset_url"] = json!("https://x.example/a")),
        ),
        (
            "query",
            Box::new(|p: &mut Value| p["query"] = json!("mutation publish")),
        ),
        (
            "channel",
            Box::new(|p: &mut Value| p["channel"] = json!("linkedin")),
        ),
        (
            "post id",
            Box::new(|p: &mut Value| p["post_id"] = json!("post-1")),
        ),
        (
            "hash",
            Box::new(|p: &mut Value| p["content_hash"] = json!("0")),
        ),
        (
            "editing",
            Box::new(|p: &mut Value| p["draft_copy"] = json!(" edited\u{0007}")),
        ),
        (
            "account",
            Box::new(|p: &mut Value| p["account_id"] = json!("other-owner")),
        ),
        (
            "assets",
            Box::new(|p: &mut Value| p["asset_hash"] = json!("hash")),
        ),
        (
            "publish at",
            Box::new(|p: &mut Value| p["publish_at"] = json!("2026-01-01T00:00:00Z")),
        ),
        (
            "nonadjacent duplicate source",
            Box::new(|p: &mut Value| p["source_ids"] = json!(["source-b", "source-a", "source-b"])),
        ),
    ];
    for (name, mutate) in cases {
        let fixture = Fixture::new().await;
        let mut params = fixture.params("x", "hello from Buffer");
        mutate(&mut params);
        let result = fixture
            .plugin
            .execute(fixture.request("draft_create", params, "credential-1", true))
            .await;
        assert!(result.is_err(), "case {name} unexpectedly succeeded");
        assert!(
            fixture.requests().is_empty(),
            "case {name} reached upstream"
        );
    }

    let fixture = Fixture::new().await;
    let result = fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", "hello"),
            "credential-1",
            false,
        ))
        .await;
    assert!(result.is_err(), "approval absence must fail closed");
    assert!(fixture.requests().is_empty());

    let fixture = Fixture::new().await;
    let mut request = fixture.request(
        "draft_create",
        fixture.params("x", "hello"),
        "credential-1",
        true,
    );
    request.context.tenant = Some("other-tenant".into());
    let result = fixture.plugin.execute(request).await;
    assert!(result.is_err(), "tenant mismatch must fail closed");
    assert!(fixture.requests().is_empty());

    let fixture = Fixture::new().await;
    let result = fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("mastodon", "hello"),
            "credential-1",
            true,
        ))
        .await;
    assert!(result.is_err(), "missing operator pin must fail closed");
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn legacy_mutations_and_unknown_actions_are_unsupported() {
    let fixture = Fixture::new().await;
    for action in [
        "draft_create_legacy",
        "draft_read_legacy",
        "draft_edit",
        "draft_publish",
        "draft_delete",
    ] {
        let result = fixture
            .plugin
            .execute(fixture.request(action, json!({}), "credential-1", true))
            .await;
        assert!(
            matches!(result, Err(PluginError::UnsupportedAction(_))),
            "{action}"
        );
    }
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn upstream_failures_are_terminal_and_never_blindly_recreated() {
    // A top-level GraphQL error with no data at all is a refusal, not an
    // ambiguous outcome; it is covered by the release fixtures below.
    let failures = [
        Reply::Status(500, "upstream failure".into()),
        Reply::Json(json!({"data": {"createPost": {"__typename": "PostActionSuccess"}}})),
        Reply::Raw(200, "not json".into()),
        Reply::Json(
            json!({"data": {"createPost": {"__typename": "PostActionSuccess", "post": {"text": "hello", "status": "draft", "channelId": "channel-x", "channelService": "twitter", "dueAt": null, "assets": []}}}}),
        ),
        Reply::Json(
            json!({"data": {"createPost": {"__typename": "PostActionSuccess", "post": {"id": "post-1", "text": "hello", "status": "draft", "channelId": "channel-x", "channelService": "twitter", "dueAt": null}}}}),
        ),
        Reply::Json(
            json!({"data": {"createPost": {"__typename": "PostActionSuccess", "post": {"id": "post-1", "text": "hello", "status": "draft", "channelId": "channel-x", "channelService": "twitter", "dueAt": "", "assets": []}}}}),
        ),
        Reply::Json(
            json!({"data": {"createPost": {"__typename": "PostActionSuccess", "post": {"id": "post-1", "text": "hello", "status": "published", "channelId": "channel-x", "channelService": "twitter", "dueAt": null, "assets": []}}}}),
        ),
        Reply::Json(
            json!({"data": {"createPost": {"__typename": "PostActionSuccess", "post": {"id": "post-1", "text": "hello", "status": "draft", "channelId": "other-channel", "channelService": "twitter", "dueAt": null, "assets": []}}}}),
        ),
    ];
    for failure in failures {
        let fixture = Fixture::new().await;
        fixture.queue([Reply::Json(channel_success(&fixture.pin("x"))), failure]);
        let params = fixture.params("x", "hello");
        let first = fixture
            .plugin
            .execute(fixture.request("draft_create", params.clone(), "credential-1", true))
            .await;
        assert!(first.is_err());
        let creates_after_first = fixture.count_query(CREATE_QUERY);
        let second = fixture
            .plugin
            .execute(fixture.request("draft_create", params, "credential-1", true))
            .await;
        assert!(second.is_err());
        assert_eq!(
            fixture.count_query(CREATE_QUERY),
            creates_after_first,
            "terminal failure was recreated"
        );
    }
}

fn draft_key(fixture: &Fixture) -> NativeDraftKey {
    BufferPlugin::native_key(
        "tenant-a",
        &fixture.pin("x"),
        &fixture.credential("credential-1"),
        "campaign-1",
        "variant-1",
        1,
    )
}

/// Drive one create that the provider refuses before executing it, then prove
/// the reservation was released and the same canonical row can be attempted
/// again under a new approval.
async fn assert_refusal_releases_the_key(refusal: Reply) {
    let fixture = Fixture::new().await;
    fixture.queue([Reply::Json(channel_success(&fixture.pin("x"))), refusal]);
    let params = fixture.params("x", "hello");
    let refused = fixture
        .plugin
        .execute(fixture.request("draft_create", params.clone(), "credential-1", true))
        .await
        .expect_err("a refused create must never report success");
    let message = refused.to_string();
    assert!(
        message.contains("refused the request before execution")
            || message.contains("refused the create before execution"),
        "{message}"
    );
    assert!(message.contains("new approval"), "{message}");
    assert!(!message.contains("fixture-token"), "{message}");
    assert_eq!(fixture.count_query(CREATE_QUERY), 1);
    assert!(
        fixture
            .storage
            .get_native_draft(&draft_key(&fixture))
            .await
            .unwrap()
            .is_none(),
        "a refused create must leave no durable record"
    );

    // The queue is now empty, so the fixture's default replies let a retry
    // through: the key is usable again rather than permanently blocked.
    let retry = fixture
        .plugin
        .execute(fixture.request("draft_create", params, "credential-1", true))
        .await
        .expect("a released key is attemptable again");
    assert_eq!(
        fixture.count_query(CREATE_QUERY),
        2,
        "the retry must reach the provider"
    );
    let receipt: Value = serde_json::from_slice(&retry.body).unwrap();
    assert_eq!(receipt["external_id"], "post-1");
    let record = fixture
        .storage
        .get_native_draft(&draft_key(&fixture))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DraftSyncStatus::Succeeded);
}

#[tokio::test]
async fn unauthorized_create_is_refused_and_releases_the_reservation() {
    assert_refusal_releases_the_key(Reply::Raw(401, "{}".into())).await;
}

#[tokio::test]
async fn schema_rejected_create_is_refused_and_releases_the_reservation() {
    assert_refusal_releases_the_key(Reply::Raw(
        400,
        json!({"errors": [{"message": "Variable \"$input\" got an invalid value"}]}).to_string(),
    ))
    .await;
}

#[tokio::test]
async fn graphql_errors_without_data_are_refused_and_release_the_reservation() {
    assert_refusal_releases_the_key(Reply::Json(
        json!({"data": null, "errors": [{"message": "Not authorized for this channel"}]}),
    ))
    .await;
}

#[tokio::test]
async fn typed_limit_reached_is_refused_and_releases_the_reservation() {
    assert_refusal_releases_the_key(Reply::Json(json!({
        "data": {"createPost": {
            "__typename": "LimitReachedError",
            "message": "channel queue limit reached"
        }}
    })))
    .await;
}

#[tokio::test]
async fn contradictory_or_server_side_outcomes_stay_ambiguous_and_terminal() {
    let ambiguous = [
        // Errors next to a created post: the mutation may well have run.
        Reply::Json(json!({
            "errors": [{"message": "partial failure"}],
            "data": {"createPost": {"__typename": "PostActionSuccess", "post": {
                "id": "half-post", "text": "hello", "status": "draft",
                "channelId": "channel-x", "channelService": "twitter",
                "dueAt": null, "assets": []
            }}}
        })),
        // A 5xx is never a refusal, even when it carries a GraphQL error body.
        Reply::Raw(500, json!({"errors": [{"message": "boom"}]}).to_string()),
    ];
    for reply in ambiguous {
        let fixture = Fixture::new().await;
        fixture.queue([Reply::Json(channel_success(&fixture.pin("x"))), reply]);
        let params = fixture.params("x", "hello");
        let first = fixture
            .plugin
            .execute(fixture.request("draft_create", params.clone(), "credential-1", true))
            .await;
        assert!(first.is_err());
        let record = fixture
            .storage
            .get_native_draft(&draft_key(&fixture))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.status, DraftSyncStatus::Unknown);
        let creates = fixture.count_query(CREATE_QUERY);
        let second = fixture
            .plugin
            .execute(fixture.request("draft_create", params, "credential-1", true))
            .await;
        assert!(second.is_err(), "an ambiguous outcome stays terminal");
        assert_eq!(
            fixture.count_query(CREATE_QUERY),
            creates,
            "an ambiguous outcome was blindly recreated"
        );
    }
}

#[tokio::test]
async fn malformed_create_with_known_id_is_durably_unknown() {
    let fixture = Fixture::new().await;
    fixture.queue([
        Reply::Json(channel_success(&fixture.pin("x"))),
        Reply::Json(json!({
            "data": {"createPost": {"__typename": "PostActionSuccess", "post": {
                "id": "known-post", "text": "hello", "status": "draft",
                "channelId": "channel-x", "channelService": "twitter", "dueAt": null
            }}}
        })),
    ]);
    let result = fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", "hello"),
            "credential-1",
            true,
        ))
        .await;
    assert!(result.is_err());
    let key = BufferPlugin::native_key(
        "tenant-a",
        &fixture.pin("x"),
        &fixture.credential("credential-1"),
        "campaign-1",
        "variant-1",
        1,
    );
    let record = fixture
        .storage
        .get_native_draft(&key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DraftSyncStatus::Unknown);
}

#[tokio::test]
async fn partial_read_matching_text_can_never_be_reported_as_success() {
    let fixture = Fixture::new().await;
    create(&fixture, "x").await.1.unwrap();
    fixture.clear_requests();
    fixture.queue([
        Reply::Json(channel_success(&fixture.pin("x"))),
        Reply::Json(json!({"data": {"post": {
            "id": "post-1", "text": "hello from Buffer", "status": "draft",
            "channelId": "channel-x", "channelService": "twitter", "dueAt": null
        }}})),
    ]);
    let result = fixture
        .plugin
        .execute(fixture.request("draft_read", fixture.read_params("x"), "credential-1", true))
        .await;
    assert!(
        result.is_err(),
        "missing assets must not become a successful read"
    );
}

#[tokio::test]
async fn timeout_after_reservation_remains_durably_blocked() {
    let fixture = Fixture::new().await;
    fixture.queue([
        Reply::Json(channel_success(&fixture.pin("x"))),
        Reply::Delay(
            100,
            Box::new(Reply::Json(json!({
                "data": {"createPost": {"__typename": "PostActionSuccess", "post": {
                    "id": "late-post", "text": "hello", "status": "draft",
                    "channelId": "channel-x", "channelService": "twitter", "dueAt": null,
                    "assets": []
                }}}
            }))),
        ),
    ]);
    let plugin = BufferPlugin::with_client_endpoint(
        Client::builder().build().unwrap(),
        fixture.endpoint.clone(),
        fixture.pins.clone(),
        fixture.storage.clone(),
    )
    .with_request_timeout(Duration::from_millis(20));
    let params = fixture.params("x", "hello");
    let first = plugin
        .execute(fixture.request("draft_create", params.clone(), "credential-1", true))
        .await;
    assert!(first.is_err());
    let key = BufferPlugin::native_key(
        "tenant-a",
        &fixture.pin("x"),
        &fixture.credential("credential-1"),
        "campaign-1",
        "variant-1",
        1,
    );
    let record = fixture
        .storage
        .get_native_draft(&key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DraftSyncStatus::Unknown);
    let create_count = fixture.count_query(CREATE_QUERY);
    let second = plugin
        .execute(fixture.request("draft_create", params, "credential-1", true))
        .await;
    assert!(second.is_err());
    assert_eq!(fixture.count_query(CREATE_QUERY), create_count);
}

#[tokio::test]
async fn unicode_urls_and_limits_are_checked_without_truncation() {
    let fixture = Fixture::new().await;
    let text = "é".repeat(140); // conservative X weighting: exactly 280
    let params = fixture.params("x", &text);
    assert!(fixture
        .plugin
        .execute(fixture.request("draft_create", params, "credential-1", true))
        .await
        .is_ok());
    let input = &fixture.requests()[1]["variables"]["input"];
    assert_eq!(input["text"].as_str().unwrap(), text);

    let fixture = Fixture::new().await;
    let url_text = "https://x.co";
    assert!(fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", url_text),
            "credential-1",
            true
        ))
        .await
        .is_ok());
    assert_eq!(
        fixture.requests()[1]["variables"]["input"]["text"],
        url_text
    );

    let fixture = Fixture::new().await;
    let spaced = format!("{}x", "x ".repeat(139));
    assert!(fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", &spaced),
            "credential-1",
            true,
        ))
        .await
        .is_ok());
    assert_eq!(fixture.requests()[1]["variables"]["input"]["text"], spaced);

    let fixture = Fixture::new().await;
    let adjacent_urls = "https://x.co".repeat(13);
    assert!(fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", &adjacent_urls),
            "credential-1",
            true,
        ))
        .await
        .is_err());
    assert!(
        fixture.requests().is_empty(),
        "adjacent URLs must use per-URL weighting"
    );

    let fixture = Fixture::new().await;
    let ideographic_space = format!("{}\u{3000}x", "x".repeat(280));
    assert!(fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", &ideographic_space),
            "credential-1",
            true,
        ))
        .await
        .is_err());
    assert!(
        fixture.requests().is_empty(),
        "unicode whitespace must count toward limits"
    );

    let fixture = Fixture::new().await;
    let too_long = "x".repeat(281);
    assert!(fixture
        .plugin
        .execute(fixture.request(
            "draft_create",
            fixture.params("x", &too_long),
            "credential-1",
            true
        ))
        .await
        .is_err());
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn owned_read_detects_text_and_published_status_drift_without_remote_write() {
    let fixture = Fixture::new().await;
    let (params, created) = create(&fixture, "x").await;
    created.unwrap();
    fixture.clear_requests();
    fixture.queue([
        Reply::Json(channel_success(&fixture.pin("x"))),
        Reply::Json(json!({"data": {"post": {"id": "post-1", "text": "edited remotely", "status": "published", "channelId": "channel-x", "channelService": "twitter", "dueAt": null, "assets": []}}})),
    ]);
    let read = fixture
        .plugin
        .execute(fixture.request("draft_read", fixture.read_params("x"), "credential-1", true))
        .await
        .unwrap();
    let receipt: Value = serde_json::from_slice(&read.body).unwrap();
    assert_eq!(receipt["sync_status"], "drift");
    assert_eq!(receipt["external_status"], "published");
    assert_eq!(fixture.count_query(CREATE_QUERY), 0, "read never writes");
    assert_eq!(fixture.count_query(POST_QUERY), 1);
    let key = BufferPlugin::native_key(
        "tenant-a",
        &fixture.pin("x"),
        &fixture.credential("credential-1"),
        "campaign-1",
        "variant-1",
        1,
    );
    let record = fixture
        .storage
        .get_native_draft(&key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DraftSyncStatus::Succeeded);
    let stored_receipt = record.receipt.unwrap();
    assert_eq!(stored_receipt.sync_status, DraftSyncStatus::Succeeded);
    assert_eq!(stored_receipt.external_status.as_deref(), Some("draft"));
    let _ = params;
}

#[tokio::test]
async fn reads_are_owned_and_validate_returned_identity() {
    let fixture = Fixture::new().await;
    fixture.clear_requests();
    let result = fixture
        .plugin
        .execute(fixture.request("draft_read", fixture.read_params("x"), "credential-1", true))
        .await;
    assert!(result.is_err());
    assert!(
        fixture.requests().is_empty(),
        "unknown local mapping must not call Buffer"
    );

    let fixture = Fixture::new().await;
    create(&fixture, "x").await.1.unwrap();
    for (id, service, channel) in [
        ("other-post", "twitter", "channel-x"),
        ("post-1", "linkedin", "channel-x"),
        ("post-1", "twitter", "other-channel"),
    ] {
        fixture.clear_requests();
        fixture.queue([
            Reply::Json(channel_success(&fixture.pin("x"))),
            Reply::Json(json!({"data": {"post": {"id": id, "text": "hello from Buffer", "status": "draft", "channelId": channel, "channelService": service, "dueAt": null, "assets": []}}})),
        ]);
        let result = fixture
            .plugin
            .execute(fixture.request("draft_read", fixture.read_params("x"), "credential-1", true))
            .await;
        assert!(result.is_err());
    }
}
