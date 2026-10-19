//! feir-ops#1, "refusals on proof": every gateway refusal of an authenticated agent is sealed as a
//! `gateway-refusal` record (averin `POST /v2/refusals`) on every entry point, without ever
//! delaying or changing the refusal itself.
//!
//! The averin here is a stub that records what vultrino posts; the real averin's side (the closed
//! vocabularies, the record shape, the verifier count) is tested in averin's own PR and pinned
//! here by the vendored `vectors/refusal-classes.v1.json`.
//!
//! Test names beginning `refusal_table_` are the entry point x class table
//! (`refusal-sealed-every-entry-point`), `refusal_never_blocks_` the availability claim,
//! `refusal_coalesced_` and `refusal_budget_` the volume bound, `refusal_gap_` the gap record,
//! `refusal_no_secret_` the disclosure bound and `not_a_refusal_` the negative controls.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::approval::{CriticalityClass, NewApproval, RequesterInfo};
use vultrino::auth::{AuthManager, NewUseToken, UseToken};
use vultrino::averin::{AverinClient, AverinConfig, AverinMode};
use vultrino::capability::{Capability, CapabilityTarget, LlmProxy};
use vultrino::config::{Config, EnforcementConfig, EnforcementDefault, TenantMode};
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
use vultrino::router::CredentialResolver;
use vultrino::server::{ApprovalCaller, ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};
use vultrino::{
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, Secret,
};

const AGENT: &str = "ep_test_agent";
const CANARY_URL: &str = "https://canary.example/CANARY-URL-9f3a";
const CANARY_BODY: &str = "CANARY-PARAM-77c1";
const DOWN: &str = "http://127.0.0.1:9";

// ---------------------------------------------------------------------------
// A stub averin: records every POST /v2/refusals, answers by mode.
// ---------------------------------------------------------------------------

const OK: u8 = 0;
const OVERLOADED: u8 = 1;
const HANG: u8 = 2;
const REJECT: u8 = 3;

#[derive(Clone)]
struct Stub {
    url: String,
    /// Every body posted, in any mode (a retry shows up again with the same idempotency key).
    attempts: Arc<Mutex<Vec<Value>>>,
    /// Bodies the stub accepted (answered 2xx): the sealed records.
    sealed: Arc<Mutex<Vec<Value>>>,
    mode: Arc<AtomicU8>,
}

async fn refusals_handler(State(st): State<Stub>, body: axum::body::Bytes) -> (StatusCode, String) {
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    st.attempts.lock().unwrap().push(v.clone());
    match st.mode.load(Ordering::SeqCst) {
        OK => {
            st.sealed.lock().unwrap().push(v);
            (
                StatusCode::CREATED,
                json!({"record_id": "refusal-x", "created": true}).to_string(),
            )
        }
        OVERLOADED => (StatusCode::SERVICE_UNAVAILABLE, "{}".to_string()),
        HANG => {
            tokio::time::sleep(Duration::from_secs(120)).await;
            (StatusCode::OK, "{}".to_string())
        }
        _ => (StatusCode::BAD_REQUEST, "{}".to_string()),
    }
}

async fn start_stub(mode: u8) -> Stub {
    let stub = Stub {
        url: String::new(),
        attempts: Arc::default(),
        sealed: Arc::default(),
        mode: Arc::new(AtomicU8::new(mode)),
    };
    let app = axum::Router::new()
        .route("/v2/refusals", axum::routing::post(refusals_handler))
        // D8 evidence: refuse the exact grant, so an evidence-required dispatch is refused.
        .route(
            "/v2/grants",
            axum::routing::post(|| async { (StatusCode::FORBIDDEN, "{}") }),
        )
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Stub {
        url: format!("http://{addr}"),
        ..stub
    }
}

// ---------------------------------------------------------------------------
// The upstream the refusals must never reach.
// ---------------------------------------------------------------------------

struct MockHttp(Arc<AtomicUsize>);

#[async_trait]
impl Plugin for MockHttp {
    fn name(&self) -> &str {
        "http"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["request"]
    }
    async fn execute(&self, _request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ExecuteResponse::new(
            200,
            HashMap::from([("content-type".to_string(), "application/json".to_string())]),
            b"{\"ok\":true}".to_vec(),
        ))
    }
    fn validate_params(&self, _a: &str, _p: &Value) -> Result<(), PluginError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The fixture.
// ---------------------------------------------------------------------------

/// A change to the fixture's config before the server is built.
type ConfigEdit = Box<dyn FnOnce(&mut Config)>;

struct Opts {
    averin_url: Option<String>,
    token_scope: &'static str,
    action_scope: Option<&'static str>,
    max_uses: Option<u32>,
    token_tenant: Option<&'static str>,
    edit: Option<ConfigEdit>,
    policies: Vec<Policy>,
    llm_models: Option<Vec<String>>,
    card: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            averin_url: None,
            token_scope: "cred-*",
            action_scope: None,
            max_uses: None,
            token_tenant: None,
            edit: None,
            policies: Vec::new(),
            llm_models: None,
            card: false,
        }
    }
}

struct Fx {
    router: axum::Router,
    storage: Arc<dyn StorageBackend>,
    srv: Arc<VultrinoServer>,
    av: Option<Arc<AverinClient>>,
    secret: String,
    token: UseToken,
    upstream: Arc<AtomicUsize>,
}

fn allow(pattern: &str) -> Policy {
    Policy::allow_all(format!("allow-{pattern}"), pattern).with_rule(
        PolicyCondition::UrlMatch("*".to_string()),
        PolicyAction::Allow,
    )
}

fn api_cred(alias: &str) -> Credential {
    Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("sk-vault-only-REFUSAL-TEST-key"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
}

async fn fx(o: Opts) -> Fx {
    unsafe { std::env::set_var("VULTRINO_PROVIDER_OPENAI_ENABLED", "true") };
    let mut policies = vec![
        allow("cred-ok"),
        allow("cred-tenant"),
        allow("cred-approve"),
        allow("cred-llm"),
        // Not matched by any allow: a request on it falls to the default deny.
        Policy::deny_all("rate-limited", "cred-rl").with_rule(
            PolicyCondition::And(vec![
                PolicyCondition::UrlMatch("*".to_string()),
                PolicyCondition::RateLimit {
                    max: 1,
                    window_secs: 3600,
                },
            ]),
            PolicyAction::Allow,
        ),
        Policy::deny_all("observe-me", "cred-obs"),
    ];
    policies.extend(o.policies);
    let mut config = Config {
        enforcement: EnforcementConfig {
            default_action: EnforcementDefault::Deny,
            require_declared_capabilities: false,
        },
        policies,
        ..Config::default()
    };
    config
        .tenants
        .insert("acme-obs".to_string(), TenantMode::Observe);
    if o.card {
        let dir = tempdir().unwrap();
        let path = dir.path().join("card.json");
        std::mem::forget(dir);
        std::fs::write(
            &path,
            r#"[{"rate_card_version":"t-1","entries":[
 {"model_ref":"gpt-4o-mini","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":2}
]}]"#,
        )
        .unwrap();
        config.llm_proxy = config.llm_proxy.clone().with_rate_card_path(path).unwrap();
    }
    if let Some(url) = &o.averin_url {
        config.averin = AverinConfig {
            enabled: true,
            base_url: url.clone(),
            resource_id: "orders-db".to_string(),
            mode: AverinMode::Observe,
            timeout: Duration::from_secs(2),
            refusal_window_secs: 1,
            ..AverinConfig::default()
        };
    }
    if let Some(edit) = o.edit {
        edit(&mut config);
    }

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("test-password"))
            .await
            .unwrap(),
    );
    let admin = AdminAuth::new("admin", "password123").unwrap();
    let auth_manager = AuthManager::from_data(
        storage.list_roles().await.unwrap(),
        storage.list_api_keys().await.unwrap(),
    );
    let srv = Arc::new(VultrinoServer::new(
        config.clone(),
        storage.clone(),
        CredentialResolver::new(storage.clone()),
    ));
    srv.load_plugins().await.unwrap();
    srv.reload_policies().await.unwrap();
    let upstream = Arc::new(AtomicUsize::new(0));
    srv.plugins().register(Arc::new(MockHttp(upstream.clone())));

    for alias in [
        "cred-ok",
        "cred-other",
        "cred-nopolicy",
        "cred-rl",
        "cred-obs",
    ] {
        storage.store(&api_cred(alias)).await.unwrap();
    }
    storage
        .store(&api_cred("cred-tenant").with_metadata("tenant", "acme"))
        .await
        .unwrap();
    storage
        .store(&api_cred("cred-approve").with_metadata("require_approval", "true"))
        .await
        .unwrap();
    storage.store(&api_cred("cred-llm")).await.unwrap();
    // The model channel for `cred-llm`, stored only when a test asks for one: without it /llm fails
    // closed (no channel granted).
    if let Some(allowed) = o.llm_models.clone() {
        let chan = Capability {
            id: "cap-llm".to_string(),
            tool_name: "model_proxy".to_string(),
            description: "the agent's model channel".to_string(),
            action: "http.request".to_string(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: "cred-llm".to_string(),
            input_schema: Value::Null,
            reversibility: "reversible".to_string(),
            llm: Some(LlmProxy {
                provider_base: "http://127.0.0.1:9".to_string(),
                allowed_models: allowed,
                ..Default::default()
            }),
            approval_preview: None,
        };
        chan.validate().unwrap();
        storage.store_capability(&chan).await.unwrap();
    }

    let (secret, mut token) = UseToken::create(NewUseToken {
        name: "agent".to_string(),
        credential_scope: o.token_scope.to_string(),
        action_scope: o.action_scope.map(str::to_string),
        max_uses: o.max_uses,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some(AGENT.to_string());
    token.tenant = o.token_tenant.map(str::to_string);
    storage.store_use_token(&token).await.unwrap();

    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage.clone(),
        auth_manager,
        admin,
        srv.clone(),
    )
    .into_router();
    let av = srv.averin();
    Fx {
        router,
        storage,
        srv,
        av,
        secret,
        token,
        upstream,
    }
}

impl Fx {
    async fn execute(
        &self,
        bearer: &str,
        cred: &str,
        action: Option<&str>,
    ) -> (StatusCode, String) {
        let mut body = json!({
            "credential": cred,
            "method": "GET",
            "url": CANARY_URL,
            "body": CANARY_BODY,
        });
        if let Some(a) = action {
            body["action"] = json!(a);
        }
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/execute")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn llm(&self, bearer: &str, body: Value) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri("/llm/v1/chat/completions")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// An MCP `tools/call` as `secret`; returns the JSON-RPC response as JSON.
    async fn mcp(&self, secret: &str, tool: &str, mut arguments: Value) -> Value {
        let auth_manager = Arc::new(tokio::sync::RwLock::new(AuthManager::from_data(
            self.storage.list_roles().await.unwrap(),
            self.storage.list_api_keys().await.unwrap(),
        )));
        let mut mcp = vultrino::mcp::McpServer::new(self.srv.clone(), auth_manager);
        arguments["api_key"] = json!(secret);
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        });
        let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
        serde_json::to_value(&resp).unwrap()
    }

    /// A vk_ admin key (the MCP generic tools take keys).
    async fn admin_key(&self) -> String {
        let (key, rec) = AuthManager::new()
            .create_api_key("admin-key", vultrino::auth::ROLE_ADMIN, None)
            .unwrap();
        self.storage.store_api_key(&rec).await.unwrap();
        key
    }

    fn av(&self) -> &Arc<AverinClient> {
        self.av.as_ref().expect("averin enabled in this fixture")
    }

    /// Drain once and return what the stub sealed.
    async fn sealed(&self, stub: &Stub) -> Vec<Value> {
        self.av().drain_refusals_once().await;
        stub.sealed.lock().unwrap().clone()
    }
}

/// The one record the stub sealed, with its closed shape checked.
fn only(records: &[Value]) -> &Value {
    assert_eq!(records.len(), 1, "exactly one refusal record: {records:#?}");
    let r = &records[0];
    let keys: std::collections::BTreeSet<&str> =
        r.as_object().unwrap().keys().map(String::as_str).collect();
    let allowed: std::collections::BTreeSet<&str> = [
        "project_id",
        "session_id",
        "idempotency_key",
        "agent_id",
        "action",
        "entry_point",
        "reason_class",
        "credential",
        "attempts",
        "first_at",
        "last_at",
    ]
    .into_iter()
    .collect();
    assert!(
        keys.is_subset(&allowed),
        "unexpected keys in the refusal body: {keys:?}"
    );
    r
}

fn expect(
    records: &[Value],
    class: &str,
    entry: &str,
    agent: Option<&str>,
    action: &str,
    credential: Option<&str>,
) {
    let r = only(records);
    assert_eq!(r["reason_class"], class, "{r}");
    assert_eq!(r["entry_point"], entry, "{r}");
    assert_eq!(r["action"], action, "{r}");
    assert_eq!(r["attempts"], 1, "{r}");
    match agent {
        Some(a) => assert_eq!(r["agent_id"], a, "{r}"),
        None => assert!(
            r["agent_id"].as_str().unwrap().starts_with("vultrino:"),
            "{r}"
        ),
    }
    match credential {
        Some(c) => assert_eq!(r["credential"], c, "{r}"),
        None => assert!(r.get("credential").is_none(), "{r}"),
    }
    assert!(r["idempotency_key"]
        .as_str()
        .unwrap()
        .starts_with("vultrino-refusal-"));
}

async fn averin_fx(edit: impl FnOnce(&mut Opts)) -> (Fx, Stub) {
    let stub = start_stub(OK).await;
    let mut o = Opts {
        averin_url: Some(stub.url.clone()),
        ..Opts::default()
    };
    edit(&mut o);
    (fx(o).await, stub)
}

// ===========================================================================
// refusal-sealed-every-entry-point: the entry point x class table.
// ===========================================================================

#[tokio::test]
async fn refusal_table_execute_not_granted() {
    let (f, stub) = averin_fx(|o| o.token_scope = "cred-ok").await;
    let (status, _) = f.execute(&f.secret, "cred-other", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The principal's own credential scope refuses before the credential is resolved, so the
    // record carries no credential.
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "execute",
        Some(AGENT),
        "http.request",
        None,
    );
    assert_eq!(
        f.upstream.load(Ordering::SeqCst),
        0,
        "the upstream is never reached"
    );
}

#[tokio::test]
async fn refusal_table_execute_not_granted_action_scope_after_the_credential_resolves() {
    let (f, stub) = averin_fx(|o| o.action_scope = Some("http.request")).await;
    let (status, _) = f.execute(&f.secret, "cred-ok", Some("plug.other")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "execute",
        Some(AGENT),
        "plug.other",
        Some("cred-ok"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_execute_policy_deny() {
    let (f, stub) = averin_fx(|_| {}).await;
    f.execute(&f.secret, "cred-nopolicy", None).await;
    expect(
        &f.sealed(&stub).await,
        "policy_deny",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-nopolicy"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_execute_kill_fence() {
    let (f, stub) = averin_fx(|o| {
        o.policies.push(Policy::kill_switch("halt:agent", AGENT));
    })
    .await;
    f.execute(&f.secret, "cred-ok", None).await;
    expect(
        &f.sealed(&stub).await,
        "kill_fence",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-ok"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_execute_rate_limit() {
    let (f, stub) = averin_fx(|_| {}).await;
    let (first, _) = f.execute(&f.secret, "cred-rl", None).await;
    assert_eq!(first, StatusCode::OK, "the first call is inside the limit");
    assert!(
        f.sealed(&stub).await.is_empty(),
        "an admitted call is not a refusal"
    );
    f.execute(&f.secret, "cred-rl", None).await;
    expect(
        &f.sealed(&stub).await,
        "rate_limit",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-rl"),
    );
    assert_eq!(
        f.upstream.load(Ordering::SeqCst),
        1,
        "only the admitted call ran"
    );
}

#[tokio::test]
async fn refusal_table_execute_cross_tenant() {
    let (f, stub) = averin_fx(|_| {}).await;
    f.execute(&f.secret, "cred-tenant", None).await;
    expect(
        &f.sealed(&stub).await,
        "cross_tenant",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-tenant"),
    );
}

#[tokio::test]
async fn refusal_table_execute_token_unusable() {
    let (f, stub) = averin_fx(|o| o.max_uses = Some(1)).await;
    f.storage.consume_use_token(&f.token.id).await.unwrap();
    let (status, _) = f.execute(&f.secret, "cred-ok", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The credential is not resolved at that point, so the record carries none.
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "execute",
        Some(AGENT),
        "http.request",
        None,
    );
}

#[tokio::test]
async fn refusal_table_execute_llm_channel_only() {
    let (f, stub) = averin_fx(|o| o.llm_models = Some(Vec::new())).await;
    let (status, _) = f.execute(&f.secret, "cred-llm", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "llm_channel_only",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-llm"),
    );
}

#[tokio::test]
async fn refusal_table_execute_capability_undeclared() {
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| {
            c.enforcement.require_declared_capabilities = true
        }));
    })
    .await;
    f.execute(&f.secret, "cred-ok", None).await;
    expect(
        &f.sealed(&stub).await,
        "capability_undeclared",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-ok"),
    );
}

#[tokio::test]
async fn refusal_table_execute_approval_unavailable() {
    let (f, stub) = averin_fx(|_| {}).await;
    f.execute(&f.secret, "cred-approve", None).await;
    expect(
        &f.sealed(&stub).await,
        "approval_unavailable",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-approve"),
    );
}

#[tokio::test]
async fn refusal_table_execute_decision_unavailable_at_dispatch() {
    // Evidence is required before the act and averin refuses the grant: nothing runs, and the
    // dispatch-time refusal is sealed under the entry point that carried it.
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| c.averin.d8_complete_evidence = true));
    })
    .await;
    let (status, _) = f.execute(&f.secret, "cred-ok", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    expect(
        &f.sealed(&stub).await,
        "decision_unavailable",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-ok"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

/// The streaming tail refuses at dispatch the same way, and notes it once under the same entry.
#[tokio::test]
async fn refusal_table_execute_streaming_decision_unavailable_at_dispatch() {
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| c.averin.d8_complete_evidence = true));
    })
    .await;
    let auth = ExecAuth::from_use_token(f.token.clone());
    let err = f
        .srv
        .execute_gated_streaming(token_request("http.request"), auth)
        .await
        .err()
        .expect("the streaming tail refuses");
    assert!(
        err.to_string().contains("D8 before-act evidence failed"),
        "{err}"
    );
    expect(
        &f.sealed(&stub).await,
        "decision_unavailable",
        "execute",
        Some(AGENT),
        "http.request",
        Some("cred-ok"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_mcp_tool_not_available_to_a_use_token() {
    let (f, stub) = averin_fx(|_| {}).await;
    let v = f
        .mcp(
            &f.secret,
            "http_request",
            json!({"credential": "cred-ok", "method": "GET", "url": CANARY_URL}),
        )
        .await;
    assert!(v.get("error").is_some(), "the gate refuses: {v}");
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "mcp",
        Some(AGENT),
        "http_request",
        None,
    );
}

#[tokio::test]
async fn refusal_table_mcp_unknown_tool_for_an_api_key() {
    let (f, stub) = averin_fx(|_| {}).await;
    let key = f.admin_key().await;
    let v = f.mcp(&key, "no_such_tool_xyz", json!({})).await;
    assert!(v.get("error").is_some(), "{v}");
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "mcp",
        None,
        "no_such_tool_xyz",
        None,
    );
}

#[tokio::test]
async fn refusal_table_mcp_policy_deny_through_the_shared_gate() {
    let (f, stub) = averin_fx(|_| {}).await;
    let key = f.admin_key().await;
    let v = f
        .mcp(
            &key,
            "http_request",
            json!({"credential": "cred-nopolicy", "method": "GET", "url": CANARY_URL}),
        )
        .await;
    assert_eq!(v["result"]["isError"], true, "{v}");
    expect(
        &f.sealed(&stub).await,
        "policy_deny",
        "mcp",
        None,
        "http.request",
        Some("cred-nopolicy"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_llm_no_channel_granted() {
    let (f, stub) = averin_fx(|_| {}).await;
    let (status, _) = f
        .llm(&f.secret, json!({"model": "gpt-4o-mini", "messages": []}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "llm",
        Some(AGENT),
        "llm.proxy",
        None,
    );
}

#[tokio::test]
async fn refusal_table_llm_model_not_permitted() {
    let (f, stub) = averin_fx(|o| o.llm_models = Some(vec!["gpt-4o".to_string()])).await;
    let (status, _) = f
        .llm(&f.secret, json!({"model": "gpt-3.5-turbo", "messages": []}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "llm",
        Some(AGENT),
        "http.request",
        Some("cred-llm"),
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusal_table_llm_model_unpriced() {
    let (f, stub) = averin_fx(|o| {
        o.llm_models = Some(Vec::new());
        o.card = true;
    })
    .await;
    let (status, _) = f
        .llm(
            &f.secret,
            json!({"model": "model-nobody-prices", "messages": []}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "model_unpriced",
        "llm",
        Some(AGENT),
        "http.request",
        Some("cred-llm"),
    );
}

#[tokio::test]
async fn refusal_table_llm_token_unusable() {
    let (f, stub) = averin_fx(|o| o.max_uses = Some(1)).await;
    f.storage.consume_use_token(&f.token.id).await.unwrap();
    let (status, _) = f.llm(&f.secret, json!({"model": "x"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "llm",
        Some(AGENT),
        "llm.proxy",
        None,
    );
}

/// A named capability for `cred-ok`, callable over MCP by tool name.
async fn store_named_capability(f: &Fx, tool: &str) {
    f.storage
        .store_capability(&Capability {
            id: format!("cap-{tool}"),
            tool_name: tool.to_string(),
            description: "a named http capability".to_string(),
            action: "http.request".to_string(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: "cred-ok".to_string(),
            input_schema: json!({"type": "object"}),
            reversibility: "reversible".to_string(),
            llm: None,
            approval_preview: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn refusal_table_mcp_exhausted_token_on_a_named_capability() {
    let (f, stub) = averin_fx(|o| o.max_uses = Some(1)).await;
    store_named_capability(&f, "named_http").await;
    f.storage.consume_use_token(&f.token.id).await.unwrap();
    let v = f.mcp(&f.secret, "named_http", json!({})).await;
    let text = v.to_string();
    assert!(text.contains("cannot be used"), "{v}");
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "mcp",
        Some(AGENT),
        "named_http",
        None,
    );
}

#[tokio::test]
async fn refusal_table_mcp_exhausted_token_at_the_use_token_gate() {
    // The gate refuses a generic tool for a use token; the token being unusable is what the record
    // says, because the same resolution that finds the agent fails first.
    let (f, stub) = averin_fx(|o| o.max_uses = Some(1)).await;
    f.storage.consume_use_token(&f.token.id).await.unwrap();
    let v = f
        .mcp(
            &f.secret,
            "http_request",
            json!({"credential": "cred-ok", "method": "GET", "url": CANARY_URL}),
        )
        .await;
    assert!(v.get("error").is_some(), "{v}");
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "mcp",
        Some(AGENT),
        "http_request",
        None,
    );
}

#[tokio::test]
async fn refusal_table_mcp_unknown_secret_on_a_named_capability_is_noted_nowhere() {
    let (f, stub) = averin_fx(|_| {}).await;
    store_named_capability(&f, "named_http").await;
    let v = f
        .mcp(
            "vut_not_a_stored_token_0000000000000000",
            "named_http",
            json!({}),
        )
        .await;
    assert!(v.to_string().contains("Invalid use token"), "{v}");
    assert!(f.sealed(&stub).await.is_empty());
    assert_eq!(f.av().refusal_counters().noted, 0);
}

async fn revoke_token(f: &Fx) {
    f.storage.set_use_token_revoked(&f.token.id).await.unwrap();
}

#[tokio::test]
async fn refusal_table_approval_poll_by_a_revoked_token_rest() {
    let (f, stub) = averin_fx(|_| {}).await;
    revoke_token(&f).await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/approvals/ap_any")
        .header("authorization", format!("Bearer {}", f.secret))
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "approval_resume",
        Some(AGENT),
        "check_approval",
        None,
    );
}

#[tokio::test]
async fn refusal_table_approval_poll_by_a_revoked_token_mcp() {
    let (f, stub) = averin_fx(|_| {}).await;
    revoke_token(&f).await;
    let v = f
        .mcp(
            &f.secret,
            "check_approval",
            json!({"approval_id": "ap_any"}),
        )
        .await;
    assert!(v.to_string().contains("revoked"), "{v}");
    expect(
        &f.sealed(&stub).await,
        "token_unusable",
        "approval_resume",
        Some(AGENT),
        "check_approval",
        None,
    );
}

#[tokio::test]
async fn refusal_table_approval_poll_by_an_exhausted_token_is_not_a_refusal() {
    // Polling is a read: an exhausted token legitimately polls the approval it just consumed.
    let (f, stub) = averin_fx(|o| o.max_uses = Some(1)).await;
    f.storage.consume_use_token(&f.token.id).await.unwrap();
    let v = f
        .mcp(
            &f.secret,
            "check_approval",
            json!({"approval_id": "ap_any"}),
        )
        .await;
    assert!(!v.to_string().contains("cannot be used"), "{v}");
    assert!(f.sealed(&stub).await.is_empty());
}

/// A refusal raised while an approved action is resumed (here: the credential changed after the
/// human approved) is sealed under the approval's recorded principal on the `approval_resume`
/// entry point. Removing the note on the resume path, or losing the principal, fails this.
#[tokio::test]
async fn refusal_table_approval_resume_refusal_at_resume_time() {
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| c.approval.enabled = true));
    })
    .await;
    store_named_capability_for(&f, "approve_http", "cred-approve").await;
    let (status, body) = f.execute(&f.secret, "cred-approve", None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let approval = f.storage.list_approvals().await.unwrap().remove(0);
    f.storage
        .decide_approval(
            &approval.id,
            true,
            "test",
            "secops",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    // The credential the human approved is replaced in place before the resume.
    let current = f
        .storage
        .get_by_alias("cred-approve")
        .await
        .unwrap()
        .unwrap();
    f.storage.delete(&current.id).await.unwrap();
    f.storage
        .store(
            &api_cred("cred-approve")
                .with_metadata("require_approval", "true")
                .with_metadata("rotated", "yes"),
        )
        .await
        .unwrap();
    assert!(f.sealed(&stub).await.is_empty(), "nothing refused yet");
    let caller = ApprovalCaller {
        principal_id: f.token.id.clone(),
        agent_label: Some(AGENT.to_string()),
        tenant: None,
    };
    let resumed = f
        .srv
        .check_and_resume_approval(&approval.id, Some(&caller))
        .await
        .unwrap();
    assert!(
        resumed.result_error.is_some(),
        "the resume refused: {resumed:?}"
    );
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0, "nothing ran");
    let records = f.sealed(&stub).await;
    let r = only(&records);
    assert_eq!(r["entry_point"], "approval_resume", "{r}");
    assert_eq!(r["agent_id"], AGENT, "{r}");
    assert_eq!(r["action"], "http.request", "{r}");
    assert_eq!(r["credential"], "cred-approve", "{r}");
    assert!(
        matches!(
            r["reason_class"].as_str(),
            Some("decision_unavailable") | Some("cross_tenant")
        ),
        "{r}"
    );
}

async fn store_named_capability_for(f: &Fx, tool: &str, credential: &str) {
    f.storage
        .store_capability(&Capability {
            id: format!("cap-{tool}"),
            tool_name: tool.to_string(),
            description: "reversible http".to_string(),
            action: "http.request".to_string(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: credential.to_string(),
            input_schema: json!({"type": "object"}),
            reversibility: "reversible".to_string(),
            llm: None,
            approval_preview: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn refusal_table_llm_ambiguous_channels_is_not_a_refusal_of_access() {
    // An agent that holds more than one model channel and names none made a request-shape error.
    let (f, stub) = averin_fx(|o| o.llm_models = Some(vec!["m1".to_string()])).await;
    let mut second = f.storage.list_capabilities().await.unwrap().remove(0);
    second.id = "cap-llm-2".to_string();
    second.tool_name = "model_proxy_2".to_string();
    f.storage.store_capability(&second).await.unwrap();
    let (status, body) = f.llm(&f.secret, json!({"model": "m1"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("Multiple model channels"), "{body}");
    assert!(f.sealed(&stub).await.is_empty(), "no refusal record");
    assert_eq!(f.av().refusal_counters().noted, 0);
}

#[tokio::test]
async fn refusal_table_approval_resume_by_a_non_owner() {
    let (f, stub) = averin_fx(|_| {}).await;
    let (approval, _oob) = vultrino::approval::ApprovalRequest::open(NewApproval {
        credential: "cred-ok".to_string(),
        action: "http.request".to_string(),
        params: json!({"method": "GET"}),
        requester: RequesterInfo {
            principal_kind: "use_token".to_string(),
            principal_id: Some("ut_owner".to_string()),
            principal_name: Some("agent".to_string()),
            role: None,
            owner: None,
        },
        use_token_id: None,
        principal_id: Some("ut_owner".to_string()),
        agent_label: Some("ep_owner".to_string()),
        tenant: None,
        trusted_irreversible: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: CriticalityClass::Low,
        escalate_after: chrono::Duration::minutes(30),
        escalate_window: chrono::Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    });
    f.storage.store_approval(&approval).await.unwrap();
    let caller = ApprovalCaller {
        principal_id: "ut_intruder".to_string(),
        agent_label: Some("ep_intruder".to_string()),
        tenant: None,
    };
    let err = f
        .srv
        .check_and_resume_approval(&approval.id, Some(&caller))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("different principal"), "{err}");
    expect(
        &f.sealed(&stub).await,
        "not_granted",
        "approval_resume",
        Some("ep_intruder"),
        "http.request",
        Some("cred-ok"),
    );
}

// ===========================================================================
// refusal-never-blocks: the refusal is returned first, byte for byte.
// ===========================================================================

/// The status and body of a refusal, with averin off, healthy, down and tarpitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_never_blocks_and_is_byte_identical_with_averin_off_down_or_hung() {
    let off = fx(Opts::default()).await;
    let healthy = start_stub(OK).await;
    let hung = start_stub(HANG).await;
    let cases = [
        ("off", off, None),
        (
            "healthy",
            fx(Opts {
                averin_url: Some(healthy.url.clone()),
                ..Opts::default()
            })
            .await,
            Some(healthy.clone()),
        ),
        (
            "down",
            fx(Opts {
                averin_url: Some(DOWN.to_string()),
                ..Opts::default()
            })
            .await,
            None,
        ),
        (
            "hung",
            fx(Opts {
                averin_url: Some(hung.url.clone()),
                ..Opts::default()
            })
            .await,
            Some(hung.clone()),
        ),
    ];
    let mut baseline: Option<(StatusCode, String)> = None;
    let mut worst = Duration::ZERO;
    for (name, f, _) in &cases {
        for _ in 0..5 {
            let t = Instant::now();
            let got = f.execute(&f.secret, "cred-nopolicy", None).await;
            let took = t.elapsed();
            worst = worst.max(took);
            assert!(
                took < Duration::from_millis(1500),
                "{name}: a refusal waited {took:?}: sealing must never be on the request path"
            );
            match &baseline {
                None => baseline = Some(got),
                Some(b) => assert_eq!(&got, b, "{name}: the refusal must be byte-identical"),
            }
        }
    }
    // Nothing was drained, so the hung averin was never even contacted from a request.
    assert!(hung.attempts.lock().unwrap().is_empty());
}

/// The same property on the MCP refusal paths that resolve the refused principal first (an unusable
/// token, a tool a use token may not call): the answer is identical and prompt with [averin] off,
/// unreachable or hung, and the hung averin is never contacted from the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_never_blocks_the_mcp_refusal_paths() {
    let hung = start_stub(HANG).await;
    let mut cases = Vec::new();
    for url in [None, Some(DOWN.to_string()), Some(hung.url.clone())] {
        let f = fx(Opts {
            averin_url: url,
            max_uses: Some(1),
            ..Opts::default()
        })
        .await;
        store_named_capability(&f, "named_http").await;
        f.storage.consume_use_token(&f.token.id).await.unwrap();
        cases.push(f);
    }
    let mut baseline: Option<(Value, Value)> = None;
    for f in &cases {
        let t = Instant::now();
        let a = f.mcp(&f.secret, "named_http", json!({})).await;
        let b = f
            .mcp(&f.secret, "http_request", json!({"credential": "cred-ok"}))
            .await;
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "an MCP refusal waited {:?}",
            t.elapsed()
        );
        match &baseline {
            None => baseline = Some((a, b)),
            Some((ba, bb)) => {
                assert_eq!(&a, ba, "the refusal must be identical");
                assert_eq!(&b, bb, "the refusal must be identical");
            }
        }
    }
    assert!(hung.attempts.lock().unwrap().is_empty());
}

/// The same property in RequireEvidence mode: the refusal stands whatever averin does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_never_blocks_in_require_evidence_mode() {
    let hung = start_stub(HANG).await;
    let f = fx(Opts {
        averin_url: Some(hung.url.clone()),
        edit: Some(Box::new(|c| c.averin.mode = AverinMode::RequireEvidence)),
        ..Opts::default()
    })
    .await;
    for _ in 0..5 {
        let t = Instant::now();
        let (status, _) = f.execute(&f.secret, "cred-nopolicy", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t.elapsed()
        );
    }
    assert!(hung.attempts.lock().unwrap().is_empty());
}

// ===========================================================================
// refusal-coalesced-and-budgeted: a storm cannot grow the record count.
// ===========================================================================

fn token_request(action: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: "cred-ok".to_string(),
        action: action.to_string(),
        params: json!({"method": "GET", "url": CANARY_URL}),
    }
}

#[tokio::test]
async fn refusal_coalesced_1000_identical_refusals_are_two_records_with_an_exact_sum() {
    let (f, stub) = averin_fx(|o| o.token_scope = "cred-nomatch").await;
    for _ in 0..1000 {
        let auth = ExecAuth::from_use_token(f.token.clone());
        f.srv
            .execute_gated(token_request("http.request"), auth)
            .await
            .unwrap_err();
    }
    let first = f.sealed(&stub).await;
    assert_eq!(
        first.len(),
        1,
        "the first refusal is sealed at the next drain"
    );
    assert_eq!(first[0]["attempts"], 1);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let all = f.sealed(&stub).await;
    assert_eq!(
        all.len(),
        2,
        "the rest of the window is one record: {all:#?}"
    );
    let sum: u64 = all.iter().map(|r| r["attempts"].as_u64().unwrap()).sum();
    assert_eq!(sum, 1000, "counts stay exact");
    assert_eq!(f.av().refusal_counters().noted, 1000);
    // And nothing more is ever produced for them.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(f.sealed(&stub).await.len(), 2);
}

#[tokio::test]
async fn refusal_budget_a_distinct_key_flood_stays_inside_the_bucket_with_exact_counts() {
    let (f, stub) = averin_fx(|o| {
        o.token_scope = "cred-nomatch";
        o.edit = Some(Box::new(|c| {
            c.averin.refusal_burst = 3;
            c.averin.refusal_records_per_hour = 1;
        }));
    })
    .await;
    for i in 0..50 {
        let auth = ExecAuth::from_use_token(f.token.clone());
        f.srv
            .execute_gated(token_request(&format!("plug.act{i}")), auth)
            .await
            .unwrap_err();
    }
    let sealed = f.sealed(&stub).await;
    assert_eq!(
        sealed.len(),
        3,
        "the burst bounds the records: {}",
        sealed.len()
    );
    let c = f.av().refusal_counters();
    assert_eq!(c.noted, 50);
    assert_eq!(
        c.summarized, 47,
        "the rest are merged into the exact-count summary"
    );
}

// ===========================================================================
// refusal-gap-recorded: averin down = the refusal stands and the gap is recorded.
// ===========================================================================

async fn refusal_gaps(f: &Fx) -> Vec<Value> {
    vultrino::server::flush_receipt_gaps_once(&f.storage, f.av()).await;
    f.storage
        .list_events_after(0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_EVIDENCE_RECEIPT_GAP)
        .map(|e| e.payload)
        .collect()
}

#[tokio::test]
async fn refusal_gap_averin_down_is_a_refusal_gap_not_an_action_that_ran() {
    let f = fx(Opts {
        averin_url: Some(DOWN.to_string()),
        ..Opts::default()
    })
    .await;
    let (status, _) = f.execute(&f.secret, "cred-nopolicy", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the refusal stands");
    // A transient failure is retried on the next ticks; the last one becomes the gap.
    for _ in 0..3 {
        assert!(refusal_gaps(&f).await.is_empty() || f.av().refusal_counters().unsealed > 0);
        f.av().drain_refusals_once().await;
    }
    let gaps = refusal_gaps(&f).await;
    assert_eq!(gaps.len(), 1, "{gaps:#?}");
    let g = &gaps[0];
    assert_eq!(g["kind"], "refusal");
    assert_eq!(g["outcome"], "refused_not_sealed");
    assert_eq!(g["reason"], "refusal_seal_failed");
    // The refused agent is `agent_id`, never `token_id`, and there is no use counter: a consumer
    // must not read a refusal gap as a token whose action ran.
    assert_eq!(g["agent_id"], AGENT);
    assert!(g.get("token_id").is_none(), "{g}");
    assert!(g.get("use_sequence_number").is_none(), "{g}");
    assert_ne!(g["outcome"], "action_ran_without_receipt");
    assert_eq!(f.av().refusal_counters().unsealed, 1);
    assert_eq!(f.upstream.load(Ordering::SeqCst), 0);
}

/// The process stops: the first refusal still waiting for the next drain and the tail of the open
/// window are sealed by the shutdown flush, not dropped.
#[tokio::test]
async fn refusal_gap_shutdown_flush_seals_the_first_refusal_and_the_open_tail() {
    let (f, stub) = averin_fx(|_| {}).await;
    for _ in 0..4 {
        let (status, _) = f.execute(&f.secret, "cred-nopolicy", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(
        stub.sealed.lock().unwrap().is_empty(),
        "nothing drained yet"
    );
    vultrino::server::flush_refusals_on_shutdown(&f.storage, f.av(), Duration::from_secs(5)).await;
    let sealed = stub.sealed.lock().unwrap().clone();
    assert_eq!(sealed.len(), 2, "{sealed:#?}");
    let total: u64 = sealed.iter().map(|r| r["attempts"].as_u64().unwrap()).sum();
    assert_eq!(total, 4, "the counts stay exact: {sealed:#?}");
    assert_eq!(f.av().refusal_counters().unsealed, 0);
}

/// With averin unreachable at shutdown, what could not be sealed is a counted refusal gap in the
/// outbox, never silence.
#[tokio::test]
async fn refusal_gap_shutdown_flush_with_averin_down_records_refusal_gaps() {
    let f = fx(Opts {
        averin_url: Some(DOWN.to_string()),
        ..Opts::default()
    })
    .await;
    for _ in 0..4 {
        f.execute(&f.secret, "cred-nopolicy", None).await;
    }
    vultrino::server::flush_refusals_on_shutdown(&f.storage, f.av(), Duration::from_secs(5)).await;
    let gaps = refusal_gaps(&f).await;
    assert_eq!(gaps.len(), 2, "{gaps:#?}");
    for g in &gaps {
        assert_eq!(g["kind"], "refusal", "{g}");
        assert_eq!(g["outcome"], "refused_not_sealed", "{g}");
        assert_eq!(g["agent_id"], AGENT, "{g}");
    }
    assert_eq!(f.av().refusal_counters().unsealed, 2);
}

#[tokio::test]
async fn refusal_gap_an_overloaded_averin_is_retried_with_the_same_key_then_a_gap() {
    let stub = start_stub(OVERLOADED).await;
    let f = fx(Opts {
        averin_url: Some(stub.url.clone()),
        ..Opts::default()
    })
    .await;
    f.execute(&f.secret, "cred-nopolicy", None).await;
    for _ in 0..3 {
        f.av().drain_refusals_once().await;
    }
    let attempts = stub.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 3, "three ticks, three tries");
    let keys: std::collections::BTreeSet<&str> = attempts
        .iter()
        .map(|a| a["idempotency_key"].as_str().unwrap())
        .collect();
    assert_eq!(keys.len(), 1, "a retry replays the same idempotency key");
    assert_eq!(refusal_gaps(&f).await.len(), 1);
    // The record was given up on: no further attempts.
    f.av().drain_refusals_once().await;
    assert_eq!(stub.attempts.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn refusal_gap_a_rejecting_averin_is_a_gap_at_once() {
    let stub = start_stub(REJECT).await;
    let f = fx(Opts {
        averin_url: Some(stub.url.clone()),
        ..Opts::default()
    })
    .await;
    f.execute(&f.secret, "cred-nopolicy", None).await;
    f.av().drain_refusals_once().await;
    assert_eq!(
        stub.attempts.lock().unwrap().len(),
        1,
        "a 4xx is not retried"
    );
    let gaps = refusal_gaps(&f).await;
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["reason"], "refusal_seal_failed");
}

// ===========================================================================
// refusal-no-secret-or-payload
// ===========================================================================

#[tokio::test]
async fn refusal_no_secret_or_payload_reaches_the_record() {
    let (f, stub) = averin_fx(|o| o.token_scope = "cred-ok").await;
    // The canary is in the URL, the body and the bearer (the token secret itself).
    f.execute(&f.secret, "cred-other", None).await;
    // And in an agent-chosen action name shaped like the bearer.
    let bad_action = format!("do.{}", f.secret);
    f.execute(&f.secret, "cred-other", Some(&bad_action)).await;
    let key = f.admin_key().await;
    f.mcp(&key, &format!("tool_{key}"), json!({})).await;
    let sealed = f.sealed(&stub).await;
    assert!(!sealed.is_empty());
    let text = serde_json::to_string(&sealed).unwrap();
    for needle in [
        CANARY_URL,
        "CANARY-URL",
        CANARY_BODY,
        f.secret.as_str(),
        key.as_str(),
        "sk-vault-only",
        // vultrino's free-text reasons embed credential, tenant and policy names.
        "is not scoped",
        "Denied by policy",
        "Access denied",
        "no_policy",
    ] {
        assert!(
            !text.contains(needle),
            "{needle:?} reached a refusal record: {text}"
        );
    }
    assert!(
        sealed.iter().any(|r| r["action"] == "invalid_name"),
        "a bearer-shaped name becomes invalid_name: {text}"
    );
}

// ===========================================================================
// not-a-refusal: negative controls.
// ===========================================================================

#[tokio::test]
async fn not_a_refusal_an_observe_mode_downgrade_runs_and_notes_nothing() {
    let (f, stub) = averin_fx(|o| o.token_tenant = Some("acme-obs")).await;
    // `cred-obs` has a deny-all policy; the token's tenant is observe-only, so the action runs.
    let (status, _) = f.execute(&f.secret, "cred-obs", None).await;
    assert_eq!(status, StatusCode::OK, "observe mode lets it run");
    assert_eq!(f.upstream.load(Ordering::SeqCst), 1);
    assert!(f.sealed(&stub).await.is_empty());
    assert_eq!(f.av().refusal_counters().noted, 0);
}

#[tokio::test]
async fn not_a_refusal_a_prompt_routed_to_approval_notes_nothing() {
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| c.approval.enabled = true));
    })
    .await;
    // A declared-reversible action opens an ordinary approval (an undeclared one is human-floor and,
    // with no govder to confirm a recipe, is refused: that is a refusal, covered above).
    f.storage
        .store_capability(&Capability {
            id: "cap-approve".to_string(),
            tool_name: "approve_http".to_string(),
            description: "reversible http".to_string(),
            action: "http.request".to_string(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: "cred-approve".to_string(),
            input_schema: json!({"type": "object"}),
            reversibility: "reversible".to_string(),
            llm: None,
            approval_preview: None,
        })
        .await
        .unwrap();
    let (status, body) = f.execute(&f.secret, "cred-approve", None).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "routed to a human, not refused: {body}"
    );
    assert!(f.sealed(&stub).await.is_empty());
    assert_eq!(f.av().refusal_counters().noted, 0);
}

#[tokio::test]
async fn not_a_refusal_tools_list_and_unauthenticated_attempts_note_nothing() {
    let (f, stub) = averin_fx(|_| {}).await;
    // tools/list is filtering, not a refusal.
    let auth_manager = Arc::new(tokio::sync::RwLock::new(AuthManager::from_data(
        f.storage.list_roles().await.unwrap(),
        f.storage.list_api_keys().await.unwrap(),
    )));
    let mut mcp = vultrino::mcp::McpServer::new(f.srv.clone(), auth_manager);
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {"api_key": f.secret}});
    mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    // A secret that resolves to no stored principal is unauthenticated: there is no agent.
    let (status, _) = f.execute("vut_does_not_exist_0000", "cred-ok", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = f.execute("vk_bogus_bogus_bogus", "cred-ok", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let v = f
        .mcp("vut_does_not_exist_0000", "http_request", json!({}))
        .await;
    assert!(
        v.get("error").is_some() || v["result"]["isError"] == true,
        "{v}"
    );
    let (status, _) = f
        .llm("vut_does_not_exist_0000", json!({"model": "x"}))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(f.sealed(&stub).await.is_empty());
    assert_eq!(f.av().refusal_counters().noted, 0);
}

#[tokio::test]
async fn not_a_refusal_a_local_caller_with_no_principal_notes_nothing() {
    let (f, stub) = averin_fx(|_| {}).await;
    f.srv
        .execute_gated(token_request("http.request"), ExecAuth::default())
        .await
        .ok();
    f.srv
        .execute_gated(
            ExecuteRequest {
                credential: "cred-nopolicy".to_string(),
                action: "http.request".to_string(),
                params: json!({"method": "GET", "url": CANARY_URL}),
            },
            ExecAuth::default(),
        )
        .await
        .unwrap_err();
    assert!(f.sealed(&stub).await.is_empty());
}

#[tokio::test]
async fn refusal_off_by_config_counts_but_never_posts() {
    let (f, stub) = averin_fx(|o| {
        o.edit = Some(Box::new(|c| c.averin.seal_refusals = false));
    })
    .await;
    f.execute(&f.secret, "cred-nopolicy", None).await;
    assert!(f.sealed(&stub).await.is_empty());
    assert!(stub.attempts.lock().unwrap().is_empty());
    assert_eq!(f.av().refusal_counters().noted, 1);
}

// ===========================================================================
// refusal-census: no refusal site skips the seam.
// ===========================================================================

/// Every `VultrinoError::PolicyDenied(`, `PolicyUnavailable(` and `LlmChannelOnly(` the gate and the
/// dispatch tails construct must pass through `refuse(` / `RunError::refused*(` (so it is noted), or
/// be one of the named sites that are not a refusal of an agent. A new refusal site that forgets the
/// seam fails here.
#[test]
fn refusal_census_every_gate_site_goes_through_the_seam() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server/mod.rs")).unwrap();
    // The production code only: tests start at the first `#[cfg(test)]` module.
    let prod = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    assert!(
        prod.lines().count() > 5000,
        "the census must cover the whole gate, not a truncated file"
    );
    let mut sites = 0usize;
    let mut missing = Vec::new();
    for needle in [
        "VultrinoError::PolicyDenied(",
        "VultrinoError::PolicyUnavailable(",
        "VultrinoError::LlmChannelOnly(",
    ] {
        for (at, _) in prod.match_indices(needle) {
            sites += 1;
            let before = &prod[at.saturating_sub(260)..at];
            // The construction is an argument of the seam when `refuse(` / `refused(` /
            // `refused_retryable(` opens within the few lines before it, with no statement end
            // between them.
            let seam = ["refuse(", "refused(", "refused_retryable("]
                .iter()
                .filter_map(|s| before.rfind(s).map(|i| (i, s)))
                .max_by_key(|(i, _)| *i);
            let ok = seam.is_some_and(|(i, _)| !before[i..].contains(';'));
            if !ok {
                let line = prod[..at].matches('\n').count() + 1;
                missing.push(format!("src/server/mod.rs:{line}: {needle}"));
            }
        }
    }
    assert!(
        sites >= 40,
        "the census found only {sites} sites: the scan is broken"
    );
    // Sites that are deliberately not a gateway refusal of an agent:
    //  * fetch_gate_rule_for_action builds fail-closed errors that its callers (the admission gate
    //    and the approval resume) note as `decision_unavailable`;
    //  * the committed D8 outcome-evidence error is raised after the action ran.
    let allowed = [
        // `direct_admission` returns the error; its one caller notes it as decision_unavailable.
        "the execution permit kernel refused the effective policy decision",
        "fetch_gate_rule_for_action",
        "action completed but D8 outcome evidence failed",
        "the canonical action is shared by configured business labels",
        "could not confirm the approval requirement with the policy engine",
    ];
    let unexplained: Vec<&String> = missing
        .iter()
        .filter(|m| {
            let line: usize = m.split(':').nth(1).unwrap().parse().unwrap();
            let text: String = src
                .lines()
                .skip(line.saturating_sub(1))
                .take(6)
                .collect::<Vec<_>>()
                .join(" ");
            let in_fetch = src
                .lines()
                .take(line)
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .find(|l| l.contains("    async fn ") || l.contains("    fn "))
                .is_some_and(|l| l.contains("fetch_gate_rule_for_action"));
            !(in_fetch || allowed.iter().any(|a| text.contains(a)))
        })
        .collect();
    assert!(
        unexplained.is_empty(),
        "refusal sites that skip the seam (add `refuse(`/`RunError::refused(` or justify): {unexplained:#?}"
    );
}

/// The entry points name themselves: no entry point may call the unnamed `execute_gated` and thereby
/// seal its refusals as `execute`.
#[test]
fn refusal_census_entry_points_name_their_entry() {
    for (file, must_have) in [
        (
            "src/mcp/server.rs",
            "execute_gated_via(crate::refusal::RefusalEntry::Mcp",
        ),
        (
            "src/web/llm_proxy.rs",
            "execute_gated_streaming_llm_channel",
        ),
        ("src/web/llm_proxy.rs", "execute_gated_llm_channel"),
    ] {
        let src =
            std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert!(src.contains(must_have), "{file} must use {must_have}");
    }
    let mcp =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mcp/server.rs")).unwrap();
    assert!(
        !mcp.contains(".execute_gated(request"),
        "an MCP call must name its entry (execute_gated_via(Mcp, ..))"
    );
}
