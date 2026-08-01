//! Plan 103 §10g FIX 1 — the AGENT-FACING money path, driven through the real
//! MCP `tools/call` handler.
//!
//! Every `internal_http` proof that existed before this file went in through
//! `POST /api/v1/execute` (or straight into `execute_gated`) with a hand-written
//! `method`. That is the API an OPERATOR scripts. The API an AGENT is handed is
//! `tools/list` + `tools/call`, and that composition
//! (`build_action_params` -> `validate_params` -> plugin) had never been driven
//! for this plugin. It was broken: `InternalHttpParams::method` is required with
//! no serde default under `deny_unknown_fields`, the non-`http` branch of
//! `build_action_params` passed the model's raw args through untouched, and no
//! shipped capability declares `method` anywhere the agent could see it. An L3
//! sender therefore saw `issue_refund` in `tools/list`, called it with exactly
//! the schema it was given, and was refused BEFORE the use token was consumed —
//! no approval, no ledger row, no meter event.
//!
//! So these tests are deliberately written the way an agent behaves:
//! the arguments are BUILT FROM THE ADVERTISED SCHEMA (`tools/list`'s
//! `inputSchema.required`), never from a hand-picked param set. A schema that
//! cannot be invoked fails here even if the plugin's own unit tests are green.
//!
//! The capability registered below carries the **verbatim** input schema of
//! `cap-payments-refund` from
//! `feir-os/packs/fintech-payments-ops/catalog/capabilities.yaml` (the YAML
//! translated to JSON, which is exactly what govder's loader posts to
//! `/api/v1/capabilities`).

use std::sync::Arc;
use std::sync::Mutex;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use secrecy::SecretString;
use tempfile::tempdir;
use tokio::sync::RwLock;

use vultrino::auth::{AuthManager, NewUseToken, UseToken};
use vultrino::capability::{Capability, CapabilityTarget};
use vultrino::config::Config;
use vultrino::mcp::McpServer;
use vultrino::plugins::META_DESTINATION;
use vultrino::router::CredentialResolver;
use vultrino::server::VultrinoServer;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, Secret};

/// The sandbox API key that exists ONLY in the vault.
const SANDBOX_KEY: &str = "sbx-vault-only-KEY-4a3b2c1d0e9f8a7b6c5d";

// ---------------------------------------------------------------------------
// A loopback "payments sandbox" that records what it received.
// ---------------------------------------------------------------------------

/// One recorded request: method, path+query, authorization header, body.
type Hit = (String, String, Option<String>, String);

#[derive(Default)]
struct Recorder {
    hits: Mutex<Vec<Hit>>,
}

async fn record(
    State(rec): State<Arc<Recorder>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    rec.hits
        .lock()
        .unwrap()
        .push((method.to_string(), uri.to_string(), auth, body));
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"refund_id":"rf_1","status":"posted"}"#,
    )
}

async fn start_sandbox() -> (u16, Arc<Recorder>) {
    let rec = Arc::new(Recorder::default());
    let app = Router::new()
        .route("/v1/{*rest}", any(record))
        .with_state(rec.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, rec)
}

// ---------------------------------------------------------------------------
// The operator's shipped configuration.
// ---------------------------------------------------------------------------

/// The config `deploy/vultrino.toml` ships for the payments sandbox: the V8
/// action-label row, one pinned destination, and a govder-shaped allow policy
/// (`ActionMatch AND UrlMatch AND MethodMatch`).
fn operator_config(dest_port: u16) -> Config {
    let toml = format!(
        r#"
[[action_labels]]
label = "money.refund"
action = "internal_http.request"

[[action_labels]]
label = "data.read"
action = "internal_http.request"

[[internal_destinations]]
name = "finsandbox"
base_url = "http://127.0.0.1:{dest_port}"
allow_methods = ["GET", "POST"]
allow_paths = ["/v1/refunds", "/v1/ledger"]

[[policies]]
name = "money-refund"
credential_pattern = "finsandbox-*"
default_action = "deny"

[[policies.rules]]
action = "allow"
condition = {{ and = [
  {{ action_match = "money.refund" }},
  {{ url_match = "/v1/refunds" }},
  {{ method_match = ["POST"] }},
] }}

[[policies.rules]]
action = "allow"
condition = {{ and = [
  {{ action_match = "data.read" }},
  {{ url_match = "/v1/ledger*" }},
  {{ method_match = ["GET"] }},
] }}
"#
    );
    Config::parse(&toml).expect("operator config parses")
}

/// VERBATIM `cap-payments-refund.mcp_tool.input_schema` from
/// `feir-os/packs/fintech-payments-ops/catalog/capabilities.yaml`.
fn pack_refund_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "url": { "type": "string", "description": "Relative path on the pinned destination." },
            "body": {
                "type": "object",
                "properties": {
                    "transaction_id": { "type": "string" },
                    "amount": { "type": "string" },
                    "currency": { "type": "string" },
                    "reason": { "type": "string" }
                },
                "required": ["transaction_id", "amount", "currency", "reason"]
            }
        },
        "required": ["url", "body"]
    })
}

/// VERBATIM `cap-payments-ledger-read.mcp_tool.input_schema` from the same file.
fn pack_ledger_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "url": { "type": "string", "description": "Relative path on the pinned destination." }
        },
        "required": ["url"]
    })
}

/// One pack capability, as its YAML declares it.
struct PackCap {
    id: &'static str,
    tool_name: &'static str,
    action: &'static str,
    url_glob: &'static str,
    methods: &'static [&'static str],
    credential_ref: &'static str,
    reversibility: &'static str,
    input_schema: serde_json::Value,
    plugin_params: serde_json::Map<String, serde_json::Value>,
}

/// The shipped `cap-payments-refund`, verbatim.
fn refund_cap() -> PackCap {
    PackCap {
        id: "cap-payments-refund",
        tool_name: "issue_refund",
        action: "money.refund",
        url_glob: "/v1/refunds",
        methods: &["POST"],
        credential_ref: "finsandbox-refund",
        reversibility: "irreversible",
        input_schema: pack_refund_input_schema(),
        plugin_params: serde_json::Map::new(),
    }
}

/// The shipped `cap-payments-ledger-read`, verbatim.
fn ledger_cap() -> PackCap {
    PackCap {
        id: "cap-payments-ledger-read",
        tool_name: "ledger_read",
        action: "data.read",
        url_glob: "/v1/ledger*",
        methods: &["GET"],
        credential_ref: "finsandbox-read",
        reversibility: "reversible",
        input_schema: pack_ledger_input_schema(),
        plugin_params: serde_json::Map::new(),
    }
}

/// Register the capability exactly as govder's `ToCapUpsert` would: the pack's
/// action, plugin, target (url_glob + methods) and input schema, and NOTHING
/// hand-added on the agent's behalf.
async fn register_pack_capability(storage: &Arc<dyn StorageBackend>, c: PackCap) -> Capability {
    let cap = Capability {
        id: c.id.to_string(),
        tool_name: c.tool_name.to_string(),
        description: "A shipped pack capability".to_string(),
        action: c.action.to_string(),
        plugin: Some("internal_http".to_string()),
        target: CapabilityTarget {
            url_glob: Some(c.url_glob.to_string()),
            methods: c.methods.iter().map(|m| m.to_string()).collect(),
            plugin_params: c.plugin_params,
        },
        credential_ref: c.credential_ref.to_string(),
        input_schema: c.input_schema,
        reversibility: c.reversibility.to_string(),
        llm: None,
        approval_preview: None,
    };
    cap.validate().expect("pack capability validates");
    storage.store_capability(&cap).await.unwrap();
    cap
}

/// A test policy authority that definitively confirms that no per-action recipe
/// is stored. This licenses the ordinary one-human approval path; an absent or
/// unreachable authority would correctly refuse an irreversible capability.
async fn start_mock_govder_confirming_no_recipe() -> vultrino::govder::GovderConfig {
    async fn handler() -> impl IntoResponse {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "has_rule": false })),
        )
    }

    let app = Router::new().route("/v1/oversight/gates/rule", axum::routing::get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    vultrino::govder::GovderConfig {
        base_url: format!("http://{addr}"),
        assertion_secret: "test-govder-assertion-secret".to_string(),
        assertion_ttl: std::time::Duration::from_secs(90),
        http_timeout: std::time::Duration::from_secs(5),
    }
}

async fn build_stack(
    mut config: Config,
) -> (Arc<dyn StorageBackend>, Arc<VultrinoServer>, McpServer) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the scratch vault alive for the test process
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("test-password"))
            .await
            .unwrap(),
    );
    let auth_manager = Arc::new(RwLock::new(AuthManager::from_data(
        storage.list_roles().await.unwrap(),
        storage.list_api_keys().await.unwrap(),
    )));
    // The shipped refund is irreversible. Give the fixture a real approval
    // subsystem and a reachable recipe authority so its happy path proves an
    // approved resume, never an inline dispatch or an unwired-policy fallback.
    config.approval.enabled = true;
    config.govder = Some(start_mock_govder_confirming_no_recipe().await);
    let resolver = CredentialResolver::new(storage.clone());
    let server = Arc::new(VultrinoServer::new(config, storage.clone(), resolver));
    server.load_plugins().await.unwrap();
    server.reload_policies().await.unwrap();
    let mcp = McpServer::new(server.clone(), auth_manager);
    (storage, server, mcp)
}

/// Seed the sandbox credential (with its operator-pinned destination metadata)
/// and mint the agent's use token, returning the plaintext `vut_…`.
async fn seed(
    storage: &Arc<dyn StorageBackend>,
    alias: &str,
    destination: &str,
    action_scope: &str,
) -> String {
    let mut cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new(SANDBOX_KEY),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    cred.metadata
        .insert(META_DESTINATION.to_string(), destination.to_string());
    storage.store(&cred).await.unwrap();

    let (full, mut token) = UseToken::create(NewUseToken {
        name: format!("{alias}-token"),
        credential_scope: alias.to_string(),
        action_scope: Some(action_scope.to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.tenant = Some("acme".to_string());
    token.agent_label = Some(format!("{alias}-agent"));
    storage.store_use_token(&token).await.unwrap();
    full
}

// ---------------------------------------------------------------------------
// Agent-shaped helpers: everything the agent sends comes from tools/list.
// ---------------------------------------------------------------------------

/// The `inputSchema` the agent is HANDED for a tool, as `tools/list` renders it.
async fn advertised_schema(mcp: &mut McpServer, token: &str, tool: &str) -> serde_json::Value {
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "api_key": token }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    let tools = value["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let found = tools
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("tool {tool} not offered to this agent: {tools:#?}"));
    found["inputSchema"].clone()
}

/// Fill EVERY required property of the advertised schema from `values`, and
/// nothing else. This is the whole point: a model that follows the schema it was
/// given sends exactly this. A required property with no value here is a test
/// bug; an extra key is not sent, because the schema does not mention one.
fn arguments_from_schema(
    schema: &serde_json::Value,
    api_key: &str,
    values: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    let required: Vec<String> = schema["required"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let mut args = serde_json::Map::new();
    for name in &required {
        if name == "api_key" {
            continue;
        }
        let v = values
            .iter()
            .find(|(k, _)| k == name)
            .unwrap_or_else(|| panic!("schema requires {name:?} but the test supplies no value"))
            .1
            .clone();
        args.insert(name.clone(), v);
    }
    args.insert("api_key".to_string(), serde_json::json!(api_key));
    serde_json::Value::Object(args)
}

/// Drive the real MCP `tools/call`. Returns Ok(text) on success, Err(message) on
/// a JSON-RPC error OR an `isError` tool result — an agent cannot tell the two
/// apart, and neither should this test.
async fn tools_call(
    mcp: &mut McpServer,
    tool: &str,
    arguments: serde_json::Value,
) -> Result<String, String> {
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    if let Some(err) = value.get("error") {
        return Err(err["message"].as_str().unwrap_or("").to_string());
    }
    let text = value["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if value["result"]["isError"].as_bool().unwrap_or(false) {
        return Err(text);
    }
    Ok(text)
}

fn refund_body() -> serde_json::Value {
    serde_json::json!({
        "transaction_id": "tx_1001",
        "amount": "12.50",
        "currency": "USD",
        "reason": "duplicate charge"
    })
}

/// Apply one valid human decision to the only pending request and drive the
/// trusted local resume path. The destination must remain untouched until this
/// helper is called.
async fn approve_only_pending_and_resume(
    storage: &Arc<dyn StorageBackend>,
    server: &Arc<VultrinoServer>,
) -> vultrino::approval::ApprovalRequest {
    let mut approvals = storage.list_approvals().await.unwrap();
    assert_eq!(
        approvals.len(),
        1,
        "the MCP call must open exactly one approval"
    );
    let mut approval = approvals.pop().unwrap();
    assert!(
        approval.trusted_irreversible,
        "the stored catalog classification must be stamped on the gate"
    );
    assert_eq!(
        approval.required_approvals, 1,
        "the mock policy authority explicitly confirmed the ordinary one-human path"
    );
    approval
        .approve(vultrino::approval::Decision::new("admin panel", "dana"))
        .unwrap();
    storage.update_approval(&approval).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .expect("an approved request must resume");
    assert!(
        resumed.executed,
        "the approved action must reach a terminal execution result: {:?}",
        resumed.result_error
    );
    resumed
}

// ===========================================================================
// (1) The money path an agent actually uses.
// ===========================================================================

/// THE REGRESSION TEST FOR §10g FIX 1. An L3 sender is offered `issue_refund`,
/// fills the schema it was handed, and receives a pending approval through
/// `tools/call`, not `/api/v1/execute`. The refund reaches the sandbox only after
/// a valid human decision and the approved-resume path injects the credential.
#[tokio::test]
async fn agent_refund_from_advertised_schema_executes_only_after_approval() {
    let (port, rec) = start_sandbox().await;
    let (storage, server, mut mcp) = build_stack(operator_config(port)).await;
    let token = seed(&storage, "finsandbox-refund", "finsandbox", "money.refund").await;
    register_pack_capability(&storage, refund_cap()).await;

    let schema = advertised_schema(&mut mcp, &token, "issue_refund").await;
    let args = arguments_from_schema(
        &schema,
        &token,
        &[
            ("url", serde_json::json!("/v1/refunds")),
            ("body", refund_body()),
        ],
    );

    let pending = tools_call(&mut mcp, "issue_refund", args)
        .await
        .expect("a refund called with the advertised schema must open its approval");
    assert!(
        pending.contains("APPROVAL REQUIRED") && pending.contains("status: pending"),
        "the agent must receive a pending-approval result: {pending}"
    );
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "the irreversible action must not dispatch before approval"
    );

    let resumed = approve_only_pending_and_resume(&storage, &server).await;
    assert!(
        resumed
            .result_body
            .as_deref()
            .unwrap_or_default()
            .contains("rf_1"),
        "the sandbox response must reach the approved resume: {:?}",
        resumed.result_body
    );

    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "exactly one sandbox request: {hits:?}");
    assert_eq!(hits[0].0, "POST", "the operator's pinned verb: {hits:?}");
    assert_eq!(hits[0].1, "/v1/refunds", "the pinned path: {hits:?}");
    assert_eq!(
        hits[0].2.as_deref(),
        Some(format!("Bearer {SANDBOX_KEY}").as_str()),
        "the vault credential is injected; the agent never held it"
    );
    assert!(
        hits[0].3.contains("tx_1001"),
        "the agent's body reaches the sandbox: {hits:?}"
    );
}

/// A read capability whose schema declares ONLY `url` (no body, no method) is
/// invokable too — the GET half of the same composition.
#[tokio::test]
async fn agent_reads_the_ledger_through_tools_call_using_only_the_advertised_schema() {
    let (port, rec) = start_sandbox().await;
    let (storage, _server, mut mcp) = build_stack(operator_config(port)).await;
    let token = seed(&storage, "finsandbox-read", "finsandbox", "data.read").await;
    register_pack_capability(&storage, ledger_cap()).await;

    let schema = advertised_schema(&mut mcp, &token, "ledger_read").await;
    let args = arguments_from_schema(
        &schema,
        &token,
        &[("url", serde_json::json!("/v1/ledger?limit=5"))],
    );

    tools_call(&mut mcp, "ledger_read", args)
        .await
        .expect("a ledger read called with the schema the agent was given must execute");

    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "exactly one sandbox request: {hits:?}");
    assert_eq!(hits[0].0, "GET", "the operator's pinned verb: {hits:?}");
    assert_eq!(hits[0].1, "/v1/ledger?limit=5", "the path: {hits:?}");
}

// ===========================================================================
// (2) The agent may not choose the verb.
// ===========================================================================

/// The fail-closed half of the fix. The verb is the OPERATOR's: a caller-supplied
/// `method` on an `internal_http` capability is refused outright — it is not
/// silently honoured (which would let a declared GET become a POST) and it is not
/// silently overwritten (which would run a money action the agent did not ask
/// for). The refusal is pre-side-effect: the sandbox is never contacted.
#[tokio::test]
async fn a_caller_supplied_method_is_refused_and_never_widens_the_verb() {
    let (port, rec) = start_sandbox().await;
    let (storage, _server, mut mcp) = build_stack(operator_config(port)).await;
    // A READ capability: GET /v1/ledger*. The classic escalation is turning it
    // into a POST.
    let token = seed(&storage, "finsandbox-read", "finsandbox", "data.read").await;
    register_pack_capability(&storage, ledger_cap()).await;

    let err = tools_call(
        &mut mcp,
        "ledger_read",
        serde_json::json!({
            "api_key": token,
            "url": "/v1/ledger",
            "method": "POST",
        }),
    )
    .await
    .expect_err("a caller-supplied method must be refused");
    assert!(
        err.contains("method"),
        "the refusal must name the offending field: {err}"
    );
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "the refusal is pre-side-effect: the sandbox must never be contacted"
    );
}

/// Even a caller-supplied method that AGREES with the pin is refused. The rule is
/// "the agent does not send the verb", not "the agent may send the right verb":
/// a schema that never mentions `method` and a request that carries one is a
/// divergence between what the agent was told and what it did, on a money path.
#[tokio::test]
async fn a_caller_supplied_method_is_refused_even_when_it_matches_the_pin() {
    let (port, rec) = start_sandbox().await;
    let (storage, _server, mut mcp) = build_stack(operator_config(port)).await;
    let token = seed(&storage, "finsandbox-refund", "finsandbox", "money.refund").await;
    register_pack_capability(&storage, refund_cap()).await;

    let err = tools_call(
        &mut mcp,
        "issue_refund",
        serde_json::json!({
            "api_key": token,
            "url": "/v1/refunds",
            "body": refund_body(),
            "method": "POST",
        }),
    )
    .await
    .expect_err("a caller-supplied method must be refused even when it matches");
    assert!(err.contains("method"), "refusal must name the field: {err}");
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "nothing may reach the sandbox"
    );
}

/// An operator-pinned `plugin_params.method` (what govder's `ToCapUpsert` now
/// writes) is honoured and wins: after approval, the capability executes with
/// the pinned verb even though the target's `methods` list is empty.
#[tokio::test]
async fn an_operator_pinned_plugin_param_method_is_what_executes() {
    let (port, rec) = start_sandbox().await;
    let (storage, server, mut mcp) = build_stack(operator_config(port)).await;
    let token = seed(&storage, "finsandbox-refund", "finsandbox", "money.refund").await;
    let mut pinned = serde_json::Map::new();
    pinned.insert("method".to_string(), serde_json::json!("POST"));
    let mut cap = refund_cap();
    // Deliberately EMPTY target.methods: the pin is the only source of the verb,
    // so this proves the pin (not the methods list) is being read.
    cap.methods = &[];
    cap.plugin_params = pinned;
    register_pack_capability(&storage, cap).await;

    let schema = advertised_schema(&mut mcp, &token, "issue_refund").await;
    let args = arguments_from_schema(
        &schema,
        &token,
        &[
            ("url", serde_json::json!("/v1/refunds")),
            ("body", refund_body()),
        ],
    );
    let pending = tools_call(&mut mcp, "issue_refund", args)
        .await
        .expect("the operator-pinned request opens its approval");
    assert!(
        pending.contains("APPROVAL REQUIRED") && pending.contains("status: pending"),
        "{pending}"
    );
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "the method pin must not bypass the critical-action gate"
    );
    approve_only_pending_and_resume(&storage, &server).await;

    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "exactly one sandbox request: {hits:?}");
    assert_eq!(hits[0].0, "POST");
}

// ===========================================================================
// (3) The un-invokable shape cannot be REGISTERED at all.
// ===========================================================================

/// The registration-time gate. An `internal_http` capability whose verb is not
/// determinable (no pin, and a `methods` list that is empty or ambiguous) is a
/// tool the agent can see and can never call. It is refused by
/// `Capability::validate`, so `POST /api/v1/capabilities` 400s at provision time
/// instead of at money time.
#[test]
fn an_internal_http_capability_with_no_determinable_verb_is_refused_at_registration() {
    let base = Capability {
        id: "cap-x".to_string(),
        tool_name: "issue_refund".to_string(),
        description: String::new(),
        action: "money.refund".to_string(),
        plugin: Some("internal_http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("/v1/refunds".to_string()),
            methods: vec![],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: "finsandbox-refund".to_string(),
        input_schema: pack_refund_input_schema(),
        reversibility: "irreversible".to_string(),
        llm: None,
        approval_preview: None,
    };

    // No methods, no pin -> the verb is undeterminable.
    let err = base.validate().expect_err("no verb must be refused");
    assert!(err.contains("method"), "{err}");

    // Two methods, no pin -> ambiguous, and an ambiguity resolved at call time is
    // an ambiguity the AGENT resolves.
    let mut ambiguous = base.clone();
    ambiguous.target.methods = vec!["GET".to_string(), "POST".to_string()];
    let err = ambiguous.validate().expect_err("two verbs must be refused");
    assert!(err.contains("method"), "{err}");

    // A pin that is not a verb at all.
    let mut bad_pin = base.clone();
    bad_pin
        .target
        .plugin_params
        .insert("method".to_string(), serde_json::json!("FETCH"));
    let err = bad_pin.validate().expect_err("a non-verb pin is refused");
    assert!(err.contains("FETCH"), "{err}");

    // A pin that contradicts the declared methods list is refused rather than
    // silently preferred: two operator statements that disagree is a config bug.
    let mut contradictory = base.clone();
    contradictory.target.methods = vec!["GET".to_string()];
    contradictory
        .target
        .plugin_params
        .insert("method".to_string(), serde_json::json!("POST"));
    let err = contradictory
        .validate()
        .expect_err("a pin contradicting target.methods is refused");
    assert!(err.contains("POST") && err.contains("GET"), "{err}");

    // Exactly one method, no pin -> fine (govder pins it, but a hand-registered
    // capability with one declared verb is unambiguous).
    let mut ok = base.clone();
    ok.target.methods = vec!["POST".to_string()];
    ok.validate().expect("one declared verb is enough");
}
