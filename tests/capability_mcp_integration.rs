//! Connector M1 — capability (named MCP tool) integration tests.
//!
//! Verifies the acceptance criteria from feir-os
//! `docs/connectors/ARCHITECTURE.md`:
//! - a capability registered + a principal whose policy ALLOWS its action sees
//!   the named tool in `tools/list` and a `tools/call` runs it through the SAME
//!   enforced `/execute` path (default-deny policy + egress scrub + token consume);
//! - a principal NOT allowed does NOT see the tool / is denied on `tools/call`
//!   (no bypass);
//! - the generic existing tools still work;
//! - no secret leaks in tool output (egress scrub applies on the execute path).

use secrecy::SecretString;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;

use vultrino::auth::{AuthManager, NewUseToken, UseToken};
use vultrino::capability::{Capability, CapabilityTarget};
use vultrino::config::{Config, EnforcementConfig, EnforcementDefault};
use vultrino::mcp::McpServer;
use vultrino::policy::{Policy, PolicyAction, PolicyCondition};
use vultrino::router::CredentialResolver;
use vultrino::server::VultrinoServer;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, Secret};

/// Build a fresh encrypted vault on disk and return the shared storage handle.
async fn new_storage() -> (tempfile::TempDir, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    (dir, storage)
}

/// A default-deny config carrying the given static policies.
fn config_with_policies(policies: Vec<Policy>) -> Config {
    Config {
        enforcement: EnforcementConfig {
            default_action: EnforcementDefault::Deny,
            require_declared_capabilities: false,
        },
        policies,
        ..Config::default()
    }
}

/// Register the standard "send_email"-style HTTP capability against a credential.
async fn register_capability(
    storage: &Arc<dyn StorageBackend>,
    credential_ref: &str,
) -> Capability {
    let cap = Capability {
        id: "cap-send-email".to_string(),
        tool_name: "send_email".to_string(),
        description: "Send an email via the provider".to_string(),
        action: "http.request".to_string(),
        plugin: Some("http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("https://api.sendgrid.example/v3/mail/send".to_string()),
            methods: vec!["POST".to_string()],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: credential_ref.to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "body": { "type": "object" } },
            "required": ["body"]
        }),
        reversibility: "reversible".to_string(),
        llm: None,
        approval_preview: None,
    };
    storage.store_capability(&cap).await.unwrap();
    cap
}

/// Store an api-key credential whose secret is long enough to be egress-scrubbed.
async fn store_credential(storage: &Arc<dyn StorageBackend>, alias: &str) {
    let cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("SG.super-secret-sendgrid-key-1234567890"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
}

/// Mint a use token scoped to the credential + action, persist it, return the
/// plaintext (`vut_…`) the agent presents.
async fn mint_token(
    storage: &Arc<dyn StorageBackend>,
    credential_scope: &str,
    action_scope: Option<&str>,
) -> String {
    let (full, token) = UseToken::create(NewUseToken {
        name: "agent".to_string(),
        credential_scope: credential_scope.to_string(),
        action_scope: action_scope.map(str::to_string),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();
    full
}

/// Build an `McpServer` wired to a server with the given config + storage, with
/// plugins loaded and stored policies merged into the engine.
async fn build_mcp(config: Config, storage: Arc<dyn StorageBackend>) -> McpServer {
    let auth_manager = Arc::new(RwLock::new(AuthManager::from_data(
        storage.list_roles().await.unwrap(),
        storage.list_api_keys().await.unwrap(),
    )));
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage, resolver);
    server.load_plugins().await.unwrap();
    server.reload_policies().await.unwrap();
    McpServer::new(Arc::new(server), auth_manager)
}

fn tools_in(response: &serde_json::Value) -> Vec<String> {
    response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

// ---- An allow policy for the credential so the principal is permitted. ----
fn allow_policy(credential_pattern: &str) -> Policy {
    Policy::allow_all("allow-cap", credential_pattern).with_rule(
        PolicyCondition::UrlMatch("https://*".to_string()),
        PolicyAction::Allow,
    )
}

#[tokio::test]
async fn allowed_principal_sees_capability_in_tools_list() {
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    register_capability(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request")).await;

    // Config allows the credential, engine is default-deny otherwise.
    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;

    // tools/list WITH the principal's token → the named capability appears.
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "api_key": token }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    let names = tools_in(&value);

    assert!(
        names.contains(&"send_email".to_string()),
        "allowed principal must see the named tool: {names:?}"
    );
    // Connector model: a scoped use-token (vut_) agent sees ONLY its granted named
    // capabilities + the control tool — NOT vultrino's generic built-in tools (the
    // generic surface is for a direct admin/operator vk_ key). The built-ins remain
    // default-deny enforced regardless; this is about not OFFERING them to an agent.
    assert!(
        !names.contains(&"http_request".to_string()),
        "a use-token agent must NOT see generic http_request: {names:?}"
    );
    assert!(
        !names.contains(&"list_credentials".to_string()),
        "a use-token agent must NOT see generic list_credentials"
    );
    assert!(
        names.contains(&"check_approval".to_string()),
        "the control tool stays available to an agent"
    );

    // The capability tool exposes its schema with the injected api_key field.
    let send_email = value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "send_email")
        .unwrap();
    assert!(send_email["inputSchema"]["properties"]["api_key"].is_object());
    assert!(send_email["inputSchema"]["properties"]["body"].is_object());
}

#[tokio::test]
async fn denied_principal_does_not_see_capability() {
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    register_capability(&storage, "cred-sendgrid").await;
    // Token scoped to a DIFFERENT credential glob → can't access cred-sendgrid.
    let token = mint_token(&storage, "other-*", Some("http.request")).await;

    // Even with an allow policy for the credential, the token's own scope blocks it.
    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "api_key": token }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    let names = tools_in(&value);
    assert!(
        !names.contains(&"send_email".to_string()),
        "a principal not scoped to the credential must NOT see the tool: {names:?}"
    );
    // Connector model: a use-token sees no generic built-ins either — only its
    // granted capabilities (none here, since it's scoped to a different credential)
    // plus the control tool.
    assert!(
        !names.contains(&"http_request".to_string()),
        "a use-token agent must NOT see generic http_request"
    );
    assert!(names.contains(&"check_approval".to_string()));
}

#[tokio::test]
async fn no_token_in_tools_list_means_no_capability_tools() {
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    register_capability(&storage, "cred-sendgrid").await;

    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;
    // tools/list with NO principal → capability tools require a principal to gate.
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    let names = tools_in(&value);
    assert!(!names.contains(&"send_email".to_string()));
    // The generic tools are unconditionally listed.
    assert!(names.contains(&"http_request".to_string()));
}

#[tokio::test]
async fn denied_principal_tools_call_is_rejected_not_bypassed() {
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    register_capability(&storage, "cred-sendgrid").await;
    // Token scoped to a different credential → execute_gated must deny.
    let token = mint_token(&storage, "other-*", Some("http.request")).await;

    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": { "api_key": token, "body": { "to": "a@b.com" } }
        }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    // A denied capability call surfaces as an MCP tool error, never a result.
    assert_eq!(value["result"]["isError"], serde_json::json!(true));
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("denied") || text.contains("not scoped") || text.contains("Access denied"),
        "expected a denial message, got: {text}"
    );
}

#[tokio::test]
async fn no_policy_default_deny_blocks_capability_call() {
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    register_capability(&storage, "cred-sendgrid").await;
    let token = mint_token(&storage, "cred-sendgrid", Some("http.request")).await;

    // NO allow policy → default-deny engine blocks the credential.
    let mut mcp = build_mcp(config_with_policies(vec![]), storage).await;

    // tools/list: the capability is hidden because policy would deny it.
    let list = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": { "api_key": token }
    });
    let resp = mcp.handle_jsonrpc(&list.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    assert!(
        !tools_in(&value).contains(&"send_email".to_string()),
        "default-deny must hide the tool"
    );

    // tools/call: even a forged call is denied (no bypass).
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": { "api_key": token, "body": { "to": "a@b.com" } }
        }
    });
    let resp = mcp.handle_jsonrpc(&call.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    assert_eq!(value["result"]["isError"], serde_json::json!(true));
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("denied") || text.contains("no_policy"),
        "got: {text}"
    );
}

#[tokio::test]
async fn allowed_tools_call_reaches_execute_past_policy() {
    // Allowed principal: the capability call must get PAST policy into the plugin.
    // We point the capability at a private URL so the http plugin's SSRF guard
    // rejects it deterministically and offline — an SSRF error proves the request
    // reached the plugin's validate/execute (i.e. it ran through execute_gated and
    // was NOT a policy denial / not a bypass).
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-internal").await;
    // A capability whose target is a private/internal URL.
    let cap = Capability {
        id: "cap-internal".to_string(),
        tool_name: "ping_internal".to_string(),
        description: "ping an internal service".to_string(),
        action: "http.request".to_string(),
        plugin: Some("http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("http://127.0.0.1/health".to_string()),
            methods: vec!["GET".to_string()],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: "cred-internal".to_string(),
        input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        reversibility: "reversible".to_string(),
        llm: None,
        approval_preview: None,
    };
    storage.store_capability(&cap).await.unwrap();
    let token = mint_token(&storage, "cred-*", Some("http.request")).await;

    // Allow policy admits the credential for any URL/method.
    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "ping_internal",
            "arguments": { "api_key": token }
        }
    });
    let resp = mcp.handle_jsonrpc(&call.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    // It is an error, but a PLUGIN/SSRF error (got past policy into execute), not a
    // policy denial — proving the enforced execute path ran.
    assert_eq!(value["result"]["isError"], serde_json::json!(true));
    let text = value["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        text.contains("private") || text.contains("internal") || text.contains("ssrf"),
        "expected the call to reach the http plugin (SSRF/private rejection), got: {text}"
    );
    assert!(
        !text.contains("no_policy") && !text.contains("default action"),
        "the allowed call must not be a policy denial, got: {text}"
    );
}

#[tokio::test]
async fn generic_tools_still_work() {
    // The generic list_credentials tool still functions with an API key.
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-sendgrid").await;
    // An admin API key with full access.
    let manager = AuthManager::new();
    let (full_key, api_key) = manager
        .create_api_key("admin-key", vultrino::auth::ROLE_ADMIN, None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let mut mcp = build_mcp(config_with_policies(vec![]), storage).await;
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {
            "name": "list_credentials",
            "arguments": { "api_key": full_key }
        }
    });
    let resp = mcp.handle_jsonrpc(&req.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    // No error; the listing mentions our credential.
    assert_ne!(value["result"]["isError"], serde_json::json!(true));
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("cred-sendgrid"),
        "generic list_credentials should still work: {text}"
    );
}

#[tokio::test]
async fn capability_tool_output_does_not_leak_secret() {
    // The capability execute path is egress-scrubbed: even if a (hypothetical)
    // response reflected the credential secret, the scrub runs inside run_action
    // before the body reaches the agent. Here we assert the secret never appears
    // in the tool output of a (denied/plugin-error) call — the secret is never
    // surfaced regardless of outcome.
    let (_dir, storage) = new_storage().await;
    store_credential(&storage, "cred-internal").await;
    let cap = Capability {
        id: "cap-internal".to_string(),
        tool_name: "ping_internal".to_string(),
        description: "ping".to_string(),
        action: "http.request".to_string(),
        plugin: Some("http".to_string()),
        target: CapabilityTarget {
            url_glob: Some("http://127.0.0.1/health".to_string()),
            methods: vec!["GET".to_string()],
            plugin_params: serde_json::Map::new(),
        },
        credential_ref: "cred-internal".to_string(),
        input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        reversibility: "reversible".to_string(),
        llm: None,
        approval_preview: None,
    };
    storage.store_capability(&cap).await.unwrap();
    let token = mint_token(&storage, "cred-*", Some("http.request")).await;

    let mut mcp = build_mcp(config_with_policies(vec![allow_policy("cred-*")]), storage).await;
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": { "name": "ping_internal", "arguments": { "api_key": token } }
    });
    let resp = mcp.handle_jsonrpc(&call.to_string()).await.unwrap();
    let value = serde_json::to_value(&resp).unwrap();
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        !text.contains("super-secret-sendgrid-key") && !text.contains("SG.super-secret"),
        "the credential secret must never appear in tool output: {text}"
    );
}
