//! Plan 103 P2 — `internal_http` must ignore the deployment's proxy environment.
//!
//! reqwest honours `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` from the environment
//! by DEFAULT. With a proxy in effect, hyper connects to the PROXY host and sends
//! the vault credential there instead of to the operator-pinned destination — and
//! when the proxy is an IP literal, `internal_http`'s pinned-host DNS resolver is
//! not even consulted (hyper-util skips a custom resolver for literals,
//! `connect/http.rs:541`), so nothing else catches it. `.no_proxy()` on the
//! plugin's client is the guard.
//!
//! This lives in its OWN test binary because it mutates process environment: a
//! single `#[tokio::test]` in this file means no other test can observe it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::auth::{NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::plugins::META_DESTINATION;
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, ExecuteRequest, ExecutionOutcome, Secret};

const SANDBOX_KEY: &str = "sbx-vault-only-KEY-proxy-4a3b2c1d0e9f";

#[derive(Default)]
struct Seen {
    /// Every authorization header value this server received.
    auth: Mutex<Vec<String>>,
    count: AtomicUsize,
}

async fn note(State(seen): State<Arc<Seen>>, headers: HeaderMap) -> impl IntoResponse {
    seen.count.fetch_add(1, Ordering::SeqCst);
    if let Some(a) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        seen.auth.lock().unwrap().push(a.to_string());
    }
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"who":"me"}"#,
    )
}

/// A loopback server that answers ANY path (a proxy sees absolute-form targets).
async fn start_server() -> (u16, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let app = Router::new().fallback(any(note)).with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, seen)
}

#[tokio::test]
async fn the_deployment_proxy_environment_cannot_capture_an_internal_http_credential() {
    let (sandbox_port, sandbox) = start_server().await;
    let (proxy_port, proxy) = start_server().await;

    // The hostile/accidental deployment environment. Set BEFORE the server (and so
    // before the plugin's reqwest client) is built, which is when reqwest reads it.
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    std::env::set_var("HTTP_PROXY", &proxy_url);
    std::env::set_var("http_proxy", &proxy_url);
    std::env::set_var("HTTPS_PROXY", &proxy_url);
    std::env::set_var("ALL_PROXY", &proxy_url);
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    let config = Config::parse(&format!(
        r#"
[[action_labels]]
label = "money.refund"
action = "internal_http.request"

[[internal_destinations]]
name = "finsandbox"
base_url = "http://127.0.0.1:{sandbox_port}"
allow_methods = ["POST"]
allow_paths = ["/v1/refunds"]

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
"#
    ))
    .expect("config parses");

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("test-password"))
            .await
            .unwrap(),
    );
    let resolver = CredentialResolver::new(storage.clone());
    let server = Arc::new(VultrinoServer::new(config, storage.clone(), resolver));

    let mut cred = Credential::new(
        "finsandbox-refund".to_string(),
        CredentialData::ApiKey {
            key: Secret::new(SANDBOX_KEY),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    cred.metadata
        .insert(META_DESTINATION.to_string(), "finsandbox".to_string());
    storage.store(&cred).await.unwrap();
    let (_full, token) = UseToken::create(NewUseToken {
        name: "refund-token".to_string(),
        credential_scope: "finsandbox-refund".to_string(),
        action_scope: Some("money.refund".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let outcome = server
        .execute_gated(
            ExecuteRequest {
                credential: "finsandbox-refund".to_string(),
                action: "money.refund".to_string(),
                params: serde_json::json!({
                    "url": "/v1/refunds",
                    "method": "POST",
                    "body": {"transaction_id": "txn_1", "amount": "10.00"}
                }),
            },
            ExecAuth::from_use_token(token.clone()),
        )
        .await;

    let response = match outcome {
        Ok(ExecutionOutcome::Completed(r)) => r,
        other => panic!("the governed call must complete, got: {other:?}"),
    };
    assert_eq!(response.status, 200);

    let proxy_hits = proxy.count.load(Ordering::SeqCst);
    let proxy_auth = proxy.auth.lock().unwrap().clone();
    let sandbox_hits = sandbox.count.load(Ordering::SeqCst);
    eprintln!(
        "PROXY-GUARD sandbox_hits={sandbox_hits} proxy_hits={proxy_hits} proxy_auth={proxy_auth:?}"
    );

    assert_eq!(
        proxy_hits, 0,
        "the environment's proxy received {proxy_hits} request(s) — the vault credential left \
         the operator-pinned destination"
    );
    assert!(
        proxy_auth.is_empty(),
        "the environment's proxy saw credential material: {proxy_auth:?}"
    );
    assert_eq!(
        sandbox_hits, 1,
        "the governed call must reach the pinned destination itself"
    );

    // Keep the import honest.
    let _: HashMap<String, String> = HashMap::new();
}
