//! Plan 103 P0 item 5 — `internal_http` spike proofs.
//!
//! These drive the REAL enforced path (`VultrinoServer::execute_gated` → policy →
//! use-token consume → plugin) against a REAL loopback HTTP server, so every
//! claim below is end-to-end and not a unit-level assertion about a helper:
//!
//! 1. a governed capability reaches an operator-pinned loopback destination and
//!    the vault credential is injected (the agent never holds it);
//! 2. a caller-supplied absolute URL, a protocol-relative host override, a
//!    credential naming an undeclared destination, and a redirect to another host
//!    are ALL refused fail-closed (and the other host is never contacted);
//! 3. path traversal / encoded-separator / scheme smuggling in the caller path are
//!    refused, as is a path or method outside the operator allowlists;
//! 4. the existing policy `url_glob` + method dimensions still bound the call (the
//!    relative path IS what policy matches);
//! 5. the `http` plugin's SSRF guard is UNCHANGED: loopback, cloud-metadata and a
//!    ClusterIP-shaped private address are all still refused on `http.request`.

use std::collections::HashMap;
use std::net::SocketAddr;
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
        .push((method.to_string(), uri.to_string(), auth, body.clone()));
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"refund_id":"rf_1","status":"posted"}"#,
    )
}

/// Start the sandbox on an ephemeral loopback port; returns (port, recorder).
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

/// A second loopback origin that a redirect will try to send the credential to.
/// It counts every request it receives — the count MUST stay 0.
async fn start_redirect_target() -> (u16, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let app = Router::new().route(
        "/{*rest}",
        any(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                "leaked"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, hits)
}

/// A destination that 302-redirects everything to `target`.
async fn start_redirector(target: SocketAddr) -> u16 {
    let app = Router::new().route(
        "/v1/{*rest}",
        any(move || async move {
            (
                StatusCode::FOUND,
                [("location", format!("http://{}/stolen", target))],
                "",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

// ---------------------------------------------------------------------------
// Harness: real server, real vault, real use token, govder-shaped policy.
// ---------------------------------------------------------------------------

/// The config an operator would ship: one pinned destination + the V8 action
/// label row (`money.refund` → `internal_http.request`) + a govder-shaped allow
/// policy (`ActionMatch AND UrlMatch AND MethodMatch`).
fn operator_config(dest_port: u16, extra_dest: &str) -> Config {
    let toml = format!(
        r#"
[[action_labels]]
label = "money.refund"
action = "internal_http.request"

[[action_labels]]
label = "money.payout"
action = "internal_http.request"

[[internal_destinations]]
name = "finsandbox"
base_url = "http://127.0.0.1:{dest_port}"
allow_methods = ["GET", "POST"]
allow_paths = ["/v1/refunds", "/v1/payouts", "/v1/ledger", "/v1/accounts/"]
{extra_dest}

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
    );
    Config::parse(&toml).expect("operator config parses")
}

/// The SAME pinned destination, but with a deliberately PERMISSIVE policy
/// (`url_match = "*"`, every verb). This isolates the plugin: any refusal under
/// this config is the plugin's own doing, not the policy's. It is the config an
/// operator must never ship — and the point is that even then, the caller cannot
/// steer the destination.
fn permissive_config(dest_port: u16) -> Config {
    let toml = format!(
        r#"
[[action_labels]]
label = "money.refund"
action = "internal_http.request"

[[internal_destinations]]
name = "finsandbox"
base_url = "http://127.0.0.1:{dest_port}"
allow_methods = ["GET", "POST"]
allow_paths = ["/v1/refunds", "/v1/payouts", "/v1/ledger", "/v1/accounts/"]

[[policies]]
name = "permissive"
credential_pattern = "finsandbox-*"
default_action = "deny"

[[policies.rules]]
action = "allow"
condition = {{ url_match = "*" }}
"#
    );
    Config::parse(&toml).expect("permissive config parses")
}

async fn build_server(config: Config) -> (Arc<VultrinoServer>, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the scratch vault alive for the test process
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("test-password"))
            .await
            .unwrap(),
    );
    let resolver = CredentialResolver::new(storage.clone());
    let server = Arc::new(VultrinoServer::new(config, storage.clone(), resolver));
    (server, storage)
}

/// Seed the sandbox credential with its operator-pinned destination metadata plus
/// a use token scoped to the `money.refund` label.
async fn seed(
    storage: &Arc<dyn StorageBackend>,
    alias: &str,
    destination: Option<&str>,
    action_scope: &str,
) -> UseToken {
    let mut cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new(SANDBOX_KEY),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    if let Some(d) = destination {
        cred.metadata
            .insert(META_DESTINATION.to_string(), d.to_string());
    }
    storage.store(&cred).await.unwrap();

    let (_full, token) = UseToken::create(NewUseToken {
        name: format!("{alias}-token"),
        credential_scope: alias.to_string(),
        action_scope: Some(action_scope.to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();
    token
}

fn refund_request(alias: &str, params: serde_json::Value) -> ExecuteRequest {
    ExecuteRequest {
        credential: alias.to_string(),
        action: "money.refund".to_string(),
        params,
    }
}

async fn run(
    server: &Arc<VultrinoServer>,
    token: &UseToken,
    req: ExecuteRequest,
) -> Result<vultrino::ExecuteResponse, String> {
    match server
        .execute_gated(req, ExecAuth::from_use_token(token.clone()))
        .await
    {
        Ok(ExecutionOutcome::Completed(r)) => Ok(r),
        Ok(ExecutionOutcome::Pending(_)) => Err("pending approval".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// ===========================================================================
// (a) The governed happy path
// ===========================================================================

#[tokio::test]
async fn governed_call_reaches_pinned_loopback_destination_with_injected_credential() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;

    let resp = run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({
                "url": "/v1/refunds",
                "method": "POST",
                "body": {"transaction_id": "tx_9", "amount_cents": 2500}
            }),
        ),
    )
    .await
    .expect("the governed internal call must succeed");

    assert_eq!(resp.status, 200, "sandbox returned 200");
    assert!(
        String::from_utf8_lossy(&resp.body).contains("rf_1"),
        "the agent sees the sandbox response body: {}",
        String::from_utf8_lossy(&resp.body)
    );

    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "exactly one request reached the sandbox");
    let (method, uri, auth, body) = &hits[0];
    assert_eq!(method, "POST");
    assert_eq!(uri, "/v1/refunds");
    // The vault credential was injected by vultrino — the agent never supplied it.
    assert_eq!(
        auth.as_deref(),
        Some(format!("Bearer {SANDBOX_KEY}").as_str()),
        "the vault credential must be injected into the internal call"
    );
    assert!(
        body.contains("tx_9"),
        "the caller-supplied body is forwarded: {body}"
    );
}

// ===========================================================================
// (b) Caller cannot influence scheme/host/port — every shape refused
// ===========================================================================

#[tokio::test]
async fn caller_cannot_steer_the_destination() {
    let (port, rec) = start_sandbox().await;
    let (evil_port, evil_hits) = start_redirect_target().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;

    let refusals = [
        // absolute URL to another origin
        serde_json::json!({"url": format!("http://127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
        // absolute URL back at the pinned origin (still refused: `url` is a path)
        serde_json::json!({"url": format!("http://127.0.0.1:{port}/v1/refunds"), "method": "POST"}),
        // protocol-relative authority
        serde_json::json!({"url": format!("//127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
        // backslash authority
        serde_json::json!({"url": format!("/\\127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
        // caller-supplied destination name
        serde_json::json!({"url": "/v1/refunds", "method": "POST", "destination": "other"}),
        // caller-supplied base_url / host / headers
        serde_json::json!({"url": "/v1/refunds", "method": "POST", "base_url": format!("http://127.0.0.1:{evil_port}")}),
        serde_json::json!({"url": "/v1/refunds", "method": "POST", "host": "127.0.0.1"}),
        serde_json::json!({"url": "/v1/refunds", "method": "POST", "headers": {"Host": "evil.example"}}),
        // cloud metadata / ClusterIP smuggled as an absolute URL
        serde_json::json!({"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"}),
        serde_json::json!({"url": "http://10.96.0.1:443/api", "method": "GET"}),
    ];

    for params in refusals {
        let err = run(
            &server,
            &token,
            refund_request("finsandbox-refund", params.clone()),
        )
        .await
        .expect_err(&format!("must be refused: {params}"));
        eprintln!("REFUSED {params} -> {err}");
        assert!(
            !err.is_empty(),
            "refusal must carry a reason for {params}: {err}"
        );
    }

    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "no refused request may reach the pinned destination"
    );
    assert_eq!(
        evil_hits.load(Ordering::SeqCst),
        0,
        "no refused request may reach any other origin"
    );
}

#[tokio::test]
async fn credential_naming_an_undeclared_destination_is_refused() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    // Credential pins a destination name that config.toml does not declare.
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("not-declared"),
        "money.refund",
    )
    .await;

    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect_err("an undeclared destination name must be refused");
    assert!(
        err.contains("not declared") || err.contains("internal destination"),
        "refusal must name the cause, got: {err}"
    );
    assert!(rec.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn credential_without_destination_metadata_is_refused() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    let token = seed(&storage, "finsandbox-refund", None, "money.refund").await;

    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect_err("a credential with no pinned destination must be refused");
    assert!(
        err.contains(META_DESTINATION),
        "refusal must name the missing metadata key, got: {err}"
    );
    assert!(rec.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn redirect_to_another_host_is_refused_and_never_followed() {
    let (evil_port, evil_hits) = start_redirect_target().await;
    let redirector_port = start_redirector(SocketAddr::from(([127, 0, 0, 1], evil_port))).await;
    // The pinned destination IS the redirector: reachable, allowlisted, and it
    // answers with a 302 to another origin.
    let (server, storage) = build_server(operator_config(redirector_port, "")).await;
    let token = seed(
        &storage,
        "finsandbox-read",
        Some("finsandbox"),
        "money.refund",
    )
    .await;

    let err = run(
        &server,
        &token,
        // GET /v1/ledger is on the destination allowlist; policy allows only
        // POST /v1/refunds, so use the refunds path with the label's policy.
        ExecuteRequest {
            credential: "finsandbox-read".to_string(),
            action: "money.refund".to_string(),
            params: serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        },
    )
    .await
    .expect_err("a redirect response must be refused");
    assert!(
        err.contains("redirect"),
        "refusal must name the redirect, got: {err}"
    );
    assert_eq!(
        evil_hits.load(Ordering::SeqCst),
        0,
        "the credential must never be sent to the redirect target"
    );
}

// ===========================================================================
// (c) Path traversal / scheme smuggling / allowlist escapes
// ===========================================================================

#[tokio::test]
async fn traversal_and_allowlist_escapes_are_refused() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    let token = seed(&storage, "finsandbox-refund", Some("finsandbox"), "money.*").await;

    let refusals = [
        // traversal, raw + encoded
        serde_json::json!({"url": "/v1/refunds/../../admin", "method": "POST"}),
        serde_json::json!({"url": "/v1/%2e%2e/admin", "method": "POST"}),
        serde_json::json!({"url": "/v1/%2f%2fadmin", "method": "POST"}),
        serde_json::json!({"url": "/v1\\admin", "method": "POST"}),
        // scheme smuggling
        serde_json::json!({"url": "javascript:alert(1)", "method": "POST"}),
        serde_json::json!({"url": "file:///etc/passwd", "method": "GET"}),
        // not rooted
        serde_json::json!({"url": "v1/refunds", "method": "POST"}),
        // path outside the operator allowlist (destination-level default-deny)
        serde_json::json!({"url": "/v1/admin", "method": "POST"}),
        serde_json::json!({"url": "/v1/refunds/secret", "method": "POST"}),
        // method outside the operator allowlist
        serde_json::json!({"url": "/v1/refunds", "method": "DELETE"}),
        serde_json::json!({"url": "/v1/refunds", "method": "CONNECT"}),
    ];
    for params in refusals {
        let err = run(
            &server,
            &token,
            refund_request("finsandbox-refund", params.clone()),
        )
        .await
        .expect_err(&format!("must be refused: {params}"));
        eprintln!("REFUSED {params} -> {err}");
        assert!(!err.is_empty(), "{params} -> {err}");
    }
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "no escape attempt may reach the sandbox"
    );
}

// ===========================================================================
// (d) The existing policy dimensions still bound the call
// ===========================================================================

#[tokio::test]
async fn policy_url_glob_and_method_still_bound_the_relative_path() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;
    // Token scope allows any money.* label; the POLICY allows only
    // (money.refund AND /v1/refunds AND POST).
    let token = seed(&storage, "finsandbox-refund", Some("finsandbox"), "money.*").await;

    // /v1/payouts is on the DESTINATION allowlist but not on the policy's
    // url_glob → default-deny.
    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/payouts", "method": "POST"}),
        ),
    )
    .await
    .expect_err("policy url_glob must still bound the path");
    assert!(
        err.to_lowercase().contains("polic") || err.to_lowercase().contains("den"),
        "expected a policy denial, got: {err}"
    );

    // Same path, but presented under the money.payout label: the policy's
    // ActionMatch fails too.
    let err = run(
        &server,
        &token,
        ExecuteRequest {
            credential: "finsandbox-refund".to_string(),
            action: "money.payout".to_string(),
            params: serde_json::json!({"url": "/v1/payouts", "method": "POST"}),
        },
    )
    .await
    .expect_err("policy action_match must still bound the label");
    assert!(!err.is_empty(), "{err}");

    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "a policy-denied call must never reach the destination"
    );

    // The allowed combination still works (proves the denials above are the
    // policy's doing, not a broken happy path).
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect("the policy-allowed combination must still execute");
    assert_eq!(rec.hits.lock().unwrap().len(), 1);
}

// ===========================================================================
// (e) The `http` plugin's SSRF guarantee is unchanged
// ===========================================================================

#[tokio::test]
async fn http_plugin_still_refuses_loopback_metadata_and_clusterip() {
    let (port, rec) = start_sandbox().await;
    // An allow-everything policy for this credential, so the ONLY thing that can
    // refuse these calls is the http plugin's own SSRF guard.
    let config = Config {
        policies: vec![
            vultrino::policy::Policy::allow_all("allow-http", "web-*").with_rule(
                vultrino::policy::PolicyCondition::UrlMatch("*".to_string()),
                vultrino::policy::PolicyAction::Allow,
            ),
        ],
        ..Config::default()
    };
    let (server, storage) = build_server(config).await;
    let token = seed(&storage, "web-cred", None, "http.request").await;

    for url in [
        format!("http://127.0.0.1:{port}/v1/refunds"),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://10.96.0.1:443/api".to_string(),
        "http://[::1]:8080/x".to_string(),
        "http://192.168.1.10/admin".to_string(),
    ] {
        let err = run(
            &server,
            &token,
            ExecuteRequest {
                credential: "web-cred".to_string(),
                action: "http.request".to_string(),
                params: serde_json::json!({"url": url, "method": "GET"}),
            },
        )
        .await
        .expect_err(&format!("http plugin must still refuse {url}"));
        assert!(
            err.contains("private/internal") || err.contains("not allowed"),
            "expected the SSRF refusal for {url}, got: {err}"
        );
    }
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "the http plugin must not reach a loopback service"
    );
}

// ===========================================================================
// (f) Per-credential path pinning (separate scoped credential per money action)
// ===========================================================================

#[tokio::test]
async fn per_credential_path_prefix_pins_a_scoped_credential() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(operator_config(port, "")).await;

    // The refund credential is additionally pinned to /v1/refunds.
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
    cred.metadata.insert(
        vultrino::plugins::META_PATH_PREFIX.to_string(),
        "/v1/refunds".to_string(),
    );
    storage.store(&cred).await.unwrap();
    let (_f, token) = UseToken::create(NewUseToken {
        name: "refund-token".to_string(),
        credential_scope: "finsandbox-refund".to_string(),
        action_scope: Some("money.*".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // Allowed: its own path.
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect("the credential's own path must work");

    // Refused: another money path on the same destination (would need the payout
    // credential). Presented under the label whose policy allows it, so the
    // refusal can only come from the credential pin.
    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/ledger", "method": "POST"}),
        ),
    )
    .await
    .expect_err("a scoped credential must not reach a sibling money path");
    assert!(!err.is_empty(), "{err}");
    assert_eq!(
        rec.hits.lock().unwrap().len(),
        1,
        "only the pinned path reached the sandbox"
    );
}

// ===========================================================================
// (g) The PLUGIN is the refuser — proven with policy deliberately permissive
// ===========================================================================

/// Same attacks as (b)/(c), but under `url_match = "*"`: the policy would admit
/// them all, so every refusal below is produced by `internal_http` itself. This
/// is the load-bearing proof that the destination is not caller-influenceable
/// even on a badly authored policy.
#[tokio::test]
async fn plugin_itself_refuses_every_steering_attempt_under_a_permissive_policy() {
    let (port, rec) = start_sandbox().await;
    let (evil_port, evil_hits) = start_redirect_target().await;
    let (server, storage) = build_server(permissive_config(port)).await;
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;

    // (params, substring the refusal must contain)
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (
            serde_json::json!({"url": format!("http://127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": format!("https://127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": format!("http://127.0.0.1:{port}/v1/refunds"), "method": "POST"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": format!("//127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
            "carries an authority",
        ),
        (
            serde_json::json!({"url": format!("/\\127.0.0.1:{evil_port}/v1/refunds"), "method": "POST"}),
            "carries an authority",
        ),
        (
            serde_json::json!({"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": "http://10.96.0.1:443/api", "method": "GET"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": "/v1/refunds", "method": "POST", "destination": "other"}),
            "unknown field `destination`",
        ),
        (
            // The `headers` FIELD is accepted (the shipped /api/v1/execute route always
            // sends one), but any ENTRY is refused: the caller supplies no headers here.
            serde_json::json!({"url": "/v1/refunds", "method": "POST", "headers": {"Host": "evil"}}),
            "may not supply request headers",
        ),
        (
            serde_json::json!({"url": "/v1/refunds", "method": "POST", "headers": {"Authorization": "Bearer stolen"}}),
            "may not supply request headers",
        ),
        (
            serde_json::json!({"url": "/v1/refunds/../../admin", "method": "POST"}),
            "'..' segment",
        ),
        (
            serde_json::json!({"url": "/v1/%2e%2e/admin", "method": "POST"}),
            "encoded path separator",
        ),
        (
            serde_json::json!({"url": "/v1/%2f%2fadmin", "method": "POST"}),
            "encoded path separator",
        ),
        (
            serde_json::json!({"url": "/v1\\admin", "method": "POST"}),
            "backslash",
        ),
        (
            serde_json::json!({"url": "javascript:alert(1)", "method": "POST"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": "file:///etc/passwd", "method": "GET"}),
            "carries a scheme",
        ),
        (
            serde_json::json!({"url": "v1/refunds", "method": "POST"}),
            "not rooted",
        ),
        (
            serde_json::json!({"url": "/v1/admin", "method": "POST"}),
            "path allowlist",
        ),
        (
            serde_json::json!({"url": "/v1/refunds/secret", "method": "POST"}),
            "path allowlist",
        ),
        (
            serde_json::json!({"url": "/v1/refunds", "method": "DELETE"}),
            "not allowed on internal destination",
        ),
        (
            serde_json::json!({"url": "/v1/refunds", "method": "CONNECT"}),
            "not an allowed HTTP verb",
        ),
    ];

    for (params, want) in cases {
        let err = run(
            &server,
            &token,
            refund_request("finsandbox-refund", params.clone()),
        )
        .await
        .expect_err(&format!("must be refused: {params}"));
        eprintln!("PLUGIN-REFUSED {params} -> {err}");
        assert!(
            err.contains(want),
            "refusal for {params} must name '{want}', got: {err}"
        );
    }

    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "no steering attempt may reach the pinned destination"
    );
    assert_eq!(
        evil_hits.load(Ordering::SeqCst),
        0,
        "no steering attempt may reach any other origin"
    );

    // Control: the legitimate call still works under this config.
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect("the legitimate call must still work");
    assert_eq!(rec.hits.lock().unwrap().len(), 1);
}

// ===========================================================================
// (i) Query handling — and the policy-authoring nuance it creates
// ===========================================================================

/// A query is legal in two places: inside `url` (then it IS part of the string
/// policy's `url_glob` matches) or in the `query` map (invisible to `url_glob`).
/// Neither can change the origin or the path allowlist decision, which is taken
/// on the normalized path alone.
#[tokio::test]
async fn query_is_forwarded_and_is_part_of_the_policy_matched_string() {
    let (port, rec) = start_sandbox().await;

    // Permissive policy (url_match "*"): both query forms reach the sandbox.
    let (server, storage) = build_server(permissive_config(port)).await;
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/ledger?limit=5", "method": "GET"}),
        ),
    )
    .await
    .expect("a query inside `url` is forwarded");
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/ledger", "method": "GET", "query": {"flagged": "1"}}),
        ),
    )
    .await
    .expect("a query in the `query` map is forwarded");
    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].1, "/v1/ledger?limit=5");
    assert_eq!(hits[1].1, "/v1/ledger?flagged=1");

    // Strict policy with url_glob "/v1/refunds": a query-bearing `url` no longer
    // matches the glob, so it is DENIED. This is the authoring nuance packs must
    // respect — pin `url_glob` with a trailing `*` if the agent may pass a query
    // inside `url`, or require the `query` map instead.
    let (server2, storage2) = build_server(operator_config(port, "")).await;
    let token2 = seed(
        &storage2,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;
    let err = run(
        &server2,
        &token2,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/refunds?dry_run=1", "method": "POST"}),
        ),
    )
    .await
    .expect_err("a query inside `url` changes the policy-matched string");
    eprintln!("QUERY-IN-URL vs STRICT url_glob -> {err}");
    assert!(err.to_lowercase().contains("polic"), "{err}");
}

// ===========================================================================
// (h) WHICH refusals burn a single-use token (the validate/execute split)
// ===========================================================================

/// Documents a real cost of the current `Plugin` trait: `validate_params` sees the
/// params but NOT the credential, so the destination/allowlist checks can only run
/// inside `execute` — i.e. AFTER `consume_use_token`. A shape violation (caught in
/// `validate_params`) leaves a single-use token intact; an allowlist violation
/// (caught in `execute`) burns it.
#[tokio::test]
async fn shape_refusals_spare_a_single_use_token_but_allowlist_refusals_burn_it() {
    async fn single_use(storage: &Arc<dyn StorageBackend>, alias: &str) -> UseToken {
        let mut cred = Credential::new(
            alias.to_string(),
            CredentialData::ApiKey {
                key: Secret::new(SANDBOX_KEY),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );
        cred.metadata
            .insert(META_DESTINATION.to_string(), "finsandbox".to_string());
        storage.store(&cred).await.unwrap();
        let (_f, token) = UseToken::create(NewUseToken {
            name: format!("{alias}-single"),
            credential_scope: alias.to_string(),
            action_scope: Some("money.refund".to_string()),
            max_uses: Some(1),
            require_approval: false,
            expires_in: None,
        });
        storage.store_use_token(&token).await.unwrap();
        token
    }

    // A: shape violation first (validate_params, pre-consume) → the token survives.
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(permissive_config(port)).await;
    let token = single_use(&storage, "finsandbox-a").await;
    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-a",
            serde_json::json!({"url": "http://evil.example/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect_err("absolute URL is refused");
    assert!(err.contains("carries a scheme"), "{err}");
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-a",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect("a pre-consume refusal must NOT burn the single use");
    assert_eq!(rec.hits.lock().unwrap().len(), 1);

    // B: allowlist violation first (execute, post-consume) → the use IS burned.
    let token = single_use(&storage, "finsandbox-b").await;
    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-b",
            serde_json::json!({"url": "/v1/admin", "method": "POST"}),
        ),
    )
    .await
    .expect_err("an off-allowlist path is refused");
    assert!(err.contains("path allowlist"), "{err}");
    let err = run(
        &server,
        &token,
        refund_request(
            "finsandbox-b",
            serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
        ),
    )
    .await
    .expect_err("the single use was burned by the post-consume refusal");
    eprintln!("BURNED-USE follow-up -> {err}");
    assert!(
        err.to_lowercase().contains("token"),
        "expected a token-exhausted refusal, got: {err}"
    );
    assert_eq!(
        rec.hits.lock().unwrap().len(),
        1,
        "the burned-token call never reached the sandbox"
    );
}

// ===========================================================================
// (j) P2 hardening: the reviewed string must equal the executed path
// ===========================================================================

/// URL normalization STRIPS tab/LF/CR and DROPS a fragment. `params["url"]` is what
/// the policy engine matched, what an approval summary shows a human, and what the
/// audit/averin seal records — so if those characters were allowed, a money action
/// could be reviewed and recorded as one path and executed as another. This proves
/// the divergence is refused, and (the load-bearing half) that the divergence is
/// REAL: the same string reaches a DIFFERENT path when the guard is removed.
#[tokio::test]
async fn a_path_that_normalization_would_rewrite_is_refused_before_it_executes() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(permissive_config(port)).await;
    let token = seed(
        &storage,
        "finsandbox-refund",
        Some("finsandbox"),
        "money.refund",
    )
    .await;

    // Every one of these NORMALIZES to an allowlisted path (`/v1/ledger` or
    // `/v1/refunds`) — i.e. without the guard they execute, under a different
    // string than the one policy matched and an approver would have read.
    let divergent = [
        "/v1/led\tger",
        "/v1/led\nger",
        "/v1/led\rger",
        " /v1/ledger",
        "/v1/ledger ",
        "/v1/ledger#/v1/refunds",
    ];
    let mut outcomes: Vec<(&str, Result<u16, String>)> = Vec::new();
    for bad in divergent {
        let r = run(
            &server,
            &token,
            refund_request(
                "finsandbox-refund",
                serde_json::json!({"url": bad, "method": "GET"}),
            ),
        )
        .await;
        outcomes.push((bad, r.map(|resp| resp.status)));
    }
    // Assert the RECORDER first, so a removed guard fails with the executed path
    // next to the string policy matched — the divergence itself, not just "it ran".
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "a normalization-divergent path reached the destination. sent -> executed: {:?} / {:?}",
        outcomes,
        rec.hits.lock().unwrap()
    );
    for (bad, outcome) in outcomes {
        let err = outcome.expect_err(&format!("must be refused: {bad:?}"));
        eprintln!("DIVERGENT-REFUSED {bad:?} -> {err}");
        assert!(
            err.contains("control character or space") || err.contains("fragment"),
            "refusal for {bad:?} must name the reason, got: {err}"
        );
    }

    // Control: the honest form of the same call works and is recorded verbatim.
    run(
        &server,
        &token,
        refund_request(
            "finsandbox-refund",
            serde_json::json!({"url": "/v1/ledger", "method": "GET"}),
        ),
    )
    .await
    .expect("the honest path must work");
    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].1, "/v1/ledger");
}

// ===========================================================================
// (k) P2 hardening: a credential may not re-route inside the pinned destination
// ===========================================================================

/// The destination is OPERATOR authority (config.toml); a credential is ADMIN-API
/// authority (govder / `orgpack apply`). A credential whose `header_name` is `Host`
/// would reach a different virtual host on the same pinned address; the framing
/// headers are request-smuggling primitives. Refused, and nothing is sent.
#[tokio::test]
async fn a_credential_cannot_inject_a_routing_or_framing_header() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(permissive_config(port)).await;

    for (alias, header) in [
        ("finsandbox-host", "Host"),
        ("finsandbox-cl", "Content-Length"),
        ("finsandbox-te", "Transfer-Encoding"),
    ] {
        let mut cred = Credential::new(
            alias.to_string(),
            CredentialData::ApiKey {
                key: Secret::new(SANDBOX_KEY),
                header_name: header.to_string(),
                header_prefix: String::new(),
            },
        );
        cred.metadata
            .insert(META_DESTINATION.to_string(), "finsandbox".to_string());
        storage.store(&cred).await.unwrap();
        let (_f, token) = UseToken::create(NewUseToken {
            name: format!("{alias}-token"),
            credential_scope: alias.to_string(),
            action_scope: Some("money.refund".to_string()),
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });
        storage.store_use_token(&token).await.unwrap();

        let err = run(
            &server,
            &token,
            refund_request(
                alias,
                serde_json::json!({"url": "/v1/refunds", "method": "POST"}),
            ),
        )
        .await
        .expect_err(&format!("a '{header}' credential must be refused"));
        eprintln!("CRED-HEADER-REFUSED {header} -> {err}");
        assert!(err.contains("routing/framing header"), "{err}");
    }
    assert!(
        rec.hits.lock().unwrap().is_empty(),
        "no request may be sent for a re-routing credential"
    );
}

// ===========================================================================
// (l) P2: per-credential method+path scope (D8's refund != payout != read)
// ===========================================================================

/// `internal_allow_methods` narrows a credential to a subset of the destination's
/// verbs, so a READ credential can never write even to a path it may read. Together
/// with `internal_path_prefix` this makes D8's "refund cred != payout cred != read
/// cred" a vultrino-enforced method+path scope rather than a naming convention.
#[tokio::test]
async fn a_read_credential_cannot_write_even_to_a_path_it_may_read() {
    let (port, rec) = start_sandbox().await;
    let (server, storage) = build_server(permissive_config(port)).await;

    let alias = "finsandbox-read";
    let mut cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new(SANDBOX_KEY),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    cred.metadata
        .insert(META_DESTINATION.to_string(), "finsandbox".to_string());
    cred.metadata
        .insert("internal_allow_methods".to_string(), "GET".to_string());
    cred.metadata
        .insert("internal_path_prefix".to_string(), "/v1/ledger".to_string());
    storage.store(&cred).await.unwrap();
    let (_f, token) = UseToken::create(NewUseToken {
        name: "read-token".to_string(),
        credential_scope: alias.to_string(),
        action_scope: Some("money.refund".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // The read it is scoped for.
    run(
        &server,
        &token,
        refund_request(
            alias,
            serde_json::json!({"url": "/v1/ledger", "method": "GET"}),
        ),
    )
    .await
    .expect("the scoped read must work");

    // A write to the SAME path — refused on the method dimension.
    let err = run(
        &server,
        &token,
        refund_request(
            alias,
            serde_json::json!({"url": "/v1/ledger", "method": "POST"}),
        ),
    )
    .await
    .expect_err("a read credential must not POST");
    eprintln!("READ-CRED-POST-REFUSED -> {err}");
    assert!(err.contains("scoped to methods"), "{err}");

    // A read of a DIFFERENT allowlisted path — refused on the path dimension.
    let err = run(
        &server,
        &token,
        refund_request(
            alias,
            serde_json::json!({"url": "/v1/refunds", "method": "GET"}),
        ),
    )
    .await
    .expect_err("a ledger-pinned credential must not reach /v1/refunds");
    eprintln!("READ-CRED-OFFPATH-REFUSED -> {err}");
    assert!(err.contains("is pinned to"), "{err}");

    let hits = rec.hits.lock().unwrap().clone();
    assert_eq!(
        hits.len(),
        1,
        "only the scoped read reached the destination"
    );
    assert_eq!(hits[0].0, "GET");
    assert_eq!(hits[0].1, "/v1/ledger");
}

// A `HashMap` import keeps the recorder tuple readable in failures.
#[allow(dead_code)]
fn _unused(_: HashMap<String, String>) {}
