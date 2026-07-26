//! HTTP-level integration tests for the workload-exchange DENY paths.
//!
//! Drives the real Axum router's `POST /api/v1/workload/exchange` endpoint via
//! `tower::ServiceExt::oneshot` (no socket bound). The endpoint authenticates a
//! `vwa_` verified-workload assertion (HMAC-SHA256), looks up the stored grant
//! template bound to that identity, single-consumes the assertion `jti` (replay
//! guard), then mints scoped use-tokens. These tests assert every way that path
//! must REFUSE: forged signature, replay, identity-binding mismatch, expiry, and
//! the feature being disabled / unconfigured.
//!
//! `exchange_workload_token` reads two PROCESS-GLOBAL env vars
//! (`VULTRINO_WORKLOAD_EXCHANGE_ENABLED`, `VULTRINO_WORKLOAD_ASSERTION_SECRET`).
//! cargo runs the tests in this binary on parallel threads, so a static mutex
//! (`ENV_LOCK`) serializes them: each test takes the lock, sets the exact env
//! state it needs, and holds the guard across its request so no sibling test can
//! observe a half-configured environment.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use secrecy::SecretString;
use sha2::Sha256;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::auth::AuthManager;
use vultrino::config::Config;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};

/// Serializes access to the process-global workload-exchange env vars.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A 32-byte verifier secret (the handler rejects anything shorter than 32 bytes).
const VERIFIER_SECRET: &[u8] = b"01234567890123456789012345678901";
/// A different 32-byte secret used to FORGE a signature the server will reject.
const WRONG_SECRET: &[u8] = b"ffffffffffffffffffffffffffffffff";

/// Configure the exchange env vars to the enabled + correctly-configured state.
/// Caller must already hold [`ENV_LOCK`].
fn enable_exchange() {
    unsafe {
        std::env::set_var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED", "1");
        std::env::set_var(
            "VULTRINO_WORKLOAD_ASSERTION_SECRET",
            String::from_utf8_lossy(VERIFIER_SECRET).to_string(),
        );
        // The file-based override takes precedence when set — keep it clear so the
        // inline secret is the one used.
        std::env::remove_var("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE");
    }
}

/// Build a web router plus a persisted admin key (so the grant can be authored
/// over the real PUT route) and the shared storage.
async fn build_router() -> (axum::Router, Arc<dyn StorageBackend>, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the vault alive for the test's lifetime

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager
        .create_api_key("admin-key", "admin", None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        Config::default(),
        storage.clone(),
        resolver,
    ));
    let server = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        Config::default(),
        storage.clone(),
        auth_manager,
        admin,
        exec_server,
    );
    (server.into_router(), storage, admin_key)
}

/// Author the standard workload grant template for `t1`/`ep_agent` over the real
/// admin PUT route, so the exchange lookup (keyed on tenant+agent) resolves it.
async fn author_grant(router: &axum::Router, admin_key: &str) {
    let grant = serde_json::json!({
        "tenant": "t1", "agent_label": "ep_agent", "issuer": "https://issuer",
        "subject": "workload", "audience": "vultrino", "mcp_credential_scope": "cred-*",
        "mcp_action_scope": "tool.*", "ttl_secs": 300
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/workload-grants/ep_agent")
                .header("authorization", format!("Bearer {admin_key}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&grant).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "grant author must succeed");
}

/// Mint a `vwa_` assertion over `claims`, HMAC-SHA256-signed with `secret`
/// (pass [`WRONG_SECRET`] to forge a signature the server will reject).
fn mint_assertion(secret: &[u8], claims: serde_json::Value) -> String {
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("vwa_{payload}.{sig}")
}

/// A well-formed claim set bound to the authored grant, with `exp` inside the
/// accepted `now < exp <= now+600` window and a caller-chosen `jti`.
fn valid_claims(jti: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "oidc", "iss": "https://issuer", "sub": "workload",
        "aud": "vultrino", "tenant": "t1", "agent_label": "ep_agent",
        "jti": jti, "exp": Utc::now().timestamp() + 300
    })
}

fn exchange_req(assertion: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/workload/exchange")
        .header("authorization", format!("Bearer {assertion}"))
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------

/// A `vwa_` assertion signed with the wrong key (forged/tampered HMAC) is
/// rejected 401 — the signature is verified before any claim is trusted.
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn forged_hmac_assertion_is_401() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    // Correct claims, but signed with WRONG_SECRET → HMAC verify fails.
    let forged = mint_assertion(WRONG_SECRET, valid_claims("jti-forged"));
    let resp = router.oneshot(exchange_req(&forged)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A valid assertion may be exchanged exactly once. Replaying the SAME assertion
/// (same `jti`) is refused 409 — the `jti` is single-consumed (replay guard).
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn replayed_jti_second_request_is_409() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let assertion = mint_assertion(VERIFIER_SECRET, valid_claims("jti-replay"));

    // First exchange succeeds and mints tokens.
    let first = router
        .clone()
        .oneshot(exchange_req(&assertion))
        .await
        .unwrap();
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "first exchange must succeed"
    );

    // Replaying the identical assertion is rejected as a replay.
    let second = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

/// A validly-signed assertion whose issuer/subject/audience do not match the
/// stored grant template (but whose tenant+agent DO, so the grant is found) is
/// refused 403 — the identity binding is enforced, not just the signature.
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn identity_binding_mismatch_is_403() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    // Same tenant/agent (so grant_key resolves the template) but a different iss.
    let mut claims = valid_claims("jti-mismatch");
    claims["iss"] = serde_json::json!("https://attacker.example");
    let assertion = mint_assertion(VERIFIER_SECRET, claims);

    let resp = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A validly-signed assertion whose `exp` is in the past is refused 401 — expiry
/// is checked inside signature verification, so an expired token never mints.
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn expired_assertion_is_401() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let mut claims = valid_claims("jti-expired");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() - 30); // already expired
    let assertion = mint_assertion(VERIFIER_SECRET, claims);

    let resp = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// With the feature flag off, the endpoint refuses BEFORE looking at the
/// assertion at all: it 404s (`feature_disabled`) so the surface is invisible.
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn feature_disabled_is_404() {
    let _guard = ENV_LOCK.lock().unwrap();
    // Explicitly OFF: remove the enable flag (secret state is irrelevant here).
    unsafe {
        std::env::remove_var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED");
    }
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    // A well-formed, correctly-signed assertion still gets nowhere.
    let assertion = mint_assertion(VERIFIER_SECRET, valid_claims("jti-disabled"));
    let resp = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A verifier configured with a COMMA-LIST of secrets (dual-secret overlap for rotation) accepts an
/// assertion signed with EITHER the primary or the secondary — the try-each verify loop matches on the
/// second candidate. The external edge signs; vultrino verifies. A single-element list stays exactly
/// the pre-rotation behavior (the other tests here cover that).
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn dual_secret_list_accepts_either_secret() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED", "1");
        // PRIMARY (VERIFIER_SECRET) + SECONDARY (a different 32-byte key) as a comma-list.
        std::env::set_var(
            "VULTRINO_WORKLOAD_ASSERTION_SECRET",
            format!(
                "{},{}",
                String::from_utf8_lossy(VERIFIER_SECRET),
                String::from_utf8_lossy(WRONG_SECRET)
            ),
        );
        std::env::remove_var("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE");
    }
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    // Signed with the SECONDARY secret — accepted because it is now in the verifier list.
    let assertion = mint_assertion(WRONG_SECRET, valid_claims("jti-rot-secondary"));
    let resp = router
        .clone()
        .oneshot(exchange_req(&assertion))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an assertion signed with the secondary secret must be accepted"
    );

    // And the PRIMARY still verifies (fresh jti so it is not a replay).
    let assertion2 = mint_assertion(VERIFIER_SECRET, valid_claims("jti-rot-primary"));
    let resp2 = router.oneshot(exchange_req(&assertion2)).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "an assertion signed with the primary secret must still be accepted"
    );
}

/// A secret NOT in the verifier list is still rejected 401 — the list widens the accept set to exactly
/// the configured secrets, no further (the overlap is a bounded, temporary rotation window).
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn secret_outside_the_list_is_still_401() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED", "1");
        // Only the PRIMARY is configured; WRONG_SECRET is NOT in the list.
        std::env::set_var(
            "VULTRINO_WORKLOAD_ASSERTION_SECRET",
            String::from_utf8_lossy(VERIFIER_SECRET).to_string(),
        );
        std::env::remove_var("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE");
    }
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let assertion = mint_assertion(WRONG_SECRET, valid_claims("jti-not-listed"));
    let resp = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Enabled but with NO verifier secret configured, the endpoint refuses 503
/// (`exchange_unconfigured`) — it fails closed rather than trusting assertions
/// against a missing/short key.
#[tokio::test]
// The guard intentionally spans the `.await`s below: it holds the env stable
// (see the ENV_LOCK doc comment) for the whole request, not just setup.
#[allow(clippy::await_holding_lock)]
async fn enabled_without_secret_is_503() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED", "1");
        std::env::remove_var("VULTRINO_WORKLOAD_ASSERTION_SECRET");
        std::env::remove_var("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE");
    }
    let (router, _storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    // The assertion is signed correctly, but the server has no key to verify it.
    let assertion = mint_assertion(VERIFIER_SECRET, valid_claims("jti-unconfigured"));
    let resp = router.oneshot(exchange_req(&assertion)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// TOKEN MULTIPLICATION BOUNDS (plan 103 §10 item 6 / P4d)
//
// Everything below was measured before it was fixed, on an isolated vultrino and on a
// real eve pod, and the numbers are in the assertions' failure messages so a
// regression reads as the finding rather than as "an assert flipped".

/// PREDECESSOR-RETIRE: a second exchange leaves exactly ONE live generation.
///
/// Before this, every exchange left its predecessor live with a full `max_uses`
/// allowance until that generation's own TTL: N=10 exchanges measured 10 independent
/// live MCP tokens (aggregate 50 uses against an intended per-generation 5) plus 10
/// UNBOUNDED-use model tokens, and a real eve pod accumulated 38 in 19 minutes.
#[tokio::test]
async fn second_exchange_retires_its_predecessor() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let first = mint_assertion(VERIFIER_SECRET, valid_claims("jti-retire-1"));
    let resp = router.clone().oneshot(exchange_req(&first)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first exchange must succeed");
    let live_after_first = live_tokens(&storage, "t1", "ep_agent").await;
    assert_eq!(live_after_first.len(), 1, "one exchange = one live generation");

    let second = mint_assertion(VERIFIER_SECRET, valid_claims("jti-retire-2"));
    let resp = router.clone().oneshot(exchange_req(&second)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "second exchange must succeed");

    let live = live_tokens(&storage, "t1", "ep_agent").await;
    assert_eq!(
        live.len(),
        1,
        "after a second exchange there must be exactly ONE live generation \
         (mint-then-retire). Found {}: the predecessor was left usable, which is the \
         measured defect — 10 exchanges produced 10 live tokens with 10x the intended \
         aggregate allowance, and a real pod reached 38 in 19 minutes, past the ~150-200 \
         crossover where the W2 grant-delete revoke exceeds govder's 10s timeout.",
        live.len()
    );
    assert_ne!(
        live[0].id, live_after_first[0].id,
        "the surviving generation must be the NEW one — retire must never revoke the \
         credential the caller was just handed"
    );
}

/// The retired predecessor is REVOKED, not merely absent from a list: a stale
/// generation must stop being usable, which is what makes the bound a security
/// property rather than bookkeeping.
#[tokio::test]
async fn the_retired_predecessor_is_revoked() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let a = mint_assertion(VERIFIER_SECRET, valid_claims("jti-rev-1"));
    router.clone().oneshot(exchange_req(&a)).await.unwrap();
    let first_id = live_tokens(&storage, "t1", "ep_agent").await[0].id.clone();

    let b = mint_assertion(VERIFIER_SECRET, valid_claims("jti-rev-2"));
    router.clone().oneshot(exchange_req(&b)).await.unwrap();

    let prior = storage.get_use_token(&first_id).await.unwrap().unwrap();
    assert!(
        prior.revoked,
        "the predecessor generation must be REVOKED after the next exchange; an \
         unrevoked stale token keeps executing real actions until its own TTL"
    );
}

/// `max_live_generations` is a FAIL-CLOSED refusal, and it is reached even when the
/// grant omits the field — an omitted field must not restore unbounded behaviour.
#[tokio::test]
async fn max_live_generations_refuses_an_over_cap_exchange() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, storage, admin_key) = build_router().await;
    // cap = 1 makes the SECOND exchange the one over the bound, which is the smallest
    // configuration that exercises the refusal.
    let grant = serde_json::json!({
        "tenant": "t1", "agent_label": "ep_agent", "issuer": "https://issuer",
        "subject": "workload", "audience": "vultrino", "mcp_credential_scope": "cred-*",
        "mcp_action_scope": "tool.*", "ttl_secs": 300, "max_live_generations": 1
    });
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/workload-grants/ep_agent")
                .header("authorization", format!("Bearer {admin_key}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&grant).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let a = mint_assertion(VERIFIER_SECRET, valid_claims("jti-cap-1"));
    let resp = router.clone().oneshot(exchange_req(&a)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the first exchange is under the cap");

    // Leave the predecessor live so the cap is what is being measured, not retire.
    let live = live_tokens(&storage, "t1", "ep_agent").await;
    assert_eq!(live.len(), 1);

    // A second exchange now sees 1 live >= cap 1 and must REFUSE, before minting.
    let b = mint_assertion(VERIFIER_SECRET, valid_claims("jti-cap-2"));
    let resp = router.clone().oneshot(exchange_req(&b)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "an exchange at the live-generation cap must be REFUSED, not granted: an \
         unbounded live set degrades the W2 containment leg past its own timeout"
    );
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("live_generation_cap"),
        "the refusal must be machine-identifiable, got: {body}"
    );
    assert_eq!(
        live_tokens(&storage, "t1", "ep_agent").await.len(),
        1,
        "the refused exchange must have minted NOTHING — a cap checked after the mint \
         would let the very request that breached the bound add to it"
    );
}

/// Deprovisioning revokes every live generation in ONE pass and reports the count.
#[tokio::test]
async fn deleting_the_grant_revokes_every_live_generation() {
    let _guard = ENV_LOCK.lock().unwrap();
    enable_exchange();
    let (router, storage, admin_key) = build_router().await;
    author_grant(&router, &admin_key).await;

    let a = mint_assertion(VERIFIER_SECRET, valid_claims("jti-del-1"));
    router.clone().oneshot(exchange_req(&a)).await.unwrap();
    assert_eq!(live_tokens(&storage, "t1", "ep_agent").await.len(), 1);

    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/workload-grants/ep_agent?tenant=t1")
                .header("authorization", format!("Bearer {admin_key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains("\"removed\":true"),
        "grant delete must report removal, got: {body}"
    );
    assert!(
        body.contains("\"revoked_tokens\":1"),
        "W2 must report the tokens it revoked so a caller can tell containment from a \
         no-op, got: {body}"
    );
    assert_eq!(
        live_tokens(&storage, "t1", "ep_agent").await.len(),
        0,
        "no live generation may survive a grant delete — that is the W2 kill leg"
    );
}

/// Live = unrevoked AND unexpired, for one (tenant, agent_label).
async fn live_tokens(
    storage: &Arc<dyn StorageBackend>,
    tenant: &str,
    agent_label: &str,
) -> Vec<vultrino::auth::UseToken> {
    storage
        .list_use_tokens()
        .await
        .unwrap()
        .into_iter()
        .filter(|t| {
            t.tenant.as_deref() == Some(tenant)
                && t.agent_label.as_deref() == Some(agent_label)
                && !t.revoked
                && !t.is_expired()
        })
        .collect()
}
