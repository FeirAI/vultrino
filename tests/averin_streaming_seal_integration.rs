//! Plan 087 FIX 1 — the averin use-seal on the STREAMING execute path.
//!
//! Before plan 087, `run_action_streaming` had NO seal hook: a `stream: true`
//! request consumed the use token and ran WITHOUT a `/v2/use` receipt, so
//! `require_evidence` failed OPEN for streams (the exact strict-mode hole). These
//! tests drive the real `VultrinoServer::execute_gated_streaming` path (which calls
//! `run_action_streaming` under the default, egress-safe config) with the seal-client
//! enabled and assert the shared `seal_after_consume` hook now fires on streams too:
//!
//!   - Observe (fail-open): the stream PROCEEDS and a seal is SPAWNED off the hot path
//!     (it fails NoGrant here — no grant was pre-sealed — which is exactly what proves
//!     the hook ran, off the hot path, without blocking or failing the action).
//!   - RequireEvidence (fail-closed): the seal is AWAITED and its failure DENIES the
//!     action before any stream byte opens.
//!
//! No network + no real averin: a `base_url` pointing at a dead port is enough because
//! a token with no pre-sealed grant fails at `NoGrant` BEFORE any request is sent.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::approval::RequesterInfo;
use vultrino::auth::{AuthResult, NewUseToken, UseToken};
use vultrino::averin::{AverinConfig, AverinMode};
use vultrino::config::Config;
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, StreamingOutcome, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, ExecutionOutcome,
    Secret,
};

/// A deterministic plugin that echoes its params back. It does NOT override
/// `execute_streaming`, so it exercises the trait's default streaming impl — i.e.
/// the real `run_action_streaming` server path, which is where the seal hook lives.
struct MockPlugin;

#[async_trait::async_trait]
impl Plugin for MockPlugin {
    fn name(&self) -> &str {
        "mock"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["echo"]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        let body = serde_json::to_vec(&request.params).unwrap_or_default();
        Ok(ExecuteResponse::success(body))
    }
    fn validate_params(
        &self,
        _action: &str,
        _params: &serde_json::Value,
    ) -> Result<(), PluginError> {
        Ok(())
    }
}

/// Build a server with the averin seal-client ENABLED in `mode`, pointed at `base_url`.
async fn setup_averin_at(
    base_url: &str,
    mode: AverinMode,
) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // short-lived test; OS reclaims on exit

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    // These suites exercise the seal, not engine default-deny.
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.averin = AverinConfig {
        enabled: true,
        base_url: base_url.to_string(),
        resource_id: "orders-db".to_string(),
        mode,
        ..AverinConfig::default()
    };

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    (server, storage)
}

/// Convenience: a server whose averin points at a DEAD port (unused — the NoGrant
/// failure the streaming tests observe happens before any network I/O).
async fn setup_averin(mode: AverinMode) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    setup_averin_at("http://127.0.0.1:9", mode).await
}

/// A minimal stub averin: `POST /v2/grants` returns a grant + a `.`-bearing capability
/// (so `credential_binding` succeeds), and `POST /v2/use` returns a sealed record id.
/// It validates nothing — enough to prove `seal_mint` records the grant so the first
/// `/execute` does NOT hit NoGrant. Returns the base_url.
async fn spawn_stub_averin() -> String {
    use axum::routing::post;
    use axum::{Json, Router};

    async fn grants() -> Json<serde_json::Value> {
        Json(serde_json::json!({"grant_id": "g-stub-1", "capability": "AAAABBBB.sig"}))
    }
    async fn use_seal() -> Json<serde_json::Value> {
        Json(serde_json::json!({"record": {"record_id": "use-stub-1"}}))
    }

    let app = Router::new()
        .route("/v2/grants", post(grants))
        .route("/v2/use", post(use_seal));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Store an api-key credential and a single-use token scoped to `mock.echo`. NB: the
/// token is stored DIRECTLY (no `seal_mint`), so no grant is on record → the use seal
/// deterministically fails `NoGrant` (which is what these tests want to observe).
async fn store_cred_and_token(storage: &Arc<dyn StorageBackend>) -> UseToken {
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();

    let (_full, token) = UseToken::create(NewUseToken {
        name: "stream-once".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();
    token
}

fn exec_auth_for(token: &UseToken) -> ExecAuth {
    ExecAuth {
        auth: Some(AuthResult::for_use_token(token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    }
}

fn echo_request() -> ExecuteRequest {
    ExecuteRequest {
        credential: "api-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"hello": "world"}),
    }
}

/// Observe + streaming: the action PROCEEDS (stream opens, body delivered) and a seal
/// is SPAWNED off the hot path — proving `run_action_streaming` now invokes the shared
/// seal hook. The seal fails NoGrant (deterministic, no grant pre-sealed), which the
/// failed counter records — WITHOUT blocking or failing the stream.
#[tokio::test]
async fn observe_streaming_execute_proceeds_and_spawns_seal() {
    let (server, storage) = setup_averin(AverinMode::Observe).await;
    let token = store_cred_and_token(&storage).await;

    let outcome = server
        .execute_gated_streaming(echo_request(), exec_auth_for(&token))
        .await
        .expect("Observe streaming must PROCEED fail-open even though the seal fails");

    let mut exec = match outcome {
        StreamingOutcome::Streaming(e) => e,
        StreamingOutcome::Pending(_) => panic!("must not be approval-gated"),
    };

    // The action really ran: the streamed body carries the echoed params.
    let mut collected = Vec::new();
    while let Some(chunk) = exec.body.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert!(
        !collected.is_empty(),
        "streamed body must carry the echoed action output (the action proceeded)"
    );

    // The seal was spawned off the hot path and (NoGrant) failed — poll the counter.
    let av = server.averin().expect("averin enabled");
    let mut failed = 0;
    for _ in 0..200 {
        failed = av.metrics().failed;
        if failed >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        failed, 1,
        "the streaming path must spawn exactly one async use-seal (NoGrant → failed)"
    );
    assert_eq!(av.metrics().sealed, 0, "no grant on record → nothing seals");

    // The single use was still consumed (the action proceeded despite the seal gap).
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());
}

/// RequireEvidence + streaming: the seal is AWAITED and its failure DENIES the action
/// BEFORE any stream byte opens — closing the strict-mode fail-OPEN hole streams had.
#[tokio::test]
async fn require_evidence_streaming_denies_when_seal_fails() {
    let (server, storage) = setup_averin(AverinMode::RequireEvidence).await;
    let token = store_cred_and_token(&storage).await;

    let result = server
        .execute_gated_streaming(echo_request(), exec_auth_for(&token))
        .await;
    let err = match result {
        Ok(_) => panic!("RequireEvidence streaming must DENY when the seal fails — no stream may open"),
        Err(e) => e,
    };

    let msg = format!("{err}");
    assert!(
        msg.contains("averin evidence seal required"),
        "deny reason must name the failed require_evidence seal, got: {msg}"
    );

    // The seal was attempted and counted as a (blocking) failure.
    assert_eq!(server.averin().unwrap().metrics().failed, 1);
    assert_eq!(server.averin().unwrap().metrics().sealed, 0);

    // Documented consume-before-seal caveat (§10): the vut_ token was consumed before
    // the seal, so a strict block burns it — identical to the buffered path.
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
}

/// Plan 087 FIX 2 — a token whose grant is recorded via the SHARED `seal_mint` (the
/// exact hook the JSON API, web console, and workload exchange all now call) does NOT
/// seal NoGrant on its first `/execute`: the grant is on record, so the use seals.
/// Before FIX 2 only the JSON admin API called `on_mint`, so a web-console- or
/// workload-minted token's first execute sealed NoGrant.
#[tokio::test]
async fn seal_mint_records_grant_so_first_execute_seals_not_nogrant() {
    let base = spawn_stub_averin().await;
    let (server, storage) = setup_averin_at(&base, AverinMode::Observe).await;
    let token = store_cred_and_token(&storage).await; // stored WITHOUT a grant yet

    // The centralized mint hook every in-process surface calls. It must record the
    // grant (POST /v2/grants → PoP entry) BEFORE the token is usable.
    server.seal_mint(&token).await;

    // First execute (buffered): the async use seal must SUCCEED — grant on record.
    let outcome = server
        .execute_gated(echo_request(), exec_auth_for(&token))
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    let av = server.averin().expect("averin enabled");
    // Observe seal is async — poll for the sealed receipt.
    let mut sealed = 0;
    for _ in 0..200 {
        sealed = av.metrics().sealed;
        if sealed >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        sealed, 1,
        "grant recorded via seal_mint → the first execute seals a use (NOT NoGrant)"
    );
    assert_eq!(
        av.metrics().failed,
        0,
        "no NoGrant / no seal failure once the grant is on record"
    );
}
