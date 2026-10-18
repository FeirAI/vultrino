//! feir-ops#1 against a REAL averin-server (the one that has `POST /v2/refusals`, FeirAI/averin#26):
//! a refusal vultrino notes is accepted by averin's closed-vocabulary endpoint, sealed as a
//! `gateway-refusal` record, and counted by averin's verifier. The stub-based tests in
//! `refusals_integration.rs` cover vultrino's side exhaustively; only a real averin can show that
//! the body vultrino posts is one averin accepts.
//!
//! `#[ignore]` because it spawns an external binary. Build it from the averin branch, then:
//!   AVERIN_SERVER_BIN=/path/to/averin-server \
//!   cargo test --locked --no-default-features --test refusals_real_averin -- --ignored --nocapture
//! (averin: `cargo build -p averin-decision-core --features rfc3161`, then in `server/`
//! `CGO_LDFLAGS=-ldl go build -o averin-server ./cmd/averin-server`.)

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use serde_json::{json, Value};
use tempfile::tempdir;

use vultrino::auth::{NewUseToken, UseToken};
use vultrino::averin::{AverinConfig, AverinMode};
use vultrino::config::{Config, EnforcementConfig, EnforcementDefault};
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, ExecuteRequest, Secret};

const PROJECT: &str = "vultrino";
const AGENT: &str = "ep_real_averin_agent";

struct Averin {
    child: Child,
    base_url: String,
}

impl Drop for Averin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_averin() -> Averin {
    let bin = std::env::var("AVERIN_SERVER_BIN")
        .expect("set AVERIN_SERVER_BIN to an averin-server built from the refusals branch");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(&bin)
        .env("AVERIN_DEV_MODE", "1")
        .env("AVERIN_SIGNING_SEED", "11".repeat(32))
        .env("AVERIN_BROKER_ISSUING_SEED", "22".repeat(32))
        .env("AVERIN_RESOURCE_SEED", "33".repeat(32))
        .env("AVERIN_RESOURCE_ID", "orders-db")
        .env("AVERIN_ADDR", format!(":{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn averin-server at {bin}: {e}"));
    Averin {
        child,
        base_url: format!("http://127.0.0.1:{port}"),
    }
}

async fn wait_healthz(base_url: &str) {
    let http = reqwest::Client::new();
    for _ in 0..200 {
        if let Ok(r) = http.get(format!("{base_url}/healthz")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("averin-server did not become healthy at {base_url}");
}

#[tokio::test]
#[ignore = "spawns a real averin-server binary; run with --ignored"]
async fn a_refusal_is_sealed_by_a_real_averin_and_counted_by_its_verifier() {
    let av = spawn_averin();
    wait_healthz(&av.base_url).await;

    let dir = tempdir().unwrap();
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(
            &dir.path().join("store.enc"),
            &SecretString::from("test-password"),
        )
        .await
        .unwrap(),
    );
    let config = Config {
        enforcement: EnforcementConfig {
            default_action: EnforcementDefault::Deny,
            require_declared_capabilities: false,
        },
        averin: AverinConfig {
            enabled: true,
            base_url: av.base_url.clone(),
            project_id: PROJECT.to_string(),
            resource_id: "orders-db".to_string(),
            mode: AverinMode::Observe,
            ..AverinConfig::default()
        },
        ..Config::default()
    };
    let srv = VultrinoServer::new(
        config,
        storage.clone(),
        CredentialResolver::new(storage.clone()),
    );
    storage
        .store(&Credential::new(
            "cred-ok".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("sk-real-averin-test"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        ))
        .await
        .unwrap();
    let (_secret, mut token) = UseToken::create(NewUseToken {
        name: "agent".to_string(),
        credential_scope: "cred-nomatch".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some(AGENT.to_string());
    storage.store_use_token(&token).await.unwrap();

    // Three refusals of the same kind: the first is its own record, the other two a tail.
    for _ in 0..3 {
        srv.execute_gated(
            ExecuteRequest {
                credential: "cred-ok".to_string(),
                action: "http.request".to_string(),
                params: json!({"method": "GET", "url": "https://canary.example/x"}),
            },
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap_err();
    }
    let client = srv.averin().expect("averin client");
    assert_eq!(
        client.drain_refusals_once().await,
        1,
        "averin accepts the first record"
    );
    assert_eq!(client.refusal_counters().sealed, 1);
    assert_eq!(client.refusal_counters().unsealed, 0);

    let http = reqwest::Client::new();
    let export = http
        .get(format!("{}/v2/export?project={PROJECT}", av.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        export.contains("gateway-refusal"),
        "the record is in the bundle"
    );
    assert!(export.contains(AGENT));
    assert!(
        !export.contains("canary.example"),
        "no URL reaches the record"
    );
    assert!(!export.contains("sk-real-averin-test"));

    let verify: Value = http
        .get(format!("{}/v2/verify?project={PROJECT}", av.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["gateway_refusals"], 1, "{verify}");
    assert_eq!(verify["gateway_refusal_attempts"], 1, "{verify}");
    assert_eq!(
        verify["gateway_refusals_by_class"]["not_granted"], 1,
        "{verify}"
    );
}
