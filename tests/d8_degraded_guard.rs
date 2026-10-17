//! VUL-38: the D8 one-phase fallback is allowed only for a declared-Reversible action and only
//! when Averin is unavailable (unreachable, 5xx, 429). Every other failure refuses, on both the
//! buffered and the streaming tail: an undeclared action, an irreversible one, a 4xx from a live
//! Averin, and params over the evidence bound (refused before the use token is consumed).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, Secret,
};

struct CountingPlugin(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Plugin for CountingPlugin {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ExecuteResponse::success(
            serde_json::to_vec(&request.params).unwrap_or_default(),
        ))
    }
    fn validate_params(&self, _: &str, _: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }
}

/// A fake Averin: `/v2/grants` answers `grant_status`; with 200 the three D8 calls succeed and
/// are counted.
async fn fake_averin(grant_status: u16) -> (String, Arc<AtomicUsize>) {
    use axum::routing::post;
    let intents = Arc::new(AtomicUsize::new(0));
    let i2 = intents.clone();
    let app = axum::Router::new()
        .route(
            "/v2/grants",
            post(move || async move {
                (
                    axum::http::StatusCode::from_u16(grant_status).unwrap(),
                    axum::Json(serde_json::json!({"grant_id": "g-1", "capability": "Y2Fw.sig"})),
                )
            }),
        )
        .route(
            "/v2/use-intent",
            post(move || {
                let i = i2.clone();
                async move {
                    i.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({"record": {"record_id": "intent-1"}}))
                }
            }),
        )
        .route(
            "/v2/use-outcome",
            post(|| async { axum::Json(serde_json::json!({"outcome_id": "outcome-1"})) }),
        )
        .route(
            "/v2/use",
            post(|| async { axum::Json(serde_json::json!({"record": {"record_id": "use-1"}})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), intents)
}

const DOWN: &str = "http://127.0.0.1:9";

struct Outcome {
    ran: bool,
    error: String,
    plugin_calls: usize,
    degraded: u64,
    uses: u32,
}

/// The Solo posture (Observe, `d8_complete_evidence` on, not strict) on the direct path.
async fn drive(
    reversibility: Option<&str>,
    averin_url: &str,
    max_seal_params_bytes: Option<usize>,
    streaming: bool,
) -> Outcome {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let storage: Arc<dyn StorageBackend> = Arc::new(
        FileStorage::new(&path, &SecretString::from("pw"))
            .await
            .unwrap(),
    );
    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    let mut averin = AverinConfig {
        enabled: true,
        base_url: averin_url.to_string(),
        resource_id: "orders-db".to_string(),
        mode: AverinMode::Observe,
        d8_complete_evidence: true,
        ..AverinConfig::default()
    };
    if let Some(cap) = max_seal_params_bytes {
        averin.max_seal_params_bytes = cap;
    }
    config.averin = averin;
    let server = VultrinoServer::new(
        config,
        storage.clone(),
        CredentialResolver::new(storage.clone()),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    server
        .plugins()
        .register(Arc::new(CountingPlugin(calls.clone())));
    storage
        .store(&Credential::new(
            "api-cred".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("secret"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        ))
        .await
        .unwrap();
    if let Some(r) = reversibility {
        storage
            .store_capability(&vultrino::capability::Capability {
                id: "cap-d8".to_string(),
                tool_name: "mock_echo".to_string(),
                description: "d8 guard fixture".to_string(),
                action: "mock.echo".to_string(),
                plugin: None,
                target: vultrino::capability::CapabilityTarget::default(),
                credential_ref: "api-cred".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                reversibility: r.to_string(),
                llm: None,
                approval_preview: None,
            })
            .await
            .unwrap();
    }
    let (_full, token) = UseToken::create(NewUseToken {
        name: "d8-guard".to_string(),
        credential_scope: "api-cred".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();
    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let request = ExecuteRequest {
        credential: "api-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"hello": "world"}),
    };
    let result: Result<(), String> = if streaming {
        match server.execute_gated_streaming(request, auth).await {
            Ok(StreamingOutcome::Streaming(mut exec)) => {
                use futures::StreamExt;
                while exec.body.next().await.is_some() {}
                Ok(())
            }
            Ok(StreamingOutcome::Pending(_)) => Err("pending".into()),
            Err(e) => Err(e.to_string()),
        }
    } else {
        server
            .execute_gated(request, auth)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    Outcome {
        ran: result.is_ok(),
        error: result.err().unwrap_or_default(),
        plugin_calls: calls.load(Ordering::SeqCst),
        degraded: server.averin().map_or(0, |a| a.metrics().d8_degraded),
        uses: storage
            .get_use_token(&token.id)
            .await
            .unwrap()
            .unwrap()
            .uses,
    }
}

/// The run was refused for `reason` (a text the error must contain), before the plugin ran.
fn refused(o: &Outcome, reason: &str) {
    assert!(!o.ran, "must refuse, ran instead");
    assert!(o.error.contains(reason), "wrong refusal, wanted {reason:?}: {}", o.error);
    assert_eq!(o.plugin_calls, 0, "the plugin must not run: {}", o.error);
    assert_eq!(o.degraded, 0);
}

#[tokio::test]
async fn reversible_with_averin_down_degrades_buffered_and_streaming() {
    for streaming in [false, true] {
        let o = drive(Some("reversible"), DOWN, None, streaming).await;
        assert!(o.ran, "{}", o.error);
        assert_eq!(
            (o.plugin_calls, o.degraded),
            (1, 1),
            "streaming={streaming}"
        );
    }
}

#[tokio::test]
async fn reversible_with_averin_overloaded_degrades() {
    let (url, _) = fake_averin(503).await;
    let o = drive(Some("reversible"), &url, None, false).await;
    assert!(o.ran, "{}", o.error);
    assert_eq!(o.degraded, 1);
}

#[tokio::test]
async fn irreversible_with_averin_down_refuses_buffered_and_streaming() {
    for streaming in [false, true] {
        // On the direct path a non-reversible action is human-floor: it goes to approval, which
        // this instance does not have, so it is refused there, before D8 is reached. The D8
        // refusal of a non-reversible action is shown on the approved resume, in
        // approval_token_integration. Either way it never runs and never degrades.
        refused(
            &drive(Some("irreversible"), DOWN, None, streaming).await,
            "requires human approval",
        );
    }
}

#[tokio::test]
async fn undeclared_with_averin_down_refuses_buffered_and_streaming() {
    for streaming in [false, true] {
        refused(
            &drive(None, DOWN, None, streaming).await,
            "D8 before-act evidence failed",
        );
    }
}

#[tokio::test]
async fn reversible_with_a_live_averin_refusing_the_grant_is_refused() {
    for streaming in [false, true] {
        let (url, intents) = fake_averin(403).await;
        let o = drive(Some("reversible"), &url, None, streaming).await;
        refused(&o, "D8 before-act evidence failed");
        assert_eq!(intents.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn reversible_with_params_over_the_evidence_bound_is_refused_before_the_token_is_spent() {
    for streaming in [false, true] {
        let (url, intents) = fake_averin(200).await;
        let o = drive(Some("reversible"), &url, Some(4), streaming).await;
        refused(&o, "evidence bound");
        assert_eq!(intents.load(Ordering::SeqCst), 0);
        assert_eq!(o.uses, 0, "an oversize body must not spend the token");
    }
}
