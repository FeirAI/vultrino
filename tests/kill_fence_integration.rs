//! The durable kill fence (P3-KILL; BACKLOG XV-03; model: govder formal/tla/KillFence.tla).
//!
//! Two `VultrinoServer`s over one encrypted vault stand in for two vultrino
//! processes (for example the web process govder halts through, and a second
//! web replica or the MCP process). Each has its own in-memory policy engine,
//! loaded once at setup and never refreshed here, which is exactly the state
//! another process is in for up to its policy refresh interval after a halt.
//! A counting plugin is the dispatch oracle: it counts every `plugin.execute`.
//!
//! Every test replays a counterexample of the model's `KillFence_today*`
//! configurations against the real execution path:
//! a halt through process A, then work on process B (or on A before its engine
//! reload) must not dispatch. Positive controls on the same fixture show the
//! oracle sees a dispatch when nothing was killed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::auth::{NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::policy::Policy;
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, StreamingOutcome, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, ExecutionOutcome,
    Secret,
};

const AGENT: &str = "agent-k";
const GATED: &str = "kf-gated";
const LIVE: &str = "kf-live";

/// Counts every dispatch (`plugin.execute`, which the default streaming adaptor
/// also calls).
struct CountingPlugin {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Plugin for CountingPlugin {
    fn name(&self) -> &str {
        "count"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["run"]
    }
    async fn execute(&self, _request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ExecuteResponse::success(b"ran".to_vec()))
    }
    fn validate_params(
        &self,
        _action: &str,
        _params: &serde_json::Value,
    ) -> Result<(), PluginError> {
        Ok(())
    }
}

struct Pair {
    a: VultrinoServer,
    b: VultrinoServer,
    storage_a: Arc<dyn StorageBackend>,
    storage_b: Arc<dyn StorageBackend>,
    calls: Arc<AtomicUsize>,
}

fn config() -> Config {
    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    // The agent is allowed by an explicit policy; everything else is denied.
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Deny;
    config.policies = vec![Policy::allow_all("base", "kf-*")];
    config
}

/// Two servers over one vault, both engines loaded once (before any halt).
async fn pair() -> Pair {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let pw = SecretString::from("test-password");
    let storage_a: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());
    let storage_b: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());

    let calls = Arc::new(AtomicUsize::new(0));
    let a = VultrinoServer::new(
        config(),
        storage_a.clone(),
        CredentialResolver::new(storage_a.clone()),
    );
    let b = VultrinoServer::new(
        config(),
        storage_b.clone(),
        CredentialResolver::new(storage_b.clone()),
    );
    for s in [&a, &b] {
        s.plugins().register(Arc::new(CountingPlugin {
            calls: calls.clone(),
        }));
    }

    for (alias, gated) in [(GATED, true), (LIVE, false)] {
        let mut cred = Credential::new(
            alias.to_string(),
            CredentialData::ApiKey {
                key: Secret::new("kill-fence-test-secret-value"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        );
        if gated {
            cred = cred.with_metadata("require_approval", "true");
        }
        storage_a.store(&cred).await.unwrap();
    }
    storage_a
        .store_capability(&vultrino::capability::Capability {
            id: "cap-kf-count-run".to_string(),
            tool_name: "count_run".to_string(),
            description: "in-process counting double; no effect outside this process".to_string(),
            action: "count.run".to_string(),
            plugin: None,
            target: vultrino::capability::CapabilityTarget::default(),
            credential_ref: "*".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            reversibility: "reversible".to_string(),
            llm: None,
            approval_preview: None,
        })
        .await
        .unwrap();
    // Both "processes" load the engine now; neither refreshes again in these tests.
    storage_b.reload().await.unwrap();
    a.reload_policies().await.unwrap();
    b.reload_policies().await.unwrap();
    Pair {
        a,
        b,
        storage_a,
        storage_b,
        calls,
    }
}

fn request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "count.run".to_string(),
        params: serde_json::json!({}),
    }
}

/// A use token bound to the agent, stored in the vault.
async fn token(storage: &Arc<dyn StorageBackend>, credential: &str) -> UseToken {
    let (_plaintext, mut token) = UseToken::create(NewUseToken {
        name: format!("kf-{credential}-{}", next()),
        credential_scope: credential.to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some(AGENT.to_string());
    storage.store_use_token(&token).await.unwrap();
    token
}

fn next() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

/// Open an approval for the agent on `server`.
async fn open_approval(server: &VultrinoServer, storage: &Arc<dyn StorageBackend>) -> String {
    let tok = token(storage, GATED).await;
    match server
        .execute_gated(request(GATED), ExecAuth::from_use_token(tok))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected a pending approval, got {other:?}"),
    }
}

async fn approve(storage: &Arc<dyn StorageBackend>, id: &str) {
    storage
        .decide_approval(
            id, true, "test", "secops", false, None, None, None, None, None,
        )
        .await
        .unwrap();
}

fn dispatches(p: &Pair) -> usize {
    p.calls.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Positive controls: the oracle sees a dispatch when nothing was killed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn control_unkilled_approval_resumes_on_the_other_process() {
    let p = pair().await;
    let id = open_approval(&p.a, &p.storage_a).await;
    approve(&p.storage_a, &id).await;
    let resumed = p.b.check_and_resume_approval(&id, None).await.unwrap();
    assert!(
        resumed.executed && resumed.result_error.is_none(),
        "{resumed:?}"
    );
    assert_eq!(dispatches(&p), 1, "the positive control must dispatch once");
}

#[tokio::test]
async fn control_unkilled_live_call_runs_on_the_other_process() {
    let p = pair().await;
    let tok = token(&p.storage_a, LIVE).await;
    let out =
        p.b.execute_gated(request(LIVE), ExecAuth::from_use_token(tok))
            .await
            .unwrap();
    assert!(matches!(out, ExecutionOutcome::Completed(_)));
    assert_eq!(dispatches(&p), 1);
}

// ---------------------------------------------------------------------------
// KillFence_today_approval: an approval pending at the halt, approved after it
// and resumed by another process whose engine has not loaded the kill.
// (Every resume path, the decision route, the result feed, an agent poll and
// MCP check_approval, runs check_and_resume_approval.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approval_resumed_on_another_process_after_a_halt_does_not_dispatch() {
    let p = pair().await;
    let id = open_approval(&p.a, &p.storage_a).await;
    p.a.halt_agent(AGENT).await.unwrap();
    approve(&p.storage_a, &id).await;

    let resumed = p.b.check_and_resume_approval(&id, None).await.unwrap();
    assert_eq!(
        dispatches(&p),
        0,
        "process B dispatched an approval of an agent halted through process A: {resumed:?}"
    );
    assert!(
        resumed.executed,
        "the refused approval is terminal: {resumed:?}"
    );
    assert!(resumed.result_error.is_some(), "{resumed:?}");
}

/// The claim itself, on the other process, finalizes the approval as refused.
#[tokio::test]
async fn claim_on_another_process_after_a_halt_is_refused_and_finalized() {
    let p = pair().await;
    let id = open_approval(&p.a, &p.storage_a).await;
    approve(&p.storage_a, &id).await;
    p.a.halt_agent(AGENT).await.unwrap();

    let claim = p.storage_b.claim_approval_for_execution(&id).await.unwrap();
    assert!(
        claim.is_none(),
        "a halted agent's approval was claimed for execution on process B"
    );
    let stored = p.storage_b.get_approval(&id).await.unwrap().unwrap();
    assert!(stored.executed && !stored.executing, "{stored:?}");
    assert!(
        stored
            .result_error
            .as_deref()
            .unwrap_or_default()
            .contains("halted"),
        "{stored:?}"
    );
    // A later resume returns the terminal record and never dispatches.
    let resumed = p.b.check_and_resume_approval(&id, None).await.unwrap();
    assert!(resumed.executed);
    assert_eq!(dispatches(&p), 0);
}

// ---------------------------------------------------------------------------
// KillFence_today: a live call (/execute, /mcp, /llm) on another process with a
// credential the halt did not revoke (a token minted after it).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_call_on_another_process_after_a_halt_does_not_dispatch() {
    let p = pair().await;
    p.a.halt_agent(AGENT).await.unwrap();
    let fresh = token(&p.storage_a, LIVE).await;

    let out =
        p.b.execute_gated(request(LIVE), ExecAuth::from_use_token(fresh))
            .await;
    assert_eq!(
        dispatches(&p),
        0,
        "process B dispatched a live call of an agent halted through process A: {out:?}"
    );
    assert!(out.is_err(), "{out:?}");
}

#[tokio::test]
async fn streamed_call_on_another_process_after_a_halt_does_not_dispatch() {
    let p = pair().await;
    p.a.halt_agent(AGENT).await.unwrap();
    let fresh = token(&p.storage_a, LIVE).await;

    let out =
        p.b.execute_gated_streaming(request(LIVE), ExecAuth::from_use_token(fresh))
            .await;
    assert_eq!(
        dispatches(&p),
        0,
        "process B streamed a call of an agent halted through process A"
    );
    assert!(
        !matches!(out, Ok(StreamingOutcome::Streaming(_))),
        "a halted agent's streamed call was served"
    );
}

// ---------------------------------------------------------------------------
// KillFence_today_one_process: one process, the kill already in the vault but
// not yet in this process's engine (the halt's store has committed, its engine
// reload has not run, or its evaluation preceded the kill).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kill_in_the_vault_but_not_in_the_engine_blocks_resume_in_the_same_process() {
    let p = pair().await;
    let id = open_approval(&p.a, &p.storage_a).await;
    approve(&p.storage_a, &id).await;
    // The halt's storage write, without the engine reload that follows it.
    p.storage_a
        .store_policy(&Policy::kill_switch(format!("halt:{AGENT}"), AGENT))
        .await
        .unwrap();

    let resumed = p.a.check_and_resume_approval(&id, None).await.unwrap();
    assert_eq!(dispatches(&p), 0, "{resumed:?}");
    assert!(
        resumed.executed && resumed.result_error.is_some(),
        "{resumed:?}"
    );
}

#[tokio::test]
async fn kill_in_the_vault_but_not_in_the_engine_blocks_a_live_call_in_the_same_process() {
    let p = pair().await;
    let tok = token(&p.storage_a, LIVE).await;
    p.storage_a
        .store_policy(&Policy::kill_switch(format!("halt:{AGENT}"), AGENT))
        .await
        .unwrap();
    let out =
        p.a.execute_gated(request(LIVE), ExecAuth::from_use_token(tok))
            .await;
    assert_eq!(dispatches(&p), 0, "{out:?}");
    assert!(out.is_err());
}

// ---------------------------------------------------------------------------
// KillFence_no_epoch: an approval opened before a kill must not run after the
// kill is lifted. Work admitted after the lift runs (control).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approval_opened_before_a_kill_does_not_run_after_the_lift() {
    let p = pair().await;
    let id = open_approval(&p.a, &p.storage_a).await;
    p.a.halt_agent(AGENT).await.unwrap();
    assert!(
        p.a.unhalt_agent(AGENT).await.unwrap(),
        "the halt was lifted"
    );
    approve(&p.storage_a, &id).await;

    let resumed = p.a.check_and_resume_approval(&id, None).await.unwrap();
    assert_eq!(
        dispatches(&p),
        0,
        "an approval opened before the kill ran after the lift: {resumed:?}"
    );
    assert!(
        resumed.executed && resumed.result_error.is_some(),
        "{resumed:?}"
    );

    // Control: an approval opened AFTER the lift runs.
    let after = open_approval(&p.a, &p.storage_a).await;
    approve(&p.storage_a, &after).await;
    let resumed = p.a.check_and_resume_approval(&after, None).await.unwrap();
    assert!(
        resumed.executed && resumed.result_error.is_none(),
        "{resumed:?}"
    );
    assert_eq!(dispatches(&p), 1);
}

#[tokio::test]
async fn approval_cannot_be_opened_for_a_halted_agent_on_another_process() {
    let p = pair().await;
    p.a.halt_agent(AGENT).await.unwrap();
    let tok = token(&p.storage_a, GATED).await;
    let out =
        p.b.execute_gated(request(GATED), ExecAuth::from_use_token(tok))
            .await;
    assert!(
        out.is_err(),
        "process B opened an approval for an agent halted through process A: {out:?}"
    );
    let open = p
        .storage_b
        .list_approvals()
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.agent_label.as_deref() == Some(AGENT))
        .count();
    assert_eq!(open, 0, "no approval may be stored for the halted agent");
}

// ---------------------------------------------------------------------------
// KillFence_today_one_process, the evaluation-to-dispatch race on ONE process:
// the work passed its policy evaluation (and, for an approval, its claim), then
// the kill lands during an await before dispatch. The await used here is the
// Averin before-act evidence write (D8), which every dispatch makes when
// `d8_complete_evidence` is on; the fake Averin stores the kill policy into the
// vault (as a halt through another process would) before it answers.
// ---------------------------------------------------------------------------

/// A fake Averin whose first `/v2/use-intent` stores the agent's halt policy into
/// the vault through its own handle, then answers like Averin.
async fn start_killing_averin(vault: Arc<dyn StorageBackend>) -> String {
    use axum::routing::post;
    #[derive(Clone)]
    struct St {
        vault: Arc<dyn StorageBackend>,
        fired: Arc<AtomicUsize>,
    }
    async fn grant() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({"grant_id": "g-1", "capability": "Y2Fw.sig"}))
    }
    async fn intent(
        axum::extract::State(st): axum::extract::State<St>,
    ) -> axum::Json<serde_json::Value> {
        if st.fired.fetch_add(1, Ordering::SeqCst) == 0 {
            st.vault
                .store_policy(&Policy::kill_switch(format!("halt:{AGENT}"), AGENT))
                .await
                .unwrap();
        }
        axum::Json(serde_json::json!({"record": {"record_id": "intent-1"}}))
    }
    async fn outcome() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({"outcome_id": "outcome-1"}))
    }
    let app = axum::Router::new()
        .route("/v2/grants", post(grant))
        .route("/v2/use-intent", post(intent))
        .route("/v2/use-outcome", post(outcome))
        .with_state(St {
            vault,
            fired: Arc::new(AtomicUsize::new(0)),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// One server with D8 evidence on, plus a separate vault handle the fake Averin
/// halts through.
async fn racing_server() -> (VultrinoServer, Arc<dyn StorageBackend>, Arc<AtomicUsize>) {
    let p = pair().await;
    let killer = p.storage_b.clone();
    let mut cfg = config();
    cfg.averin = vultrino::averin::AverinConfig {
        enabled: true,
        base_url: start_killing_averin(killer).await,
        resource_id: "kill-fence-resource".to_string(),
        d8_complete_evidence: true,
        ..vultrino::averin::AverinConfig::default()
    };
    let server = VultrinoServer::new(
        cfg,
        p.storage_a.clone(),
        CredentialResolver::new(p.storage_a.clone()),
    );
    server.plugins().register(Arc::new(CountingPlugin {
        calls: p.calls.clone(),
    }));
    server.reload_policies().await.unwrap();
    (server, p.storage_a, p.calls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_landing_after_a_resume_evaluated_blocks_its_dispatch() {
    let (server, storage, calls) = racing_server().await;
    let id = open_approval(&server, &storage).await;
    approve(&storage, &id).await;

    let resumed = server.check_and_resume_approval(&id, None).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a kill that landed after the resume's claim and policy evaluation did not stop its dispatch: {resumed:?}"
    );
    assert!(
        resumed.executed && resumed.result_error.is_some(),
        "{resumed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_landing_after_a_live_call_evaluated_blocks_its_dispatch() {
    let (server, storage, calls) = racing_server().await;
    let tok = token(&storage, LIVE).await;
    let out = server
        .execute_gated(request(LIVE), ExecAuth::from_use_token(tok))
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a kill that landed after a live call's policy evaluation did not stop its dispatch: {out:?}"
    );
    assert!(out.is_err(), "{out:?}");
}
