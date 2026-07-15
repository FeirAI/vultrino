//! End-to-end integration tests for use tokens and action approvals.
//!
//! These drive the real `VultrinoServer` execution path (`execute_gated`,
//! `run_action`, `check_and_resume_approval`) against encrypted `FileStorage`,
//! using a deterministic in-process mock plugin so nothing touches the network.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::approval::{ApprovalRequest, ApprovalStatus, Decision, NewApproval, RequesterInfo};
use vultrino::auth::{AuthResult, NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, ExecutionOutcome,
    Secret,
};

/// A deterministic plugin that echoes its params back as the response body.
struct MockPlugin;

#[async_trait]
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

/// A plugin that counts how many times `execute` is invoked, so a double-run is
/// directly observable (#8 at-most-once).
struct CountingPlugin {
    calls: Arc<std::sync::atomic::AtomicUsize>,
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
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

/// An execute request routed to [`CountingPlugin`] (`count.run`).
fn count_request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "count.run".to_string(),
        params: serde_json::json!({}),
    }
}

/// Build a server backed by fresh encrypted storage, with the mock plugin
/// registered and approvals enabled.
async fn setup() -> (VultrinoServer, Arc<dyn StorageBackend>) {
    setup_with_policies(vec![]).await
}

/// Like [`setup`] but installs the given policies on the server's policy engine
/// (so rate-limit / deny rules can be exercised end-to-end).
async fn setup_with_policies(
    policies: Vec<vultrino::policy::Policy>,
) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    // Keep the tempdir alive for the duration of the process by leaking it; the
    // OS reclaims it on exit. (Tests are short-lived.)
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.policies = policies;
    // These suites exercise tokens/approvals, not engine default-deny, so opt
    // into legacy fail-open; default-deny is covered by its own test below.
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));

    (server, storage)
}

/// Build a server in **fail-closed** (default-deny) enforcement mode with the
/// given policies, the mock plugin registered, and approvals enabled.
async fn setup_deny_mode(
    policies: Vec<vultrino::policy::Policy>,
) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Deny;
    config.policies = policies;

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));

    (server, storage)
}

/// Store a credential, optionally flagged to require approval.
async fn store_credential(storage: &Arc<dyn StorageBackend>, alias: &str, require_approval: bool) {
    let mut cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    if require_approval {
        cred = cred.with_metadata("require_approval", "true");
    }
    storage.store(&cred).await.unwrap();
}

fn echo_request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"hello": "world"}),
    }
}

// ==================== Use tokens ====================

#[tokio::test]
async fn test_single_use_token_consumed_once() {
    let (_server, storage) = setup().await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "once".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // First consume succeeds and increments.
    let consumed = storage.consume_use_token(&token.id).await.unwrap();
    assert_eq!(consumed.uses, 1);
    assert!(consumed.last_used_at.is_some());

    // Second consume is rejected — the token is exhausted.
    let err = storage.consume_use_token(&token.id).await.unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("use token"));
}

#[tokio::test]
async fn test_expired_token_cannot_be_consumed() {
    let (_server, storage) = setup().await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "expired".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: Some(Duration::seconds(-1)), // already in the past
    });
    storage.store_use_token(&token).await.unwrap();

    assert!(storage.consume_use_token(&token.id).await.is_err());
}

#[tokio::test]
async fn test_token_authorized_execution_consumes_use() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "exec-once".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let exec_auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    let outcome = server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    // The single use is now spent.
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());

    // A second attempt is denied because the token is exhausted (fail-closed).
    let exec_auth2 = ExecAuth {
        auth: Some(AuthResult::for_use_token(&after)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let err = server
        .execute_gated(echo_request("api-cred"), exec_auth2)
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("use token"));
}

#[tokio::test]
async fn test_token_credential_scope_enforced() {
    let (server, storage) = setup().await;
    store_credential(&storage, "secret-cred", false).await;

    // Token scoped to a different credential family.
    let (_full, token) = UseToken::create(NewUseToken {
        name: "scoped".to_string(),
        credential_scope: "github-*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let exec_auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    // Synthesized role scope rejects access to the out-of-scope credential, and
    // the token is NOT consumed.
    let err = server
        .execute_gated(echo_request("secret-cred"), exec_auth)
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("access denied"));
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 0);
}

/// The token's ACTION scope is enforced authoritatively in the server seam
/// (`execute_gated`), not only at the MCP/HTTP edge — defended in depth.
#[tokio::test]
async fn test_token_action_scope_enforced_at_server() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    // Token allowed only for postgres.run_sql, but the request is mock.echo.
    let (_full, token) = UseToken::create(NewUseToken {
        name: "wrong-action".to_string(),
        credential_scope: "*".to_string(),
        action_scope: Some("postgres.run_sql".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let err = server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap_err();
    assert!(format!("{}", err)
        .to_lowercase()
        .contains("not scoped to action"));
    assert_eq!(
        storage
            .get_use_token(&token.id)
            .await
            .unwrap()
            .unwrap()
            .uses,
        0
    );

    // An in-scope glob action is allowed and consumes.
    let (_f2, ok_token) = UseToken::create(NewUseToken {
        name: "ok-action".to_string(),
        credential_scope: "*".to_string(),
        action_scope: Some("mock.*".to_string()),
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&ok_token).await.unwrap();
    match server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(ok_token.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Completed(_) => {}
        _ => panic!("expected completed"),
    }
    assert_eq!(
        storage
            .get_use_token(&ok_token.id)
            .await
            .unwrap()
            .unwrap()
            .uses,
        1
    );
}

// ==================== Approvals ====================

#[tokio::test]
async fn test_credential_flag_gates_then_executes_on_approval() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await; // require_approval = true

    // 1. Request is gated — nothing runs, an approval is opened.
    let outcome = server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap();
    let approval = match outcome {
        ExecutionOutcome::Pending(a) => a,
        ExecutionOutcome::Completed(_) => panic!("expected pending approval"),
    };
    assert_eq!(approval.status, ApprovalStatus::Pending);
    assert_eq!(approval.action, "mock.echo");

    // Polling before a decision keeps it pending.
    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(polled.status, ApprovalStatus::Pending);
    assert!(!polled.executed);

    // 2. A human approves (as the admin panel / CLI would).
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored
        .approve(Decision::new("admin panel", "secops"))
        .unwrap();
    storage.update_approval(&stored).await.unwrap();

    // 3. The agent's next poll runs the action and returns the real result.
    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(resumed.status, ApprovalStatus::Approved);
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));
    assert!(resumed.result_body.as_deref().unwrap().contains("world"));
    assert!(resumed.result_error.is_none());

    // 4. Re-polling is idempotent — it does not re-run the action.
    let again = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(again.executed);
    assert_eq!(again.result_status, Some(200));
}

#[tokio::test]
async fn test_requested_outbox_event_carries_tenant_key() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await; // require_approval = true

    // Open an approval through the server — this emits the approval.requested
    // outbox event that govder's signed-webhook receiver consumes.
    let approval = match server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        ExecutionOutcome::Completed(_) => panic!("expected pending approval"),
    };
    assert_eq!(approval.status, ApprovalStatus::Pending);

    // The requested event's payload carries the `tenant` key on the wire (null for
    // this untenanted open); govder reads payload.tenant to route + seal.
    let events = storage.list_events_after(0, 100).await.unwrap();
    let requested = events
        .iter()
        .find(|e| e.event_type == vultrino::outbox::EVENT_APPROVAL_REQUESTED)
        .expect("a requested event was emitted");
    assert!(
        requested.payload.get("tenant").is_some(),
        "approval.requested carries the tenant key"
    );
    assert!(
        requested.payload["tenant"].is_null(),
        "untenanted open ⇒ tenant is null"
    );
}

#[tokio::test]
async fn test_denied_approval_never_executes() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await;

    let approval = match server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };

    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored
        .deny(Decision::new("admin panel", "secops").with_note(Some("not allowed".to_string())))
        .unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(resumed.status, ApprovalStatus::Denied);
    assert!(!resumed.executed);
    assert!(resumed.result_status.is_none());
}

#[tokio::test]
async fn test_token_force_approval_consumes_on_resume() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    // Single-use token that forces approval.
    let (_full, token) = UseToken::create(NewUseToken {
        name: "gated-token".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let exec_auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: token.require_approval,
        requester: RequesterInfo {
            principal_kind: "use_token".to_string(),
            principal_id: Some(token.id.clone()),
            principal_name: Some(token.name.clone()),
            role: None,
            owner: None,
        },
    };

    // Gated: nothing runs, token NOT yet consumed.
    let approval = match server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    assert_eq!(approval.use_token_id.as_deref(), Some(token.id.as_str()));
    let mid = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(
        mid.uses, 0,
        "token must not be consumed until the action runs"
    );

    // Approve, then resume runs the action and consumes the token.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored
        .approve(Decision::new("admin panel", "secops"))
        .unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));

    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());
}

/// A resumed approval must meter against the requesting AGENT, not the shared
/// credential alias. On the resume path the request context is rebuilt from the
/// stored approval; if its identity isn't seeded, `run_action` falls back to the
/// credential alias as the meter subject and per-agent leria budgets never see the
/// approval-gated spend (an under-count — the dangerous direction).
#[tokio::test]
async fn test_resumed_approval_meters_against_agent_not_credential() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    // A require_approval token bound to a named agent. The approval snapshots this
    // label at open; the resume must attribute the meter to it.
    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "refund-token".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    token.agent_label = Some("refund-bot".to_string());
    storage.store_use_token(&token).await.unwrap();

    // Open the approval (nothing runs yet).
    let approval = match server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected pending, got {other:?}"),
    };
    assert_eq!(
        approval.agent_label.as_deref(),
        Some("refund-bot"),
        "the approval must snapshot the requesting agent label at open"
    );

    // Human approves, agent polls → the action runs and the meter is emitted.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored
        .approve(Decision::new("admin panel", "secops"))
        .unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));

    // The meter.observed event(s) from this resume must be attributed to the AGENT,
    // never to the credential alias.
    let events = storage.list_events_after(0, 100).await.unwrap();
    let meters: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_METER_OBSERVED)
        .collect();
    assert!(
        !meters.is_empty(),
        "the resumed action must emit at least one meter.observed event"
    );
    for m in &meters {
        assert_eq!(
            m.subject, "refund-bot",
            "meter subject must be the agent label, not the credential alias; got {:?}",
            m.subject
        );
        assert_eq!(
            m.payload["principal"], "refund-bot",
            "meter payload principal must be the agent label; got {:?}",
            m.payload["principal"]
        );
        assert_ne!(
            m.subject, "api-cred",
            "meter must NOT be attributed to the credential alias (the pre-fix bug)"
        );
    }
}

/// A single-use require_approval token may have at most one *pending* approval
/// outstanding — a second open is refused, so it can't flood the approval queue.
#[tokio::test]
async fn test_single_use_token_pending_approval_bounded() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "one-pending".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // First open succeeds (one pending approval reserves the single use).
    let first = server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap();
    assert!(matches!(first, ExecutionOutcome::Pending(_)));

    // Second open is refused — no remaining capacity.
    let err = server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap_err();
    assert!(format!("{}", err)
        .to_lowercase()
        .contains("no remaining capacity"));
}

/// The bound is `uses + pending < max_uses`, so a `max_uses = 2` token may have
/// exactly two pending approvals before the third is refused (off-by-one guard).
#[tokio::test]
async fn test_pending_bound_allows_up_to_max_uses() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "two-pending".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(2),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // Two opens succeed (two pending approvals reserve the two uses).
    for _ in 0..2 {
        let outcome = server
            .execute_gated(
                echo_request("api-cred"),
                ExecAuth::from_use_token(token.clone()),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, ExecutionOutcome::Pending(_)));
    }

    // The third open is refused — capacity is fully reserved.
    let err = server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap_err();
    assert!(format!("{}", err)
        .to_lowercase()
        .contains("no remaining capacity"));
}

/// Concurrency: two opens racing on a single-use token must not both slip past
/// a stale pending count. The atomic `store_approval_reserving` guarantees at
/// most one pending approval is created (the rest get a capacity error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_pending_opens_are_bounded() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "race".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let server = Arc::new(server);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = server.clone();
        let t = token.clone();
        handles.push(tokio::spawn(async move {
            s.execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(t))
                .await
        }));
    }

    let mut pending = 0;
    let mut denied = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(ExecutionOutcome::Pending(_)) => pending += 1,
            Err(_) => denied += 1,
            Ok(other) => panic!("unexpected outcome: {:?}", other),
        }
    }
    assert_eq!(
        pending, 1,
        "exactly one pending approval may open for a single-use token"
    );
    assert_eq!(denied, 7);

    // Storage agrees: precisely one pending approval is bound to the token.
    let n = storage
        .list_approvals()
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.use_token_id.as_deref() == Some(token.id.as_str()))
        .count();
    assert_eq!(n, 1);
}

/// Regression for the resume-path policy re-eval: a human-approved action whose
/// credential is also under a tight rate-limit policy must STILL execute. The
/// request already consumed its rate-limit slot when it opened the approval, so
/// the deferred (read-only) re-evaluation must not re-charge or re-fail it.
#[tokio::test]
async fn test_approved_action_executes_despite_rate_limit() {
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition, PolicyRule};

    // Allow while within a budget of 1 request / hour; deny otherwise.
    let policy = Policy {
        id: "rl".to_string(),
        name: "rate-limit".to_string(),
        credential_pattern: "*".to_string(),
        principal_pattern: None,
        rules: vec![PolicyRule {
            condition: PolicyCondition::RateLimit {
                max: 1,
                window_secs: 3600,
            },
            action: PolicyAction::Allow,
        }],
        default_action: PolicyAction::Deny,
        kill: false,
    };
    let (server, storage) = setup_with_policies(vec![policy]).await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "rl-token".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // Open the approval. This counts the single rate-limit unit at request time.
    let approval = match server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected pending, got {:?}", other),
    };

    // Human approves out of band.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored
        .approve(Decision::new("admin panel", "secops"))
        .unwrap();
    storage.update_approval(&stored).await.unwrap();

    // Resume must NOT be denied by the now-exhausted rate budget — it executes.
    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(
        resumed.executed,
        "approved action should execute despite the rate limit"
    );
    assert_eq!(resumed.result_status, Some(200));
    assert!(resumed.result_error.is_none());
}

#[tokio::test]
async fn test_approval_expires_when_undecided() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await;

    let approval = match server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };

    // Force the TTL into the past, then poll: it should flip to Expired.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored.expires_at = chrono::Utc::now() - Duration::minutes(1);
    storage.update_approval(&stored).await.unwrap();

    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(polled.status, ApprovalStatus::Expired);
    assert!(!polled.executed);
}

/// Two `FileStorage` instances over the same file model the web + MCP processes.
/// The OS file lock must ensure a single-use token yields exactly one successful
/// consume even under concurrent cross-instance contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_single_use_atomic_across_instances() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let pw = SecretString::from("pw");

    let s1: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());
    let s2: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&path, &pw).await.unwrap());

    let (_f, token) = UseToken::create(NewUseToken {
        name: "once".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: false,
        expires_in: None,
    });
    s1.store_use_token(&token).await.unwrap();
    let id = token.id.clone();

    // Hammer the same single-use token from both instances concurrently.
    let mut handles = Vec::new();
    for s in [s1.clone(), s2.clone(), s1.clone(), s2.clone()] {
        let id = id.clone();
        handles.push(tokio::spawn(async move {
            s.consume_use_token(&id).await.is_ok()
        }));
    }
    let mut successes = 0;
    for h in handles {
        if h.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(
        successes, 1,
        "exactly one consume may succeed for a single-use token"
    );
}

/// A non-owner principal must not be able to trigger (or read) another
/// principal's approved action.
#[tokio::test]
async fn test_ownership_check_blocks_foreign_principal() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await;

    let exec_auth = ExecAuth {
        auth: None,
        use_token: None,
        force_approval: false,
        requester: RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some("owner".to_string()),
            principal_name: Some("owner-key".to_string()),
            role: None,
            owner: None,
        },
    };
    let approval = match server
        .execute_gated(echo_request("gated-cred"), exec_auth)
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage
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

    // Foreign principal: rejected, and the action must NOT have run.
    let err = server
        .check_and_resume_approval(&approval.id, Some("intruder"))
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));
    let still = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert!(!still.executed, "a foreign poll must not trigger execution");

    // The real owner can.
    let resumed = server
        .check_and_resume_approval(&approval.id, Some("owner"))
        .await
        .unwrap();
    assert!(resumed.executed);
}

/// A preflight failure (plugin not loaded) when resuming an approved action must
/// leave it retryable and must NOT burn the use token.
#[tokio::test]
async fn test_preflight_failure_is_retryable_and_does_not_burn_token() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", true).await; // require_approval

    let (_f, token) = UseToken::create(NewUseToken {
        name: "t".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // Action references a plugin that is not registered on this server.
    let req = ExecuteRequest {
        credential: "api-cred".to_string(),
        action: "ghost.do".to_string(),
        params: serde_json::json!({}),
    };
    let exec_auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: true,
        requester: RequesterInfo::default(),
    };
    let approval = match server.execute_gated(req, exec_auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage
        .decide_approval(
            &approval.id,
            true,
            "t",
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

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(!resumed.executed, "preflight failure must remain retryable");
    let tok = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(
        tok.uses, 0,
        "a preflight failure must not consume the token"
    );
}

/// A stale execution claim (a worker that set `executing` then crashed mid-flight)
/// must be recovered FAIL-CLOSED (#8): because the crashed attempt's side effect
/// may already have fired, the stale re-take must NOT re-run the action — it
/// finalizes the grant TERMINALLY as "outcome unknown", which the requester must
/// re-approve to retry. A counting plugin proves the action runs 0 additional
/// times, so at-most-once holds on the resume path even across a crash.
#[tokio::test]
async fn test_stale_execution_claim_is_terminal_not_rerun() {
    let (server, storage) = setup().await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    server.plugins().register(Arc::new(CountingPlugin {
        calls: calls.clone(),
    }));
    store_credential(&storage, "gated-cred", true).await;

    let approval = match server
        .execute_gated(count_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage
        .decide_approval(
            &approval.id,
            true,
            "t",
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

    // Simulate a worker that claimed then crashed mid-execution: `executing` set,
    // its claim aged past STALE_EXECUTING_SECS (120s), and it never finalized.
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.executing = true;
    a.executing_since = Some(chrono::Utc::now() - Duration::seconds(121));
    a.executed = false;
    storage.update_approval(&a).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();

    // The action must NOT re-run — its prior (crashed) outcome is unknown.
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a stale (crashed-worker) claim must NOT re-run the approved action"
    );
    // The grant is finalized TERMINALLY (not left executing, not a fabricated 200),
    // with an outcome-unknown error that steers the operator to re-approve.
    assert!(resumed.executed, "the stale grant is finalized (terminal)");
    assert!(!resumed.executing, "the stale claim is cleared");
    assert_eq!(
        resumed.result_status, None,
        "no fresh success may be fabricated for an unknown outcome"
    );
    assert!(
        resumed
            .result_error
            .as_deref()
            .unwrap_or_default()
            .contains("outcome unknown"),
        "the terminal error must explain the outcome is unknown; got {:?}",
        resumed.result_error
    );
}

/// A heartbeat on an in-flight claim refreshes executing_since, so a claim that
/// would otherwise look stale is NOT re-taken — protecting a slow-but-alive
/// worker from a double-run.
#[tokio::test]
async fn test_heartbeat_prevents_stale_reclaim() {
    let (server, storage) = setup().await;
    store_credential(&storage, "gated-cred", true).await;

    let approval = match server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage
        .decide_approval(
            &approval.id,
            true,
            "t",
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

    // Worker A claims, then its claim ages past the stale window...
    let claimed = storage
        .claim_approval_for_execution(&approval.id)
        .await
        .unwrap();
    assert!(claimed.is_some(), "first claim should succeed");
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.executing_since = Some(chrono::Utc::now() - Duration::seconds(300));
    storage.update_approval(&a).await.unwrap();

    // ...but a heartbeat refreshes it, so a competing claim is refused.
    storage.heartbeat_approval(&approval.id).await.unwrap();
    let reclaim = storage
        .claim_approval_for_execution(&approval.id)
        .await
        .unwrap();
    assert!(
        reclaim.is_none(),
        "a heartbeated (live) claim must not be re-taken"
    );
}

/// A use-token-gated approval whose token has become unusable by the time it is
/// approved finalizes TERMINALLY (executed, with an error) rather than telling
/// the agent to poll forever.
#[tokio::test]
async fn test_resume_with_unusable_token_is_terminal() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "gated".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        require_approval: true,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let approval = match server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(token.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage
        .decide_approval(
            &approval.id,
            true,
            "t",
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

    // Token is revoked after approval but before the agent polls to execute.
    storage.set_use_token_revoked(&token.id).await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(
        resumed.executed,
        "an unusable-token resume must be terminal, not retryable"
    );
    assert!(resumed.result_status.is_none());
    let err = resumed.result_error.unwrap().to_lowercase();
    assert!(err.contains("use token") || err.contains("revoked"));
}

#[tokio::test]
async fn test_approvals_disabled_denies_gated_action() {
    // A credential flagged for approval, but approvals disabled in config → deny.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default(); // approvals disabled by default
                                        // Opt into fail-open so the request reaches the approval gate (this test is
                                        // about approvals-disabled, not engine default-deny).
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));

    store_credential(&storage, "gated-cred", true).await;

    let err = server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("approval"));
}

#[tokio::test]
async fn test_default_deny_denies_unpolicied_credential() {
    // V2: in fail-closed mode, a credential with no matching policy is denied
    // with the distinct `no_policy` reason — the action never runs.
    let (server, storage) = setup_deny_mode(vec![]).await;
    store_credential(&storage, "api-cred", false).await;

    let err = server
        .execute_gated(echo_request("api-cred"), ExecAuth::default())
        .await
        .unwrap_err();
    match err {
        vultrino::VultrinoError::PolicyDenied(reason) => {
            assert!(
                reason.contains("no_policy"),
                "expected no_policy reason, got: {reason}"
            );
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn test_refresh_policies_once_picks_up_cross_process_write() {
    // Simulate the web writer and the MCP reader as two processes sharing one
    // vault file: a policy written by one is picked up by the other's engine on
    // a single refresh iteration (the loop the MCP server spawns).
    use vultrino::policy::{Policy, PolicyDecision, PolicyEngine};
    use vultrino::server::refresh_policies_once;
    use vultrino::RequestContext;

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let writer: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    let reader: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let engine = PolicyEngine::new();
    engine.set_default_deny(true);

    writer
        .store_policy(&Policy::allow_all("pushed", "x-*"))
        .await
        .unwrap();
    // The reader's in-memory cache is still stale (it loaded before the write).
    assert!(reader.list_stored_policies().await.unwrap().is_empty());

    refresh_policies_once(&reader, &engine, &[]).await.unwrap();
    assert!(engine.list_policies().iter().any(|p| p.name == "pushed"));
    assert_eq!(
        engine.evaluate(
            "x-1",
            Some("https://x"),
            Some("GET"),
            &RequestContext::new()
        ),
        PolicyDecision::Allow
    );

    // With a non-empty config too, the refresh→merge→engine path surfaces both.
    let cfg = Policy::allow_all("cfg-base", "c-*");
    refresh_policies_once(&reader, &engine, std::slice::from_ref(&cfg))
        .await
        .unwrap();
    let names: Vec<String> = engine.list_policies().into_iter().map(|p| p.name).collect();
    assert!(names.contains(&"cfg-base".to_string()), "{names:?}");
    assert!(names.contains(&"pushed".to_string()), "{names:?}");
    drop(dir);
}

#[tokio::test]
async fn test_refresh_auth_once_drops_revoked_key_cross_process() {
    // The web/admin process revokes a vk_ key; a sibling process (MCP, or an HA web
    // replica) that built its AuthManager at startup must stop authenticating that key
    // after one refresh tick — not only at restart. This is the API-key analogue of
    // test_refresh_policies_once_picks_up_cross_process_write above.
    use tokio::sync::RwLock;
    use vultrino::auth::AuthManager;
    use vultrino::server::refresh_auth_once;

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let writer: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    let reader: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    // Writer (admin process) mints a key against the predefined `executor` role and
    // persists it to the shared vault.
    let writer_mgr = AuthManager::new();
    let (full_key, api_key) = writer_mgr.create_api_key("ci", "executor", None).unwrap();
    writer.store_api_key(&api_key).await.unwrap();

    // Reader built its manager BEFORE the key was written — stale, so it can't see it.
    let reader_mgr = Arc::new(RwLock::new(AuthManager::from_data(
        reader.list_roles().await.unwrap(),
        reader.list_api_keys().await.unwrap(),
    )));
    assert!(reader_mgr.read().await.validate_key(&full_key).is_err());

    // One refresh tick and the reader authenticates the new key.
    refresh_auth_once(&reader, &reader_mgr).await.unwrap();
    assert!(reader_mgr.read().await.validate_key(&full_key).is_ok());

    // Writer revokes the key. The stale reader still accepts it until it refreshes —
    // exactly the pre-fix bug the periodic loop closes.
    writer.delete_api_key(&api_key.id).await.unwrap();
    assert!(reader_mgr.read().await.validate_key(&full_key).is_ok());

    // After the next tick the revoked key stops validating cross-process.
    refresh_auth_once(&reader, &reader_mgr).await.unwrap();
    assert!(
        reader_mgr.read().await.validate_key(&full_key).is_err(),
        "revoked vk_ key must stop validating after a refresh tick"
    );
    drop(dir);
}

#[tokio::test]
async fn test_deny_pushed_after_approval_blocks_resume() {
    // An allow policy + a require_approval credential opens an approval; once
    // approved, an emergency Deny is pushed and the engine reloaded (as the
    // periodic refresh would). The deferred resume re-evaluates and is blocked.
    use vultrino::policy::Policy;
    let (server, storage) = setup_deny_mode(vec![Policy::allow_all("base", "gated-*")]).await;
    store_credential(&storage, "gated-cred", true).await; // require_approval metadata

    let approval_id = match server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending, got {other:?}"),
    };
    storage
        .decide_approval(
            &approval_id,
            true,
            "approver",
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

    // Emergency Deny pushed (evaluated after the allow policy, which defaults to
    // Allow → continue → the Deny policy denies).
    storage
        .store_policy(&Policy::deny_all("kill", "gated-*"))
        .await
        .unwrap();
    server.reload_policies().await.unwrap();

    let resumed = server
        .check_and_resume_approval(&approval_id, None)
        .await
        .unwrap();
    assert!(
        resumed.result_error.is_some(),
        "a Deny pushed between approval and resume must block the approved action"
    );

    // R3: the resume-path enforce denial is a DETECT event too (kind=policy_resume)
    // — an incident first caught at resume must not be invisible to MTTD.
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == vultrino::outbox::EVENT_POLICY_DENIED
                && e.payload["kind"] == "policy_resume"
                && e.payload["credential"] == "gated-cred"),
        "a Deny re-fired at resume must emit a policy.denied detect event"
    );
}

#[tokio::test]
async fn test_reload_policies_merges_config_and_stored() {
    // The engine is the union of static config policies and admin-API-managed
    // stored policies; reload_policies() (used at startup and by the periodic
    // cross-process refresh) must surface both.
    use vultrino::policy::Policy;
    let config_policy = Policy::allow_all("from-config", "config-*");
    let (server, storage) = setup_with_policies(vec![config_policy]).await;

    // A policy pushed "via the admin API" (here: straight to storage).
    let stored = Policy::deny_all("from-admin", "admin-*");
    let stored_id = stored.id.clone();
    storage.store_policy(&stored).await.unwrap();

    server.reload_policies().await.unwrap();

    let names: Vec<String> = server
        .policy_engine()
        .list_policies()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert!(
        names.contains(&"from-config".to_string()),
        "config policy missing: {names:?}"
    );
    assert!(
        names.contains(&"from-admin".to_string()),
        "stored policy missing: {names:?}"
    );

    // Deleting the stored policy and reloading drops it but keeps config.
    storage.delete_policy(&stored_id).await.unwrap();
    server.reload_policies().await.unwrap();
    let names: Vec<String> = server
        .policy_engine()
        .list_policies()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert!(names.contains(&"from-config".to_string()));
    assert!(!names.contains(&"from-admin".to_string()));
}

#[tokio::test]
async fn test_default_deny_approved_action_still_resumes() {
    // The riskiest interaction: in deny mode, a credential matched by a Prompt
    // policy opens an approval. Once approved, resume re-evaluates policy
    // read-only — it must NOT spuriously deny the (now legitimately approved)
    // action with the no_policy fallback (the credential IS policied; it
    // matched the Prompt policy), and the action must actually run.
    use vultrino::policy::{Policy, PolicyAction};
    let mut prompt_policy = Policy::deny_all("gate-it", "gated-*");
    prompt_policy.default_action = PolicyAction::Prompt;

    let (server, storage) = setup_deny_mode(vec![prompt_policy]).await;
    store_credential(&storage, "gated-cred", false).await;

    let outcome = server
        .execute_gated(echo_request("gated-cred"), ExecAuth::default())
        .await
        .unwrap();
    let approval_id = match outcome {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending under Prompt policy, got {other:?}"),
    };

    storage
        .decide_approval(
            &approval_id,
            true,
            "test approver",
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

    let resumed = server
        .check_and_resume_approval(&approval_id, None)
        .await
        .unwrap();
    assert_eq!(resumed.status, ApprovalStatus::Approved);
    assert!(resumed.executed, "approved action must run in deny mode");
    assert!(
        resumed.result_error.is_none(),
        "resume must not be denied by default-deny: {:?}",
        resumed.result_error
    );
}

#[tokio::test]
async fn test_default_deny_allows_with_explicit_policy() {
    // With an explicit allow policy covering the credential, the same fail-closed
    // server admits and runs the action.
    use vultrino::policy::Policy;
    let (server, storage) = setup_deny_mode(vec![Policy::allow_all("allow-api", "api-*")]).await;
    store_credential(&storage, "api-cred", false).await;

    let outcome = server
        .execute_gated(echo_request("api-cred"), ExecAuth::default())
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));
}

#[tokio::test]
async fn test_spend_cap_enforced_end_to_end() {
    // V3 end-to-end: extractor reads /amount from params; a SpendCap policy caps
    // per-action at 100 usd. Within → runs; over → denied; unparseable → denied.
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition, PolicyRule, SpendExtractor};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut spend_pol = Policy::deny_all("pay-cap", "pay-*");
    spend_pol.rules = vec![PolicyRule {
        condition: PolicyCondition::SpendCap {
            asset: "usd".to_string(),
            per_action_max: 100,
        },
        action: PolicyAction::Allow,
    }];

    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.policies = vec![spend_pol];
    config.spend_extractors = vec![SpendExtractor {
        action_pattern: "mock.echo".to_string(),
        credential_pattern: "pay-*".to_string(),
        amount_pointer: "/amount".to_string(),
        asset: Some("usd".to_string()),
        asset_pointer: None,
    }];

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "pay-cred", false).await;

    let req = |amount: i64| ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": amount }),
    };

    // Within per-action cap → runs.
    assert!(matches!(
        server
            .execute_gated(req(100), ExecAuth::default())
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
    // Over per-action cap → denied (action did not run).
    assert!(matches!(
        server
            .execute_gated(req(101), ExecAuth::default())
            .await
            .unwrap_err(),
        vultrino::VultrinoError::PolicyDenied(_)
    ));
    // No extractable amount under a SpendCap policy → fail closed (denied).
    let no_amt = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "hello": "world" }),
    };
    assert!(matches!(
        server
            .execute_gated(no_amt, ExecAuth::default())
            .await
            .unwrap_err(),
        vultrino::VultrinoError::PolicyDenied(_)
    ));
}

#[tokio::test]
async fn test_per_agent_deny_end_to_end() {
    // V4 end-to-end (kill-leg W3): a Deny scoped to agent_label "refund-bot"
    // blocks only that agent's token; another agent on the same credential runs.
    use vultrino::policy::Policy;

    let deny = Policy::deny_all("kill-refund-bot", "api-*").with_principal("refund-bot");
    let (server, storage) = setup_with_policies(vec![deny]).await; // allow mode
    store_credential(&storage, "api-cred", false).await;

    let new_token = |name: &str| NewUseToken {
        name: name.to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    };
    let (_f1, mut bot_token) = UseToken::create(new_token("bot"));
    bot_token.agent_label = Some("refund-bot".to_string());
    storage.store_use_token(&bot_token).await.unwrap();
    let (_f2, other_token) = UseToken::create(new_token("other"));
    storage.store_use_token(&other_token).await.unwrap();

    // The targeted agent is denied...
    assert!(matches!(
        server
            .execute_gated(
                echo_request("api-cred"),
                ExecAuth::from_use_token(bot_token)
            )
            .await
            .unwrap_err(),
        vultrino::VultrinoError::PolicyDenied(_)
    ));
    // ...while another agent on the same credential is unaffected.
    assert!(matches!(
        server
            .execute_gated(
                echo_request("api-cred"),
                ExecAuth::from_use_token(other_token)
            )
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
}

#[tokio::test]
async fn test_per_agent_deny_refires_at_resume() {
    // V4 resume re-enforcement: an approval opened under a labeled agent is
    // BLOCKED at resume if a per-agent Deny is pushed before it runs (the
    // principal id + agent_label are recorded on the approval at open time).
    use vultrino::policy::Policy;
    let (server, storage) = setup_with_policies(vec![]).await; // allow mode
    store_credential(&storage, "api-cred", false).await;

    let (_f, mut tok) = UseToken::create(NewUseToken {
        name: "bot".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: true, // force an approval so there's a resume to gate
        expires_in: None,
    });
    tok.agent_label = Some("refund-bot".to_string());
    storage.store_use_token(&tok).await.unwrap();

    let approval_id = match server
        .execute_gated(
            echo_request("api-cred"),
            ExecAuth::from_use_token(tok.clone()),
        )
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => {
            assert_eq!(a.agent_label.as_deref(), Some("refund-bot"));
            assert_eq!(a.principal_id.as_deref(), Some(tok.id.as_str()));
            a.id
        }
        other => panic!("expected Pending, got {other:?}"),
    };

    // Push a per-agent Deny and approve; the resume must be blocked.
    storage
        .store_policy(&Policy::deny_all("kill-bot", "api-*").with_principal("refund-bot"))
        .await
        .unwrap();
    server.reload_policies().await.unwrap();
    storage
        .decide_approval(
            &approval_id,
            true,
            "approver",
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

    let resumed = server
        .check_and_resume_approval(&approval_id, None)
        .await
        .unwrap();
    assert!(
        resumed.result_error.is_some(),
        "a per-agent Deny pushed before resume must block the approved action"
    );
}

#[tokio::test]
async fn test_spend_capped_approval_resumes_without_recheck() {
    // V3 resume re-enforcement: a spend-capped, approval-gated action is checked
    // when the approval OPENS and must still resume — the read-only resume path
    // treats the per-action spend as already-admitted and must not spuriously deny
    // (it has no spend amount threaded through, which would otherwise fail closed).
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition, PolicyRule, SpendExtractor};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut spend_pol = Policy::deny_all("pay-cap", "pay-*");
    spend_pol.rules = vec![PolicyRule {
        condition: PolicyCondition::SpendCap {
            asset: "usd".to_string(),
            per_action_max: 100,
        },
        action: PolicyAction::Allow,
    }];

    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.policies = vec![spend_pol];
    config.spend_extractors = vec![SpendExtractor {
        action_pattern: "mock.echo".to_string(),
        credential_pattern: "pay-*".to_string(),
        amount_pointer: "/amount".to_string(),
        asset: Some("usd".to_string()),
        asset_pointer: None,
    }];

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "pay-cred", true).await; // require_approval

    // Within cap (60 ≤ 100): checked at open, then gated on approval.
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": 60 }),
    };
    let approval_id = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending, got {other:?}"),
    };

    // An over-cap request is denied at open (proving the per-action cap is live).
    let over = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": 101 }),
    };
    match server
        .execute_gated(over, ExecAuth::default())
        .await
        .unwrap_err()
    {
        vultrino::VultrinoError::PolicyDenied(reason) => {
            assert!(
                reason.contains("pay-cap"),
                "expected spend-cap deny, got: {reason}"
            );
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    storage
        .decide_approval(
            &approval_id,
            true,
            "approver",
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

    // Resume must succeed (read-only spend check treats it as already-admitted).
    let resumed = server
        .check_and_resume_approval(&approval_id, None)
        .await
        .unwrap();
    assert!(resumed.executed);
    assert!(
        resumed.result_error.is_none(),
        "spend-capped approval must resume: {:?}",
        resumed.result_error
    );
}

/// A plugin that reflects the injected credential's secret back in its response
/// (simulating a header-echoing endpoint) — to exercise V7 egress redaction.
struct SecretReflectorPlugin;

#[async_trait]
impl Plugin for SecretReflectorPlugin {
    fn name(&self) -> &str {
        "reflect"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["echo_secret"]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        let secrets = request.credential.data.secret_material();
        let strs: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();
        let body = format!("reflected: {}", strs.join(",")).into_bytes();
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "X-Echoed-Auth".to_string(),
            format!("Bearer {}", strs.first().copied().unwrap_or_default()),
        );
        Ok(ExecuteResponse {
            status: 200,
            headers,
            body,
            updated_credential: None,
        })
    }
    fn validate_params(&self, _a: &str, _p: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_egress_redacts_reflected_secret_end_to_end() {
    let (server, storage) = setup().await; // allow mode
    server.plugins().register(Arc::new(SecretReflectorPlugin));
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("super-secret-value"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();

    let req = ExecuteRequest {
        credential: "api-cred".to_string(),
        action: "reflect.echo_secret".to_string(),
        params: serde_json::json!({}),
    };
    let resp = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Completed(r) => r,
        other => panic!("expected Completed, got {other:?}"),
    };
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        !body.contains("super-secret-value"),
        "secret leaked in body: {body}"
    );
    assert!(body.contains("[REDACTED:api-cred]"));
    // Header reflection is scrubbed too.
    assert!(!resp
        .headers
        .get("X-Echoed-Auth")
        .unwrap()
        .contains("super-secret-value"));
}

#[tokio::test]
async fn test_egress_block_withholds_response_end_to_end() {
    use vultrino::egress::EgressRule;
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.egress = vec![EgressRule {
        credential_pattern: glob::Pattern::new("sts-*").unwrap(),
        action_pattern: glob::Pattern::new("*").unwrap(),
        block: true,
        redact_patterns: vec![],
    }];
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "sts-cred", false).await;

    let req = ExecuteRequest {
        credential: "sts-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"downstream_token": "abc123"}),
    };
    let resp = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Completed(r) => r,
        other => panic!("expected Completed, got {other:?}"),
    };
    let body = String::from_utf8_lossy(&resp.body);
    assert!(!body.contains("abc123"), "blocked body leaked: {body}");
    assert!(body.contains("withheld by egress policy"));
}

#[tokio::test]
async fn test_action_label_token_scope_and_approval_summary() {
    // V8: a token scoped to a govder action label authorizes a request that
    // presents that label (resolved to the canonical plugin.action), and the
    // approver sees the business verb.
    let dir = tempdir().unwrap(); // kept for the test's lifetime, cleaned on drop
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.action_labels =
        std::collections::HashMap::from([("payments.refund".to_string(), "mock.echo".to_string())]);
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "pay-cred", true).await; // require_approval → gates

    let (_f, token) = UseToken::create(NewUseToken {
        name: "refund".to_string(),
        credential_scope: "pay-*".to_string(),
        action_scope: Some("payments.refund".to_string()), // scoped to the LABEL
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "payments.refund".to_string(),
        params: serde_json::json!({ "amount": 10 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::from_use_token(token))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    // Canonical action recorded; the approver sees the govder business verb.
    assert_eq!(approval.action, "mock.echo");
    assert_eq!(approval.action_label.as_deref(), Some("payments.refund"));
    assert!(
        approval.summary.contains("payments.refund"),
        "summary: {}",
        approval.summary
    );
}

#[tokio::test]
async fn test_action_label_scope_isolation() {
    // V8 (negative cases — the security-critical direction): the EITHER-match
    // scope check (presented label OR resolved canonical) must NOT widen a
    // label-scoped token to (a) the raw canonical action, nor (b) a *different*
    // label that resolves to the same canonical action. And a token scoped to
    // the canonical action is intentionally broad (authorizes any label of it).
    let dir = tempdir().unwrap(); // kept for the test's lifetime, cleaned on drop
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    // Two distinct labels collapse to the same canonical action.
    config.action_labels = std::collections::HashMap::from([
        ("payments.refund".to_string(), "mock.echo".to_string()),
        ("payments.charge".to_string(), "mock.echo".to_string()),
    ]);
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "pay-cred", false).await;

    let mint = |action_scope: &str| {
        let (_f, token) = UseToken::create(NewUseToken {
            name: "t".to_string(),
            credential_scope: "pay-*".to_string(),
            action_scope: Some(action_scope.to_string()),
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });
        token
    };
    let req = |action: &str| ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: action.to_string(),
        params: serde_json::json!({ "amount": 10 }),
    };

    // (a) Label-scoped token, raw canonical action presented → DENIED: the
    //     canonical form must not satisfy a label-only scope.
    let label_tok = mint("payments.refund");
    storage.store_use_token(&label_tok).await.unwrap();
    let err = server
        .execute_gated(req("mock.echo"), ExecAuth::from_use_token(label_tok))
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "canonical action must not satisfy a label-only scope, got {err:?}"
    );

    // (b) Label-scoped token, a *different* label (same canonical) presented →
    //     DENIED: resolving to the same plugin.action must not cross labels.
    let refund_tok = mint("payments.refund");
    storage.store_use_token(&refund_tok).await.unwrap();
    let err = server
        .execute_gated(req("payments.charge"), ExecAuth::from_use_token(refund_tok))
        .await
        .unwrap_err();
    match &err {
        vultrino::VultrinoError::PolicyDenied(reason) => {
            // The diagnostic surfaces both the presented label and its canonical.
            assert!(reason.contains("payments.charge"), "reason: {reason}");
            assert!(
                reason.contains("resolved to"),
                "reason should show both forms: {reason}"
            );
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    // (c) Canonical-scoped token, label presented → ALLOWED (canonical scope is
    //     intentionally the broader form).
    let canon_tok = mint("mock.echo");
    storage.store_use_token(&canon_tok).await.unwrap();
    let outcome = server
        .execute_gated(req("payments.refund"), ExecAuth::from_use_token(canon_tok))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Completed(_)),
        "canonical-scoped token should authorize any label of it, got {outcome:?}"
    );
}

// ==================== V5: SLA escalation / approver identity / SoD ====================

/// Build a server with approvals enabled, default-allow, the mock plugin, and
/// the given approval config tweaks applied.
async fn setup_v5(
    tweak: impl FnOnce(&mut vultrino::approval::ApprovalConfig),
) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap(); // kept for the test's lifetime, cleaned on drop
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.approval.enabled = true;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    tweak(&mut config.approval);
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    (server, storage)
}

#[tokio::test]
async fn test_v5_criticality_sla_escalation_then_expiry() {
    use vultrino::approval::{CriticalityClass, CriticalityRule, CriticalitySla};

    let (server, storage) = setup_v5(|a| {
        // pay-* is Critical, with explicit 100s + 100s windows.
        a.criticality_rules = vec![CriticalityRule {
            credential_pattern: glob::Pattern::new("pay-*").unwrap(),
            action_pattern: glob::Pattern::new("*").unwrap(),
            class: CriticalityClass::Critical,
        }];
        a.sla_overrides = std::collections::HashMap::from([(
            CriticalityClass::Critical,
            CriticalitySla {
                escalate_after_secs: 100,
                escalate_window_secs: 100,
            },
        )]);
    })
    .await;
    store_credential(&storage, "pay-cred", true).await;

    // A gated request opens a Pending approval carrying the Critical SLA.
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(approval.criticality, CriticalityClass::Critical);
    assert_eq!(
        (approval.escalate_at - approval.created_at).num_seconds(),
        100
    );
    assert_eq!(
        (approval.expires_at - approval.created_at).num_seconds(),
        200
    );

    // Back-date the first window → the SLA sweep escalates it (window 1 elapsed).
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.escalate_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage.update_approval(&a).await.unwrap();
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(
        sweep.escalated.iter().any(|x| x.id == approval.id),
        "should escalate"
    );
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Escalated);
    assert!(a.escalated_at.is_some());

    // Back-date the final deadline → the next sweep expires (denies) it (window 2).
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage.update_approval(&a).await.unwrap();
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(
        sweep.expired.iter().any(|id| id == &approval.id),
        "should expire"
    );
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Expired);
}

#[tokio::test]
async fn test_v5_approver_identity_recorded_and_sod_computable() {
    let (server, storage) = setup_v5(|_| {}).await;
    store_credential(&storage, "pay-cred", true).await;

    // A request from an api-key principal named "agent-x".
    let requester = RequesterInfo {
        principal_kind: "api_key".to_string(),
        principal_id: Some("k1".to_string()),
        principal_name: Some("agent-x".to_string()),
        role: Some("executor".to_string()),
        owner: None,
    };
    let exec_auth = ExecAuth {
        auth: None,
        use_token: None,
        force_approval: false,
        requester: requester.clone(),
    };
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server.execute_gated(req, exec_auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // A blank approver identity is rejected (every decision must be attributable).
    let err = storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "  ",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err}")
            .to_lowercase()
            .contains("approver identity"),
        "got: {err}"
    );

    // Self-approval (approver == requester owner) records the identity and is a
    // computable SoD violation.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "agent-x",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.approver_identity.as_deref(), Some("agent-x"));
    assert_eq!(a.decided_by.as_deref(), Some("admin panel"));
    assert_eq!(
        a.violates_sod(),
        Some(true),
        "approver == requester → SoD violation"
    );
}

#[tokio::test]
async fn test_v5_distinct_approver_satisfies_sod() {
    let (server, storage) = setup_v5(|_| {}).await;
    store_credential(&storage, "pay-cred", true).await;

    let requester = RequesterInfo {
        principal_kind: "api_key".to_string(),
        principal_id: Some("k1".to_string()),
        principal_name: Some("agent-x".to_string()),
        role: None,
        owner: None,
    };
    let exec_auth = ExecAuth {
        auth: None,
        use_token: None,
        force_approval: false,
        requester,
    };
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server.execute_gated(req, exec_auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "secops-oncall",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(
        a.violates_sod(),
        Some(false),
        "distinct approver satisfies SoD"
    );
}

#[tokio::test]
async fn test_v5_reauth_lapse_expires_on_poll() {
    // V5: an approved-but-unrun grant whose continuous-reauth window lapsed is
    // expired on the next poll (atomically), rather than executing on a stale
    // decision — and the resume path returns Expired, not a result.
    let (server, storage) = setup_v5(|a| {
        a.reauth_interval_secs = Some(60);
    })
    .await;
    store_credential(&storage, "pay-cred", true).await;

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Approve it, then back-date the decision so the reauth window has lapsed.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
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
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.decided_at = Some(chrono::Utc::now() - chrono::Duration::seconds(120));
    storage.update_approval(&a).await.unwrap();

    // Poll: the stale grant is expired (re-auth lapsed), not executed; the
    // original approver attribution is preserved and the lapse is noted.
    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(polled.status, ApprovalStatus::Expired);
    assert!(!polled.executed, "a lapsed grant must not run");
    assert_eq!(
        polled.approver_identity.as_deref(),
        Some("secops"),
        "approver preserved"
    );
    assert!(
        polled
            .decision_note
            .as_deref()
            .unwrap_or("")
            .contains("re-authorization"),
        "lapse recorded in note, got: {:?}",
        polled.decision_note
    );
}

#[tokio::test]
async fn test_v5_enforce_sod_rejects_self_approval_end_to_end() {
    // V5: with enforce_separation_of_duty, a self-approval through the storage
    // decide path is rejected and the request stays open.
    let (server, storage) = setup_v5(|a| {
        a.enforce_separation_of_duty = true;
    })
    .await;
    store_credential(&storage, "pay-cred", true).await;

    let requester = RequesterInfo {
        principal_kind: "api_key".to_string(),
        principal_id: Some("k1".to_string()),
        principal_name: Some("agent-x".to_string()),
        role: None,
        owner: None,
    };
    let exec_auth = ExecAuth {
        auth: None,
        use_token: None,
        force_approval: false,
        requester,
    };
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server.execute_gated(req, exec_auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Self-approval is rejected (SoD enforced).
    let err = storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "agent-x",
            true,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err}")
            .to_lowercase()
            .contains("separation of duty"),
        "got: {err}"
    );
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Pending, "must stay undecided");

    // A distinct approver succeeds even with enforcement on.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "secops-oncall",
            true,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Approved);
    assert_eq!(a.violates_sod(), Some(false));
}

#[tokio::test]
async fn test_v5_decide_past_deadline_is_rejected() {
    // V5: decide_approval advances the lifecycle first, so a decision raced
    // against the final SLA deadline is rejected (expired), not accepted.
    let (server, storage) = setup_v5(|_| {}).await;
    store_credential(&storage, "pay-cred", true).await;

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Back-date the final deadline so the request is past expiry.
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage.update_approval(&a).await.unwrap();

    // The decision is refused (the request expired under the lock first); it is
    // never approved. (The rejected transaction isn't persisted, so the record
    // stays open until the next poll/sweep expires it — which we then confirm.)
    let err = storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "secops",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("expire"),
        "got: {err}"
    );
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_ne!(
        a.status,
        ApprovalStatus::Approved,
        "a past-deadline request must never approve"
    );
    // A subsequent atomic refresh expires it.
    let refreshed = storage.poll_refresh_approval(&approval.id).await.unwrap();
    assert_eq!(refreshed.status, ApprovalStatus::Expired);
}

#[tokio::test]
async fn test_v5_poll_refresh_does_not_clobber_a_decision() {
    // V5 (atomicity): the headline race fix — poll_refresh_approval re-reads the
    // authoritative state under the lock, so a committed decision is never
    // reverted to escalated/expired by a stale poll snapshot.
    let (server, storage) = setup_v5(|_| {}).await;
    store_credential(&storage, "pay-cred", true).await;

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Decide it (Approved).
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
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

    // A subsequent poll_refresh must NOT revert the decision (advance_lifecycle is
    // a no-op on a decided request), even if its boundaries are now in the past.
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.escalate_at = chrono::Utc::now() - chrono::Duration::seconds(10);
    a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);
    storage.update_approval(&a).await.unwrap();

    let refreshed = storage.poll_refresh_approval(&approval.id).await.unwrap();
    assert_eq!(
        refreshed.status,
        ApprovalStatus::Approved,
        "a decision must survive a poll"
    );
    assert_eq!(refreshed.approver_identity.as_deref(), Some("secops"));
}

#[tokio::test]
async fn test_v5_sweep_expires_reauth_lapsed_grant_preserving_approver() {
    // V5: an approved-but-unrun grant whose continuous-reauth window lapsed and
    // that nobody polls is expired by the background sweep — and the original
    // approver attribution is preserved in the audit record (the lapse is noted,
    // not overwritten with a system actor).
    let (server, storage) = setup_v5(|a| {
        a.reauth_interval_secs = Some(60);
    })
    .await;
    store_credential(&storage, "pay-cred", true).await;

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "x": 1 }),
    };
    let approval = match server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Approve as alice, then back-date the decision past the reauth window.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "alice",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.decided_at = Some(chrono::Utc::now() - chrono::Duration::seconds(120));
    storage.update_approval(&a).await.unwrap();

    // The sweep (not a poll) expires it.
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(
        sweep.expired.iter().any(|id| id == &approval.id),
        "sweep should expire it"
    );
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Expired);
    // Approver attribution preserved; lapse recorded in the note.
    assert_eq!(
        a.decided_by.as_deref(),
        Some("admin panel"),
        "original channel kept"
    );
    assert_eq!(
        a.approver_identity.as_deref(),
        Some("alice"),
        "original approver kept"
    );
    assert!(
        a.decision_note
            .as_deref()
            .unwrap_or("")
            .contains("re-authorization"),
        "lapse should be recorded in the note, got: {:?}",
        a.decision_note
    );
}

// ==================== V6: kill/halt + session registry ====================

/// A HaltCallback that records the (label, in_flight_count) it was fired with.
struct RecordingHaltCallback {
    hits: std::sync::Arc<std::sync::Mutex<Vec<(String, usize)>>>,
}

#[async_trait]
impl vultrino::session::HaltCallback for RecordingHaltCallback {
    fn name(&self) -> &str {
        "recording"
    }
    async fn on_halt(&self, agent_label: &str, in_flight: &[vultrino::session::SessionEntry]) {
        self.hits
            .lock()
            .unwrap()
            .push((agent_label.to_string(), in_flight.len()));
    }
}

#[tokio::test]
async fn test_v6_halt_revokes_tokens_installs_kill_and_fires_callback() {
    use vultrino::session::SessionEntry;

    let (server, storage) = setup().await; // allow mode
    store_credential(&storage, "api-cred", false).await;

    // A token bound to agent "bot-7".
    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "bot-token".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("bot-7".to_string());
    storage.store_use_token(&token).await.unwrap();

    let auth = || ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    // Before halt: the agent can execute.
    let outcome = server
        .execute_gated(echo_request("api-cred"), auth())
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    // Register a recording callback and pin an in-flight session for bot-7 so the
    // halt has something to report/abort.
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    server.register_halt_callback(std::sync::Arc::new(RecordingHaltCallback {
        hits: hits.clone(),
    }));
    let _inflight = server.sessions().begin(SessionEntry {
        session_id: "sess-1".to_string(),
        agent_label: Some("bot-7".to_string()),
        principal_id: Some(token.id.clone()),
        token_id: Some(token.id.clone()),
        credential: "api-cred".to_string(),
        action: "mock.echo".to_string(),
        started_at: chrono::Utc::now(),
    });

    // Halt the agent.
    let outcome = server.halt_agent("bot-7").await.unwrap();
    assert_eq!(outcome.agent_label, "bot-7");
    assert!(
        outcome.revoked_tokens.contains(&token.id),
        "agent's token revoked"
    );
    assert_eq!(outcome.deny_policy_id, "halt:bot-7");
    assert!(
        outcome.policy_active,
        "kill policy active in the live engine"
    );
    assert_eq!(outcome.callbacks_fired, 1);
    assert_eq!(
        outcome.in_flight.len(),
        1,
        "the in-flight session is reported"
    );

    // The callback was fired with the agent + its one in-flight session.
    let recorded = hits.lock().unwrap().clone();
    assert_eq!(recorded, vec![("bot-7".to_string(), 1)]);

    // The token is now revoked in storage.
    let revoked = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert!(revoked.revoked);

    // After halt: the agent's next gated call is DENIED by the kill policy, even
    // though the credential is otherwise allowed (allow mode).
    let err = server
        .execute_gated(echo_request("api-cred"), auth())
        .await
        .unwrap_err();
    match err {
        vultrino::VultrinoError::PolicyDenied(r) => assert!(r.contains("halt"), "reason: {r}"),
        other => panic!("expected PolicyDenied by kill switch, got {other:?}"),
    }

    // A different agent is unaffected: lift the halt and confirm bot-7 works again
    // (with a fresh, non-revoked token — revocation is permanent).
    assert!(server.unhalt_agent("bot-7").await.unwrap());
    let (_f2, mut t2) = UseToken::create(NewUseToken {
        name: "bot-token-2".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    t2.agent_label = Some("bot-7".to_string());
    storage.store_use_token(&t2).await.unwrap();
    let auth2 = ExecAuth {
        auth: Some(AuthResult::for_use_token(&t2)),
        use_token: Some(t2.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let outcome = server
        .execute_gated(echo_request("api-cred"), auth2)
        .await
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Completed(_)),
        "halt lifted → executes again"
    );
}

#[tokio::test]
async fn test_v6_halt_denies_approved_action_on_resume() {
    // V6 + approvals: halting an agent mid-flight (after approval, before the
    // agent polls to execute) must block the resume — a human approval is not a
    // kill bypass. Exercises the real deferred-resume path, not just the engine.
    let (server, storage) = setup().await; // allow mode
    store_credential(&storage, "api-cred", true).await; // require_approval

    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "bot".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("bot-7".to_string());
    storage.store_use_token(&token).await.unwrap();

    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let approval = match server
        .execute_gated(echo_request("api-cred"), auth)
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(approval.agent_label.as_deref(), Some("bot-7"));

    // Approve it, then halt the agent before it polls to execute.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
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
    server.halt_agent("bot-7").await.unwrap();

    // The resume re-evaluates policy and is denied by the kill switch; the action
    // does not run.
    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(
        polled
            .result_error
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains("halt"),
        "resume should be denied by the halt, got: {:?}",
        polled.result_error
    );
    assert!(
        polled.result_status.is_none(),
        "the action must not have produced a result"
    );
}

#[tokio::test]
async fn test_v6_halt_by_principal_id_for_labelless_agent() {
    // V6: an agent with no agent_label is still halt-able — by its principal id
    // (the kill policy's principal_pattern matches the principal id OR label).
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "labelless".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    // No agent_label set.
    storage.store_use_token(&token).await.unwrap();
    let auth = || ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    // A registered callback + an in-flight session keyed only by id (no label).
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    server.register_halt_callback(std::sync::Arc::new(RecordingHaltCallback {
        hits: hits.clone(),
    }));
    let _inflight = server.sessions().begin(vultrino::session::SessionEntry {
        session_id: "by-id-sess".to_string(),
        agent_label: None,
        principal_id: Some(token.id.clone()),
        token_id: Some(token.id.clone()),
        credential: "api-cred".to_string(),
        action: "mock.echo".to_string(),
        started_at: chrono::Utc::now(),
    });

    // Halt by the token's principal id → kill policy denies (leg 2), the token
    // itself is revoked (leg 1 matches by id), AND the by-id session is reported
    // to the abort callback (leg 3 matches by id, not just label).
    let outcome = server.halt_agent(&token.id).await.unwrap();
    assert!(
        outcome.revoked_tokens.contains(&token.id),
        "by-id halt revokes that token"
    );
    assert!(
        storage
            .get_use_token(&token.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(outcome.in_flight.len(), 1, "by-id session reported");
    assert_eq!(
        hits.lock().unwrap().as_slice(),
        &[(token.id.clone(), 1)],
        "leg 3 fired for by-id"
    );
    let err = server
        .execute_gated(echo_request("api-cred"), auth())
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "labelless agent halted by id"
    );
}

#[tokio::test]
async fn test_v12a_enforce_denial_emits_timestamped_detect_event() {
    // R3 (V12a): an enforce-mode denial emits a durable, signed, timestamped
    // DETECT event (policy.denied) whose created_at is a per-incident detected_at,
    // and it pairs (same subject = agent label) with the agent.halted contained_at
    // so MTTD/MTTC is computable.
    let (server, storage) = setup_deny_mode(vec![]).await; // fail-closed: no policy → deny
    store_credential(&storage, "api-cred", false).await;

    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "bot-token".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("bot-9".to_string());
    storage.store_use_token(&token).await.unwrap();
    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    // An unauthorized (default-deny) call is DENIED in enforce mode.
    let err = server
        .execute_gated(echo_request("api-cred"), auth)
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));

    // A timestamped policy.denied DETECT event was emitted, subject = agent label.
    let events = storage.list_events_after(0, 100).await.unwrap();
    let detect = events
        .iter()
        .find(|e| e.event_type == vultrino::outbox::EVENT_POLICY_DENIED)
        .expect("an enforce-mode denial must emit a policy.denied detect event");
    assert_eq!(detect.subject, "bot-9");
    assert_eq!(detect.payload["agent_label"], "bot-9");
    assert_eq!(detect.payload["kind"], "policy");
    assert_eq!(detect.payload["outcome"], "denied");
    assert_eq!(detect.payload["credential"], "api-cred");
    let detected_at = detect.created_at;

    // Contain: halting the agent emits agent.halted with the SAME subject.
    server.halt_agent("bot-9").await.unwrap();
    let events = storage.list_events_after(0, 100).await.unwrap();
    let contain = events
        .iter()
        .find(|e| e.event_type == vultrino::outbox::EVENT_AGENT_HALTED && e.subject == "bot-9")
        .expect("halt must emit agent.halted for the same subject");
    let contained_at = contain.created_at;

    // detect↔contain pair on subject, and detection precedes containment (MTTD/MTTC).
    assert_eq!(detect.subject, contain.subject);
    assert!(
        detected_at <= contained_at,
        "detected_at must not be after contained_at"
    );
}

#[tokio::test]
async fn test_v12a_cross_tenant_isolation_emits_detect_event() {
    // R3: the cross-tenant isolation deny site also emits a timestamped detect
    // event (kind = cross_tenant_isolation), not just the policy-Deny site.
    let (server, storage) = setup_tenants(false, vec![]).await; // allow mode; tenants default Enforce
                                                                // A credential tagged to team-a.
    let cred = Credential::new(
        "pay-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("tenant", "team-a");
    storage.store(&cred).await.unwrap();

    // A token in team-b attempting to use the team-a credential.
    let token = {
        let mut t = tenant_token("team-b");
        t.credential_scope = "*".to_string();
        t
    };
    storage.store_use_token(&token).await.unwrap();
    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({}),
    };
    let err = server
        .execute_gated(req, tenant_auth(&token))
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));

    let events = storage.list_events_after(0, 100).await.unwrap();
    let detect = events
        .iter()
        .find(|e| {
            e.event_type == vultrino::outbox::EVENT_POLICY_DENIED
                && e.payload["kind"] == "cross_tenant_isolation"
        })
        .expect("cross-tenant isolation must emit a policy.denied detect event");
    assert_eq!(detect.payload["credential"], "pay-cred");
    assert_eq!(detect.payload["tenant"], "team-b");
}

#[tokio::test]
async fn test_v12a_detect_events_coalesced_per_subject() {
    // R3 (perf/DoS): a denial storm must not become one signed-outbox vault write
    // per blocked call. The always-on counter still counts every attempt, but the
    // durable detect event is coalesced to one per subject per window.
    let (server, storage) = setup_deny_mode(vec![]).await; // fail-closed: no policy → deny
    store_credential(&storage, "api-cred", false).await;
    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "storm-bot".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("bot-storm".to_string());
    storage.store_use_token(&token).await.unwrap();
    let auth = || ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    for _ in 0..4 {
        let _ = server.execute_gated(echo_request("api-cred"), auth()).await;
    }
    // Every attempt is counted (the metric is not coalesced)...
    assert_eq!(server.unauthorized_attempts(), 4);
    // ...but the durable detect event is coalesced to one per subject this window.
    let events = storage.list_events_after(0, 100).await.unwrap();
    let n = events
        .iter()
        .filter(|e| {
            e.event_type == vultrino::outbox::EVENT_POLICY_DENIED && e.subject == "bot-storm"
        })
        .count();
    assert_eq!(
        n, 1,
        "detect events must coalesce per subject within the window"
    );
}

#[tokio::test(start_paused = true)]
async fn test_v6_hanging_halt_callback_does_not_block() {
    // V6: a hanging abort callback is time-bounded — the halt still completes, and
    // a fast callback registered alongside it still runs. (start_paused virtualizes
    // the timeout so the test doesn't actually wait the full timeout.)
    struct SlowCallback;
    #[async_trait]
    impl vultrino::session::HaltCallback for SlowCallback {
        fn name(&self) -> &str {
            "slow"
        }
        async fn on_halt(&self, _label: &str, _in_flight: &[vultrino::session::SessionEntry]) {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await; // hangs
        }
    }

    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred", false).await;
    let fast_hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    server.register_halt_callback(std::sync::Arc::new(SlowCallback));
    server.register_halt_callback(std::sync::Arc::new(RecordingHaltCallback {
        hits: fast_hits.clone(),
    }));

    let outcome = server.halt_agent("bot-7").await.unwrap();
    assert_eq!(outcome.callbacks_fired, 2);
    assert_eq!(
        fast_hits.lock().unwrap().len(),
        1,
        "the fast callback still ran"
    );
}

#[tokio::test]
async fn test_v6_invalid_halt_label_rejected() {
    // V6: a glob/invalid label is rejected so a halt can't accidentally deny a
    // fleet, covering metachars, path separators, empty, and the length cap.
    let (server, _storage) = setup().await;
    let too_long = "a".repeat(129);
    for bad in ["*", "bot-*", "bot?x", "bot[x]", "a/b", "", &too_long] {
        let err = server.halt_agent(bad).await.unwrap_err();
        assert!(
            matches!(err, vultrino::VultrinoError::InvalidRequest(_)),
            "label {bad:?} must be rejected"
        );
    }
}

#[tokio::test]
async fn test_v6_kill_policy_survives_cross_process_refresh() {
    // V6: a stored kill policy reloaded by another process (the periodic refresh)
    // retains kill=true and stays authoritative — guards against a serialization
    // downgrade to a plain Deny that an allow rule could override.
    use vultrino::policy::{EvalInput, PolicyDecision, PolicyEngine, Principal};

    let (_server, storage) = setup().await;
    storage
        .store_policy(&vultrino::policy::Policy::kill_switch(
            "halt:bot-7",
            "bot-7",
        ))
        .await
        .unwrap();

    // A fresh engine (as a separate process would have) picks it up via refresh.
    let engine = PolicyEngine::new();
    engine.set_default_deny(false);
    let storage_dyn: Arc<dyn StorageBackend> = storage.clone();
    vultrino::server::refresh_policies_once(&storage_dyn, &engine, &[])
        .await
        .unwrap();
    assert!(
        engine
            .list_policies()
            .iter()
            .any(|p| p.id == "halt:bot-7" && p.kill),
        "kill flag must survive the storage round-trip"
    );
    let halted = Principal {
        id: "k1".to_string(),
        agent_label: Some("bot-7".to_string()),
        owner: None,
        workload_id: None,
    };
    let decision = engine.evaluate_full(&EvalInput {
        credential_alias: "anything",
        url: None,
        method: None,
        action: None,
        principal: Some(&halted),
        spend: None,
    });
    assert!(
        matches!(decision, PolicyDecision::Deny(_)),
        "reloaded kill is authoritative"
    );
}

#[tokio::test]
async fn test_v9_lifecycle_events_emitted_to_outbox() {
    // V9: the approval lifecycle + halt emit ordered events to the signed outbox.
    let (server, storage) = setup().await; // allow mode
    store_credential(&storage, "pay-cred", true).await; // require_approval

    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "bot".to_string(),
        credential_scope: "pay-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some("bot-7".to_string());
    storage.store_use_token(&token).await.unwrap();

    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let approval = match server
        .execute_gated(echo_request("pay-cred"), auth)
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // approval.requested emitted, keyed by the approval id.
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "approval.requested" && e.subject == approval.id),
        "approval.requested emitted"
    );

    // Decide → approval.approved emitted atomically with the decision.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
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
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e.event_type == "approval.approved" && e.subject == approval.id));

    // Halt → agent.halted emitted, keyed by the agent label.
    server.halt_agent("bot-7").await.unwrap();
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e.event_type == "agent.halted" && e.subject == "bot-7"));

    // Sequences are strictly increasing and unique across all emitted events.
    let seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(seqs, sorted, "monotonic, no dupes");
}

// ==================== V12: dual-control (M-of-N) approvals ====================

#[tokio::test]
async fn test_v12_dual_control_requires_two_distinct_approvers_e2e() {
    let (server, storage) = setup().await; // allow mode
    store_credential(&storage, "pay-cred", true).await; // require_approval

    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "high-risk".to_string(),
        credential_scope: "pay-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.dual_control = true; // V8 strictness `direct` sets this
    storage.store_use_token(&token).await.unwrap();

    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    let approval = match server
        .execute_gated(echo_request("pay-cred"), auth)
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(
        approval.required_approvals, 2,
        "dual control needs 2 approvers"
    );

    // First approver → still pending (1 of 2), action must NOT run.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "alice",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Pending, "1 of 2 → still pending");
    assert_eq!(a.signoffs.len(), 1);

    // The same approver can't satisfy the second sign-off.
    let err = storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "alice",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err}")
            .to_lowercase()
            .contains("already signed off"),
        "got: {err}"
    );

    // A polling agent sees it's still pending (not executed).
    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert_eq!(polled.status, ApprovalStatus::Pending);
    assert!(!polled.executed);

    // A second DISTINCT approver meets the threshold → Approved → runs on next poll.
    storage
        .decide_approval(
            &approval.id,
            true,
            "admin panel",
            "bob",
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Approved);
    assert_eq!(a.signoffs.len(), 2);

    let polled = server
        .check_and_resume_approval(&approval.id, None)
        .await
        .unwrap();
    assert!(polled.executed, "executes once both approvers signed off");
    assert_eq!(polled.result_status, Some(200));
}

#[tokio::test]
async fn test_v12_dual_control_forces_gating_on_allow_path() {
    // V12 (critical): a dual-control token must be gated through M-of-N approval
    // EVEN when the policy allows the action and the credential does NOT require
    // approval — dual control is not bypassable on the Allow path.
    let (server, storage) = setup().await; // allow mode
    store_credential(&storage, "pay-cred", false).await; // NOT require_approval

    let (_full, mut token) = UseToken::create(NewUseToken {
        name: "high-risk".to_string(),
        credential_scope: "pay-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false, // token doesn't request approval either
        expires_in: None,
    });
    token.dual_control = true;
    storage.store_use_token(&token).await.unwrap();

    let auth = ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    };
    // Despite Allow + no require_approval, dual_control gates it.
    let outcome = server
        .execute_gated(echo_request("pay-cred"), auth)
        .await
        .unwrap();
    let approval = match outcome {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("dual_control must gate even on Allow, got {other:?}"),
    };
    assert_eq!(
        approval.effective_required_approvals(),
        2,
        "dual control needs 2 approvers"
    );
    assert!(approval.status.is_open());
}

// ==================== V11: multi-tenancy / per-team partition ====================

async fn setup_tenants(
    default_deny: bool,
    tenants: Vec<(&str, vultrino::config::TenantMode)>,
) -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    let mut config = Config::default();
    config.enforcement.default_action = if default_deny {
        vultrino::config::EnforcementDefault::Deny
    } else {
        vultrino::config::EnforcementDefault::Allow
    };
    for (id, mode) in tenants {
        config.tenants.insert(id.to_string(), mode);
    }
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    (server, storage)
}

fn tenant_token(tenant: &str) -> UseToken {
    let (_f, mut t) = UseToken::create(NewUseToken {
        name: format!("tok-{tenant}"),
        credential_scope: "*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    t.tenant = Some(tenant.to_string());
    t
}

fn tenant_auth(token: &UseToken) -> ExecAuth {
    ExecAuth {
        auth: Some(AuthResult::for_use_token(token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    }
}

#[tokio::test]
async fn test_v11_observe_mode_downgrades_deny_to_allow() {
    // One team observe-only, another enforcing, on the same vultrino.
    let (server, storage) = setup_tenants(
        true,
        vec![("team-observe", vultrino::config::TenantMode::Observe)],
    )
    .await;
    store_credential(&storage, "api-cred", false).await; // un-policied → no_policy deny

    // team-observe: the no_policy deny is downgraded — the action RUNS.
    let tb = tenant_token("team-observe");
    storage.store_use_token(&tb).await.unwrap();
    let outcome = server
        .execute_gated(echo_request("api-cred"), tenant_auth(&tb))
        .await
        .unwrap();
    assert!(
        matches!(outcome, ExecutionOutcome::Completed(_)),
        "observe tenant runs despite deny"
    );

    // An observed-denial event was emitted for visibility.
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "policy.observed_denial" && e.subject == "team-observe"),
        "observe-mode denial emitted to the outbox"
    );

    // team-enforce (default, not listed): the same deny BLOCKS.
    let ta = tenant_token("team-enforce");
    storage.store_use_token(&ta).await.unwrap();
    let err = server
        .execute_gated(echo_request("api-cred"), tenant_auth(&ta))
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "enforce tenant is blocked"
    );
}

#[tokio::test]
async fn test_v11_cross_tenant_credential_isolation() {
    // allow mode → policy never denies; isolation is the only gate here.
    let (server, storage) = setup_tenants(false, vec![]).await;

    // A credential tagged to team-a.
    let cred = Credential::new(
        "team-a-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("tenant", "team-a");
    storage.store(&cred).await.unwrap();
    // A shared (untenanted) credential.
    store_credential(&storage, "shared-cred", false).await;

    let req = |alias: &str| ExecuteRequest {
        credential: alias.to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"x": 1}),
    };

    // team-b → denied access to team-a's credential (cross-tenant isolation).
    let tb = tenant_token("team-b");
    storage.store_use_token(&tb).await.unwrap();
    let err = server
        .execute_gated(req("team-a-cred"), tenant_auth(&tb))
        .await
        .unwrap_err();
    match err {
        vultrino::VultrinoError::PolicyDenied(r) => assert!(r.contains("tenant"), "reason: {r}"),
        other => panic!("expected cross-tenant denial, got {other:?}"),
    }
    // team-b → CAN use the shared (untenanted) credential.
    assert!(matches!(
        server
            .execute_gated(req("shared-cred"), tenant_auth(&tb))
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
    // team-a → CAN use its own credential.
    let ta = tenant_token("team-a");
    storage.store_use_token(&ta).await.unwrap();
    assert!(matches!(
        server
            .execute_gated(req("team-a-cred"), tenant_auth(&ta))
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
}

#[tokio::test]
async fn test_v11_halt_is_not_downgraded_by_observe_mode() {
    // V11 critical: a V6 halt/kill switch is a security override, NOT a per-tenant
    // policy — observe mode must NOT downgrade it. A halted agent in an observe
    // tenant stays blocked.
    let (server, storage) = setup_tenants(
        false,
        vec![("team-observe", vultrino::config::TenantMode::Observe)],
    )
    .await;
    store_credential(&storage, "api-cred", false).await;

    let mut token = tenant_token("team-observe");
    token.agent_label = Some("bot-x".to_string());
    storage.store_use_token(&token).await.unwrap();

    // Sanity: without a halt, the observe tenant runs (allow mode → Allow).
    assert!(matches!(
        server
            .execute_gated(echo_request("api-cred"), tenant_auth(&token))
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));

    // Install a kill switch for bot-x; now the agent is HALTED.
    server
        .policy_engine()
        .add_policy(vultrino::policy::Policy::kill_switch("halt:bot-x", "bot-x"));

    // Even in an observe tenant, the halt is enforced — NOT observed-away.
    let err = server
        .execute_gated(echo_request("api-cred"), tenant_auth(&token))
        .await
        .unwrap_err();
    match err {
        vultrino::VultrinoError::PolicyDenied(r) => {
            assert!(
                r.contains("halt"),
                "halt must block in observe mode, got: {r}"
            )
        }
        other => panic!("a halted agent must be blocked even in an observe tenant, got {other:?}"),
    }
}

#[tokio::test]
async fn test_v11_halt_not_downgraded_for_api_key_principal() {
    // V11 critical (the worst-case variant): an API-key-authed agent has no
    // token-revocation leg, so the kill policy is its ONLY defense. Observe mode
    // must not downgrade it.
    use vultrino::auth::{ApiKey, AuthResult, Permission, Role};

    let (server, storage) = setup_tenants(
        false,
        vec![("team-observe", vultrino::config::TenantMode::Observe)],
    )
    .await;
    store_credential(&storage, "api-cred", false).await;

    let role = Role::new(
        "exec",
        [Permission::Read, Permission::Execute]
            .into_iter()
            .collect(),
    );
    let api_key = ApiKey {
        id: "vk_bot".to_string(),
        key_prefix: "vk_bot".to_string(),
        key_hash: "h".to_string(),
        name: "bot".to_string(),
        role_id: role.id.clone(),
        expires_at: None,
        created_at: chrono::Utc::now(),
        last_used_at: None,
        agent_label: None,
        owner_identity: None,
        tenant: Some("team-observe".to_string()),
        workload_id: None,
    };
    let auth = || ExecAuth {
        auth: Some(AuthResult {
            api_key: api_key.clone(),
            role: role.clone(),
        }),
        use_token: None,
        force_approval: false,
        requester: RequesterInfo::default(),
    };

    // Without a halt, the observe tenant runs (allow mode).
    assert!(matches!(
        server
            .execute_gated(echo_request("api-cred"), auth())
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));

    // Halt the API key by its id; observe must NOT downgrade it.
    server
        .policy_engine()
        .add_policy(vultrino::policy::Policy::kill_switch(
            "halt:vk_bot",
            "vk_bot",
        ));
    let err = server
        .execute_gated(echo_request("api-cred"), auth())
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "API-key agent halted by id must stay blocked in an observe tenant, got {err:?}"
    );
}

#[tokio::test]
async fn test_v11_observe_does_not_downgrade_resource_guards() {
    // V11: SpendCap / RateLimit are financial/abuse boundaries — observe mode must
    // NOT downgrade a denial for a credential under such a guard.
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition};

    let (server, storage) = setup_tenants(
        false,
        vec![("team-observe", vultrino::config::TenantMode::Observe)],
    )
    .await;
    store_credential(&storage, "api-cred", false).await;
    // A rate-limited policy: 1 request / hour, else deny (fail-closed default).
    server
        .policy_engine()
        .add_policy(Policy::deny_all("rl", "*").with_rule(
            PolicyCondition::RateLimit {
                max: 1,
                window_secs: 3600,
            },
            PolicyAction::Allow,
        ));

    let token = tenant_token("team-observe");
    storage.store_use_token(&token).await.unwrap();
    // First call is within the rate limit → allowed.
    assert!(matches!(
        server
            .execute_gated(echo_request("api-cred"), tenant_auth(&token))
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
    // Second call exceeds the limit → DENIED even in observe (resource guard).
    let err = server
        .execute_gated(echo_request("api-cred"), tenant_auth(&token))
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "a rate-limit denial must hold in observe mode, got {err:?}"
    );
}

#[tokio::test]
async fn test_v11_observe_does_not_downgrade_spend_cap() {
    // V11 (the original HIGH's core case): a SpendCap over-limit denial must hold
    // in an observe tenant — a per-action spend cap is a financial boundary, not
    // an authorization posture observe mode may wave away.
    use vultrino::policy::{Policy, PolicyAction, PolicyCondition, PolicyRule, SpendExtractor};

    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut spend_pol = Policy::deny_all("pay-cap", "pay-*");
    spend_pol.rules = vec![PolicyRule {
        condition: PolicyCondition::SpendCap {
            asset: "usd".to_string(),
            per_action_max: 100,
        },
        action: PolicyAction::Allow,
    }];

    let mut config = Config::default();
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    config.policies = vec![spend_pol];
    config.spend_extractors = vec![SpendExtractor {
        action_pattern: "mock.echo".to_string(),
        credential_pattern: "pay-*".to_string(),
        amount_pointer: "/amount".to_string(),
        asset: Some("usd".to_string()),
        asset_pointer: None,
    }];
    config.tenants.insert(
        "team-observe".to_string(),
        vultrino::config::TenantMode::Observe,
    );

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "pay-cred", false).await;

    let token = {
        let mut t = tenant_token("team-observe");
        t.credential_scope = "pay-*".to_string();
        t
    };
    storage.store_use_token(&token).await.unwrap();
    let req = |amount: i64| ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": amount }),
    };

    // Within cap → runs.
    assert!(matches!(
        server
            .execute_gated(req(100), tenant_auth(&token))
            .await
            .unwrap(),
        ExecutionOutcome::Completed(_)
    ));
    // Over the per-action cap → DENIED even in observe (resource guard, not posture).
    let err = server
        .execute_gated(req(500), tenant_auth(&token))
        .await
        .unwrap_err();
    assert!(
        matches!(err, vultrino::VultrinoError::PolicyDenied(_)),
        "an over-cap spend denial must hold in observe mode, got {err:?}"
    );
}

#[tokio::test]
async fn test_v11_approvals_are_tenant_scoped() {
    // R4: an approval is tagged with the opening principal's tenant; visibility
    // and decision are partitioned — a tenant-A admin can never see or decide a
    // tenant-B approval, while a global admin (None) sees/decides all. Parallels
    // the credential-isolation guarantee, at the approval layer.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));
    store_credential(&storage, "api-cred", true).await; // require_approval

    let ta = tenant_token("team-a");
    let tb = tenant_token("team-b");
    storage.store_use_token(&ta).await.unwrap();
    storage.store_use_token(&tb).await.unwrap();

    let a_id = match server
        .execute_gated(echo_request("api-cred"), tenant_auth(&ta))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending, got {other:?}"),
    };
    let b_id = match server
        .execute_gated(echo_request("api-cred"), tenant_auth(&tb))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Each approval is tagged with its opener's tenant.
    assert_eq!(
        storage
            .get_approval(&a_id)
            .await
            .unwrap()
            .unwrap()
            .tenant
            .as_deref(),
        Some("team-a")
    );
    assert_eq!(
        storage
            .get_approval(&b_id)
            .await
            .unwrap()
            .unwrap()
            .tenant
            .as_deref(),
        Some("team-b")
    );

    // Visibility: each tenant sees only its own; a global admin sees both.
    let a_view = server
        .list_approvals_for_tenant(Some("team-a"))
        .await
        .unwrap();
    assert_eq!(a_view.len(), 1, "team-a sees only its own approval");
    assert_eq!(a_view[0].id, a_id);
    let b_view = server
        .list_approvals_for_tenant(Some("team-b"))
        .await
        .unwrap();
    assert_eq!(b_view.len(), 1, "team-b sees only its own approval");
    assert_eq!(b_view[0].id, b_id);
    assert_eq!(
        server.list_approvals_for_tenant(None).await.unwrap().len(),
        2,
        "global admin sees both"
    );

    // Decision scoping rests on the visible_to_tenant primitive (the gate a
    // tenant-scoped admin surface uses): team-a can act on its own approval but not
    // team-b's, and a global admin (None) can act on either.
    let a = storage.get_approval(&a_id).await.unwrap().unwrap();
    let b = storage.get_approval(&b_id).await.unwrap().unwrap();
    assert!(a.visible_to_tenant(Some("team-a")), "team-a sees its own");
    assert!(
        !b.visible_to_tenant(Some("team-a")),
        "team-a must NOT see team-b's approval"
    );
    assert!(
        !a.visible_to_tenant(Some("team-b")),
        "team-b must NOT see team-a's approval"
    );
    assert!(
        a.visible_to_tenant(None) && b.visible_to_tenant(None),
        "global admin sees both"
    );
    // An untenanted (shared) approval is visible to every admin.
    let shared = ApprovalRequest::open(NewApproval {
        credential: "api-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({}),
        requester: RequesterInfo::default(),
        use_token_id: None,
        principal_id: None,
        agent_label: None,
        tenant: None,
        workload_id: None,
        preview: None,
        action_label: None,
        dual_control: false,
        criticality: vultrino::approval::CriticalityClass::Medium,
        trusted_irreversible: None,
        escalate_after: Duration::minutes(30),
        escalate_window: Duration::minutes(30),
        oob_identity: None,
        reauth_interval_secs: None,
        required_approvals: 1,
        approval_rule: None,
    })
    .0;
    assert!(shared.visible_to_tenant(Some("team-a")) && shared.visible_to_tenant(Some("team-b")));
}

// ==================== V7: OAuth rotation event + revoke-propagation ============

/// A plugin that simulates the http plugin's OAuth2 refresh: it returns an
/// `updated_credential` (a fresh token) iff the presented OAuth2 token is
/// absent/expired — exactly the condition under which the real plugin rotates —
/// so the server's persist+emit-on-rotation seam can be exercised in-process
/// (the real refresh hits an HTTPS token endpoint blocked by the SSRF guard).
struct RotatingMockPlugin;

#[async_trait]
impl Plugin for RotatingMockPlugin {
    fn name(&self) -> &str {
        "oauthmock"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::OAuth2]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["refresh"]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        let updated = match &request.credential.data {
            CredentialData::OAuth2 {
                client_id,
                client_secret,
                refresh_token,
                access_token,
                expires_at,
                token_url,
                scopes,
            } => {
                let needs_refresh = access_token.is_none()
                    || expires_at.map(|e| e <= chrono::Utc::now()).unwrap_or(false);
                needs_refresh.then(|| CredentialData::OAuth2 {
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                    refresh_token: refresh_token.clone(),
                    access_token: Some(Secret::new("fresh-access-token".to_string())),
                    expires_at: Some(chrono::Utc::now() + Duration::hours(1)),
                    token_url: token_url.clone(),
                    scopes: scopes.clone(),
                })
            }
            _ => None,
        };
        Ok(ExecuteResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: b"ok".to_vec(),
            updated_credential: updated,
        })
    }
    fn validate_params(&self, _a: &str, _p: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }
}

fn oauth_credential(alias: &str, expires_at: Option<chrono::DateTime<chrono::Utc>>) -> Credential {
    Credential::new(
        alias.to_string(),
        CredentialData::OAuth2 {
            client_id: "client".to_string(),
            client_secret: Secret::new("client-secret".to_string()),
            refresh_token: Some(Secret::new("refresh".to_string())),
            access_token: Some(Secret::new("stale-access".to_string())),
            expires_at,
            token_url: "https://idp.example.com/token".to_string(),
            scopes: vec![],
        },
    )
}

#[tokio::test]
async fn test_v7_oauth_rotation_emits_credential_rotated_event() {
    // R5(a): when the plugin refreshes an OAuth2 token, the server persists the
    // updated credential AND emits a credential.rotated event; a still-valid token
    // triggers no refresh and emits nothing.
    let (server, storage) = setup().await; // allow mode
    server.plugins().register(Arc::new(RotatingMockPlugin));

    // An expired token → the plugin rotates → credential.rotated emitted.
    let past = chrono::Utc::now() - Duration::hours(1);
    storage
        .store(&oauth_credential("oauth-cred", Some(past)))
        .await
        .unwrap();
    let req = ExecuteRequest {
        credential: "oauth-cred".to_string(),
        action: "oauthmock.refresh".to_string(),
        params: serde_json::json!({}),
    };
    let outcome = server
        .execute_gated(req, ExecAuth::default())
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    let events = storage.list_events_after(0, 100).await.unwrap();
    let rotated: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_ROTATED)
        .collect();
    assert_eq!(rotated.len(), 1, "exactly one rotation event");
    assert_eq!(rotated[0].subject, "oauth-cred");
    assert_eq!(rotated[0].payload["credential"], "oauth-cred");
    // The fresh token was persisted.
    let stored = storage.get_by_alias("oauth-cred").await.unwrap().unwrap();
    match stored.data {
        CredentialData::OAuth2 { access_token, .. } => {
            assert_eq!(access_token.unwrap().expose(), "fresh-access-token");
        }
        _ => panic!("expected OAuth2"),
    }

    // A still-valid token → no refresh → no new rotation event.
    let future = chrono::Utc::now() + Duration::hours(2);
    storage
        .store(&oauth_credential("oauth-valid", Some(future)))
        .await
        .unwrap();
    let req2 = ExecuteRequest {
        credential: "oauth-valid".to_string(),
        action: "oauthmock.refresh".to_string(),
        params: serde_json::json!({}),
    };
    server
        .execute_gated(req2, ExecAuth::default())
        .await
        .unwrap();
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        !events.iter().any(
            |e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_ROTATED
                && e.subject == "oauth-valid"
        ),
        "a still-valid token must not emit a rotation event"
    );
}

/// A RevocationClient that records every revoke call instead of hitting network.
struct RecordingRevoker {
    calls: std::sync::Mutex<Vec<(String, String, String)>>, // (url, token, hint)
}

#[async_trait]
impl vultrino::revocation::RevocationClient for RecordingRevoker {
    async fn revoke(
        &self,
        revocation_url: &str,
        token: &str,
        token_type_hint: &str,
        _client_id: &str,
        _client_secret: &str,
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push((
            revocation_url.to_string(),
            token.to_string(),
            token_type_hint.to_string(),
        ));
        Ok(())
    }
}

#[tokio::test]
async fn test_v7_revoke_propagation_calls_endpoint_and_emits_event() {
    // R5(b): deleting an OAuth2 credential that carries a revocation_url metadata
    // key propagates a revoke to the resource side (access + refresh tokens) and
    // emits a credential.revoked event. A credential without the endpoint does not.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let revoker = RecordingRevoker {
        calls: std::sync::Mutex::new(Vec::new()),
    };

    // A credential WITH a revocation endpoint → both tokens propagated + event.
    let cred = oauth_credential("oauth-prod", Some(chrono::Utc::now()))
        .with_metadata("revocation_url", "https://idp.example.com/revoke");
    storage.store(&cred).await.unwrap();
    vultrino::revocation::propagate_revoke(&revoker, &*storage, &cred).await;

    let calls = revoker.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "both access and refresh tokens revoked");
    assert!(calls
        .iter()
        .all(|(url, _, _)| url == "https://idp.example.com/revoke"));
    let hints: Vec<&str> = calls.iter().map(|(_, _, h)| h.as_str()).collect();
    assert!(hints.contains(&"access_token") && hints.contains(&"refresh_token"));
    assert!(calls.iter().any(|(_, tok, _)| tok == "stale-access"));

    let events = storage.list_events_after(0, 100).await.unwrap();
    let revoked: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_REVOKED)
        .collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].subject, "oauth-prod");

    // A credential WITHOUT a revocation endpoint → nothing propagated, no event.
    let revoker2 = RecordingRevoker {
        calls: std::sync::Mutex::new(Vec::new()),
    };
    let plain = oauth_credential("oauth-noendpoint", Some(chrono::Utc::now()));
    storage.store(&plain).await.unwrap();
    vultrino::revocation::propagate_revoke(&revoker2, &*storage, &plain).await;
    assert!(
        revoker2.calls.lock().unwrap().is_empty(),
        "no endpoint → no revoke call"
    );
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        !events.iter().any(
            |e| e.event_type == vultrino::outbox::EVENT_CREDENTIAL_REVOKED
                && e.subject == "oauth-noendpoint"
        ),
        "no endpoint → no credential.revoked event"
    );
}

// ==================== V13a — meter.observed (leria metering plane) ====================
//
// V13a emits exactly one signed `meter.observed` MeterEvent (asset=api-calls,
// amount=1, cost_source=gateway-observed) onto the existing V9 signed outbox on
// every ADMITTED `/execute`, off the latency path. leria's gateway-observed cost
// source polls these via `GET /api/v1/events?after=N` (the v1 subscriber
// decision). These tests drive the real `execute_gated`/`run_action` path and
// read back through `list_events_after` — the exact data source the AdminApiAuth-
// gated `api_list_events` handler serves (it is a thin pass-through to this call).

/// Collect every `meter.observed` event currently in the outbox.
async fn meter_events(storage: &Arc<dyn StorageBackend>) -> Vec<vultrino::outbox::OutboxEvent> {
    storage
        .list_events_after(0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_METER_OBSERVED)
        .collect()
}

/// Store a credential, optionally tagged with a V11 tenant.
async fn store_tenanted_credential(
    storage: &Arc<dyn StorageBackend>,
    alias: &str,
    tenant: Option<&str>,
) {
    let mut cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("super-secret-key-material"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    if let Some(t) = tenant {
        cred = cred.with_metadata("tenant", t);
    }
    storage.store(&cred).await.unwrap();
}

/// Mint + store a use token bound to an agent label / tenant, returning an
/// `ExecAuth` for it (so the resolved principal carries V4 `agent_label` + V11
/// `tenant`).
async fn auth_for_agent(
    storage: &Arc<dyn StorageBackend>,
    agent_label: &str,
    tenant: Option<&str>,
) -> ExecAuth {
    let (_full, mut token) = UseToken::create(NewUseToken {
        name: format!("tok-{agent_label}"),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: None,
        require_approval: false,
        expires_in: None,
    });
    token.agent_label = Some(agent_label.to_string());
    token.tenant = tenant.map(|t| t.to_string());
    storage.store_use_token(&token).await.unwrap();
    ExecAuth {
        auth: Some(AuthResult::for_use_token(&token)),
        use_token: Some(token.clone()),
        force_approval: false,
        requester: RequesterInfo::default(),
    }
}

#[tokio::test]
async fn test_v13a_admitted_execute_emits_one_meter_observed() {
    // Acceptance 1: every admitted /execute emits exactly one signed
    // meter.observed with asset=api-calls, amount=1, principal=agent_label,
    // correlation_id=request id, cost_source=gateway-observed.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_refund_bot_v3", None).await;

    let outcome = server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .unwrap();
    let resp = match outcome {
        ExecutionOutcome::Completed(r) => r,
        other => panic!("expected Completed, got {other:?}"),
    };

    let metered = meter_events(&storage).await;
    assert_eq!(
        metered.len(),
        1,
        "exactly one meter.observed per admitted action"
    );
    let e = &metered[0];
    // The subject (outbox ordering key) is the principal — the V4 agent label.
    assert_eq!(e.subject, "agent_refund_bot_v3");
    let p = &e.payload;
    assert_eq!(p["asset"], "api-calls");
    assert_eq!(p["amount"], 1);
    assert_eq!(p["cost_source"], "gateway-observed");
    assert_eq!(p["confidence"], "low");
    assert_eq!(p["principal"], "agent_refund_bot_v3");
    // event_id == correlation_id == the /execute request id, and they are a real
    // id, not empty. event_id is leria's hard-required wire dedup key.
    let req_id = p["event_id"].as_str().unwrap();
    assert!(!req_id.is_empty(), "event_id must be the request id");
    assert_eq!(p["correlation_id"].as_str().unwrap(), req_id);
    assert!(
        p["occurred_at"].is_string(),
        "occurred_at is the action timestamp"
    );
    // dims carries the credential alias; tenant omitted when the credential is
    // untenanted (no phantom keys).
    assert_eq!(p["dims"]["credential"], "api-cred");
    assert!(
        p["dims"].get("tenant").is_none(),
        "untenanted → no tenant dim"
    );
    assert!(
        p["dims"].get("model").is_none(),
        "V13a does not parse the body → no model"
    );

    // The action itself still succeeded.
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn test_v13a_principal_falls_back_to_id_then_alias() {
    // The principal is agent_label, else the vk_/vut_ id, else the credential
    // alias. An unauthenticated (no-auth) admitted call (Allow default-action,
    // no policy denial) has neither agent_label nor api_key_id → falls back to
    // the credential alias as the subject/principal.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;

    // ExecAuth::default() = no auth; setup() runs in Allow mode so this is
    // admitted and executes.
    let outcome = server
        .execute_gated(echo_request("api-cred"), ExecAuth::default())
        .await
        .unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    let metered = meter_events(&storage).await;
    assert_eq!(metered.len(), 1);
    assert_eq!(metered[0].payload["principal"], "api-cred");
    assert_eq!(metered[0].subject, "api-cred");
}

#[tokio::test]
async fn test_v13a_denied_action_emits_no_meter_observed() {
    // Acceptance 1 (deny half): a denied action emits NO meter.observed (the emit
    // is on the post-admission path, which a denial never reaches).
    let (server, storage) = setup_deny_mode(vec![]).await; // default-deny, no policy
    store_credential(&storage, "api-cred", false).await;

    let err = server
        .execute_gated(echo_request("api-cred"), ExecAuth::default())
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));

    assert!(
        meter_events(&storage).await.is_empty(),
        "denied → no meter.observed"
    );
}

#[tokio::test]
async fn test_v13a_replay_dedups_by_event_id() {
    // Acceptance 2: a replay of the same /execute (same request_id) dedups by
    // event_id. vultrino assigns a fresh request_id per execute_gated, so
    // two distinct executes are two distinct occurrences (two events, two keys) —
    // the dedup contract is that the SAME request_id yields the SAME
    // event_id, which is leria's dedup key. We assert the key IS the
    // request id (so leria can dedup), and that two genuinely-distinct calls
    // carry two distinct keys (no spurious collision).
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;

    let auth1 = auth_for_agent(&storage, "agent_a", None).await;
    server
        .execute_gated(echo_request("api-cred"), auth1)
        .await
        .unwrap();
    let auth2 = auth_for_agent(&storage, "agent_a", None).await;
    server
        .execute_gated(echo_request("api-cred"), auth2)
        .await
        .unwrap();

    let metered = meter_events(&storage).await;
    assert_eq!(metered.len(), 2, "two distinct calls → two occurrences");
    let key1 = metered[0].payload["event_id"].as_str().unwrap();
    let key2 = metered[1].payload["event_id"].as_str().unwrap();
    assert_ne!(
        key1, key2,
        "distinct calls → distinct event_id keys (no collision)"
    );
    // Within one event, the dedup handle IS the per-occurrence id (== correlation_id
    // == the /execute request id), so leria dedups a re-arrival of the SAME request
    // id and threads the SAME occurrence across sources.
    assert_eq!(metered[0].payload["correlation_id"].as_str().unwrap(), key1);
    assert_eq!(metered[1].payload["correlation_id"].as_str().unwrap(), key2);
}

#[tokio::test]
async fn test_v13a_emit_is_off_the_latency_path_outage_does_not_fail_execute() {
    // Acceptance 3: the emit is best-effort/off the latency path — a leria/outbox
    // outage must NOT fail /execute. emit_event swallows append failures by
    // contract; the observable guarantee is that the action SUCCEEDS regardless of
    // the event log. We assert the admitted action completes (its result is the
    // source of truth) — i.e. an event-log problem never propagates to the caller.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_x", None).await;

    // The action completes (the emit, whatever its fate, is downstream of the
    // committed action and never turned into a caller-facing error).
    let outcome = server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .expect("an event-log/outbox problem must never fail /execute");
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));
}

#[tokio::test]
async fn test_v13a_event_carries_no_secret_and_hmac_verifies() {
    // Acceptance 4: no body/prompt/secret in the event; the Govder-Signature HMAC
    // verifies over the delivery body; a tampered event is rejectable.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_y", None).await;

    server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .unwrap();

    let metered = meter_events(&storage).await;
    assert_eq!(metered.len(), 1);
    let e = &metered[0];

    // No secret material / prompt / response body anywhere in the serialized event.
    let serialized = serde_json::to_string(&e.payload).unwrap();
    assert!(
        !serialized.contains("super-secret-key-material"),
        "credential secret must never ride the meter event: {serialized}"
    );
    assert!(
        !serialized.contains("hello") && !serialized.contains("world"),
        "request/response body must never ride the meter event: {serialized}"
    );

    // The delivery body is the exact envelope the poll path (api_list_events) and
    // a push delivery both sign. The Govder-Signature HMAC verifies, and any
    // tamper invalidates it (so leria rejects a spoofed/replayed-with-edits event).
    let secret = "leria-shared-signing-secret";
    let body = e.delivery_body();
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = vultrino::outbox::sign_body(secret, &bytes);
    assert!(sig.starts_with("sha256="));
    // A verifier recomputes the same signature over the same bytes.
    assert_eq!(sig, vultrino::outbox::sign_body(secret, &bytes));
    // Tamper the amount (1 → 1_000_000) → signature no longer matches.
    let mut tampered = body.clone();
    tampered["payload"]["amount"] = serde_json::json!(1_000_000);
    let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
    assert_ne!(
        sig,
        vultrino::outbox::sign_body(secret, &tampered_bytes),
        "a tampered meter event must fail signature verification"
    );
    // A wrong secret also fails (the HMAC is keyed).
    assert_ne!(sig, vultrino::outbox::sign_body("wrong-secret", &bytes));
}

#[tokio::test]
async fn test_v13a_carries_correct_tenant_and_never_crosses_tenants() {
    // Acceptance 5: the event carries the correct V11 tenant in dims; a meter
    // event never crosses tenants. Two tenants, two principals, two tenanted
    // credentials → each meter event carries its own tenant only.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "cred-acme", Some("acme")).await;
    store_tenanted_credential(&storage, "cred-globex", Some("globex")).await;

    let auth_acme = auth_for_agent(&storage, "agent_acme", Some("acme")).await;
    server
        .execute_gated(echo_request("cred-acme"), auth_acme)
        .await
        .unwrap();

    let auth_globex = auth_for_agent(&storage, "agent_globex", Some("globex")).await;
    server
        .execute_gated(echo_request("cred-globex"), auth_globex)
        .await
        .unwrap();

    let metered = meter_events(&storage).await;
    assert_eq!(metered.len(), 2);
    let acme = metered
        .iter()
        .find(|e| e.payload["dims"]["credential"] == "cred-acme")
        .expect("acme meter event");
    let globex = metered
        .iter()
        .find(|e| e.payload["dims"]["credential"] == "cred-globex")
        .expect("globex meter event");
    assert_eq!(acme.payload["dims"]["tenant"], "acme");
    assert_eq!(globex.payload["dims"]["tenant"], "globex");
    // No cross-contamination: acme's event never mentions globex and vice versa.
    assert_ne!(acme.payload["dims"]["tenant"], "globex");
    assert_ne!(globex.payload["dims"]["tenant"], "acme");
}

#[tokio::test]
async fn test_v13a_cross_tenant_denial_emits_no_meter_observed() {
    // V11 isolation half of acceptance 5: a principal in tenant `acme` trying to
    // use a `globex`-tagged credential is denied at the isolation gate (before
    // admission) → NO meter event (a meter event never attributes a cross-tenant
    // use).
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "cred-globex", Some("globex")).await;

    let auth_acme = auth_for_agent(&storage, "agent_acme", Some("acme")).await;
    let err = server
        .execute_gated(echo_request("cred-globex"), auth_acme)
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));

    assert!(
        meter_events(&storage).await.is_empty(),
        "cross-tenant denial → no meter.observed (no cross-tenant attribution)"
    );
}

#[tokio::test]
async fn test_v13a_meter_observed_retrievable_via_poll_path() {
    // Acceptance 6: meter.observed is retrievable via the poll path leria uses
    // (`api_list_events` → `list_events_after`), gap-free by sequence. We drive
    // two admitted actions and replay from a cursor exactly as leria would,
    // asserting the cursor semantics + the signed delivery envelope.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", Some("acme")).await;

    let auth1 = auth_for_agent(&storage, "agent_a", Some("acme")).await;
    server
        .execute_gated(echo_request("api-cred"), auth1)
        .await
        .unwrap();
    let auth2 = auth_for_agent(&storage, "agent_b", Some("acme")).await;
    server
        .execute_gated(echo_request("api-cred"), auth2)
        .await
        .unwrap();

    // leria's first poll: from cursor 0.
    let page1 = storage.list_events_after(0, 1000).await.unwrap();
    let meter: Vec<_> = page1
        .iter()
        .filter(|e| e.event_type == vultrino::outbox::EVENT_METER_OBSERVED)
        .collect();
    assert_eq!(meter.len(), 2, "both admitted actions are pollable");
    // Sequences are monotonic + gap-free.
    assert!(meter[0].sequence < meter[1].sequence);

    // leria resumes from its last-seen sequence → strictly-after, no dupes.
    let last_seen = meter[0].sequence;
    let page2 = storage.list_events_after(last_seen, 1000).await.unwrap();
    assert!(
        page2.iter().all(|e| e.sequence > last_seen),
        "replay is strictly after the cursor (gap-free, no dupes)"
    );
    assert!(
        page2.iter().any(|e| e.sequence == meter[1].sequence),
        "the second meter event is picked up on the next poll"
    );

    // The poll path returns the same signed envelope a push delivery carries: the
    // delivery_body + Govder-Signature (what api_list_events emits when a secret
    // is configured), so leria verifies a replayed event exactly like a pushed one.
    let secret = "leria-shared-signing-secret";
    let body = meter[1].delivery_body();
    assert_eq!(body["event"], "meter.observed");
    assert_eq!(body["payload"]["asset"], "api-calls");
    let sig = vultrino::outbox::sign_body(secret, &serde_json::to_vec(&body).unwrap());
    assert!(sig.starts_with("sha256="));
}

// ==================== V13b — token meter.observed (leria pricing input) ========
//
// V13b emits a SECOND `meter.observed` event for a non-streamed LLM response that
// carries a provider usage block: `asset=usd` + a `tokens{input,output}` split +
// `dims.model_ref`, SAME correlation_id as the V13a `api-calls=1` event. vultrino
// sends COUNTS, not dollars — leria mints usd from the tokens via its RateCard.
// The MockPlugin echoes its params as the response body, so a request whose params
// are an OpenAI/Anthropic-style response drive the raw-body usage parser end-to-end.

/// Collect every `meter.observed` event whose payload is a TOKEN event (asset=usd
/// + a tokens split) — i.e. the V13b second event, not the V13a api-calls=1 one.
fn is_token_event(e: &vultrino::outbox::OutboxEvent) -> bool {
    e.event_type == vultrino::outbox::EVENT_METER_OBSERVED
        && e.payload["asset"] == "usd"
        && e.payload.get("tokens").is_some()
}

/// An /execute whose echoed response body is an OpenAI-style completion carrying a
/// `usage` block. The MockPlugin echoes params → the response body IS this JSON.
fn openai_usage_request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({
            "id": "cmpl-xyz",
            "model": "gpt-4o-2024-08-06",
            "choices": [{"text": "the secret answer"}],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 345, "total_tokens": 1545}
        }),
    }
}

/// An /execute whose echoed response body is an Anthropic-style message carrying a
/// `usage` block.
fn anthropic_usage_request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({
            "id": "msg_abc",
            "model": "claude-opus-4-20260101",
            "content": [{"type": "text", "text": "the secret answer"}],
            "usage": {"input_tokens": 5000, "output_tokens": 900}
        }),
    }
}

#[tokio::test]
async fn test_v13b_openai_usage_emits_token_event_alongside_api_calls() {
    // Acceptance: a non-streamed response with an OpenAI-style usage block emits a
    // 2nd meter.observed (asset=usd + tokens{input,output} + dims.model_ref +
    // correlation_id == the V13a event), in ADDITION to the V13a api-calls=1 event.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", Some("acme")).await;
    let exec_auth = auth_for_agent(&storage, "agent_llm", Some("acme")).await;

    server
        .execute_gated(openai_usage_request("api-cred"), exec_auth)
        .await
        .unwrap();

    let all = meter_events(&storage).await;
    // Two meter events for the one call: the V13a api-calls=1 and the V13b token.
    assert_eq!(
        all.len(),
        2,
        "one admitted LLM call → V13a + V13b meter events"
    );
    let api = all
        .iter()
        .find(|e| e.payload["asset"] == "api-calls")
        .expect("the V13a api-calls event");
    let tok = all
        .iter()
        .find(|e| is_token_event(e))
        .expect("the V13b token event");

    // The token event prices via leria's rate card: asset=usd + a tokens split,
    // NO amount (leria mints usd from the counts).
    assert_eq!(tok.payload["asset"], "usd");
    assert_eq!(tok.payload["tokens"]["input_tokens"], 1200);
    assert_eq!(tok.payload["tokens"]["output_tokens"], 345);
    assert!(
        tok.payload.get("amount").is_none(),
        "a priced token event must NOT carry an amount (leria rejects ambiguous_amount)"
    );
    // The model the provider served selects the rate card.
    assert_eq!(tok.payload["dims"]["model_ref"], "gpt-4o-2024-08-06");
    assert_eq!(tok.payload["cost_source"], "gateway-observed");
    assert_eq!(tok.payload["confidence"], "low");
    // dims carry the same tenant + credential as the V13a event.
    assert_eq!(tok.payload["dims"]["tenant"], "acme");
    assert_eq!(tok.payload["dims"]["credential"], "api-cred");

    // SAME correlation_id (the occurrence handle threads both observations onto the
    // same call) but a DISTINCT event_id: the token event's dedup key is the request
    // id + ":tokens", so leria does NOT classify it as a dup-mismatch of the
    // api-calls=1 event (which uses the bare request id as its event_id, with a
    // different resolved amount).
    assert_eq!(
        tok.payload["correlation_id"], api.payload["correlation_id"],
        "the token event shares the V13a correlation_id (same call)"
    );
    let api_eid = api.payload["event_id"].as_str().unwrap();
    assert_eq!(tok.payload["event_id"], format!("{api_eid}:tokens"));
    assert_ne!(
        tok.payload["event_id"], api.payload["event_id"],
        "the token event has a DISTINCT dedup key from the api-calls event"
    );
    assert_eq!(tok.payload["principal"], api.payload["principal"]);
}

#[tokio::test]
async fn test_v13b_anthropic_usage_parsed() {
    // Acceptance: an Anthropic-style usage block (input_tokens/output_tokens) is
    // parsed too, producing the same priced shape.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_llm", None).await;

    server
        .execute_gated(anthropic_usage_request("api-cred"), exec_auth)
        .await
        .unwrap();

    let tok = meter_events(&storage)
        .await
        .into_iter()
        .find(is_token_event)
        .expect("the V13b token event from an Anthropic usage block");
    assert_eq!(tok.payload["asset"], "usd");
    assert_eq!(tok.payload["tokens"]["input_tokens"], 5000);
    assert_eq!(tok.payload["tokens"]["output_tokens"], 900);
    assert_eq!(tok.payload["dims"]["model_ref"], "claude-opus-4-20260101");
}

#[tokio::test]
async fn test_v13b_no_usage_block_emits_only_api_calls() {
    // Acceptance: a response with NO usage block (a streamed response without a
    // usage trailer, or a non-LLM action — the echo_request body is {"hello":...})
    // emits ONLY the V13a api-calls=1 event, no token event. This is the stated
    // non-streaming-only v1 limitation.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_plain", None).await;

    server
        .execute_gated(echo_request("api-cred"), exec_auth)
        .await
        .unwrap();

    let all = meter_events(&storage).await;
    assert_eq!(
        all.len(),
        1,
        "no usage block → only the V13a api-calls event"
    );
    assert_eq!(all[0].payload["asset"], "api-calls");
    assert!(
        !all.iter().any(is_token_event),
        "no token event when there is no parseable usage block"
    );
}

#[tokio::test]
async fn test_v13b_token_read_is_from_raw_body_before_egress_redaction() {
    // Acceptance: the token count is read from the RAW body BEFORE scrub_response —
    // a response that egress WOULD redact still yields the CORRECT count (no
    // under-count, the dangerous direction). We configure an egress redact rule
    // that would rewrite the usage numbers in the agent-visible body; the meter
    // event must still carry the original counts (proving the pre-scrub read).
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let mut config = Config::default();
    config.approval.enabled = true;
    config.approval.ttl_secs = 3600;
    config.enforcement.default_action = vultrino::config::EnforcementDefault::Allow;
    // An egress redact rule that rewrites any run of digits in the body — this
    // would corrupt the usage counts if the meter read happened post-scrub. Built
    // through the real config parse path (compiles glob + regex) so the test uses
    // the same compiled `EgressRule` production does.
    config.egress = Config::parse(
        "[[egress]]\ncredential_pattern = \"*\"\naction_pattern = \"*\"\nredact_patterns = [\"\\\\d+\"]\n",
    )
    .expect("egress rule parses")
    .egress;

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(config, storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));

    store_tenanted_credential(&storage, "api-cred", None).await;
    let exec_auth = auth_for_agent(&storage, "agent_llm", None).await;

    let outcome = server
        .execute_gated(openai_usage_request("api-cred"), exec_auth)
        .await
        .unwrap();
    let resp = match outcome {
        ExecutionOutcome::Completed(r) => r,
        other => panic!("expected Completed, got {other:?}"),
    };
    // Sanity: the agent-visible body WAS redacted (the digits are gone), so a
    // post-scrub read would have under-counted.
    let agent_body = String::from_utf8_lossy(&resp.body);
    assert!(
        agent_body.contains("[REDACTED:egress]"),
        "the egress rule must have redacted the agent-visible body: {agent_body}"
    );
    assert!(
        !agent_body.contains("1200"),
        "the original count is redacted from the agent body"
    );

    // The meter event nonetheless carries the CORRECT pre-scrub counts.
    let tok = meter_events(&storage)
        .await
        .into_iter()
        .find(is_token_event)
        .expect("the V13b token event");
    assert_eq!(
        tok.payload["tokens"]["input_tokens"], 1200,
        "the token count is read pre-scrub (no under-count from egress redaction)"
    );
    assert_eq!(tok.payload["tokens"]["output_tokens"], 345);
    assert_eq!(tok.payload["dims"]["model_ref"], "gpt-4o-2024-08-06");
}

#[tokio::test]
async fn test_v13b_denied_action_emits_no_token_event() {
    // A denied action emits neither the V13a nor the V13b event (the emit is on
    // the post-admission path a denial never reaches).
    let (server, storage) = setup_deny_mode(vec![]).await;
    store_credential(&storage, "api-cred", false).await;

    let err = server
        .execute_gated(openai_usage_request("api-cred"), ExecAuth::default())
        .await
        .unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)));

    assert!(
        meter_events(&storage).await.is_empty(),
        "denied → no meter events at all (neither api-calls nor tokens)"
    );
}

#[tokio::test]
async fn test_v13b_token_event_decodes_into_leria_wire_shape() {
    // Acceptance: the emitted shape decodes into leria's WireEvent (the tokens
    // pricing path). We model leria's strict (DisallowUnknownFields) decoder with a
    // mirror struct: asset=usd, a tokens{input,output} split, NO amount, model_ref
    // in dims, correlation_id present. A surplus/renamed key would fail this decode
    // exactly as leria's ingest would 400.
    let (server, storage) = setup().await;
    store_tenanted_credential(&storage, "api-cred", Some("acme")).await;
    let exec_auth = auth_for_agent(&storage, "agent_llm", Some("acme")).await;

    server
        .execute_gated(openai_usage_request("api-cred"), exec_auth)
        .await
        .unwrap();

    let tok = meter_events(&storage)
        .await
        .into_iter()
        .find(is_token_event)
        .expect("the V13b token event");

    // Mirror of leria's WireEvent token path (internal/ingest/pipeline.go):
    // tokens != nil + asset=usd ⇒ rate-card pricing; dims.model_ref selects the
    // card; amount must be zero (omitted) for a priced token event.
    #[derive(serde::Deserialize)]
    struct WireTokenSplit {
        input_tokens: i64,
        output_tokens: i64,
    }
    #[derive(serde::Deserialize)]
    struct WireEventMirror {
        event_id: String,
        correlation_id: String,
        #[allow(dead_code)]
        principal: String,
        asset: String,
        #[serde(default)]
        amount: i64,
        tokens: WireTokenSplit,
        cost_source: String,
        #[allow(dead_code)]
        confidence: String,
        #[allow(dead_code)]
        occurred_at: String,
        dims: std::collections::HashMap<String, String>,
    }

    let wire: WireEventMirror = serde_json::from_value(tok.payload.clone())
        .expect("token payload decodes into leria's WireEvent token path");
    assert_eq!(wire.asset, "usd", "leria prices tokens only when asset=usd");
    assert_eq!(
        wire.amount, 0,
        "a priced token event leaves amount zero (omitted)"
    );
    assert_eq!(wire.tokens.input_tokens, 1200);
    assert_eq!(wire.tokens.output_tokens, 345);
    assert_eq!(wire.cost_source, "gateway-observed");
    assert!(!wire.event_id.is_empty());
    assert!(!wire.correlation_id.is_empty());
    assert_eq!(
        wire.dims.get("model_ref").map(String::as_str),
        Some("gpt-4o-2024-08-06"),
        "dims.model_ref selects leria's rate card"
    );
}
