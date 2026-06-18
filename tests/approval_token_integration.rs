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

use vultrino::approval::{ApprovalStatus, Decision, RequesterInfo};
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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("not scoped to action"));
    assert_eq!(storage.get_use_token(&token.id).await.unwrap().unwrap().uses, 0);

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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(ok_token.clone()))
        .await
        .unwrap()
    {
        ExecutionOutcome::Completed(_) => {}
        _ => panic!("expected completed"),
    }
    assert_eq!(storage.get_use_token(&ok_token.id).await.unwrap().unwrap().uses, 1);
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
    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert_eq!(polled.status, ApprovalStatus::Pending);
    assert!(!polled.executed);

    // 2. A human approves (as the admin panel / CLI would).
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored.approve(Decision::new("admin panel", "secops")).unwrap();
    storage.update_approval(&stored).await.unwrap();

    // 3. The agent's next poll runs the action and returns the real result.
    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert_eq!(resumed.status, ApprovalStatus::Approved);
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));
    assert!(resumed.result_body.as_deref().unwrap().contains("world"));
    assert!(resumed.result_error.is_none());

    // 4. Re-polling is idempotent — it does not re-run the action.
    let again = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(again.executed);
    assert_eq!(again.result_status, Some(200));
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
    stored.deny(Decision::new("admin panel", "secops").with_note(Some("not allowed".to_string()))).unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
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
    assert_eq!(mid.uses, 0, "token must not be consumed until the action runs");

    // Approve, then resume runs the action and consumes the token.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored.approve(Decision::new("admin panel", "secops")).unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));

    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());
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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap();
    assert!(matches!(first, ExecutionOutcome::Pending(_)));

    // Second open is refused — no remaining capacity.
    let err = server
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("no remaining capacity"));
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
            .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
            .await
            .unwrap();
        assert!(matches!(outcome, ExecutionOutcome::Pending(_)));
    }

    // The third open is refused — capacity is fully reserved.
    let err = server
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("no remaining capacity"));
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
            s.execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(t)).await
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
    assert_eq!(pending, 1, "exactly one pending approval may open for a single-use token");
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
            condition: PolicyCondition::RateLimit { max: 1, window_secs: 3600 },
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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected pending, got {:?}", other),
    };

    // Human approves out of band.
    let mut stored = storage.get_approval(&approval.id).await.unwrap().unwrap();
    stored.approve(Decision::new("admin panel", "secops")).unwrap();
    storage.update_approval(&stored).await.unwrap();

    // Resume must NOT be denied by the now-exhausted rate budget — it executes.
    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(resumed.executed, "approved action should execute despite the rate limit");
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

    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
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
        handles.push(tokio::spawn(async move { s.consume_use_token(&id).await.is_ok() }));
    }
    let mut successes = 0;
    for h in handles {
        if h.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1, "exactly one consume may succeed for a single-use token");
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
    storage.decide_approval(&approval.id, true, "test", "secops", false, None).await.unwrap();

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
    storage.decide_approval(&approval.id, true, "t", "secops", false, None).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(!resumed.executed, "preflight failure must remain retryable");
    let tok = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(tok.uses, 0, "a preflight failure must not consume the token");
}

/// A stale execution claim (crashed worker) must be reclaimable after the
/// timeout so an approved action is never stuck forever.
#[tokio::test]
async fn test_stale_execution_claim_recovers() {
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
    storage.decide_approval(&approval.id, true, "t", "secops", false, None).await.unwrap();

    // Simulate a crashed worker holding a stale claim.
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.executing = true;
    a.executing_since = Some(chrono::Utc::now() - Duration::seconds(300));
    storage.update_approval(&a).await.unwrap();

    // A fresh poll reclaims and runs it.
    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));
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
    storage.decide_approval(&approval.id, true, "t", "secops", false, None).await.unwrap();

    // Worker A claims, then its claim ages past the stale window...
    let claimed = storage.claim_approval_for_execution(&approval.id).await.unwrap();
    assert!(claimed.is_some(), "first claim should succeed");
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.executing_since = Some(chrono::Utc::now() - Duration::seconds(300));
    storage.update_approval(&a).await.unwrap();

    // ...but a heartbeat refreshes it, so a competing claim is refused.
    storage.heartbeat_approval(&approval.id).await.unwrap();
    let reclaim = storage.claim_approval_for_execution(&approval.id).await.unwrap();
    assert!(reclaim.is_none(), "a heartbeated (live) claim must not be re-taken");
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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(token.clone()))
        .await
        .unwrap()
    {
        ExecutionOutcome::Pending(a) => a,
        _ => panic!("expected pending"),
    };
    storage.decide_approval(&approval.id, true, "t", "secops", false, None).await.unwrap();

    // Token is revoked after approval but before the agent polls to execute.
    storage.set_use_token_revoked(&token.id).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(resumed.executed, "an unusable-token resume must be terminal, not retryable");
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
            assert!(reason.contains("no_policy"), "expected no_policy reason, got: {reason}");
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

    writer.store_policy(&Policy::allow_all("pushed", "x-*")).await.unwrap();
    // The reader's in-memory cache is still stale (it loaded before the write).
    assert!(reader.list_stored_policies().await.unwrap().is_empty());

    refresh_policies_once(&reader, &engine, &[]).await.unwrap();
    assert!(engine.list_policies().iter().any(|p| p.name == "pushed"));
    assert_eq!(
        engine.evaluate("x-1", Some("https://x"), Some("GET"), &RequestContext::new()),
        PolicyDecision::Allow
    );

    // With a non-empty config too, the refresh→merge→engine path surfaces both.
    let cfg = Policy::allow_all("cfg-base", "c-*");
    refresh_policies_once(&reader, &engine, std::slice::from_ref(&cfg)).await.unwrap();
    let names: Vec<String> = engine.list_policies().into_iter().map(|p| p.name).collect();
    assert!(names.contains(&"cfg-base".to_string()), "{names:?}");
    assert!(names.contains(&"pushed".to_string()), "{names:?}");
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
    storage.decide_approval(&approval_id, true, "approver", "secops", false, None).await.unwrap();

    // Emergency Deny pushed (evaluated after the allow policy, which defaults to
    // Allow → continue → the Deny policy denies).
    storage.store_policy(&Policy::deny_all("kill", "gated-*")).await.unwrap();
    server.reload_policies().await.unwrap();

    let resumed = server.check_and_resume_approval(&approval_id, None).await.unwrap();
    assert!(
        resumed.result_error.is_some(),
        "a Deny pushed between approval and resume must block the approved action"
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
    assert!(names.contains(&"from-config".to_string()), "config policy missing: {names:?}");
    assert!(names.contains(&"from-admin".to_string()), "stored policy missing: {names:?}");

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
        .decide_approval(&approval_id, true, "test approver", "secops", false, None)
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
            per_action_max: Some(100),
            cumulative_max: None,
            window_secs: 3600,
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
        server.execute_gated(req(100), ExecAuth::default()).await.unwrap(),
        ExecutionOutcome::Completed(_)
    ));
    // Over per-action cap → denied (action did not run).
    assert!(matches!(
        server.execute_gated(req(101), ExecAuth::default()).await.unwrap_err(),
        vultrino::VultrinoError::PolicyDenied(_)
    ));
    // No extractable amount under a SpendCap policy → fail closed (denied).
    let no_amt = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "hello": "world" }),
    };
    assert!(matches!(
        server.execute_gated(no_amt, ExecAuth::default()).await.unwrap_err(),
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
            .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(bot_token))
            .await
            .unwrap_err(),
        vultrino::VultrinoError::PolicyDenied(_)
    ));
    // ...while another agent on the same credential is unaffected.
    assert!(matches!(
        server
            .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(other_token))
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
        .execute_gated(echo_request("api-cred"), ExecAuth::from_use_token(tok.clone()))
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
    storage.store_policy(&Policy::deny_all("kill-bot", "api-*").with_principal("refund-bot")).await.unwrap();
    server.reload_policies().await.unwrap();
    storage.decide_approval(&approval_id, true, "approver", "secops", false, None).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval_id, None).await.unwrap();
    assert!(
        resumed.result_error.is_some(),
        "a per-agent Deny pushed before resume must block the approved action"
    );
}

#[tokio::test]
async fn test_spend_capped_approval_resumes_without_recharge() {
    // V3 resume re-enforcement: a spend-capped, approval-gated action is charged
    // when the approval OPENS and must still resume (the read-only resume path
    // does not re-charge and must not spuriously deny).
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
            per_action_max: None,
            cumulative_max: Some(100),
            window_secs: 3600,
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

    let req = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": 60 }),
    };
    // Within cap (60 ≤ 100): charged at open, then gated on approval.
    let approval_id = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Pending(a) => a.id,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Prove the 60 was actually charged at OPEN: a second 60 (=120) now exceeds
    // the 100 cumulative cap and is denied before it can even open an approval.
    let again = ExecuteRequest {
        credential: "pay-cred".to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({ "amount": 60 }),
    };
    match server.execute_gated(again, ExecAuth::default()).await.unwrap_err() {
        vultrino::VultrinoError::PolicyDenied(reason) => {
            // Denied by the spend-cap policy specifically (not a coincidental deny):
            // both calls are principal-less, so the cred-keyed cap accumulated.
            assert!(reason.contains("pay-cap"), "expected spend-cap deny, got: {reason}");
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }

    storage.decide_approval(&approval_id, true, "approver", "secops", false, None).await.unwrap();

    // Resume must succeed (read-only spend check does not re-charge/deny).
    let resumed = server.check_and_resume_approval(&approval_id, None).await.unwrap();
    assert!(resumed.executed);
    assert!(resumed.result_error.is_none(), "spend-capped approval must resume: {:?}", resumed.result_error);
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
        Ok(ExecuteResponse { status: 200, headers, body, updated_credential: None })
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
    let resp = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Completed(r) => r,
        other => panic!("expected Completed, got {other:?}"),
    };
    let body = String::from_utf8_lossy(&resp.body);
    assert!(!body.contains("super-secret-value"), "secret leaked in body: {body}");
    assert!(body.contains("[REDACTED:api-cred]"));
    // Header reflection is scrubbed too.
    assert!(!resp.headers.get("X-Echoed-Auth").unwrap().contains("super-secret-value"));
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
    let resp = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
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
    assert!(approval.summary.contains("payments.refund"), "summary: {}", approval.summary);
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
            assert!(reason.contains("resolved to"), "reason should show both forms: {reason}");
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
            CriticalitySla { escalate_after_secs: 100, escalate_window_secs: 100 },
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
    let approval = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(approval.criticality, CriticalityClass::Critical);
    assert_eq!((approval.escalate_at - approval.created_at).num_seconds(), 100);
    assert_eq!((approval.expires_at - approval.created_at).num_seconds(), 200);

    // Back-date the first window → the SLA sweep escalates it (window 1 elapsed).
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.escalate_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage.update_approval(&a).await.unwrap();
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(sweep.escalated.iter().any(|x| x.id == approval.id), "should escalate");
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Escalated);
    assert!(a.escalated_at.is_some());

    // Back-date the final deadline → the next sweep expires (denies) it (window 2).
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    storage.update_approval(&a).await.unwrap();
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(sweep.expired.iter().any(|id| id == &approval.id), "should expire");
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
        .decide_approval(&approval.id, true, "admin panel", "  ", false, None)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("approver identity"), "got: {err}");

    // Self-approval (approver == requester owner) records the identity and is a
    // computable SoD violation.
    storage
        .decide_approval(&approval.id, true, "admin panel", "agent-x", false, None)
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.approver_identity.as_deref(), Some("agent-x"));
    assert_eq!(a.decided_by.as_deref(), Some("admin panel"));
    assert_eq!(a.violates_sod(), Some(true), "approver == requester → SoD violation");
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
        .decide_approval(&approval.id, true, "admin panel", "secops-oncall", false, None)
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.violates_sod(), Some(false), "distinct approver satisfies SoD");
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
    let approval = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Approve it, then back-date the decision so the reauth window has lapsed.
    storage
        .decide_approval(&approval.id, true, "admin panel", "secops", false, None)
        .await
        .unwrap();
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.decided_at = Some(chrono::Utc::now() - chrono::Duration::seconds(120));
    storage.update_approval(&a).await.unwrap();

    // Poll: the stale grant is expired (re-auth lapsed), not executed; the
    // original approver attribution is preserved and the lapse is noted.
    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert_eq!(polled.status, ApprovalStatus::Expired);
    assert!(!polled.executed, "a lapsed grant must not run");
    assert_eq!(polled.approver_identity.as_deref(), Some("secops"), "approver preserved");
    assert!(
        polled.decision_note.as_deref().unwrap_or("").contains("re-authorization"),
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
        .decide_approval(&approval.id, true, "admin panel", "agent-x", true, None)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("separation of duty"), "got: {err}");
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Pending, "must stay undecided");

    // A distinct approver succeeds even with enforcement on.
    storage
        .decide_approval(&approval.id, true, "admin panel", "secops-oncall", true, None)
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
    let approval = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
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
        .decide_approval(&approval.id, true, "admin panel", "secops", false, None)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("expire"), "got: {err}");
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_ne!(a.status, ApprovalStatus::Approved, "a past-deadline request must never approve");
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
    let approval = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Decide it (Approved).
    storage
        .decide_approval(&approval.id, true, "admin panel", "secops", false, None)
        .await
        .unwrap();

    // A subsequent poll_refresh must NOT revert the decision (advance_lifecycle is
    // a no-op on a decided request), even if its boundaries are now in the past.
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.escalate_at = chrono::Utc::now() - chrono::Duration::seconds(10);
    a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);
    storage.update_approval(&a).await.unwrap();

    let refreshed = storage.poll_refresh_approval(&approval.id).await.unwrap();
    assert_eq!(refreshed.status, ApprovalStatus::Approved, "a decision must survive a poll");
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
    let approval = match server.execute_gated(req, ExecAuth::default()).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Approve as alice, then back-date the decision past the reauth window.
    storage
        .decide_approval(&approval.id, true, "admin panel", "alice", false, None)
        .await
        .unwrap();
    let mut a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    a.decided_at = Some(chrono::Utc::now() - chrono::Duration::seconds(120));
    storage.update_approval(&a).await.unwrap();

    // The sweep (not a poll) expires it.
    let sweep = server.sweep_approvals_once().await.unwrap();
    assert!(sweep.expired.iter().any(|id| id == &approval.id), "sweep should expire it");
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Expired);
    // Approver attribution preserved; lapse recorded in the note.
    assert_eq!(a.decided_by.as_deref(), Some("admin panel"), "original channel kept");
    assert_eq!(a.approver_identity.as_deref(), Some("alice"), "original approver kept");
    assert!(
        a.decision_note.as_deref().unwrap_or("").contains("re-authorization"),
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
        self.hits.lock().unwrap().push((agent_label.to_string(), in_flight.len()));
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
    let outcome = server.execute_gated(echo_request("api-cred"), auth()).await.unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)));

    // Register a recording callback and pin an in-flight session for bot-7 so the
    // halt has something to report/abort.
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    server.register_halt_callback(std::sync::Arc::new(RecordingHaltCallback { hits: hits.clone() }));
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
    assert!(outcome.revoked_tokens.contains(&token.id), "agent's token revoked");
    assert_eq!(outcome.deny_policy_id, "halt:bot-7");
    assert!(outcome.policy_active, "kill policy active in the live engine");
    assert_eq!(outcome.callbacks_fired, 1);
    assert_eq!(outcome.in_flight.len(), 1, "the in-flight session is reported");

    // The callback was fired with the agent + its one in-flight session.
    let recorded = hits.lock().unwrap().clone();
    assert_eq!(recorded, vec![("bot-7".to_string(), 1)]);

    // The token is now revoked in storage.
    let revoked = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert!(revoked.revoked);

    // After halt: the agent's next gated call is DENIED by the kill policy, even
    // though the credential is otherwise allowed (allow mode).
    let err = server.execute_gated(echo_request("api-cred"), auth()).await.unwrap_err();
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
    let outcome = server.execute_gated(echo_request("api-cred"), auth2).await.unwrap();
    assert!(matches!(outcome, ExecutionOutcome::Completed(_)), "halt lifted → executes again");
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
    let approval = match server.execute_gated(echo_request("api-cred"), auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(approval.agent_label.as_deref(), Some("bot-7"));

    // Approve it, then halt the agent before it polls to execute.
    storage
        .decide_approval(&approval.id, true, "admin panel", "secops", false, None)
        .await
        .unwrap();
    server.halt_agent("bot-7").await.unwrap();

    // The resume re-evaluates policy and is denied by the kill switch; the action
    // does not run.
    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(
        polled.result_error.as_deref().unwrap_or("").to_lowercase().contains("halt"),
        "resume should be denied by the halt, got: {:?}",
        polled.result_error
    );
    assert!(polled.result_status.is_none(), "the action must not have produced a result");
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
    server.register_halt_callback(std::sync::Arc::new(RecordingHaltCallback { hits: hits.clone() }));
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
    assert!(outcome.revoked_tokens.contains(&token.id), "by-id halt revokes that token");
    assert!(storage.get_use_token(&token.id).await.unwrap().unwrap().revoked);
    assert_eq!(outcome.in_flight.len(), 1, "by-id session reported");
    assert_eq!(hits.lock().unwrap().as_slice(), &[(token.id.clone(), 1)], "leg 3 fired for by-id");
    let err = server.execute_gated(echo_request("api-cred"), auth()).await.unwrap_err();
    assert!(matches!(err, vultrino::VultrinoError::PolicyDenied(_)), "labelless agent halted by id");
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
    assert_eq!(fast_hits.lock().unwrap().len(), 1, "the fast callback still ran");
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
        .store_policy(&vultrino::policy::Policy::kill_switch("halt:bot-7", "bot-7"))
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
        engine.list_policies().iter().any(|p| p.id == "halt:bot-7" && p.kill),
        "kill flag must survive the storage round-trip"
    );
    let halted = Principal { id: "k1".to_string(), agent_label: Some("bot-7".to_string()) };
    let decision = engine.evaluate_full(&EvalInput {
        credential_alias: "anything",
        url: None,
        method: None,
        principal: Some(&halted),
        spend: None,
    });
    assert!(matches!(decision, PolicyDecision::Deny(_)), "reloaded kill is authoritative");
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
    let approval = match server.execute_gated(echo_request("pay-cred"), auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };

    // approval.requested emitted, keyed by the approval id.
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "approval.requested" && e.subject == approval.id),
        "approval.requested emitted"
    );

    // Decide → approval.approved emitted atomically with the decision.
    storage
        .decide_approval(&approval.id, true, "admin panel", "secops", false, None)
        .await
        .unwrap();
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(events.iter().any(|e| e.event_type == "approval.approved" && e.subject == approval.id));

    // Halt → agent.halted emitted, keyed by the agent label.
    server.halt_agent("bot-7").await.unwrap();
    let events = storage.list_events_after(0, 100).await.unwrap();
    assert!(events.iter().any(|e| e.event_type == "agent.halted" && e.subject == "bot-7"));

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
    let approval = match server.execute_gated(echo_request("pay-cred"), auth).await.unwrap() {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("expected Pending, got {other:?}"),
    };
    assert_eq!(approval.required_approvals, 2, "dual control needs 2 approvers");

    // First approver → still pending (1 of 2), action must NOT run.
    storage
        .decide_approval(&approval.id, true, "admin panel", "alice", false, None)
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Pending, "1 of 2 → still pending");
    assert_eq!(a.signoffs.len(), 1);

    // The same approver can't satisfy the second sign-off.
    let err = storage
        .decide_approval(&approval.id, true, "admin panel", "alice", false, None)
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("already signed off"), "got: {err}");

    // A polling agent sees it's still pending (not executed).
    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert_eq!(polled.status, ApprovalStatus::Pending);
    assert!(!polled.executed);

    // A second DISTINCT approver meets the threshold → Approved → runs on next poll.
    storage
        .decide_approval(&approval.id, true, "admin panel", "bob", false, None)
        .await
        .unwrap();
    let a = storage.get_approval(&approval.id).await.unwrap().unwrap();
    assert_eq!(a.status, ApprovalStatus::Approved);
    assert_eq!(a.signoffs.len(), 2);

    let polled = server.check_and_resume_approval(&approval.id, None).await.unwrap();
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
    let outcome = server.execute_gated(echo_request("pay-cred"), auth).await.unwrap();
    let approval = match outcome {
        ExecutionOutcome::Pending(a) => a,
        other => panic!("dual_control must gate even on Allow, got {other:?}"),
    };
    assert_eq!(approval.required_approvals, 2);
    assert!(approval.status.is_open());
}
