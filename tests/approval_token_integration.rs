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

use vultrino::approval::{ApprovalStatus, RequesterInfo};
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
    stored.approve("test", None).unwrap();
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
    stored.deny("test", Some("not allowed".to_string())).unwrap();
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
    stored.approve("test", None).unwrap();
    storage.update_approval(&stored).await.unwrap();

    let resumed = server.check_and_resume_approval(&approval.id, None).await.unwrap();
    assert!(resumed.executed);
    assert_eq!(resumed.result_status, Some(200));

    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());
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
    storage.decide_approval(&approval.id, true, "test", None).await.unwrap();

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
    storage.decide_approval(&approval.id, true, "t", None).await.unwrap();

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
    storage.decide_approval(&approval.id, true, "t", None).await.unwrap();

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

#[tokio::test]
async fn test_approvals_disabled_denies_gated_action() {
    // A credential flagged for approval, but approvals disabled in config → deny.
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let password = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let config = Config::default(); // approvals disabled by default
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
