//! End-to-end integration tests for use tokens.
//!
//! These drive the real `VultrinoServer` execution path (`execute_gated`,
//! `run_action`) against encrypted `FileStorage`, using a deterministic
//! in-process mock plugin so nothing touches the network.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::auth::{NewUseToken, UseToken};
use vultrino::config::Config;
use vultrino::plugins::{Plugin, PluginError, PluginRequest};
use vultrino::router::CredentialResolver;
use vultrino::server::{ExecAuth, VultrinoServer};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{
    Credential, CredentialData, CredentialType, ExecuteRequest, ExecuteResponse, Secret,
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

async fn setup() -> (VultrinoServer, Arc<dyn StorageBackend>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir); // keep the file alive for the test's lifetime

    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());

    let resolver = CredentialResolver::new(storage.clone());
    let server = VultrinoServer::new(Config::default(), storage.clone(), resolver);
    server.plugins().register(Arc::new(MockPlugin));

    (server, storage)
}

async fn store_credential(storage: &Arc<dyn StorageBackend>, alias: &str) {
    let cred = Credential::new(
        alias.to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
}

fn echo_request(credential: &str) -> ExecuteRequest {
    ExecuteRequest {
        credential: credential.to_string(),
        action: "mock.echo".to_string(),
        params: serde_json::json!({"hello": "world"}),
    }
}

fn token_auth(token: &UseToken) -> ExecAuth {
    ExecAuth::from_use_token(token.clone())
}

#[tokio::test]
async fn test_single_use_token_consumed_once() {
    let (_server, storage) = setup().await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "once".to_string(),
        credential_scope: "*".to_string(),
        action_scope: None,
        max_uses: Some(1),
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

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
        expires_in: Some(Duration::seconds(-1)), // already in the past
    });
    storage.store_use_token(&token).await.unwrap();

    assert!(storage.consume_use_token(&token.id).await.is_err());
}

#[tokio::test]
async fn test_token_authorized_execution_consumes_use() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred").await;

    let (_full, token) = UseToken::create(NewUseToken {
        name: "exec-once".to_string(),
        credential_scope: "api-*".to_string(),
        action_scope: Some("mock.echo".to_string()),
        max_uses: Some(1),
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let resp = server
        .execute_gated(echo_request("api-cred"), token_auth(&token))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);

    // The single use is now spent.
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 1);
    assert!(after.is_exhausted());

    // A second attempt is denied because the token is exhausted (fail-closed).
    let err = server
        .execute_gated(echo_request("api-cred"), token_auth(&after))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("use token"));
}

#[tokio::test]
async fn test_token_credential_scope_enforced() {
    let (server, storage) = setup().await;
    store_credential(&storage, "secret-cred").await;

    // Token scoped to a different credential family.
    let (_full, token) = UseToken::create(NewUseToken {
        name: "scoped".to_string(),
        credential_scope: "github-*".to_string(),
        action_scope: None,
        max_uses: None,
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    // Synthesized role scope rejects access to the out-of-scope credential, and
    // the token is NOT consumed.
    let err = server
        .execute_gated(echo_request("secret-cred"), token_auth(&token))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("access denied"));
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 0);
}

/// The token's ACTION scope is enforced authoritatively in the server seam
/// (`execute_gated`), not only at the MCP/HTTP edge — so it's defended in depth.
#[tokio::test]
async fn test_token_action_scope_enforced_at_server() {
    let (server, storage) = setup().await;
    store_credential(&storage, "api-cred").await;

    // Token allowed only for postgres.run_sql, but the request is mock.echo.
    let (_full, token) = UseToken::create(NewUseToken {
        name: "wrong-action".to_string(),
        credential_scope: "*".to_string(),
        action_scope: Some("postgres.run_sql".to_string()),
        max_uses: Some(1),
        expires_in: None,
    });
    storage.store_use_token(&token).await.unwrap();

    let err = server
        .execute_gated(echo_request("api-cred"), token_auth(&token))
        .await
        .unwrap_err();
    assert!(format!("{}", err).to_lowercase().contains("not scoped to action"));
    // Out-of-scope action must NOT consume the token.
    let after = storage.get_use_token(&token.id).await.unwrap().unwrap();
    assert_eq!(after.uses, 0);

    // The in-scope action (via a glob token) is allowed and consumes.
    let (_f2, ok_token) = UseToken::create(NewUseToken {
        name: "ok-action".to_string(),
        credential_scope: "*".to_string(),
        action_scope: Some("mock.*".to_string()),
        max_uses: Some(1),
        expires_in: None,
    });
    storage.store_use_token(&ok_token).await.unwrap();
    server
        .execute_gated(echo_request("api-cred"), token_auth(&ok_token))
        .await
        .unwrap();
    assert_eq!(storage.get_use_token(&ok_token.id).await.unwrap().unwrap().uses, 1);
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
        expires_in: None,
    });
    s1.store_use_token(&token).await.unwrap();
    let id = token.id.clone();

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
