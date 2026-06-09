//! Integration tests for the authentication system
//!
//! Tests the full flow: storage -> auth manager -> API validation

use chrono::{Duration, Utc};
use secrecy::SecretString;
use tempfile::tempdir;
use vultrino::auth::{AuthManager, Permission, ROLE_ADMIN, ROLE_EXECUTOR, ROLE_READ_ONLY};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, Secret};

/// Test that predefined roles are available immediately
#[tokio::test]
async fn test_predefined_roles_available() {
    let manager = AuthManager::new();

    // All predefined roles should exist
    assert!(manager.get_role_by_name(ROLE_ADMIN).is_some());
    assert!(manager.get_role_by_name(ROLE_EXECUTOR).is_some());
    assert!(manager.get_role_by_name(ROLE_READ_ONLY).is_some());
}

/// Test creating and validating API keys with different roles
#[tokio::test]
async fn test_api_key_with_executor_role() {
    let manager = AuthManager::new();

    // Create an executor key
    let (full_key, key_meta) = manager
        .create_api_key("test-executor", ROLE_EXECUTOR, None)
        .unwrap();

    // Validate the key
    let (validated_key, role) = manager.validate_key(&full_key).unwrap();
    assert_eq!(validated_key.id, key_meta.id);
    assert_eq!(role.name, ROLE_EXECUTOR);

    // Executor should have read and execute permissions
    assert!(role.has_permission(Permission::Read));
    assert!(role.has_permission(Permission::Execute));
    assert!(!role.has_permission(Permission::Write));
    assert!(!role.has_permission(Permission::Delete));
}

/// Test creating and validating API keys with read-only role
#[tokio::test]
async fn test_api_key_with_readonly_role() {
    let manager = AuthManager::new();

    // Create a read-only key
    let (full_key, _) = manager
        .create_api_key("test-readonly", ROLE_READ_ONLY, None)
        .unwrap();

    // Validate the key
    let (_, role) = manager.validate_key(&full_key).unwrap();
    assert_eq!(role.name, ROLE_READ_ONLY);

    // Read-only should only have read permission
    assert!(role.has_permission(Permission::Read));
    assert!(!role.has_permission(Permission::Execute));
    assert!(!role.has_permission(Permission::Write));
}

/// Test credential scoping with custom roles
#[tokio::test]
async fn test_credential_scoping() {
    let manager = AuthManager::new();

    // Create a custom role with scoped access
    let role = manager
        .create_role(
            "github-only",
            [Permission::Read, Permission::Execute].into_iter().collect(),
            vec!["github-*".to_string()],
            Some("Access only GitHub credentials".to_string()),
        )
        .unwrap();

    // Create a key with this role
    let (full_key, _) = manager
        .create_api_key("github-key", &role.name, None)
        .unwrap();

    // Validate and check scoping
    let (_, validated_role) = manager.validate_key(&full_key).unwrap();

    // Should access github credentials
    assert!(validated_role.can_access_credential("github-api"));
    assert!(validated_role.can_access_credential("github-org"));

    // Should NOT access other credentials
    assert!(!validated_role.can_access_credential("aws-prod"));
    assert!(!validated_role.can_access_credential("stripe-api"));
}

/// Test that AuthManager can be rebuilt from stored data
#[tokio::test]
async fn test_auth_manager_from_stored_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    // Create storage and add a role and key
    let (full_key, role_name) = {
        let storage = FileStorage::new(&path, &password).await.unwrap();
        let manager = AuthManager::new();

        // Create custom role
        let role = manager
            .create_role(
                "test-role",
                [Permission::Read].into_iter().collect(),
                vec![],
                None,
            )
            .unwrap();

        // Store role
        storage.store_role(&role).await.unwrap();

        // Create and store API key
        let (full_key, api_key) = manager
            .create_api_key("stored-key", &role.name, None)
            .unwrap();
        storage.store_api_key(&api_key).await.unwrap();

        (full_key, role.name)
    };

    // Reload storage and rebuild auth manager
    {
        let storage = FileStorage::new(&path, &password).await.unwrap();
        let roles = storage.list_roles().await.unwrap();
        let keys = storage.list_api_keys().await.unwrap();

        let manager = AuthManager::from_data(roles, keys);

        // The role and key should be valid
        let (_, role) = manager.validate_key(&full_key).unwrap();
        assert_eq!(role.name, role_name);
    }
}

/// Test storage reload picks up new keys
#[tokio::test]
async fn test_storage_reload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    // Create initial storage
    let storage1 = FileStorage::new(&path, &password).await.unwrap();

    // Create a second storage instance (simulating another process)
    let storage2 = FileStorage::new(&path, &password).await.unwrap();

    // Add a key via storage1
    let manager = AuthManager::new();
    let (full_key, api_key) = manager
        .create_api_key("new-key", ROLE_EXECUTOR, None)
        .unwrap();
    storage1.store_api_key(&api_key).await.unwrap();

    // Storage2 shouldn't see it yet (cached)
    let keys_before = storage2.list_api_keys().await.unwrap();
    assert!(keys_before.is_empty());

    // Reload storage2
    storage2.reload().await.unwrap();

    // Now storage2 should see the key
    let keys_after = storage2.list_api_keys().await.unwrap();
    assert_eq!(keys_after.len(), 1);
    assert_eq!(keys_after[0].name, "new-key");

    // Verify the key can be validated with the new manager
    let manager2 = AuthManager::from_data(vec![], keys_after);
    let (validated, _) = manager2.validate_key(&full_key).unwrap();
    assert_eq!(validated.name, "new-key");
}

/// Test permission checking with AuthResult
#[tokio::test]
async fn test_auth_result_permissions() {
    use vultrino::auth::AuthResult;

    let manager = AuthManager::new();

    // Create executor key
    let (full_key, _) = manager
        .create_api_key("perm-test", ROLE_EXECUTOR, None)
        .unwrap();

    let (api_key, role) = manager.validate_key(&full_key).unwrap();

    let auth_result = AuthResult { api_key, role };

    // Executor should have read and execute
    assert!(auth_result.has_permission(Permission::Read));
    assert!(auth_result.has_permission(Permission::Execute));

    // Executor should NOT have write or delete
    assert!(!auth_result.has_permission(Permission::Write));
    assert!(!auth_result.has_permission(Permission::Delete));
}

/// Test storing credentials and verifying access
#[tokio::test]
async fn test_credential_storage_and_access() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();

    // Store a credential
    let cred = Credential::new(
        "github-api".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("ghp_test_key_12345"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    )
    .with_metadata("description", "GitHub API token");

    storage.store(&cred).await.unwrap();

    // List credentials
    let credentials = storage.list().await.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].alias, "github-api");

    // Get by alias
    let retrieved = storage.get_by_alias("github-api").await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().alias, "github-api");
}

/// Test key revocation flow
#[tokio::test]
async fn test_key_revocation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();
    let manager = AuthManager::new();

    // Create and store a key
    let (_full_key, api_key) = manager
        .create_api_key("to-revoke", ROLE_EXECUTOR, None)
        .unwrap();
    let key_id = api_key.id.clone();
    storage.store_api_key(&api_key).await.unwrap();

    // Key should be valid
    let keys = storage.list_api_keys().await.unwrap();
    assert_eq!(keys.len(), 1);

    // Delete (revoke) the key
    storage.delete_api_key(&key_id).await.unwrap();

    // Key should be gone
    let keys_after = storage.list_api_keys().await.unwrap();
    assert!(keys_after.is_empty());
}

/// Test multiple API keys with different scopes
#[tokio::test]
async fn test_multiple_scoped_keys() {
    let manager = AuthManager::new();

    // Create role for GitHub only
    let github_role = manager
        .create_role(
            "github-access",
            [Permission::Read, Permission::Execute].into_iter().collect(),
            vec!["github-*".to_string()],
            None,
        )
        .unwrap();

    // Create role for AWS only
    let aws_role = manager
        .create_role(
            "aws-access",
            [Permission::Read, Permission::Execute].into_iter().collect(),
            vec!["aws-*".to_string()],
            None,
        )
        .unwrap();

    // Create keys for each role
    let (github_key, _) = manager
        .create_api_key("github-agent", &github_role.name, None)
        .unwrap();

    let (aws_key, _) = manager
        .create_api_key("aws-agent", &aws_role.name, None)
        .unwrap();

    // GitHub key should only access GitHub
    let (_, gh_validated) = manager.validate_key(&github_key).unwrap();
    assert!(gh_validated.can_access_credential("github-api"));
    assert!(!gh_validated.can_access_credential("aws-prod"));

    // AWS key should only access AWS
    let (_, aws_validated) = manager.validate_key(&aws_key).unwrap();
    assert!(aws_validated.can_access_credential("aws-prod"));
    assert!(!aws_validated.can_access_credential("github-api"));
}

// ============== OAuth2 Credential Tests ==============

/// Test OAuth2 credential storage and retrieval
#[tokio::test]
async fn test_oauth2_credential_storage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();

    // Store an OAuth2 credential
    let cred = Credential::new(
        "oauth2-api".to_string(),
        CredentialData::OAuth2 {
            client_id: "test-client-id".to_string(),
            client_secret: Secret::new("test-client-secret"),
            refresh_token: Some(Secret::new("test-refresh-token")),
            access_token: None,
            expires_at: None,
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
        },
    )
    .with_metadata("description", "OAuth2 API credential");

    storage.store(&cred).await.unwrap();

    // List credentials (returns metadata only)
    let credentials = storage.list().await.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].alias, "oauth2-api");

    // Get full credential by alias
    let retrieved = storage.get_by_alias("oauth2-api").await.unwrap().unwrap();

    // Verify credential type
    match &retrieved.data {
        CredentialData::OAuth2 {
            client_id,
            scopes,
            token_url,
            ..
        } => {
            assert_eq!(client_id, "test-client-id");
            assert_eq!(scopes, &vec!["read".to_string(), "write".to_string()]);
            assert_eq!(token_url, "https://oauth.example.com/token");
        }
        _ => panic!("Expected OAuth2 credential"),
    }
}

/// Test OAuth2 credential with access token and expiration
#[tokio::test]
async fn test_oauth2_credential_with_token() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();

    // Create credential with access token that expires in 1 hour
    let expires_at = Utc::now() + Duration::hours(1);
    let cred = Credential::new(
        "oauth2-with-token".to_string(),
        CredentialData::OAuth2 {
            client_id: "client-123".to_string(),
            client_secret: Secret::new("secret-456"),
            refresh_token: None,
            access_token: Some(Secret::new("access-token-789")),
            expires_at: Some(expires_at),
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec![],
        },
    );

    storage.store(&cred).await.unwrap();

    // Retrieve and verify
    let retrieved = storage.get_by_alias("oauth2-with-token").await.unwrap().unwrap();
    match &retrieved.data {
        CredentialData::OAuth2 {
            access_token,
            expires_at: stored_expires,
            ..
        } => {
            assert!(access_token.is_some());
            assert!(stored_expires.is_some());
            // Expiration time should be approximately what we set
            let diff = stored_expires.unwrap() - expires_at;
            assert!(diff.num_seconds().abs() < 2);
        }
        _ => panic!("Expected OAuth2 credential"),
    }
}

/// Test OAuth2 credential update (simulating token refresh)
#[tokio::test]
async fn test_oauth2_credential_update_after_refresh() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();

    // Create initial credential without access token
    let cred = Credential::new(
        "oauth2-refresh-test".to_string(),
        CredentialData::OAuth2 {
            client_id: "client-id".to_string(),
            client_secret: Secret::new("client-secret"),
            refresh_token: Some(Secret::new("refresh-token")),
            access_token: None,
            expires_at: None,
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec!["api".to_string()],
        },
    );

    storage.store(&cred).await.unwrap();

    // Simulate token refresh by updating the credential
    let new_expires = Utc::now() + Duration::hours(1);
    let updated_cred = Credential {
        id: cred.id.clone(),
        alias: cred.alias.clone(),
        credential_type: cred.credential_type,
        data: CredentialData::OAuth2 {
            client_id: "client-id".to_string(),
            client_secret: Secret::new("client-secret"),
            refresh_token: Some(Secret::new("new-refresh-token")), // Rotated
            access_token: Some(Secret::new("new-access-token")),
            expires_at: Some(new_expires),
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec!["api".to_string()],
        },
        metadata: cred.metadata.clone(),
        created_at: cred.created_at,
        updated_at: Utc::now(),
    };

    storage.store(&updated_cred).await.unwrap();

    // Verify only one credential exists (update, not duplicate)
    let credentials = storage.list().await.unwrap();
    assert_eq!(credentials.len(), 1);

    // Verify the credential was updated
    let retrieved = storage.get_by_alias("oauth2-refresh-test").await.unwrap().unwrap();
    match &retrieved.data {
        CredentialData::OAuth2 {
            access_token,
            refresh_token,
            expires_at,
            ..
        } => {
            assert!(access_token.is_some());
            assert!(refresh_token.is_some());
            assert!(expires_at.is_some());
        }
        _ => panic!("Expected OAuth2 credential"),
    }
}

/// Test OAuth2 credential scoped access
#[tokio::test]
async fn test_oauth2_credential_scoped_access() {
    let manager = AuthManager::new();

    // Create a role that can only access OAuth2 credentials
    let role = manager
        .create_role(
            "oauth2-only",
            [Permission::Read, Permission::Execute].into_iter().collect(),
            vec!["oauth2-*".to_string()],
            Some("Access only OAuth2 credentials".to_string()),
        )
        .unwrap();

    // Create API key with this role
    let (full_key, _) = manager
        .create_api_key("oauth2-key", &role.name, None)
        .unwrap();

    let (_, validated_role) = manager.validate_key(&full_key).unwrap();

    // Should access oauth2 credentials
    assert!(validated_role.can_access_credential("oauth2-github"));
    assert!(validated_role.can_access_credential("oauth2-google"));

    // Should NOT access other credentials
    assert!(!validated_role.can_access_credential("api-key-stripe"));
    assert!(!validated_role.can_access_credential("basic-auth-db"));
}

/// Storage-authoritative validation: a key revoked (or role-changed) by
/// another process must stop working immediately, without the validating
/// process rebuilding any in-memory snapshot. Regression test for the stale
/// AuthManager finding (REVIEW.md H1).
#[tokio::test]
async fn test_revocation_propagates_across_processes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let password = SecretString::from("test-password");

    // "Process A" (e.g. the CLI) creates a key.
    let storage_a = FileStorage::new(&path, &password).await.unwrap();
    let manager = AuthManager::new();
    let (full_key, api_key) = manager
        .create_api_key("revocable", ROLE_EXECUTOR, None)
        .unwrap();
    storage_a.store_api_key(&api_key).await.unwrap();

    // "Process B" (e.g. the MCP server) validates straight against storage.
    let storage_b = FileStorage::new(&path, &password).await.unwrap();
    let (validated, role) =
        AuthManager::validate_key_against_storage(&storage_b, &full_key)
            .await
            .unwrap();
    assert_eq!(validated.name, "revocable");
    assert_eq!(role.name, ROLE_EXECUTOR);

    // Process A revokes the key (writes only to storage, like `vultrino auth revoke`).
    storage_a.delete_api_key(&api_key.id).await.unwrap();

    // Process B must reject the key on the very next call — no restart, no
    // explicit reload by the caller.
    let result = AuthManager::validate_key_against_storage(&storage_b, &full_key).await;
    assert!(result.is_err(), "revoked key must stop validating immediately");
}

/// A key bound to a custom role stored in the vault validates via storage,
/// and garbage input is rejected.
#[tokio::test]
async fn test_storage_authoritative_validation_custom_role_and_bad_keys() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let password = SecretString::from("test-password");

    let storage = FileStorage::new(&path, &password).await.unwrap();
    let manager = AuthManager::new();
    let role = manager
        .create_role("deploy-bot", [Permission::Execute].into_iter().collect(), vec![], None)
        .unwrap();
    storage.store_role(&role).await.unwrap();
    let (full_key, api_key) = manager
        .create_api_key("deployer", &role.name, None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();

    let (_, validated_role) =
        AuthManager::validate_key_against_storage(&storage, &full_key)
            .await
            .unwrap();
    assert_eq!(validated_role.name, "deploy-bot");

    assert!(AuthManager::validate_key_against_storage(&storage, "vk_nonexistent")
        .await
        .is_err());
    assert!(AuthManager::validate_key_against_storage(&storage, "not-even-a-key")
        .await
        .is_err());
}
