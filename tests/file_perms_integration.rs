//! Sensitive on-disk files (the encrypted vault, the signed outbox, and their lock
//! sidecars) must be created owner-only (`0600`), not left world/group-readable
//! under a permissive umask. The vault holds the cleartext KDF salt (an offline
//! Argon2 target) and `admin.json` (tested at the unit level) holds the bcrypt admin
//! hash — a `0644` default would expose them to any local user.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, Secret};

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn test_vault_and_outbox_written_owner_only() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("store.enc");
    let outbox = dir.path().join("outbox.enc");
    let pw = SecretString::from("pw");
    let storage: Arc<dyn StorageBackend> = Arc::new(FileStorage::new(&vault, &pw).await.unwrap());

    // Storing a credential persists the vault via the temp-file + atomic rename path.
    let cred = Credential::new(
        "api-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    storage.store(&cred).await.unwrap();
    assert!(vault.exists(), "vault file should exist after a store");
    assert_eq!(
        mode_of(&vault),
        0o600,
        "the encrypted vault must be owner-only (0600), got {:o}",
        mode_of(&vault)
    );

    // Appending a signed event persists outbox.enc (its own temp + rename).
    storage
        .append_event("subj", "test.event", serde_json::json!({ "n": 1 }))
        .await
        .unwrap();
    assert!(outbox.exists(), "outbox file should exist after an append");
    assert_eq!(
        mode_of(&outbox),
        0o600,
        "the signed outbox must be owner-only (0600), got {:o}",
        mode_of(&outbox)
    );

    // The advisory-lock sidecars, when created, are owner-only too.
    for lock in [
        dir.path().join("store.lock"),
        dir.path().join("outbox.lock"),
    ] {
        if lock.exists() {
            assert_eq!(
                mode_of(&lock),
                0o600,
                "lock sidecar must be owner-only (0600): {}",
                lock.display()
            );
        }
    }
}
