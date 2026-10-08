//! Known-answer tests for the Argon2 key derivation that protects the vault.
//!
//! The fixtures under `tests/fixtures/argon2/` were generated with argon2 0.5.3, before the
//! 0.6 port. They pin: the derived master key for fixed (password, salt, params), an
//! AES-GCM blob sealed under such a key, and whole vault files (one with a persisted `kdf`
//! header, one in the legacy shape with no `kdf` key). If a future argon2 changes the KDF
//! output, these fail, because a vault written by an older build would stop opening.
//!
//! Regenerate (only with a deliberately chosen KDF): `ARGON2_KAT_GENERATE=1 cargo test --test argon2_kat generate -- --ignored --nocapture`

use secrecy::SecretString;
use std::path::PathBuf;
use vultrino::crypto::{decrypt, derive_key, encrypt, EncryptedData, KdfParams};
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::{Credential, CredentialData, Secret};

struct Case {
    name: &'static str,
    password: &'static str,
    salt_hex: &'static str,
    params: KdfParams,
}

const SEALED_PLAINTEXT: &[u8] = b"vultrino argon2 known-answer plaintext";
const VAULT_PASSWORD: &str = "kat-vault-password";

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "default-params",
            password: "correct horse battery staple",
            salt_hex: "000102030405060708090a0b0c0d0e0f",
            params: KdfParams {
                m_cost: 19 * 1024,
                t_cost: 2,
                p_cost: 1,
            },
        },
        Case {
            name: "non-default-params-unicode-password",
            password: "p\u{e4}ssw\u{f6}rd-\u{1f511}",
            salt_hex: "ffeeddccbbaa99887766554433221100",
            params: KdfParams {
                m_cost: 8192,
                t_cost: 3,
                p_cost: 2,
            },
        },
        Case {
            name: "empty-password-short-salt",
            password: "",
            salt_hex: "a1b2c3d4e5f60718",
            params: KdfParams {
                m_cost: 19 * 1024,
                t_cost: 2,
                p_cost: 1,
            },
        },
    ]
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/argon2")
        .join(name)
}

fn key_for(c: &Case) -> vultrino::crypto::MasterKey {
    let salt = hex::decode(c.salt_hex).unwrap();
    derive_key(&SecretString::from(c.password), &salt, c.params).unwrap()
}

fn blob_for(c: &Case) -> EncryptedData {
    let encoded = std::fs::read_to_string(fixture(&format!("sealed-{}.txt", c.name))).unwrap();
    EncryptedData::decode(encoded.trim()).unwrap()
}

/// AES-GCM authenticates, so a blob sealed under the 0.5.3 key opens only if 0.6 derives the
/// byte-identical key. The key bytes themselves are not exported by the crate.
#[test]
fn derived_keys_match_the_0_5_3_known_answers() {
    for c in cases() {
        let plain = decrypt(&blob_for(&c), &key_for(&c))
            .unwrap_or_else(|e| panic!("KDF output changed for case {}: {e}", c.name));
        assert_eq!(plain, SEALED_PLAINTEXT, "case {}", c.name);
    }
}

#[test]
fn a_different_cost_parameter_does_not_open_the_blob() {
    let c = &cases()[0];
    let wrong = Case {
        params: KdfParams {
            t_cost: 3,
            ..c.params
        },
        ..cases().remove(0)
    };
    assert!(decrypt(&blob_for(c), &key_for(&wrong)).is_err());
}

fn copy_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::fs::copy(fixture(name), &path).unwrap();
    (dir, path)
}

async fn assert_kat_vault_opens(path: &PathBuf) {
    let pw = SecretString::from(VAULT_PASSWORD);
    let storage = FileStorage::new(path, &pw).await.unwrap();
    let cred = storage
        .get_by_alias("kat-cred")
        .await
        .unwrap()
        .expect("credential present");
    match cred.data {
        CredentialData::ApiKey { key, .. } => assert_eq!(key.expose(), "kat-secret-value"),
        other => panic!("unexpected credential shape: {other:?}"),
    }
}

#[tokio::test]
async fn vault_written_by_0_5_3_with_persisted_kdf_opens() {
    let (_d, path) = copy_fixture("vault-0.5.3.enc");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(v.get("kdf").is_some(), "fixture must carry the kdf header");
    assert_kat_vault_opens(&path).await;
}

#[tokio::test]
async fn legacy_vault_without_kdf_header_opens() {
    let (_d, path) = copy_fixture("vault-0.5.3-legacy-no-kdf.enc");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(
        v.get("kdf").is_none(),
        "legacy fixture must have no kdf header"
    );
    assert_kat_vault_opens(&path).await;
}

#[tokio::test]
async fn new_vaults_persist_the_same_parameters_as_0_5_3() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let pw = SecretString::from("fresh");
    let _s = FileStorage::new(&path, &pw).await.unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let kdf: KdfParams = serde_json::from_value(v["kdf"].clone()).unwrap();
    assert_eq!(
        kdf,
        KdfParams {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1
        }
    );
    assert_eq!(KdfParams::default(), kdf);
    // The committed 0.5.3 vault carries the same parameters.
    let old: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("vault-0.5.3.enc")).unwrap())
            .unwrap();
    assert_eq!(
        serde_json::from_value::<KdfParams>(old["kdf"].clone()).unwrap(),
        kdf
    );
}

#[tokio::test]
#[ignore]
async fn generate() {
    assert!(std::env::var("ARGON2_KAT_GENERATE").is_ok());
    for c in cases() {
        let blob = encrypt(SEALED_PLAINTEXT, &key_for(&c)).unwrap();
        std::fs::write(
            fixture(&format!("sealed-{}.txt", c.name)),
            format!("{}\n", blob.encode()),
        )
        .unwrap();
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let pw = SecretString::from(VAULT_PASSWORD);
    let s = FileStorage::new(&path, &pw).await.unwrap();
    let cred = Credential::new(
        "kat-cred".to_string(),
        CredentialData::ApiKey {
            key: Secret::new("kat-secret-value"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        },
    );
    s.store(&cred).await.unwrap();
    drop(s);
    std::fs::copy(&path, fixture("vault-0.5.3.enc")).unwrap();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("kdf");
    std::fs::write(
        fixture("vault-0.5.3-legacy-no-kdf.enc"),
        serde_json::to_string_pretty(&v).unwrap(),
    )
    .unwrap();
}
