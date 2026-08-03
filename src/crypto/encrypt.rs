//! Encryption utilities using AES-256-GCM with Argon2 key derivation

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),
}

/// Size of the AES-256 key in bytes
const KEY_SIZE: usize = 32;

/// Size of the GCM nonce in bytes
const NONCE_SIZE: usize = 12;

/// A derived master key for encryption/decryption
pub struct MasterKey {
    key: SecretBox<[u8; KEY_SIZE]>,
}

impl MasterKey {
    /// Create a master key from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key_array = [0u8; KEY_SIZE];
        key_array.copy_from_slice(&bytes);
        Ok(Self {
            key: SecretBox::new(Box::new(key_array)),
        })
    }

    /// Get the key bytes (for internal use only)
    fn as_bytes(&self) -> &[u8] {
        self.key.expose_secret().as_slice()
    }
}

/// Encrypted data with its nonce (stored together)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64-encoded nonce
    pub nonce: String,
    /// Base64-encoded ciphertext
    pub ciphertext: String,
}

impl EncryptedData {
    /// Serialize to a single string for storage
    pub fn encode(&self) -> String {
        format!("{}:{}", self.nonce, self.ciphertext)
    }

    /// Parse from a single string
    pub fn decode(s: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidFormat(
                "Expected format: nonce:ciphertext".to_string(),
            ));
        }
        Ok(Self {
            nonce: parts[0].to_string(),
            ciphertext: parts[1].to_string(),
        })
    }
}

/// Argon2 key-derivation cost parameters, PINNED and persisted alongside each vault (in the
/// `StorageFile` header). Vultrino historically derived its master key with `Argon2::default()`,
/// whose `m`/`t`/`p` are a *crate default* — a minor (or RUSTSEC-forced) argon2 bump that changed
/// those defaults would derive a DIFFERENT AES key from the same password and make every already
/// deployed vault undecryptable. Persisting the params breaks that coupling: a vault always opens
/// with the params it was created with, regardless of the crate's current default.
///
/// FAIL-CLOSED / MIGRATION TRAP: a vault written before this field existed carries NO params on
/// disk, so it serde-defaults to [`KdfParams::default`]. That default MUST therefore stay pinned to
/// the argon2 0.5 `Argon2::default()` values the vault was actually created with — do NOT "track"
/// a future crate default here, or the field addition would brick every deployed vault. The
/// `default_kdf_params_match_argon2_crate_default` test guards this equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Argon2 memory cost, in KiB.
    pub m_cost: u32,
    /// Argon2 time cost (number of iterations).
    pub t_cost: u32,
    /// Argon2 degree of parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Snapshot of argon2 0.5's `Params::DEFAULT` (m = 19 MiB, t = 2, p = 1). Load-bearing: a
        // vault with no persisted `kdf` field derives its key from THIS, so it must reproduce the
        // key that `Argon2::default()` produced when the vault was created. See the type doc.
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// Derive a master key from a password using Argon2 with the given (pinned, persisted) cost
/// parameters. Passing [`KdfParams::default`] reproduces the historical `Argon2::default()`
/// derivation byte-for-byte (output length 32), so existing vaults keep opening.
pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<MasterKey, CryptoError> {
    // Use a fixed salt string for Argon2 (the actual salt is in the data)
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    // Pin the cost params explicitly instead of relying on `Argon2::default()` (whose values are a
    // crate default that can shift under a version bump). `output_len: None` matches `Params::DEFAULT`
    // exactly, so the derived key is identical to the pre-pinning derivation for the default params.
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), argon_params);

    // Hash the password
    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    // Get the hash output and use first 32 bytes as key
    let hash_bytes = hash
        .hash
        .ok_or_else(|| CryptoError::KeyDerivationFailed("No hash output".to_string()))?;

    let key_bytes: Vec<u8> = hash_bytes.as_bytes()[..KEY_SIZE].to_vec();
    MasterKey::from_bytes(key_bytes)
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(plaintext: &[u8], key: &MasterKey) -> Result<EncryptedData, CryptoError> {
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Create cipher and encrypt
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedData {
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(encrypted: &EncryptedData, key: &MasterKey) -> Result<Vec<u8>, CryptoError> {
    // Decode nonce
    let nonce_bytes = STANDARD
        .decode(&encrypted.nonce)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid nonce: {}", e)))?;

    if nonce_bytes.len() != NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed(format!(
            "Invalid nonce length: expected {}, got {}",
            NONCE_SIZE,
            nonce_bytes.len()
        )));
    }

    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce".into()))?;

    // Decode ciphertext
    let ciphertext = STANDARD
        .decode(&encrypted.ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid ciphertext: {}", e)))?;

    // Create cipher and decrypt
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let plaintext = cipher.decrypt(&nonce, ciphertext.as_slice()).map_err(|_| {
        CryptoError::DecryptionFailed(
            "Decryption failed - invalid key or corrupted data".to_string(),
        )
    })?;

    Ok(plaintext)
}

// (removed dead `encrypt_string`/`decrypt_string` helpers — production encrypts/decrypts bytes directly
// via encrypt/decrypt; the string wrappers were only exercised by their own test.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = SecretString::from("test-password-123");
        let salt = generate_salt();
        let key = derive_key(&password, &salt, KdfParams::default()).unwrap();

        let plaintext = b"Hello, Vultrino!";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let password1 = SecretString::from("password1");
        let password2 = SecretString::from("password2");
        let salt = generate_salt();

        let key1 = derive_key(&password1, &salt, KdfParams::default()).unwrap();
        let key2 = derive_key(&password2, &salt, KdfParams::default()).unwrap();

        let encrypted = encrypt(b"secret", &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let password = SecretString::from("test");
        let salt = generate_salt();
        let key = derive_key(&password, &salt, KdfParams::default()).unwrap();

        let encrypted = encrypt(b"test data", &key).unwrap();
        let serialized = encrypted.encode();
        let parsed = EncryptedData::decode(&serialized).unwrap();

        assert_eq!(encrypted.nonce, parsed.nonce);
        assert_eq!(encrypted.ciphertext, parsed.ciphertext);

        // Verify we can still decrypt
        let decrypted = decrypt(&parsed, &key).unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn default_kdf_params_match_argon2_crate_default() {
        // Fail-closed pin guard (#12): a vault written before KDF params were persisted derives its
        // key from `KdfParams::default()`. That default MUST reproduce the key the OLD code path
        // (`Argon2::default()`) produced, or adding the persisted field would brick every deployed
        // vault. Assert byte-for-byte key equality.
        let password = SecretString::from("some-vault-password");
        let salt = generate_salt();

        let pinned = derive_key(&password, &salt, KdfParams::default()).unwrap();

        // Reproduce the pre-pinning derivation independently: Argon2::default() + first 32 bytes.
        let salt_string = SaltString::encode_b64(&salt).unwrap();
        let hash = Argon2::default()
            .hash_password(password.expose_secret().as_bytes(), &salt_string)
            .unwrap();
        let legacy_key = hash.hash.unwrap().as_bytes()[..KEY_SIZE].to_vec();

        assert_eq!(
            pinned.as_bytes(),
            legacy_key.as_slice(),
            "pinned default params must derive the same key as the historical Argon2::default()"
        );
    }

    #[test]
    fn key_roundtrips_through_persisted_params() {
        // A vault created with the pinned default params must decrypt when reopened with the SAME
        // params (the create → save → load round-trip in FileStorage).
        let password = SecretString::from("pw");
        let salt = generate_salt();
        let params = KdfParams::default();
        let k1 = derive_key(&password, &salt, params).unwrap();
        let ct = encrypt(b"secret", &k1).unwrap();
        let k2 = derive_key(&password, &salt, params).unwrap();
        assert_eq!(decrypt(&ct, &k2).unwrap(), b"secret");
    }
}
