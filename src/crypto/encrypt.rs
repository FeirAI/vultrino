//! Encryption utilities using AES-256-GCM with Argon2 key derivation

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
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

/// Derive a master key from a password using Argon2
pub fn derive_key(password: &SecretString, salt: &[u8]) -> Result<MasterKey, CryptoError> {
    // Use a fixed salt string for Argon2 (the actual salt is in the data)
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::default();

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
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
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

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decode ciphertext
    let ciphertext = STANDARD
        .decode(&encrypted.ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid ciphertext: {}", e)))?;

    // Create cipher and decrypt
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| CryptoError::DecryptionFailed("Decryption failed - invalid key or corrupted data".to_string()))?;

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
        let key = derive_key(&password, &salt).unwrap();

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

        let key1 = derive_key(&password1, &salt).unwrap();
        let key2 = derive_key(&password2, &salt).unwrap();

        let encrypted = encrypt(b"secret", &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let password = SecretString::from("test");
        let salt = generate_salt();
        let key = derive_key(&password, &salt).unwrap();

        let encrypted = encrypt(b"test data", &key).unwrap();
        let serialized = encrypted.encode();
        let parsed = EncryptedData::decode(&serialized).unwrap();

        assert_eq!(encrypted.nonce, parsed.nonce);
        assert_eq!(encrypted.ciphertext, parsed.ciphertext);

        // Verify we can still decrypt
        let decrypted = decrypt(&parsed, &key).unwrap();
        assert_eq!(decrypted, b"test data");
    }
}
