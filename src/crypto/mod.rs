//! Cryptographic utilities for Vultrino
//!
//! Provides AES-256-GCM encryption with Argon2 key derivation for
//! secure credential storage.

mod encrypt;

pub use encrypt::{
    decrypt, derive_key, encrypt, generate_salt, CryptoError, EncryptedData, KdfParams, MasterKey,
};
