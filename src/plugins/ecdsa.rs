//! ECDSA signing plugin
//!
//! Provides ECDSA secp256k1 signing capabilities for Ethereum-style
//! authentication (Hyperliquid, etc.).
//!
//! Actions:
//! - `sign`: Sign arbitrary data with ECDSA
//! - `get_address`: Get Ethereum address from private key
//! - `sign_message`: Sign a message with EIP-191 personal sign prefix

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::HashMap;

/// ECDSA plugin for Ethereum-style signing
pub struct EcdsaPlugin;

/// Parameters for sign action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignParams {
    /// Data to sign (hex encoded or raw bytes as base64)
    pub data: String,
    /// Data format: "hex", "utf8", or "base64" (default: "hex")
    #[serde(default = "default_hex")]
    pub format: String,
    /// Hash algorithm: "keccak256", "sha256", or "none" (default: "keccak256")
    #[serde(default = "default_keccak")]
    pub hash: String,
}

fn default_hex() -> String {
    "hex".to_string()
}

fn default_keccak() -> String {
    "keccak256".to_string()
}

/// Response from sign action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Signature r component (32 bytes hex)
    pub r: String,
    /// Signature s component (32 bytes hex)
    pub s: String,
    /// Recovery id (0 or 1)
    pub v: u8,
    /// Full signature (r + s + v as hex, 65 bytes)
    pub signature: String,
}

/// Response from get_address action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressResponse {
    /// Ethereum address (0x prefixed, checksummed)
    pub address: String,
    /// Public key (uncompressed, 65 bytes hex)
    pub public_key: String,
}

impl EcdsaPlugin {
    /// Create a new ECDSA plugin
    pub fn new() -> Self {
        Self
    }

    /// Parse private key from hex string
    fn parse_private_key(key_str: &str) -> Result<SigningKey, PluginError> {
        let key_hex = key_str.strip_prefix("0x").unwrap_or(key_str);

        let key_bytes = hex::decode(key_hex)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(PluginError::InvalidParams(format!(
                "Private key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        SigningKey::from_slice(&key_bytes)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid private key: {}", e)))
    }

    /// Get Ethereum address from public key
    fn public_key_to_address(verifying_key: &VerifyingKey) -> String {
        // Get uncompressed public key (65 bytes, 04 prefix + 64 bytes)
        let public_key = verifying_key.to_sec1_point(false);
        let public_key_bytes = public_key.as_bytes();

        // Skip the 0x04 prefix, hash the remaining 64 bytes
        let hash = Keccak256::digest(&public_key_bytes[1..]);

        // Take last 20 bytes as address
        let address_bytes = &hash[12..];
        let address_hex = hex::encode(address_bytes);

        // Apply EIP-55 checksum
        Self::checksum_address(&address_hex)
    }

    /// Apply EIP-55 checksum to address
    fn checksum_address(address_hex: &str) -> String {
        let address_lower = address_hex.to_lowercase();
        let hash = Keccak256::digest(address_lower.as_bytes());
        let hash_hex = hex::encode(hash);

        let mut checksummed = String::with_capacity(42);
        checksummed.push_str("0x");

        for (i, c) in address_lower.chars().enumerate() {
            let hash_char = hash_hex.chars().nth(i).unwrap_or('0');
            let hash_value = hash_char.to_digit(16).unwrap_or(0);

            if c.is_ascii_alphabetic() && hash_value >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }

        checksummed
    }

    /// Parse data based on format
    fn parse_data(data: &str, format: &str) -> Result<Vec<u8>, PluginError> {
        match format {
            "hex" => {
                let data_hex = data.strip_prefix("0x").unwrap_or(data);
                hex::decode(data_hex)
                    .map_err(|e| PluginError::InvalidParams(format!("Invalid hex data: {}", e)))
            }
            "utf8" => Ok(data.as_bytes().to_vec()),
            "base64" => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                STANDARD
                    .decode(data)
                    .map_err(|e| PluginError::InvalidParams(format!("Invalid base64 data: {}", e)))
            }
            _ => Err(PluginError::InvalidParams(format!(
                "Unknown data format: {}. Use 'hex', 'utf8', or 'base64'",
                format
            ))),
        }
    }

    /// Hash data based on algorithm
    fn hash_data(data: &[u8], algorithm: &str) -> Result<Vec<u8>, PluginError> {
        match algorithm {
            "keccak256" => Ok(Keccak256::digest(data).to_vec()),
            "sha256" => Ok(Sha256::digest(data).to_vec()),
            "none" => {
                if data.len() != 32 {
                    return Err(PluginError::InvalidParams(
                        "When hash='none', data must be exactly 32 bytes".to_string(),
                    ));
                }
                Ok(data.to_vec())
            }
            _ => Err(PluginError::InvalidParams(format!(
                "Unknown hash algorithm: {}. Use 'keccak256', 'sha256', or 'none'",
                algorithm
            ))),
        }
    }

    /// Sign data with ECDSA
    fn sign_data(
        &self,
        params: SignParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let private_key = match cred_data {
            CredentialData::EcdsaKey { private_key, .. } => private_key.expose(),
            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "ECDSA plugin requires EcdsaKey credential".to_string(),
                ))
            }
        };

        let signing_key = Self::parse_private_key(private_key)?;

        // Parse and hash data
        let data_bytes = Self::parse_data(&params.data, &params.format)?;
        let hash = Self::hash_data(&data_bytes, &params.hash)?;

        // Sign the hash
        let signature: Signature = signing_key.sign(&hash);
        let signature_bytes = signature.to_bytes();

        // Split into r and s
        let (r_bytes, s_bytes) = signature_bytes.split_at(32);

        // Calculate recovery id (simplified - may need refinement for full Ethereum compatibility)
        let recovery_id = 27_u8; // Default, proper implementation needs recovery

        let response = SignResponse {
            r: format!("0x{}", hex::encode(r_bytes)),
            s: format!("0x{}", hex::encode(s_bytes)),
            v: recovery_id,
            signature: format!(
                "0x{}{}{:02x}",
                hex::encode(r_bytes),
                hex::encode(s_bytes),
                recovery_id
            ),
        };

        let body = serde_json::to_vec(&response).map_err(|e| {
            PluginError::ExecutionFailed(format!("Failed to serialize response: {}", e))
        })?;

        Ok(ExecuteResponse {
            status: 200,
            headers: {
                let mut h = HashMap::new();
                h.insert("Content-Type".to_string(), "application/json".to_string());
                h
            },
            body,
            updated_credential: None,
        })
    }

    /// Get Ethereum address from private key
    fn get_address(&self, cred_data: &CredentialData) -> Result<ExecuteResponse, PluginError> {
        let (private_key, api_address) = match cred_data {
            CredentialData::EcdsaKey {
                private_key,
                api_address,
                ..
            } => (private_key.expose(), api_address.clone()),
            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "ECDSA plugin requires EcdsaKey credential".to_string(),
                ))
            }
        };

        let signing_key = Self::parse_private_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        let wallet_address = Self::public_key_to_address(verifying_key);
        let public_key = verifying_key.to_sec1_point(false);
        let public_key_hex = format!("0x{}", hex::encode(public_key.as_bytes()));

        let response = AddressResponse {
            address: api_address.unwrap_or(wallet_address),
            public_key: public_key_hex,
        };

        let body = serde_json::to_vec(&response).map_err(|e| {
            PluginError::ExecutionFailed(format!("Failed to serialize response: {}", e))
        })?;

        Ok(ExecuteResponse {
            status: 200,
            headers: {
                let mut h = HashMap::new();
                h.insert("Content-Type".to_string(), "application/json".to_string());
                h
            },
            body,
            updated_credential: None,
        })
    }

    /// Sign a message with EIP-191 personal sign prefix
    fn sign_message(
        &self,
        message: &str,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        // EIP-191 prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut prefixed = prefix.into_bytes();
        prefixed.extend_from_slice(message.as_bytes());

        // Sign with keccak256 hash
        self.sign_data(
            SignParams {
                data: hex::encode(&prefixed),
                format: "hex".to_string(),
                hash: "keccak256".to_string(),
            },
            cred_data,
        )
    }
}

impl Default for EcdsaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for EcdsaPlugin {
    fn name(&self) -> &str {
        "ecdsa"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::EcdsaKey]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["sign", "get_address", "sign_message"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "sign" => {
                let params: SignParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;

                self.sign_data(params, &request.credential.data)
            }
            "get_address" => self.get_address(&request.credential.data),
            "sign_message" => {
                let message = request
                    .params
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        PluginError::InvalidParams("Missing 'message' parameter".to_string())
                    })?;

                self.sign_message(message, &request.credential.data)
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        match action {
            "sign" => {
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("data") {
                    return Err(PluginError::InvalidParams(
                        "Missing 'data' field".to_string(),
                    ));
                }

                Ok(())
            }
            "get_address" => {
                // No parameters needed
                Ok(())
            }
            "sign_message" => {
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("message") {
                    return Err(PluginError::InvalidParams(
                        "Missing 'message' field".to_string(),
                    ));
                }

                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    // Known test private key (DO NOT USE IN PRODUCTION)
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    // Expected address for the test key (Hardhat account #0)
    const TEST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn test_credential() -> CredentialData {
        CredentialData::EcdsaKey {
            private_key: Secret::new(TEST_PRIVATE_KEY),
            api_address: None,
            testnet: false,
        }
    }

    #[test]
    fn test_parse_private_key_with_prefix() {
        let key = EcdsaPlugin::parse_private_key(TEST_PRIVATE_KEY);
        assert!(key.is_ok());
    }

    #[test]
    fn test_parse_private_key_without_prefix() {
        let key_no_prefix = TEST_PRIVATE_KEY.strip_prefix("0x").unwrap();
        let key = EcdsaPlugin::parse_private_key(key_no_prefix);
        assert!(key.is_ok());
    }

    #[test]
    fn test_parse_private_key_invalid() {
        let result = EcdsaPlugin::parse_private_key("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_address() {
        let plugin = EcdsaPlugin::new();
        let cred = test_credential();
        let credential = crate::Credential::new("test".to_string(), cred);

        let result = plugin.get_address(&credential.data);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, 200);

        let addr_response: AddressResponse = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(addr_response.address, TEST_ADDRESS);
    }

    #[test]
    fn test_checksum_address() {
        // Test vectors from EIP-55
        let tests = [
            (
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
        ];

        for (input, expected) in tests {
            let result = EcdsaPlugin::checksum_address(input);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_sign_data_hex() {
        let plugin = EcdsaPlugin::new();
        let cred = test_credential();
        let credential = crate::Credential::new("test".to_string(), cred);

        let params = SignParams {
            data: "0x1234567890abcdef".to_string(),
            format: "hex".to_string(),
            hash: "keccak256".to_string(),
        };

        let result = plugin.sign_data(params, &credential.data);
        assert!(result.is_ok());

        let response = result.unwrap();
        let sign_response: SignResponse = serde_json::from_slice(&response.body).unwrap();

        assert!(sign_response.r.starts_with("0x"));
        assert!(sign_response.s.starts_with("0x"));
        assert_eq!(sign_response.r.len(), 66); // 0x + 64 hex chars
        assert_eq!(sign_response.s.len(), 66);
    }

    #[test]
    fn test_sign_data_utf8() {
        let plugin = EcdsaPlugin::new();
        let cred = test_credential();
        let credential = crate::Credential::new("test".to_string(), cred);

        let params = SignParams {
            data: "Hello, World!".to_string(),
            format: "utf8".to_string(),
            hash: "keccak256".to_string(),
        };

        let result = plugin.sign_data(params, &credential.data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_message() {
        let plugin = EcdsaPlugin::new();
        let cred = test_credential();
        let credential = crate::Credential::new("test".to_string(), cred);

        let result = plugin.sign_message("Hello!", &credential.data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_params_sign() {
        let plugin = EcdsaPlugin::new();

        let params = serde_json::json!({
            "data": "0x1234"
        });
        assert!(plugin.validate_params("sign", &params).is_ok());

        let bad_params = serde_json::json!({});
        assert!(plugin.validate_params("sign", &bad_params).is_err());
    }

    #[test]
    fn test_validate_params_get_address() {
        let plugin = EcdsaPlugin::new();
        let params = serde_json::json!({});
        assert!(plugin.validate_params("get_address", &params).is_ok());
    }
}
