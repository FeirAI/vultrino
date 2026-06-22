//! HMAC-signed API authentication plugin
//!
//! Handles HTTP requests with HMAC-SHA256 signature authentication,
//! compatible with Binance, AsterDex, and similar exchanges.
//!
//! Signing process:
//! 1. Build query string with all parameters + timestamp
//! 2. Compute HMAC-SHA256(query_string, api_secret)
//! 3. Append signature to query string
//! 4. Add API key header

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// HMAC plugin for exchange API authentication
pub struct HmacPlugin {
    client: Client,
}

/// Parameters for HMAC-signed HTTP request action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacRequestParams {
    /// HTTP method (GET, POST, PUT, DELETE)
    pub method: String,
    /// Target URL (base endpoint, query params added separately)
    pub url: String,
    /// Query parameters (will be signed)
    #[serde(default)]
    pub query: HashMap<String, String>,
    /// Request body for POST/PUT (optional, will be signed if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Additional headers (optional)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Override timestamp (for testing, normally auto-generated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

impl HmacPlugin {
    /// Create a new HMAC plugin
    pub fn new() -> Self {
        // Same secret-bearing-egress SSRF guards as the HTTP plugin (no auto-redirect
        // + connect-time private-IP filter); an HMAC-signed request must not follow a
        // 3xx or a rebinding host into an internal target.
        Self { client: super::build_guarded_client() }
    }

    /// Get current timestamp in milliseconds
    fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }

    /// Build query string from parameters
    fn build_query_string(params: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = params.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Compute HMAC-SHA256 signature
    fn compute_signature(data: &str, secret: &str) -> Result<String, PluginError> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| PluginError::ExecutionFailed(format!("HMAC init failed: {}", e)))?;
        mac.update(data.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Validate URL for SSRF protection
    fn validate_url_ssrf(url_str: &str) -> Result<url::Url, PluginError> {
        let url = url::Url::parse(url_str)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid URL: {}", e)))?;

        // Only allow https for exchange APIs
        if url.scheme() != "https" {
            return Err(PluginError::InvalidParams(
                "HMAC plugin only allows HTTPS URLs for security".to_string(),
            ));
        }

        let host = url.host_str().ok_or_else(|| {
            PluginError::InvalidParams("URL must have a host".to_string())
        })?;

        // Check for IP address literals (these never reach the connect-time DNS
        // resolver, so the literal guard must catch them). Use the SHARED HTTP-plugin
        // classifier so IPv4-mapped IPv6 literals (e.g. ::ffff:169.254.169.254) are
        // rejected here too (Codex high) — a duplicated classifier missed them.
        if let Ok(ip) = host.parse::<IpAddr>() {
            if crate::plugins::HttpPlugin::is_private_ip(&ip) {
                return Err(PluginError::InvalidParams(
                    "Requests to private/internal IP addresses are not allowed".to_string(),
                ));
            }
        }

        // Resolve hostname and check all resolved IPs
        let port = url.port_or_known_default().unwrap_or(443);
        let socket_addr = format!("{}:{}", host, port);

        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                if crate::plugins::HttpPlugin::is_private_ip(&addr.ip()) {
                    return Err(PluginError::InvalidParams(format!(
                        "Host '{}' resolves to private/internal IP address",
                        host
                    )));
                }
            }
        }

        Ok(url)
    }

    /// Execute an HMAC-signed HTTP request
    async fn execute_request(
        &self,
        params: HmacRequestParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let (api_key, api_secret, header_name, recv_window) = match cred_data {
            CredentialData::HmacApiKey {
                api_key,
                api_secret,
                header_name,
                recv_window,
            } => (
                api_key.clone(),
                api_secret.expose().to_string(),
                header_name.clone(),
                *recv_window,
            ),
            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "HMAC plugin requires HmacApiKey credential".to_string(),
                ))
            }
        };

        // Validate URL
        let validated_url = Self::validate_url_ssrf(&params.url)?;

        // Parse method
        let method = Method::from_str(&params.method.to_uppercase())
            .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", params.method)))?;

        // Build query parameters with timestamp and recvWindow
        let mut query_params = params.query.clone();
        let timestamp = params.timestamp.unwrap_or_else(Self::current_timestamp_ms);
        query_params.insert("timestamp".to_string(), timestamp.to_string());
        query_params.insert("recvWindow".to_string(), recv_window.to_string());

        // Build the string to sign
        let query_string = Self::build_query_string(&query_params);

        // For POST with body, sign query + body
        let string_to_sign = if let Some(ref body) = params.body {
            if query_string.is_empty() {
                body.clone()
            } else {
                format!("{}&{}", query_string, body)
            }
        } else {
            query_string.clone()
        };

        // Compute signature
        let signature = Self::compute_signature(&string_to_sign, &api_secret)?;

        // Build final URL with signature
        let final_url = format!(
            "{}?{}&signature={}",
            validated_url,
            query_string,
            signature
        );

        // Build request
        let mut request = self.client.request(method, &final_url);

        // Add API key header
        request = request.header(&header_name, &api_key);

        // Add custom headers
        for (key, value) in &params.headers {
            request = request.header(key, value);
        }

        // Add body for POST/PUT
        if let Some(body) = params.body {
            request = request
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body);
        }

        // Execute request
        let response = request
            .send()
            .await
            .map_err(|e| PluginError::Http(e.to_string()))?;

        // Extract response details
        let status = response.status().as_u16();
        let response_headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();

        let body = response
            .bytes()
            .await
            .map_err(|e| PluginError::Http(e.to_string()))?
            .to_vec();

        Ok(ExecuteResponse {
            status,
            headers: response_headers,
            body,
            updated_credential: None,
        })
    }

    /// Sign data without making a request (utility action)
    fn sign_data(
        &self,
        data: &str,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let api_secret = match cred_data {
            CredentialData::HmacApiKey { api_secret, .. } => api_secret.expose().to_string(),
            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "HMAC plugin requires HmacApiKey credential".to_string(),
                ))
            }
        };

        let signature = Self::compute_signature(data, &api_secret)?;

        Ok(ExecuteResponse {
            status: 200,
            headers: HashMap::new(),
            body: signature.into_bytes(),
            updated_credential: None,
        })
    }
}

impl Default for HmacPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for HmacPlugin {
    fn name(&self) -> &str {
        "hmac"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::HmacApiKey]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["request", "sign"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "request" => {
                let params: HmacRequestParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;

                self.execute_request(params, &request.credential.data).await
            }
            "sign" => {
                let data = request.params.get("data")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PluginError::InvalidParams("Missing 'data' parameter".to_string()))?;

                self.sign_data(data, &request.credential.data)
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(
        &self,
        action: &str,
        params: &serde_json::Value,
    ) -> Result<(), PluginError> {
        match action {
            "request" => {
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("method") {
                    return Err(PluginError::InvalidParams("Missing 'method' field".to_string()));
                }

                if !obj.contains_key("url") {
                    return Err(PluginError::InvalidParams("Missing 'url' field".to_string()));
                }

                let method = obj["method"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'method' must be a string".to_string()))?;

                Method::from_str(&method.to_uppercase())
                    .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", method)))?;

                let url = obj["url"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'url' must be a string".to_string()))?;

                Self::validate_url_ssrf(url)?;

                Ok(())
            }
            "sign" => {
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("data") {
                    return Err(PluginError::InvalidParams("Missing 'data' field".to_string()));
                }

                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    fn url_patterns(&self) -> Vec<&str> {
        // Common HMAC-authenticated exchange endpoints
        vec![
            "https://fapi.asterdex.com/*",
            "https://api.asterdex.com/*",
            "https://fapi.binance.com/*",
            "https://api.binance.com/*",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn test_compute_signature() {
        let data = "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=0.001&timestamp=1234567890000&recvWindow=5000";
        let secret = "test_secret_key";

        let signature = HmacPlugin::compute_signature(data, secret).unwrap();

        // Verify it's a valid hex string of correct length (64 chars for SHA256)
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_query_string() {
        let mut params = HashMap::new();
        params.insert("symbol".to_string(), "BTCUSDT".to_string());
        params.insert("side".to_string(), "BUY".to_string());
        params.insert("quantity".to_string(), "0.001".to_string());

        let query = HmacPlugin::build_query_string(&params);

        // Should be sorted alphabetically
        assert!(query.contains("quantity=0.001"));
        assert!(query.contains("side=BUY"));
        assert!(query.contains("symbol=BTCUSDT"));
    }

    #[test]
    fn test_build_query_string_url_encoding() {
        let mut params = HashMap::new();
        params.insert("value".to_string(), "hello world".to_string());

        let query = HmacPlugin::build_query_string(&params);

        assert_eq!(query, "value=hello%20world");
    }

    #[test]
    fn test_validate_url_blocks_http() {
        let result = HmacPlugin::validate_url_ssrf("http://api.example.com/v1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_url_blocks_private_ip() {
        let result = HmacPlugin::validate_url_ssrf("https://192.168.1.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_validate_url_allows_https() {
        let result = HmacPlugin::validate_url_ssrf("https://fapi.asterdex.com/fapi/v1/account");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_blocks_ipv4_mapped_ipv6_literals() {
        // IP literals never reach the connect-time DNS resolver, so the literal guard
        // must reject IPv4-mapped IPv6 forms of internal targets (Codex high). The
        // shared HttpPlugin classifier handles ::ffff:a.b.c.d.
        for url in [
            "https://[::ffff:127.0.0.1]/api",
            "https://[::ffff:10.0.0.1]/api",
            "https://[::ffff:169.254.169.254]/latest/meta-data",
        ] {
            let result = HmacPlugin::validate_url_ssrf(url);
            assert!(result.is_err(), "{url} must be rejected as private/internal");
            assert!(result.unwrap_err().to_string().contains("private"));
        }
    }

    #[test]
    fn test_validate_params_request() {
        let plugin = HmacPlugin::new();

        let params = serde_json::json!({
            "method": "GET",
            "url": "https://fapi.asterdex.com/fapi/v1/account"
        });

        assert!(plugin.validate_params("request", &params).is_ok());
    }

    #[test]
    fn test_validate_params_sign() {
        let plugin = HmacPlugin::new();

        let params = serde_json::json!({
            "data": "test data to sign"
        });

        assert!(plugin.validate_params("sign", &params).is_ok());
    }

    #[test]
    fn test_sign_data() {
        let plugin = HmacPlugin::new();

        let cred_data = CredentialData::HmacApiKey {
            api_key: "test_key".to_string(),
            api_secret: Secret::new("test_secret"),
            header_name: "X-MBX-APIKEY".to_string(),
            recv_window: 5000,
        };

        let credential = crate::Credential::new("test".to_string(), cred_data);

        let result = plugin.sign_data("hello world", &credential.data);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, 200);

        let signature = String::from_utf8(response.body).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_current_timestamp() {
        let ts1 = HmacPlugin::current_timestamp_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = HmacPlugin::current_timestamp_ms();

        assert!(ts2 > ts1);
        // Should be a reasonable timestamp (after 2020)
        assert!(ts1 > 1577836800000);
    }
}
