//! HTTP authentication plugin
//!
//! Handles HTTP requests with credential injection:
//! - API Key authentication (Bearer tokens, custom headers)
//! - Basic Authentication
//! - OAuth2 (token refresh, etc.)

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse, Secret};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

/// HTTP plugin for API authentication
pub struct HttpPlugin {
    client: Client,
}

/// SsrfGuardResolver is the connect-time half of the SSRF defense. validate_url_ssrf
/// vets the host's resolution at REQUEST time, but reqwest re-resolves at CONNECT
/// time, so a DNS-rebinding host (public at validate, private at connect) would slip
/// past. This custom resolver runs at connect time and filters the system resolution
/// to ONLY public IPs — a host that now resolves only to private/internal addresses
/// fails closed (no addresses => connection error). It closes the rebinding TOCTOU
/// for every request through the client, including OAuth token fetches. (Codex #12b.)
struct SsrfGuardResolver;

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            // getaddrinfo is blocking; run it off the async reactor. Port 0 is a
            // placeholder — reqwest applies the real port to each returned IP.
            let resolved: std::io::Result<Vec<SocketAddr>> =
                tokio::task::spawn_blocking(move || {
                    (host.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|it| it.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let addrs = resolved
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            // Keep ONLY public IPs; fail closed if nothing public remains.
            let public = filter_public_addrs(addrs).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { Box::from(e) },
            )?;
            let iter: Addrs = Box::new(public.into_iter());
            Ok(iter)
        })
    }
}

/// filter_public_addrs keeps only public IPs (drops a rebinding host's private
/// connect-time answers) and fails closed when none remain. Split out so the SSRF
/// filter is unit-testable without DNS.
fn filter_public_addrs(addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, &'static str> {
    let public: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| !HttpPlugin::is_private_ip(&a.ip()))
        .collect();
    if public.is_empty() {
        return Err("SSRF guard: host resolved only to private/internal IP addresses");
    }
    Ok(public)
}

/// Parameters for HTTP request action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestParams {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,
    /// Target URL
    pub url: String,
    /// Request headers (optional)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Request body (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    /// Query parameters (optional)
    #[serde(default)]
    pub query: HashMap<String, String>,
}

/// Response from OAuth2 token endpoint
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Token type (typically "Bearer") - kept for completeness but not used
    #[serde(default)]
    #[allow(dead_code)]
    token_type: String,
    /// Token lifetime in seconds
    expires_in: Option<u64>,
    /// New refresh token (some providers rotate refresh tokens)
    refresh_token: Option<String>,
}

/// Buffer time before token expiration to trigger refresh (5 minutes)
const TOKEN_REFRESH_BUFFER_SECS: i64 = 300;

/// build_guarded_client constructs the reqwest client EVERY secret-bearing outbound
/// path must use, so the SSRF guards can't be forgotten by a new caller:
///   - redirect::Policy::none(): validate_url_ssrf checks only the INITIAL url;
///     reqwest's default follows up to 10 hops, so a redirect to a private/link-local
///     host (e.g. 169.254.169.254 IMDS) would escape the allowlist with no
///     re-validation. none() surfaces the 3xx instead. (GLM #5.)
///   - dns_resolver(SsrfGuardResolver): filters the CONNECT-time resolution to public
///     IPs only, closing the DNS-rebinding TOCTOU that the request-time
///     validate_url_ssrf cannot (the host re-resolves at connect). (Codex #12b.)
pub(crate) fn build_guarded_client() -> Client {
    Client::builder()
        .user_agent("vultrino/0.1.0")
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(SsrfGuardResolver))
        .build()
        .expect("Failed to create HTTP client")
}

impl HttpPlugin {
    /// Create a new HTTP plugin
    pub fn new() -> Self {
        Self { client: build_guarded_client() }
    }

    /// Validate token URL for SSRF protection - requires HTTPS. `pub(crate)` so
    /// other secret-bearing outbound paths (e.g. OAuth2 revoke-propagation, R5)
    /// reuse the same HTTPS + IP-literal + DNS private-range guard rather than
    /// re-implementing it inconsistently.
    pub(crate) fn validate_token_url_ssrf(url_str: &str) -> Result<url::Url, PluginError> {
        let url = url::Url::parse(url_str)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid token URL: {}", e)))?;

        // Token URLs must use HTTPS to prevent credential leakage
        if url.scheme() != "https" {
            return Err(PluginError::InvalidParams(
                "Token URL must use HTTPS for security".to_string(),
            ));
        }

        // Get the host
        let host = url.host_str().ok_or_else(|| {
            PluginError::InvalidParams("Token URL must have a host".to_string())
        })?;

        // Check for IP address literals
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_private_ip(&ip) {
                return Err(PluginError::InvalidParams(
                    "Token URL cannot point to private/internal IP addresses".to_string(),
                ));
            }
        }

        // Resolve hostname and check all resolved IPs
        let port = url.port_or_known_default().unwrap_or(443);
        let socket_addr = format!("{}:{}", host, port);

        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                if Self::is_private_ip(&addr.ip()) {
                    return Err(PluginError::InvalidParams(format!(
                        "Token URL host '{}' resolves to private/internal IP address, which is not allowed",
                        host
                    )));
                }
            }
        }

        Ok(url)
    }

    /// Check if an OAuth2 token needs refresh
    fn needs_refresh(expires_at: Option<DateTime<Utc>>) -> bool {
        match expires_at {
            Some(expires) => {
                let buffer = Duration::seconds(TOKEN_REFRESH_BUFFER_SECS);
                Utc::now() + buffer >= expires
            }
            // No expiration time means we should try to use the token
            // and let the API tell us if it's expired
            None => false,
        }
    }

    /// Fetch access token using client credentials flow
    async fn fetch_client_credentials_token(
        &self,
        client_id: &str,
        client_secret: &Secret,
        token_url: &str,
        scopes: &[String],
    ) -> Result<TokenResponse, PluginError> {
        let validated_url = Self::validate_token_url_ssrf(token_url)?;

        let mut form_data = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.expose().to_string()),
        ];

        if !scopes.is_empty() {
            form_data.push(("scope", scopes.join(" ")));
        }

        let response = self
            .client
            .post(validated_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PluginError::Http(format!("Token request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PluginError::ExecutionFailed(format!(
                "Token endpoint returned {}: {}",
                status, body
            )));
        }

        response
            .json::<TokenResponse>()
            .await
            .map_err(|e| PluginError::ExecutionFailed(format!("Failed to parse token response: {}", e)))
    }

    /// Refresh access token using refresh token
    async fn refresh_access_token(
        &self,
        client_id: &str,
        client_secret: &Secret,
        refresh_token: &Secret,
        token_url: &str,
        scopes: &[String],
    ) -> Result<TokenResponse, PluginError> {
        let validated_url = Self::validate_token_url_ssrf(token_url)?;

        let mut form_data = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.expose().to_string()),
            ("client_id", client_id.to_string()),
            ("client_secret", client_secret.expose().to_string()),
        ];

        if !scopes.is_empty() {
            form_data.push(("scope", scopes.join(" ")));
        }

        let response = self
            .client
            .post(validated_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PluginError::Http(format!("Token refresh failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PluginError::ExecutionFailed(format!(
                "Token refresh endpoint returned {}: {}",
                status, body
            )));
        }

        response
            .json::<TokenResponse>()
            .await
            .map_err(|e| PluginError::ExecutionFailed(format!("Failed to parse token response: {}", e)))
    }

    /// Ensure we have a valid access token, refreshing if needed
    ///
    /// Returns the access token to use and optionally updated credential data
    async fn ensure_valid_token(
        &self,
        cred_data: &CredentialData,
    ) -> Result<(String, Option<CredentialData>), PluginError> {
        match cred_data {
            CredentialData::OAuth2 {
                client_id,
                client_secret,
                refresh_token,
                access_token,
                expires_at,
                token_url,
                scopes,
            } => {
                // Check if we have a valid, non-expired token
                if let Some(token) = access_token {
                    if !Self::needs_refresh(*expires_at) {
                        // Token is still valid
                        return Ok((token.expose().to_string(), None));
                    }
                }

                // Need to get a new token
                let token_response = if let Some(rt) = refresh_token {
                    // Try refresh token flow first
                    match self
                        .refresh_access_token(client_id, client_secret, rt, token_url, scopes)
                        .await
                    {
                        Ok(resp) => resp,
                        Err(_) => {
                            // Refresh token might be expired, fall back to client credentials
                            self.fetch_client_credentials_token(client_id, client_secret, token_url, scopes)
                                .await?
                        }
                    }
                } else {
                    // No refresh token, use client credentials flow
                    self.fetch_client_credentials_token(client_id, client_secret, token_url, scopes)
                        .await?
                };

                // Calculate new expiration time
                let new_expires_at = token_response.expires_in.map(|secs| {
                    Utc::now() + Duration::seconds(secs as i64)
                });

                // Build updated credential data
                let updated_cred = CredentialData::OAuth2 {
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                    refresh_token: token_response
                        .refresh_token
                        .map(Secret::new)
                        .or_else(|| refresh_token.clone()),
                    access_token: Some(Secret::new(token_response.access_token.clone())),
                    expires_at: new_expires_at,
                    token_url: token_url.clone(),
                    scopes: scopes.clone(),
                };

                Ok((token_response.access_token, Some(updated_cred)))
            }
            _ => Err(PluginError::UnsupportedCredentialType(
                "ensure_valid_token only works with OAuth2 credentials".to_string(),
            )),
        }
    }

    /// Inject credentials into request headers
    fn inject_credentials(
        &self,
        headers: &mut HashMap<String, String>,
        cred_data: &CredentialData,
    ) -> Result<(), PluginError> {
        match cred_data {
            CredentialData::ApiKey {
                key,
                header_name,
                header_prefix,
            } => {
                let value = format!("{}{}", header_prefix, key.expose());
                headers.insert(header_name.clone(), value);
            }

            CredentialData::BasicAuth { username, password } => {
                let credentials = format!("{}:{}", username, password.expose());
                let encoded = STANDARD.encode(credentials.as_bytes());
                headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            }

            CredentialData::OAuth2 { access_token, .. } => {
                if let Some(token) = access_token {
                    headers.insert(
                        "Authorization".to_string(),
                        format!("Bearer {}", token.expose()),
                    );
                } else {
                    return Err(PluginError::ExecutionFailed(
                        "OAuth2 credential has no access token".to_string(),
                    ));
                }
            }

            _ => {
                return Err(PluginError::UnsupportedCredentialType(
                    "HTTP plugin only supports ApiKey, BasicAuth, and OAuth2".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Check if an IP address is private/internal (SSRF protection). `pub(crate)` so
    /// every SSRF check (the connect-time resolver here, the HMAC plugin's literal
    /// guard, etc.) shares ONE classifier — including the IPv4-mapped-IPv6 case
    /// (`::ffff:a.b.c.d`) that a separate copy is easy to forget (Codex high).
    pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // Loopback (127.0.0.0/8)
                ipv4.is_loopback()
                // Private ranges
                || ipv4.is_private()
                // Link-local (169.254.0.0/16)
                || ipv4.is_link_local()
                // Broadcast
                || ipv4.is_broadcast()
                // Documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
                || ipv4.is_documentation()
                // Unspecified (0.0.0.0)
                || ipv4.is_unspecified()
                // Shared address space (100.64.0.0/10 - CGNAT)
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
                // Loopback extended (127.0.0.0/8 - already covered by is_loopback)
                // Reserved for future use (240.0.0.0/4)
                || ipv4.octets()[0] >= 240
                // Local network control block (224.0.0.0/24)
                || (ipv4.octets()[0] == 224 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0)
            }
            IpAddr::V6(ipv6) => {
                // Loopback (::1)
                ipv6.is_loopback()
                // Unspecified (::)
                || ipv6.is_unspecified()
                // Unique local (fc00::/7)
                || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                // Link-local (fe80::/10)
                || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                // IPv4-mapped addresses - check the IPv4 portion
                || Self::is_ipv4_mapped_private(ipv6)
            }
        }
    }

    /// Check if an IPv6 address is an IPv4-mapped address pointing to a private IPv4
    fn is_ipv4_mapped_private(ipv6: &Ipv6Addr) -> bool {
        // IPv4-mapped IPv6 addresses are ::ffff:x.x.x.x
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            Self::is_private_ip(&IpAddr::V4(ipv4))
        } else {
            false
        }
    }

    /// Validate URL for SSRF protection
    fn validate_url_ssrf(url_str: &str) -> Result<url::Url, PluginError> {
        let url = url::Url::parse(url_str)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid URL: {}", e)))?;

        // Only allow http and https schemes
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(PluginError::InvalidParams(format!(
                    "URL scheme '{}' not allowed. Only http and https are permitted.",
                    scheme
                )));
            }
        }

        // Get the host
        let host = url.host_str().ok_or_else(|| {
            PluginError::InvalidParams("URL must have a host".to_string())
        })?;

        // Check for IP address literals
        if let Ok(ip) = host.parse::<IpAddr>() {
            if Self::is_private_ip(&ip) {
                return Err(PluginError::InvalidParams(
                    "Requests to private/internal IP addresses are not allowed".to_string(),
                ));
            }
        }

        // Resolve hostname and check all resolved IPs
        let port = url.port_or_known_default().unwrap_or(80);
        let socket_addr = format!("{}:{}", host, port);

        if let Ok(addrs) = socket_addr.to_socket_addrs() {
            for addr in addrs {
                if Self::is_private_ip(&addr.ip()) {
                    return Err(PluginError::InvalidParams(format!(
                        "Host '{}' resolves to private/internal IP address, which is not allowed",
                        host
                    )));
                }
            }
        }
        // This is the REQUEST-time check (fast reject of obvious private targets +
        // IP literals). The DNS-rebinding TOCTOU it cannot close on its own — a host
        // public here but private at connect — IS closed by SsrfGuardResolver, which
        // re-filters the CONNECT-time resolution to public IPs only (see new()). So
        // the two together cover both the request-time and connect-time windows; a
        // DNS *failure* here is not a fail-open (reqwest's connect resolves + fails too).

        Ok(url)
    }

    /// Execute an HTTP request
    async fn execute_request(
        &self,
        params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        // Validate URL for SSRF before proceeding
        let validated_url = Self::validate_url_ssrf(&params.url)?;

        // Parse method
        let method = Method::from_str(&params.method.to_uppercase())
            .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", params.method)))?;

        // For OAuth2, ensure we have a valid token and get any updated credential
        let (effective_cred, updated_credential) = match cred_data {
            CredentialData::OAuth2 { .. } => {
                let (_access_token, updated) = self.ensure_valid_token(cred_data).await?;
                // Use the updated credential with fresh token for the request
                let effective = updated.clone().unwrap_or_else(|| cred_data.clone());
                (effective, updated)
            }
            _ => (cred_data.clone(), None),
        };

        // Build headers with credential injection
        let mut headers = params.headers;
        self.inject_credentials(&mut headers, &effective_cred)?;

        // Let the HTTP client negotiate and auto-decompress the response
        // (gzip/deflate/brotli features) so egress secret-redaction always sees
        // plaintext bytes. Strip any caller-supplied Accept-Encoding so the
        // client controls it (an agent can't request a compressed body to evade
        // the scrubber); a residual undecoded Content-Encoding is failed-closed
        // at the egress seam.
        force_client_managed_encoding(&mut headers);

        // Build request using the validated URL
        let mut request = self.client.request(method, validated_url);

        // Add headers
        for (key, value) in &headers {
            request = request.header(key, value);
        }

        // Add query parameters
        if !params.query.is_empty() {
            request = request.query(&params.query);
        }

        // Add body
        if let Some(body) = params.body {
            request = request.json(&body);
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
            updated_credential,
        })
    }
}

/// Remove any caller-supplied `Accept-Encoding` so the HTTP client negotiates
/// and auto-decompresses the response itself — preventing an agent from
/// requesting a compressed body to evade egress secret-redaction.
fn force_client_managed_encoding(headers: &mut HashMap<String, String>) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case("accept-encoding"));
}

impl Default for HttpPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for HttpPlugin {
    fn name(&self) -> &str {
        "http"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![
            CredentialType::ApiKey,
            CredentialType::BasicAuth,
            CredentialType::OAuth2,
        ]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["request"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "request" => {
                let params: HttpRequestParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;

                self.execute_request(params, &request.credential.data).await
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
                // Validate required fields
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("method") {
                    return Err(PluginError::InvalidParams("Missing 'method' field".to_string()));
                }

                if !obj.contains_key("url") {
                    return Err(PluginError::InvalidParams("Missing 'url' field".to_string()));
                }

                // Validate method is valid
                let method = obj["method"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'method' must be a string".to_string()))?;

                Method::from_str(&method.to_uppercase())
                    .map_err(|_| PluginError::InvalidParams(format!("Invalid HTTP method: {}", method)))?;

                // Validate URL with SSRF protection
                let url = obj["url"]
                    .as_str()
                    .ok_or_else(|| PluginError::InvalidParams("'url' must be a string".to_string()))?;

                Self::validate_url_ssrf(url)?;

                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    fn url_patterns(&self) -> Vec<&str> {
        // HTTP plugin is the default, so it matches all HTTP URLs
        vec!["http://*", "https://*"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    #[test]
    fn test_validate_params_valid() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "method": "GET",
            "url": "https://api.example.com/users"
        });

        assert!(plugin.validate_params("request", &params).is_ok());
    }

    #[test]
    fn test_validate_params_missing_method() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "url": "https://api.example.com/users"
        });

        assert!(plugin.validate_params("request", &params).is_err());
    }

    #[test]
    fn test_validate_params_invalid_url() {
        let plugin = HttpPlugin::new();
        let params = serde_json::json!({
            "method": "GET",
            "url": "not-a-valid-url"
        });

        assert!(plugin.validate_params("request", &params).is_err());
    }

    #[test]
    fn test_force_client_managed_encoding_strips_caller_value() {
        // An agent-supplied Accept-Encoding (any case / q-values) is removed so
        // the client controls compression and decompresses for the scrubber.
        for hdr in ["Accept-Encoding", "accept-encoding", "ACCEPT-ENCODING"] {
            let mut headers = HashMap::new();
            headers.insert(hdr.to_string(), "gzip, identity;q=0.5".to_string());
            headers.insert("X-Keep".to_string(), "1".to_string());
            force_client_managed_encoding(&mut headers);
            assert!(!headers.keys().any(|k| k.eq_ignore_ascii_case("accept-encoding")));
            assert!(headers.contains_key("X-Keep"));
        }
    }

    #[test]
    fn test_inject_api_key() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::ApiKey {
            key: Secret::new("test-key-123"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        };

        plugin.inject_credentials(&mut headers, &cred_data).unwrap();

        assert_eq!(
            headers.get("Authorization"),
            Some(&"Bearer test-key-123".to_string())
        );
    }

    #[test]
    fn test_inject_basic_auth() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::BasicAuth {
            username: "user".to_string(),
            password: Secret::new("pass"),
        };

        plugin.inject_credentials(&mut headers, &cred_data).unwrap();

        // user:pass base64 encoded
        let expected = format!("Basic {}", STANDARD.encode("user:pass"));
        assert_eq!(headers.get("Authorization"), Some(&expected));
    }

    // SSRF Protection Tests

    #[test]
    fn test_ssrf_blocks_localhost() {
        let result = HttpPlugin::validate_url_ssrf("http://127.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_localhost_ipv6() {
        let result = HttpPlugin::validate_url_ssrf("http://[::1]/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_10_network() {
        let result = HttpPlugin::validate_url_ssrf("http://10.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_172_network() {
        let result = HttpPlugin::validate_url_ssrf("http://172.16.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_private_192_network() {
        let result = HttpPlugin::validate_url_ssrf("http://192.168.1.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        let result = HttpPlugin::validate_url_ssrf("http://169.254.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    // --- connect-time DNS-rebinding filter (Codex #12b) --------------------

    #[test]
    fn ssrf_resolver_drops_private_keeps_public() {
        use std::net::{Ipv4Addr, SocketAddr};
        // A rebinding host that resolves to BOTH a public and an internal IP: the
        // private one is dropped, the public one survives (we still connect, but
        // never to the internal target).
        let public = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        let imds = SocketAddr::from((Ipv4Addr::new(169, 254, 169, 254), 443));
        let got = filter_public_addrs(vec![imds, public]).expect("a public IP remains");
        assert_eq!(got, vec![public], "only the public IP should be kept");
    }

    #[test]
    fn ssrf_resolver_fails_closed_when_only_private() {
        use std::net::{Ipv4Addr, SocketAddr};
        // The rebinding attack: at connect time the host resolves ONLY to an internal
        // IP (IMDS / loopback). The filter must fail closed (no addresses to dial).
        let imds = SocketAddr::from((Ipv4Addr::new(169, 254, 169, 254), 80));
        let loopback = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 80));
        let err = filter_public_addrs(vec![imds, loopback]).unwrap_err();
        assert!(err.contains("private"), "must report a private-only failure: {err}");
    }

    #[test]
    fn test_ssrf_blocks_cgnat_range() {
        let result = HttpPlugin::validate_url_ssrf("http://100.64.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_unspecified() {
        let result = HttpPlugin::validate_url_ssrf("http://0.0.0.0/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_ssrf_blocks_file_scheme() {
        let result = HttpPlugin::validate_url_ssrf("file:///etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_blocks_ftp_scheme() {
        let result = HttpPlugin::validate_url_ssrf("ftp://ftp.example.com/file");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_blocks_data_scheme() {
        let result = HttpPlugin::validate_url_ssrf("data:text/html,<h1>test</h1>");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scheme"));
    }

    #[test]
    fn test_ssrf_allows_https() {
        let result = HttpPlugin::validate_url_ssrf("https://api.example.com/v1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ssrf_allows_http() {
        let result = HttpPlugin::validate_url_ssrf("http://api.example.com/v1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_private_ip_ipv4() {
        use std::net::IpAddr;

        // Private IPs
        assert!(HttpPlugin::is_private_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"169.254.0.1".parse::<IpAddr>().unwrap()));

        // Public IPs should not be blocked
        assert!(!HttpPlugin::is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!HttpPlugin::is_private_ip(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv6() {
        use std::net::IpAddr;

        // Private IPv6
        assert!(HttpPlugin::is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"fe80::1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(&"fc00::1".parse::<IpAddr>().unwrap()));

        // Public IPv6
        assert!(!HttpPlugin::is_private_ip(&"2001:4860:4860::8888".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_validate_params_blocks_ssrf() {
        let plugin = HttpPlugin::new();

        // Should block private IP
        let params = serde_json::json!({
            "method": "GET",
            "url": "http://192.168.1.1/admin"
        });
        assert!(plugin.validate_params("request", &params).is_err());

        // Should block file:// scheme
        let params = serde_json::json!({
            "method": "GET",
            "url": "file:///etc/passwd"
        });
        assert!(plugin.validate_params("request", &params).is_err());
    }

    // OAuth2 Token Refresh Tests

    #[test]
    fn test_needs_refresh_none_expiration() {
        // No expiration should not trigger refresh
        assert!(!HttpPlugin::needs_refresh(None));
    }

    #[test]
    fn test_needs_refresh_future_expiration() {
        // Token expiring in 1 hour should not need refresh
        let expires = Utc::now() + Duration::hours(1);
        assert!(!HttpPlugin::needs_refresh(Some(expires)));
    }

    #[test]
    fn test_needs_refresh_near_expiration() {
        // Token expiring in 2 minutes should trigger refresh (within 5 min buffer)
        let expires = Utc::now() + Duration::minutes(2);
        assert!(HttpPlugin::needs_refresh(Some(expires)));
    }

    #[test]
    fn test_needs_refresh_expired() {
        // Already expired token should trigger refresh
        let expires = Utc::now() - Duration::minutes(5);
        assert!(HttpPlugin::needs_refresh(Some(expires)));
    }

    #[test]
    fn test_validate_token_url_requires_https() {
        // HTTP should be rejected
        let result = HttpPlugin::validate_token_url_ssrf("http://oauth.example.com/token");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));

        // HTTPS should be accepted
        let result = HttpPlugin::validate_token_url_ssrf("https://oauth.example.com/token");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_token_url_blocks_private_ip() {
        let result = HttpPlugin::validate_token_url_ssrf("https://192.168.1.1/token");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[test]
    fn test_inject_oauth2_with_token() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::OAuth2 {
            client_id: "client-123".to_string(),
            client_secret: Secret::new("secret-456"),
            refresh_token: None,
            access_token: Some(Secret::new("access-token-789")),
            expires_at: None,
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec![],
        };

        plugin.inject_credentials(&mut headers, &cred_data).unwrap();

        assert_eq!(
            headers.get("Authorization"),
            Some(&"Bearer access-token-789".to_string())
        );
    }

    #[test]
    fn test_inject_oauth2_without_token_fails() {
        let plugin = HttpPlugin::new();
        let mut headers = HashMap::new();

        let cred_data = CredentialData::OAuth2 {
            client_id: "client-123".to_string(),
            client_secret: Secret::new("secret-456"),
            refresh_token: None,
            access_token: None,
            expires_at: None,
            token_url: "https://oauth.example.com/token".to_string(),
            scopes: vec![],
        };

        let result = plugin.inject_credentials(&mut headers, &cred_data);
        assert!(result.is_err());
    }
}
