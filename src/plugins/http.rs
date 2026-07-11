//! HTTP authentication plugin
//!
//! Handles HTTP requests with credential injection:
//! - API Key authentication (Bearer tokens, custom headers)
//! - Basic Authentication
//! - OAuth2 (token refresh, etc.)
//! - URL-embedded tokens (secret substituted into the request path/query rather
//!   than a header — e.g. Telegram's `bot<TOKEN>/sendMessage`)

use super::{Plugin, PluginError, PluginRequest};
use crate::{CredentialData, CredentialType, ExecuteResponse, Secret};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

fn hmac_bytes(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[allow(clippy::too_many_arguments)] // mirrors the fixed AWS canonical-request fields
fn sign_aws_sigv4(
    headers: &mut HashMap<String, String>,
    method: &Method,
    url: &url::Url,
    body: &[u8],
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    now: DateTime<Utc>,
) -> Result<(), PluginError> {
    if access_key_id.trim().is_empty()
        || secret_access_key.is_empty()
        || region.trim().is_empty()
        || service.trim().is_empty()
    {
        return Err(PluginError::InvalidParams(
            "AWS SigV4 credential requires access key, secret key, region, and service".into(),
        ));
    }
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let host = url
        .host_str()
        .ok_or_else(|| PluginError::InvalidParams("AWS URL has no host".into()))?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    remove_header_ci(headers, "authorization");
    remove_header_ci(headers, "x-amz-date");
    remove_header_ci(headers, "x-amz-security-token");
    headers.insert("host".into(), host.clone());
    headers.insert("x-amz-date".into(), amz_date.clone());
    if let Some(token) = session_token {
        headers.insert("x-amz-security-token".into(), token.to_string());
    }
    let mut signed = vec![("host", host), ("x-amz-date", amz_date.clone())];
    if let Some(token) = session_token {
        signed.push(("x-amz-security-token", token.to_string()));
    }
    signed.sort_by_key(|(name, _)| *name);
    let canonical_headers = signed
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect::<String>();
    let signed_headers = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let payload_hash = hex::encode(Sha256::digest(body));
    let canonical_uri = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let canonical_query = url.query().unwrap_or("");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_bytes(format!("AWS4{secret_access_key}").as_bytes(), &date);
    let k_region = hmac_bytes(&k_date, region);
    let k_service = hmac_bytes(&k_region, service);
    let k_signing = hmac_bytes(&k_service, "aws4_request");
    let signature = hex::encode(hmac_bytes(&k_signing, &string_to_sign));
    headers.insert("Authorization".into(), format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"));
    Ok(())
}

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
            let public = filter_public_addrs(addrs)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::from(e) })?;
            let iter: Addrs = Box::new(public.into_iter());
            Ok(iter)
        })
    }
}

/// embedded_v4 reconstructs the IPv4 address carried in two IPv6 segments (used to
/// decode the IPv4 embedded in NAT64 / 6to4 prefixes so it can be SSRF-classified).
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (hi >> 8) as u8,
        (hi & 0xff) as u8,
        (lo >> 8) as u8,
        (lo & 0xff) as u8,
    )
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
///   - connect_timeout: bound only connection ESTABLISHMENT, never the whole
///     request — a total client `.timeout()` here would also kill the long-lived
///     SSE streaming path (`execute_request_streaming`), which shares this client.
///     The buffered path applies its own total read timeout per request instead.
///     (H4/timeouts, ported from fix/agent-boundary-hardening, streaming-reconciled.)
pub(crate) fn build_guarded_client() -> Client {
    Client::builder()
        .user_agent("vultrino/0.1.0")
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(SsrfGuardResolver))
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .expect("Failed to create HTTP client")
}

/// Total read timeout for a BUFFERED outbound request (applied per-request so it
/// never touches the streaming path, whose connections are intentionally long-lived).
pub(crate) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Connection-establishment timeout for every guarded client (safe for streaming —
/// it bounds only the TCP/TLS connect, not the stream lifetime).
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Hard cap on a BUFFERED response body read into memory. The in-path proxy holds
/// the fd-lock while it reads; an unbounded upstream body could OOM it. The streaming
/// path is not buffered (it is metered chunk-by-chunk by the server's usage tap).
pub(crate) const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// read_body_capped reads a buffered response body but refuses to buffer more than
/// [`MAX_RESPONSE_BYTES`], failing closed (an oversize / unbounded-chunked upstream
/// cannot OOM the in-path proxy). A declared oversize Content-Length is rejected up
/// front; a lying/chunked upstream is caught while streaming the bytes.
pub(crate) async fn read_body_capped(response: reqwest::Response) -> Result<Vec<u8>, PluginError> {
    use futures::StreamExt;
    if let Some(len) = response.content_length() {
        if len as usize > MAX_RESPONSE_BYTES {
            return Err(PluginError::Http(format!(
                "upstream response body {len} bytes exceeds the {MAX_RESPONSE_BYTES}-byte cap"
            )));
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        // .without_url(): reqwest's Display embeds the request URL, which for a
        // UrlToken credential contains the secret — never surface it in an error.
        let chunk = chunk.map_err(|e| PluginError::Http(e.without_url().to_string()))?;
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(PluginError::Http(format!(
                "upstream response body exceeds the {MAX_RESPONSE_BYTES}-byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

impl HttpPlugin {
    /// Create a new HTTP plugin
    pub fn new() -> Self {
        Self {
            client: build_guarded_client(),
        }
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
        let host = url
            .host_str()
            .ok_or_else(|| PluginError::InvalidParams("Token URL must have a host".to_string()))?;

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

        response.json::<TokenResponse>().await.map_err(|e| {
            PluginError::ExecutionFailed(format!("Failed to parse token response: {}", e))
        })
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

        response.json::<TokenResponse>().await.map_err(|e| {
            PluginError::ExecutionFailed(format!("Failed to parse token response: {}", e))
        })
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
                            self.fetch_client_credentials_token(
                                client_id,
                                client_secret,
                                token_url,
                                scopes,
                            )
                            .await?
                        }
                    }
                } else {
                    // No refresh token, use client credentials flow
                    self.fetch_client_credentials_token(client_id, client_secret, token_url, scopes)
                        .await?
                };

                // Calculate new expiration time. `expires_in` comes verbatim from the token endpoint, so
                // use checked arithmetic (a hostile/buggy huge value must not panic the credential path):
                // an unrepresentable/overflowing value resolves to None ("unknown expiry").
                let new_expires_at = token_response.expires_in.and_then(|secs| {
                    i64::try_from(secs)
                        .ok()
                        .and_then(Duration::try_seconds)
                        .and_then(|d| Utc::now().checked_add_signed(d))
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
                // Remove any agent-supplied case-variant first so the vault credential is the SOLE copy
                // of this header on the wire (no header shadowing / duplicate-Authorization confusion).
                remove_header_ci(headers, header_name);
                headers.insert(header_name.clone(), value);
            }

            CredentialData::BasicAuth { username, password } => {
                let credentials = format!("{}:{}", username, password.expose());
                let encoded = STANDARD.encode(credentials.as_bytes());
                remove_header_ci(headers, "Authorization");
                headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            }

            CredentialData::OAuth2 { access_token, .. } => {
                if let Some(token) = access_token {
                    remove_header_ci(headers, "Authorization");
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

    /// Substitute the `{URL_TOKEN_PLACEHOLDER}` placeholder in a request URL with a
    /// vault-held [`CredentialData::UrlToken`] secret (Telegram-style
    /// `bot<TOKEN>/sendMessage` APIs that put the secret in the URL path rather than
    /// a header — there is no header for the http plugin to inject it into). Fails
    /// closed:
    ///   - no placeholder present -> error. A `UrlToken` credential with nowhere to
    ///     inject is a misconfiguration, not a silent unauthenticated request.
    ///   - substitution changes the scheme or host -> error. The SSRF/url_glob
    ///     policy checks run against the pre-substitution URL (the `{credential}`
    ///     placeholder is inert to them); this guard makes sure the token itself
    ///     can't smuggle a different origin past those checks (REVIEW).
    ///
    /// Runs on the raw URL *string*, before `url::Url::parse`: the parser
    /// percent-encodes `{`/`}` (they're outside the path percent-encode set), so a
    /// literal-substring match against an already-parsed URL would never find the
    /// placeholder.
    fn substitute_url_token(url_str: &str, token: &Secret) -> Result<String, PluginError> {
        const PLACEHOLDER: &str = "{credential}";

        if !url_str.contains(PLACEHOLDER) {
            return Err(PluginError::InvalidParams(format!(
                "UrlToken credential requires a '{}' placeholder in the request URL",
                PLACEHOLDER
            )));
        }

        // Parse the PRE-substitution URL first to capture the scheme/host the
        // caller (and any upstream url_glob policy) actually approved. This parse
        // is safe to log/echo in errors below — it never contains the token.
        let before = url::Url::parse(url_str)
            .map_err(|e| PluginError::InvalidParams(format!("Invalid URL: {}", e)))?;

        let substituted = url_str.replace(PLACEHOLDER, token.expose());

        // Re-parse the substituted URL to check it's still well-formed and to
        // compare scheme/host — do NOT include the substituted string in any
        // error here, it now contains the secret.
        let after = url::Url::parse(&substituted).map_err(|_| {
            PluginError::InvalidParams("URL is invalid after credential substitution".to_string())
        })?;

        if after.scheme() != before.scheme() || after.host_str() != before.host_str() {
            return Err(PluginError::InvalidParams(
                "credential substitution altered the request scheme or host".to_string(),
            ));
        }

        Ok(substituted)
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
                // "This host on this network" — the WHOLE 0.0.0.0/8, not just
                // 0.0.0.0: on Linux 0.0.0.1 etc. route to the local host (Codex high).
                || ipv4.octets()[0] == 0
                // Shared address space (100.64.0.0/10 - CGNAT)
                || (ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64)
                // Loopback extended (127.0.0.0/8 - already covered by is_loopback)
                // Reserved for future use (240.0.0.0/4)
                || ipv4.octets()[0] >= 240
                // Local network control block (224.0.0.0/24)
                || (ipv4.octets()[0] == 224 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 0)
            }
            IpAddr::V6(ipv6) => {
                let seg = ipv6.segments();
                // Loopback (::1)
                ipv6.is_loopback()
                // Unspecified (::)
                || ipv6.is_unspecified()
                // Unique local (fc00::/7)
                || ((seg[0] & 0xfe00) == 0xfc00)
                // Link-local (fe80::/10)
                || ((seg[0] & 0xffc0) == 0xfe80)
                // IPv4-mapped addresses - check the IPv4 portion
                || Self::is_ipv4_mapped_private(ipv6)
                // NAT64 well-known prefix 64:ff9b::/96 — embedded IPv4 in the low 32
                // bits; decode + recurse so an internal IPv4 can't be reached via NAT64.
                || (seg[0] == 0x0064 && seg[1] == 0xff9b
                    && Self::is_private_ip(&IpAddr::V4(embedded_v4(seg[6], seg[7]))))
                // 6to4 2002::/16 — embedded IPv4 in segments [1..=2]; decode + recurse.
                || (seg[0] == 0x2002
                    && Self::is_private_ip(&IpAddr::V4(embedded_v4(seg[1], seg[2]))))
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
        let host = url
            .host_str()
            .ok_or_else(|| PluginError::InvalidParams("URL must have a host".to_string()))?;

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

    /// Build the guarded outbound request shared by the buffered and streaming
    /// paths: SSRF-validate the URL, OAuth-refresh if needed, inject the vault
    /// credential, force client-managed encoding, and attach headers/query/body.
    /// Returns the ready-to-send builder plus any refreshed credential to persist.
    ///
    /// Factored out so the streaming path ([`Self::execute_request_streaming`]) and
    /// the buffered path ([`Self::execute_request`]) share EXACTLY the same SSRF
    /// guards + credential injection — a streaming-only code path could otherwise
    /// drift from the buffered one and forget a guard.
    async fn prepare_request(
        &self,
        mut params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<(reqwest::RequestBuilder, Option<CredentialData>), PluginError> {
        // UrlToken credentials substitute the secret into the URL PATH before
        // anything else runs, so the SSRF host check just below (and the DNS-
        // resolving SsrfGuardResolver at connect time) validate the REAL
        // destination (e.g. api.telegram.org), not the `{credential}` placeholder.
        // `substitute_url_token` itself guards against the substitution smuggling
        // a different scheme/host past the checks that already ran on the
        // placeholder URL (request-time url_glob policy, upstream of this plugin).
        if let CredentialData::UrlToken { token } = cred_data {
            params.url = Self::substitute_url_token(&params.url, token)?;
        }

        // Validate URL for SSRF before proceeding
        let mut validated_url = Self::validate_url_ssrf(&params.url)?;

        // Parse method
        let method = Method::from_str(&params.method.to_uppercase()).map_err(|_| {
            PluginError::InvalidParams(format!("Invalid HTTP method: {}", params.method))
        })?;

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

        // SigV4 signs the complete request target. Merge caller query parameters
        // into the URL before signing (in deterministic order) so reqwest cannot
        // append unsigned parameters after the Authorization header is produced.
        let uses_aws_sigv4 = matches!(effective_cred, CredentialData::AwsSigV4 { .. });
        if uses_aws_sigv4 && !params.query.is_empty() {
            let mut query = validated_url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            query.extend(
                params
                    .query
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            query.sort();
            validated_url.set_query(None);
            validated_url.query_pairs_mut().extend_pairs(query);
        }

        // Build headers with credential injection. First drop agent-supplied routing / hop-by-hop
        // headers (Host-routing tricks, request smuggling) — reqwest derives these from the validated
        // URL + body, and an agent on this governed capability path must not control them.
        let mut headers = params.headers;
        strip_unsafe_request_headers(&mut headers);
        let aws_body = match &params.body {
            Some(body) => {
                serde_json::to_vec(body).map_err(|e| PluginError::InvalidParams(e.to_string()))?
            }
            None => Vec::new(),
        };
        match &effective_cred {
            CredentialData::AwsSigV4 {
                access_key_id,
                secret_access_key,
                session_token,
                region,
                service,
            } => {
                sign_aws_sigv4(
                    &mut headers,
                    &method,
                    &validated_url,
                    &aws_body,
                    access_key_id,
                    secret_access_key.expose(),
                    session_token.as_ref().map(Secret::expose),
                    region,
                    service,
                    Utc::now(),
                )?;
            }
            // The token was already substituted into the URL above; no header to set.
            CredentialData::UrlToken { .. } => {}
            _ => self.inject_credentials(&mut headers, &effective_cred)?,
        }

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
        if !uses_aws_sigv4 && !params.query.is_empty() {
            request = request.query(&params.query);
        }

        // Add body
        if params.body.is_some() {
            if uses_aws_sigv4 {
                request = request
                    .header("content-type", "application/json")
                    .body(aws_body);
            } else if let Some(body) = params.body {
                request = request.json(&body);
            }
        }

        Ok((request, updated_credential))
    }

    /// Execute an HTTP request, buffering the whole response body.
    async fn execute_request(
        &self,
        params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<ExecuteResponse, PluginError> {
        let (request, updated_credential) = self.prepare_request(params, cred_data).await?;

        // Execute request. The total read timeout is applied PER-REQUEST here (not on
        // the shared client) so it bounds this buffered call without truncating the
        // long-lived SSE streaming path, which shares the same client.
        let response = request
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            // .without_url(): see read_body_capped — the request URL may embed a
            // UrlToken secret and reqwest's Display would otherwise echo it.
            .map_err(|e| PluginError::Http(e.without_url().to_string()))?;

        // Extract response details
        let status = response.status().as_u16();
        let response_headers = collect_response_headers(response.headers());

        let body = read_body_capped(response).await?;

        Ok(ExecuteResponse {
            status,
            headers: response_headers,
            body,
            updated_credential,
        })
    }

    /// Execute an HTTP request, returning the response body as an **incremental
    /// stream** (connector M1, streaming LLM proxy). Status + headers (+ any
    /// refreshed credential) are known before the body, so a pre-stream error is
    /// surfaced with the correct status; the body chunks flow through the server's
    /// scrub + usage tap before reaching the agent. Same guarded client, same SSRF
    /// + credential injection as the buffered path (via [`Self::prepare_request`]).
    async fn execute_request_streaming(
        &self,
        params: HttpRequestParams,
        cred_data: &CredentialData,
    ) -> Result<crate::StreamingResponse, PluginError> {
        use futures::StreamExt;

        let (request, updated_credential) = self.prepare_request(params, cred_data).await?;

        let response = request
            .send()
            .await
            // .without_url(): see read_body_capped — the request URL may embed a
            // UrlToken secret and reqwest's Display would otherwise echo it.
            .map_err(|e| PluginError::Http(e.without_url().to_string()))?;

        let status = response.status().as_u16();
        let response_headers = collect_response_headers(response.headers());

        // The upstream body as a chunk stream. A transport error mid-stream becomes
        // a stream `Err`, which the server's adaptor turns into a terminal SSE error
        // (it never reflects upstream detail to the agent). No body byte is buffered.
        let body = response
            .bytes_stream()
            .map(|r| r.map_err(|e| PluginError::Http(e.without_url().to_string())));

        Ok(crate::StreamingResponse {
            status,
            headers: response_headers,
            body: Box::pin(body),
            updated_credential,
        })
    }
}

/// Collect reqwest response headers into the plain `HashMap` shape vultrino's
/// response types use, dropping any non-UTF-8 header value (those can't be
/// scrubbed/forwarded as a `String` and don't carry model output).
fn collect_response_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect()
}

/// Remove any caller-supplied `Accept-Encoding` so the HTTP client negotiates
/// and auto-decompresses the response itself — preventing an agent from
/// requesting a compressed body to evade egress secret-redaction.
fn force_client_managed_encoding(headers: &mut HashMap<String, String>) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case("accept-encoding"));
}

/// Remove every header whose name case-insensitively equals `name`. The header map is case-sensitive,
/// so an agent-supplied case-variant (`authorization`) would otherwise survive alongside the canonical
/// one we inject — used so the vault credential header is the sole copy on the wire.
fn remove_header_ci(headers: &mut HashMap<String, String>, name: &str) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
}

/// Drop agent-supplied routing / hop-by-hop headers the PEP must control: `Host` (host-routing tricks
/// against the upstream), `Content-Length` / `Transfer-Encoding` (request smuggling), `Connection`
/// (hop-by-hop), and `Content-Encoding` (the body is set by us). reqwest derives all of these from the
/// validated URL + body, so an agent on the governed capability path can never inject them.
fn strip_unsafe_request_headers(headers: &mut HashMap<String, String>) {
    const UNSAFE: [&str; 5] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "content-encoding",
    ];
    headers.retain(|k, _| !UNSAFE.iter().any(|u| k.eq_ignore_ascii_case(u)));
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
            CredentialType::AwsSigV4,
            CredentialType::UrlToken,
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

    async fn execute_streaming(
        &self,
        request: PluginRequest,
    ) -> Result<crate::StreamingResponse, PluginError> {
        match request.action.as_str() {
            "request" => {
                let params: HttpRequestParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;

                self.execute_request_streaming(params, &request.credential.data)
                    .await
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        match action {
            "request" => {
                // Validate required fields
                let obj = params
                    .as_object()
                    .ok_or_else(|| PluginError::InvalidParams("Expected object".to_string()))?;

                if !obj.contains_key("method") {
                    return Err(PluginError::InvalidParams(
                        "Missing 'method' field".to_string(),
                    ));
                }

                if !obj.contains_key("url") {
                    return Err(PluginError::InvalidParams(
                        "Missing 'url' field".to_string(),
                    ));
                }

                // Validate method is valid
                let method = obj["method"].as_str().ok_or_else(|| {
                    PluginError::InvalidParams("'method' must be a string".to_string())
                })?;

                Method::from_str(&method.to_uppercase()).map_err(|_| {
                    PluginError::InvalidParams(format!("Invalid HTTP method: {}", method))
                })?;

                // Validate URL with SSRF protection
                let url = obj["url"].as_str().ok_or_else(|| {
                    PluginError::InvalidParams("'url' must be a string".to_string())
                })?;

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

    fn resp_with_body(body: Vec<u8>) -> reqwest::Response {
        reqwest::Response::from(http::Response::new(body))
    }

    #[tokio::test]
    async fn read_body_capped_allows_within_limit() {
        let body = vec![7u8; 4096];
        let got = read_body_capped(resp_with_body(body.clone()))
            .await
            .unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn read_body_capped_rejects_oversize_declared_length() {
        // http::Response sets Content-Length from the body, so an over-cap body is
        // rejected up front via the content_length pre-check.
        let body = vec![0u8; MAX_RESPONSE_BYTES + 1];
        let err = read_body_capped(resp_with_body(body)).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("cap"),
            "want a cap-exceeded error, got {err:?}"
        );
    }

    #[test]
    fn aws_sigv4_signs_bedrock_without_exposing_secret() {
        let mut headers = HashMap::new();
        let url = url::Url::parse(
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic/invoke",
        )
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        sign_aws_sigv4(
            &mut headers,
            &Method::POST,
            &url,
            br#"{"input":"hi"}"#,
            "AKIDEXAMPLE",
            "very-secret-key",
            Some("session-token"),
            "us-east-1",
            "bedrock-runtime",
            now,
        )
        .unwrap();
        let auth = headers.get("Authorization").unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/bedrock-runtime/aws4_request")
        );
        assert!(!auth.contains("very-secret-key"));
        assert_eq!(
            headers.get("x-amz-date").map(String::as_str),
            Some("20260102T030405Z")
        );
        assert_eq!(
            headers.get("x-amz-security-token").map(String::as_str),
            Some("session-token")
        );
    }

    #[test]
    fn agent_cannot_shadow_or_duplicate_the_credential_header() {
        // An agent-supplied case-variant of the credential header must NOT survive next to the injected
        // vault credential — the vault header must be the SOLE copy on the wire.
        let plugin = HttpPlugin::new();
        let mut headers = std::collections::HashMap::new();
        headers.insert("authorization".to_string(), "Bearer attacker".to_string()); // lowercase variant
        headers.insert("X-Other".to_string(), "ok".to_string());
        let cred = CredentialData::ApiKey {
            key: Secret::new("vault-secret"),
            header_name: "Authorization".to_string(),
            header_prefix: "Bearer ".to_string(),
        };
        plugin.inject_credentials(&mut headers, &cred).unwrap();
        let auth: Vec<_> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .collect();
        assert_eq!(auth.len(), 1, "exactly one Authorization header");
        assert_eq!(
            auth[0].1, "Bearer vault-secret",
            "the vault credential wins"
        );
        assert_eq!(headers.get("X-Other").map(String::as_str), Some("ok"));
    }

    #[test]
    fn strip_unsafe_request_headers_drops_routing_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Host".to_string(), "evil.example.com".to_string());
        headers.insert("content-length".to_string(), "999".to_string());
        headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
        headers.insert("X-Keep".to_string(), "ok".to_string());
        strip_unsafe_request_headers(&mut headers);
        assert!(!headers.keys().any(|k| k.eq_ignore_ascii_case("host")));
        assert!(!headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-length")));
        assert!(!headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("transfer-encoding")));
        assert_eq!(headers.get("X-Keep").map(String::as_str), Some("ok"));
    }

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
            assert!(!headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("accept-encoding")));
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

    // UrlToken credential tests

    #[test]
    fn test_substitute_url_token_replaces_placeholder() {
        let token = Secret::new("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11");
        let substituted = HttpPlugin::substitute_url_token(
            "https://api.telegram.org/bot{credential}/sendMessage",
            &token,
        )
        .unwrap();

        assert_eq!(
            substituted,
            "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage"
        );
        // Host must be exactly the pre-substitution host — the real target.
        let url = url::Url::parse(&substituted).unwrap();
        assert_eq!(url.host_str(), Some("api.telegram.org"));
    }

    #[test]
    fn test_substitute_url_token_fails_closed_without_placeholder() {
        let token = Secret::new("some-secret-token");
        let result =
            HttpPlugin::substitute_url_token("https://api.telegram.org/sendMessage", &token);
        assert!(matches!(result, Err(PluginError::InvalidParams(_))));
    }

    #[test]
    fn test_substitute_url_token_rejects_host_change() {
        // Non-special schemes parse the host "opaque" (url crate: `{`/`}` are not
        // forbidden opaque-host characters, unlike the strict domain validation
        // http/https use), so a placeholder can legally sit inside the host here.
        // Once the real token is substituted in, the host textually changes — the
        // guard must reject that even though validate_url_ssrf (elsewhere) already
        // restricts schemes to http/https; this proves the guard's own logic holds
        // independent of that separate defense.
        let token = Secret::new("evil.example.com");
        let result = HttpPlugin::substitute_url_token("myapp://api.{credential}/path", &token);
        assert!(matches!(result, Err(PluginError::InvalidParams(_))));
    }

    #[tokio::test]
    async fn test_prepare_request_url_token_substitutes_and_sets_no_header() {
        let plugin = HttpPlugin::new();
        let cred_data = CredentialData::UrlToken {
            token: Secret::new("123456:ABC-DEF"),
        };
        let params = HttpRequestParams {
            method: "POST".to_string(),
            url: "https://api.telegram.org/bot{credential}/sendMessage".to_string(),
            headers: HashMap::new(),
            query: HashMap::new(),
            body: None,
        };

        let (request_builder, _updated) = plugin.prepare_request(params, &cred_data).await.unwrap();
        let request = request_builder.build().unwrap();

        assert_eq!(
            request.url().as_str(),
            "https://api.telegram.org/bot123456:ABC-DEF/sendMessage"
        );
        assert_eq!(request.url().host_str(), Some("api.telegram.org"));
        // No auth header — the secret lives only in the URL for this credential type.
        assert!(request.headers().get("Authorization").is_none());
    }

    #[tokio::test]
    async fn test_prepare_request_url_token_fails_closed_without_placeholder() {
        let plugin = HttpPlugin::new();
        let cred_data = CredentialData::UrlToken {
            token: Secret::new("123456:ABC-DEF"),
        };
        let params = HttpRequestParams {
            method: "POST".to_string(),
            url: "https://api.telegram.org/sendMessage".to_string(),
            headers: HashMap::new(),
            query: HashMap::new(),
            body: None,
        };

        let result = plugin.prepare_request(params, &cred_data).await;
        assert!(matches!(result, Err(PluginError::InvalidParams(_))));
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
        assert!(
            err.contains("private"),
            "must report a private-only failure: {err}"
        );
    }

    #[test]
    fn test_ssrf_blocks_this_host_range() {
        // 0.0.0.0/8 ("this host on this network") — not just 0.0.0.0 (Codex high).
        for url in [
            "http://0.0.0.1/api",
            "http://0.1.2.3/api",
            "http://0.0.0.0/api",
        ] {
            let r = HttpPlugin::validate_url_ssrf(url);
            assert!(r.is_err(), "{url} must be blocked (0.0.0.0/8)");
        }
    }

    #[test]
    fn test_ssrf_blocks_nat64_and_6to4_embedded_private() {
        use std::net::{IpAddr, Ipv6Addr};
        // NAT64 64:ff9b::/96 embedding 169.254.169.254 -> blocked via recursion.
        let nat64 = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe); // 169.254.169.254
        assert!(
            HttpPlugin::is_private_ip(&IpAddr::V6(nat64)),
            "NAT64-embedded link-local must be blocked"
        );
        // 6to4 2002::/16 embedding 10.0.0.1 -> blocked.
        let v6to4 = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 0); // 10.0.0.1
        assert!(
            HttpPlugin::is_private_ip(&IpAddr::V6(v6to4)),
            "6to4-embedded RFC1918 must be blocked"
        );
        // NAT64 embedding a PUBLIC IPv4 (8.8.8.8) is allowed (no false positive).
        let nat64_pub = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808);
        assert!(
            !HttpPlugin::is_private_ip(&IpAddr::V6(nat64_pub)),
            "NAT64-embedded public IPv4 must be allowed"
        );
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
        assert!(HttpPlugin::is_private_ip(
            &"127.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(HttpPlugin::is_private_ip(
            &"10.0.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(HttpPlugin::is_private_ip(
            &"172.16.0.1".parse::<IpAddr>().unwrap()
        ));
        assert!(HttpPlugin::is_private_ip(
            &"192.168.1.1".parse::<IpAddr>().unwrap()
        ));
        assert!(HttpPlugin::is_private_ip(
            &"169.254.0.1".parse::<IpAddr>().unwrap()
        ));

        // Public IPs should not be blocked
        assert!(!HttpPlugin::is_private_ip(
            &"8.8.8.8".parse::<IpAddr>().unwrap()
        ));
        assert!(!HttpPlugin::is_private_ip(
            &"1.1.1.1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ip_ipv6() {
        use std::net::IpAddr;

        // Private IPv6
        assert!(HttpPlugin::is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(HttpPlugin::is_private_ip(
            &"fe80::1".parse::<IpAddr>().unwrap()
        ));
        assert!(HttpPlugin::is_private_ip(
            &"fc00::1".parse::<IpAddr>().unwrap()
        ));

        // Public IPv6
        assert!(!HttpPlugin::is_private_ip(
            &"2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
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
