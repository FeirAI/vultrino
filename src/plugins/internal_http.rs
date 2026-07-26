//! `internal_http` — governed HTTP to an OPERATOR-PINNED internal destination.
//!
//! Plan 103 D8 / fork F8. The `http` plugin's SSRF guard rejects every
//! loopback/private/ClusterIP destination unconditionally and has no bypass
//! anywhere in the repo — deliberately, because on `http` the *agent* supplies
//! the URL. A local payments-sandbox service is therefore unreachable through
//! `http.request`, and weakening that guard would turn the stated SSRF invariant
//! into "unless the operator pinned a destination".
//!
//! This plugin takes the opposite shape: **the destination is not part of the
//! request at all.**
//!
//! - Each destination is declared in `config.toml` as `[[internal_destinations]]`
//!   with an exact `base_url` (scheme + host + port, no globs), a method
//!   allowlist and a path allowlist. Operator authority, validated at startup.
//! - Which destination a call reaches comes from the **vault credential's
//!   `internal_destination` metadata** — admin-authored, and the caller can only
//!   name credentials its policy/use-token scope already allows. A credential
//!   with no `internal_destination` cannot be used here at all.
//! - The request carries only `url` (a RELATIVE path + optional query), `method`,
//!   `query`, `body`. An absolute URL, a protocol-relative `//host`, an encoded
//!   separator or a `..` segment is refused; the composed target is re-checked
//!   for origin + base-path containment after normalization.
//! - Redirects are never followed and a redirect STATUS is refused, so the vault
//!   credential cannot be walked off the pinned origin by the destination itself.
//!
//! Caller influence over scheme/host/port is therefore exactly zero, and the
//! `http` plugin is untouched (`src/plugins/http.rs` is byte-identical).

use super::http::{CONNECT_TIMEOUT, REQUEST_TIMEOUT};
use super::{read_body_capped, Plugin, PluginError, PluginRequest};
use crate::config::InternalDestination;
use crate::{CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Method};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

/// Credential metadata key naming the operator-declared destination this
/// credential may be used against. REQUIRED — a credential without it is
/// refused (fail-closed: there is no default destination).
pub const META_DESTINATION: &str = "internal_destination";
/// Optional credential metadata key narrowing this credential further to a path
/// prefix *inside* the destination (e.g. the refund credential pinned to
/// `/v1/refunds`), so separate scoped credentials per money action are enforced
/// by vultrino and not only by convention.
pub const META_PATH_PREFIX: &str = "internal_path_prefix";
/// Optional credential metadata key narrowing this credential to a subset of the
/// destination's `allow_methods` (comma- or space-separated verbs). Together with
/// [`META_PATH_PREFIX`] this is what makes "refund cred != payout cred != read
/// cred" a vultrino-enforced *method+path* scope rather than a convention: a read
/// credential declares `GET` and can never POST, even to a path it may read.
pub const META_ALLOW_METHODS: &str = "internal_allow_methods";

/// Request headers the PEP must own on this path.
///
/// The destination is OPERATOR authority (`config.toml`), while a credential and
/// its metadata are ADMIN-API authority (govder / `orgpack apply`). Those are not
/// the same actor, so a credential must not be able to re-route *inside* the
/// pinned origin: `Host` selects a different virtual host on the same address,
/// and the framing headers are request-smuggling primitives. This is the same
/// list `http.rs` strips from agent-supplied headers — here it is applied to the
/// credential's own `header_name`, which is the only header source this plugin has.
const OPERATOR_OWNED_HEADERS: [&str; 5] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "content-encoding",
];

/// Whether `ip` is inside the INTERNAL address space this plugin exists to reach.
///
/// This is the deliberate mirror image of the `http` plugin's connect-time
/// public-only filter (`filter_public_addrs`): between the two plugins, no single
/// egress path can reach both address spaces, and the SSRF story stays sayable in
/// one sentence per plugin.
///
/// It is an ALLOWLIST, not `!is_private_ip`: that classifier counts
/// `169.254.0.0/16` as private, and that is the cloud-metadata range — an
/// "internal" destination must never resolve there. Accepted: IPv4 loopback,
/// RFC1918, CGNAT (100.64/10 — EKS pod space); IPv6 loopback, unique-local
/// (fc00::/7), and IPv4-mapped forms of the above. Everything else (public,
/// link-local/metadata, 0.0.0.0/8, documentation, multicast, broadcast, NAT64 and
/// 6to4 encodings) is refused.
pub(crate) fn is_internal_destination_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_internal_destination_ip(&IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            v6.is_loopback() || (seg[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Belt-and-braces assertion that the internal allowlist above never admits an
/// address the `http` plugin's public-only guard would also admit — i.e. the two
/// plugins' reachable address spaces are provably disjoint. Test-only.
#[cfg(test)]
fn internal_and_public_spaces_are_disjoint(ip: &IpAddr) -> bool {
    if is_internal_destination_ip(ip) {
        // Everything `internal_http` may reach must be something the `http`
        // plugin's guard classifies as private, i.e. refuses.
        super::HttpPlugin::is_private_ip(ip)
    } else {
        true
    }
}

/// The canonical verbs a request may name. Mirrors the config-side verb list;
/// anything else is refused before the destination is even resolved.
const VERBS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Request params for `internal_http.request`.
///
/// `deny_unknown_fields` is load-bearing: it is what makes a caller-supplied
/// `destination`, `base_url`, `host` or `headers` a hard, *pre-side-effect*
/// refusal instead of a silently ignored field. It also means an operator's
/// capability `input_schema` must expose exactly these names.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalHttpParams {
    /// RELATIVE reference within the pinned destination: `/v1/refunds`, or
    /// `/v1/transactions?flagged=1`. MUST start with a single `/`. This is also
    /// the string the policy engine's `url_glob` conditions match against
    /// (`server::execute_gated` reads `params["url"]`), so an operator bounds the
    /// path surface with the same policy dimension the `http` plugin uses.
    pub url: String,
    /// HTTP method. Checked against the destination's `allow_methods`.
    pub method: String,
    /// Extra query parameters, merged into the composed URL.
    #[serde(default)]
    pub query: HashMap<String, String>,
    /// JSON request body.
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

/// Connect-time resolver for declared destinations addressed by NAME.
///
/// Two guards, both fail-closed:
/// 1. the hostname must belong to a declared destination (an unpinned name never
///    resolves at all);
/// 2. every resolved address must be in the internal space
///    ([`is_internal_destination_ip`]) — so a hostile or compromised DNS answer
///    cannot walk the vault credential to a public host or to the cloud-metadata
///    endpoint. This is the DNS-rebinding half, and it is the exact mirror of
///    `http.rs`'s `SsrfGuardResolver`, which keeps only PUBLIC answers.
///
/// **Honest bound on where this fires.** hyper-util skips a custom resolver
/// entirely when the URL host is already an IP literal
/// (`hyper-util/src/client/legacy/connect/http.rs:541` →
/// `dns::SocketAddrs::try_parse`, `dns.rs:190-204`), so for the shipped
/// `base_url = "http://127.0.0.1:PORT"` shape this resolver is NEVER consulted.
/// IP-literal destinations are classified at CONFIG-PARSE time instead
/// (`config::parse_internal_destination`), which is the only place they can be
/// checked. Between the two, coverage is total. The same asymmetry exists in
/// `http.rs` (literals vetted by `validate_url_ssrf`, names by the resolver).
struct PinnedHostResolver {
    hosts: HashSet<String>,
}

impl Resolve for PinnedHostResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let permitted = self.hosts.contains(&host);
        Box::pin(async move {
            if !permitted {
                return Err::<Addrs, Box<dyn std::error::Error + Send + Sync>>(Box::from(format!(
                    "internal_http: host '{host}' is not a declared internal destination"
                )));
            }
            let lookup = host.clone();
            let resolved: std::io::Result<Vec<SocketAddr>> =
                tokio::task::spawn_blocking(move || {
                    (lookup.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|it| it.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let addrs = resolved
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let internal: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| is_internal_destination_ip(&a.ip()))
                .collect();
            if internal.is_empty() {
                return Err::<Addrs, Box<dyn std::error::Error + Send + Sync>>(Box::from(format!(
                    "internal_http: destination host '{host}' resolved to no internal address \
                     (a public, link-local or cloud-metadata answer is refused)"
                )));
            }
            let iter: Addrs = Box::new(internal.into_iter());
            Ok(iter)
        })
    }
}

/// The `internal_http` plugin.
pub struct InternalHttpPlugin {
    client: Client,
    destinations: Vec<InternalDestination>,
}

impl InternalHttpPlugin {
    /// Build the plugin over the operator's declared destinations. An empty list
    /// is legal and means every call is refused ("no internal destination is
    /// configured") — a money capability routed here on a vultrino with no
    /// destination fails closed rather than falling back to the `http` plugin.
    pub fn new(destinations: Vec<InternalDestination>) -> Self {
        let hosts: HashSet<String> = destinations
            .iter()
            .filter_map(|d| d.base_url.host_str().map(|h| h.to_ascii_lowercase()))
            .collect();
        let client = Client::builder()
            .user_agent("vultrino/0.1.0")
            .redirect(reqwest::redirect::Policy::none())
            // MUST come before/with the resolver: reqwest honours HTTP_PROXY /
            // HTTPS_PROXY / ALL_PROXY from the environment by DEFAULT. With a proxy
            // in effect, hyper connects to the PROXY host and sends the vault
            // credential there — and if the proxy is an IP literal, the pinned-host
            // resolver is not even consulted (hyper-util skips it for literals), so
            // nothing else would catch it. An internal destination is by definition
            // directly reachable, so a proxy is never correct here: refuse the whole
            // mechanism rather than depend on the deployment's environment.
            .no_proxy()
            .dns_resolver(Arc::new(PinnedHostResolver { hosts }))
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("Failed to create internal HTTP client");
        Self {
            client,
            destinations,
        }
    }

    fn destination(&self, name: &str) -> Option<&InternalDestination> {
        self.destinations.iter().find(|d| d.name == name)
    }

    /// Shape-check the caller-supplied relative reference. This runs in
    /// `validate_params` — i.e. BEFORE the use token is consumed — so a smuggling
    /// attempt never burns a use.
    ///
    /// Refuses, in order: an empty value; an ASCII control character, space or
    /// `#`; anything with a scheme (`http:`, `https:`, `file:`, `javascript:`); a
    /// protocol-relative `//host`; a backslash (some servers treat `\` as a
    /// separator); an encoded separator (`%2f`, `%5c`) or encoded dot (`%2e`); a
    /// literal `..` segment; and a missing leading `/`.
    ///
    /// The control-character/`#` rule closes a DIVERGENCE class rather than an
    /// SSRF: `params["url"]` is the string the policy engine matches
    /// (`server::execute_gated`), the string an approval summary shows a human
    /// approver, and the string sealed into the audit/averin record — while the
    /// WHATWG URL parser **strips** tab/LF/CR and **drops** a fragment when the
    /// request is composed. Without this rule a money action could be reviewed and
    /// recorded as `/v1/led<TAB>ger` (or `/v1/ledger#x`) and executed as
    /// `/v1/ledger`. On an approval-gated money path the reviewed string and the
    /// executed path must be the same string.
    pub fn validate_relative_reference(raw: &str) -> Result<(), PluginError> {
        let refuse = |why: &str| {
            Err(PluginError::InvalidParams(format!(
                "internal_http: 'url' must be a path within the pinned destination ({why}); \
                 the destination is operator-configured and cannot be supplied by the caller"
            )))
        };
        // NO trim: a leading/trailing space would make the policy-matched and
        // audited string differ from the executed path in exactly the same way an
        // interior tab would. The value must BE the path, byte for byte.
        let s = raw;
        if s.is_empty() {
            return refuse("it is empty");
        }
        if s.chars().any(|c| c.is_control() || c == ' ') {
            return refuse(
                "it contains a control character or space, which URL normalization would strip \
                 or re-encode — the reviewed/audited string must equal the executed path",
            );
        }
        if s.contains('#') {
            return refuse(
                "it carries a fragment, which is never sent to the server — the \
                 reviewed/audited string must equal the executed path",
            );
        }
        let lower = s.to_ascii_lowercase();
        // A scheme can only appear before the first '/', '?' or '#'.
        let head_end = s.find(['/', '?', '#']).unwrap_or(s.len());
        if s[..head_end].contains(':') {
            return refuse("it carries a scheme");
        }
        if s.starts_with("//") || s.starts_with("/\\") || s.starts_with("\\") {
            return refuse("it carries an authority");
        }
        if !s.starts_with('/') {
            return refuse("it is not rooted at '/'");
        }
        if s.contains('\\') {
            return refuse("it contains a backslash");
        }
        if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e") {
            return refuse("it contains an encoded path separator or dot");
        }
        if s.split(['/', '?']).any(|seg| seg == "..") {
            return refuse("it contains a '..' segment");
        }
        Ok(())
    }

    /// Uppercase + verb-check the caller's method (also pre-side-effect).
    fn normalize_method(raw: &str) -> Result<String, PluginError> {
        let m = raw.trim().to_ascii_uppercase();
        if !VERBS.contains(&m.as_str()) {
            return Err(PluginError::InvalidParams(format!(
                "internal_http: method '{}' is not an allowed HTTP verb",
                raw
            )));
        }
        Ok(m)
    }

    /// Compose the absolute target from the pinned base and the caller's relative
    /// reference, then re-verify containment AFTER url normalization (which
    /// resolves any dot segments the shape check did not already refuse). The
    /// composed URL must stay on the destination's scheme, host, port AND base
    /// path prefix. Mirrors the containment discipline of
    /// `Capability::llm_upstream_url`.
    fn compose(dest: &InternalDestination, relative: &str) -> Result<url::Url, PluginError> {
        let base_str = dest.base_url.as_str().trim_end_matches('/');
        let joined = format!("{}{}", base_str, relative);
        let target = url::Url::parse(&joined).map_err(|e| {
            PluginError::InvalidParams(format!("internal_http: composed target is invalid: {e}"))
        })?;
        let base = &dest.base_url;
        if target.scheme() != base.scheme()
            || target.host_str() != base.host_str()
            || target.port_or_known_default() != base.port_or_known_default()
        {
            return Err(PluginError::InvalidParams(
                "internal_http: composed target left the pinned destination origin".to_string(),
            ));
        }
        let base_path = base.path().trim_end_matches('/');
        let target_path = target.path();
        let contained = if base_path.is_empty() {
            target_path.starts_with('/')
        } else {
            target_path == base_path || target_path.starts_with(&format!("{}/", base_path))
        };
        if !contained {
            return Err(PluginError::InvalidParams(
                "internal_http: composed target left the pinned destination base path".to_string(),
            ));
        }
        Ok(target)
    }

    /// Reject a credential whose `header_name` is one the PEP must own, or which is
    /// not a legal RFC 9110 field name.
    ///
    /// The destination is operator authority (`config.toml`); a credential is
    /// admin-API authority (govder / `orgpack apply`). Those differ, so an
    /// admin-authored credential must not be able to re-route inside the pinned
    /// origin (`Host` → a different virtual host on the same address) or smuggle a
    /// second request into the connection (`Content-Length` / `Transfer-Encoding`).
    /// `http.rs` strips exactly this list from agent-supplied headers; here the
    /// credential is the only header source, so the check lives here.
    fn validate_header_name(name: &str) -> Result<(), PluginError> {
        if name.is_empty() {
            return Err(PluginError::InvalidParams(
                "internal_http: credential header_name must not be empty".to_string(),
            ));
        }
        // RFC 9110 token: visible ASCII minus the separators.
        const SEPARATORS: &str = "()<>@,;:\\\"/[]?={} \t";
        if !name
            .chars()
            .all(|c| c.is_ascii_graphic() && !SEPARATORS.contains(c))
        {
            return Err(PluginError::InvalidParams(format!(
                "internal_http: credential header_name '{}' is not a legal HTTP field name",
                name
            )));
        }
        if OPERATOR_OWNED_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
        {
            return Err(PluginError::InvalidParams(format!(
                "internal_http: credential header_name '{}' is a routing/framing header the \
                 proxy must own — a credential may not re-route or re-frame a request inside \
                 the operator-pinned destination",
                name
            )));
        }
        Ok(())
    }

    /// Reject a header VALUE carrying CR/LF/NUL. reqwest would refuse it later with
    /// an opaque builder error; refusing here names the cause and keeps the failure
    /// on the pre-side-effect side of the request.
    fn validate_header_value(value: &str) -> Result<(), PluginError> {
        if value.contains('\r') || value.contains('\n') || value.contains('\0') {
            return Err(PluginError::InvalidParams(
                "internal_http: credential header value contains a control character"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Inject the vault credential. Only the two header-shaped credential types
    /// are supported; anything else (OAuth2 refresh flows, SigV4, a UrlToken that
    /// would put a secret in the path) is refused rather than half-handled.
    fn inject_credentials(
        headers: &mut HashMap<String, String>,
        data: &CredentialData,
    ) -> Result<(), PluginError> {
        match data {
            CredentialData::ApiKey {
                key,
                header_name,
                header_prefix,
            } => {
                Self::validate_header_name(header_name)?;
                let value = format!("{}{}", header_prefix, key.expose());
                Self::validate_header_value(&value)?;
                headers.insert(header_name.clone(), value);
                Ok(())
            }
            CredentialData::BasicAuth { username, password } => {
                let encoded =
                    STANDARD.encode(format!("{}:{}", username, password.expose()).as_bytes());
                headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
                Ok(())
            }
            other => Err(PluginError::UnsupportedCredentialType(format!(
                "internal_http supports api_key and basic_auth credentials only (got {:?})",
                other.credential_type()
            ))),
        }
    }

    async fn execute_request(
        &self,
        params: InternalHttpParams,
        credential: &crate::Credential,
    ) -> Result<ExecuteResponse, PluginError> {
        // 1. Destination comes from the CREDENTIAL, never from the request.
        let dest_name = credential
            .metadata
            .get(META_DESTINATION)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                PluginError::InvalidParams(format!(
                    "internal_http: credential '{}' has no '{}' metadata — an internal \
                     destination must be pinned on the credential by an operator",
                    credential.alias, META_DESTINATION
                ))
            })?;
        let dest = self.destination(dest_name).ok_or_else(|| {
            PluginError::InvalidParams(format!(
                "internal_http: credential '{}' names internal destination '{}', which is not \
                 declared in this vultrino's configuration",
                credential.alias, dest_name
            ))
        })?;

        // 2. Re-run the caller-input shape checks (validate_params already ran
        //    them on the request path; re-running here keeps the plugin sound if
        //    it is ever invoked directly).
        Self::validate_relative_reference(&params.url)?;
        let method_str = Self::normalize_method(&params.method)?;

        // 3. Compose + containment. The raw `url` is used verbatim (not trimmed):
        //    it is the same string policy matched and an approver reviewed.
        let mut target = Self::compose(dest, &params.url)?;

        // 4. Operator allowlists, on the NORMALIZED path.
        if !dest.method_allowed(&method_str) {
            return Err(PluginError::InvalidParams(format!(
                "internal_http: method {} is not allowed on internal destination '{}'",
                method_str, dest.name
            )));
        }
        if !dest.path_allowed(target.path()) {
            return Err(PluginError::InvalidParams(format!(
                "internal_http: path '{}' is not on internal destination '{}'s path allowlist",
                target.path(),
                dest.name
            )));
        }
        // 5a. Optional per-credential METHOD narrowing. A read credential declares
        //     `internal_allow_methods = "GET"` and can never POST, even to a path it
        //     may read — so "refund cred != payout cred != read cred" is enforced on
        //     both dimensions by vultrino, not just by the sandbox's own scopes.
        if let Some(raw) = credential
            .metadata
            .get(META_ALLOW_METHODS)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let allowed: Vec<String> = raw
                .split([',', ' ', '\t'])
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty())
                .collect();
            if !allowed.iter().any(|m| m == &method_str) {
                return Err(PluginError::InvalidParams(format!(
                    "internal_http: credential '{}' is scoped to methods [{}] and may not {}",
                    credential.alias,
                    allowed.join(", "),
                    method_str
                )));
            }
        }
        // 5b. Optional per-credential PATH narrowing (refund cred != payout cred).
        if let Some(prefix) = credential
            .metadata
            .get(META_PATH_PREFIX)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let p = target.path();
            let ok = if let Some(stripped) = prefix.strip_suffix('/') {
                p == stripped || p.starts_with(prefix)
            } else {
                p == prefix
            };
            if !ok {
                return Err(PluginError::InvalidParams(format!(
                    "internal_http: credential '{}' is pinned to '{}' and may not reach '{}'",
                    credential.alias, prefix, p
                )));
            }
        }

        // 6. Merge caller query params (they cannot alter the origin or path).
        if !params.query.is_empty() {
            let mut pairs: Vec<(String, String)> = params
                .query
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            pairs.sort();
            target.query_pairs_mut().extend_pairs(pairs);
        }

        // 7. Credential injection. The caller supplies NO headers at all on this
        //    plugin (`deny_unknown_fields` refuses a `headers` field), so there is
        //    no agent-controlled header to strip.
        let mut headers: HashMap<String, String> = HashMap::new();
        Self::inject_credentials(&mut headers, &credential.data)?;

        let method = Method::from_str(&method_str).map_err(|_| {
            PluginError::InvalidParams(format!("internal_http: invalid method {method_str}"))
        })?;
        let mut request = self.client.request(method, target);
        for (k, v) in &headers {
            request = request.header(k, v);
        }
        if let Some(body) = params.body {
            request = request.json(&body);
        }

        let response = request
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| PluginError::Http(e.without_url().to_string()))?;

        let status = response.status();
        // Redirects are NOT followed (Policy::none) — and a redirect status is
        // refused outright, so a compromised/misbehaving internal destination
        // cannot use a 30x to walk the vault credential to another origin, and
        // the agent never receives a half-answer with a Location it can chase.
        if status.is_redirection() {
            return Err(PluginError::Http(format!(
                "internal_http: internal destination returned {} — redirects are not followed",
                status.as_u16()
            )));
        }

        let status = status.as_u16();
        let response_headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        // `read_body_capped` applies the shared `MAX_RESPONSE_BYTES` ceiling (both
        // a declared oversize Content-Length and a lying/chunked upstream).
        let body = read_body_capped(response).await?;

        Ok(ExecuteResponse {
            status,
            headers: response_headers,
            body,
            updated_credential: None,
        })
    }
}

#[async_trait]
impl Plugin for InternalHttpPlugin {
    fn name(&self) -> &str {
        "internal_http"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey, CredentialType::BasicAuth]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["request"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "request" => {
                let params: InternalHttpParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                self.execute_request(params, &request.credential).await
            }
            _ => Err(PluginError::UnsupportedAction(request.action)),
        }
    }

    fn validate_params(&self, action: &str, params: &serde_json::Value) -> Result<(), PluginError> {
        match action {
            "request" => {
                // Strict deserialization is the gate: an unknown field (a
                // caller-supplied `destination`, `base_url`, `host`, `headers`)
                // fails here, BEFORE the use token is consumed.
                let params: InternalHttpParams = serde_json::from_value(params.clone())
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                Self::validate_relative_reference(&params.url)?;
                Self::normalize_method(&params.method)?;
                Ok(())
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    /// No `url_patterns`: this plugin must never be auto-selected by URL. It is
    /// reachable only through an explicit `internal_http.request` action (an
    /// `[[action_labels]]` row or a canonical action), never as a default.
    fn url_patterns(&self) -> Vec<&str> {
        vec![]
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn description(&self) -> Option<&str> {
        Some("HTTP to an operator-pinned internal destination (no caller-supplied host)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn dest(base: &str, paths: &[&str], methods: &[&str]) -> InternalDestination {
        let toml = format!(
            "[[internal_destinations]]\nname = \"sandbox\"\nbase_url = \"{base}\"\n\
             allow_methods = [{}]\nallow_paths = [{}]\n",
            methods
                .iter()
                .map(|m| format!("\"{m}\""))
                .collect::<Vec<_>>()
                .join(", "),
            paths
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        Config::parse(&toml)
            .expect("destination parses")
            .internal_destinations
            .remove(0)
    }

    #[test]
    fn relative_reference_rejects_every_host_smuggling_shape() {
        let bad = [
            "http://evil.example/v1/refunds",
            "https://evil.example/v1/refunds",
            "//evil.example/v1/refunds",
            "\\\\evil.example/v1/refunds",
            "/\\evil.example/v1/refunds",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "v1/refunds",       // not rooted
            "/v1/../../admin",  // traversal
            "/v1/%2e%2e/admin", // encoded traversal
            "/v1/%2f/admin",    // encoded separator
            "/v1\\admin",       // backslash separator
            "",
        ];
        for b in bad {
            assert!(
                InternalHttpPlugin::validate_relative_reference(b).is_err(),
                "expected refusal for {b:?}"
            );
        }
        for good in ["/v1/refunds", "/v1/transactions?flagged=1", "/"] {
            assert!(
                InternalHttpPlugin::validate_relative_reference(good).is_ok(),
                "expected acceptance for {good:?}"
            );
        }
    }

    #[test]
    fn compose_stays_on_the_pinned_origin_and_base_path() {
        let d = dest("http://127.0.0.1:18099/api", &["/api/v1/"], &["GET"]);
        let ok = InternalHttpPlugin::compose(&d, "/v1/ledger").unwrap();
        assert_eq!(ok.as_str(), "http://127.0.0.1:18099/api/v1/ledger");
        assert!(d.path_allowed(ok.path()));

        // A dot-segment escape that got past a shape check would still be caught
        // by the containment re-check after normalization.
        let escaped = InternalHttpPlugin::compose(&d, "/../admin");
        assert!(escaped.is_err(), "dot-segment escape must be refused");
    }

    #[test]
    fn path_and_method_allowlists_are_default_deny() {
        let d = dest(
            "http://127.0.0.1:18099",
            &["/v1/refunds", "/v1/accounts/"],
            &["POST", "GET"],
        );
        assert!(d.path_allowed("/v1/refunds"));
        assert!(d.path_allowed("/v1/accounts/acc_1"));
        assert!(d.path_allowed("/v1/accounts"));
        assert!(!d.path_allowed("/v1/refunds/secret"));
        assert!(!d.path_allowed("/v1/payouts"));
        assert!(!d.path_allowed("/admin"));
        assert!(d.method_allowed("POST"));
        assert!(!d.method_allowed("DELETE"));
    }

    #[test]
    fn params_refuse_caller_supplied_destination_or_headers() {
        let plugin = InternalHttpPlugin::new(vec![]);
        for bad in [
            serde_json::json!({"url":"/v1/refunds","method":"POST","destination":"other"}),
            serde_json::json!({"url":"/v1/refunds","method":"POST","base_url":"http://evil"}),
            serde_json::json!({"url":"/v1/refunds","method":"POST","host":"evil"}),
            serde_json::json!({"url":"/v1/refunds","method":"POST","headers":{"Host":"evil"}}),
            serde_json::json!({"url":"http://evil/v1","method":"POST"}),
            serde_json::json!({"url":"/v1/refunds","method":"CONNECT"}),
            serde_json::json!({"method":"POST"}),
        ] {
            assert!(
                plugin.validate_params("request", &bad).is_err(),
                "expected refusal for {bad}"
            );
        }
        assert!(plugin
            .validate_params(
                "request",
                &serde_json::json!({"url":"/v1/refunds","method":"post","body":{"amount":1}})
            )
            .is_ok());
    }

    #[test]
    fn config_rejects_over_broad_or_malformed_destinations() {
        let cases = [
            // glob host
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://*.local\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]",
            // no scheme
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"127.0.0.1:18099\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]",
            // non-http scheme
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"file:///etc\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]",
            // userinfo
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://u:p@127.0.0.1:1\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]",
            // no methods
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_paths=[\"/v1\"]",
            // no paths
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"GET\"]",
            // glob path
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1/*\"]",
            // unrooted path
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"GET\"]\nallow_paths=[\"v1\"]",
            // bogus verb
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"FETCH\"]\nallow_paths=[\"/v1\"]",
            // duplicate name
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]\n[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:2\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]",
            // unknown field (typo protection)
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\nallow_methods=[\"GET\"]\nallow_paths=[\"/v1\"]\nallow_hosts=[\"evil\"]",
        ];
        for c in cases {
            assert!(
                Config::parse(c).is_err(),
                "expected config rejection for:\n{c}"
            );
        }
        // The shipped shape parses.
        let ok = Config::parse(
            "[[internal_destinations]]\nname=\"finsandbox\"\nbase_url=\"http://127.0.0.1:18099\"\n\
             allow_methods=[\"GET\",\"POST\"]\nallow_paths=[\"/v1/refunds\",\"/v1/ledger\"]",
        )
        .unwrap();
        assert_eq!(ok.internal_destinations.len(), 1);
        assert_eq!(ok.internal_destinations[0].name, "finsandbox");
    }

    #[test]
    fn plugin_is_never_url_auto_selected() {
        let plugin = InternalHttpPlugin::new(vec![]);
        assert!(plugin.url_patterns().is_empty());
        assert!(plugin.mcp_tool_definitions().is_empty());
    }

    // -------------------------------------------------------------------
    // Hardening added when the spike was landed (P2 adversarial review)
    // -------------------------------------------------------------------

    /// The reviewed/audited string must equal the executed path: URL
    /// normalization strips tab/LF/CR and drops a fragment, so those characters
    /// would let `params["url"]` (what policy matched, what an approver read,
    /// what the seal recorded) differ from the path actually requested.
    #[test]
    fn relative_reference_refuses_normalization_stripped_characters() {
        for bad in [
            "/v1/led\tger",
            "/v1/led\nger",
            "/v1/led\rger",
            "/v1/ledger\n",
            "/v1/ led ger",
            " /v1/ledger",
            "/v1/ledger ",
            "/v1/ledger#frag",
            "/v1/ledger\u{0}",
        ] {
            let err = InternalHttpPlugin::validate_relative_reference(bad)
                .expect_err(&format!("must refuse {bad:?}"));
            let msg = err.to_string();
            assert!(
                msg.contains("control character or space") || msg.contains("fragment"),
                "refusal for {bad:?} must name the reason, got: {msg}"
            );
        }
    }

    /// A credential is admin-API authority; the destination is operator authority.
    /// A credential may not re-route (`Host`) or re-frame (`Content-Length` /
    /// `Transfer-Encoding`) a request inside the pinned destination.
    #[test]
    fn credential_header_name_cannot_be_a_routing_or_framing_header() {
        for bad in [
            "Host",
            "host",
            "HOST",
            "Content-Length",
            "Transfer-Encoding",
            "connection",
            "Content-Encoding",
        ] {
            let mut h = HashMap::new();
            let err = InternalHttpPlugin::inject_credentials(
                &mut h,
                &CredentialData::ApiKey {
                    key: crate::Secret::new("s3cret"),
                    header_name: bad.to_string(),
                    header_prefix: String::new(),
                },
            )
            .expect_err(&format!("must refuse header_name {bad:?}"));
            assert!(
                err.to_string().contains("routing/framing header"),
                "got: {err}"
            );
            assert!(h.is_empty(), "no header may be injected on refusal");
        }
        // Illegal field names are refused too (CRLF injection shape included).
        for bad in ["Auth orization", "Auth\r\nX-Evil: 1", "Auth:", ""] {
            let mut h = HashMap::new();
            assert!(InternalHttpPlugin::inject_credentials(
                &mut h,
                &CredentialData::ApiKey {
                    key: crate::Secret::new("s3cret"),
                    header_name: bad.to_string(),
                    header_prefix: String::new(),
                },
            )
            .is_err());
        }
        // The shipped shape still injects.
        let mut h = HashMap::new();
        InternalHttpPlugin::inject_credentials(
            &mut h,
            &CredentialData::ApiKey {
                key: crate::Secret::new("s3cret"),
                header_name: "Authorization".to_string(),
                header_prefix: "Bearer ".to_string(),
            },
        )
        .unwrap();
        assert_eq!(h.get("Authorization").map(String::as_str), Some("Bearer s3cret"));
    }

    /// The internal-space allowlist is the mirror image of the `http` plugin's
    /// public-only guard: the two reachable address spaces are disjoint, and the
    /// cloud-metadata range — which `is_private_ip` counts as private — is NOT
    /// internal.
    #[test]
    fn internal_address_space_is_an_allowlist_and_excludes_metadata() {
        let internal = [
            "127.0.0.1",
            "127.1.2.3",
            "10.96.0.1",
            "172.16.5.4",
            "172.31.255.255",
            "192.168.1.10",
            "100.64.0.7",
            "::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ];
        let refused = [
            "169.254.169.254", // AWS/GCP/Azure IMDS — is_private_ip() says private
            "169.254.0.1",     // link-local generally
            "0.0.0.0",
            "0.0.0.1",
            "8.8.8.8",
            "93.184.216.34",
            "192.0.2.1", // documentation
            "224.0.0.1", // multicast
            "255.255.255.255",
            "172.32.0.1", // just outside RFC1918
            "100.128.0.1", // just outside CGNAT
            "fe80::1",
            "2001:4860:4860::8888",
            "64:ff9b::0a00:0001", // NAT64-encoded 10.0.0.1
            "2002:0a00:0001::1",  // 6to4-encoded 10.0.0.1
            "::ffff:8.8.8.8",
        ];
        for ip in internal {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_internal_destination_ip(&ip), "{ip} must be internal");
            assert!(internal_and_public_spaces_are_disjoint(&ip), "{ip}");
        }
        for ip in refused {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(
                !is_internal_destination_ip(&ip),
                "{ip} must NOT be an internal destination"
            );
        }
    }

    /// An IP-literal destination outside the internal space is refused at config
    /// load — the only place it CAN be refused, because hyper-util skips the
    /// custom resolver for literals.
    #[test]
    fn config_refuses_a_non_internal_ip_literal_destination() {
        for host in [
            "http://169.254.169.254",
            "http://8.8.8.8",
            "https://93.184.216.34:8443",
            "http://[fe80::1]:80",
            "http://0.0.0.0:8080",
        ] {
            let toml = format!(
                "[[internal_destinations]]\nname=\"s\"\nbase_url=\"{host}\"\n\
                 allow_methods=[\"GET\"]\nallow_paths=[\"/v1/x\"]"
            );
            let err = Config::parse(&toml).expect_err(&format!("must refuse {host}"));
            assert!(
                format!("{err}").contains("is not an internal address"),
                "got: {err}"
            );
        }
        // The internal shapes still parse.
        for host in [
            "http://127.0.0.1:18099",
            "http://10.96.0.42:8080",
            "http://[::1]:18099",
            "http://finsandbox.feir-os.svc.cluster.local:8080",
        ] {
            let toml = format!(
                "[[internal_destinations]]\nname=\"s\"\nbase_url=\"{host}\"\n\
                 allow_methods=[\"GET\"]\nallow_paths=[\"/v1/x\"]"
            );
            Config::parse(&toml).unwrap_or_else(|e| panic!("{host} must parse: {e}"));
        }
    }

    /// A bare `/` allow_paths entry is a silent allow-all (prefix = ""), so it is
    /// refused loudly at config load.
    #[test]
    fn config_refuses_a_bare_slash_path_allowlist() {
        let err = Config::parse(
            "[[internal_destinations]]\nname=\"s\"\nbase_url=\"http://127.0.0.1:1\"\n\
             allow_methods=[\"GET\"]\nallow_paths=[\"/\"]",
        )
        .expect_err("a bare '/' must be refused");
        assert!(format!("{err}").contains("would allow EVERY path"), "got: {err}");
    }
}
