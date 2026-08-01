//! Configuration system for Vultrino
//!
//! Loads configuration from TOML files and environment variables.

mod types;

pub use types::*;

use crate::policy::Policy;
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),

    #[error("Failed to read configuration: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse configuration: {0}")]
    ParseError(String),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Main Vultrino configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security policies
    pub policies: Vec<Policy>,
    /// MCP server configuration
    pub mcp: McpConfig,
    /// Action approval configuration
    pub approval: crate::approval::ApprovalConfig,
    /// Engine-level enforcement defaults (V2: default-deny mode).
    pub enforcement: EnforcementConfig,
    /// Amount-extraction rules for SpendCap policies (V3).
    pub spend_extractors: Vec<crate::policy::SpendExtractor>,
    /// Egress classification rules (V7).
    pub egress: Vec<crate::egress::EgressRule>,
    /// govder action-label → canonical plugin.action map (V8).
    pub action_labels: std::collections::HashMap<String, String>,
    /// Signed event-outbox delivery config (V9).
    pub outbox: crate::outbox::OutboxConfig,
    /// Per-tenant enforcement mode (V11): a tenant absent here uses
    /// [`TenantMode::Enforce`]. Lets one team run enforce while another observes.
    pub tenants: std::collections::HashMap<String, TenantMode>,
    /// Inbound workload-identity resolution (V10/R6): resolve an SVID/OIDC
    /// document presented on a request into the principal evaluated by policy.
    /// `None` = no resolver wired (principal stays the `vk_`/`vut_` id).
    pub identity: Option<IdentityConfig>,
    /// Server-held secret keying the policy `content_hash` (D2). The hash the
    /// inventory list and create/replace responses emit is an
    /// **HMAC-SHA256(secret, canonical-policy-bytes)**, not a bare digest — so a
    /// compromised read-only key cannot brute-force the reduced DTO back into the
    /// full enforcement topology offline. Sourced from `VULTRINO_POLICY_HASH_SECRET`
    /// at startup (not parsed from the TOML, so a config dump never carries it).
    /// MUST be stable across restarts (a per-process random salt would make every
    /// authored hash mismatch on restart → false drift). `None` = no secret
    /// configured: `content_hash` is emitted **empty** (the oracle is removed and
    /// govder degrades gracefully — it skips drift detection on an empty hash).
    /// Never falls back to a bare unkeyed digest.
    pub policy_hash_secret: Option<String>,
    /// Metered LLM-proxy tunables (connector M1, streaming): the streaming
    /// kill-switch, the `stream_options.include_usage` injection toggle, and the
    /// stream-safety DoS caps. Defaults are streaming-on with conservative caps.
    pub llm_proxy: LlmProxyConfig,
    /// Govder decide-plane client config (plan 031). Sourced from
    /// `GOVDER_BASE_URL` + `GOVDER_TENANT_ASSERTION_SECRET` at startup — not TOML.
    pub govder: Option<crate::govder::GovderConfig>,
    /// averin seal-client config (plan 086, the "fourth contract"). Parsed from
    /// the `[averin]` TOML block; `enabled` defaults to **false**, so the seal
    /// path is off and `/execute` is byte-identical unless explicitly turned on.
    /// The API key is filled from `AVERIN_API_KEY` at startup (never TOML).
    pub averin: crate::averin::AverinConfig,
    /// Operator-pinned internal destinations for the `internal_http` plugin
    /// (plan 103 D8/F8). Empty = the plugin is registered but refuses every
    /// call ("no internal destination is configured"), which is the fail-closed
    /// posture: a money capability pointed at `internal_http.request` on a
    /// vultrino with no declared destination fails, it does not fall back to the
    /// `http` plugin.
    pub internal_destinations: Vec<InternalDestination>,
}

/// One operator-pinned internal destination (plan 103 D8/F8), validated at
/// config load. The caller/agent never supplies any part of this: the request
/// carries only a path (+ optional query), method and body.
#[derive(Debug, Clone)]
pub struct InternalDestination {
    /// The name a vault credential binds to via its `internal_destination`
    /// metadata. Lower-case `[a-z0-9_-]+`, unique.
    pub name: String,
    /// Normalized absolute base: scheme + host + port (+ optional base path,
    /// no trailing slash). No userinfo, no query, no fragment, no glob.
    pub base_url: url::Url,
    /// Uppercase HTTP verbs this destination accepts. Non-empty (a destination
    /// with no methods would accept nothing, which is an authoring error).
    pub allow_methods: Vec<String>,
    /// Path allowlist. An entry ending in `/` is a prefix match; any other
    /// entry is an exact match. Non-empty, no globs, no dot segments.
    pub allow_paths: Vec<String>,
}

impl InternalDestination {
    /// Whether `method` (already uppercased) is on this destination's verb list.
    pub fn method_allowed(&self, method: &str) -> bool {
        self.allow_methods.iter().any(|m| m == method)
    }

    /// Whether the NORMALIZED request path is on this destination's path
    /// allowlist. Prefix entries (`/v1/accounts/`) match anything beneath them;
    /// every other entry must match exactly.
    pub fn path_allowed(&self, path: &str) -> bool {
        self.allow_paths.iter().any(|p| {
            if let Some(prefix) = p.strip_suffix('/') {
                path == prefix || path.starts_with(p)
            } else {
                path == p
            }
        })
    }
}

/// Validate + normalize one `[[internal_destinations]]` entry. Fail-closed: every
/// rejection here is an operator error surfaced at startup rather than a
/// request-time surprise.
fn parse_internal_destination(
    raw: types::RawInternalDestination,
) -> Result<InternalDestination, ConfigError> {
    let name = raw.name.trim().to_string();
    if name.is_empty() {
        return Err(ConfigError::Invalid(
            "internal_destinations: name must not be empty".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations: name '{}' must be lower-case [a-z0-9_-] (no globs, no dots)",
            name
        )));
    }

    // Base URL: an EXACT origin. Anything glob-ish, credential-bearing or
    // query/fragment-bearing is rejected — the destination is a pinned origin,
    // not a pattern.
    let base_raw = raw.base_url.trim();
    if base_raw.contains('*') || base_raw.contains('?') || base_raw.contains('#') {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url must be an exact scheme://host[:port][/base-path] \
             with no glob, query or fragment",
            name
        )));
    }
    let base = url::Url::parse(base_raw.trim_end_matches('/')).map_err(|e| {
        ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url is not a valid URL: {}",
            name, e
        ))
    })?;
    match base.scheme() {
        "http" | "https" => {}
        other => {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': base_url scheme '{}' is not allowed (http|https only)",
                name, other
            )))
        }
    }
    if base.host_str().unwrap_or("").is_empty() {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url must have a host",
            name
        )));
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url must not carry userinfo",
            name
        )));
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url must not carry a query or fragment",
            name
        )));
    }
    if base.path().contains("..") {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': base_url path must not contain dot segments",
            name
        )));
    }
    // An IP-LITERAL host must be in the internal address space, checked HERE
    // because it is the only place it can be: hyper-util skips a custom DNS
    // resolver entirely for IP literals (`connect/http.rs:541` →
    // `dns::SocketAddrs::try_parse`), so `internal_http`'s connect-time
    // internal-space filter never sees them. Without this check an operator could
    // point `internal_http` — whose whole premise is "internal only" — at
    // 169.254.169.254 or at a public host, and the vault credential would go there
    // with no guard at all. A NAME-addressed destination is checked at connect time.
    if let Ok(ip) = base
        .host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        if !crate::plugins::is_internal_destination_ip(&ip) {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': base_url host {} is not an internal address. \
                 internal_http reaches ONLY loopback, RFC1918, CGNAT and IPv6 \
                 unique-local/loopback space; a public, link-local or cloud-metadata \
                 address is refused (use the `http` plugin for public destinations, \
                 which enforces the mirror-image guard)",
                name, ip
            )));
        }
    }

    // Methods: non-empty, real verbs, uppercased.
    const VERBS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
    let mut allow_methods = Vec::new();
    for m in &raw.allow_methods {
        let m = m.trim().to_ascii_uppercase();
        if !VERBS.contains(&m.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': allow_methods entry '{}' is not an HTTP verb",
                name, m
            )));
        }
        if !allow_methods.contains(&m) {
            allow_methods.push(m);
        }
    }
    if allow_methods.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': allow_methods must list at least one HTTP verb",
            name
        )));
    }

    // Paths: non-empty, rooted, no globs, no dot segments, no percent-encoding
    // (an encoded separator in an ALLOWLIST entry can only obscure what it
    // permits — the request-side check rejects encoded separators too).
    let mut allow_paths = Vec::new();
    for p in &raw.allow_paths {
        let p = p.trim().to_string();
        if !p.starts_with('/') {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': allow_paths entry '{}' must start with '/'",
                name, p
            )));
        }
        if p.contains('*') || p.contains('?') || p.contains('[') || p.contains(']') {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': allow_paths entry '{}' must not contain a glob \
                 (use a trailing '/' for a prefix)",
                name, p
            )));
        }
        if p.contains("..") || p.contains('%') || p.contains('\\') {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': allow_paths entry '{}' must not contain dot segments, \
                 percent-encoding or backslashes",
                name, p
            )));
        }
        // A bare "/" is a SILENT allow-all: it is a prefix entry whose prefix is the
        // empty string, so `path_allowed` returns true for every path an operator
        // believed they had enumerated. Refuse it loudly instead — the whole point
        // of the allowlist is that reading the config tells you the blast radius.
        if p == "/" {
            return Err(ConfigError::Invalid(format!(
                "internal_destinations '{}': allow_paths entry '/' would allow EVERY path on \
                 this destination (it is a prefix whose prefix is empty). List the paths or \
                 prefixes the destination really exposes",
                name
            )));
        }
        if !allow_paths.contains(&p) {
            allow_paths.push(p);
        }
    }
    if allow_paths.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "internal_destinations '{}': allow_paths must list at least one path (a destination \
             with no path allowlist would accept nothing)",
            name
        )));
    }

    Ok(InternalDestination {
        name,
        base_url: base,
        allow_methods,
        allow_paths,
    })
}

/// Tunables for the metered LLM proxy's streaming path (connector M1).
///
/// All defaults make streaming work out of the box (`streaming_enabled = true`)
/// with usage injection on and conservative resource caps. An operator can flip
/// `streaming_enabled` off as a kill-switch (a `stream:true` request then has its
/// stream flags stripped and is served buffered), or tune the caps for unusually
/// long/large completions.
#[derive(Debug, Clone)]
pub struct LlmProxyConfig {
    /// Master switch for incremental SSE streaming. When `false`, a `stream:true`
    /// request still works: vultrino strips the stream flags so the upstream
    /// returns a single JSON body and serves it on the buffered path (so an
    /// operator disabling streaming never breaks a client, only de-streams it).
    pub streaming_enabled: bool,
    /// When `true` and a streamed OpenAI-chat request omits
    /// `stream_options.include_usage`, vultrino injects `include_usage = true` so
    /// the provider emits a terminal usage chunk and V13b token metering fires. An
    /// explicit client value (true OR false) is always honored, never overwritten.
    pub inject_stream_usage: bool,
    /// Abort a stream that goes this many seconds without producing a chunk
    /// (slow-loris upstream). `0` disables the idle timeout.
    pub stream_idle_timeout_secs: u64,
    /// Abort a stream that runs longer than this many seconds total (a
    /// never-ending stream). `0` disables the total timeout.
    pub stream_total_timeout_secs: u64,
    /// Abort a stream once it has forwarded more than this many bytes to the agent
    /// (unbounded body). `0` disables the byte cap.
    pub stream_max_bytes: u64,
    /// Fail closed if a single un-delimited SSE line / scrub carry-buffer would
    /// exceed this many bytes (a delimiter-less giant line would otherwise OOM).
    /// Must be > 0, and must comfortably exceed the longest credential secret form
    /// (the scrub carry is sized off that): a secret form approaching this cap would
    /// make every stream for that capability fail closed. The 4 MiB default is far
    /// above any real secret.
    pub stream_max_line_bytes: usize,
}

impl Default for LlmProxyConfig {
    fn default() -> Self {
        Self {
            streaming_enabled: true,
            inject_stream_usage: true,
            // 2 min between chunks, 30 min total — generous for long completions
            // while still bounding a stuck/slow-loris upstream.
            stream_idle_timeout_secs: 120,
            stream_total_timeout_secs: 1800,
            // 256 MiB forwarded / 4 MiB single-line cap — far above any real
            // completion, low enough to stop an unbounded/OOM stream.
            stream_max_bytes: 256 * 1024 * 1024,
            stream_max_line_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Inbound workload-identity resolution config (V10/R6). A request carrying the
/// configured `header` (an **already transport-verified** SVID or OIDC claims
/// document) has its principal resolved from that document before policy
/// evaluation. The header is trusted: a deployment must terminate mTLS / verify
/// the token at the edge and pass the verified document in this header.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Which resolver maps the inbound document to a principal.
    pub kind: IdentityResolverKind,
    /// Inbound header carrying the verified document (lower-cased for matching).
    pub header: String,
    /// Allowlist: SPIFFE trust domains, or OIDC issuers (empty = accept any).
    pub allowed: Vec<String>,
}

/// The inbound resolver kind wired into the request path (V10/R6). Only the two
/// complete, pure resolvers are wireable inbound; the cloud-IAM claim adapters
/// need per-cloud verification and stay integration-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityResolverKind {
    Spiffe,
    Oidc,
}

/// How a tenant's policy denials are handled (V11 multi-tenancy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenantMode {
    /// A policy `Deny` blocks the action (the secure default).
    #[default]
    Enforce,
    /// A policy `Deny` is **logged and emitted but not blocked** — the action
    /// runs anyway. Lets a team onboard in observe-only mode while another team
    /// on the same vultrino enforces.
    Observe,
}

impl Config {
    /// The enforcement mode for a principal's tenant (V11). Untenanted principals
    /// and tenants not listed default to [`TenantMode::Enforce`] (fail-closed).
    pub fn tenant_mode(&self, tenant: Option<&str>) -> TenantMode {
        match tenant {
            Some(t) => self.tenants.get(t).copied().unwrap_or_default(),
            None => TenantMode::Enforce,
        }
    }
}

impl Config {
    /// Resolve a presented action: if it is a configured govder label, return
    /// `(canonical_plugin_action, Some(label))`; otherwise it is already a
    /// canonical `plugin.action`, so `(presented, None)` (V8).
    pub fn resolve_action(&self, presented: &str) -> (String, Option<String>) {
        match self.action_labels.get(presented) {
            Some(canonical) => (canonical.clone(), Some(presented.to_string())),
            None => (presented.to_string(), None),
        }
    }

    /// Whether at least one configured business label dispatches to this exact
    /// canonical plugin action. A caller that presents the canonical spelling
    /// directly has discarded which label (and therefore which Govder gate key)
    /// it meant whenever this is true. Approval lookup must not interpret that
    /// ambiguity as permission to use the weaker numeric fallback.
    pub fn canonical_action_has_labels(&self, canonical: &str) -> bool {
        self.action_labels
            .values()
            .any(|configured| configured == canonical)
    }
}

/// Whether `s` is a well-formed canonical `plugin.action` — a non-empty plugin
/// and a non-empty action separated by a `.`. Used to validate `action_labels`
/// targets at config load so a typo can't silently route to a default plugin.
fn is_well_formed_action(s: &str) -> bool {
    matches!(s.split_once('.'), Some((plugin, action)) if !plugin.is_empty() && !action.is_empty())
}

/// Engine-level enforcement configuration.
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// What the policy engine decides for a credential that matches **no**
    /// policy. Defaults to [`EnforcementDefault::Deny`] (fail-closed).
    pub default_action: EnforcementDefault,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        // Fail-closed by default: an un-policied credential is denied. This is
        // the govder enforcement posture and closes the historical fail-open
        // gap. Operators who want the legacy behavior opt in with
        // `[enforcement] default_action = "allow"`.
        Self {
            default_action: EnforcementDefault::Deny,
        }
    }
}

/// Policy-engine decision for a credential that matches no policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDefault {
    /// Allow un-policied credentials (legacy fail-open).
    Allow,
    /// Deny un-policied credentials (fail-closed; default).
    Deny,
}

impl Config {
    /// Load configuration from a file
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path).await?;
        let raw: RawConfig =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        Self::from_raw(raw)
    }

    /// Load configuration from a string
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        Self::from_raw(raw)
    }

    /// Convert from raw TOML config to validated config
    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        let server = raw.server.unwrap_or_default().try_into()?;
        let storage = raw.storage.unwrap_or_default().try_into()?;
        let logging = raw.logging.unwrap_or_default().into();
        let mcp = raw.mcp.unwrap_or_default().into();
        let approval = raw
            .approvals
            .map(TryInto::try_into)
            .transpose()?
            .unwrap_or_default();
        let enforcement = raw
            .enforcement
            .map(EnforcementConfig::try_from)
            .transpose()?
            .unwrap_or_default();
        let spend_extractors = raw.spend_extractors.into_iter().map(Into::into).collect();
        let egress = raw
            .egress
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        // Validate action-label mappings at load (fail-closed): a malformed or
        // ambiguous mapping is an operator error we surface now, rather than a
        // deferred footgun that only fails at request time.
        let mut action_labels = std::collections::HashMap::new();
        for a in raw.action_labels {
            let label = a.label.trim().to_string();
            let action = a.action.trim().to_string();
            if label.is_empty() || action.is_empty() {
                return Err(ConfigError::Invalid(
                    "action_labels: label and action must both be non-empty".to_string(),
                ));
            }
            // The canonical target must be a well-formed `plugin.action`, so a
            // typo can't silently route to the default `http` plugin later.
            if !is_well_formed_action(&action) {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: action '{}' for label '{}' is not a well-formed 'plugin.action'",
                    action, label
                )));
            }
            // A label that equals its own target, or shadows another label's
            // target, would make resolution ambiguous/circular — reject it.
            if label == action {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: label '{}' must differ from its canonical action",
                    label
                )));
            }
            if action_labels.insert(label.clone(), action).is_some() {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: duplicate label '{}'",
                    label
                )));
            }
        }
        // A label must not shadow another mapping's canonical target (which would
        // make `resolve_action` order-dependent on that target).
        for canonical in action_labels.values() {
            if action_labels.contains_key(canonical) {
                return Err(ConfigError::Invalid(format!(
                    "action_labels: '{}' is both a label and a canonical action target",
                    canonical
                )));
            }
        }

        let policies = raw
            .policies
            .into_iter()
            .map(|p| p.try_into())
            .collect::<Result<Vec<Policy>, _>>()?;
        // Validate spend-cap structural invariants (fail-closed, no nesting).
        for p in &policies {
            p.validate().map_err(ConfigError::Invalid)?;
        }

        let outbox = raw
            .outbox
            .map(TryInto::try_into)
            .transpose()?
            .unwrap_or_default();

        // Per-tenant enforcement mode (V11).
        let mut tenants = std::collections::HashMap::new();
        for t in raw.tenants {
            let mode = match t
                .mode
                .as_deref()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("observe") => TenantMode::Observe,
                Some("enforce") | None | Some("") => TenantMode::Enforce,
                Some(other) => {
                    return Err(ConfigError::Invalid(format!(
                        "tenant '{}': unknown mode '{}' (expected enforce|observe)",
                        t.id, other
                    )))
                }
            };
            // Trim the id so a padded `" team-a "` matches the (trimmed-at-mint)
            // principal tenant rather than silently falling back to Enforce.
            let id = t.id.trim().to_string();
            if id.is_empty() {
                return Err(ConfigError::Invalid(
                    "tenant id must not be empty".to_string(),
                ));
            }
            if tenants.insert(id.clone(), mode).is_some() {
                return Err(ConfigError::Invalid(format!("duplicate tenant '{}'", id)));
            }
        }

        // Inbound workload-identity resolver (V10/R6).
        let identity = raw
            .identity
            .map(|ri| {
                let kind = match ri.kind.trim().to_ascii_lowercase().as_str() {
                    "spiffe" => IdentityResolverKind::Spiffe,
                    "oidc" => IdentityResolverKind::Oidc,
                    other => {
                        return Err(ConfigError::Invalid(format!(
                            "identity.kind '{}' is not wireable inbound (expected spiffe|oidc)",
                            other
                        )))
                    }
                };
                let header = ri.header.trim().to_ascii_lowercase();
                if header.is_empty() {
                    return Err(ConfigError::Invalid(
                        "identity.header must not be empty".to_string(),
                    ));
                }
                // Trim allowlist entries and drop blanks — the resolvers match
                // exactly, so a stray-whitespace or empty trust-domain/issuer would
                // silently never match. A list that's non-empty in TOML but empties
                // after trimming is a misconfigured allowlist → reject.
                let raw_allowed_len = ri.allowed.len();
                let allowed: Vec<String> = ri
                    .allowed
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if raw_allowed_len > 0 && allowed.is_empty() {
                    return Err(ConfigError::Invalid(
                        "identity.allowed has only blank entries — remove it to accept any, \
                         or list real trust domains/issuers"
                            .to_string(),
                    ));
                }
                Ok(IdentityConfig {
                    kind,
                    header,
                    allowed,
                })
            })
            .transpose()?;

        let llm_proxy = raw.llm_proxy.map(Into::into).unwrap_or_default();

        // Operator-pinned internal destinations (plan 103 D8/F8). Validated here so
        // a malformed/over-broad destination is a startup failure, never a
        // request-time surprise; duplicate names are rejected (an ambiguous
        // destination name is exactly the kind of silent drift this stack fails
        // closed on).
        let mut internal_destinations: Vec<InternalDestination> = Vec::new();
        for raw_dest in raw.internal_destinations {
            let dest = parse_internal_destination(raw_dest)?;
            if internal_destinations.iter().any(|d| d.name == dest.name) {
                return Err(ConfigError::Invalid(format!(
                    "internal_destinations: duplicate name '{}'",
                    dest.name
                )));
            }
            internal_destinations.push(dest);
        }

        Ok(Self {
            server,
            storage,
            logging,
            policies,
            mcp,
            approval,
            enforcement,
            spend_extractors,
            egress,
            action_labels,
            outbox,
            tenants,
            identity,
            // Not parsed from the TOML — sourced from the environment at startup so
            // a config dump never carries the key. Defaults to None here; the
            // process entrypoint fills it from `VULTRINO_POLICY_HASH_SECRET`.
            policy_hash_secret: None,
            llm_proxy,
            govder: None,
            // Plan 088 D6 — `TryInto` (was `Into`): the `[averin] durable = true` +
            // `mode = "require_evidence"` combination is rejected here at config load.
            averin: raw.averin.map(TryInto::try_into).transpose()?.unwrap_or_default(),
            internal_destinations,
        })
    }

    /// Create a default configuration
    pub fn default_config() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            policies: vec![],
            mcp: McpConfig::default(),
            approval: crate::approval::ApprovalConfig::default(),
            enforcement: EnforcementConfig::default(),
            spend_extractors: vec![],
            egress: vec![],
            action_labels: std::collections::HashMap::new(),
            outbox: crate::outbox::OutboxConfig::default(),
            tenants: std::collections::HashMap::new(),
            identity: None,
            policy_hash_secret: None,
            llm_proxy: LlmProxyConfig::default(),
            govder: None,
            averin: crate::averin::AverinConfig::default(),
            internal_destinations: vec![],
        }
    }

    /// Get the default config file path
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vultrino")
            .join("config.toml")
    }

    /// Get the default storage path
    pub fn default_storage_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vultrino")
            .join("credentials.enc")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to
    pub bind: String,
    /// Server mode: "local" or "server"
    pub mode: ServerMode,
    /// TLS configuration (optional)
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7878".to_string(),
            mode: ServerMode::Local,
            tls: None,
        }
    }
}

/// Server operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMode {
    /// Local mode - single user, localhost only
    Local,
    /// Server mode - multi-user, network accessible
    Server,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackendType,
    /// Path for file storage
    pub file_path: Option<PathBuf>,
    /// Vault configuration
    pub vault: Option<VaultConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackendType::File,
            file_path: Some(Config::default_storage_path()),
            vault: None,
        }
    }
}

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendType {
    /// Encrypted file storage
    File,
    /// OS keychain (macOS Keychain, Windows Credential Manager)
    Keychain,
    /// HashiCorp Vault
    Vault,
}

/// HashiCorp Vault configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server address
    pub address: String,
    /// Authentication method
    pub auth_method: VaultAuthMethod,
}

/// Vault authentication method
#[derive(Debug, Clone)]
pub enum VaultAuthMethod {
    /// Token authentication
    Token(SecretString),
    /// AppRole authentication
    AppRole {
        role_id: String,
        secret_id: SecretString,
    },
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Format: "json" or "pretty"
    pub format: LogFormat,
    /// Path to audit log file
    pub audit_file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Pretty,
            audit_file: None,
        }
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable format
    Pretty,
    /// JSON format
    Json,
}

/// MCP server configuration
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Whether MCP server is enabled
    pub enabled: bool,
    /// Transport type
    pub transport: McpTransport,
    /// Unix socket path (for socket transport)
    pub socket_path: Option<PathBuf>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: McpTransport::Stdio,
            socket_path: None,
        }
    }
}

/// MCP transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    /// Standard input/output
    Stdio,
    /// Unix socket
    Socket,
}
