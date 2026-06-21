//! Capabilities — named MCP tools backed by a vault credential + a scoped action.
//!
//! The connector's locked design (muntin `docs/connectors/ARCHITECTURE.md`): a
//! *capability* is a **named MCP tool** (e.g. `send_email`) that an agent
//! harness sees in `tools/list` and invokes via `tools/call`. Where vultrino's
//! MCP today exposes only generic tools (`http_request`, …), a capability turns
//! a configured (action + vault credential + target scope + input schema) tuple
//! into its own LLM-facing tool. A `tools/call` is compiled into an
//! [`crate::ExecuteRequest`] and run through the SAME enforced path the generic
//! tools use ([`crate::server::VultrinoServer::execute_gated`]): default-deny
//! policy, single-use token consumption, egress scrub, and feir/leria emits all
//! still apply. The credential is referenced by alias; the agent never sees it.
//!
//! Capabilities are operator/control-plane config (created via the Admin API,
//! mirroring policies/credentials), stored alongside policies in the same vault.
//! They carry **no secret material** — only a `credential_ref` alias.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The plugin backing a capability and the scope of what its action may target.
///
/// For the `http` plugin this is a URL glob + an allowed-methods list; the LLM
/// fills `url`/`method`/`body` within that scope and the policy engine enforces
/// it independently. Other plugins (ssh/postgres/…) carry fixed plugin params
/// merged into the action request. The two are not mutually exclusive — a
/// future plugin could use both — so both are optional and additive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityTarget {
    /// URL glob the action may hit (http plugin). The policy that backs this
    /// capability's action should pin the same glob (defense in depth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_glob: Option<String>,
    /// HTTP methods the action may use (http plugin). Empty = any method the
    /// backing policy allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Fixed plugin parameters merged into every action request for this
    /// capability (e.g. an ssh host, a postgres database). The LLM's args are
    /// layered on top, but these fixed params take precedence so an agent can't
    /// override a pinned target.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub plugin_params: serde_json::Map<String, serde_json::Value>,
}

/// A stored capability: a named MCP tool bound to a vault credential + a scoped
/// govder action. Carries no secret — only a `credential_ref` alias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Stable id (for storage / management). Server-generated on POST.
    pub id: String,
    /// The MCP tool name the LLM sees and calls (e.g. `send_email`). Must be a
    /// valid MCP tool name (lowercase alphanumerics + underscores) and is what
    /// `tools/call` dispatches on.
    pub tool_name: String,
    /// Human-readable description shown to the LLM in `tools/list`.
    #[serde(default)]
    pub description: String,
    /// The action this capability performs: a canonical `plugin.action` OR a
    /// govder action label (V8) that `Config::resolve_action` maps to one. This
    /// is the action gated by policy and recorded for audit/metering.
    pub action: String,
    /// The vultrino plugin backing the action (`http`, `ssh`, `postgres`, …).
    /// Informational/forward-looking — the authoritative plugin is derived from
    /// the resolved canonical action at execute time, so this need not be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Target scope (url glob + methods, or fixed plugin params).
    #[serde(default)]
    pub target: CapabilityTarget,
    /// The vault credential alias this capability injects. The agent never sees
    /// the secret; vultrino resolves and injects it at execute time.
    pub credential_ref: String,
    /// JSON Schema the LLM fills for `tools/call` — surfaced verbatim as the
    /// MCP tool's `inputSchema`. The Bearer secret (`api_key`) is added to the
    /// schema dynamically at `tools/list` time, so this schema should describe
    /// only the action's own arguments (e.g. `to`, `subject`, `body`).
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// When set, this capability is an **LLM-proxy** capability rather than a
    /// named MCP tool: it backs the `POST /llm/...` model endpoint a harness
    /// points its `base_url` at (connector M1, decision 5). It is NOT exposed in
    /// `tools/list` (it isn't an LLM-callable tool — it IS the model channel), and
    /// the proxy forwards the harness's OpenAI-compatible request to
    /// [`LlmProxy::provider_base`] with the vault credential injected, metering
    /// token spend (V13) on the response. See [`Capability::is_llm_proxy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmProxy>,
}

/// LLM-proxy configuration on a [`Capability`] (connector M1, decision 5).
///
/// A harness's model endpoint (`config.yaml` `model.base_url`) is pointed at
/// vultrino's `POST /llm` so the **provider model key never leaves the vault** and
/// token spend is metered. The proxy forwards the harness's OpenAI-compatible
/// request body to `provider_base` + the request path, injecting the credential
/// referenced by the capability's `credential_ref`; the existing `run_action`
/// metering (V13a api-calls + V13b token counts) fires on the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmProxy {
    /// The real model provider's base URL (scheme + host, optionally a path
    /// prefix), e.g. `https://api.openai.com`. The proxy appends the inbound
    /// request path (e.g. `/v1/chat/completions`) to form the upstream URL. Must
    /// be HTTPS in production; the backing policy/egress still apply.
    pub provider_base: String,
}

impl Capability {
    /// Validate structural invariants so a misconfigured capability fails loudly
    /// at create time (admin API) rather than producing a tool that can never be
    /// called or that silently degrades:
    /// - `tool_name` must be a valid MCP tool name (lowercase alnum + `_`),
    ///   non-empty, and not collide with a built-in generic tool;
    /// - `action` must be non-empty;
    /// - `credential_ref` must be non-empty;
    /// - a `target.url_glob`, if set, must compile as a glob (a bad glob would
    ///   silently degrade to exact-match and effectively never match).
    pub fn validate(&self) -> Result<(), String> {
        let name = self.tool_name.trim();
        if name.is_empty() {
            return Err("capability tool_name must not be empty".to_string());
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "capability tool_name '{}' must contain only lowercase ASCII letters, digits, and '_'",
                name
            ));
        }
        if RESERVED_TOOL_NAMES.contains(&name) {
            return Err(format!(
                "capability tool_name '{}' collides with a built-in generic tool",
                name
            ));
        }
        if self.action.trim().is_empty() {
            return Err("capability action must not be empty".to_string());
        }
        if self.credential_ref.trim().is_empty() {
            return Err("capability credential_ref must not be empty".to_string());
        }
        if let Some(glob) = &self.target.url_glob {
            glob::Pattern::new(glob)
                .map_err(|e| format!("capability target.url_glob '{}' is not a valid glob: {}", glob, e))?;
        }
        if let Some(llm) = &self.llm {
            let base = llm.provider_base.trim();
            if base.is_empty() {
                return Err("capability llm.provider_base must not be empty".to_string());
            }
            let parsed = url::Url::parse(base).map_err(|e| {
                format!("capability llm.provider_base '{}' is not a valid URL: {}", base, e)
            })?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!(
                    "capability llm.provider_base '{}' must use http or https",
                    base
                ));
            }
            // SSRF consistency guard at config time (GLM review #5b): reject an
            // obvious loopback / private / link-local host literal. The authoritative
            // (DNS-resolving) check still runs at execute time via the http plugin's
            // validate_url_ssrf; this also rejects the misconfig at create time.
            if let Some(host) = parsed.host_str() {
                let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
                let private = h == "localhost"
                    || h == "::1"
                    || h.starts_with("127.")
                    || h.starts_with("169.254.") // link-local incl. cloud metadata 169.254.169.254
                    || h.starts_with("10.")
                    || h.starts_with("192.168.")
                    || (h.starts_with("172.")
                        && h.split('.')
                            .nth(1)
                            .and_then(|o| o.parse::<u8>().ok())
                            .map(|o| (16..=31).contains(&o))
                            .unwrap_or(false));
                if private {
                    return Err(format!(
                        "capability llm.provider_base '{}' resolves to a loopback/private/link-local host (SSRF)",
                        base
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether this capability is an LLM-proxy channel (it backs `POST /llm`
    /// rather than appearing as a named MCP tool in `tools/list`).
    pub fn is_llm_proxy(&self) -> bool {
        self.llm.is_some()
    }

    /// Build the upstream provider URL for an LLM-proxy `tools` call: the
    /// configured `provider_base` joined with the inbound request `path` (e.g.
    /// `/v1/chat/completions`). Returns `None` if this is not an LLM-proxy
    /// capability or the join fails. The path's leading slash is normalized so
    /// `provider_base` may or may not carry a trailing slash and the result is
    /// stable. Query strings on `path` are preserved.
    pub fn llm_upstream_url(&self, path: &str) -> Option<String> {
        let llm = self.llm.as_ref()?;
        let base = llm.provider_base.trim_end_matches('/');
        let suffix = path.trim_start_matches('/');
        let joined = if suffix.is_empty() {
            base.to_string()
        } else {
            format!("{}/{}", base, suffix)
        };
        // Validate the joined result parses as an absolute http(s) URL so a
        // malformed path can never produce a non-URL handed to the http plugin.
        let parsed = url::Url::parse(&joined).ok()?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return None;
        }
        Some(joined)
    }

    /// The MCP `inputSchema` presented to the LLM for this tool: the operator's
    /// `input_schema` with the Bearer secret field (`api_key`) injected so the
    /// agent knows to present its `vut_`/`vk_`. Mirrors how the generic plugin
    /// tools inject `api_key` into their schema. If the operator left
    /// `input_schema` empty/non-object, a minimal object schema is synthesized.
    pub fn mcp_input_schema(&self) -> serde_json::Value {
        let mut schema = if self.input_schema.is_object() {
            self.input_schema.clone()
        } else {
            serde_json::json!({ "type": "object", "properties": {} })
        };
        // Ensure a properties map exists, then add the auth field.
        let obj = schema.as_object_mut().expect("schema is an object");
        obj.entry("type")
            .or_insert_with(|| serde_json::json!("object"));
        let props = obj
            .entry("properties")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(props) = props.as_object_mut() {
            props.insert(
                "api_key".to_string(),
                serde_json::json!({
                    "type": "string",
                    "description": "Your vultrino use token (starts with 'vut_') or API key (starts with 'vk_') for authentication"
                }),
            );
        }
        // Require api_key.
        let required = obj
            .entry("required")
            .or_insert_with(|| serde_json::json!([]));
        if let Some(arr) = required.as_array_mut() {
            if !arr.iter().any(|v| v.as_str() == Some("api_key")) {
                arr.insert(0, serde_json::json!("api_key"));
            }
        }
        schema
    }
}

/// Built-in generic MCP tool names a capability must not shadow.
const RESERVED_TOOL_NAMES: &[&str] = &[
    "list_credentials",
    "http_request",
    "get_credential_info",
    "check_approval",
];

/// Metadata view of a capability (the stored shape carries no secret, so this is
/// the same fields — provided as a distinct alias for symmetry with credentials
/// and to keep room for a future redacted view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    pub id: String,
    pub tool_name: String,
    pub description: String,
    pub action: String,
    pub plugin: Option<String>,
    pub target: CapabilityTarget,
    pub credential_ref: String,
    pub input_schema: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmProxy>,
}

impl From<&Capability> for CapabilityMetadata {
    fn from(c: &Capability) -> Self {
        Self {
            id: c.id.clone(),
            tool_name: c.tool_name.clone(),
            description: c.description.clone(),
            action: c.action.clone(),
            plugin: c.plugin.clone(),
            target: c.target.clone(),
            credential_ref: c.credential_ref.clone(),
            input_schema: c.input_schema.clone(),
            llm: c.llm.clone(),
        }
    }
}

/// Build the action params for a capability's `tools/call`, given the LLM's args.
///
/// The result is the params object handed to the backing plugin (via
/// [`crate::ExecuteRequest`]). For the `http` plugin we shape the canonical
/// `{method, url, headers, body, query}` request from the capability's target
/// scope plus the LLM args (the LLM may supply `method`/`url`/`body`/`headers`/
/// `query`; the capability's pinned `url_glob`/`methods` are advisory defaults
/// that policy then enforces). For other plugins we pass the LLM args through and
/// overlay the capability's fixed `plugin_params` (which take precedence so a
/// pinned target can't be overridden by the agent).
///
/// The caller is responsible for having stripped the `api_key` from `args`
/// before this (it must never reach a plugin).
pub fn build_action_params(
    capability: &Capability,
    plugin_name: &str,
    args: &serde_json::Value,
) -> serde_json::Value {
    let args_obj = args.as_object().cloned().unwrap_or_default();

    if plugin_name == "http" {
        // Shape the canonical http.request params. The LLM provides the dynamic
        // bits; the capability's target supplies defaults. Policy independently
        // enforces url/method, so a missing/absent default is safe (it just
        // relies on the LLM-supplied value being within policy).
        let method = args_obj
            .get("method")
            .and_then(|v| v.as_str())
            .map(|m| m.to_uppercase())
            .or_else(|| capability.target.methods.first().map(|m| m.to_uppercase()))
            .unwrap_or_else(|| "GET".to_string());
        let url = args_obj
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| capability.target.url_glob.clone());

        let mut params = serde_json::Map::new();
        params.insert("method".to_string(), serde_json::json!(method));
        if let Some(url) = url {
            params.insert("url".to_string(), serde_json::json!(url));
        }
        if let Some(headers) = args_obj.get("headers") {
            params.insert("headers".to_string(), headers.clone());
        }
        if let Some(body) = args_obj.get("body") {
            params.insert("body".to_string(), body.clone());
        }
        if let Some(query) = args_obj.get("query") {
            params.insert("query".to_string(), query.clone());
        }
        return serde_json::Value::Object(params);
    }

    // Non-http plugin: pass the LLM args through, then overlay the capability's
    // fixed plugin params (operator-pinned target wins over agent input).
    let mut params = args_obj;
    for (k, v) in &capability.target.plugin_params {
        params.insert(k.clone(), v.clone());
    }
    serde_json::Value::Object(params)
}

/// Reserved generic tool names (exported for callers that need to skip them).
pub fn reserved_tool_names() -> &'static [&'static str] {
    RESERVED_TOOL_NAMES
}

/// A no-op marker so `HashMap` import is used in dependents that re-export.
#[doc(hidden)]
pub type CapabilityMap = HashMap<String, Capability>;

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(tool_name: &str) -> Capability {
        Capability {
            id: "cap-1".to_string(),
            tool_name: tool_name.to_string(),
            description: "send an email".to_string(),
            action: "email.send".to_string(),
            plugin: Some("http".to_string()),
            target: CapabilityTarget {
                url_glob: Some("https://api.sendgrid.com/v3/mail/send".to_string()),
                methods: vec!["POST".to_string()],
                plugin_params: serde_json::Map::new(),
            },
            credential_ref: "cred-sendgrid".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "body": { "type": "object" } },
                "required": ["body"]
            }),
            llm: None,
        }
    }

    #[test]
    fn test_validate_ok() {
        assert!(cap("send_email").validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_bad_names() {
        assert!(cap("").validate().is_err());
        assert!(cap("Send-Email").validate().is_err()); // uppercase + hyphen
        assert!(cap("send email").validate().is_err()); // space
        // Collision with a built-in generic tool.
        assert!(cap("http_request").validate().is_err());
        assert!(cap("check_approval").validate().is_err());
    }

    #[test]
    fn test_validate_requires_action_and_credential() {
        let mut c = cap("send_email");
        c.action = "  ".to_string();
        assert!(c.validate().is_err());
        let mut c = cap("send_email");
        c.credential_ref = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_bad_url_glob() {
        let mut c = cap("send_email");
        c.target.url_glob = Some("https://[invalid".to_string());
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_mcp_input_schema_injects_api_key() {
        let schema = cap("send_email").mcp_input_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["api_key"].is_object());
        assert!(schema["properties"]["body"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "api_key"));
        assert!(required.iter().any(|v| v == "body"));
    }

    #[test]
    fn test_mcp_input_schema_synthesizes_when_empty() {
        let mut c = cap("send_email");
        c.input_schema = serde_json::Value::Null;
        let schema = c.mcp_input_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["api_key"].is_object());
    }

    #[test]
    fn test_build_http_params_uses_target_defaults() {
        let c = cap("send_email");
        // LLM supplies only a body; method/url default from the capability target.
        let args = serde_json::json!({ "body": { "to": "a@b.com" } });
        let params = build_action_params(&c, "http", &args);
        assert_eq!(params["method"], "POST");
        assert_eq!(params["url"], "https://api.sendgrid.com/v3/mail/send");
        assert_eq!(params["body"]["to"], "a@b.com");
    }

    #[test]
    fn test_build_http_params_llm_can_override_within_policy() {
        let c = cap("send_email");
        let args = serde_json::json!({ "method": "get", "url": "https://api.sendgrid.com/v3/x" });
        let params = build_action_params(&c, "http", &args);
        // Method upper-cased; url is the LLM's (policy then enforces the glob).
        assert_eq!(params["method"], "GET");
        assert_eq!(params["url"], "https://api.sendgrid.com/v3/x");
    }

    fn llm_cap(provider_base: &str) -> Capability {
        let mut c = cap("model_proxy");
        c.action = "http.request".to_string();
        c.credential_ref = "cred-openai".to_string();
        c.target = CapabilityTarget::default();
        c.llm = Some(LlmProxy {
            provider_base: provider_base.to_string(),
        });
        c
    }

    #[test]
    fn test_is_llm_proxy() {
        assert!(!cap("send_email").is_llm_proxy());
        assert!(llm_cap("https://api.openai.com").is_llm_proxy());
    }

    #[test]
    fn test_llm_validate_ok_and_rejects_bad_base() {
        assert!(llm_cap("https://api.openai.com").validate().is_ok());
        // Empty provider_base.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy { provider_base: "  ".to_string() });
        assert!(c.validate().is_err());
        // Non-URL provider_base.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy { provider_base: "not a url".to_string() });
        assert!(c.validate().is_err());
        // Disallowed scheme.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy { provider_base: "ftp://api.openai.com".to_string() });
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_llm_upstream_url_joins_path() {
        let c = llm_cap("https://api.openai.com");
        // Path with leading slash.
        assert_eq!(
            c.llm_upstream_url("/v1/chat/completions").as_deref(),
            Some("https://api.openai.com/v1/chat/completions")
        );
        // Path without a leading slash (axum {*path} strips it).
        assert_eq!(
            c.llm_upstream_url("v1/chat/completions").as_deref(),
            Some("https://api.openai.com/v1/chat/completions")
        );
        // Trailing slash on the base is normalized (no double slash).
        let c2 = llm_cap("https://api.openai.com/");
        assert_eq!(
            c2.llm_upstream_url("/v1/chat/completions").as_deref(),
            Some("https://api.openai.com/v1/chat/completions")
        );
        // A provider_base with a path prefix is preserved.
        let c3 = llm_cap("https://gateway.internal/openai");
        assert_eq!(
            c3.llm_upstream_url("/v1/chat/completions").as_deref(),
            Some("https://gateway.internal/openai/v1/chat/completions")
        );
        // Empty path → the base itself.
        assert_eq!(
            c.llm_upstream_url("").as_deref(),
            Some("https://api.openai.com")
        );
    }

    #[test]
    fn test_llm_upstream_url_none_for_non_llm_capability() {
        // A plain (non-LLM) capability has no upstream URL.
        assert!(cap("send_email").llm_upstream_url("/v1/chat/completions").is_none());
    }

    #[test]
    fn test_build_nonhttp_params_pins_plugin_params() {
        let mut c = cap("run_query");
        c.action = "postgres.run_sql".to_string();
        c.plugin = Some("postgres".to_string());
        c.target = CapabilityTarget {
            url_glob: None,
            methods: vec![],
            plugin_params: serde_json::json!({ "database": "prod" }).as_object().unwrap().clone(),
        };
        // The agent tries to override the pinned database; the capability wins.
        let args = serde_json::json!({ "sql": "SELECT 1", "database": "evil" });
        let params = build_action_params(&c, "postgres", &args);
        assert_eq!(params["sql"], "SELECT 1");
        assert_eq!(params["database"], "prod");
    }
}
