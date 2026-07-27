//! Capabilities — named MCP tools backed by a vault credential + a scoped action.
//!
//! The connector's locked design (feir-os `docs/connectors/ARCHITECTURE.md`): a
//! *capability* is a **named MCP tool** (e.g. `send_email`) that an agent
//! harness sees in `tools/list` and invokes via `tools/call`. Where vultrino's
//! MCP today exposes only generic tools (`http_request`, …), a capability turns
//! a configured (action + vault credential + target scope + input schema) tuple
//! into its own LLM-facing tool. A `tools/call` is compiled into an
//! [`crate::ExecuteRequest`] and run through the SAME enforced path the generic
//! tools use ([`crate::server::VultrinoServer::execute_gated`]): default-deny
//! policy, single-use token consumption, egress scrub, and averin/leria emits all
//! still apply. The credential is referenced by alias; the agent never sees it.
//!
//! Capabilities are operator/control-plane config (created via the Admin API,
//! mirroring policies/credentials), stored alongside policies in the same vault.
//! They carry **no secret material** — only a `credential_ref` alias.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_reversible() -> String {
    "reversible".to_string()
}

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
    /// Reversibility class stamped on approvals opened for this capability
    /// (`reversible` | `partially-reversible` | `irreversible`). Drives the D3 floor.
    #[serde(default = "default_reversible")]
    pub reversibility: String,
    /// When set, this capability is an **LLM-proxy** capability rather than a
    /// named MCP tool: it backs the `POST /llm/...` model endpoint a harness
    /// points its `base_url` at (connector M1, decision 5). It is NOT exposed in
    /// `tools/list` (it isn't an LLM-callable tool — it IS the model channel), and
    /// the proxy forwards the harness's OpenAI-compatible request to
    /// [`LlmProxy::provider_base`] with the vault credential injected, metering
    /// token spend (V13) on the response. See [`Capability::is_llm_proxy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmProxy>,
    /// Optional per-capability approval-preview SPEC: which `params` fields an
    /// approver should see (action-type-specific), extracted fresh at each
    /// approval-open by [`extract_preview`]. `None` = today's behavior unchanged
    /// (the approver sees only the generic `summarize()` one-liner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_preview: Option<ApprovalPreviewSpec>,
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
    /// Certified wire family used for feature gating and assurance reporting.
    #[serde(default = "default_llm_protocol")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The real model provider's base URL (scheme + host, optionally a path
    /// prefix), e.g. `https://api.openai.com`. The proxy appends the inbound
    /// request path (e.g. `/v1/chat/completions`) to form the upstream URL. Must
    /// be HTTPS in production; the backing policy/egress still apply.
    pub provider_base: String,
    /// When non-empty, restricts this model channel to a specific set of model
    /// names (per-model granularity, connector P1-1): a `POST /llm` request whose
    /// body `model` is not in this list is DENIED (403) before any upstream call.
    /// The match is exact on the request's `model` field. An EMPTY list (the
    /// default) permits any model the provider exposes — per-provider scope only.
    /// govder (the decide plane) sets this from the capability's
    /// `llm.allowed_models`; vultrino is the enforcing PEP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_models: Vec<String>,
    /// When set, a per-call OUTPUT-TOKEN ceiling: the `/llm` proxy clamps the
    /// request body's `max_tokens` to `min(requested, ceiling)` (and SETS it to the
    /// ceiling when the request omits it, so the provider default can't exceed it).
    /// This bounds per-call output tokens — and therefore per-call cost — which a
    /// `SpendCap` cannot do for an LLM request (it carries no request-time spend).
    /// It is the per-call leg of the rate_companion overshoot bound (P1-8); govder
    /// sizes it from the budget's cost hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
}

fn default_llm_protocol() -> String {
    "openai-chat".to_string()
}

/// Operator-declared approval-preview SPEC on a [`Capability`]: which fields of
/// the request `params` an approver should see when this capability's action is
/// gated on human approval, instead of just the generic `summarize()` one-liner
/// (or a raw params dump, which is never exposed — see [`ApprovalPreview`]).
///
/// This is config, not data: it names *paths*, not values. The values are
/// extracted at approval-open time by [`extract_preview`] from the SAME `params`
/// that will execute, so the approver sees exactly what will run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPreviewSpec {
    /// Optional heading shown above the extracted fields (e.g. "Telegram message").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Fields to extract from `params`, in display order.
    #[serde(default)]
    pub fields: Vec<PreviewFieldSpec>,
}

/// One field the approval preview extracts: a display `label` and a dot `path`
/// into the request `params` (e.g. `body.chat_id` -> `params["body"]["chat_id"]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewFieldSpec {
    pub label: String,
    pub path: String,
    /// Display hint: `"text"` (wrapped block, e.g. a message body) or `"inline"`
    /// (default). Purely a UI hint — extraction behavior is identical either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Extracted approval-preview VALUES, computed by [`extract_preview`] from a live
/// `params` blob at approval-open time. This — never the raw `params`, never the
/// credential — is what an approval's JSON projection exposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub fields: Vec<PreviewField>,
}

/// One extracted preview field: a label plus its coerced display value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewField {
    pub label: String,
    pub value: String,
    #[serde(default = "default_preview_format")]
    pub format: String,
}

fn default_preview_format() -> String {
    "inline".to_string()
}

/// Walk a dot path (e.g. `"body.chat_id"`) into a JSON object, returning the leaf
/// value if every segment resolves to an object key. Never descends into arrays
/// or any structure not named by the path.
fn dot_path_get<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Coerce a JSON leaf value to its display string per the wire contract: a JSON
/// string as-is, a number/bool via `to_string`, and `null`/missing/anything else
/// (object/array — the spec only names leaf paths) skipped (`None`).
fn coerce_preview_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => None,
    }
}

/// Extract an [`ApprovalPreview`]'s VALUES from a live `params` blob per a
/// capability's declared [`ApprovalPreviewSpec`]. Pure and total: a missing or
/// null leaf, or a path through a non-object, is silently skipped (not an
/// error) — only fields the spec names are ever read, and only those that
/// resolve to a scalar are ever emitted. This is the SOLE way preview values
/// reach an approval; the raw `params` is never otherwise exposed.
pub fn extract_preview(spec: &ApprovalPreviewSpec, params: &serde_json::Value) -> ApprovalPreview {
    let fields = spec
        .fields
        .iter()
        .filter_map(|field_spec| {
            let value = dot_path_get(params, &field_spec.path)?;
            let display = coerce_preview_value(value)?;
            Some(PreviewField {
                label: field_spec.label.clone(),
                value: display,
                format: field_spec
                    .format
                    .clone()
                    .unwrap_or_else(default_preview_format),
            })
        })
        .collect();
    ApprovalPreview {
        title: spec.title.clone(),
        fields,
    }
}

impl Default for LlmProxy {
    fn default() -> Self {
        Self {
            protocol: default_llm_protocol(),
            provider: None,
            region: None,
            provider_base: String::new(),
            allowed_models: Vec::new(),
            max_output_tokens: None,
        }
    }
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
        match self.reversibility.trim() {
            "reversible" | "partially-reversible" | "irreversible" => {}
            other => {
                return Err(format!(
                    "capability reversibility {other:?} must be reversible, partially-reversible, or irreversible"
                ));
            }
        }
        if let Some(glob) = &self.target.url_glob {
            glob::Pattern::new(glob).map_err(|e| {
                format!(
                    "capability target.url_glob '{}' is not a valid glob: {}",
                    glob, e
                )
            })?;
        }
        if let Some(llm) = &self.llm {
            match llm.protocol.as_str() {
                "openai-chat" | "openai-responses" | "azure-openai" | "anthropic-messages"
                | "bedrock-converse" | "bedrock-invoke" | "gemini" | "vertex-ai" | "nvidia"
                | "observed-only" => {}
                other => {
                    return Err(format!(
                        "capability llm.protocol '{}' is not supported",
                        other
                    ))
                }
            }
            let base = llm.provider_base.trim();
            if base.is_empty() {
                return Err("capability llm.provider_base must not be empty".to_string());
            }
            let parsed = url::Url::parse(base).map_err(|e| {
                format!(
                    "capability llm.provider_base '{}' is not a valid URL: {}",
                    base, e
                )
            })?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!(
                    "capability llm.provider_base '{}' must use http or https",
                    base
                ));
            }
            // SSRF config-time guard (GLM review #5b, narrowed): reject ONLY the
            // link-local range (169.254.0.0/16 — the cloud-metadata SSRF target,
            // 169.254.169.254), which has no legitimate provider_base use. We do NOT
            // reject loopback / RFC1918 here: those are legitimate self-hosted /
            // private model-gateway addresses (the operator-fixed provider_base host
            // is agent-untouchable — the agent only supplies the path, never the
            // host, see llm_upstream_url), and the AUTHORITATIVE DNS-resolving SSRF
            // control runs at execute time in the http plugin's validate_url_ssrf.
            // Duplicating that broad block here added no security (it is a string
            // subset of the execute-time check) while breaking the only end-to-end
            // test that drives the real http plugin through the proxy.
            if let Some(host) = parsed.host_str() {
                let h = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_ascii_lowercase();
                if h.starts_with("169.254.") {
                    return Err(format!(
                        "capability llm.provider_base '{}' points at the link-local / cloud-metadata range (SSRF)",
                        base
                    ));
                }
                // A "nvidia" channel reuses the OpenAI-compatible wire but is a
                // DISTINCT, separately-gated provider (VULTRINO_PROVIDER_NVIDIA_ENABLED)
                // so an operator can run NVIDIA without enabling the generic OpenAI
                // provider. Pin its provider_base to NVIDIA hosts so a nvidia-labeled
                // channel can never be aimed at a different provider's endpoint.
                if llm.protocol == "nvidia" && !(h == "nvidia.com" || h.ends_with(".nvidia.com")) {
                    return Err(format!(
                        "capability llm.protocol 'nvidia' requires an NVIDIA provider_base host (*.nvidia.com); got '{}'",
                        base
                    ));
                }
            }
        }
        if self.declares_internal_http() {
            // Registration-time half of plan 103 §10g FIX 1. An `internal_http`
            // capability whose verb is not decidable from OPERATOR config is a tool
            // an agent can see in tools/list and can never call: the plugin requires
            // `method`, the caller is not allowed to supply it, and nothing else
            // would fill it. Refusing here turns that into a 400 at provision time
            // instead of a refusal at money time.
            self.resolve_pinned_http_method()?;
        }
        Ok(())
    }

    /// Whether this capability DECLARES the internal transport. The authoritative
    /// plugin is resolved from the action at execute time (an action label can
    /// route anywhere), so this is the best a config-free `validate` can do — it is
    /// a second layer, not the load-bearing one. The load-bearing check is
    /// [`build_action_params`], which keys on the RESOLVED plugin name.
    fn declares_internal_http(&self) -> bool {
        self.plugin.as_deref().map(str::trim) == Some(INTERNAL_HTTP_PLUGIN)
            || self.action.trim() == "internal_http.request"
    }

    /// The HTTP verb an `internal_http` capability executes with — decided by the
    /// OPERATOR, never by the caller.
    ///
    /// Sources, in order, and they must not disagree:
    /// 1. `target.plugin_params.method` — the explicit pin govder's `ToCapUpsert`
    ///    writes from the pack's declared method;
    /// 2. a `target.methods` list of exactly ONE verb.
    ///
    /// Every other shape is an error: no verb (nothing to send), two verbs (an
    /// ambiguity that could only be resolved by the agent, which is the thing we
    /// are refusing), a pin that is not a verb, or a pin that contradicts the
    /// declared list (two operator statements that disagree is a config bug, and
    /// silently preferring one of them is how an inert control is born).
    pub fn resolve_pinned_http_method(&self) -> Result<String, String> {
        let declared: Vec<String> = self
            .target
            .methods
            .iter()
            .map(|m| m.trim().to_ascii_uppercase())
            .filter(|m| !m.is_empty())
            .collect();
        let pinned = self
            .target
            .plugin_params
            .get("method")
            .map(|v| match v.as_str() {
                Some(s) => Ok(s.trim().to_ascii_uppercase()),
                None => Err(format!(
                    "capability '{}' target.plugin_params.method must be a string verb, got {}",
                    self.tool_name, v
                )),
            })
            .transpose()?;

        let method = match (&pinned, declared.as_slice()) {
            (Some(p), []) => p.clone(),
            (Some(p), [one]) if p == one => p.clone(),
            (Some(p), many) => {
                return Err(format!(
                    "capability '{}' pins target.plugin_params.method = {p:?} but declares target.methods = {many:?}; \
                     the operator's two statements must agree (or drop one)",
                    self.tool_name
                ))
            }
            (None, [one]) => one.clone(),
            (None, []) => {
                return Err(format!(
                    "capability '{}' backs the internal transport but declares no method: \
                     the plugin requires one, the agent is not allowed to supply one, so this tool could be listed and never called. \
                     Declare exactly one target.methods entry (or pin target.plugin_params.method)",
                    self.tool_name
                ))
            }
            (None, many) => {
                return Err(format!(
                    "capability '{}' declares {} methods {many:?} on the internal transport: the verb must be unambiguous on the OPERATOR side, \
                     because resolving it at call time means the AGENT resolves it. Split it into one capability per verb",
                    self.tool_name,
                    many.len()
                ))
            }
        };
        if !INTERNAL_HTTP_VERBS.contains(&method.as_str()) {
            return Err(format!(
                "capability '{}' method {method:?} is not an HTTP verb",
                self.tool_name
            ));
        }
        Ok(method)
    }

    /// The verb list-time policy evaluation should match on. It must be the SAME
    /// verb call time will send, or a capability can be hidden from `tools/list`
    /// (or shown and then denied) purely because the two read different fields.
    pub fn effective_http_method(&self) -> Option<String> {
        if self.declares_internal_http() {
            if let Ok(m) = self.resolve_pinned_http_method() {
                return Some(m);
            }
        }
        self.target.methods.first().cloned()
    }

    /// Whether this capability is an LLM-proxy channel (it backs `POST /llm`
    /// rather than appearing as a named MCP tool in `tools/list`).
    pub fn is_llm_proxy(&self) -> bool {
        self.llm.is_some()
    }

    /// Whether a `POST /llm` request for the `requested` model is permitted by this
    /// capability's model allowlist (per-model granularity, P1-1). Semantics:
    /// - a non-LLM-proxy capability is not this gate's concern → allowed;
    /// - an EMPTY `allowed_models` permits any model (per-provider scope only);
    /// - a non-empty allowlist is DEFAULT-DENY: the requested model must match an
    ///   entry EXACTLY, and a request with NO model (`None`) is DENIED — an
    ///   allowlisted channel must see a model to verify it (fail-closed).
    pub fn llm_model_allowed(&self, requested: Option<&str>) -> bool {
        let allow = match self.llm.as_ref() {
            Some(l) => &l.allowed_models,
            None => return true, // not an LLM-proxy capability; not this gate's concern
        };
        if allow.is_empty() {
            return true; // any-model (per-provider scope only)
        }
        match requested {
            Some(m) => allow.iter().any(|a| a == m),
            None => false, // fail-closed: allowlist set but no model to check
        }
    }

    /// The per-call output-token ceiling for this LLM-proxy capability, if any (the
    /// per-call cost leg of the rate_companion, P1-8). `None` = no ceiling.
    pub fn llm_max_output_tokens(&self) -> Option<u64> {
        self.llm.as_ref().and_then(|l| l.max_output_tokens)
    }

    /// Build the upstream provider URL for an LLM-proxy `tools` call: the
    /// configured `provider_base` joined with the inbound request `path` (e.g.
    /// `/v1/chat/completions`). Returns `None` if this is not an LLM-proxy
    /// capability or the join fails. The path's leading slash is normalized so
    /// `provider_base` may or may not carry a trailing slash and the result is
    /// stable. The normalized result is constrained to provider_base's
    /// scheme/host/port AND path prefix (the agent controls only the path under the
    /// prefix; see the containment check). NOTE: the LLM proxy does not forward the
    /// inbound query string in v1 (it captures only the path).
    pub fn llm_upstream_url(&self, path: &str) -> Option<String> {
        let llm = self.llm.as_ref()?;
        let base_str = llm.provider_base.trim_end_matches('/');
        let base = url::Url::parse(base_str).ok()?;
        let suffix = path.trim_start_matches('/');
        // Reject an ENCODED slash/backslash in the agent path (Codex high): url parsing
        // keeps %2f/%5c as a single path char, so it survives the prefix-containment
        // check below — but many upstream servers decode it to a separator, letting
        // "..%2f..%2fadmin" escape a /openai-scoped base. These have no legitimate use
        // in an OpenAI-style route.
        {
            let lower = suffix.to_ascii_lowercase();
            if lower.contains("%2f") || lower.contains("%5c") {
                return None;
            }
        }
        let joined = if suffix.is_empty() {
            base_str.to_string()
        } else {
            format!("{}/{}", base_str, suffix)
        };
        // Validate the joined result parses as an absolute http(s) URL so a malformed
        // path can never produce a non-URL handed to the http plugin.
        let parsed = url::Url::parse(&joined).ok()?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return None;
        }
        // CONTAINMENT (Codex high): the agent supplies only the path, so the NORMALIZED
        // upstream must stay on provider_base's scheme/host/port AND under its path
        // prefix. url::Url normalization resolves dot-segments ("../", "%2e%2e"), so an
        // agent path that escapes the configured prefix (e.g. base /openai + "../admin"
        // -> /admin) is rejected here — the agent cannot steer the vault-credential'd
        // POST to a sibling endpoint on the (possibly internal) provider host. We
        // validate the PARSED form but return the original string the http plugin
        // re-parses identically.
        if parsed.scheme() != base.scheme()
            || parsed.host_str() != base.host_str()
            || parsed.port_or_known_default() != base.port_or_known_default()
        {
            return None;
        }
        let base_path = base.path().trim_end_matches('/'); // "" for a root base
        let up_path = parsed.path();
        let contained = if base_path.is_empty() {
            up_path.starts_with('/')
        } else {
            up_path == base_path || up_path.starts_with(&format!("{}/", base_path))
        };
        if !contained {
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

/// The plugin name of the operator-pinned internal transport (F8). Kept here as
/// well as in `plugins::internal_http` because the capability layer must key on
/// it without depending on the plugin registry.
pub const INTERNAL_HTTP_PLUGIN: &str = "internal_http";

/// The verbs `internal_http` accepts. Mirrors `plugins::internal_http::VERBS`.
const INTERNAL_HTTP_VERBS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_preview: Option<ApprovalPreviewSpec>,
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
            approval_preview: c.approval_preview.clone(),
        }
    }
}

/// Build the action params for a capability's `tools/call`, given the LLM's args.
///
/// The result is the params object handed to the backing plugin (via
/// [`crate::ExecuteRequest`]). Three shapes:
///
/// - **`http`**: the canonical `{method, url, headers, body, query}` request,
///   composed from the capability's target scope plus the LLM args (the LLM may
///   supply `method`/`url`/`body`/`headers`/`query`; the capability's pinned
///   `url_glob`/`methods` are advisory defaults that policy then enforces).
/// - **`internal_http`**: the same canonical shape, but the VERB IS THE
///   OPERATOR'S — see [`build_internal_http_params`]. This branch exists because
///   the generic passthrough below produced a tool that could be listed and never
///   called (plan 103 §10g FIX 1).
/// - **everything else**: pass the LLM args through and overlay the capability's
///   fixed `plugin_params` (which take precedence so a pinned target can't be
///   overridden by the agent).
///
/// Returns `Err` when the agent's args cannot be composed into a legal request
/// for this capability. The caller must surface that as a tool error: it is a
/// refusal, and it happens BEFORE the use token is consumed.
///
/// The caller is responsible for having stripped the `api_key` from `args`
/// before this (it must never reach a plugin).
pub fn build_action_params(
    capability: &Capability,
    plugin_name: &str,
    args: &serde_json::Value,
) -> Result<serde_json::Value, String> {
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
        return Ok(serde_json::Value::Object(params));
    }

    if plugin_name == INTERNAL_HTTP_PLUGIN {
        return build_internal_http_params(capability, args_obj);
    }

    // Non-http plugin: pass the LLM args through, then overlay the capability's
    // fixed plugin params (operator-pinned target wins over agent input).
    let mut params = args_obj;
    for (k, v) in &capability.target.plugin_params {
        params.insert(k.clone(), v.clone());
    }
    Ok(serde_json::Value::Object(params))
}

/// Compose the `internal_http.request` params for a `tools/call`.
///
/// **The agent supplies the path and the payload. The operator supplies the
/// verb.** That asymmetry is the whole point, and it is why this is not the
/// generic passthrough:
///
/// - `internal_http` requires `method` with no serde default, so the generic
///   passthrough handed the plugin a request with no verb and every shipped money
///   capability was refused before the use token was consumed — an agent could see
///   `issue_refund` in `tools/list` and never execute it (plan 103 §10g FIX 1);
/// - the only way an agent COULD execute one was to invent a `method` field its
///   schema never mentioned, i.e. the caller would be choosing the HTTP verb of a
///   money action. A declared GET capability turning into a POST is exactly the
///   escalation the pinned destination exists to prevent.
///
/// So a caller-supplied `method` is REFUSED rather than overwritten. Overwriting
/// would execute a money action the agent did not ask for; honouring it would let
/// the agent pick the verb. Refusing is the only fail-closed answer, and it costs
/// nothing: the schema the agent is handed never declares `method`.
fn build_internal_http_params(
    capability: &Capability,
    args_obj: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if args_obj.contains_key("method") {
        return Err(format!(
            "capability '{}' does not take a 'method' argument: the HTTP method of an internal-transport action is pinned by the operator, \
             not chosen by the caller. Call it with the fields in this tool's schema",
            capability.tool_name
        ));
    }
    let method = capability.resolve_pinned_http_method()?;

    let mut params = args_obj;
    // The operator's fixed params win over anything the agent sent...
    for (k, v) in &capability.target.plugin_params {
        params.insert(k.clone(), v.clone());
    }
    // ...and the resolved verb is written LAST, so what reaches the plugin, the
    // policy engine's MethodMatch, the approval line and the audit record is one
    // normalized uppercase string rather than however the operator spelled it.
    params.insert("method".to_string(), serde_json::json!(method));
    Ok(serde_json::Value::Object(params))
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
            reversibility: "reversible".to_string(),
            llm: None,
            approval_preview: None,
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

    fn nvidia_cap(base: &str) -> Capability {
        let mut c = cap("nemotron");
        c.target.url_glob = None; // an LLM-proxy channel is not a named MCP tool endpoint
        c.llm = Some(LlmProxy {
            protocol: "nvidia".to_string(),
            provider: Some("nvidia".to_string()),
            provider_base: base.to_string(),
            allowed_models: vec![],
            ..Default::default()
        });
        c
    }

    #[test]
    fn nvidia_channel_accepts_nvidia_host_only() {
        // The real NVIDIA OpenAI-compatible endpoint is accepted.
        assert!(nvidia_cap("https://integrate.api.nvidia.com/v1")
            .validate()
            .is_ok());
        // A nvidia-labeled channel pointed at another provider is rejected (least
        // privilege: "nvidia" means NVIDIA, so the generic OpenAI switch can stay off).
        assert!(nvidia_cap("https://api.openai.com/v1").validate().is_err());
        assert!(nvidia_cap("https://evil.example.com/v1")
            .validate()
            .is_err());
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
        let params = build_action_params(&c, "http", &args).unwrap();
        assert_eq!(params["method"], "POST");
        assert_eq!(params["url"], "https://api.sendgrid.com/v3/mail/send");
        assert_eq!(params["body"]["to"], "a@b.com");
    }

    #[test]
    fn test_build_http_params_llm_can_override_within_policy() {
        let c = cap("send_email");
        let args = serde_json::json!({ "method": "get", "url": "https://api.sendgrid.com/v3/x" });
        let params = build_action_params(&c, "http", &args).unwrap();
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
            allowed_models: Vec::new(),
            max_output_tokens: None,
            ..Default::default()
        });
        c
    }

    #[test]
    fn test_is_llm_proxy() {
        assert!(!cap("send_email").is_llm_proxy());
        assert!(llm_cap("https://api.openai.com").is_llm_proxy());
    }

    #[test]
    fn test_llm_model_allowed_empty_list_permits_any() {
        // An empty allowlist is per-provider scope only: any model (incl. none) passes.
        let c = llm_cap("https://api.openai.com");
        assert!(c.llm_model_allowed(Some("gpt-4o")));
        assert!(c.llm_model_allowed(Some("anything-at-all")));
        assert!(c.llm_model_allowed(None));
    }

    #[test]
    fn test_llm_model_allowed_enforces_allowlist() {
        let mut c = llm_cap("https://api.openai.com");
        c.llm.as_mut().unwrap().allowed_models =
            vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string()];
        // Exact match on a listed model passes.
        assert!(c.llm_model_allowed(Some("gpt-4o")));
        assert!(c.llm_model_allowed(Some("gpt-4o-mini")));
        // A model not in the list is denied.
        assert!(!c.llm_model_allowed(Some("gpt-3.5-turbo")));
        // Exact match: a date-suffixed variant is a DIFFERENT string → denied.
        assert!(!c.llm_model_allowed(Some("gpt-4o-2024-08-06")));
        // Fail-closed: an allowlisted channel with NO model to verify is denied.
        assert!(!c.llm_model_allowed(None));
    }

    #[test]
    fn test_llm_model_allowed_non_proxy_capability_is_unconcerned() {
        // A named-tool (non-LLM-proxy) capability is not this gate's concern.
        assert!(cap("send_email").llm_model_allowed(Some("whatever")));
        assert!(cap("send_email").llm_model_allowed(None));
    }

    #[test]
    fn test_llm_validate_ok_and_rejects_bad_base() {
        assert!(llm_cap("https://api.openai.com").validate().is_ok());
        // Empty provider_base.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy {
            provider_base: "  ".to_string(),
            allowed_models: Vec::new(),
            max_output_tokens: None,
            ..Default::default()
        });
        assert!(c.validate().is_err());
        // Non-URL provider_base.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy {
            provider_base: "not a url".to_string(),
            allowed_models: Vec::new(),
            max_output_tokens: None,
            ..Default::default()
        });
        assert!(c.validate().is_err());
        // Disallowed scheme.
        let mut c = llm_cap("https://api.openai.com");
        c.llm = Some(LlmProxy {
            provider_base: "ftp://api.openai.com".to_string(),
            allowed_models: Vec::new(),
            max_output_tokens: None,
            ..Default::default()
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_llm_validate_ssrf_narrowed_to_link_local() {
        // The cloud-metadata / link-local range has no legitimate provider use and is
        // rejected at config time (defense-in-depth before the execute-time check).
        let meta = llm_cap("http://169.254.169.254/latest/meta-data");
        let err = meta.validate().unwrap_err();
        assert!(
            err.contains("link-local") || err.contains("metadata"),
            "got: {err}"
        );

        // Loopback + RFC1918 are LEGITIMATE self-hosted model-gateway addresses (the
        // operator-fixed host is agent-untouchable). They VALIDATE at config; the
        // authoritative DNS-resolving SSRF control runs at execute time.
        for base in [
            "http://127.0.0.1:9",
            "http://localhost:11434", // e.g. a local Ollama gateway
            "http://10.0.0.5:8000",
            "http://192.168.1.10:8080",
        ] {
            assert!(
                llm_cap(base).validate().is_ok(),
                "self-hosted gateway base must validate at config: {base}"
            );
        }
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
    fn test_llm_upstream_url_host_cannot_be_hijacked_by_path() {
        // The security premise behind narrowing the config-time provider_base SSRF
        // check (#5b): the agent supplies only the PATH; it can NEVER change the
        // operator-fixed host. If any of these adversarial paths produced a URL whose
        // host != the provider_base host, the narrowing would be unsafe. The upstream
        // is whatever the http plugin's validate_url_ssrf re-parses, so we assert on
        // the re-parsed host (exactly what the execute-time SSRF check sees).
        let c = llm_cap("https://api.openai.com");
        let attacks = [
            "/@evil.com/x",
            "@evil.com/x",
            "//evil.com/x",
            "/..//evil.com/x",
            "/\\evil.com/x",
            "https://evil.com/x",
            "/x?next=https://evil.com",
            "/x#@evil.com",
            "/%2F%2Fevil.com/x",
            " /evil.com",
        ];
        for path in attacks {
            if let Some(upstream) = c.llm_upstream_url(path) {
                let parsed = url::Url::parse(&upstream)
                    .unwrap_or_else(|e| panic!("upstream for {path:?} must parse: {e}"));
                assert_eq!(
                    parsed.host_str(),
                    Some("api.openai.com"),
                    "path {path:?} hijacked the host to {:?} (upstream={upstream})",
                    parsed.host_str()
                );
            }
            // None (rejected) is also acceptable — the point is it must NEVER yield a
            // different host.
        }
    }

    #[test]
    fn test_llm_upstream_url_path_prefix_cannot_be_escaped() {
        // A provider_base WITH a path prefix scopes the agent to that prefix. An agent
        // path using dot-segments must NOT normalize outside it (Codex high) — else the
        // vault-credential'd POST could hit a sibling endpoint on the same (internal)
        // host. The host is fixed; the prefix must hold too.
        let c = llm_cap("https://gateway.internal/openai");
        // Legit paths under the prefix are allowed.
        assert!(c.llm_upstream_url("/v1/chat/completions").is_some());
        assert_eq!(
            c.llm_upstream_url("").as_deref(),
            Some("https://gateway.internal/openai")
        );
        // Escapes are rejected (None).
        for escape in [
            "/../admin",
            "../admin",
            "/../../etc",
            "/v1/../../admin",
            "/%2e%2e/admin",
            "/..%2Fadmin",
        ] {
            let got = c.llm_upstream_url(escape);
            if let Some(u) = &got {
                // If not rejected, it MUST still be under /openai/ (never escaped).
                let p = url::Url::parse(u).unwrap();
                assert!(
                    p.path() == "/openai" || p.path().starts_with("/openai/"),
                    "path {escape:?} escaped the /openai prefix -> {} (path {})",
                    u,
                    p.path()
                );
            }
        }
        // A sibling-prefix host path must not satisfy the prefix (/openai vs /openai2).
        assert!(c.llm_upstream_url("/../openai2/secret").is_none_or(|u| {
            let p = url::Url::parse(&u).unwrap();
            p.path() == "/openai" || p.path().starts_with("/openai/")
        }));
    }

    #[test]
    fn test_llm_upstream_url_none_for_non_llm_capability() {
        // A plain (non-LLM) capability has no upstream URL.
        assert!(cap("send_email")
            .llm_upstream_url("/v1/chat/completions")
            .is_none());
    }

    #[test]
    fn test_build_nonhttp_params_pins_plugin_params() {
        let mut c = cap("run_query");
        c.action = "postgres.run_sql".to_string();
        c.plugin = Some("postgres".to_string());
        c.target = CapabilityTarget {
            url_glob: None,
            methods: vec![],
            plugin_params: serde_json::json!({ "database": "prod" })
                .as_object()
                .unwrap()
                .clone(),
        };
        // The agent tries to override the pinned database; the capability wins.
        let args = serde_json::json!({ "sql": "SELECT 1", "database": "evil" });
        let params = build_action_params(&c, "postgres", &args).unwrap();
        assert_eq!(params["sql"], "SELECT 1");
        assert_eq!(params["database"], "prod");
    }

    // ---- extract_preview ----

    #[test]
    fn test_extract_preview_dot_path_into_nested_body() {
        let spec = ApprovalPreviewSpec {
            title: Some("Telegram message".to_string()),
            fields: vec![
                PreviewFieldSpec {
                    label: "To (chat)".to_string(),
                    path: "body.chat_id".to_string(),
                    format: None,
                },
                PreviewFieldSpec {
                    label: "Message".to_string(),
                    path: "body.text".to_string(),
                    format: Some("text".to_string()),
                },
            ],
        };
        let params = serde_json::json!({
            "method": "POST",
            "url": "https://api.telegram.org/bot123/sendMessage",
            "body": { "chat_id": "7647924153", "text": "hello there" }
        });
        let preview = extract_preview(&spec, &params);
        assert_eq!(preview.title.as_deref(), Some("Telegram message"));
        assert_eq!(preview.fields.len(), 2);
        assert_eq!(preview.fields[0].label, "To (chat)");
        assert_eq!(preview.fields[0].value, "7647924153");
        assert_eq!(preview.fields[0].format, "inline"); // default
        assert_eq!(preview.fields[1].label, "Message");
        assert_eq!(preview.fields[1].value, "hello there");
        assert_eq!(preview.fields[1].format, "text");
    }

    #[test]
    fn test_extract_preview_coerces_number_and_bool() {
        let spec = ApprovalPreviewSpec {
            title: None,
            fields: vec![
                PreviewFieldSpec {
                    label: "Amount".to_string(),
                    path: "body.amount".to_string(),
                    format: None,
                },
                PreviewFieldSpec {
                    label: "Urgent".to_string(),
                    path: "body.urgent".to_string(),
                    format: None,
                },
            ],
        };
        let params = serde_json::json!({ "body": { "amount": 42, "urgent": true } });
        let preview = extract_preview(&spec, &params);
        assert_eq!(preview.fields[0].value, "42");
        assert_eq!(preview.fields[1].value, "true");
    }

    #[test]
    fn test_extract_preview_skips_missing_or_null_field() {
        let spec = ApprovalPreviewSpec {
            title: None,
            fields: vec![
                PreviewFieldSpec {
                    label: "Present".to_string(),
                    path: "body.text".to_string(),
                    format: None,
                },
                PreviewFieldSpec {
                    label: "Missing".to_string(),
                    path: "body.nonexistent".to_string(),
                    format: None,
                },
                PreviewFieldSpec {
                    label: "Null".to_string(),
                    path: "body.nothing".to_string(),
                    format: None,
                },
            ],
        };
        let params = serde_json::json!({ "body": { "text": "hi", "nothing": null } });
        let preview = extract_preview(&spec, &params);
        // Only the present, non-null field survives.
        assert_eq!(preview.fields.len(), 1);
        assert_eq!(preview.fields[0].label, "Present");
        assert_eq!(preview.fields[0].value, "hi");
    }

    #[test]
    fn test_extract_preview_only_emits_declared_fields() {
        // params carries far more than the spec names (including a nested object
        // and an array) — extract_preview must emit ONLY the declared paths and
        // must never descend into / surface anything else (e.g. secrets sitting
        // alongside the declared fields in `params`).
        let spec = ApprovalPreviewSpec {
            title: None,
            fields: vec![PreviewFieldSpec {
                label: "To".to_string(),
                path: "body.to".to_string(),
                format: None,
            }],
        };
        let params = serde_json::json!({
            "method": "POST",
            "url": "https://api.example.com/send",
            "headers": { "Authorization": "Bearer super-secret" },
            "body": {
                "to": "a@b.com",
                "cc": ["x@y.com"],
                "metadata": { "internal_id": "should-not-leak" }
            }
        });
        let preview = extract_preview(&spec, &params);
        assert_eq!(preview.fields.len(), 1);
        assert_eq!(preview.fields[0].label, "To");
        assert_eq!(preview.fields[0].value, "a@b.com");
    }

    #[test]
    fn test_extract_preview_path_through_non_object_is_skipped() {
        // A path that walks through a scalar or array (not an object) must be
        // skipped rather than panicking.
        let spec = ApprovalPreviewSpec {
            title: None,
            fields: vec![PreviewFieldSpec {
                label: "Bad".to_string(),
                path: "body.to.nested".to_string(),
                format: None,
            }],
        };
        let params = serde_json::json!({ "body": { "to": "a@b.com" } });
        let preview = extract_preview(&spec, &params);
        assert!(preview.fields.is_empty());
    }
}
