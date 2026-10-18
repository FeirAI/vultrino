//! Networked LLM proxy (connector M1, decision 5).
//!
//! A harness's model endpoint (hermes `config.yaml` `model.base_url`) is pointed
//! at vultrino's `POST /llm` so the **provider model key never leaves the vault**
//! and token spend is **metered** (V13). The harness keeps speaking the
//! OpenAI-compatible wire protocol; vultrino is a transparent reverse proxy that:
//!
//! 1. **authenticates** the inbound `Authorization: Bearer <vut_|vk_>` (the same
//!    use-token the harness uses for `/mcp`),
//! 2. resolves the principal's single **LLM-proxy capability**
//!    ([`crate::capability::Capability::is_llm_proxy`]) — the bound model channel,
//! 3. forwards the request body to `provider_base` + the inbound path (e.g.
//!    `/v1/chat/completions`), **injecting the vault credential** referenced by the
//!    capability via the SAME enforced path the named tools use
//!    ([`crate::server::VultrinoServer::execute_gated`] → `run_action`):
//!    default-deny policy, single-use token consumption, V7 egress scrub (so no
//!    model key ever reflects back to the agent), and the V13a/V13b leria emits,
//! 4. returns the provider's response body + status **verbatim** so the harness's
//!    OpenAI client sees a normal completion.
//!
//! ## Why metering "just works"
//! [`crate::server::VultrinoServer`]'s `run_action` already reads the provider
//! `usage` block from the RAW response body (pre-scrub) and emits BOTH the V13a
//! `api-calls=1` event and — for a non-streamed response carrying a usage split —
//! the V13b `asset=usd` + `tokens{input,output}` + `dims.model_ref` event that
//! leria PRICES. The proxy only has to drive that path with the agent's body; the
//! token accounting is automatic and identical to any other metered action.
//!
//! ## Streaming (SSE)
//! A `{"stream": true}` request is forwarded **incrementally** as
//! `text/event-stream` (connector M1 streaming), engaged purely on the wire flag
//! and the operator kill-switch (`[llm_proxy] streaming_enabled`, default on; when
//! off, the stream flags are stripped and the turn is served buffered). The same
//! gate runs ([`crate::server::VultrinoServer::execute_gated_streaming`] shares
//! [`crate::server::VultrinoServer`]'s decision step with the buffered path), and
//! the streamed body passes through an INCREMENTAL egress scrub (a secret split
//! across SSE chunks is still caught) before reaching the agent.
//!
//! Metering on a streamed turn: V13a `api-calls=1` always fires (even on a halt or
//! disconnect); the V13b token event fires whenever a complete usage trailer was
//! parsed — including a client disconnect or upstream error AFTER the trailer arrived
//! (the parsed usage is carried into the finalizer's Drop), not only on a clean EOF.
//! For OpenAI-chat requests vultrino FORCES `stream_options.include_usage = true`
//! (gateway-owned — a client cannot opt out by sending `include_usage:false`) so the
//! provider emits that trailer. NVIDIA rejects that option on a streaming request with
//! a non-empty OpenAI `tools` array, so for that provider-specific shape vultrino removes
//! `stream_options` and records V13a only. Anthropic `/v1/messages` and OpenAI
//! `/v1/responses` report usage natively. Honest residuals: a capability with an operator
//! `block`/`redact_patterns` egress rule, or a compressed response, is served BUFFERED;
//! a stream that is truncated/halted BEFORE the usage trailer arrives meters V13a only.
//!
//! ## Gateway-owned reasoning effort
//! A capability may declare `llm.reasoning_effort` (one of `none`, `minimal`, `low`,
//! `medium`, `high`). When it is set, vultrino WRITES that effort into every request on
//! the channel — top-level `reasoning_effort` for OpenAI Chat Completions, nested
//! `reasoning.effort` (other `reasoning` keys preserved) for OpenAI Responses —
//! OVERWRITING any value the agent supplied, of any type. Like `include_usage` and the
//! `max_output_tokens` ceiling this is gateway-owned and not negotiable by the agent:
//! reasoning tokens are billed as OUTPUT tokens, so the effort a channel runs at is
//! spend, and an agent that could raise it could raise its own bill past the ceiling the
//! operator sized. It is also a compatibility requirement on some models (OpenAI refuses
//! function tools on Chat Completions for `gpt-5.6-luna` at any effort above `none`).
//! Unconfigured, the proxy touches nothing.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;

use crate::auth::UseToken;
use crate::server::ExecAuth;
use crate::{ExecuteRequest, ExecutionOutcome};

use super::server::AppState;

/// Extract the Bearer secret (use token `vut_` or API key `vk_`) from the
/// `Authorization` header.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Inbound request headers vultrino forwards verbatim to the provider. This is a
/// strict ALLOWLIST (not a denylist) so a new SDK header can never accidentally
/// smuggle the agent's vultrino Bearer, `Host`, `Content-Length`, or
/// `Accept-Encoding` upstream — only these named provider-protocol headers ride
/// along. Lower-cased for case-insensitive matching.
///
/// - `anthropic-version` is **required** by the Anthropic Messages API (a request
///   without it 400s), so dropping it (as the pre-streaming proxy did) made the
///   Anthropic provider unusable. `anthropic-beta` opts into beta features.
/// - `openai-beta` opts an OpenAI request into beta behaviour when the SDK sets it.
/// - `openai-organization` and `openai-project` are NOT forwarded: they pick the
///   organization and project that are billed and scoped, so they are the
///   operator's (credential metadata), injected downstream, never the client's.
///   The same goes for `anthropic-workspace-id`.
const FORWARDED_PROVIDER_HEADERS: &[&str] = &[
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
    "x-goog-user-project",
    "x-goog-api-client",
    "x-ms-client-request-id",
];

/// The gateway-owned credential metadata key a `CredentialConfig` reason names, for
/// the agent-facing refusal. Only the key name is echoed, never the stored value.
fn misconfigured_key(reason: &str) -> &'static str {
    [
        crate::ANTHROPIC_WORKSPACE_META,
        crate::OPENAI_ORGANIZATION_META,
        crate::OPENAI_PROJECT_META,
    ]
    .into_iter()
    .find(|k| reason.contains(k))
    .unwrap_or("credential metadata")
}

fn provider_feature_enabled(protocol: &str) -> bool {
    let flag = match protocol {
        "openai-chat" | "openai-responses" => "VULTRINO_PROVIDER_OPENAI_ENABLED",
        // NVIDIA's integrate.api.nvidia.com is OpenAI-wire-compatible, so it rides the
        // same transparent-proxy path as openai-chat — but on its OWN switch, so an
        // operator can run NVIDIA (e.g. a hermes fleet on Nemotron) WITHOUT enabling the
        // generic OpenAI provider. capability validation pins a nvidia channel's
        // provider_base to an *.nvidia.com host.
        "nvidia" => "VULTRINO_PROVIDER_NVIDIA_ENABLED",
        "azure-openai" => "VULTRINO_PROVIDER_AZURE_OPENAI_ENABLED",
        "anthropic-messages" => "VULTRINO_PROVIDER_ANTHROPIC_ENABLED",
        "bedrock-converse" | "bedrock-invoke" => "VULTRINO_PROVIDER_BEDROCK_ENABLED",
        "gemini" => "VULTRINO_PROVIDER_GEMINI_ENABLED",
        "vertex-ai" => "VULTRINO_PROVIDER_VERTEX_AI_ENABLED",
        // FAIL CLOSED on anything unmapped. Capability validation whitelists the seven
        // provider families above plus "observed-only"; an observed-only channel is
        // telemetry-grade and must never be served credential-injected proxy traffic,
        // and any future protocol must be wired to an explicit VULTRINO_PROVIDER_*
        // switch before it can carry traffic.
        _ => return false,
    };
    std::env::var(flag).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Copy the allowlisted provider-protocol headers from the inbound request into
/// the forwarded header map. Never copies auth/transport headers (the allowlist
/// excludes them by construction); the vault credential is injected downstream by
/// the http plugin.
fn forward_provider_headers(inbound: &HeaderMap, fwd: &mut HashMap<String, String>) {
    for &name in FORWARDED_PROVIDER_HEADERS {
        if let Some(value) = inbound.get(name).and_then(|v| v.to_str().ok()) {
            let value = value.trim();
            if !value.is_empty() {
                fwd.insert(name.to_string(), value.to_string());
            }
        }
    }
}

/// Whether the RESOLVED UPSTREAM URL targets an OpenAI **chat/completions**-style
/// endpoint (so `stream_options.include_usage` injection is appropriate). Matches
/// `…/chat/completions` and the legacy `…/completions`; excludes `/v1/responses` and
/// Anthropic `/v1/messages`, which report streamed usage natively. It is keyed on the
/// resolved upstream (provider_base + inbound path), NOT the inbound path alone — a bare
/// `POST /llm` carries an empty inbound path but its provider_base may itself be the
/// chat-completions endpoint, and injection must still apply there.
fn is_openai_chat_endpoint(upstream: &str) -> bool {
    // Ignore any query/fragment, then suffix-match the path component.
    let path = upstream
        .split(['?', '#'])
        .next()
        .unwrap_or(upstream)
        .trim_end_matches('/');
    path.ends_with("/completions")
}

/// NVIDIA's OpenAI-compatible streaming endpoint hangs when `stream_options` is present
/// alongside a non-empty top-level OpenAI `tools` array. Remove the unsupported option
/// for precisely that provider/request shape, including a client-supplied value. Returns
/// whether this is the NVIDIA tool-stream compatibility path, so its caller can leave the
/// request V13a-only instead of re-injecting `include_usage`.
fn normalize_nvidia_tool_stream_options(provider: &str, body: &mut serde_json::Value) -> bool {
    if provider != "nvidia" {
        return false;
    }
    let Some(obj) = body.as_object_mut() else {
        return false;
    };
    let has_tools = obj
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tools| !tools.is_empty());
    if !has_tools {
        return false;
    }
    obj.remove("stream_options");
    true
}

/// How the resolved upstream URL picks the model, which for some providers is not the
/// body's `model` (the upstream ignores that field): Gemini and Vertex AI name it in a
/// `models/<id>[:<method>]` segment, Amazon Bedrock in `model/<id>/...`, Azure OpenAI by
/// `deployments/<name>`. The gate, the allowlist and the meter all use the model this
/// returns, never one the agent can choose in the body.
#[derive(Debug, PartialEq, Eq)]
enum UrlModel {
    /// The body's `model` is what the upstream serves (OpenAI, Anthropic, NVIDIA, and the
    /// OpenAI-compatible endpoints of Gemini and Vertex).
    BodyPicks,
    /// The URL selects `model`. A body `model` is accepted only if it equals `model` or
    /// `body_ok` (an Azure deployment name).
    Names {
        model: String,
        body_ok: Option<String>,
    },
    /// The URL does not name exactly one model (or names one the operator has not
    /// mapped): the request cannot be shown to be priced.
    Unresolvable(String),
}

/// The percent-decoded id following the single path segment equal to `key`. `Ok(None)` when
/// the path has no such segment, `Err` when it has several or an empty id (ambiguous: the
/// upstream's choice cannot be known here).
fn id_after_segment(upstream: &str, key: &str) -> Result<Option<String>, ()> {
    let Ok(url) = url::Url::parse(upstream) else {
        return Err(());
    };
    let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
    let mut found: Option<String> = None;
    for (i, seg) in segments.iter().enumerate() {
        if *seg != key {
            continue;
        }
        let Some(id) = segments.get(i + 1) else {
            return Err(());
        };
        let id = urlencoding::decode(id).map_err(|_| ())?.into_owned();
        if id.is_empty() || found.is_some() {
            return Err(());
        }
        found = Some(id);
    }
    Ok(found)
}

fn url_model(
    protocol: &str,
    upstream: &str,
    body_model: Option<&str>,
    azure_deployments: &HashMap<String, String>,
) -> UrlModel {
    let unresolvable = |why: &str| UrlModel::Unresolvable(why.to_string());
    match protocol {
        "gemini" | "vertex-ai" => match id_after_segment(upstream, "models") {
            Ok(Some(id)) => UrlModel::Names {
                model: id.split(':').next().unwrap_or(&id).to_string(),
                body_ok: None,
            },
            // The OpenAI-compatible endpoint takes the model from the body.
            Ok(None) if is_openai_chat_endpoint(upstream) => UrlModel::BodyPicks,
            Ok(None) => unresolvable("the upstream URL names no models/<id> segment"),
            Err(()) => unresolvable("the upstream URL names more than one model, or none cleanly"),
        },
        "bedrock-converse" | "bedrock-invoke" => match id_after_segment(upstream, "model") {
            Ok(Some(id)) => UrlModel::Names {
                model: id,
                body_ok: None,
            },
            Ok(None) => unresolvable("the upstream URL names no model/<id> segment"),
            Err(()) => unresolvable("the upstream URL names more than one model, or none cleanly"),
        },
        "azure-openai" => {
            let name = match id_after_segment(upstream, "deployments") {
                Ok(Some(name)) => name,
                Ok(None) => match body_model {
                    Some(m) => m.to_string(),
                    None => {
                        return unresolvable("no deployment in the URL and no model in the body")
                    }
                },
                Err(()) => {
                    return unresolvable(
                        "the upstream URL names more than one deployment, or none cleanly",
                    )
                }
            };
            match azure_deployments.get(&name) {
                Some(model) => UrlModel::Names {
                    model: model.clone(),
                    body_ok: Some(name),
                },
                None => UrlModel::Unresolvable(format!(
                    "deployment '{name}' is not mapped to a priced model in [llm_proxy.azure_deployments]"
                )),
            }
        }
        _ => UrlModel::BodyPicks,
    }
}

/// How a request field is checked once its name is on the table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Bills tokens alone whatever it holds (a sampling parameter, the messages, a stop list).
    Plain,
    /// `tools`: an array of entries of the dialect's plain client-tool shape.
    Tools,
    /// OpenAI's legacy `functions`: an array of plain function definitions.
    LegacyFunctions,
    /// Bedrock Converse `toolConfig`: `tools` of plain tool specs and a `toolChoice`.
    ConverseToolConfig,
    /// Gemini `toolConfig`: function-calling settings only.
    GeminiToolConfig,
    /// A list (or comma string) of `anthropic-beta` values, each on [`PRICED_BETAS`].
    Betas,
}

/// The tool-entry dialect of a protocol.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Anthropic,
    OpenAiChat,
    OpenAiResponses,
    /// Azure serves both OpenAI shapes; an entry may be either.
    Azure,
    Gemini,
    Converse,
}

use Kind::{Betas, ConverseToolConfig, GeminiToolConfig, LegacyFunctions, Plain, Tools};

// ---------------------------------------------------------------------------------------
// THE ALLOWLIST. Every top-level request field the proxy admits, per protocol, and nothing
// else. A field on one of these tables is one whose top-level presence cannot change what a
// token costs (the rate card holds one input and one output price per model), with one
// bounded exception: the gate also inspects the nested media and modality markers in
// `modality_marker` (a Gemini media part admitted only for image, PDF and text types, found
// at any depth; `responseModalities` exactly TEXT; an OpenAI content part only text or
// image), because audio and video bill above the token rate inside an admitted field.
// Other nested options are NOT inspected (bounded). ADDING A FIELD TO A
// TABLE IS A PRICING DECISION: do it only after reading the provider's price list for what
// the field switches on, and add a test that fails without it. A field not listed here
// (compaction, context_management, fallbacks, speed, inference_geo, any service tier in any
// casing, a search option, a guardrail, a field the provider adds next year) is refused with
// `403 modifier_unpriced` before the upstream call. The rate-card format has no entry for a
// priced variant of a field, so no card can widen this; an operator widens it by a code
// change. Matching is exact and case-sensitive: `ServiceTier` is not `serviceTier`, and is
// refused because it is on no table.
// ---------------------------------------------------------------------------------------

const ANTHROPIC_FIELDS: &[(&str, Kind)] = &[
    ("model", Plain),
    ("messages", Plain),
    ("system", Plain),
    ("max_tokens", Plain),
    ("temperature", Plain),
    ("top_p", Plain),
    ("top_k", Plain),
    ("stop_sequences", Plain),
    ("stream", Plain),
    ("metadata", Plain),
    // Thinking tokens bill as output tokens, which the usage block carries.
    ("thinking", Plain),
    ("cache_control", Plain),
    ("tool_choice", Plain),
    ("tools", Tools),
];

/// Anthropic models behind Bedrock InvokeModel and Vertex rawPredict: the same body, with the
/// version and beta list in the body.
const ANTHROPIC_HOSTED_EXTRA: &[(&str, Kind)] =
    &[("anthropic_version", Plain), ("anthropic_beta", Betas)];

const BEDROCK_INVOKE_OTHER: &[(&str, Kind)] = &[
    ("prompt", Plain),
    ("max_gen_len", Plain),
    ("inputText", Plain),
    ("textGenerationConfig", Plain),
];

const OPENAI_CHAT_FIELDS: &[(&str, Kind)] = &[
    ("model", Plain),
    ("messages", Plain),
    ("max_tokens", Plain),
    ("max_completion_tokens", Plain),
    ("temperature", Plain),
    ("top_p", Plain),
    ("n", Plain),
    ("stop", Plain),
    ("stream", Plain),
    ("stream_options", Plain),
    ("frequency_penalty", Plain),
    ("presence_penalty", Plain),
    ("logit_bias", Plain),
    ("logprobs", Plain),
    ("top_logprobs", Plain),
    ("seed", Plain),
    ("response_format", Plain),
    ("tool_choice", Plain),
    ("parallel_tool_calls", Plain),
    ("function_call", Plain),
    ("user", Plain),
    ("reasoning_effort", Plain),
    ("verbosity", Plain),
    ("store", Plain),
    ("metadata", Plain),
    ("prediction", Plain),
    ("prompt_cache_key", Plain),
    ("safety_identifier", Plain),
    ("tools", Tools),
    ("functions", LegacyFunctions),
];

const NVIDIA_EXTRA: &[(&str, Kind)] = &[
    ("top_k", Plain),
    ("min_p", Plain),
    ("repetition_penalty", Plain),
    ("chat_template_kwargs", Plain),
];

const OPENAI_RESPONSES_FIELDS: &[(&str, Kind)] = &[
    ("model", Plain),
    ("input", Plain),
    ("instructions", Plain),
    ("max_output_tokens", Plain),
    ("max_tool_calls", Plain),
    ("temperature", Plain),
    ("top_p", Plain),
    ("stream", Plain),
    ("stream_options", Plain),
    ("tool_choice", Plain),
    ("parallel_tool_calls", Plain),
    ("reasoning", Plain),
    ("text", Plain),
    ("metadata", Plain),
    ("store", Plain),
    ("previous_response_id", Plain),
    ("truncation", Plain),
    ("include", Plain),
    ("user", Plain),
    ("prompt_cache_key", Plain),
    ("safety_identifier", Plain),
    ("tools", Tools),
];

const GEMINI_FIELDS: &[(&str, Kind)] = &[
    ("model", Plain),
    ("contents", Plain),
    ("systemInstruction", Plain),
    ("system_instruction", Plain),
    ("generationConfig", Plain),
    ("generation_config", Plain),
    ("safetySettings", Plain),
    ("safety_settings", Plain),
    ("cachedContent", Plain),
    ("cached_content", Plain),
    ("labels", Plain),
    ("toolConfig", GeminiToolConfig),
    ("tool_config", GeminiToolConfig),
    ("tools", Tools),
];

const CONVERSE_FIELDS: &[(&str, Kind)] = &[
    ("model", Plain),
    ("messages", Plain),
    ("system", Plain),
    ("inferenceConfig", Plain),
    ("requestMetadata", Plain),
    ("toolConfig", ConverseToolConfig),
];

/// `anthropic-beta` values that do not change the price of a token. Anything else (the 1M
/// context window bills long prompts at a higher rate, fast mode, compaction, context
/// management, code execution and the like) is refused. Adding a value is a pricing decision.
const PRICED_BETAS: &[&str] = &[
    "prompt-caching-2024-07-31",
    "extended-cache-ttl-2025-04-11",
    "interleaved-thinking-2025-05-14",
    "fine-grained-tool-streaming-2025-05-14",
    "token-efficient-tools-2025-02-19",
    "output-128k-2025-02-19",
    "structured-outputs-2025-11-13",
    "effort-2025-11-24",
    "computer-use-2024-10-22",
    "computer-use-2025-01-24",
    "computer-use-2025-11-24",
    "pdf-2024-09-25",
    "claude-code-20250219",
];

/// Anthropic client-executed tools, by exact versioned type. Matching by prefix would admit
/// the server-run `bash_code_execution_*` and `text_editor_code_execution_*`.
const ANTHROPIC_CLIENT_TOOL_TYPES: &[&str] = &[
    "bash_20241022",
    "bash_20250124",
    "text_editor_20241022",
    "text_editor_20250124",
    "text_editor_20250429",
    "text_editor_20250728",
    "memory_20250818",
    "computer_20241022",
    "computer_20250124",
    "computer_20251124",
];

/// The tables and tool dialect a request is checked against: the protocol, and for the
/// protocols that serve more than one body shape, the upstream URL that says which.
fn request_tables(
    protocol: &str,
    upstream: &str,
) -> (Vec<&'static [(&'static str, Kind)]>, Dialect) {
    match protocol {
        "anthropic-messages" => (vec![ANTHROPIC_FIELDS], Dialect::Anthropic),
        "openai-chat" => (vec![OPENAI_CHAT_FIELDS], Dialect::OpenAiChat),
        "nvidia" => (vec![OPENAI_CHAT_FIELDS, NVIDIA_EXTRA], Dialect::OpenAiChat),
        "openai-responses" => (vec![OPENAI_RESPONSES_FIELDS], Dialect::OpenAiResponses),
        "azure-openai" => (
            vec![OPENAI_CHAT_FIELDS, OPENAI_RESPONSES_FIELDS],
            Dialect::Azure,
        ),
        "gemini" | "vertex-ai" if upstream.contains("/publishers/anthropic/") => (
            vec![ANTHROPIC_FIELDS, ANTHROPIC_HOSTED_EXTRA],
            Dialect::Anthropic,
        ),
        "gemini" | "vertex-ai" if is_openai_chat_endpoint(upstream) => {
            (vec![OPENAI_CHAT_FIELDS], Dialect::OpenAiChat)
        }
        "gemini" | "vertex-ai" => (vec![GEMINI_FIELDS], Dialect::Gemini),
        "bedrock-converse" => (vec![CONVERSE_FIELDS], Dialect::Converse),
        "bedrock-invoke" => (
            vec![
                ANTHROPIC_FIELDS,
                ANTHROPIC_HOSTED_EXTRA,
                BEDROCK_INVOKE_OTHER,
            ],
            Dialect::Anthropic,
        ),
        // Fail closed: a protocol with no table admits no field.
        _ => (Vec::new(), Dialect::Anthropic),
    }
}

/// Whether `obj` has no key outside `allowed`.
fn only_keys(obj: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> bool {
    obj.keys().all(|k| allowed.contains(&k.as_str()))
}

fn has_name(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("name").is_some_and(serde_json::Value::is_string)
}

fn sub_object<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    obj.get(key).and_then(serde_json::Value::as_object)
}

/// Whether one tool entry is exactly a plain client-side tool of `dialect`: its cost is the
/// model's tokens, no server runs anything. The shapes are the ones each protocol defines
/// for a function (or custom) tool; an entry with a key beyond them, an untyped object that
/// is not the plain function shape, and every server tool are refused.
fn tool_is_plain(dialect: Dialect, tool: &serde_json::Value) -> bool {
    let Some(obj) = tool.as_object() else {
        return false;
    };
    let kind = obj.get("type").map(serde_json::Value::as_str);
    match dialect {
        Dialect::Anthropic => match kind {
            None | Some(Some("custom")) => {
                only_keys(
                    obj,
                    &[
                        "type",
                        "name",
                        "description",
                        "input_schema",
                        "cache_control",
                        "strict",
                    ],
                ) && has_name(obj)
                    && obj
                        .get("input_schema")
                        .is_some_and(serde_json::Value::is_object)
            }
            Some(Some(t)) if ANTHROPIC_CLIENT_TOOL_TYPES.contains(&t) => {
                only_keys(
                    obj,
                    &[
                        "type",
                        "name",
                        "cache_control",
                        "display_width_px",
                        "display_height_px",
                        "display_number",
                        "max_characters",
                        "enable_zoom",
                    ],
                ) && has_name(obj)
            }
            _ => false,
        },
        Dialect::OpenAiChat => openai_chat_tool(obj, kind),
        Dialect::OpenAiResponses => openai_responses_tool(obj, kind),
        Dialect::Azure => openai_chat_tool(obj, kind) || openai_responses_tool(obj, kind),
        Dialect::Gemini => {
            !obj.is_empty()
                && only_keys(obj, &["functionDeclarations", "function_declarations"])
                && obj.values().all(|decls| {
                    decls.as_array().is_some_and(|list| {
                        list.iter().all(|d| {
                            d.as_object().is_some_and(|d| {
                                has_name(d)
                                    && only_keys(
                                        d,
                                        &[
                                            "name",
                                            "description",
                                            "parameters",
                                            "parametersJsonSchema",
                                            "parameters_json_schema",
                                            "response",
                                            "responseJsonSchema",
                                            "response_json_schema",
                                            "behavior",
                                        ],
                                    )
                            })
                        })
                    })
                })
        }
        Dialect::Converse => {
            if obj.len() != 1 {
                return false;
            }
            if let Some(spec) = sub_object(obj, "toolSpec") {
                return has_name(spec)
                    && only_keys(spec, &["name", "description", "inputSchema", "strict"]);
            }
            sub_object(obj, "cachePoint").is_some_and(|c| only_keys(c, &["type"]))
        }
    }
}

fn openai_chat_tool(
    obj: &serde_json::Map<String, serde_json::Value>,
    kind: Option<Option<&str>>,
) -> bool {
    match kind {
        Some(Some("function")) => {
            obj.len() == 2
                && sub_object(obj, "function").is_some_and(|f| {
                    has_name(f) && only_keys(f, &["name", "description", "parameters", "strict"])
                })
        }
        Some(Some("custom")) => {
            obj.len() == 2
                && sub_object(obj, "custom").is_some_and(|c| {
                    has_name(c) && only_keys(c, &["name", "description", "format"])
                })
        }
        _ => false,
    }
}

fn openai_responses_tool(
    obj: &serde_json::Map<String, serde_json::Value>,
    kind: Option<Option<&str>>,
) -> bool {
    match kind {
        Some(Some("function")) => {
            has_name(obj)
                && only_keys(
                    obj,
                    &["type", "name", "description", "parameters", "strict"],
                )
        }
        Some(Some("custom")) => {
            has_name(obj) && only_keys(obj, &["type", "name", "description", "format"])
        }
        _ => false,
    }
}

/// Whether one beta value, or a comma-separated list of them, is entirely on [`PRICED_BETAS`].
fn betas_priced(list: &str) -> bool {
    list.split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .all(|b| PRICED_BETAS.contains(&b))
}

fn field_is_priced(kind: Kind, dialect: Dialect, value: &serde_json::Value) -> bool {
    match kind {
        Plain => true,
        Tools => value
            .as_array()
            .is_some_and(|list| list.iter().all(|t| tool_is_plain(dialect, t))),
        LegacyFunctions => value.as_array().is_some_and(|list| {
            list.iter().all(|f| {
                f.as_object().is_some_and(|f| {
                    has_name(f) && only_keys(f, &["name", "description", "parameters"])
                })
            })
        }),
        ConverseToolConfig => value.as_object().is_some_and(|c| {
            only_keys(c, &["tools", "toolChoice"])
                && c.get("tools").is_none_or(|t| {
                    t.as_array()
                        .is_some_and(|l| l.iter().all(|t| tool_is_plain(Dialect::Converse, t)))
                })
        }),
        GeminiToolConfig => value.as_object().is_some_and(|c| {
            only_keys(
                c,
                &[
                    "functionCallingConfig",
                    "function_calling_config",
                    "retrievalConfig",
                    "retrieval_config",
                ],
            )
        }),
        Betas => match value {
            serde_json::Value::String(s) => betas_priced(s),
            serde_json::Value::Array(list) => {
                list.iter().all(|b| b.as_str().is_some_and(betas_priced))
            }
            _ => false,
        },
    }
}

/// Media types a Gemini `inlineData` or `fileData` part may carry: those that bill at the
/// model's token rate (images, PDF, text). Anything else, including audio, video and a type
/// the provider adds next year, is refused until the card prices it. Matching is exact on the
/// lowercased string (no trimming, no parameters), so a spelling the proxy does not recognise
/// is refused rather than forwarded.
const PRICED_MEDIA_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/heic",
    "image/heif",
    "image/gif",
    "application/pdf",
];

/// Whether a media type value is a string on [`PRICED_MEDIA_TYPES`] or a `text/*` type. A
/// missing, non-string or any other value is not priced.
fn is_priced_mime(v: Option<&serde_json::Value>) -> bool {
    v.and_then(serde_json::Value::as_str)
        .is_some_and(is_priced_mime_str)
}

/// [`is_priced_mime`] for a string already taken out of its value.
fn is_priced_mime_str(m: &str) -> bool {
    let m = m.to_ascii_lowercase();
    PRICED_MEDIA_TYPES.contains(&m.as_str()) || m.starts_with("text/")
}

/// Whether an OpenAI image URL may be forwarded. A `data:` URL (any casing, leading
/// whitespace ignored) declares its media type between `data:` and the first `;` or `,`
/// (trimmed): it is admitted only when that type is priced, so a `data:audio/wav` or
/// `data:video/mp4` URL, or one with no media type, is refused (fail closed). Any other URL
/// (https and the like) is fetched by the provider and is not inspected.
fn image_url_priced(url: &str) -> bool {
    let url = url.trim_start();
    let Some(head) = url.get(..5) else {
        return true;
    };
    if !head.eq_ignore_ascii_case("data:") {
        return true;
    }
    let rest = &url[5..];
    let end = rest.find([';', ',']).unwrap_or(rest.len());
    is_priced_mime_str(rest[..end].trim())
}

/// A marker for an `image_url` part (chat: a string or an object with `url`) or an
/// `input_image` part (a string) whose data URL carries an unpriced media type.
fn image_part_marker(part: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    use serde_json::Value;
    let url = match part.get("image_url") {
        Some(Value::String(u)) => Some(u.as_str()),
        Some(Value::Object(o)) => o.get("url").and_then(Value::as_str),
        _ => None,
    }?;
    (!image_url_priced(url)).then(|| {
        "an image part whose data URL declares a media type that is not an image, PDF or text type (audio, video or none) bills above the token rate or cannot be priced"
            .to_string()
    })
}

/// How deep the Gemini body walk goes before it refuses (fail closed): a body nested deeper
/// than this cannot exhaust the stack and cannot hide a part below the walk.
const MODALITY_WALK_MAX_DEPTH: usize = 64;

/// Walk a Gemini request value at any depth, treating a single object and an array the same
/// (Google's parser accepts one object for a repeated field, and the proxy forwards the value
/// as parsed). An object under `inlineData`, `inline_data`, `fileData` or `file_data` must be
/// an object whose `mimeType` / `mime_type` is on the priced list, and a `responseModalities`
/// or `response_modalities` must be a non-empty array of exactly `TEXT`; anything else is a
/// marker. Returns what was found.
fn gemini_media_marker(v: &serde_json::Value, depth: usize) -> Option<String> {
    use serde_json::Value;
    match v {
        Value::Array(items) => items.iter().find_map(|i| gemini_media_marker(i, depth + 1)),
        Value::Object(map) => gemini_map_marker(map, depth),
        _ => None,
    }
    .or_else(|| {
        (depth > MODALITY_WALK_MAX_DEPTH).then(|| {
            format!(
                "the request nests deeper than {MODALITY_WALK_MAX_DEPTH} levels, so its media parts cannot be checked"
            )
        })
    })
}

/// [`gemini_media_marker`] for one object (the body itself, or any object inside it).
fn gemini_map_marker(
    map: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
) -> Option<String> {
    use serde_json::Value;
    if depth > MODALITY_WALK_MAX_DEPTH {
        return Some(format!(
            "the request nests deeper than {MODALITY_WALK_MAX_DEPTH} levels, so its media parts cannot be checked"
        ));
    }
    for (key, value) in map {
        match key.as_str() {
            // A JSON null is read like an absent key.
            "inlineData"
            | "inline_data"
            | "fileData"
            | "file_data"
            | "responseModalities"
            | "response_modalities"
                if value.is_null() => {}
            "inlineData" | "inline_data" | "fileData" | "file_data" => {
                // Every media type key present must be priced, and one must be present.
                let priced = value.as_object().is_some_and(|media| {
                    let types: Vec<_> = ["mimeType", "mime_type"]
                        .iter()
                        .filter_map(|k| media.get(*k))
                        .collect();
                    !types.is_empty() && types.into_iter().all(|t| is_priced_mime(Some(t)))
                });
                if !priced {
                    return Some(format!(
                        "a `{key}` part whose media type is missing or is not an image, PDF or text type bills above the token rate or cannot be priced"
                    ));
                }
            }
            "responseModalities" | "response_modalities" => {
                let text_only = value.as_array().is_some_and(|list| {
                    !list.is_empty() && list.iter().all(|m| m.as_str() == Some("TEXT"))
                });
                if !text_only {
                    return Some(format!(
                        "`{key}` is empty or names an output modality other than TEXT, which bills above the token rate"
                    ));
                }
            }
            _ => {}
        }
        if let Value::Array(_) | Value::Object(_) = value {
            if let Some(found) = gemini_media_marker(value, depth + 1) {
                return Some(found);
            }
        }
    }
    None
}

/// Content part types of an OpenAI chat or responses request that bill at the token rate.
const OPENAI_PRICED_PART_TYPES: &[&str] = &[
    "text",
    "image_url",
    "input_text",
    "input_image",
    "output_text",
    "refusal",
];

/// Responses input item types that are plain conversation turns (no server-side tool run).
const OPENAI_PRICED_ITEM_TYPES: &[&str] = &[
    "message",
    "function_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "reasoning",
    "item_reference",
];

/// The conversation items of an OpenAI-shaped body (`messages` or `input`), where a single
/// object is read like a one-element array. A plain string input is text.
fn openai_items(v: &serde_json::Value) -> Vec<&serde_json::Value> {
    match v {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Object(_) => vec![v],
        _ => Vec::new(),
    }
}

/// An OpenAI chat or responses content part, or item, outside the token-rate allowlist: a
/// part type other than text and image, a message that carries an `audio` reference, or an
/// item of a type that runs something server side.
fn openai_content_marker(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    use serde_json::Value;
    for key in ["messages", "input"] {
        let Some(value) = obj.get(key) else { continue };
        for item in openai_items(value) {
            let item = match item {
                Value::String(_) => continue,
                Value::Object(item) => item,
                _ => {
                    return Some(format!(
                        "an entry of `{key}` that is not an object or a string cannot be shown to bill tokens alone"
                    ))
                }
            };
            if item.get("audio").is_some_and(|a| !a.is_null()) {
                return Some(
                    "a message carrying an `audio` object bills above the token rate".to_string(),
                );
            }
            if let Some(found) = image_part_marker(item) {
                return Some(found);
            }
            let item_type = item.get("type").filter(|t| !t.is_null());
            if let Some(t) = item_type {
                let known = t.as_str().is_some_and(|t| {
                    OPENAI_PRICED_ITEM_TYPES.contains(&t) || OPENAI_PRICED_PART_TYPES.contains(&t)
                });
                if !known {
                    return Some(format!(
                        "the `{key}` entry type {t} is not one the card prices at the token rate"
                    ));
                }
            }
            let parts = match item.get("content") {
                Some(c @ (Value::Array(_) | Value::Object(_))) => openai_items(c),
                _ => Vec::new(),
            };
            for part in parts {
                if matches!(part, Value::String(_)) {
                    continue;
                }
                let ok = part
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| OPENAI_PRICED_PART_TYPES.contains(&t));
                if ok {
                    if let Some(found) = part.as_object().and_then(image_part_marker) {
                        return Some(found);
                    }
                } else {
                    return Some(
                        "a content part that is not text or an image (for example `input_audio`) bills above the token rate or cannot be priced"
                            .to_string(),
                    );
                }
            }
        }
    }
    None
}

/// A nested modality marker that bills above the base token rate inside an otherwise
/// admitted field, or that the proxy cannot show bills at it. Gemini: a recursive walk of the
/// whole body (see [`gemini_media_marker`]). OpenAI chat, responses and Azure: a content part
/// or item outside the token-rate allowlist (see [`openai_content_marker`]). Only these are
/// inspected; other nested options are not (bounded).
fn modality_marker(
    dialect: Dialect,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    match dialect {
        Dialect::Gemini => gemini_map_marker(obj, 0),
        Dialect::OpenAiChat | Dialect::OpenAiResponses | Dialect::Azure => {
            openai_content_marker(obj)
        }
        Dialect::Anthropic | Dialect::Converse => None,
    }
}

/// A request that the proxy cannot show to bill tokens alone: any top-level field that is
/// not on the protocol's allowlist table (see the comment above the tables), or a field on
/// it whose value is not the plain shape (a tool that is not a plain client tool, a beta
/// that is not priced). Such a request is refused with `403 modifier_unpriced` before the
/// upstream call. Returns what was found.
fn unpriced_modifier(protocol: &str, upstream: &str, body: &serde_json::Value) -> Option<String> {
    let Some(obj) = body.as_object() else {
        return Some(
            "a request body that is not a JSON object cannot be shown to bill tokens alone"
                .to_string(),
        );
    };
    let (tables, dialect) = request_tables(protocol, upstream);
    for (key, value) in obj {
        let kind = tables
            .iter()
            .flat_map(|t| t.iter())
            .find(|(name, _)| name == key)
            .map(|(_, kind)| *kind);
        match kind {
            None => {
                return Some(format!(
                    "the request field `{key}` is not one the rate card prices for {protocol}: it may bill above the token price (unknown request features are refused; widening the allowlist is a code change)"
                ))
            }
            Some(kind) if !field_is_priced(kind, dialect, value) => {
                return Some(format!(
                    "the value of `{key}` is not a shape that bills tokens alone for {protocol} (only plain client tools, and betas that do not change the price, are admitted)"
                ))
            }
            Some(_) => {}
        }
    }
    modality_marker(dialect, obj).map(|m| {
        format!("{m} for {protocol} (unpriced modalities are refused until the card prices them)")
    })
}

/// The first `anthropic-beta` header value that is not on [`PRICED_BETAS`] (every header
/// line is read; a value that is not visible ASCII is refused too). The header is forwarded
/// upstream only when this returns `None`.
fn unpriced_beta_header(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all("anthropic-beta") {
        let Ok(text) = value.to_str() else {
            return Some("an anthropic-beta header that is not plain text".to_string());
        };
        if let Some(bad) = text
            .split(',')
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .find(|b| !PRICED_BETAS.contains(b))
        {
            return Some(format!(
                "the anthropic-beta value `{bad}` is not one that leaves the token price unchanged"
            ));
        }
    }
    None
}

/// A JSON error response shaped like an OpenAI API error so the harness's model
/// client surfaces it cleanly rather than as an opaque transport failure.
fn llm_error(status: StatusCode, kind: &str, message: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "error": {
                "type": kind,
                "message": message,
            }
        })),
    )
        .into_response()
}

/// Which output-token field to SET when a request names NONE of the known ones, for the
/// given provider `protocol` / resolved `upstream` URL. OpenAI's **Responses API**
/// (`/v1/responses`) reads `max_output_tokens`, not `max_tokens` — an injected `max_tokens`
/// there is an unrecognized field the provider may simply ignore, so the per-call ceiling
/// would silently NOT apply (the defect this function closes). Keyed primarily on
/// `protocol` (authoritative: it is the capability's configured provider family, not
/// agent-controlled), with a path-suffix fallback so a Responses call is still caught
/// even if `protocol` were ever something other than `"openai-responses"` (e.g. routed
/// through a generic/observed protocol whose upstream still ends in `/responses`). Every
/// other routed protocol/path (azure-openai, anthropic-messages, nvidia, an
/// OpenAI-compatible third party under openai-chat, legacy `/v1/completions`) uses
/// `max_tokens`, unchanged from prior behavior. The one further exception is OpenAI's own
/// Chat Completions, which takes `max_completion_tokens` (see below).
fn default_output_token_field(protocol: &str, upstream: &str) -> &'static str {
    let path = upstream
        .split(['?', '#'])
        .next()
        .unwrap_or(upstream)
        .trim_end_matches('/');
    if protocol == "openai-responses" || path.ends_with("/responses") {
        "max_output_tokens"
    } else if protocol == "openai-chat"
        && path.ends_with("/chat/completions")
        && upstream_host_is(upstream, "api.openai.com")
    {
        // OpenAI's own Chat Completions deprecated `max_tokens`, and its current models
        // (the GPT-5 family and the reasoning models) REJECT it with a 400
        // `unsupported_parameter`, so an injected `max_tokens` there would fail every call
        // from a client that names no limit. `max_completion_tokens` is accepted by every
        // chat model OpenAI serves. Host-pinned on purpose: an OpenAI-COMPATIBLE third
        // party routed under `openai-chat` may only know `max_tokens`, so it keeps it.
        "max_completion_tokens"
    } else {
        "max_tokens"
    }
}

/// True when `upstream` parses as a URL whose host is exactly `host` (case-insensitive).
/// An unparseable upstream is simply "not that host": the caller then keeps its default.
fn upstream_host_is(upstream: &str, host: &str) -> bool {
    reqwest::Url::parse(upstream)
        .ok()
        .and_then(|url| url.host_str().map(|h| h.eq_ignore_ascii_case(host)))
        .unwrap_or(false)
}

/// Where a configured `llm.reasoning_effort` is written for this protocol/upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReasoningEffortShape {
    /// OpenAI Chat Completions: top-level `"reasoning_effort": "<value>"`.
    ChatTopLevel,
    /// OpenAI Responses: nested `"reasoning": {"effort": "<value>"}`.
    ResponsesNested,
}

/// Which reasoning-effort shape (if any) the given protocol / resolved upstream
/// speaks. The resolved PATH is consulted first because it is what the provider
/// actually parses: a channel labeled `openai-chat` whose provider_base is a
/// `/v1/responses` endpoint still has to be written the Responses way, or the
/// gateway-owned effort would be an unrecognized top-level field the provider
/// ignores. `protocol` is the fallback for the common case where the inbound path
/// is empty (a bare `POST /llm` against a provider_base that is already the
/// endpoint). Any other protocol/path returns `None` — but validation already
/// refuses to store a reasoning_effort on such a capability, so `None` here means
/// "nothing configured", not "silently dropped".
fn reasoning_effort_shape(protocol: &str, upstream: &str) -> Option<ReasoningEffortShape> {
    let path = upstream
        .split(['?', '#'])
        .next()
        .unwrap_or(upstream)
        .trim_end_matches('/');
    if path.ends_with("/chat/completions") {
        return Some(ReasoningEffortShape::ChatTopLevel);
    }
    if path.ends_with("/responses") {
        return Some(ReasoningEffortShape::ResponsesNested);
    }
    match protocol {
        "openai-chat" => Some(ReasoningEffortShape::ChatTopLevel),
        "openai-responses" => Some(ReasoningEffortShape::ResponsesNested),
        _ => None,
    }
}

/// Write the capability's gateway-owned reasoning `effort` into the request body,
/// OVERWRITING whatever the agent sent (of any type: string, number, null). The
/// agent can neither raise the effort (reasoning tokens bill as output tokens, so
/// raising it is spend) nor lower it below what the operator chose. A non-object
/// body is untouched, exactly as in [`clamp_max_output_tokens`].
///
/// For the Responses shape the sibling keys of `reasoning` (e.g. `summary`) are
/// preserved when it is already an object; a `reasoning` that is absent or is not
/// an object is replaced by a fresh object carrying only `effort`.
fn apply_reasoning_effort(body: &mut serde_json::Value, effort: &str, shape: ReasoningEffortShape) {
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    match shape {
        ReasoningEffortShape::ChatTopLevel => {
            obj.insert(
                "reasoning_effort".to_string(),
                serde_json::Value::String(effort.to_string()),
            );
        }
        ReasoningEffortShape::ResponsesNested => {
            if !obj
                .get("reasoning")
                .is_some_and(serde_json::Value::is_object)
            {
                obj.insert(
                    "reasoning".to_string(),
                    serde_json::Value::Object(serde_json::Map::new()),
                );
            }
            if let Some(reasoning) = obj.get_mut("reasoning").and_then(|r| r.as_object_mut()) {
                reasoning.insert(
                    "effort".to_string(),
                    serde_json::Value::String(effort.to_string()),
                );
            }
        }
    }
}

/// Bound a request's TOTAL output-token cost to the per-call `ceiling`. This is the
/// enforceable substitute for a SpendCap on the LLM channel (which fails closed on a
/// request with no request-time spend), so it must bound EVERY way a request can multiply
/// output: the scalar limit fields, the choice-multiplicity fields, and the legacy
/// completions prompt-array (one completion per prompt). A non-object body is untouched.
/// `default_field` is the field NAME to insert when the request names none of the known
/// output-token fields (see [`default_output_token_field`]) — it must be one of
/// `OUTPUT_TOKEN_FIELDS` below so the inserted field is itself recognized as "present" by
/// any later call.
fn clamp_max_output_tokens(body: &mut serde_json::Value, ceiling: u64, default_field: &str) {
    // Every provider-supported output-token field the proxy routes to, so the per-call
    // ceiling cannot be evaded by naming an alternate field: `max_tokens` (OpenAI chat +
    // legacy + Anthropic), `max_completion_tokens` (newer OpenAI chat models), and
    // `max_output_tokens` (OpenAI /v1/responses).
    const OUTPUT_TOKEN_FIELDS: &[&str] =
        &["max_tokens", "max_completion_tokens", "max_output_tokens"];
    if let Some(obj) = body.as_object_mut() {
        // Multiplicity controls (`n` choices, legacy `best_of`) multiply TOTAL output, so
        // pin them to 1 (this fn only runs under a configured ceiling). Fail closed: a
        // present-but-non-numeric or >1 value is forced to 1.
        for mult in ["n", "best_of"] {
            if obj.get(mult).is_some_and(|v| v.as_u64() == Some(1)) {
                continue;
            }
            if obj.contains_key(mult) {
                obj.insert(mult.to_string(), serde_json::json!(1));
            }
        }
        // Legacy /v1/completions returns ONE completion per prompt, so a `prompt` ARRAY
        // multiplies total output by its length. n/best_of are pinned above, so the only
        // remaining multiplier is the prompt count; divide the per-prompt budget by it so
        // count * per_prompt <= ceiling. (A scalar/absent prompt = 1 unit.)
        let units = obj
            .get("prompt")
            .and_then(|p| p.as_array())
            .map(|a| a.len().max(1) as u64)
            .unwrap_or(1);
        let per_unit = (ceiling / units).max(1);

        let mut any_present = false;
        for field in OUTPUT_TOKEN_FIELDS {
            if obj.contains_key(*field) {
                any_present = true;
                // Clamp a present field to min(req, per_unit); a present-but-unparseable
                // value (null / non-number) fails CLOSED to per_unit.
                let clamped = obj
                    .get(*field)
                    .and_then(|v| v.as_u64())
                    .map_or(per_unit, |req| req.min(per_unit));
                obj.insert((*field).to_string(), serde_json::json!(clamped));
            }
        }
        // The request named NO output-token field → set the one this protocol/upstream
        // actually reads so the provider default can't exceed the bound. Don't inject a
        // second field when the client already chose one (a newer chat model rejects
        // `max_tokens` if it wanted `max_completion_tokens`; the Responses API does not
        // read `max_tokens` at all).
        if !any_present {
            obj.insert(default_field.to_string(), serde_json::json!(per_unit));
        }
    }
}

/// Resolve the inbound Bearer to an [`ExecAuth`] (authenticate only; the
/// capability's credential/action scope is enforced authoritatively inside
/// `execute_gated`). A `vut_` is resolved from storage (reloaded so a token
/// minted by govder's provisioner in the admin process is visible); anything else
/// is validated as an API key.
async fn resolve_exec_auth(state: &AppState, secret: &str) -> Result<ExecAuth, Response> {
    if UseToken::looks_like_token(secret) {
        let _ = state.storage.reload().await;
        let token = match state
            .storage
            .get_use_token_by_hash(&UseToken::hash(secret))
            .await
        {
            Ok(Some(t)) => t,
            _ => {
                return Err(llm_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_request_error",
                    "Invalid use token",
                ))
            }
        };
        if let Err(e) = token.check_usable() {
            return Err(llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!("Use token cannot be used: {e}"),
            ));
        }
        Ok(ExecAuth::from_use_token(token))
    } else {
        let manager = state.auth_manager.read().await;
        match manager.validate_key(secret) {
            Ok((key, role)) => Ok(ExecAuth::from_api_key(crate::auth::AuthResult {
                api_key: key,
                role,
            })),
            Err(e) => Err(llm_error(
                StatusCode::UNAUTHORIZED,
                "invalid_request_error",
                &format!("Invalid API key: {e}"),
            )),
        }
    }
}

/// `POST /llm` — the metered LLM proxy with no extra path (the provider URL is
/// the capability's `provider_base` verbatim). Delegates to [`llm_proxy_impl`].
pub async fn llm_proxy_root(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, None, String::new(), query, headers, body).await
}

/// `POST /llm/{*path}` — the metered LLM proxy.
///
/// The harness points its model `base_url` at `https://vultrino.../llm`; its
/// OpenAI client appends the route path (e.g. `/v1/chat/completions`), which is
/// captured as `path` and joined onto the bound capability's `provider_base`. The
/// request body is forwarded verbatim with the vault key injected; the response
/// is returned verbatim (post egress-scrub); token spend is metered.
pub async fn llm_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, None, path, query, headers, body).await
}

/// Explicit model-channel route for cross-provider fallback/dynamic selection.
pub async fn llm_proxy_channel(
    State(state): State<AppState>,
    Path((channel, path)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, Some(channel), path, query, headers, body).await
}

pub async fn llm_proxy_channel_root(
    State(state): State<AppState>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    llm_proxy_impl(state, Some(channel), String::new(), query, headers, body).await
}

/// Shared implementation for both `/llm` and `/llm/{*path}`.
async fn llm_proxy_impl(
    state: AppState,
    channel: Option<String>,
    path: String,
    query: HashMap<String, String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. Authenticate the inbound Bearer (the harness's use token / API key).
    let secret = match extract_bearer(&headers) {
        Some(s) => s,
        None => {
            return llm_error(
                StatusCode::UNAUTHORIZED,
                "invalid_request_error",
                "Authorization header with a Bearer use-token (vut_) or API key is required",
            )
        }
    };
    let exec_auth = match resolve_exec_auth(&state, &secret).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // 2. Resolve the principal's bound LLM-proxy capability — the model channel.
    //    Reuses the SAME default-deny enforcement the named tools use, so an agent
    //    can only route model traffic through a capability it is actually granted.
    let capability = match state
        .server
        .resolve_llm_proxy_channel_for(exec_auth.auth.as_ref(), channel.as_deref())
        .await
    {
        Ok(c) => c,
        Err(message) => return llm_error(StatusCode::FORBIDDEN, "permission_error", &message),
    };
    let llm = capability
        .llm
        .as_ref()
        .expect("resolved LLM capability has llm config");
    if !provider_feature_enabled(&llm.protocol) {
        return llm_error(
            StatusCode::FORBIDDEN,
            "provider_feature_disabled",
            &format!("Provider protocol '{}' is disabled", llm.protocol),
        );
    }
    let provider = llm.provider.clone().unwrap_or_else(|| llm.protocol.clone());
    let region = llm.region.clone();
    let channel_name = channel.clone().unwrap_or_else(|| capability.id.clone());

    // 3. Build the upstream provider URL (provider_base + inbound path). Provider
    // query parameters are copied into this already-validated URL below; they
    // cannot alter its scheme, authority, or bounded path prefix.
    let mut upstream = match capability.llm_upstream_url(&path) {
        Some(u) => u,
        None => {
            return llm_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "LLM-proxy capability has no valid provider URL",
            )
        }
    };
    // Provider query parameters such as Azure OpenAI's required `api-version`
    // are preserved. The capability still fixes scheme/host/path prefix, so a
    // query can never redirect the request to another origin.
    if !query.is_empty() {
        const AUTH_QUERY_KEYS: &[&str] = &[
            "key",
            "api_key",
            "apikey",
            "access_token",
            "token",
            "sig",
            "signature",
            "x-goog-api-key",
        ];
        if let Some(key) = query.keys().find(|key| {
            AUTH_QUERY_KEYS
                .iter()
                .any(|blocked| key.eq_ignore_ascii_case(blocked))
        }) {
            return llm_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("credential-like query parameter '{}' is not allowed; Vultrino injects provider credentials", key),
            );
        }
        if let Ok(mut parsed) = url::Url::parse(&upstream) {
            {
                let mut pairs = parsed.query_pairs_mut();
                for (key, value) in &query {
                    pairs.append_pair(key, value);
                }
            }
            upstream = parsed.to_string();
        }
    }

    // 4. Parse the agent's request body as JSON (OpenAI-compatible). An empty body
    //    is allowed (some endpoints take none); a non-JSON body is rejected so we
    //    never forward garbage upstream with the vault key attached.
    let mut request_body: Option<serde_json::Value> = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => Some(v),
            Err(e) => {
                return llm_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("Request body must be valid JSON: {e}"),
                )
            }
        }
    };

    // 4b. Per-model enforcement (connector P1-1): when the capability restricts
    //     models (non-empty allowed_models), the request body's `model` must be in
    //     the allowlist. An EMPTY allowlist permits any model (per-provider scope
    //     only). An allowlisted channel whose request carries NO parseable `model`
    //     fails CLOSED (default-deny symmetry) — we never forward an unverifiable
    //     model upstream with the vault key attached. This is the PEP for govder's
    //     `llm.allowed_models`; the deny happens BEFORE any upstream call. It runs
    //     ABOVE the streaming decision (4d) so a `stream:true` request can NOT evade
    //     the model allowlist — buffered and streaming enforce identically.
    // The body's model is checked here only where the body picks the model. Where the
    // resolved upstream URL selects it (Gemini, Vertex, Bedrock, Azure) the body names none
    // or an ignored one, and the allowlist is applied to the routed model below.
    let requested_model = request_body
        .as_ref()
        .and_then(|b| b.get("model"))
        .and_then(|m| m.as_str());
    let url_picks_model = request_body.is_some()
        && matches!(
            url_model(
                &llm.protocol,
                &upstream,
                requested_model,
                &state.config.llm_proxy.azure_deployments,
            ),
            UrlModel::Names { .. }
        );
    if !url_picks_model && !capability.llm_model_allowed(requested_model) {
        return llm_error(
            StatusCode::FORBIDDEN,
            "permission_error",
            &format!(
                "Model {} is not permitted for this LLM-proxy capability",
                requested_model
                    .map(|m| format!("'{m}'"))
                    .unwrap_or_else(|| "(unspecified)".to_string()),
            ),
        );
    }

    // 4b-bis. Priced models only (`[llm_proxy] require_priced_model`, default on). A model
    //     the rate card does not price books $0 in the metering plane (its token event is
    //     rejected as unpriced), so a budget cap would never trip for it: refuse it here,
    //     BEFORE any upstream call, exactly where the allowlist above refuses. Fail closed
    //     both ways: a request that carries a body but names no model cannot be shown to be
    //     priced, and with no card configured nothing is. A bodiless request (a model list,
    //     a health probe) is not a billed call and is not gated.
    //
    //     WHICH model: the one the resolved upstream URL selects where the URL picks it
    //     (Gemini/Vertex `models/<id>`, Bedrock `model/<id>`, Azure `deployments/<name>`
    //     through the operator's map; see `url_model`), else the body's. The upstream
    //     ignores a body `model` that disagrees with its URL, so a body model that differs
    //     from the URL's is refused, and the allowlist, the gate and the meter all use the
    //     routed model. Without this an agent could name a priced model in the body and
    //     reach an unpriced one through the path.
    let body_model = request_body
        .as_ref()
        .and_then(|b| b.get("model"))
        .and_then(|m| m.as_str());
    let route = if request_body.is_some() {
        url_model(
            &llm.protocol,
            &upstream,
            body_model,
            &state.config.llm_proxy.azure_deployments,
        )
    } else {
        UrlModel::BodyPicks
    };
    let (gated_model, route_refusal): (Option<String>, Option<String>) = match &route {
        UrlModel::BodyPicks => (body_model.map(str::to_string), None),
        UrlModel::Names { model, body_ok } => (
            Some(model.clone()),
            body_model
                .filter(|b| *b != model && Some(*b) != body_ok.as_deref())
                .map(|b| {
                    format!("the body names model '{b}' but the upstream URL selects '{model}'")
                }),
        ),
        UrlModel::Unresolvable(why) => (body_model.map(str::to_string), Some(why.clone())),
    };
    // The allowlist applies to the model the URL selects too, not only the body's.
    // Azure: the operator may list the deployment name (what the caller sends) or the model it
    // maps to.
    if let UrlModel::Names { model, body_ok } = &route {
        if !capability.llm_model_allowed(Some(model))
            && !body_ok
                .as_deref()
                .is_some_and(|d| capability.llm_model_allowed(Some(d)))
        {
            return llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!("Model '{model}' is not permitted for this LLM-proxy capability"),
            );
        }
    }
    if state.config.llm_proxy.require_priced_model && request_body.is_some() {
        let priced = route_refusal.is_none()
            && gated_model
                .as_deref()
                .is_some_and(|m| state.config.llm_proxy.rate_card.covers(m));
        if !priced {
            tracing::warn!(
                model = gated_model.as_deref().unwrap_or("(unspecified)"),
                card_configured = state.config.llm_proxy.rate_card.is_configured(),
                route_refusal = route_refusal.as_deref().unwrap_or(""),
                "LLM request refused: model is not priced by the rate card"
            );
            return llm_error(
                StatusCode::FORBIDDEN,
                "model_unpriced",
                &format!(
                    "Model {} is not priced by the rate card, so its spend could not be metered against a budget; the request was not sent{}",
                    gated_model
                        .as_deref()
                        .map(|m| format!("'{m}'"))
                        .unwrap_or_else(|| "(unspecified)".to_string()),
                    route_refusal
                        .as_deref()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default(),
                ),
            );
        }
        // The card prices tokens at one input and one output price per model. A request
        // field that raises the provider's price beyond that would be booked too low.
        let unpriced = request_body
            .as_ref()
            .and_then(|b| unpriced_modifier(&llm.protocol, &upstream, b))
            .or_else(|| unpriced_beta_header(&headers));
        if let Some(found) = unpriced {
            tracing::warn!(found = %found, "LLM request refused: it sets a price modifier the rate card does not hold");
            return llm_error(
                StatusCode::FORBIDDEN,
                "modifier_unpriced",
                &format!(
                    "The request sets a price modifier the rate card does not hold, so its spend could not be metered against a budget; the request was not sent ({found})"
                ),
            );
        }
    }

    // 4c. Per-call output-token ceiling (rate_companion per-call leg, P1-8): clamp the
    //     request body's `max_tokens` to the capability's ceiling — `min(requested,
    //     ceiling)`, and SET it to the ceiling when the request omits it so the
    //     provider default can't exceed it. This bounds per-call output tokens (hence
    //     per-call cost), the enforceable substitute for a SpendCap (which fails closed
    //     on an LLM request that carries no request-time spend). Only the common
    //     OpenAI-compatible `max_tokens` field is handled in v1. Runs ABOVE the
    //     streaming decision (4d) + usage injection, so it clamps the body BOTH the
    //     buffered and streaming paths forward — `stream:true` can NOT evade the cap.
    if let Some(ceiling) = capability.llm_max_output_tokens() {
        if let Some(body) = request_body.as_mut() {
            let default_field = default_output_token_field(&llm.protocol, &upstream);
            clamp_max_output_tokens(body, ceiling, default_field);
        }
    }

    // 4c-bis. Gateway-owned reasoning effort: when the capability declares
    //     `llm.reasoning_effort`, SET the provider's reasoning-effort field on the
    //     request, overwriting whatever the agent sent. Reasoning tokens bill as
    //     output tokens, so the effort is a spend control owned by the gateway,
    //     exactly like the 4c ceiling and the forced `include_usage` below. It is
    //     also a hard compatibility requirement on some models (OpenAI refuses
    //     function tools on Chat Completions for gpt-5.6-luna above `none`). Runs
    //     ABOVE the streaming decision (4d) so `stream:true` cannot evade it.
    //     Unconfigured = the body is untouched, byte for byte.
    if let Some(effort) = capability.llm_reasoning_effort() {
        if let Some(shape) = reasoning_effort_shape(&llm.protocol, &upstream) {
            if let Some(body) = request_body.as_mut() {
                apply_reasoning_effort(body, effort, shape);
            }
        }
    }

    // 4d. Decide buffered vs streaming. Streaming engages purely on the wire flag
    //     `{"stream": true}` and the operator kill-switch. When streaming is
    //     DISABLED but the client asked for it, strip the stream flags so the
    //     upstream returns a single JSON body served on the buffered path — never a
    //     buffered `text/event-stream` blob, which would break the client's SSE
    //     parser. Runs AFTER 4b/4c so the model allowlist + max_output_tokens clamp
    //     already applied to the body that the streaming path forwards.
    let streaming_requested = request_body
        .as_ref()
        .and_then(|b| b.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    let streaming_enabled = state.config.llm_proxy.streaming_enabled;
    let use_streaming = streaming_requested && streaming_enabled;
    if streaming_requested && !streaming_enabled {
        if let Some(obj) = request_body.as_mut().and_then(|b| b.as_object_mut()) {
            obj.remove("stream");
            obj.remove("stream_options");
        }
    }
    // NVIDIA hangs when `stream_options` accompanies a non-empty OpenAI `tools` array.
    // Normalize only that known-incompatible provider shape, including a client-supplied
    // stream_options. NVIDIA cannot send a usage trailer with tools, so that stream is
    // charged an ESTIMATE (`dims.estimated = "true"`, VUL-01) rather than exact counts.
    // Other providers' tool streams (and NVIDIA streams without tools) retain the trailer.
    let nvidia_tool_stream = use_streaming
        && request_body
            .as_mut()
            .is_some_and(|body| normalize_nvidia_tool_stream_options(&provider, body));

    // When streaming an OpenAI-chat request, force `stream_options.include_usage = true`
    // so the provider emits a terminal usage chunk and a streamed turn still meters V13b
    // token counts. include_usage is GATEWAY-OWNED — a client cannot opt out of the token
    // trailer (sending `include_usage:false` would otherwise evade token metering), so
    // maybe_inject_stream_usage overwrites a client false. Anthropic `/v1/messages` and
    // OpenAI `/v1/responses` report usage natively, so they are excluded (an unknown
    // `stream_options` field could be rejected).
    if use_streaming
        && state.config.llm_proxy.inject_stream_usage
        && is_openai_chat_endpoint(&upstream)
        && !nvidia_tool_stream
    {
        if let Some(b) = request_body.as_mut() {
            crate::outbox::maybe_inject_stream_usage(b);
        }
    }

    // Forward Content-Type plus a curated ALLOWLIST of provider protocol headers
    // (e.g. Anthropic's REQUIRED `anthropic-version`). The credential
    // (Authorization / API-key header) is injected by the http plugin from the
    // vault. The agent's own Authorization header is the vultrino Bearer — it must
    // NOT be forwarded upstream — so we copy only the named protocol headers and
    // never a blanket set. See [`forward_provider_headers`].
    let mut fwd_headers: HashMap<String, String> = HashMap::new();
    fwd_headers.insert("Content-Type".to_string(), "application/json".to_string());
    forward_provider_headers(&headers, &mut fwd_headers);

    // 5. Drive the action through the SAME enforced path the named tools use. The
    //    capability's action label (V8) is enforced + resolved by execute_gated;
    //    the http plugin injects the vault credential, scrubs the response, and
    //    run_action emits the V13a/V13b meter events from the RAW provider body.
    let execute_request = ExecuteRequest {
        credential: capability.credential_ref.clone(),
        action: capability.action.clone(),
        params: serde_json::json!({
            "method": "POST",
            "url": upstream,
            "headers": fwd_headers,
            "body": request_body,
            "query": {},
            "_feir_provider": provider,
            "_feir_region": region,
            "_feir_channel": channel_name,
            "_feir_request_model": gated_model,
        }),
    };

    // 6. Streaming path: forward the upstream SSE body incrementally. The gate is
    //    identical to the buffered path; only the response body delivery differs.
    if use_streaming {
        return match state
            .server
            .execute_gated_streaming_llm_channel(execute_request, exec_auth)
            .await
        {
            Ok(crate::server::StreamingOutcome::Streaming(exec)) => {
                let status = StatusCode::from_u16(exec.status).unwrap_or(StatusCode::BAD_GATEWAY);
                // Preserve the provider Content-Type (e.g. text/event-stream) so the
                // client's SSE parser engages; default to event-stream for a streamed
                // turn that didn't echo one.
                let content_type = exec
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "text/event-stream".to_string());
                (
                    status,
                    [(header::CONTENT_TYPE, content_type)],
                    axum::body::Body::from_stream(exec.body),
                )
                    .into_response()
            }
            Ok(crate::server::StreamingOutcome::Pending(approval)) => llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                &format!(
                    "This model request requires human approval and did not run (approval {})",
                    approval.id
                ),
            ),
            // A policy/rate/budget denial is a 403 authorization decision, not an upstream outage.
            Err(crate::VultrinoError::PolicyDenied(reason)) => {
                // The reason stays server-side (operator log + the detect event); the agent-facing
                // body below is deliberately detail-free.
                tracing::info!(reason = %reason, "LLM proxy stream request denied by policy");
                llm_error(
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    "This model request was denied by policy",
                )
            }
            Err(crate::VultrinoError::Plugin(crate::plugins::PluginError::CredentialConfig(
                reason,
            ))) => {
                tracing::error!(reason = %reason, "LLM proxy credential misconfigured; refused before upstream");
                llm_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    &format!(
                        "LLM proxy credential is misconfigured (invalid {}); \
                         the request was refused and nothing was sent upstream",
                        misconfigured_key(&reason)
                    ),
                )
            }
            Err(e) => {
                // Same no-leak posture as the buffered Err path: the scrub hasn't run
                // on a pre-stream Err, so never echo the upstream detail to the agent.
                tracing::warn!(error = %e, "LLM proxy upstream stream failed");
                llm_error(
                    StatusCode::BAD_GATEWAY,
                    "api_error",
                    "LLM proxy upstream request failed (see server logs)",
                )
            }
        };
    }

    match state
        .server
        .execute_gated_llm_channel(execute_request, exec_auth)
        .await
    {
        Ok(ExecutionOutcome::Completed(response)) => {
            // Return the provider body + status verbatim (post egress-scrub, so no
            // model key ever reflects back). Preserve the provider Content-Type so
            // the harness's OpenAI client parses it correctly.
            let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "application/json".to_string());
            (
                status,
                [(header::CONTENT_TYPE, content_type)],
                response.body,
            )
                .into_response()
        }
        // An LLM call should never be approval-gated in practice, but if a policy
        // routes it to approval, surface that honestly rather than silently
        // dropping the turn.
        Ok(ExecutionOutcome::Pending(approval)) => llm_error(
            StatusCode::FORBIDDEN,
            "permission_error",
            &format!(
                "This model request requires human approval and did not run (approval {})",
                approval.id
            ),
        ),
        // A policy/rate/budget DENIAL is an authorization decision, not an upstream outage — surface it
        // as 403 (matching the explicit 403s above), detail-free, so operators don't read denials as
        // provider flakiness. The server-side detect-event + counters still fire.
        Err(crate::VultrinoError::PolicyDenied(reason)) => {
            tracing::info!(reason = %reason, "LLM proxy request denied by policy");
            llm_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                "This model request was denied by policy",
            )
        }
        Err(crate::VultrinoError::Plugin(crate::plugins::PluginError::CredentialConfig(
            reason,
        ))) => {
            tracing::error!(reason = %reason, "LLM proxy credential misconfigured; refused before upstream");
            llm_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                &format!(
                    "LLM proxy credential is misconfigured (invalid {}); \
                     the request was refused and nothing was sent upstream",
                    misconfigured_key(&reason)
                ),
            )
        }
        Err(e) => {
            // Do NOT echo the upstream error detail to the agent: on a plugin Err
            // the egress scrub (which runs on the Ok path) has NOT run, so a
            // secret-bearing upstream body (e.g. an OAuth token-endpoint error that
            // echoes the token) could leak through `{e}`. Log the detail
            // server-side; return a generic message. (GLM review #6.)
            tracing::warn!(error = %e, "LLM proxy upstream request failed");
            llm_error(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "LLM proxy upstream request failed (see server logs)",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_reasoning_effort, clamp_max_output_tokens, default_output_token_field,
        is_openai_chat_endpoint, normalize_nvidia_tool_stream_options, provider_feature_enabled,
        reasoning_effort_shape, unpriced_modifier, url_model, ReasoningEffortShape, UrlModel,
    };
    use serde_json::json;
    use std::sync::Mutex;

    /// Serialises the two tests that touch VULTRINO_PROVIDER_NVIDIA_ENABLED.
    ///
    /// Both of their comments claimed to use "a switch no other test touches", and both were
    /// WRONG about each other: `nvidia_gate_is_independent_of_openai` set_var's that key while
    /// `provider_gate_fails_closed_for_unmapped_protocols` asserts the same key is unset. The
    /// process environment is global and cargo runs these on parallel threads, so the reader
    /// failed whenever it sampled inside the writer's set/remove window.
    ///
    /// This is NOT new code (the pair predates plan 103's integration: both are present at
    /// `d62f718` lines 664/679/682, and the writer arrived in `907e4f7`). It became VISIBLE at
    /// merge time because the merged lib carries more tests, which changes the scheduler's timing
    /// and widens the window: measured 2 failures in 5 runs on the merged tree against 0 in 6 on
    /// the pre-merge tree. A latent race that only some builds lose is worse than a loud one, so
    /// it is closed here rather than left to reappear as an unexplained red.
    ///
    /// A mutex rather than dropping the assertion: "an unset NVIDIA switch denies" is a real
    /// fail-closed property and deleting it to dodge the race would trade a flake for a hole.
    /// Same shape as tests/workload_exchange_integration.rs's ENV_LOCK.
    static PROVIDER_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn provider_gate_fails_closed_for_unmapped_protocols() {
        let _guard = PROVIDER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // No VULTRINO_PROVIDER_* switch maps these, so they must be DENIED even though
        // "observed-only" passes capability validation.
        assert!(!provider_feature_enabled("observed-only"));
        assert!(!provider_feature_enabled("openai_chat")); // typo'd / unknown
        assert!(!provider_feature_enabled(""));
        // A mapped protocol whose switch is unset is also denied (default-deny).
        assert!(!provider_feature_enabled("vertex-ai"));
        // nvidia is a real, separately-gated provider: unset => denied (does NOT ride
        // the generic OpenAI switch). Held under PROVIDER_ENV_LOCK because
        // nvidia_gate_is_independent_of_openai sets this very switch.
        assert!(!provider_feature_enabled("nvidia"));
    }

    #[test]
    fn nvidia_gate_is_independent_of_openai() {
        let _guard = PROVIDER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Enabling NVIDIA must not require (or imply) the generic OpenAI provider, and
        // vice-versa.
        std::env::set_var("VULTRINO_PROVIDER_NVIDIA_ENABLED", "1");
        assert!(provider_feature_enabled("nvidia"));
        // openai-chat stays denied unless ITS own switch is set.
        assert!(!provider_feature_enabled("openai-chat"));
        // Restored before the lock drops, so the reader above never observes it set.
        std::env::remove_var("VULTRINO_PROVIDER_NVIDIA_ENABLED");
    }

    #[test]
    fn clamps_an_over_ceiling_request_down() {
        let mut body = json!({ "model": "gpt-4o", "max_tokens": 5000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(1000));
    }

    #[test]
    fn clamps_alternate_output_token_fields() {
        // The ceiling must not be evadable by naming an alternate output-token field.
        // max_completion_tokens (newer OpenAI chat):
        let mut body = json!({ "model": "gpt-5", "max_completion_tokens": 9000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_completion_tokens"], json!(1000));
        assert!(
            body.get("max_tokens").is_none(),
            "don't inject max_tokens when another field was chosen"
        );
        // max_output_tokens (OpenAI /v1/responses):
        let mut body = json!({ "model": "o3", "max_output_tokens": 9000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_output_tokens"], json!(1000));
        assert!(body.get("max_tokens").is_none());
        // All present → all clamped.
        let mut body =
            json!({ "max_tokens": 9000, "max_completion_tokens": 8000, "max_output_tokens": 7000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(1000));
        assert_eq!(body["max_completion_tokens"], json!(1000));
        assert_eq!(body["max_output_tokens"], json!(1000));
    }

    #[test]
    fn clamp_pins_output_multiplicity_to_one() {
        // n / best_of multiply TOTAL output tokens, so under a configured ceiling they must
        // be pinned to 1 (else max_tokens:1000,n:10 produces ~10x the per-call bound).
        let mut body = json!({ "max_tokens": 1000, "n": 10 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["n"], json!(1), "n>1 evades the per-call ceiling");
        let mut body = json!({ "max_tokens": 1000, "best_of": 8 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["best_of"], json!(1));
        // Non-numeric multiplicity fails closed to 1.
        let mut body = json!({ "max_tokens": 1000, "n": "lots" });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["n"], json!(1));
        // n:1 is left as-is; absent n is not injected.
        let mut body = json!({ "max_tokens": 1000, "n": 1 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["n"], json!(1));
        let mut body = json!({ "max_tokens": 1000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert!(
            body.get("n").is_none(),
            "don't inject n when the request didn't ask for choices"
        );
    }

    #[test]
    fn clamp_divides_ceiling_by_legacy_prompt_array_count() {
        // Legacy /v1/completions returns one completion per prompt, so a prompt ARRAY
        // multiplies total output. The per-prompt budget must be divided by the count so
        // count * per_prompt <= ceiling.
        let mut body = json!({ "prompt": ["a", "b", "c", "d"], "max_tokens": 1000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(
            body["max_tokens"],
            json!(250),
            "1000 / 4 prompts = 250 per prompt"
        );
        // A scalar prompt is one unit (full ceiling).
        let mut body = json!({ "prompt": "just one", "max_tokens": 5000 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(1000));
        // Absent max_tokens with a prompt array → set to the divided per-prompt budget.
        let mut body = json!({ "prompt": ["a", "b"] });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(500));
    }

    #[test]
    fn chat_endpoint_detected_from_resolved_upstream_url() {
        // A bare POST /llm has an empty inbound path; the gate must key on the RESOLVED
        // upstream URL so include_usage injection still applies when provider_base IS the
        // chat-completions endpoint.
        assert!(is_openai_chat_endpoint(
            "https://api.openai.com/v1/chat/completions"
        ));
        assert!(is_openai_chat_endpoint(
            "https://api.openai.com/v1/completions"
        )); // legacy
        assert!(is_openai_chat_endpoint(
            "https://api.openai.com/v1/chat/completions?x=1"
        ));
        assert!(is_openai_chat_endpoint(
            "https://api.openai.com/v1/chat/completions/"
        ));
        // Native-usage endpoints must NOT match (they'd reject stream_options).
        assert!(!is_openai_chat_endpoint(
            "https://api.openai.com/v1/responses"
        ));
        assert!(!is_openai_chat_endpoint(
            "https://api.anthropic.com/v1/messages"
        ));
    }

    #[test]
    fn nvidia_tool_stream_normalization_is_provider_specific() {
        let tools = json!([{
            "type": "function",
            "function": { "name": "lookup", "parameters": { "type": "object" } }
        }]);

        // NVIDIA tool streams must not receive stream_options, including a value supplied
        // by the client: NVIDIA otherwise hangs before emitting any SSE response.
        let mut nvidia_tools = json!({
            "stream": true,
            "tools": tools,
            "stream_options": { "include_usage": true }
        });
        assert!(normalize_nvidia_tool_stream_options(
            "nvidia",
            &mut nvidia_tools
        ));
        assert!(nvidia_tools.get("stream_options").is_none());

        // NVIDIA streams without tools retain the gateway token trailer.
        let mut nvidia_no_tools = json!({ "stream": true });
        assert!(!normalize_nvidia_tool_stream_options(
            "nvidia",
            &mut nvidia_no_tools
        ));
        assert!(crate::outbox::maybe_inject_stream_usage(
            &mut nvidia_no_tools
        ));
        assert_eq!(nvidia_no_tools["stream_options"]["include_usage"], true);

        // Other OpenAI-compatible providers retain token trailers for tool streams.
        let mut openai_tools = json!({ "stream": true, "tools": tools });
        assert!(!normalize_nvidia_tool_stream_options(
            "openai-chat",
            &mut openai_tools
        ));
        assert!(crate::outbox::maybe_inject_stream_usage(&mut openai_tools));
        assert_eq!(openai_tools["stream_options"]["include_usage"], true);
    }

    #[test]
    fn leaves_an_under_ceiling_request_unchanged() {
        let mut body = json!({ "model": "gpt-4o", "max_tokens": 200 });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(200));
    }

    #[test]
    fn sets_the_ceiling_when_the_request_omits_max_tokens() {
        // The dangerous case: an absent max_tokens lets the provider default (often
        // very large) blow the per-call cost bound. We must SET it to the ceiling.
        let mut body = json!({ "model": "gpt-4o", "messages": [] });
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body["max_tokens"], json!(1000));
    }

    #[test]
    fn ignores_a_non_object_body() {
        let mut body = json!("not an object");
        clamp_max_output_tokens(&mut body, 1000, "max_tokens");
        assert_eq!(body, json!("not an object"));
    }

    #[test]
    fn responses_traffic_defaults_to_max_output_tokens_field() {
        // Protocol is authoritative.
        assert_eq!(
            default_output_token_field("openai-responses", "https://api.openai.com/v1/responses"),
            "max_output_tokens"
        );
        // Path-suffix fallback catches a Responses upstream even if `protocol` were ever
        // something other than the exact "openai-responses" string.
        assert_eq!(
            default_output_token_field("openai-chat", "https://api.openai.com/v1/responses"),
            "max_output_tokens"
        );
        // OpenAI's own chat/completions takes max_completion_tokens: its current models
        // reject max_tokens outright.
        assert_eq!(
            default_output_token_field("openai-chat", "https://api.openai.com/v1/chat/completions"),
            "max_completion_tokens"
        );
        assert_eq!(
            default_output_token_field(
                "openai-chat",
                "https://API.OpenAI.com/v1/chat/completions/"
            ),
            "max_completion_tokens"
        );
        // An OpenAI-compatible third party under the same protocol keeps max_tokens, and a
        // look-alike host or an unparseable upstream is not OpenAI.
        for upstream in [
            "https://llm.example.test/v1/chat/completions",
            "https://api.openai.com.evil.test/v1/chat/completions",
            "https://evil.test/api.openai.com/v1/chat/completions",
            "not a url/chat/completions",
        ] {
            assert_eq!(
                default_output_token_field("openai-chat", upstream),
                "max_tokens"
            );
        }
        // Other protocols pointed at the same host are unaffected.
        assert_eq!(
            default_output_token_field("nvidia", "https://api.openai.com/v1/chat/completions"),
            "max_tokens"
        );
        assert_eq!(
            default_output_token_field(
                "anthropic-messages",
                "https://api.anthropic.com/v1/messages"
            ),
            "max_tokens"
        );
    }

    #[test]
    fn sets_max_output_tokens_for_a_responses_body_that_omits_an_output_limit() {
        // The Codex-harness defect this test locks down: a Responses-shaped request
        // (no max_tokens/max_completion_tokens/max_output_tokens) routed to /v1/responses
        // must get `max_output_tokens` set to the ceiling, NOT `max_tokens` (which the
        // Responses API does not read, so the per-call ceiling would silently not apply).
        let mut body = json!({ "model": "gpt-5-codex", "input": "hi" });
        let field =
            default_output_token_field("openai-responses", "https://api.openai.com/v1/responses");
        clamp_max_output_tokens(&mut body, 1000, field);
        assert_eq!(body["max_output_tokens"], json!(1000));
        assert!(
            body.get("max_tokens").is_none(),
            "must not inject max_tokens for Responses traffic"
        );
    }

    #[test]
    fn clamps_a_present_over_ceiling_max_output_tokens_on_responses_traffic() {
        let mut body = json!({ "model": "gpt-5-codex", "input": "hi", "max_output_tokens": 9000 });
        let field =
            default_output_token_field("openai-responses", "https://api.openai.com/v1/responses");
        clamp_max_output_tokens(&mut body, 1000, field);
        assert_eq!(body["max_output_tokens"], json!(1000));
        assert!(body.get("max_tokens").is_none());
    }

    // ---- Gateway-owned reasoning effort ----

    const CHAT_UPSTREAM: &str = "https://api.openai.com/v1/chat/completions";
    const RESPONSES_UPSTREAM: &str = "https://api.openai.com/v1/responses";

    #[test]
    fn reasoning_effort_shape_keys_on_path_then_protocol() {
        assert_eq!(
            reasoning_effort_shape("openai-chat", CHAT_UPSTREAM),
            Some(ReasoningEffortShape::ChatTopLevel)
        );
        assert_eq!(
            reasoning_effort_shape("openai-responses", RESPONSES_UPSTREAM),
            Some(ReasoningEffortShape::ResponsesNested)
        );
        // The resolved PATH wins over the protocol label: a channel labeled
        // openai-chat whose provider_base IS the Responses endpoint must still be
        // written the Responses way, or the effort would be an ignored stray field.
        assert_eq!(
            reasoning_effort_shape("openai-chat", RESPONSES_UPSTREAM),
            Some(ReasoningEffortShape::ResponsesNested)
        );
        // Bare `POST /llm`: empty inbound path, so the protocol decides.
        assert_eq!(
            reasoning_effort_shape("openai-chat", "https://api.openai.com"),
            Some(ReasoningEffortShape::ChatTopLevel)
        );
        // Query strings and trailing slashes do not defeat the suffix match.
        assert_eq!(
            reasoning_effort_shape(
                "nvidia",
                "https://integrate.api.nvidia.com/v1/chat/completions?x=1"
            ),
            Some(ReasoningEffortShape::ChatTopLevel)
        );
        // A protocol with no reasoning field on the wire and no OpenAI-shaped path.
        assert_eq!(
            reasoning_effort_shape(
                "anthropic-messages",
                "https://api.anthropic.com/v1/messages"
            ),
            None
        );
    }

    #[test]
    fn inserts_reasoning_effort_on_a_chat_body_that_omits_it() {
        let mut body = json!({ "model": "gpt-5.6-luna", "messages": [] });
        apply_reasoning_effort(&mut body, "none", ReasoningEffortShape::ChatTopLevel);
        assert_eq!(body["reasoning_effort"], json!("none"));
        // Nothing else is disturbed.
        assert_eq!(body["model"], json!("gpt-5.6-luna"));
    }

    #[test]
    fn overwrites_a_client_supplied_chat_reasoning_effort_of_any_type() {
        // Gateway-owned: the agent can neither raise nor lower it, and a non-string
        // value is replaced rather than left to reach the provider.
        for supplied in [
            json!("high"),
            json!(3),
            json!(null),
            json!({"effort": "high"}),
        ] {
            let mut body = json!({ "model": "gpt-5.6-luna", "reasoning_effort": supplied });
            apply_reasoning_effort(&mut body, "none", ReasoningEffortShape::ChatTopLevel);
            assert_eq!(body["reasoning_effort"], json!("none"));
        }
    }

    #[test]
    fn sets_nested_reasoning_effort_on_a_responses_body() {
        // Absent `reasoning` → created as an object carrying only `effort`.
        let mut body = json!({ "model": "gpt-5-codex", "input": "hi" });
        apply_reasoning_effort(&mut body, "low", ReasoningEffortShape::ResponsesNested);
        assert_eq!(body["reasoning"], json!({"effort": "low"}));

        // An existing `reasoning` OBJECT keeps its other keys; only `effort` moves.
        let mut body = json!({
            "model": "gpt-5-codex",
            "reasoning": { "effort": "high", "summary": "auto" }
        });
        apply_reasoning_effort(&mut body, "minimal", ReasoningEffortShape::ResponsesNested);
        assert_eq!(body["reasoning"]["effort"], json!("minimal"));
        assert_eq!(body["reasoning"]["summary"], json!("auto"));

        // A `reasoning` that is NOT an object is replaced outright (fail closed:
        // the gateway value must land, never be dropped because the agent sent junk).
        for junk in [json!("high"), json!(7), json!(null), json!(["high"])] {
            let mut body = json!({ "model": "gpt-5-codex", "reasoning": junk });
            apply_reasoning_effort(&mut body, "medium", ReasoningEffortShape::ResponsesNested);
            assert_eq!(body["reasoning"], json!({"effort": "medium"}));
        }
    }

    #[test]
    fn reasoning_effort_leaves_a_non_object_body_untouched() {
        for mut body in [json!("a string body"), json!([1, 2, 3]), json!(null)] {
            let before = body.clone();
            apply_reasoning_effort(&mut body, "none", ReasoningEffortShape::ChatTopLevel);
            apply_reasoning_effort(&mut body, "none", ReasoningEffortShape::ResponsesNested);
            assert_eq!(body, before);
        }
    }

    #[test]
    fn an_unconfigured_channel_leaves_the_body_byte_for_byte() {
        // The proxy only calls apply_reasoning_effort under a configured value; this
        // locks the contract that an absent capability field adds no field at all.
        use crate::capability::{Capability, CapabilityTarget, LlmProxy};
        let cap = Capability {
            id: "cap-x".into(),
            tool_name: "model_proxy".into(),
            description: String::new(),
            action: "http.request".into(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: "cred-openai".into(),
            input_schema: json!({}),
            reversibility: "reversible".into(),
            llm: Some(LlmProxy {
                provider_base: "https://api.openai.com".into(),
                ..Default::default()
            }),
            approval_preview: None,
        };
        assert_eq!(cap.llm_reasoning_effort(), None);
    }

    #[test]
    fn validation_rejects_bad_efforts_and_wrong_protocols() {
        use crate::capability::{Capability, CapabilityTarget, LlmProxy};
        let build = |protocol: &str, effort: Option<&str>, base: &str| Capability {
            id: "cap-x".into(),
            tool_name: "model_proxy".into(),
            description: String::new(),
            action: "http.request".into(),
            plugin: None,
            target: CapabilityTarget::default(),
            credential_ref: "cred-openai".into(),
            input_schema: json!({}),
            reversibility: "reversible".into(),
            llm: Some(LlmProxy {
                protocol: protocol.into(),
                provider_base: base.into(),
                reasoning_effort: effort.map(str::to_string),
                ..Default::default()
            }),
            approval_preview: None,
        };
        // Every allowed value passes on both OpenAI wire families.
        for effort in ["none", "minimal", "low", "medium", "high"] {
            for protocol in ["openai-chat", "openai-responses"] {
                assert!(
                    build(protocol, Some(effort), "https://api.openai.com")
                        .validate()
                        .is_ok(),
                    "{protocol} + {effort} must validate"
                );
            }
        }
        // Unknown / mis-cased / empty values fail closed.
        for bad in ["", "None", "HIGH", "maximum", "medium ", "off"] {
            assert!(
                build("openai-chat", Some(bad), "https://api.openai.com")
                    .validate()
                    .is_err(),
                "reasoning_effort {bad:?} must be rejected"
            );
        }
        // A protocol with no reasoning field on the wire is a configuration error,
        // never a silently ignored field.
        for protocol in ["nvidia", "anthropic-messages", "observed-only", "gemini"] {
            let base = if protocol == "nvidia" {
                "https://integrate.api.nvidia.com"
            } else {
                "https://api.example.com"
            };
            assert!(
                build(protocol, Some("none"), base).validate().is_err(),
                "reasoning_effort on {protocol} must be rejected"
            );
            // ...but the same capability WITHOUT the field is still fine.
            assert!(build(protocol, None, base).validate().is_ok());
        }
    }

    // ---- feir-ops#6 review round 1: the routed model and price modifiers -----------------

    fn names(model: &str) -> UrlModel {
        UrlModel::Names {
            model: model.to_string(),
            body_ok: None,
        }
    }

    fn no_map() -> std::collections::HashMap<String, String> {
        Default::default()
    }

    #[test]
    fn gemini_and_vertex_take_the_model_from_the_url_not_the_body() {
        let g =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-9-pro:generateContent";
        // The body names a different model: the URL's is the routed one.
        assert_eq!(
            url_model("gemini", g, Some("claude-haiku-4-5"), &no_map()),
            names("gemini-9-pro")
        );
        let v = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/publishers/anthropic/models/claude-opus-5:rawPredict";
        assert_eq!(
            url_model("vertex-ai", v, None, &no_map()),
            names("claude-opus-5")
        );
        // A model baked into provider_base (no method suffix) is the same segment.
        let baked = "https://generativelanguage.googleapis.com/v1beta/models/gemini-9-pro/x";
        assert_eq!(
            url_model("gemini", baked, None, &no_map()),
            names("gemini-9-pro")
        );
        // Two model segments, or a dangling one, are ambiguous: refused, not guessed.
        let two = "https://h.example/v1/models/a/models/b:generateContent";
        assert!(matches!(
            url_model("gemini", two, None, &no_map()),
            UrlModel::Unresolvable(_)
        ));
        let dangling = "https://h.example/v1/models";
        assert!(matches!(
            url_model("gemini", dangling, None, &no_map()),
            UrlModel::Unresolvable(_)
        ));
        // No models segment: only the OpenAI-compatible endpoint takes the body's model.
        let compat = "https://h.example/v1beta/openai/chat/completions";
        assert_eq!(
            url_model("gemini", compat, Some("m"), &no_map()),
            UrlModel::BodyPicks
        );
        let tuned = "https://h.example/v1/endpoints/123:predict";
        assert!(matches!(
            url_model("vertex-ai", tuned, Some("m"), &no_map()),
            UrlModel::Unresolvable(_)
        ));
    }

    #[test]
    fn bedrock_takes_the_percent_decoded_model_from_the_model_segment() {
        let base = "https://bedrock-runtime.us-east-1.amazonaws.com";
        for proto in ["bedrock-converse", "bedrock-invoke"] {
            assert_eq!(
                url_model(
                    proto,
                    &format!("{base}/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse"),
                    None,
                    &no_map()
                ),
                names("anthropic.claude-3-haiku-20240307-v1:0")
            );
        }
        // A literal colon (also legal in a path) is not a method separator here.
        assert_eq!(
            url_model(
                "bedrock-invoke",
                &format!("{base}/model/anthropic.claude-3-haiku-20240307-v1:0/invoke"),
                None,
                &no_map()
            ),
            names("anthropic.claude-3-haiku-20240307-v1:0")
        );
        // An inference-profile id with an encoded slash stays one segment.
        assert_eq!(
            url_model(
                "bedrock-converse",
                &format!("{base}/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A1%3Ainference-profile%2Fp/converse"),
                None,
                &no_map()
            ),
            names("arn:aws:bedrock:us-east-1:1:inference-profile/p")
        );
        // No model segment, or an empty one: refused, even with a body model.
        for url in [
            format!("{base}/foundation-models"),
            format!("{base}/model//converse"),
        ] {
            assert!(
                matches!(
                    url_model("bedrock-converse", &url, Some("anything"), &no_map()),
                    UrlModel::Unresolvable(_)
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn azure_names_a_deployment_that_only_the_operators_map_can_price() {
        let map: std::collections::HashMap<String, String> =
            [("prod-4o".to_string(), "gpt-4o".to_string())].into();
        let base = "https://acme.openai.azure.com/openai";
        assert_eq!(
            url_model(
                "azure-openai",
                &format!("{base}/deployments/prod-4o/chat/completions"),
                None,
                &map
            ),
            UrlModel::Names {
                model: "gpt-4o".to_string(),
                body_ok: Some("prod-4o".to_string())
            }
        );
        // An unmapped deployment cannot be priced.
        assert!(matches!(
            url_model(
                "azure-openai",
                &format!("{base}/deployments/other/chat/completions"),
                None,
                &map
            ),
            UrlModel::Unresolvable(_)
        ));
        // The v1 API has no deployment segment: the body's model is the deployment name.
        assert_eq!(
            url_model(
                "azure-openai",
                &format!("{base}/v1/chat/completions"),
                Some("prod-4o"),
                &map
            ),
            UrlModel::Names {
                model: "gpt-4o".to_string(),
                body_ok: Some("prod-4o".to_string())
            }
        );
        assert!(matches!(
            url_model(
                "azure-openai",
                &format!("{base}/v1/chat/completions"),
                None,
                &map
            ),
            UrlModel::Unresolvable(_)
        ));
        // With no map nothing is priced.
        assert!(matches!(
            url_model(
                "azure-openai",
                &format!("{base}/deployments/prod-4o/chat/completions"),
                None,
                &no_map()
            ),
            UrlModel::Unresolvable(_)
        ));
    }

    #[test]
    fn body_routed_protocols_use_the_body_model() {
        for proto in [
            "openai-chat",
            "openai-responses",
            "anthropic-messages",
            "nvidia",
        ] {
            assert_eq!(
                url_model(
                    proto,
                    "https://api.example/v1/messages",
                    Some("m"),
                    &no_map()
                ),
                UrlModel::BodyPicks
            );
        }
    }

    const ANTHROPIC: &str = "anthropic-messages";

    fn refused(protocol: &str, upstream: &str, body: serde_json::Value) {
        assert!(
            unpriced_modifier(protocol, upstream, &body).is_some(),
            "{protocol} {body}"
        );
    }

    fn passes(protocol: &str, upstream: &str, body: serde_json::Value) {
        assert_eq!(
            unpriced_modifier(protocol, upstream, &body),
            None,
            "{protocol} {body}"
        );
    }

    #[test]
    fn an_unlisted_top_level_field_is_refused_on_every_protocol() {
        // Default-deny: a field nobody priced is refused, whatever it is called.
        let anthropic = [
            json!({"compaction": {"type": "compact_20260112"}}),
            json!({"context_management": {"edits": [{"type": "compact_20260112"}]}}),
            json!({"fallbacks": [{"model": "m"}]}),
            json!({"fallback_credit_token": "t"}),
            json!({"speed": "fast"}),
            json!({"speed": "standard"}),
            json!({"inference_geo": "global"}),
            json!({"inference_geo": "us"}),
            json!({"service_tier": "auto"}),
            json!({"service_tier": "priority"}),
            json!({"serviceTier": "default"}),
            json!({"ServiceTier": "priority"}),
            json!({"SERVICE_TIER": "priority"}),
            json!({"a_field_added_next_year": 1}),
            json!({"container": "c"}),
            json!({"mcp_servers": []}),
            json!({"output_config": {"format": {}}}),
        ];
        for body in anthropic {
            refused(ANTHROPIC, "https://api.anthropic.com/v1/messages", body);
        }
        for body in [
            json!({"service_tier": "default"}),
            json!({"web_search_options": {}}),
            json!({"modalities": ["audio"]}),
            json!({"audio": {}}),
            json!({"compaction": {}}),
            json!({"context_management": []}),
            json!({"unknown": 1}),
        ] {
            refused(
                "openai-chat",
                "https://api.openai.com/v1/chat/completions",
                body.clone(),
            );
            refused(
                "nvidia",
                "https://integrate.api.nvidia.com/v1/chat/completions",
                body,
            );
        }
        for body in [
            json!({"service_tier": "flex"}),
            json!({"background": true}),
            json!({"prompt": {"id": "p"}}),
            json!({"unknown": 1}),
        ] {
            refused(
                "openai-responses",
                "https://api.openai.com/v1/responses",
                body,
            );
        }
        for body in [
            json!({"serviceTier": "priority"}),
            json!({"service_tier": "flex"}),
            json!({"serviceTier": {"type": "priority"}}),
            json!({"performanceConfig": {"latency": "optimized"}}),
            json!({"guardrailConfig": {}}),
            json!({"additionalModelRequestFields": {"anthropic_beta": ["x"]}}),
            json!({"unknown": 1}),
        ] {
            refused("bedrock-converse", "https://b/model/m/converse", body);
        }
        for body in [
            json!({"serviceTier": "priority"}),
            json!({"service_tier": "priority"}),
            json!({"ServiceTier": "priority"}),
            json!({"unknown": 1}),
        ] {
            refused(
                "gemini",
                "https://g/v1beta/models/m:generateContent",
                body.clone(),
            );
            refused(
                "vertex-ai",
                "https://v/v1/projects/p/models/m:generateContent",
                body,
            );
        }
        refused(
            "azure-openai",
            "https://a/openai/deployments/d/chat/completions",
            json!({"data_sources": []}),
        );
        // A protocol the table does not know admits no field at all.
        refused("observed-only", "https://x", json!({"messages": []}));
        // A body that is not an object has no field to price.
        refused(ANTHROPIC, "https://x", json!([1]));
    }

    #[test]
    fn a_plain_priced_request_passes_on_every_protocol() {
        passes(
            ANTHROPIC,
            "https://api.anthropic.com/v1/messages",
            json!({"model": "m", "max_tokens": 5, "messages": [], "system": "s", "temperature": 0.1,
                "top_p": 1, "top_k": 3, "stop_sequences": ["x"], "stream": true,
                "metadata": {"user_id": "u"}, "thinking": {"type": "enabled", "budget_tokens": 2048},
                "tool_choice": {"type": "auto"},
                "tools": [{"name": "get_weather", "description": "d", "input_schema": {"type": "object"}}]}),
        );
        passes(
            "openai-chat",
            "https://api.openai.com/v1/chat/completions",
            json!({"model": "m", "messages": [], "max_tokens": 5, "temperature": 0.2, "stream": true,
                "stream_options": {"include_usage": true}, "tool_choice": "auto",
                "tools": [{"type": "function", "function": {"name": "f", "parameters": {}}}],
                "reasoning_effort": "low", "user": "u"}),
        );
        passes(
            "openai-responses",
            "https://api.openai.com/v1/responses",
            json!({"model": "m", "input": "hi", "instructions": "i", "max_output_tokens": 5,
                "reasoning": {"effort": "low"}, "store": false,
                "tools": [{"type": "function", "name": "f", "parameters": {}}]}),
        );
        passes(
            "gemini",
            "https://g/v1beta/models/m:generateContent",
            json!({"contents": [], "systemInstruction": {}, "generationConfig": {}, "safetySettings": [],
                "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
                "tools": [{"functionDeclarations": [{"name": "f", "parameters": {}}]}]}),
        );
        // The OpenAI-compatible endpoint takes the chat body.
        passes(
            "gemini",
            "https://g/v1beta/openai/chat/completions",
            json!({"model": "m", "messages": []}),
        );
        passes(
            "vertex-ai",
            "https://v/v1/projects/p/locations/l/publishers/anthropic/models/m:rawPredict",
            json!({"anthropic_version": "vertex-2023-10-16", "anthropic_beta": ["prompt-caching-2024-07-31"],
                "messages": [], "max_tokens": 5}),
        );
        passes(
            "bedrock-converse",
            "https://b/model/m/converse",
            json!({"messages": [], "system": [], "inferenceConfig": {"maxTokens": 5},
                "toolConfig": {"tools": [{"toolSpec": {"name": "f", "inputSchema": {"json": {}}}}, {"cachePoint": {"type": "default"}}],
                    "toolChoice": {"auto": {}}}}),
        );
        passes(
            "bedrock-invoke",
            "https://b/model/m/invoke",
            json!({"anthropic_version": "bedrock-2023-05-31", "messages": [], "max_tokens": 5}),
        );
        passes(
            "azure-openai",
            "https://a/openai/deployments/d/chat/completions",
            json!({"messages": [], "tools": [{"type": "function", "function": {"name": "f"}}]}),
        );
    }

    #[test]
    fn only_plain_client_tools_pass_and_the_shape_is_exact() {
        // Server tools, a typed tool nobody listed, and an untyped object with a foreign key.
        for tools in [
            json!([{"type": "web_search_20250305", "name": "web_search"}]),
            json!([{"type": "web_fetch_20250910", "name": "web_fetch"}]),
            json!([{"type": "tool_search_tool_regex_20251119", "name": "t"}]),
            json!([{"type": "code_execution_20250522", "name": "code_execution"}]),
            json!([{"type": "bash_code_execution_20250825", "name": "bash_code_execution"}]),
            json!([{"type": "text_editor_code_execution_20250825", "name": "x"}]),
            json!([{"type": "advisor_20260301", "name": "advisor", "model": "m"}]),
            json!([{"type": "quantum_lookup_20271201", "name": "q"}]),
            json!([{"type": "bash_20991231", "name": "bash"}]),
            json!([{"name": "f", "input_schema": {}, "server_side": true}]),
            json!([{"name": "f", "input_schema": {}, "max_uses": 5}]),
            json!([{"name": "f"}]),
            json!([{"type": "custom", "name": "c", "input_schema": {}, "allowed_callers": ["x"]}]),
            json!([{"future_server_tool": {}}]),
            json!([{}]),
            json!(["web_search"]),
            json!({"type": "web_search"}),
            json!([{"name": "f", "input_schema": {}}, {"type": "memory_20250818"}]),
        ] {
            refused(ANTHROPIC, "https://x", json!({"tools": tools}));
        }
        for tools in [
            json!([{"type": "web_search_preview"}]),
            json!([{"type": "file_search"}]),
            json!([{"type": "function", "function": {"name": "f"}, "extra": 1}]),
            json!([{"type": "function", "function": {"name": "f", "web": true}}]),
            json!([{"type": "function"}]),
            json!([{"function": {"name": "f"}}]),
            json!([{"name": "f", "input_schema": {}}]),
        ] {
            refused(
                "openai-chat",
                "https://api.openai.com/v1/chat/completions",
                json!({"tools": tools}),
            );
        }
        refused(
            "openai-responses",
            "https://api.openai.com/v1/responses",
            json!({"tools": [{"type": "function", "name": "f", "vector_store_ids": ["v"]}]}),
        );
        for tools in [
            json!([{"google_search": {}}]),
            json!([{"googleSearchRetrieval": {}}]),
            json!([{"urlContext": {}}]),
            json!([{"retrieval": {"vertexAiSearch": {"datastore": "d"}}}]),
            json!([{"enterpriseWebSearch": {}}]),
            json!([{"functionDeclarations": [], "googleSearch": {}}]),
            json!([{"functionDeclarations": [{"name": "f", "grounding": true}]}]),
        ] {
            refused(
                "gemini",
                "https://g/v1beta/models/m:generateContent",
                json!({"tools": tools}),
            );
        }
        for tool_config in [
            json!({"tools": [{"systemTool": {"name": "nova_grounding"}}]}),
            json!({"tools": [{"toolSpec": {"name": "f"}, "systemTool": {"name": "x"}}]}),
            json!({"tools": [{"toolSpec": {"name": "f", "extra": 1}}]}),
            json!({"tools": [{"toolSpec": {"name": "f"}}], "extra": 1}),
            json!({"tools": [{}]}),
            json!({"tools": "x"}),
        ] {
            refused(
                "bedrock-converse",
                "https://b/model/m/converse",
                json!({"toolConfig": tool_config}),
            );
        }
        // Gemini's toolConfig is an object of the function-calling settings only.
        refused(
            "gemini",
            "https://g/v1beta/models/m:generateContent",
            json!({"toolConfig": {"x": 1}}),
        );
        refused(
            "gemini",
            "https://g/v1beta/models/m:generateContent",
            json!({"toolConfig": 1}),
        );
        // Anthropic client tools by their exact versioned type.
        for t in [
            "bash_20250124",
            "text_editor_20250728",
            "memory_20250818",
            "computer_20251124",
        ] {
            passes(
                ANTHROPIC,
                "https://x",
                json!({"tools": [{"type": t, "name": "n"}]}),
            );
        }
        passes(
            ANTHROPIC,
            "https://x",
            json!({"tools": [{"type": "custom", "name": "c", "input_schema": {}, "cache_control": {"type": "ephemeral"}}]}),
        );
    }

    #[test]
    fn an_anthropic_beta_in_the_body_must_be_on_the_allowlist() {
        let up = "https://v/v1/projects/p/publishers/anthropic/models/m:rawPredict";
        for beta in [
            json!(["compact-2026-01-12"]),
            json!(["prompt-caching-2024-07-31", "fast-mode-2026-02-01"]),
            json!("context-1m-2025-08-07"),
            json!([1]),
            json!({"a": 1}),
        ] {
            refused(
                "vertex-ai",
                up,
                json!({"anthropic_beta": beta, "messages": []}),
            );
        }
        refused(
            "bedrock-invoke",
            "https://b/model/m/invoke",
            json!({"anthropic_beta": ["context-management-2025-06-27"]}),
        );
        passes(
            "bedrock-invoke",
            "https://b/model/m/invoke",
            json!({"anthropic_beta": ["interleaved-thinking-2025-05-14"]}),
        );
    }

    #[test]
    fn the_anthropic_beta_header_is_forwarded_only_for_priced_betas() {
        use super::unpriced_beta_header;
        use axum::http::{HeaderMap, HeaderValue};
        let h = |v: &[&str]| {
            let mut m = HeaderMap::new();
            for x in v {
                m.append("anthropic-beta", HeaderValue::from_str(x).unwrap());
            }
            m
        };
        assert_eq!(unpriced_beta_header(&HeaderMap::new()), None);
        assert_eq!(
            unpriced_beta_header(&h(&["prompt-caching-2024-07-31"])),
            None
        );
        assert_eq!(
            unpriced_beta_header(&h(&[
                "prompt-caching-2024-07-31, interleaved-thinking-2025-05-14"
            ])),
            None
        );
        for bad in [
            "compact-2026-01-12",
            "fast-mode-2026-02-01",
            "context-1m-2025-08-07",
            "prompt-caching-2024-07-31,compact-2026-01-12",
            "something-new-2027-01-01",
            "Prompt-Caching-2024-07-31",
        ] {
            assert!(unpriced_beta_header(&h(&[bad])).is_some(), "{bad}");
        }
        // A second header line is read too.
        assert!(
            unpriced_beta_header(&h(&["prompt-caching-2024-07-31", "compact-2026-01-12"]))
                .is_some()
        );
    }
}
