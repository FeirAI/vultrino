//! Govder decide-plane HTTP client (plan 031 D3/D4).
//!
//! Vultrino consults govder as the system-of-record for DelegationGrant scope and
//! delegate verdict evaluation. Every call is authenticated with a short-lived
//! `X-Govder-Tenant-Assertion` HMAC matching `govder/pkg/tenantassert`.

mod tenant_assert;

use crate::delegation::{DelegateEvalResult, DelegationGrantScope};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use url::Url;

pub use tenant_assert::{
    sign_tenant_assertion, verify_tenant_assertion, TenantAssertionError,
};

/// Configuration for outbound govder delegation calls.
#[derive(Clone)]
pub struct GovderConfig {
    pub base_url: String,
    pub assertion_secret: String,
    pub assertion_ttl: Duration,
    pub http_timeout: Duration,
}

impl std::fmt::Debug for GovderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovderConfig")
            .field("base_url", &self.base_url)
            .field("assertion_secret", &"<redacted>")
            .field("assertion_ttl", &self.assertion_ttl)
            .field("http_timeout", &self.http_timeout)
            .finish()
    }
}

impl GovderConfig {
    /// Load from `GOVDER_BASE_URL` + `GOVDER_TENANT_ASSERTION_SECRET`.
    /// Both must be non-empty for delegate enforcement to be active.
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("GOVDER_BASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let secret = std::env::var("GOVDER_TENANT_ASSERTION_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let ttl_secs = std::env::var("GOVDER_ASSERTION_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &u64| n > 0)
            .unwrap_or(90);
        Some(Self {
            base_url: base.trim_end_matches('/').to_string(),
            assertion_secret: secret,
            assertion_ttl: Duration::from_secs(ttl_secs),
            http_timeout: Duration::from_secs(30),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.base_url.is_empty() && !self.assertion_secret.is_empty()
    }
}

#[derive(Error, Debug)]
pub enum GovderError {
    #[error("govder request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid govder URL: {0}")]
    BadUrl(String),
    #[error("govder returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("govder response decode failed: {0}")]
    Decode(String),
    #[error("{0}")]
    Policy(String),
}

/// Live DelegationGrant row from govder SoR.
#[derive(Debug, Clone, Deserialize)]
pub struct DelegationGrant {
    pub grant_id: String,
    pub tenant_id: String,
    pub delegate_agent_id: String,
    /// Canonical enforcement principal (ep_…) bound to vap_ tokens.
    #[serde(default)]
    pub delegate_agent_ep: Option<String>,
    pub scope: GovderGrantScope,
    pub revoked: bool,
    #[serde(default)]
    pub expiry: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GovderGrantScope {
    #[serde(default)]
    pub action_classes: Vec<String>,
    #[serde(default)]
    pub max_risk_tier: String,
}

impl From<&GovderGrantScope> for DelegationGrantScope {
    fn from(s: &GovderGrantScope) -> Self {
        DelegationGrantScope {
            max_risk_tier: if s.max_risk_tier.trim().is_empty() {
                "Low".to_string()
            } else {
                s.max_risk_tier.clone()
            },
            action_classes: s.action_classes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvaluateInput<'a> {
    pub tenant: &'a str,
    pub decision_id: &'a str,
    pub grant_id: &'a str,
    pub delegate_agent_id: &'a str,
    pub requester_agent_id: &'a str,
    pub action_class: &'a str,
    pub risk_tier: &'a str,
    pub irreversible: bool,
    pub approve: bool,
    pub spend_amount_minor: Option<i64>,
    pub spend_asset: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
struct EvaluateResponse {
    permitted: bool,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    veto_window_secs: u64,
}

/// Wire shape of `GET /v1/oversight/gates/rule` (plan 100 P2 Phase D). `has_rule` is
/// the unambiguous signal of rule presence — `approval_rule` is `None` whenever
/// `has_rule` is `false`, mirroring govder's `GateApprovalRuleResponse`.
///
/// `has_rule` is a REQUIRED field (no `#[serde(default)]`): a 2xx body that OMITS it
/// is semantically malformed and must fail the fetch closed rather than silently
/// decode as `has_rule: false` and downgrade to the weaker numeric-threshold path
/// (Codex P2 review BLOCKER 6). `fetch_gate_rule` additionally rejects any body whose
/// `has_rule`/`approval_rule` pair is internally inconsistent.
///
/// `risk_tier` and `irreversible` are govder's AUTHORITATIVE risk facts for this
/// action (BLOCKER 5): vultrino stamps them alongside the rule so the recipe
/// deny-wins force uses govder's judgement rather than vultrino's LOCAL criticality.
/// `risk_tier == ""` means govder could not resolve it — the consumer treats that as
/// the fail-closed worst case (Extreme).
///
/// Both `risk_tier` and `irreversible` are REQUIRED whenever `has_rule:true` (Codex P2
/// RE-REVIEW RE-BLOCKER 2). They are modelled as `Option` here ONLY so their ABSENCE is
/// distinguishable from a present-but-empty/false value: `interpret_2xx_gate_rule_body`
/// rejects a `has_rule:true` body that omits EITHER (missing → Decode error → fail
/// closed, exactly like `has_rule`). Without this, a `has_rule:true` response that OMITS
/// `irreversible` would decode as `false` and an authoritatively-irreversible gate would
/// silently lose its forced deny-on-any-deny (fail-OPEN). `risk_tier: ""` is a VALID
/// present value (govder emits it for unresolved agents → Extreme); only true absence of
/// the field errors.
#[derive(Debug, Clone, Deserialize)]
struct GateApprovalRuleResponse {
    has_rule: bool,
    #[serde(default)]
    approval_rule: Option<crate::approval::ApprovalRule>,
    #[serde(default)]
    risk_tier: Option<String>,
    #[serde(default)]
    irreversible: Option<bool>,
}

/// A fetched, PRESENT approval rule plus govder's AUTHORITATIVE risk facts for it
/// (Codex P2 review BLOCKER 5). Only produced when `has_rule: true`. The recipe
/// deny-wins force in [`crate::approval::ApprovalRequest::transition`] uses
/// `risk_tier`/`irreversible` from here rather than vultrino's LOCAL criticality —
/// closing the Go/Rust divergence where a majority-mode deny became non-terminal
/// because vultrino locally classified an authoritatively-Extreme action as Medium.
/// `risk_tier == ""` (govder could not resolve) is carried verbatim; the consumer
/// treats it as Extreme (fail-closed).
#[derive(Debug, Clone)]
pub struct FetchedGateRule {
    pub rule: crate::approval::ApprovalRule,
    pub risk_tier: String,
    pub irreversible: bool,
}

/// Wire shape of the 404 body of `GET /v1/oversight/gates/rule` (govder's
/// `GateApprovalRuleAbsence`, plan 103 §10h FINDING 1/2). Every field is optional
/// because an OLDER govder answers a bare `{"error": …}` — and the whole point of this
/// type is that such a body is NOT a confirmed absence.
#[derive(Debug, Clone, Default, Deserialize)]
struct GateApprovalRuleAbsence {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    gate_store_durable: Option<bool>,
}

/// govder's reason code for "this known agent has no gate bound to this action class".
/// The ONLY absence that can be definitive, and only when the gate store is durable.
const GATE_ABSENCE_NO_GATE_FOR_ACTION_CLASS: &str = "no_gate_for_action_class";

/// The three ANSWERS a gate-rule lookup can produce (plan 103 §10h FINDING 1/2).
///
/// This type exists because the previous two-state result (`Option<FetchedGateRule>`)
/// could not express the state that actually mattered. `None` meant "govder CONFIRMED
/// there is no rule", and a 404 was mapped to it — but govder's 404 also covered "I
/// cannot resolve that identity at all", which is what the FINDING 1 key-axis mismatch
/// produced on every single money call. So an UNANSWERED question was recorded as an
/// answered one, vultrino fell back to its numeric threshold, and an irreversible refund
/// that the operator had gated at two distinct humans executed on ONE approval.
///
/// The distinction is not cosmetic: `NoRule` is a licence to use the weaker numeric
/// path, and only govder can grant it.
#[derive(Debug, Clone)]
pub enum GateRuleAnswer {
    /// govder returned a stamped rule plus its authoritative risk facts.
    Rule(FetchedGateRule),
    /// govder CONFIRMED there is no recipe for this (agent, action_class): either a gate
    /// exists with no rule (`has_rule:false`), or no gate exists for an agent govder
    /// knows AND govder's gate store is durable (so the absence cannot be a loss).
    /// The numeric-threshold path is correct here.
    ///
    /// EVERY `NoRule` is spoken by govder. There is no way to reach this variant without
    /// an answer from the decide plane — in particular, a deployment that wires NO govder
    /// does not produce it (that used to be listed here as a third case, and it was the
    /// last fail-open: silence from an authority you never contacted is not that
    /// authority saying "nothing"). See `ServerState::fetch_gate_rule_for_action`.
    NoRule,
    /// govder did NOT confirm anything: it could not resolve the identity under the key
    /// it was given, its gate store is volatile so an absent gate may be a dropped one,
    /// it answered a 404 with no reason code at all (an older govder — an unqualified
    /// 404, which is precisely the ambiguity the reason code removes), or this deployment
    /// wires no govder at all, so nothing was ever asked.
    ///
    /// This remains a data result rather than a transport error so the caller can apply
    /// deployment posture. Production strict mode fails closed for every action;
    /// compatibility posture retains the historical reversible numeric fallback, while
    /// an irreversible/human-floor action always refuses — see `VultrinoServer::execute_gated`.
    Inconclusive { reason: String },
}

/// HTTP client for govder delegation endpoints.
#[derive(Clone)]
pub struct GovderClient {
    cfg: GovderConfig,
    base: Url,
    host: String,
    http: Client,
}

impl GovderClient {
    pub fn new(cfg: GovderConfig) -> Result<Self, GovderError> {
        let base = Url::parse(&cfg.base_url)
            .map_err(|e| GovderError::BadUrl(format!("{}: {e}", cfg.base_url)))?;
        let host = base
            .host_str()
            .map(|h| {
                if let Some(port) = base.port() {
                    format!("{h}:{port}")
                } else {
                    h.to_string()
                }
            })
            .ok_or_else(|| GovderError::BadUrl("missing host".to_string()))?;
        let http = Client::builder().timeout(cfg.http_timeout).build()?;
        Ok(Self {
            cfg,
            base,
            host,
            http,
        })
    }

    /// Fetch an active grant by id; fail-closed on missing/revoked/scope mismatch.
    pub async fn lookup_grant(
        &self,
        tenant: &str,
        grant_id: &str,
        delegate_agent_id: Option<&str>,
    ) -> Result<(DelegationGrant, DelegationGrantScope), GovderError> {
        let grants = self.list_grants(tenant).await?;
        let grant = grants
            .into_iter()
            .find(|g| g.grant_id == grant_id)
            .ok_or_else(|| {
                GovderError::Policy(format!(
                    "delegation: grant {grant_id:?} not found in govder (fail-closed)"
                ))
            })?;
        if grant.tenant_id != tenant {
            return Err(GovderError::Policy(format!(
                "delegation: grant {grant_id} tenant {:?} does not match requested tenant {tenant:?} (fail-closed)",
                grant.tenant_id
            )));
        }
        if grant.revoked {
            return Err(GovderError::Policy(format!(
                "delegation: grant {grant_id} is revoked (fail-closed)"
            )));
        }
        if let Some(expiry) = grant.expiry.as_deref() {
            if !expiry.trim().is_empty() {
                if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expiry) {
                    if exp < chrono::Utc::now() {
                        return Err(GovderError::Policy(format!(
                            "delegation: grant {grant_id} is expired (fail-closed)"
                        )));
                    }
                }
            }
        }
        if let Some(delegate) = delegate_agent_id {
            if !delegate.trim().is_empty() && !delegate_matches_grant(&grant, delegate) {
                return Err(GovderError::Policy(format!(
                    "delegation: grant delegate {:?} does not match requested delegate {delegate} (fail-closed)",
                    grant_canonical_delegate(&grant)
                )));
            }
        }
        let scope = DelegationGrantScope::from(&grant.scope);
        scope.validate().map_err(|e| {
            GovderError::Policy(format!("delegation: invalid grant scope from govder: {e}"))
        })?;
        Ok((grant, scope))
    }

    pub async fn list_grants(&self, tenant: &str) -> Result<Vec<DelegationGrant>, GovderError> {
        let path = "/v1/delegation/grants";
        let resp = self.signed_json(tenant, "GET", path, "", None).await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(GovderError::Http { status, body });
        }
        let parsed: GrantsListResponse =
            serde_json::from_str(&body).map_err(|e| GovderError::Decode(e.to_string()))?;
        Ok(parsed.grants)
    }

    /// Consult govder evaluate-decision (D3 floors + oversight gate).
    pub async fn evaluate_delegate_decision(
        &self,
        input: EvaluateInput<'_>,
    ) -> Result<DelegateEvalResult, GovderError> {
        let body = EvaluateRequest {
            decision_id: input.decision_id.to_string(),
            grant_id: input.grant_id.to_string(),
            delegate_agent_id: input.delegate_agent_id.to_string(),
            requester_agent_id: input.requester_agent_id.to_string(),
            action_class: input.action_class.to_string(),
            risk_tier: input.risk_tier.to_string(),
            irreversible: input.irreversible,
            approve: input.approve,
            spend_amount_minor: input.spend_amount_minor,
            spend_asset: input.spend_asset.map(str::to_string),
        };
        let bytes = serde_json::to_vec(&body).map_err(|e| GovderError::Decode(e.to_string()))?;
        let resp = self
            .signed_json(
                input.tenant,
                "POST",
                "/v1/delegation/evaluate-decision",
                "",
                Some(&bytes),
            )
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        if !(200..300).contains(&status) {
            return Err(GovderError::Http { status, body: text });
        }
        let out: EvaluateResponse =
            serde_json::from_str(&text).map_err(|e| GovderError::Decode(e.to_string()))?;
        Ok(DelegateEvalResult {
            permitted: out.permitted,
            reason: if out.reason.is_empty() {
                if out.permitted {
                    "delegate approved within grant caps".to_string()
                } else {
                    "delegate verdict denied".to_string()
                }
            } else {
                out.reason
            },
            veto_window_secs: out.veto_window_secs,
        })
    }

    /// Fetch the stamped `ApprovalRule` (if any) for `(agent_id, action_class)` at
    /// approval-open (plan 100 P2 Phase D; docs/design/approval-recipes.md §6 D5).
    /// `GET /v1/oversight/gates/rule` — a 2xx body with `has_rule: false` (gate exists,
    /// no rule) is a CONFIRMED `NoRule` → today's numeric-threshold path, unchanged.
    ///
    /// A **404 is NOT automatically a confirmed absence** (plan 103 §10h FINDING 1/2 —
    /// it used to be, and that is what let one approver clear an irreversible refund).
    /// It is `NoRule` only when govder says BOTH that the agent is known to it and that
    /// its gate store is durable (`reason: "no_gate_for_action_class"`,
    /// `gate_store_durable: true`). Any other 404 — an unresolvable identity, a volatile
    /// gate store that may have dropped the recipe, or no reason code at all — is
    /// `Inconclusive`: govder answered, but confirmed nothing.
    ///
    /// Any GENUINE fetch failure — a transport/`signed_json` error, a non-2xx
    /// status other than 404 (5xx etc.), a body-read error, or a JSON parse
    /// error — returns `Err` instead. Unlike the stale contract this replaced,
    /// such a failure must NOT be treated as "no rule": vultrino never confirmed
    /// the gate's oversight requirement, so silently falling back to the (weaker)
    /// numeric-threshold path would let a transient govder blip downgrade a
    /// recipe-gated approval (e.g. "1 senior + 2 agent-reviewers") to a plain
    /// headcount. This now matches [`Self::evaluate_delegate_decision`]'s
    /// fail-closed posture: both are per-open/per-decision AUTHORITY checks with
    /// no safe fallback on a failure vultrino cannot confirm.
    pub async fn fetch_gate_rule(
        &self,
        tenant: &str,
        agent_id: &str,
        action_class: &str,
    ) -> Result<GateRuleAnswer, GovderError> {
        let agent_id = agent_id.trim();
        let action_class = action_class.trim();
        if tenant.trim().is_empty() || agent_id.is_empty() || action_class.is_empty() {
            // There is no identity to query govder WITH, so govder confirmed nothing —
            // and this client only exists because a govder IS wired. Calling that a
            // confirmed absence is the same fail-open as the old bare-404 mapping, one
            // layer up: an unnameable principal executing an irreversible action would
            // silently take the numeric path (plan 103 §10h FINDING 1).
            return Ok(GateRuleAnswer::Inconclusive {
                reason: "the request carries no tenant/agent label/action class to identify the \
                         agent to the policy engine, so no oversight requirement could be \
                         confirmed"
                    .to_string(),
            });
        }
        let query = format!(
            "agent_id={}&action_class={}",
            urlencoding::encode(agent_id),
            urlencoding::encode(action_class)
        );
        let resp = self
            .signed_json(tenant, "GET", "/v1/oversight/gates/rule", &query, None)
            .await
            .map_err(|error| {
                tracing::error!(%error, %agent_id, %action_class,
                    "govder gate-rule fetch failed; failing closed (blocking the approval-open) rather than falling back to the numeric-threshold path");
                error
            })?;
        let status = resp.status().as_u16();
        if status == 404 {
            // Read the body BEFORE deciding: the discriminator lives in it. A body-read
            // failure here is a genuine fetch failure (below), never a silent absence.
            let body = resp.text().await.map_err(|error| {
                tracing::error!(%error, %agent_id, %action_class,
                    "govder gate-rule 404 body could not be read; failing closed");
                GovderError::Request(error)
            })?;
            return Ok(interpret_404_gate_rule_body(&body, agent_id, action_class));
        }
        let body = resp.text().await.map_err(|error| {
            tracing::error!(%error, %agent_id, %action_class,
                "govder gate-rule response body could not be read; failing closed");
            GovderError::Request(error)
        })?;
        if !(200..300).contains(&status) {
            tracing::error!(status, %agent_id, %action_class, body,
                "govder gate-rule fetch returned a non-2xx status; failing closed");
            return Err(GovderError::Http { status, body });
        }
        // Parse + consistency-check the 2xx body (BLOCKER 6). A missing `has_rule`, or
        // an internally-inconsistent has_rule/approval_rule pair, is a genuine fetch
        // failure → fail closed, NEVER a numeric fallback. Only a clean `has_rule:
        // false` (no rule) maps to `Ok(None)` numeric parity.
        interpret_2xx_gate_rule_body(&body).map_err(|error| {
            tracing::error!(%error, %agent_id, %action_class,
                "govder gate-rule 2xx response is malformed or internally inconsistent (missing has_rule, or a has_rule/approval_rule contradiction); failing closed");
            error
        })
    }

    async fn signed_json(
        &self,
        tenant: &str,
        method: &str,
        path: &str,
        query: &str,
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response, GovderError> {
        let url = self
            .base
            .join(path.trim_start_matches('/'))
            .map_err(|e| GovderError::BadUrl(e.to_string()))?;
        let mut url = url;
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        let exp = chrono::Utc::now()
            + chrono::Duration::from_std(self.cfg.assertion_ttl)
                .unwrap_or(chrono::Duration::seconds(90));
        let assertion = sign_tenant_assertion(
            &self.cfg.assertion_secret,
            tenant,
            method,
            path,
            query,
            &self.host,
            body.unwrap_or_default(),
            exp,
        );
        let mut req = self.http.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
            url,
        );
        req = req.header("X-Govder-Tenant-Assertion", assertion);
        if let Some(b) = body {
            req = req
                .header("Content-Type", "application/json")
                .body(b.to_vec());
        }
        Ok(req.send().await?)
    }
}

/// Interpret a 2xx `GET /v1/oversight/gates/rule` body (Codex P2 review BLOCKER 6).
/// Pure (no I/O) so the fail-closed contract is unit-testable:
///
/// - a body that fails to parse — including one MISSING the required `has_rule` field
///   (an HTTP-200 `{}`) — is a genuine fetch failure (`Err(Decode)`), never a numeric
///   fallback;
/// - a body whose `has_rule`/`approval_rule` pair is INTERNALLY INCONSISTENT
///   (`has_rule:true` with no rule, or `has_rule:false` WITH a rule present) is
///   likewise `Err(Decode)`;
/// - a `has_rule:true` body that OMITS either authoritative risk fact — `risk_tier` or
///   `irreversible` — is `Err(Decode)` and fails closed (Codex P2 RE-REVIEW RE-BLOCKER
///   2). A missing `irreversible` must NEVER stamp `false` (that would drop the forced
///   deny-on-any-deny on an irreversible gate); a missing `risk_tier` must NEVER be
///   confused with the resolved-but-empty `""` sentinel. Both must be PRESENT on the
///   wire when a rule is present;
/// - only a clean `has_rule:false` (no rule) → `Ok(GateRuleAnswer::NoRule)` (confirmed no
///   rule → numeric parity);
/// - `has_rule:true` with a rule (and BOTH risk facts present) →
///   `Ok(GateRuleAnswer::Rule(..))`, carrying govder's authoritative
///   `risk_tier`/`irreversible`.
fn interpret_2xx_gate_rule_body(body: &str) -> Result<GateRuleAnswer, GovderError> {
    let parsed: GateApprovalRuleResponse =
        serde_json::from_str(body).map_err(|e| GovderError::Decode(e.to_string()))?;
    let GateApprovalRuleResponse {
        has_rule,
        approval_rule,
        risk_tier,
        irreversible,
    } = parsed;
    match (has_rule, approval_rule) {
        (false, None) => Ok(GateRuleAnswer::NoRule),
        (false, Some(_)) => Err(GovderError::Decode(
            "gate-rule response inconsistent: has_rule=false but approval_rule present".to_string(),
        )),
        (true, None) => Err(GovderError::Decode(
            "gate-rule response inconsistent: has_rule=true but approval_rule missing".to_string(),
        )),
        (true, Some(rule)) => {
            // RE-BLOCKER 2: a rule-present response MUST carry BOTH authoritative risk
            // facts. Their ABSENCE (not a present `""`/`false`) fails the fetch closed,
            // exactly like a missing `has_rule` — never a silent downgrade.
            let risk_tier = risk_tier.ok_or_else(|| {
                GovderError::Decode(
                    "gate-rule response inconsistent: has_rule=true but risk_tier missing \
                     (fail-closed — required authoritative risk fact)"
                        .to_string(),
                )
            })?;
            let irreversible = irreversible.ok_or_else(|| {
                GovderError::Decode(
                    "gate-rule response inconsistent: has_rule=true but irreversible missing \
                     (fail-closed — required authoritative risk fact)"
                        .to_string(),
                )
            })?;
            Ok(GateRuleAnswer::Rule(FetchedGateRule {
                rule,
                risk_tier,
                irreversible,
            }))
        }
    }
}

/// Classify a 404 gate-rule body into `NoRule` (confirmed) or `Inconclusive` (plan 103
/// §10h FINDING 1/2).
///
/// A 404 is DEFINITIVE only when govder asserts BOTH halves of the claim:
///
/// - `reason: "no_gate_for_action_class"` — it holds an agent record under this exact
///   key, so the key axis is right and the absence is a real, authored absence; and
/// - `gate_store_durable: true` — a gate it once held could not have vanished, so an
///   absence is evidence that none was ever configured.
///
/// Everything else is inconclusive, INCLUDING an unparseable or reason-less body. That
/// last case is the old behaviour's entire failure: an unqualified 404 was read as a
/// confirmation. It is deliberately NOT a `GovderError` — govder answered the call, and
/// the caller must apply the deployment posture: production strict refuses it for every
/// action; compatibility posture may retain the reversible numeric path but never the
/// human-floor path.
fn interpret_404_gate_rule_body(body: &str, agent_id: &str, action_class: &str) -> GateRuleAnswer {
    let parsed: GateApprovalRuleAbsence = serde_json::from_str(body).unwrap_or_default();
    let reason = parsed.reason.unwrap_or_default();
    let durable = parsed.gate_store_durable.unwrap_or(false);
    if reason == GATE_ABSENCE_NO_GATE_FOR_ACTION_CLASS && durable {
        return GateRuleAnswer::NoRule;
    }
    let detail = if reason.is_empty() {
        "the policy engine reported no gate but gave no machine-readable reason (an older \
         build), so an absent gate cannot be distinguished from an unresolvable agent id"
            .to_string()
    } else if reason == GATE_ABSENCE_NO_GATE_FOR_ACTION_CLASS {
        "the policy engine reports no gate for this action class, but its gate store is \
         VOLATILE — an absent gate is indistinguishable from an approval recipe dropped by a \
         restart"
            .to_string()
    } else {
        format!(
            "the policy engine could not confirm an oversight requirement for this agent \
             (reason: {reason})"
        )
    };
    tracing::warn!(%agent_id, %action_class, %reason, durable,
        "govder gate-rule 404 is INCONCLUSIVE, not a confirmed absence of a recipe");
    GateRuleAnswer::Inconclusive { reason: detail }
}

fn grant_canonical_delegate(grant: &DelegationGrant) -> String {
    grant
        .delegate_agent_ep
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(grant.delegate_agent_id.as_str())
        .to_string()
}

fn delegate_matches_grant(grant: &DelegationGrant, delegate: &str) -> bool {
    let d = delegate.trim();
    if d.is_empty() {
        return false;
    }
    if d == grant.delegate_agent_id.trim() {
        return true;
    }
    grant
        .delegate_agent_ep
        .as_deref()
        .map(|ep| d == ep.trim())
        .unwrap_or(false)
}

#[derive(Serialize)]
struct EvaluateRequest {
    decision_id: String,
    grant_id: String,
    delegate_agent_id: String,
    requester_agent_id: String,
    action_class: String,
    risk_tier: String,
    irreversible: bool,
    approve: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    spend_amount_minor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spend_asset: Option<String>,
}

#[derive(Deserialize)]
struct GrantsListResponse {
    grants: Vec<DelegationGrant>,
}

#[cfg(test)]
mod tests {
    use super::tenant_assert::sign_tenant_assertion;
    use super::{
        interpret_2xx_gate_rule_body, interpret_404_gate_rule_body, GateRuleAnswer, GovderError,
    };
    use chrono::TimeZone;

    // ===== BLOCKER 6: a semantically-malformed 2xx rule body must fail closed =====

    #[test]
    fn gate_rule_body_missing_has_rule_fails_closed() {
        // HTTP 200 `{}` — `has_rule` is required, so this is a fetch failure, NOT a
        // silent downgrade to the numeric-threshold path.
        let err = interpret_2xx_gate_rule_body("{}").unwrap_err();
        assert!(matches!(err, GovderError::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn gate_rule_body_has_rule_true_without_rule_fails_closed() {
        let err = interpret_2xx_gate_rule_body(r#"{"has_rule":true}"#).unwrap_err();
        assert!(matches!(err, GovderError::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn gate_rule_body_has_rule_false_with_rule_present_fails_closed() {
        let body = r#"{"has_rule":false,"approval_rule":{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"deny-on-any-deny"}}"#;
        let err = interpret_2xx_gate_rule_body(body).unwrap_err();
        assert!(matches!(err, GovderError::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn gate_rule_body_clean_no_rule_is_numeric_parity() {
        // Only a clean `has_rule:false` (no rule) confirms "no rule" → numeric path.
        assert!(matches!(
            interpret_2xx_gate_rule_body(r#"{"has_rule":false}"#).unwrap(),
            GateRuleAnswer::NoRule
        ));
    }

    #[test]
    fn gate_rule_body_present_carries_authoritative_risk_facts() {
        let body = r#"{"has_rule":true,"risk_tier":"High","irreversible":true,
            "approval_rule":{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"deny-on-any-deny"}}"#;
        let fetched = match interpret_2xx_gate_rule_body(body).unwrap() {
            GateRuleAnswer::Rule(f) => f,
            other => panic!("expected a stamped rule, got {other:?}"),
        };
        assert_eq!(fetched.risk_tier, "High");
        assert!(fetched.irreversible);
        assert_eq!(fetched.rule.recipes.len(), 1);
    }

    // ===== RE-BLOCKER 2: has_rule:true MUST carry BOTH risk_tier and irreversible =====

    #[test]
    fn gate_rule_body_has_rule_true_missing_irreversible_fails_closed() {
        // A rule-present body that OMITS `irreversible` must fail the fetch closed —
        // NEVER silently decode as `false` (which would drop the forced deny-on-any-deny
        // on an authoritatively-irreversible gate).
        let body = r#"{"has_rule":true,"risk_tier":"High",
            "approval_rule":{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"deny-on-any-deny"}}"#;
        let err = interpret_2xx_gate_rule_body(body).unwrap_err();
        assert!(matches!(err, GovderError::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn gate_rule_body_has_rule_true_missing_risk_tier_fails_closed() {
        // A rule-present body that OMITS `risk_tier` must fail closed — a missing field
        // must never be confused with the resolved-but-empty `""` sentinel.
        let body = r#"{"has_rule":true,"irreversible":false,
            "approval_rule":{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"deny-on-any-deny"}}"#;
        let err = interpret_2xx_gate_rule_body(body).unwrap_err();
        assert!(matches!(err, GovderError::Decode(_)), "got: {err:?}");
    }

    #[test]
    fn gate_rule_body_present_empty_risk_tier_is_valid_only_absence_errors() {
        // `risk_tier:""` is govder's RESOLVED-unresolved sentinel (→ Extreme downstream),
        // a VALID PRESENT value: only true ABSENCE of the field fails closed. `irreversible`
        // is present-and-false, likewise valid.
        let body = r#"{"has_rule":true,"risk_tier":"","irreversible":false,
            "approval_rule":{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"deny-on-any-deny"}}"#;
        let fetched = match interpret_2xx_gate_rule_body(body).unwrap() {
            GateRuleAnswer::Rule(f) => f,
            other => panic!("expected a stamped rule, got {other:?}"),
        };
        assert_eq!(fetched.risk_tier, "");
        assert!(!fetched.irreversible);
    }

    // ===== plan 103 §10h FINDING 1/2: a 404 is not automatically a confirmed absence =====

    fn absence(body: &str) -> GateRuleAnswer {
        interpret_404_gate_rule_body(body, "ep_test", "money.refund")
    }

    #[test]
    fn gate_absence_is_definitive_only_when_agent_known_and_store_durable() {
        // The ONLY 404 that licenses the weaker numeric-threshold path: govder holds an
        // agent record under this exact key (so the key axis is right and the absence is
        // real) AND its gate store is durable (so a gate it once held cannot have
        // vanished). Both halves are required.
        assert!(matches!(
            absence(r#"{"error":"no gate","reason":"no_gate_for_action_class","gate_store_durable":true}"#),
            GateRuleAnswer::NoRule
        ));
    }

    #[test]
    fn gate_absence_with_a_volatile_store_is_inconclusive() {
        // §10h FINDING 2: govder's gate store was in-memory, so every restart dropped all
        // six money recipes and the next money call found "no gate". A volatile store
        // cannot distinguish a gate nobody configured from one it lost, so it must not
        // claim the absence is definitive.
        let reason = match absence(
            r#"{"error":"no gate","reason":"no_gate_for_action_class","gate_store_durable":false}"#,
        ) {
            GateRuleAnswer::Inconclusive { reason } => reason,
            other => panic!("a volatile gate store's absence must be inconclusive, got {other:?}"),
        };
        assert!(
            reason.contains("VOLATILE"),
            "the reason must name the volatile store so an operator can fix it: {reason}"
        );
    }

    #[test]
    fn gate_absence_for_an_unresolvable_agent_is_inconclusive() {
        // §10h FINDING 1's exact shape: the gate is keyed by AgentDefinition id and the
        // lookup arrives under the EnforcementPrincipal, so govder holds neither a gate
        // nor an agent record under that key. It confirmed nothing.
        assert!(matches!(
            absence(
                r#"{"error":"unknown","reason":"agent_unknown_under_this_key","gate_store_durable":true}"#
            ),
            GateRuleAnswer::Inconclusive { .. }
        ));
    }

    #[test]
    fn a_bare_404_with_no_reason_is_inconclusive_not_confirmed() {
        // THE ORIGINAL DEFECT, pinned. A 404 carrying only prose (every govder before
        // §10h, and any future build that drops the field) was read as a CONFIRMED "no
        // rule" and downgraded an irreversible refund to one approver. An unqualified
        // answer is now an unanswered one.
        for body in [r#"{"error":"no gate configured"}"#, "{}", "not json at all"] {
            assert!(
                matches!(absence(body), GateRuleAnswer::Inconclusive { .. }),
                "a 404 body with no reason code must be inconclusive: {body}"
            );
        }
    }

    #[test]
    fn assertion_has_four_segments() {
        let exp = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let a = sign_tenant_assertion(
            "secret",
            "acme",
            "GET",
            "/v1/delegation/grants",
            "",
            "127.0.0.1:8080",
            b"",
            exp,
        );
        assert_eq!(a.split('.').count(), 4);
    }
}
