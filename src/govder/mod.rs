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

pub use tenant_assert::sign_tenant_assertion;

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
#[derive(Debug, Clone, Deserialize)]
struct GateApprovalRuleResponse {
    #[serde(default)]
    has_rule: bool,
    #[serde(default)]
    approval_rule: Option<crate::approval::ApprovalRule>,
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
    /// `GET /v1/oversight/gates/rule` — 404 (no gate configured) and a 2xx body
    /// with `has_rule: false` (gate exists, no rule) both map to `Ok(None)`: from
    /// vultrino's side these are a CONFIRMED "no rule" → today's numeric-threshold
    /// path, unchanged.
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
    ) -> Result<Option<crate::approval::ApprovalRule>, GovderError> {
        let agent_id = agent_id.trim();
        let action_class = action_class.trim();
        if tenant.trim().is_empty() || agent_id.is_empty() || action_class.is_empty() {
            // Shape issue, not a fetch failure: there is no identity to query
            // govder with, so there is nothing to confirm either way — parity
            // with today's numeric-threshold path.
            return Ok(None);
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
            return Ok(None); // no gate configured for this agent_id/action_class: confirmed no rule
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
        let parsed: GateApprovalRuleResponse = serde_json::from_str(&body).map_err(|error| {
            tracing::error!(%error, %agent_id, %action_class,
                "govder gate-rule response failed to parse; failing closed");
            GovderError::Decode(error.to_string())
        })?;
        if !parsed.has_rule {
            return Ok(None); // confirmed: gate exists, no rule stamped
        }
        Ok(parsed.approval_rule)
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
    use chrono::TimeZone;

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
