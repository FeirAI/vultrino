//! Govder decide-plane HTTP client (plan 031 D3/D4).
//!
//! Vultrino consults govder as the system-of-record for DelegationGrant scope and
//! delegate verdict evaluation. Every call is authenticated with a short-lived
//! `X-Govder-Tenant-Assertion` HMAC matching `govder/pkg/tenantassert`.

mod tenant_assert;

use crate::delegation::{DelegationGrantScope, DelegateEvalResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use url::Url;

pub use tenant_assert::sign_tenant_assertion;

/// Configuration for outbound govder delegation calls.
#[derive(Debug, Clone)]
pub struct GovderConfig {
    pub base_url: String,
    pub assertion_secret: String,
    pub assertion_ttl: Duration,
    pub http_timeout: Duration,
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
    pub grant_id: &'a str,
    pub delegate_agent_id: &'a str,
    pub action_class: &'a str,
    pub risk_tier: &'a str,
    pub irreversible: bool,
    pub approve: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct EvaluateResponse {
    permitted: bool,
    #[serde(default)]
    reason: String,
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
        let http = Client::builder()
            .timeout(cfg.http_timeout)
            .build()?;
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
        if grant.revoked {
            return Err(GovderError::Policy(format!(
                "delegation: grant {grant_id} is revoked (fail-closed)"
            )));
        }
        if let Some(delegate) = delegate_agent_id {
            if !delegate.trim().is_empty() && delegate != grant.delegate_agent_id {
                return Err(GovderError::Policy(format!(
                    "delegation: grant delegate {} does not match requested delegate {delegate} (fail-closed)",
                    grant.delegate_agent_id
                )));
            }
        }
        let scope = DelegationGrantScope::from(&grant.scope);
        scope
            .validate()
            .map_err(|e| GovderError::Policy(format!("delegation: invalid grant scope from govder: {e}")))?;
        Ok((grant, scope))
    }

    pub async fn list_grants(&self, tenant: &str) -> Result<Vec<DelegationGrant>, GovderError> {
        let path = "/v1/delegation/grants";
        let resp = self
            .signed_json(tenant, "GET", path, "", None)
            .await?;
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
            grant_id: input.grant_id.to_string(),
            delegate_agent_id: input.delegate_agent_id.to_string(),
            action_class: input.action_class.to_string(),
            risk_tier: input.risk_tier.to_string(),
            irreversible: input.irreversible,
            approve: input.approve,
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
        let exp = chrono::Utc::now() + chrono::Duration::from_std(self.cfg.assertion_ttl).unwrap_or(chrono::Duration::seconds(90));
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
            req = req.header("Content-Type", "application/json").body(b.to_vec());
        }
        Ok(req.send().await?)
    }
}

#[derive(Serialize)]
struct EvaluateRequest {
    grant_id: String,
    delegate_agent_id: String,
    action_class: String,
    risk_tier: String,
    irreversible: bool,
    approve: bool,
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
    fn assertion_has_three_segments() {
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
        assert_eq!(a.split('.').count(), 3);
    }
}