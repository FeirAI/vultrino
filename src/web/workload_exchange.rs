//! Cryptographically verified workload exchange for LangChain runtimes.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

use super::{api::AdminApiAuth, server::AppState};
use crate::auth::{NewUseToken, UseToken, UseTokenMetadata};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadGrantTemplate {
    pub tenant: String,
    pub agent_label: String,
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub mcp_credential_scope: String,
    pub mcp_action_scope: String,
    #[serde(default)]
    pub model_channels: HashMap<String, ChannelGrant>,
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelGrant {
    pub credential_scope: String,
    pub action_scope: String,
}

#[derive(Debug, Deserialize)]
struct WorkloadAssertion {
    kind: String,
    iss: String,
    sub: String,
    aud: String,
    tenant: String,
    agent_label: String,
    jti: String,
    exp: i64,
}

fn default_ttl() -> i64 {
    300
}
fn grant_key(tenant: &str, agent: &str) -> String {
    format!("{}:{}{}", tenant.len(), tenant, agent)
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({"code": code, "error": message.into()}))).into_response()
}

pub async fn put_workload_grant(
    _admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(agent): Path<String>,
    Json(template): Json<WorkloadGrantTemplate>,
) -> Response {
    if agent != template.agent_label
        || [
            template.tenant.as_str(),
            template.issuer.as_str(),
            template.subject.as_str(),
            template.audience.as_str(),
        ]
        .iter()
        .any(|v| v.trim().is_empty())
        || !(30..=3600).contains(&template.ttl_secs)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_workload_grant",
            "complete identity binding, matching agent label, and ttl 30..3600 are required",
        );
    }
    let check = |credential_scope: String, action_scope: String| {
        NewUseToken {
            name: "validation".into(),
            credential_scope,
            action_scope: Some(action_scope),
            max_uses: None,
            require_approval: false,
            expires_in: Some(Duration::seconds(template.ttl_secs)),
        }
        .validate()
    };
    if let Err(e) = check(template.mcp_credential_scope.clone(), template.mcp_action_scope.clone()) {
        return error(StatusCode::BAD_REQUEST, "invalid_workload_grant", e);
    }
    for grant in template.model_channels.values() {
        if let Err(e) = check(grant.credential_scope.clone(), grant.action_scope.clone()) {
            return error(StatusCode::BAD_REQUEST, "invalid_workload_grant", e);
        }
    }
    state
        .workload_grants
        .write()
        .await
        .insert(grant_key(&template.tenant, &agent), template);
    (
        StatusCode::OK,
        Json(serde_json::json!({"stored": true, "agent_label": agent})),
    )
        .into_response()
}

fn verify_assertion(raw: &str, secret: &[u8]) -> Result<WorkloadAssertion, String> {
    let raw = raw
        .strip_prefix("vwa_")
        .ok_or("expected a vwa_ verified-workload assertion")?;
    let (payload, signature) = raw.split_once('.').ok_or("malformed workload assertion")?;
    let sig = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "malformed assertion signature")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| "invalid verifier key")?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| "workload assertion signature invalid")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "malformed assertion payload")?;
    let claims: WorkloadAssertion = serde_json::from_slice(&bytes).map_err(|_| "malformed assertion claims")?;
    if claims.kind != "oidc" && claims.kind != "spiffe" {
        return Err("assertion kind must be oidc|spiffe".into());
    }
    let now = Utc::now().timestamp();
    if claims.exp <= now || claims.exp > now + 600 {
        return Err("workload assertion expired or overlong".into());
    }
    if claims.jti.trim().is_empty() {
        return Err("workload assertion jti is required".into());
    }
    Ok(claims)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

pub async fn exchange_workload_token(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let enabled =
        std::env::var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !enabled {
        return error(
            StatusCode::NOT_FOUND,
            "feature_disabled",
            "workload exchange is disabled",
        );
    }
    let secret = match std::env::var("VULTRINO_WORKLOAD_ASSERTION_SECRET") {
        Ok(v) if v.len() >= 32 => v,
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "exchange_unconfigured",
                "workload assertion verifier is not configured",
            )
        }
    };
    let assertion = match bearer(&headers)
        .ok_or_else(|| "missing Bearer assertion".to_string())
        .and_then(|v| verify_assertion(v, secret.as_bytes()))
    {
        Ok(v) => v,
        Err(e) => return error(StatusCode::UNAUTHORIZED, "invalid_workload_identity", e),
    };
    let template = match state
        .workload_grants
        .read()
        .await
        .get(&grant_key(&assertion.tenant, &assertion.agent_label))
        .cloned()
    {
        Some(v) => v,
        None => {
            return error(
                StatusCode::FORBIDDEN,
                "grant_not_found",
                "no workload grant is authored for this identity",
            )
        }
    };
    if assertion.iss != template.issuer
        || assertion.sub != template.subject
        || assertion.aud != template.audience
        || assertion.tenant != template.tenant
        || assertion.agent_label != template.agent_label
    {
        return error(
            StatusCode::FORBIDDEN,
            "identity_binding_mismatch",
            "issuer, subject, audience, tenant, or agent binding does not match",
        );
    }
    if !state.workload_jtis.write().await.insert(assertion.jti) {
        return error(
            StatusCode::CONFLICT,
            "assertion_replay",
            "workload assertion was already exchanged",
        );
    }
    let mint = |name: String, credential_scope: String, action_scope: String| {
        UseToken::create(NewUseToken {
            name,
            credential_scope,
            action_scope: Some(action_scope),
            max_uses: None,
            require_approval: false,
            expires_in: Some(Duration::seconds(template.ttl_secs)),
        })
    };
    let (mcp_plain, mut mcp) = mint(
        format!("{} mcp", template.agent_label),
        template.mcp_credential_scope.clone(),
        template.mcp_action_scope.clone(),
    );
    mcp.agent_label = Some(template.agent_label.clone());
    mcp.tenant = Some(template.tenant.clone());
    if let Err(e) = state.storage.store_use_token(&mcp).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string());
    }
    let mut model_tokens = HashMap::new();
    let mut metadata = Vec::new();
    let mut minted_ids = vec![mcp.id.clone()];
    for (channel, grant) in template.model_channels {
        let (plain, mut token) = mint(
            format!("{} model {}", template.agent_label, channel),
            grant.credential_scope,
            grant.action_scope,
        );
        token.agent_label = Some(template.agent_label.clone());
        token.tenant = Some(template.tenant.clone());
        if let Err(e) = state.storage.store_use_token(&token).await {
            for id in &minted_ids {
                let _ = state.storage.set_use_token_revoked(id).await;
            }
            return error(StatusCode::INTERNAL_SERVER_ERROR, "storage_error", e.to_string());
        }
        minted_ids.push(token.id.clone());
        model_tokens.insert(channel, plain);
        metadata.push(UseTokenMetadata::from(&token));
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mcp_token": mcp_plain, "model_tokens": model_tokens,
            "expires_at_unix": (Utc::now() + Duration::seconds(template.ttl_secs)).timestamp(),
            "metadata": {"mcp": UseTokenMetadata::from(&mcp), "models": metadata}
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assertion_is_cryptographically_verified() {
        let secret = b"01234567890123456789012345678901";
        let payload = URL_SAFE_NO_PAD.encode(serde_json::json!({"kind":"oidc","iss":"i","sub":"s","aud":"a","tenant":"t","agent_label":"x","jti":"j","exp":Utc::now().timestamp()+60}).to_string());
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(payload.as_bytes());
        let token = format!(
            "vwa_{}.{}",
            payload,
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        );
        assert!(verify_assertion(&token, secret).is_ok());
        assert!(verify_assertion(&token, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").is_err());
    }
}
