//! Cryptographically verified workload exchange for LangChain runtimes.

use axum::{
    extract::{Path, Query, State},
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
use std::fs;

use super::{api::AdminApiAuth, server::AppState};
use crate::auth::{NewUseToken, UseToken, UseTokenMetadata};
use crate::policy::Principal;

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
    pub mcp_max_uses: Option<u32>,
    #[serde(default)]
    pub mcp_require_approval: bool,
    #[serde(default)]
    pub model_channels: HashMap<String, ChannelGrant>,
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
    /// FAIL-CLOSED BACKSTOP on token multiplication (plan 103 §10 item 6).
    ///
    /// Predecessor-retire below is the primary control, but it is a best-effort
    /// mutation: if it ever fails or regresses, an exchange-driven agent accumulates
    /// live generations LINEARLY IN UPTIME with nothing to stop it. Measured on a
    /// real eve pod: `revoked_tokens: 38` after 19 minutes at a 60s refresh, i.e.
    /// ~1,150 tokens/day/agent at a realistic L3 TTL — far past the ~150-200
    /// crossover where the grant-delete W2 leg exceeds govder's 10s enforce timeout.
    ///
    /// So the exchange REFUSES to mint once this many LIVE (unrevoked, unexpired)
    /// generations already exist for the agent. It is deliberately a refusal and not
    /// a warning: an unbounded live set degrades an authoritative containment leg,
    /// and the alternative failure (an agent that cannot refresh) is fail-closed and
    /// SELF-HEALING — expired tokens do not count, so the cap clears within one TTL.
    ///
    /// `None` means the default below, never "unbounded": the whole point is that an
    /// omitted field cannot restore the pre-fix behaviour.
    #[serde(default)]
    pub max_live_generations: Option<u32>,
}

/// Default `max_live_generations` when a grant does not declare one.
///
/// The honest invariant predecessor-retire provides is **<= 2 live generations during
/// rotation** (mint-then-retire means the new and old generation coexist briefly), not
/// "exactly one". The default leaves headroom above that for legitimate transients — a
/// pod restarting while its predecessor's token is still unexpired, a rollout overlap —
/// while keeping the set small enough that a W2 grant-delete revoke stays far inside
/// govder's 10s budget. It is a bound, not a target: steady state is 1.
const DEFAULT_MAX_LIVE_GENERATIONS: u32 = 4;

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

fn workload_token_request(
    name: String,
    credential_scope: String,
    action_scope: String,
    max_uses: Option<u32>,
    require_approval: bool,
    ttl_secs: i64,
) -> NewUseToken {
    NewUseToken {
        name,
        credential_scope,
        action_scope: Some(action_scope),
        max_uses,
        require_approval,
        expires_in: Some(Duration::seconds(ttl_secs)),
    }
}

fn grant_key(tenant: &str, agent: &str) -> String {
    format!("{}:{}{}", tenant.len(), tenant, agent)
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({"code": code, "error": message.into()})),
    )
        .into_response()
}

pub async fn put_workload_grant(
    admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(agent): Path<String>,
    Json(template): Json<WorkloadGrantTemplate>,
) -> Response {
    // Tenant partition (#0): a tenant-scoped admin key may provision a workload
    // grant only for its OWN tenant — never for another tenant (which would let it
    // mint that tenant's exchange tokens). Operator key (tenant None): unrestricted.
    if !crate::approval::tenant_may_act(admin.0.api_key.tenant.as_deref(), Some(&template.tenant)) {
        return error(
            StatusCode::FORBIDDEN,
            "cross_tenant_denied",
            "A tenant-scoped admin key may only provision workload grants in its own tenant.",
        );
    }
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
    let check = |credential_scope: String,
                 action_scope: String,
                 max_uses: Option<u32>,
                 require_approval: bool| {
        workload_token_request(
            "validation".into(),
            credential_scope,
            action_scope,
            max_uses,
            require_approval,
            template.ttl_secs,
        )
        .validate()
    };
    if let Err(e) = check(
        template.mcp_credential_scope.clone(),
        template.mcp_action_scope.clone(),
        template.mcp_max_uses,
        template.mcp_require_approval,
    ) {
        return error(StatusCode::BAD_REQUEST, "invalid_workload_grant", e);
    }
    for grant in template.model_channels.values() {
        if let Err(e) = check(
            grant.credential_scope.clone(),
            grant.action_scope.clone(),
            None,
            false,
        ) {
            return error(StatusCode::BAD_REQUEST, "invalid_workload_grant", e);
        }
    }
    let key = grant_key(&template.tenant, &agent);
    let value = match serde_json::to_value(&template) {
        Ok(value) => value,
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                e.to_string(),
            )
        }
    };
    if let Err(e) = state.storage.store_workload_grant(&key, value).await {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "grant_store_unavailable",
            e.to_string(),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"stored": true, "agent_label": agent})),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct DeleteGrantQuery {
    tenant: String,
}

/// Remove the exchange template and revoke every token previously minted from
/// it. This is idempotent so Govder can safely retry cleanup after a partial
/// deprovision without leaving a workload able to mint or use residual grants.
pub async fn delete_workload_grant(
    admin: AdminApiAuth,
    State(state): State<AppState>,
    Path(agent): Path<String>,
    Query(query): Query<DeleteGrantQuery>,
) -> Response {
    if query.tenant.trim().is_empty() || agent.trim().is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_workload_grant",
            "tenant and agent are required",
        );
    }
    // Tenant partition (#0): a tenant-scoped admin key may deprovision only its OWN
    // tenant's grant — never another tenant's (which would delete that tenant's
    // grant AND revoke its bound tokens, a cross-tenant DoS). Operator: unrestricted.
    if !crate::approval::tenant_may_act(
        admin.0.api_key.tenant.as_deref(),
        Some(query.tenant.as_str()),
    ) {
        return error(
            StatusCode::FORBIDDEN,
            "cross_tenant_denied",
            "A tenant-scoped admin key may only deprovision workload grants in its own tenant.",
        );
    }
    let removed = match state
        .storage
        .delete_workload_grant(&grant_key(&query.tenant, &agent))
        .await
    {
        Ok(removed) => removed,
        Err(e) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grant_store_unavailable",
                e.to_string(),
            )
        }
    };
    // W2's token leg, now ONE locked pass instead of one full vault rewrite per token (plan 103
    // §10 item 6). This is the same helper the exchange's predecessor-retire uses, with an EMPTY keep
    // set — "retire every live generation" is exactly what deprovisioning means.
    //
    // Why the shape mattered: the previous per-token loop was measured at 4.6s for 120 tokens and
    // 20.8s for 240, against govder's 10s enforce-client timeout — so on an agent that had
    // accumulated generations (which, before predecessor-retire, was every long-running pod-native
    // agent) the W2 leg stopped completing inside its own budget. Containment still held, because the
    // grant delete above precedes this and W3 is independent, but W2 stopped being a durable
    // independent leg. It also skips already-expired tokens, which grant nothing and were being
    // rewritten for no authority change.
    let revoked = match state
        .storage
        .retire_workload_generations(&query.tenant, &agent, &[])
        .await
    {
        Ok((_live_before, retired)) => retired,
        Err(e) => {
            // Fail LOUD. A caller that heard "removed" while live tokens survive would believe the
            // agent is contained when it is not — and the grant is already gone, so nothing will
            // retry this on its own.
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_revocation_incomplete",
                format!(
                    "the workload grant was removed but its live token generations could NOT be revoked ({}). The agent's already-issued tokens remain usable until their own TTL: revoke them individually via POST /api/v1/tokens/{{id}}/revoke, or install a deny policy for agent_label {}.",
                    e, agent
                ),
            );
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({"removed": removed, "revoked_tokens": revoked})),
    )
        .into_response()
}

fn verify_assertion(raw: &str, secrets: &[Vec<u8>]) -> Result<WorkloadAssertion, String> {
    let raw = raw
        .strip_prefix("vwa_")
        .ok_or("expected a vwa_ verified-workload assertion")?;
    let (payload, signature) = raw.split_once('.').ok_or("malformed workload assertion")?;
    let sig = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "malformed assertion signature")?;
    // Dual-secret overlap (rotation): the external OIDC/SPIFFE edge SIGNS, vultrino VERIFIES. Try each
    // configured verifier secret and accept on the first constant-time match (`verify_slice` is
    // constant-time; a miss falls through to the next candidate). A single-element list is exactly the
    // pre-rotation behavior; an empty list (fail-closed at `verifier_secrets`) never reaches here.
    let verified = secrets.iter().any(|secret| {
        Hmac::<Sha256>::new_from_slice(secret)
            .map(|mut mac| {
                mac.update(payload.as_bytes());
                mac.verify_slice(&sig).is_ok()
            })
            .unwrap_or(false)
    });
    if !verified {
        return Err("workload assertion signature invalid".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "malformed assertion payload")?;
    let claims: WorkloadAssertion =
        serde_json::from_slice(&bytes).map_err(|_| "malformed assertion claims")?;
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

fn verifier_secrets() -> Result<Vec<Vec<u8>>, &'static str> {
    let value = match std::env::var("VULTRINO_WORKLOAD_ASSERTION_SECRET_FILE") {
        Ok(path) if !path.trim().is_empty() => fs::read_to_string(path)
            .map_err(|_| "workload assertion verifier file cannot be read")?,
        _ => std::env::var("VULTRINO_WORKLOAD_ASSERTION_SECRET")
            .map_err(|_| "workload assertion verifier is not configured")?,
    };
    // A comma-separated LIST of verifier secrets (dual-secret overlap for rotation); a single value is a
    // 1-element list = the pre-rotation behavior. Each non-blank entry is trimmed and must be >= 32
    // bytes. An all-blank/empty configuration yields no secrets → fail closed (never verify against no
    // key). Element 0 is the primary; verify accepts a match against ANY listed secret.
    let secrets: Vec<Vec<u8>> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect();
    if secrets.is_empty() {
        return Err("workload assertion verifier is not configured");
    }
    if secrets.iter().any(|s| s.len() < 32) {
        return Err("workload assertion verifier must contain at least 32 bytes");
    }
    Ok(secrets)
}

pub async fn exchange_workload_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let enabled = std::env::var("VULTRINO_WORKLOAD_EXCHANGE_ENABLED")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !enabled {
        return error(
            StatusCode::NOT_FOUND,
            "feature_disabled",
            "workload exchange is disabled",
        );
    }
    let secrets = match verifier_secrets() {
        Ok(v) => v,
        Err(message) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "exchange_unconfigured",
                message,
            )
        }
    };
    let assertion = match bearer(&headers)
        .ok_or_else(|| "missing Bearer assertion".to_string())
        .and_then(|v| verify_assertion(v, &secrets))
    {
        Ok(v) => v,
        Err(e) => return error(StatusCode::UNAUTHORIZED, "invalid_workload_identity", e),
    };
    if let Err(e) = state.storage.reload().await {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "grant_store_unavailable",
            e.to_string(),
        );
    }
    let template = match state
        .storage
        .get_workload_grant(&grant_key(&assertion.tenant, &assertion.agent_label))
        .await
    {
        Ok(Some(v)) => match serde_json::from_value::<WorkloadGrantTemplate>(v) {
            Ok(template) => template,
            Err(e) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_stored_grant",
                    e.to_string(),
                )
            }
        },
        Err(e) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grant_store_unavailable",
                e.to_string(),
            )
        }
        Ok(None) => {
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
    let now = Utc::now().timestamp();
    let consumed = match state
        .storage
        .consume_workload_jti(&assertion.jti, assertion.exp, now)
        .await
    {
        Ok(consumed) => consumed,
        Err(e) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "replay_store_unavailable",
                e.to_string(),
            )
        }
    };
    if !consumed {
        return error(
            StatusCode::CONFLICT,
            "assertion_replay",
            "workload assertion was already exchanged",
        );
    }
    // GENERATION CAP, evaluated BEFORE anything is minted (plan 103 §10 item 6). Checking after the
    // mint would mean the very request that breached the bound had already added to it.
    let gen_cap = template
        .max_live_generations
        .unwrap_or(DEFAULT_MAX_LIVE_GENERATIONS)
        .max(1) as usize;
    match state
        .storage
        .count_live_workload_tokens(&template.tenant, &template.agent_label)
        .await
    {
        Ok(live) if live >= gen_cap => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "live_generation_cap",
                format!(
                    "{} live token generation(s) already exist for this agent (cap {}). Refusing to mint another: an unbounded live set makes the grant-delete kill leg exceed its own timeout. Expired generations do not count, so this clears within one token TTL ({}s); if it does not, predecessor-retire is failing — check for revoke errors in this process's log.",
                    live, gen_cap, template.ttl_secs
                ),
            );
        }
        Ok(_) => {}
        Err(e) => {
            // Fail CLOSED: an uncountable live set is exactly the state the cap exists to prevent.
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grant_store_unavailable",
                format!("could not count live token generations: {}", e),
            );
        }
    }
    let mint = |name: String,
                credential_scope: String,
                action_scope: String,
                max_uses: Option<u32>,
                require_approval: bool| {
        UseToken::create(workload_token_request(
            name,
            credential_scope,
            action_scope,
            max_uses,
            require_approval,
            template.ttl_secs,
        ))
    };
    let (mcp_plain, mut mcp) = mint(
        format!("{} mcp", template.agent_label),
        template.mcp_credential_scope.clone(),
        template.mcp_action_scope.clone(),
        template.mcp_max_uses,
        template.mcp_require_approval,
    );
    mcp.agent_label = Some(template.agent_label.clone());
    mcp.tenant = Some(template.tenant.clone());
    if let Err(e) = state.storage.store_use_token(&mcp).await {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            e.to_string(),
        );
    }
    // averin seal (plan 087 FIX 2): record-before-issue grant for a workload-exchange
    // mint, via the SHARED `seal_mint` — so an exchanged MCP token gets its grant on
    // record and its first `/execute` doesn't seal NoGrant. No-op unless `[averin]
    // enabled = true`; best-effort + fail-open.
    state.server.seal_mint(&mcp).await;
    let mut model_tokens = HashMap::new();
    let mut metadata = Vec::new();
    let mut minted_ids = vec![mcp.id.clone()];
    for (channel, grant) in template.model_channels {
        let (plain, mut token) = mint(
            format!("{} model {}", template.agent_label, channel),
            grant.credential_scope,
            grant.action_scope,
            None,
            false,
        );
        token.agent_label = Some(template.agent_label.clone());
        token.tenant = Some(template.tenant.clone());
        if let Err(e) = state.storage.store_use_token(&token).await {
            for id in &minted_ids {
                let _ = state.storage.set_use_token_revoked(id).await;
            }
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                e.to_string(),
            );
        }
        minted_ids.push(token.id.clone());
        // averin seal (plan 087 FIX 2): grant-before-issue for each per-channel model
        // token too, via the SHARED `seal_mint`. No-op unless `[averin] enabled = true`.
        state.server.seal_mint(&token).await;
        model_tokens.insert(channel, plain);
        metadata.push(UseTokenMetadata::from(&token));
    }
    // PREDECESSOR-RETIRE, MINT-THEN-RETIRE (plan 103 §10 item 6, and the reason vultrino is a code
    // target for plan 103 at all).
    //
    // Before this, every exchange left its predecessor LIVE with a full `max_uses` allowance until
    // that generation's own TTL. Measured: N=10 exchanges produced 10 independent live MCP tokens
    // with an aggregate 50 uses against an intended per-generation 5, plus 10 UNBOUNDED-use model
    // tokens; a real eve pod accumulated 38 in 19 minutes. Three consequences, all measured:
    //   * the aggregate authority of an agent grew without limit while every individual token looked
    //     correctly scoped;
    //   * the grant-delete W2 kill leg (one full vault rewrite per token) took 4.6s at 120 tokens and
    //     20.8s at 240, against govder's 10s enforce-client timeout — so W2 stopped completing inside
    //     its own budget, and stopped being a durable independent containment leg;
    //   * every exchange token is a reconcile `trueOrphan` (workload mode leaves govder's TokenID
    //     empty), so the orphan fraction approached 100% and tripped the MaxRevokeFraction circuit
    //     breaker into RemediationHeld — suppressing auto-revoke for genuinely rogue tokens
    //     TENANT-WIDE.
    //
    // ORDER IS MINT-THEN-RETIRE, not retire-then-mint: a retire that succeeded and a mint that then
    // failed would leave the agent with NO usable credential, converting a hygiene action into an
    // outage. This way a retire failure is a bounded excess (caught by the cap above) rather than a
    // denial of service. The retire is one locked pass, skips already-expired tokens, and keeps
    // exactly the generation this request just minted.
    //
    // The host-path eve re-mint has revoked its predecessor since plan 102; this restores parity for
    // the k8s workload-exchange path, which was the only one without it.
    let keep = minted_ids.clone();
    match state
        .storage
        .retire_workload_generations(&template.tenant, &template.agent_label, &keep)
        .await
    {
        Ok((live_before, retired)) => {
            if retired > 0 {
                tracing::info!(
                    tenant = %template.tenant,
                    agent_label = %template.agent_label,
                    live_before,
                    retired,
                    "workload exchange retired predecessor generation(s)"
                );
            }
        }
        Err(e) => {
            // NOT fatal, and deliberately so: the fresh credential is already stored and usable, and
            // failing the exchange here would hand the caller an error for a mint that succeeded —
            // which a retrying workload turns into more generations, the opposite of the goal. It IS
            // logged at warn and it IS bounded: the cap above refuses the next exchange once the
            // uncollected set reaches the limit, so a persistent retire failure becomes a visible
            // refusal within one TTL rather than silent unbounded growth.
            tracing::warn!(
                tenant = %template.tenant,
                agent_label = %template.agent_label,
                error = %e,
                "workload exchange could not retire predecessor generations — the live set will be bounded by max_live_generations instead"
            );
        }
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

/// Lightweight non-consuming liveness lease for framework-native execution.
/// A runtime polls with its MCP use-token. Revocation/expiry (W2) or any matching
/// authoritative kill policy (W3) returns a non-2xx response, allowing the SDK
/// to abort cooperative in-process work without granting an admin credential.
pub async fn runtime_control(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let secret = match bearer(&headers) {
        Some(value) if UseToken::looks_like_token(value) => value,
        _ => {
            return error(
                StatusCode::UNAUTHORIZED,
                "missing_runtime_token",
                "a Bearer use-token is required",
            )
        }
    };
    let _ = state.storage.reload().await;
    let token = match state
        .storage
        .get_use_token_by_hash(&UseToken::hash(secret))
        .await
    {
        Ok(Some(token)) => token,
        Ok(None) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_runtime_token",
                "runtime token is unknown",
            )
        }
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "control_store_unavailable",
                "runtime control state is unavailable",
            )
        }
    };
    if token.revoked || token.is_expired() {
        return error(
            StatusCode::CONFLICT,
            "runtime_cancelled",
            "runtime authority was revoked or expired",
        );
    }
    let principal = Principal {
        id: token.id.clone(),
        agent_label: token.agent_label.clone(),
        owner: None,
        workload_id: None,
    };
    if state.server.policy_engine().is_principal_halted(&principal) {
        return error(
            StatusCode::CONFLICT,
            "runtime_cancelled",
            "runtime principal was halted",
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active": true,
            "agent_label": token.agent_label,
            "tenant": token.tenant,
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
        // A one-element list is the pre-rotation behavior: the matching secret verifies, a wrong one
        // does not.
        assert!(verify_assertion(&token, &[secret.to_vec()]).is_ok());
        assert!(verify_assertion(&token, &[b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec()]).is_err());
        // Dual-secret overlap: the token verifies as long as its signing secret is ANYWHERE in the
        // list (here the second, rotated-in secret), while a list of only wrong secrets still fails.
        assert!(verify_assertion(
            &token,
            &[
                b"wrongwrongwrongwrongwrongwrongww".to_vec(),
                secret.to_vec()
            ]
        )
        .is_ok());
        assert!(verify_assertion(
            &token,
            &[
                b"wrongwrongwrongwrongwrongwrongww".to_vec(),
                b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec()
            ]
        )
        .is_err());
    }

    #[test]
    fn workload_mcp_token_preserves_compiled_use_and_approval_limits() {
        let request = workload_token_request(
            "agent mcp".into(),
            "cred-*".into(),
            "payments.refund".into(),
            Some(5),
            true,
            900,
        );
        assert_eq!(request.max_uses, Some(5));
        assert!(request.require_approval);
        assert_eq!(request.expires_in, Some(Duration::seconds(900)));
        assert!(request.validate().is_ok());
    }
}
