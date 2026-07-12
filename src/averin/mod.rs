//! The averin seal-client (plan 086, the "fourth contract"): a thin PRODUCER that
//! seals vultrino's credential mint/use into averin's tamper-evident DAG.
//!
//! - on token **mint** → `POST /v2/grants` (record-before-issue, fail-open)
//! - on **`/execute`** → `POST /v2/use` (one-phase use receipt; fail-mode per config)
//!
//! **Default OFF.** With `[averin] enabled = false` (the default) the client is
//! never constructed (`AppState.averin = None`) and both hooks are no-ops, so
//! `/execute` and mint are byte-identical to today. This is a SPIKE behind a
//! flag, not a shipped seal path — see `docs/dev/averin-sealing.md` for the
//! sync-vs-async / fail-mode design and the go/no-go.
//!
//! vultrino holds NO averin signing key. The only key here is an ephemeral agent
//! PoP keypair the client generates per grant (the capability `cnf`); averin's
//! broker/resource/signing keys are disjoint and never leave averin.

pub mod pop;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use pop::PopKeypair;

/// Fail-mode on `/execute` when the synchronous seal fails or averin is
/// unreachable. Mint is always fail-open (a token must not depend on averin).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AverinMode {
    /// Fail-OPEN sink: a seal failure is logged (and must alarm in prod) but the
    /// action proceeds. The recommended default (see the design doc).
    #[default]
    Observe,
    /// Fail-CLOSED strict: a seal failure BLOCKS the action (Level-3 consume-
    /// before-act). Opt-in, per-deployment — it binds `/execute` availability to
    /// averin's. Never a fleet-wide default.
    RequireEvidence,
}

/// Validated averin seal-client config. Built from the `[averin]` TOML block plus
/// the `AVERIN_API_KEY` env (the secret is env-only, never in a config dump).
#[derive(Clone, Debug)]
pub struct AverinConfig {
    /// Master switch. Default false — the client is not even constructed when off.
    pub enabled: bool,
    /// e.g. `http://127.0.0.1:8080` — the averin server base URL.
    pub base_url: String,
    /// averin project id (tenant) all records are sealed under.
    pub project_id: String,
    /// averin session id these grants/uses chain into.
    pub session_id: String,
    /// Must equal averin's `AVERIN_RESOURCE_ID` (the use receipt's audience).
    pub resource_id: String,
    /// Optional project-scoped API key (`?project=` auth), from `AVERIN_API_KEY`.
    pub api_key: Option<String>,
    /// Fail-mode on the execute seal.
    pub mode: AverinMode,
    /// Per-request timeout for the averin round-trip.
    pub timeout: Duration,
    /// TTL (seconds) stamped on minted grants.
    pub grant_ttl_secs: u32,
}

impl Default for AverinConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            project_id: "vultrino".to_string(),
            session_id: "vultrino-seal".to_string(),
            resource_id: String::new(),
            api_key: None,
            mode: AverinMode::Observe,
            timeout: Duration::from_secs(5),
            grant_ttl_secs: 300,
        }
    }
}

/// Per-token state the seal-client keeps between mint and execute: the averin-
/// minted capability, its grant_id, and the PoP private key that proves `cnf`.
struct PopEntry {
    capability: String,
    grant_id: String,
    keypair: PopKeypair,
    /// The grant's action — the use MUST present the identical action.
    action: String,
}

/// The thin averin seal-client. Cheap to `clone` (all shared state is `Arc`).
#[derive(Clone)]
pub struct AverinClient {
    http: reqwest::Client,
    cfg: Arc<AverinConfig>,
    /// token.id -> PopEntry. In-memory and restart-losable (matching the seal's
    /// best-effort posture); durable persistence is Phase-2.
    pop: Arc<Mutex<HashMap<String, PopEntry>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AverinError {
    #[error("averin base_url is required when [averin] enabled = true")]
    MissingBaseUrl,
    #[error("averin resource_id is required when [averin] enabled = true")]
    MissingResourceId,
    #[error("http client build failed: {0}")]
    HttpBuild(#[source] reqwest::Error),
    #[error("averin request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error("averin {endpoint} returned {status}: {body}")]
    Status {
        endpoint: &'static str,
        status: u16,
        body: String,
    },
    #[error("no grant on record for token {0} (mint seal did not land)")]
    NoGrant(String),
    #[error("pop preimage error: {0}")]
    Pop(#[source] pop::PopError),
    #[error("malformed averin response: {0}")]
    BadResponse(String),
}

impl AverinClient {
    /// Build the client. Returns `Ok(None)` when disabled so the caller can fold
    /// it straight into `Option<Arc<AverinClient>>` without a guard.
    pub fn new(cfg: AverinConfig) -> Result<Option<Self>, AverinError> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.base_url.trim().is_empty() {
            return Err(AverinError::MissingBaseUrl);
        }
        if cfg.resource_id.trim().is_empty() {
            return Err(AverinError::MissingResourceId);
        }
        let http = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .map_err(AverinError::HttpBuild)?;
        Ok(Some(Self {
            http,
            cfg: Arc::new(cfg),
            pop: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub fn mode(&self) -> AverinMode {
        self.cfg.mode
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cfg.base_url.trim_end_matches('/'), path)
    }

    fn agent_id(&self, token_id: &str) -> String {
        format!("vultrino:{token_id}")
    }

    // ---- mint hook -------------------------------------------------------

    /// Best-effort grant seal on token mint. NEVER fails the mint (a token is a
    /// vultrino artifact; its existence must not depend on averin). Logs +
    /// (in prod) alarms on failure.
    pub async fn on_mint(&self, token_id: &str, scope: &str, action: &str, use_limit: Option<u32>) {
        if let Err(e) = self.seal_grant(token_id, scope, action, use_limit).await {
            tracing::warn!(
                target: "averin_seal",
                token_id, error = %e,
                "averin grant seal failed (fail-open) — token minted without a sealed grant"
            );
        }
    }

    /// Seal `POST /v2/grants` and store the PoP entry keyed by `token_id`. This is
    /// the raw mechanism (returns the real `Result`); [`Self::on_mint`] wraps it
    /// with the always-fail-open mint policy. Public so the spike's integration
    /// test can assert the grant landed against a real averin.
    pub async fn seal_grant(
        &self,
        token_id: &str,
        scope: &str,
        action: &str,
        use_limit: Option<u32>,
    ) -> Result<(), AverinError> {
        let keypair = PopKeypair::generate();
        let agent_pubkey = keypair.agent_pubkey_b64();
        let agent_id = self.agent_id(token_id);
        let resource = self.cfg.resource_id.clone();

        let challenge =
            pop::grant_challenge(action, &agent_id, &agent_pubkey, &resource, scope);
        let agent_sig = keypair.sign_b64(&challenge);

        let scope_class = use_limit.filter(|n| *n > 1).map(|_| "bounded_reuse");
        let body = serde_json::json!({
            "idempotency_key": token_id,
            "project_id": self.cfg.project_id,
            "session_id": self.cfg.session_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "scope": scope,
            "scope_class": scope_class,
            "use_limit": use_limit.filter(|n| *n > 1).unwrap_or(0),
            "agent_pubkey": agent_pubkey,
            "agent_sig": agent_sig,
            "ttl_seconds": self.cfg.grant_ttl_secs,
        });

        let resp = self.post("/v2/grants", &body).await?;
        let grant_id = resp
            .get("grant_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AverinError::BadResponse("missing grant_id".into()))?
            .to_string();
        let capability = resp
            .get("capability")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AverinError::BadResponse("missing capability".into()))?
            .to_string();

        self.pop.lock().insert(
            token_id.to_string(),
            PopEntry {
                capability,
                grant_id,
                keypair,
                action: action.to_string(),
            },
        );
        Ok(())
    }

    // ---- execute hook ----------------------------------------------------

    /// Synchronous use seal on `/execute` (consume-before-act). Returns `Err`
    /// ONLY when `mode = require_evidence` and the seal failed (so the caller
    /// fails the action, fail-closed). In `observe` mode a failure is logged and
    /// `Ok(())` is returned (fail-open) — the action proceeds.
    ///
    /// The spike calls this SYNCHRONOUSLY before the side effect on purpose, to
    /// measure the added latency; the design doc recommends async as the default.
    pub async fn on_execute(&self, token_id: &str, params: &[u8]) -> Result<(), AverinError> {
        match self.seal_use(token_id, params).await {
            Ok(rid) => {
                tracing::debug!(target: "averin_seal", token_id, record_id = %rid, "averin use sealed");
                Ok(())
            }
            Err(e) => match self.cfg.mode {
                AverinMode::RequireEvidence => {
                    tracing::error!(target: "averin_seal", token_id, error = %e, "averin use seal failed (require_evidence) — BLOCKING action");
                    Err(e)
                }
                AverinMode::Observe => {
                    tracing::warn!(target: "averin_seal", token_id, error = %e, "averin use seal failed (observe/fail-open) — action proceeds");
                    Ok(())
                }
            },
        }
    }

    /// Seal `POST /v2/use` under the token's stored grant + PoP key. Returns the
    /// averin `record.record_id` of the sealed receipt. Raw mechanism (returns the
    /// real `Result`); [`Self::on_execute`] wraps it with the configured fail-mode.
    /// Public so the spike's integration test can assert + time it against a real averin.
    pub async fn seal_use(&self, token_id: &str, params: &[u8]) -> Result<String, AverinError> {
        // Snapshot the fields we need without holding the lock across the await.
        let (capability, grant_id, agent_pubkey, action, use_sig, nonce, params_nonce) = {
            let map = self.pop.lock();
            let entry = map.get(token_id).ok_or_else(|| AverinError::NoGrant(token_id.to_string()))?;
            let credential_binding =
                pop::credential_binding(&entry.capability).map_err(AverinError::Pop)?;
            let params_nonce = pop::random_params_nonce_hex();
            let params_commitment =
                pop::params_commitment(params, &params_nonce).map_err(AverinError::Pop)?;
            let nonce = pop::random_params_nonce_hex(); // any non-empty freshness string
            let challenge = pop::use_pop_challenge(
                &entry.grant_id,
                &self.cfg.resource_id,
                &entry.action,
                &params_commitment,
                &credential_binding,
                &nonce,
            );
            (
                entry.capability.clone(),
                entry.grant_id.clone(),
                entry.keypair.agent_pubkey_b64(),
                entry.action.clone(),
                entry.keypair.sign_b64(&challenge),
                nonce,
                params_nonce,
            )
        };
        let _ = (grant_id, agent_pubkey); // (available for richer receipts in Phase-2)

        let body = serde_json::json!({
            "idempotency_key": format!("{token_id}:use"),
            "project_id": self.cfg.project_id,
            "session_id": self.cfg.session_id,
            "capability": capability,
            "use_sig": use_sig,
            "action": action,
            "params": String::from_utf8_lossy(params),
            "nonce": nonce,
            "params_nonce": params_nonce,
        });

        let resp = self.post("/v2/use", &body).await?;
        let rid = resp
            .get("record")
            .and_then(|r| r.get("record_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>")
            .to_string();
        Ok(rid)
    }

    // ---- transport -------------------------------------------------------

    async fn post(
        &self,
        endpoint: &'static str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, AverinError> {
        let mut req = self.http.post(self.url(endpoint)).json(body);
        if let Some(k) = &self.cfg.api_key {
            // averin scopes auth on ?project=; the key goes in the Authorization header.
            req = req
                .query(&[("project", self.cfg.project_id.as_str())])
                .bearer_auth(k);
        }
        let resp = req.send().await.map_err(AverinError::Request)?;
        let status = resp.status();
        let text = resp.text().await.map_err(AverinError::Request)?;
        if !status.is_success() {
            return Err(AverinError::Status {
                endpoint,
                status: status.as_u16(),
                body: text.chars().take(400).collect(),
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| AverinError::BadResponse(format!("{endpoint}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_builds_no_client() {
        // The default-off guarantee: a disabled config yields no client, so both
        // hooks are unreachable and mint/execute stay byte-identical to today.
        assert!(AverinConfig::default().enabled == false);
        assert!(AverinClient::new(AverinConfig::default()).unwrap().is_none());
    }

    #[test]
    fn enabled_config_requires_base_url_and_resource_id() {
        let mut cfg = AverinConfig::default();
        cfg.enabled = true;
        cfg.resource_id = "orders-db".into();
        assert!(matches!(
            AverinClient::new(cfg.clone()),
            Err(AverinError::MissingBaseUrl)
        ));
        cfg.base_url = "http://127.0.0.1:8080".into();
        cfg.resource_id = "".into();
        assert!(matches!(
            AverinClient::new(cfg.clone()),
            Err(AverinError::MissingResourceId)
        ));
        cfg.resource_id = "orders-db".into();
        assert!(AverinClient::new(cfg).unwrap().is_some());
    }

    #[test]
    fn mode_default_is_fail_open_observe() {
        assert_eq!(AverinMode::default(), AverinMode::Observe);
    }
}
