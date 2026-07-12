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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use pop::PopKeypair;

/// Plan 087 — greppable fail-open seal counters (the metric half of the alarm).
/// Per-process, in-memory, shared across `AverinClient` clones via `Arc`. Paired
/// with the distinct `AVERIN-SEAL-FAILED` / `AVERIN-SEAL-DROPPED` log lines and
/// surfaced on `GET /api/v1/metrics`. Plan 085 independently detects the unsealed
/// actions these counters count.
#[derive(Default)]
pub struct SealMetrics {
    /// Use receipts sealed successfully (sync or async path).
    sealed: AtomicU64,
    /// Seal attempts that failed or timed out — fail-open, the action still ran.
    failed: AtomicU64,
    /// Seals DROPPED because the async fan-out cap was saturated (fail-open gap).
    dropped: AtomicU64,
    /// Current in-flight async seal tasks (a gauge, for the cap-holds invariant).
    in_flight: AtomicU64,
    /// High-water mark of `in_flight` — proves the cap held under overload.
    max_in_flight: AtomicU64,
}

impl SealMetrics {
    fn record_sealed(&self) {
        self.sealed.fetch_add(1, Ordering::Relaxed);
    }
    fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
    fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    fn enter_inflight(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        // Keep `max_in_flight` a monotone high-water mark (best-effort CAS loop).
        let mut hw = self.max_in_flight.load(Ordering::Relaxed);
        while now > hw {
            match self.max_in_flight.compare_exchange_weak(
                hw,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(cur) => hw = cur,
            }
        }
    }
    fn leave_inflight(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
    /// Snapshot for the JSON `/api/v1/metrics` read-back and tests.
    pub fn snapshot(&self) -> SealMetricsSnapshot {
        SealMetricsSnapshot {
            sealed: self.sealed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            max_in_flight: self.max_in_flight.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of [`SealMetrics`].
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct SealMetricsSnapshot {
    pub sealed: u64,
    pub failed: u64,
    pub dropped: u64,
    pub in_flight: u64,
    pub max_in_flight: u64,
}

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
    /// Plan 087 — the fan-out bound that matters. Max concurrent in-flight ASYNC
    /// use-seal tasks (Observe/fail-open mode). A sustained averin outage under
    /// high `/execute` load must not pile up unbounded spawned tasks → OOM; once
    /// this many seals are in flight, further seals are DROPPED fail-open (an
    /// 085-detected gap) rather than blocking `/execute` or growing unboundedly.
    /// Does NOT bound the synchronous `require_evidence` path (that already blocks
    /// `/execute`, so it is naturally back-pressured).
    pub max_inflight_seals: usize,
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
            // 256 concurrent async seals — enough headroom for a healthy averin's
            // round-trip under load, small enough that a full outage caps the
            // extra memory at a few hundred pending tasks (each holds a token id +
            // params snapshot), then sheds fail-open. Operator-tunable.
            max_inflight_seals: 256,
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
    /// Plan 087 — bounds concurrent async use-seal tasks (Observe/fail-open). A
    /// permit is claimed WITHOUT blocking (`try_acquire_owned`) before each spawn;
    /// on saturation the seal is dropped fail-open instead of blocking `/execute`.
    seal_permits: Arc<Semaphore>,
    /// Plan 087 — fail-open seal counters (the metric half of the alarm).
    metrics: Arc<SealMetrics>,
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
        // At least one permit — a zero cap would drop every seal (misconfig, not
        // intent). The fan-out bound is `max(1, configured)`.
        let permits = cfg.max_inflight_seals.max(1);
        Ok(Some(Self {
            http,
            cfg: Arc::new(cfg),
            pop: Arc::new(Mutex::new(HashMap::new())),
            seal_permits: Arc::new(Semaphore::new(permits)),
            metrics: Arc::new(SealMetrics::default()),
        }))
    }

    pub fn mode(&self) -> AverinMode {
        self.cfg.mode
    }

    /// Snapshot the fail-open seal counters (for `GET /api/v1/metrics` + tests).
    pub fn metrics(&self) -> SealMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Inject a PoP entry so a unit test can exercise `seal_use`/`spawn_use_seal`
    /// against a fake/blocked averin WITHOUT a real `/v2/grants` round-trip. A
    /// capability containing a `.` (e.g. `"AAAA.sig"`) passes `credential_binding`
    /// so the seal reaches the network; one without a `.` fails there (a
    /// deterministic, no-network seal failure for the alarm test).
    #[cfg(test)]
    fn insert_test_grant(&self, token_id: &str, capability: &str) {
        self.pop.lock().insert(
            token_id.to_string(),
            PopEntry {
                capability: capability.to_string(),
                grant_id: "g-test".to_string(),
                keypair: PopKeypair::generate(),
                action: "db.query:orders-ro".to_string(),
            },
        );
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

    /// SYNCHRONOUS use seal on `/execute` — the strict `require_evidence` path
    /// (consume-before-act, fail-closed). Returns `Err` ONLY when
    /// `mode = require_evidence` and the seal failed, so the caller BLOCKS the
    /// action. In `observe` mode a failure is logged fail-open and `Ok(())` is
    /// returned — but the production Observe path no longer calls this at all; it
    /// uses [`Self::spawn_use_seal`] (async, off the hot path). `on_execute` stays
    /// synchronous-by-design for `require_evidence` and is what the spike calls
    /// directly to MEASURE the added latency.
    ///
    /// **Consume-before-seal caveat (unchanged, out of scope for plan 087):** in
    /// `require_evidence` the caller has already consumed the `vut_` token before
    /// reaching here, so a strict block here BURNS the token. Fixing that ordering
    /// (seal-before-consume, or a consume rollback) is a separate change — plan 087
    /// only moves the *fail-open* path async, where nothing ever blocks, so this
    /// caveat is unreachable in the default (Observe) posture.
    pub async fn on_execute(&self, token_id: &str, params: &[u8]) -> Result<(), AverinError> {
        match self.seal_use(token_id, params).await {
            Ok(rid) => {
                self.metrics.record_sealed();
                tracing::debug!(target: "averin_seal", token_id, record_id = %rid, "averin use sealed (sync)");
                Ok(())
            }
            Err(e) => match self.cfg.mode {
                AverinMode::RequireEvidence => {
                    self.metrics.record_failed();
                    // ALARM: greppable marker + counter. token/project context only,
                    // never a secret or raw params (params are never logged).
                    tracing::error!(target: "averin_seal", token_id, project_id = %self.cfg.project_id, error = %e, "AVERIN-SEAL-FAILED averin use seal failed (require_evidence) — BLOCKING action");
                    Err(e)
                }
                AverinMode::Observe => {
                    self.metrics.record_failed();
                    tracing::warn!(target: "averin_seal", token_id, project_id = %self.cfg.project_id, error = %e, "AVERIN-SEAL-FAILED averin use seal failed (observe/fail-open) — action proceeds");
                    Ok(())
                }
            },
        }
    }

    /// Plan 087 — the PRODUCTION Observe (fail-open) execute seal: fire-and-forget
    /// the `POST /v2/use` OFF the `/execute` hot path so `plugin.execute` never
    /// waits on averin. Returns IMMEDIATELY.
    ///
    /// Bounded by `max_inflight_seals`: a permit is claimed WITHOUT blocking
    /// (`try_acquire_owned`) before the spawn. On saturation (a sustained averin
    /// outage under load) the seal is DROPPED fail-open — an 085-detected gap —
    /// rather than blocking `/execute` or spawning unbounded tasks. Drop, failure,
    /// and timeout each bump a counter AND emit a distinct greppable alarm line
    /// (`AVERIN-SEAL-DROPPED` / `AVERIN-SEAL-FAILED`) carrying token/project
    /// context but NEVER a secret or the raw params.
    ///
    /// The snapshot-out-of-the-lock in [`Self::seal_use`] means no lock is held
    /// across the spawned `.await` (STOP-condition check: it is not).
    pub fn spawn_use_seal(&self, token_id: &str, params: &[u8]) {
        // Claim a fan-out permit without blocking; saturated → drop fail-open.
        let permit = match Arc::clone(&self.seal_permits).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.metrics.record_dropped();
                tracing::warn!(
                    target: "averin_seal",
                    token_id,
                    project_id = %self.cfg.project_id,
                    cap = self.cfg.max_inflight_seals,
                    "AVERIN-SEAL-DROPPED averin use-seal fan-out cap saturated; seal dropped (fail-open — action proceeded, plan-085 detects the unsealed use)"
                );
                return;
            }
        };
        let this = self.clone();
        let token_id = token_id.to_string();
        let params = params.to_vec();
        tokio::spawn(async move {
            // Held for the seal's whole lifetime; releasing it frees a fan-out slot.
            let _permit = permit;
            this.metrics.enter_inflight();
            let outcome = this.seal_use(&token_id, &params).await;
            this.metrics.leave_inflight();
            match outcome {
                Ok(rid) => {
                    this.metrics.record_sealed();
                    tracing::debug!(target: "averin_seal", token_id = %token_id, record_id = %rid, "averin use sealed (async, off the /execute hot path)");
                }
                Err(e) => {
                    this.metrics.record_failed();
                    // ALARM: token/project context only — params are never logged.
                    tracing::warn!(
                        target: "averin_seal",
                        token_id = %token_id,
                        project_id = %this.cfg.project_id,
                        error = %e,
                        "AVERIN-SEAL-FAILED averin async use-seal failed/timed out (fail-open — action already proceeded; plan-085 detects the unsealed use)"
                    );
                }
            }
        });
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

    #[test]
    fn default_config_has_a_sane_fan_out_cap() {
        // The fan-out bound must be a positive default so the async seal is bounded
        // out of the box; a zero cap (which would drop every seal) is impossible —
        // `new` floors it at 1.
        assert_eq!(AverinConfig::default().max_inflight_seals, 256);
    }

    // ---- plan 087 async fail-open behaviour --------------------------------

    use std::time::Instant;

    /// An averin that accepts TCP connections but NEVER responds — a seal pointed
    /// at it stays in-flight until the client timeout. Returns its base_url; the
    /// accept loop lives on the test runtime and is torn down when it ends.
    async fn blocked_averin() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // hold the connection open, never write a response
            }
        });
        format!("http://{addr}")
    }

    fn client_with(base_url: &str, cap: usize, timeout: Duration) -> AverinClient {
        AverinClient::new(AverinConfig {
            enabled: true,
            base_url: base_url.to_string(),
            resource_id: "orders-db".to_string(),
            timeout,
            max_inflight_seals: cap,
            ..AverinConfig::default()
        })
        .expect("client builds")
        .expect("client is Some when enabled")
    }

    /// Step 1: in Observe mode the `/execute` seal is fire-and-forget — the hot
    /// path returns immediately even though averin will hang for the full timeout.
    #[tokio::test]
    async fn observe_execute_does_not_wait_on_slow_seal() {
        let base = blocked_averin().await;
        let client = client_with(&base, 256, Duration::from_secs(30));
        client.insert_test_grant("vut_slow", "AAAA.sig");

        let t0 = Instant::now();
        client.spawn_use_seal("vut_slow", br#"{"q":1}"#);
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "spawn_use_seal blocked the /execute hot path for {elapsed:?} (must be fire-and-forget)"
        );

        // The seal is still in-flight against the blocked averin — not completed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let m = client.metrics();
        assert_eq!(m.sealed, 0, "seal must still be in-flight, not sealed");
        assert!(m.in_flight >= 1, "the spawned seal task must be in flight");
    }

    /// Step 2: under overload the async fan-out stays bounded — `/execute` never
    /// blocks, in-flight tasks never exceed the cap, and the surplus is DROPPED
    /// fail-open (the drop counter increments).
    #[tokio::test]
    async fn observe_fan_out_is_bounded_and_drops_on_saturation() {
        let base = blocked_averin().await;
        let cap = 8usize;
        let total = 200usize;
        let client = client_with(&base, cap, Duration::from_secs(30));
        for i in 0..total {
            client.insert_test_grant(&format!("vut_{i}"), "AAAA.sig");
        }

        let t0 = Instant::now();
        for i in 0..total {
            client.spawn_use_seal(&format!("vut_{i}"), b"{}");
        }
        let fire_elapsed = t0.elapsed();
        // (a) /execute never blocks: firing `total` bounded spawns is ~instant.
        assert!(
            fire_elapsed < Duration::from_millis(500),
            "firing {total} bounded seals blocked for {fire_elapsed:?}"
        );

        // Let the <=cap admitted tasks reach in-flight.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let m = client.metrics();
        // (b) in-flight never exceeds the cap.
        assert!(
            m.max_in_flight <= cap as u64,
            "in-flight high-water {} exceeded the fan-out cap {cap}",
            m.max_in_flight
        );
        assert!(
            m.max_in_flight >= 1,
            "at least one seal should have gone in-flight"
        );
        // (c) the surplus was dropped fail-open.
        assert!(
            m.dropped >= (total - cap) as u64,
            "expected >= {} drops on saturation, got {}",
            total - cap,
            m.dropped
        );
        assert_eq!(m.sealed, 0, "no seal completes against a blocked averin");
    }

    /// Step 3: a fail-open seal FAILURE fires the alarm counter (paired with the
    /// greppable `AVERIN-SEAL-FAILED` line on the same branch). A malformed
    /// capability fails at `credential_binding` — a deterministic, no-network
    /// failure of the async seal.
    #[tokio::test]
    async fn observe_seal_failure_fires_alarm_counter() {
        // base_url unused (the seal fails before any network), but must be non-empty.
        let client = client_with("http://127.0.0.1:9", 256, Duration::from_secs(5));
        client.insert_test_grant("vut_bad", "nodothere"); // no '.' → MalformedCapability

        client.spawn_use_seal("vut_bad", b"{}");
        // Wait for the spawned task to run.
        for _ in 0..100 {
            if client.metrics().failed >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let m = client.metrics();
        assert_eq!(
            m.failed, 1,
            "AVERIN-SEAL-FAILED counter must fire on a failed seal"
        );
        assert_eq!(m.sealed, 0);
        assert_eq!(m.dropped, 0);
    }
}
