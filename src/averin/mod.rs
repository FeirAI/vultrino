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

/// Plan 087 FIX 3c — hard cap on how many bytes of an averin response we buffer.
/// averin's real success bodies (a `grant_id`/`capability`, or a `record.record_id`)
/// are tiny; a cap keeps a hostile or malfunctioning averin from making a bounded
/// fan-out buffer an unbounded body (`resp.text()` was unbounded). 64 KiB is far above
/// any real response yet still small enough that 256 concurrent reads stay trivial.
const MAX_AVERIN_RESPONSE_BYTES: usize = 64 * 1024;

/// Plan 087 FIX 5 — minimum spacing between `AVERIN-SEAL-DROPPED` log lines. The drop
/// COUNTER still increments per drop (cheap, lock-free); only the LOG is rate-limited,
/// so a sustained averin outage under high `/execute` load cannot turn every dropped
/// seal into a synchronous `tracing::warn!` on the hot path (a log-I/O storm that could
/// stall `/execute`).
const DROP_LOG_MIN_INTERVAL_MS: u64 = 5_000;

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
    /// Plan 087 FIX 5 — monotonic-ms (relative to the client's start `Instant`) at
    /// which the last `AVERIN-SEAL-DROPPED` line was emitted; 0 = never (so the very
    /// first drop always logs). Rate-limits ONLY the log line; `dropped` still counts
    /// every drop, so no accounting is lost — only the synchronous `warn!` I/O on the
    /// hot path is coalesced during a sustained outage.
    drop_log_last_ms: AtomicU64,
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

/// Plan 087 FIX 6 — RAII so the `in_flight` gauge is decremented even when the
/// spawned seal task PANICS or is CANCELLED mid-`await`. The owned semaphore permit
/// is already RAII-released on an abnormal exit (good); this makes the gauge (and the
/// failure alarm) symmetric. On a normal exit the task calls [`Self::complete`]
/// FIRST, so `Drop` only decrements; on an abnormal exit `complete` was never called,
/// so `Drop` also counts a `failed` — the lost seal is reflected, not silently
/// dropped, and `in_flight` cannot drift upward forever.
struct InflightGuard {
    metrics: Arc<SealMetrics>,
    completed: bool,
}

impl InflightGuard {
    fn enter(metrics: Arc<SealMetrics>) -> Self {
        metrics.enter_inflight();
        Self {
            metrics,
            completed: false,
        }
    }
    /// Mark the seal task as having recorded its own outcome (sealed OR failed), so
    /// `Drop` does not double-count a failure. Called on both the Ok and Err arms.
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.metrics.leave_inflight();
        if !self.completed {
            // The task panicked/was cancelled before recording an outcome — count the
            // lost seal so the `failed` counter and its alarm reflect reality.
            self.metrics.record_failed();
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
    /// Plan 087 FIX 3 — max raw-`params` size (bytes) a single use-seal will carry to
    /// averin. `max_inflight_seals` bounds the task COUNT, not the BYTES each retains;
    /// without a byte cap, 256 large LLM payloads could pin gigabytes (each is copied
    /// into the seal body and averin's response is buffered). Params larger than this
    /// are NOT sealed: in `Observe` the seal is DROPPED fail-open (counted, oversize
    /// alarm) so `/execute` proceeds; in `RequireEvidence` the action is DENIED with a
    /// bounded error, never transmitting the oversize body. averin RECOMPUTES the
    /// params commitment from the raw bytes (§5a recompute-or-reject), so there is no
    /// "seal a fixed-size commitment WITHOUT the raw body" option — hence oversize =
    /// drop/deny, not truncate. Operator-tunable.
    pub max_seal_params_bytes: usize,
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
            // 128 KiB — comfortably above a normal `/execute` payload, below the size
            // that would let the bounded fan-out pin large memory: worst case is
            // ~`max_inflight_seals * max_seal_params_bytes` (256 * 128 KiB = 32 MiB),
            // not the gigabytes an uncapped seal could hold. Oversize payloads are
            // dropped/denied, never truncated (averin recomputes the commitment from
            // the raw bytes). Operator-tunable.
            max_seal_params_bytes: 128 * 1024,
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
    /// Plan 087 FIX 5 — the monotonic base for the drop-log rate limiter. Copied on
    /// `clone` (all clones share the same instant value), so `since.elapsed()` is a
    /// consistent process-wide clock for `drop_log_last_ms`.
    since: std::time::Instant,
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
    // FIX 4 — `Display` (what the alarm logs via `error = %e`) carries ONLY the
    // endpoint + status code, NEVER the upstream response body. The body (possible
    // PII/secret) is deliberately NOT carried on the error; it is emitted once at a
    // DEBUG-ONLY channel at the `post` site, so it can never leak into an
    // `AVERIN-SEAL-*` alarm line.
    #[error("averin {endpoint} returned {status}")]
    Status { endpoint: &'static str, status: u16 },
    #[error("averin seal params {len} bytes exceed cap {cap} bytes")]
    ParamsTooLarge { len: usize, cap: usize },
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
            since: std::time::Instant::now(),
        }))
    }

    /// Plan 087 FIX 5 — return `Some(running_dropped_total)` at most once per
    /// [`DROP_LOG_MIN_INTERVAL_MS`] (and always on the very first drop), else `None`.
    /// The counter is bumped by the caller regardless; this gates only the LOG line so
    /// a sustained outage cannot storm the hot path with a `warn!` per dropped seal.
    fn claim_drop_log(&self) -> Option<u64> {
        let now_ms = self.since.elapsed().as_millis() as u64;
        let last = self.metrics.drop_log_last_ms.load(Ordering::Relaxed);
        // 0 = never logged → always log the first drop; otherwise wait out the window.
        if last != 0 && now_ms.saturating_sub(last) < DROP_LOG_MIN_INTERVAL_MS {
            return None;
        }
        // Claim the slot (`.max(1)` so the stored stamp is never 0 = "never"). If
        // another thread claimed it first, stay silent — no double log.
        if self
            .metrics
            .drop_log_last_ms
            .compare_exchange(last, now_ms.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            Some(self.metrics.dropped.load(Ordering::Relaxed))
        } else {
            None
        }
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
    pub async fn on_execute(&self, token_id: &str, params: Vec<u8>) -> Result<(), AverinError> {
        // FIX 3 — never transmit an oversize body. averin recomputes the commitment
        // from the raw bytes (§5a), so we cannot seal a fixed-size commitment WITHOUT
        // the body; oversize therefore deny (require_evidence) or drop (observe),
        // bounded — never gigabytes on the wire.
        if params.len() > self.cfg.max_seal_params_bytes {
            return match self.cfg.mode {
                AverinMode::RequireEvidence => {
                    self.metrics.record_failed();
                    let e = AverinError::ParamsTooLarge {
                        len: params.len(),
                        cap: self.cfg.max_seal_params_bytes,
                    };
                    tracing::error!(target: "averin_seal", token_id, project_id = %self.cfg.project_id, error = %e, "AVERIN-SEAL-FAILED oversize params (require_evidence) — BLOCKING action");
                    Err(e)
                }
                AverinMode::Observe => {
                    self.metrics.record_dropped();
                    tracing::warn!(target: "averin_seal", token_id, project_id = %self.cfg.project_id, params_bytes = params.len(), cap = self.cfg.max_seal_params_bytes, "AVERIN-SEAL-DROPPED-oversize params exceed max_seal_params_bytes (observe/fail-open) — action proceeds");
                    Ok(())
                }
            };
        }
        match self.seal_use(token_id, &params).await {
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
    ///
    /// Takes OWNED `params` (FIX 3b): the buffer the caller already built moves into
    /// the spawned task instead of being copied again (`.to_vec()` is gone). Oversize
    /// params (> `max_seal_params_bytes`) are dropped BEFORE claiming a permit (FIX 3),
    /// and the saturation/oversize drop LOG is rate-limited (FIX 5) though the counter
    /// always increments. The in-flight gauge is RAII-guarded (FIX 6).
    pub fn spawn_use_seal(&self, token_id: &str, params: Vec<u8>) {
        // FIX 3 — oversize params are never sealed (averin recomputes the commitment
        // from the raw bytes, so there is no fixed-size-commitment-only option). Drop
        // fail-open + count; the action already proceeded (085 detects the gap). Done
        // BEFORE claiming a permit so an oversize flood cannot even occupy the fan-out.
        if params.len() > self.cfg.max_seal_params_bytes {
            self.metrics.record_dropped();
            if let Some(total) = self.claim_drop_log() {
                tracing::warn!(
                    target: "averin_seal",
                    token_id,
                    project_id = %self.cfg.project_id,
                    params_bytes = params.len(),
                    cap = self.cfg.max_seal_params_bytes,
                    dropped_total = total,
                    "AVERIN-SEAL-DROPPED-oversize params exceed max_seal_params_bytes; seal dropped (fail-open — action proceeded, plan-085 detects the unsealed use). Log rate-limited; dropped_total is the running count."
                );
            }
            return;
        }
        // Claim a fan-out permit without blocking; saturated → drop fail-open.
        let permit = match Arc::clone(&self.seal_permits).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.metrics.record_dropped();
                // FIX 5 — the counter always bumps (above); the LOG is rate-limited so a
                // sustained outage can't storm the hot path with a warn per dropped seal.
                if let Some(total) = self.claim_drop_log() {
                    tracing::warn!(
                        target: "averin_seal",
                        token_id,
                        project_id = %self.cfg.project_id,
                        cap = self.cfg.max_inflight_seals,
                        dropped_total = total,
                        "AVERIN-SEAL-DROPPED averin use-seal fan-out cap saturated; seal dropped (fail-open — action proceeded, plan-085 detects the unsealed use). Log rate-limited; dropped_total is the running count."
                    );
                }
                return;
            }
        };
        let this = self.clone();
        let token_id = token_id.to_string();
        tokio::spawn(async move {
            // Held for the seal's whole lifetime; releasing it frees a fan-out slot.
            let _permit = permit;
            // FIX 6 — RAII: `in_flight` is decremented (and a failure counted) even if
            // this task panics or is cancelled mid-await. `complete()` on the normal
            // arms stops `Drop` from double-counting a failure.
            let mut guard = InflightGuard::enter(this.metrics.clone());
            let outcome = this.seal_use(&token_id, &params).await;
            match outcome {
                Ok(rid) => {
                    this.metrics.record_sealed();
                    guard.complete();
                    tracing::debug!(target: "averin_seal", token_id = %token_id, record_id = %rid, "averin use sealed (async, off the /execute hot path)");
                }
                Err(e) => {
                    this.metrics.record_failed();
                    guard.complete();
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
        // FIX 3c — read at most MAX_AVERIN_RESPONSE_BYTES instead of the unbounded
        // `resp.text()`, so a hostile or malfunctioning averin cannot make a bounded
        // fan-out buffer an unbounded body. averin's real bodies are far under the cap.
        let text = read_capped(resp, MAX_AVERIN_RESPONSE_BYTES).await?;
        if !status.is_success() {
            let body_snippet: String = text.chars().take(400).collect();
            // FIX 4 — the upstream body (possible PII/secret) goes ONLY to a
            // debug-level channel, NEVER to an AVERIN-SEAL-* alarm line (those log
            // `error = %e`, and `Status`'s Display deliberately omits the body).
            tracing::debug!(
                target: "averin_seal",
                endpoint,
                status = status.as_u16(),
                body = %body_snippet,
                "averin non-2xx response body (debug-only; excluded from alarm lines)"
            );
            return Err(AverinError::Status {
                endpoint,
                status: status.as_u16(),
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| AverinError::BadResponse(format!("{endpoint}: {e}")))
    }
}

/// FIX 3c — buffer at most `cap` bytes of a response body (averin's real responses
/// are tiny; this bounds a hostile/broken one). Reads the byte stream chunk-by-chunk
/// and stops once the cap is reached, so the full body is never materialized.
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<String, AverinError> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(AverinError::Request)?;
        if buf.len() >= cap {
            break;
        }
        let take = (cap - buf.len()).min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
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
        client.spawn_use_seal("vut_slow", br#"{"q":1}"#.to_vec());
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
            client.spawn_use_seal(&format!("vut_{i}"), b"{}".to_vec());
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

        client.spawn_use_seal("vut_bad", b"{}".to_vec());
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

    // ---- plan 087 FIX 3/4/5/6 -----------------------------------------------

    /// A client with a tiny params cap, for the oversize tests.
    fn client_capped(mode: AverinMode, cap_bytes: usize) -> AverinClient {
        AverinClient::new(AverinConfig {
            enabled: true,
            base_url: "http://127.0.0.1:9".to_string(),
            resource_id: "orders-db".to_string(),
            mode,
            max_seal_params_bytes: cap_bytes,
            ..AverinConfig::default()
        })
        .expect("client builds")
        .expect("client is Some when enabled")
    }

    /// FIX 3 — in Observe, oversize params are DROPPED before a permit is claimed and
    /// before any task spawns (no unbounded bytes retained), the drop counter bumps,
    /// and the action still proceeds (spawn_use_seal returns immediately).
    #[tokio::test]
    async fn observe_oversize_params_dropped_before_spawn() {
        let client = client_capped(AverinMode::Observe, 8);
        client.insert_test_grant("vut_big", "AAAA.sig");
        client.spawn_use_seal("vut_big", vec![b'x'; 64]); // 64 > 8-byte cap
        let m = client.metrics();
        assert_eq!(m.dropped, 1, "oversize params must be dropped");
        assert_eq!(m.in_flight, 0, "no task is spawned for oversize params");
        assert_eq!(m.sealed, 0);
        assert_eq!(m.failed, 0);
        // A within-cap seal is NOT dropped (it spawns and — NoGrant-free here, but the
        // dead port means it will fail later; we only assert it wasn't oversize-dropped).
        client.insert_test_grant("vut_small", "AAAA.sig");
        client.spawn_use_seal("vut_small", vec![b'x'; 4]);
        assert_eq!(client.metrics().dropped, 1, "a within-cap seal must not be dropped");
    }

    /// FIX 3 — in RequireEvidence, oversize params DENY with a bounded `ParamsTooLarge`
    /// error (no body transmitted, no raw params in the error) and count a failure.
    #[tokio::test]
    async fn require_evidence_oversize_params_denied_bounded() {
        let client = client_capped(AverinMode::RequireEvidence, 8);
        client.insert_test_grant("vut_big", "AAAA.sig");
        let err = client
            .on_execute("vut_big", vec![b'x'; 64])
            .await
            .expect_err("oversize params must DENY in require_evidence");
        assert!(matches!(err, AverinError::ParamsTooLarge { .. }));
        let msg = format!("{err}");
        assert!(msg.contains("exceed cap"), "bounded error, got: {msg}");
        assert!(
            !msg.contains("xxxx"),
            "the error must not carry the raw params, got: {msg}"
        );
        let m = client.metrics();
        assert_eq!(m.failed, 1);
        assert_eq!(m.sealed, 0);
    }

    /// FIX 4 — the `Status` error's Display (what the alarm logs via `error = %e`)
    /// carries ONLY endpoint + status, never a response body.
    #[test]
    fn status_error_display_excludes_response_body() {
        let e = AverinError::Status {
            endpoint: "/v2/use",
            status: 500,
        };
        assert_eq!(format!("{e}"), "averin /v2/use returned 500");
    }

    /// FIX 5 — the drop LOG is rate-limited: the first claim logs, every claim within
    /// the window is silent (the COUNTER, tested elsewhere, still bumps per drop).
    #[test]
    fn drop_log_is_rate_limited_after_the_first() {
        let client = client_with("http://127.0.0.1:9", 256, Duration::from_secs(5));
        assert!(client.claim_drop_log().is_some(), "the first drop always logs");
        for _ in 0..10_000 {
            assert!(
                client.claim_drop_log().is_none(),
                "further drops within the window must be silent (no per-request log storm)"
            );
        }
    }

    /// FIX 6 — the RAII guard releases `in_flight` AND counts a failure when the task
    /// drops WITHOUT completing (the panic/cancel path).
    #[test]
    fn inflight_guard_releases_and_counts_failure_on_abnormal_drop() {
        let metrics = Arc::new(SealMetrics::default());
        {
            let _g = InflightGuard::enter(metrics.clone());
            assert_eq!(metrics.snapshot().in_flight, 1);
        } // dropped WITHOUT complete() → abnormal (panic/cancel) path
        let m = metrics.snapshot();
        assert_eq!(m.in_flight, 0, "guard must release in_flight even on panic/cancel");
        assert_eq!(m.failed, 1, "an abnormal drop must count the lost seal as failed");
        assert_eq!(m.max_in_flight, 1);
    }

    /// FIX 6 — a normally-completed guard releases `in_flight` and does NOT double-count
    /// a failure (the task already recorded its own outcome).
    #[test]
    fn inflight_guard_normal_completion_counts_no_failure() {
        let metrics = Arc::new(SealMetrics::default());
        {
            let mut g = InflightGuard::enter(metrics.clone());
            g.complete();
        }
        let m = metrics.snapshot();
        assert_eq!(m.in_flight, 0);
        assert_eq!(m.failed, 0, "a completed guard must not count a failure");
    }
}
