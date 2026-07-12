//! Vultrino server implementation
//!
//! Provides JSON API mode for execute requests.

use crate::approval::{
    ApprovalLinks, ApprovalNotifier, ApprovalRequest, ApprovalStatus, NewApproval, RequesterInfo,
};
use crate::auth::{AuthManager, AuthResult, Permission, UseToken};
use crate::config::Config;
use crate::plugins::PluginRegistry;
use crate::policy::PolicyEngine;
use crate::router::CredentialResolver;
use crate::storage::StorageBackend;
use crate::{
    Credential, ExecuteRequest, ExecuteResponse, ExecutionOutcome, RequestContext, VultrinoError,
};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use tracing::{error, info, warn};

/// The body stream of a streaming execution: scrubbed byte chunks delivered to
/// the agent. The error type is `io::Error` so axum's `Body::from_stream` accepts
/// it; in practice the adaptor never yields `Err` — a fatal upstream/scrub
/// condition is converted into a terminal in-band SSE `error` frame and the stream
/// ends cleanly (the agent's SDK sees a clean SSE error, not a torn connection).
pub type ScrubbedBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// A generic terminal SSE `error` frame emitted in-band when a stream fails after
/// the head was already sent (upstream transport error, or a fail-closed scrub).
/// Deliberately detail-free — the agent must never see the upstream error body /
/// SSRF reason (mirrors the buffered path, which withholds upstream `Err` detail).
/// `event: error` is the SSE convention both OpenAI and Anthropic clients surface.
const SSE_ERROR_FRAME: &[u8] =
    b"event: error\ndata: {\"error\":{\"type\":\"api_error\",\"message\":\"vultrino: upstream stream failed\"}}\n\n";

/// A terminal SSE `error` frame emitted when a stream is HALTED mid-flight (V6).
/// Distinct message from the generic upstream-failure frame so the agent's logs
/// show the turn was deliberately stopped, not that the provider errored.
const SSE_HALT_FRAME: &[u8] =
    b"event: error\ndata: {\"error\":{\"type\":\"api_error\",\"message\":\"vultrino: request halted\"}}\n\n";

/// One iteration's outcome in the streaming adaptor's select loop: a chunk to
/// process, a clean end, or one of the terminal conditions (upstream error, a V6
/// halt, or a DoS cap). Computed inside `select!` (no `yield` there) then matched.
enum StreamStep {
    Chunk(Bytes),
    CleanEof,
    UpstreamError,
    Halted,
    IdleTimeout,
    TotalTimeout,
}

/// While a serving process executes an approved action, it refreshes the
/// approval's execution claim this often so a slow-but-alive worker is never
/// mistaken for a crashed one. Must be comfortably smaller than the storage
/// backend's stale-claim timeout.
const EXECUTION_HEARTBEAT_SECS: u64 = 30;

/// Upper bound on how long a single halt abort callback may run before the halt
/// proceeds without waiting for it (V6) — a hanging integration can't stall the
/// halt, whose token-revoke + kill-policy legs have already committed.
const HALT_CALLBACK_TIMEOUT_SECS: u64 = 5;

/// Result of halting an agent (V6) — a machine-readable summary of the three
/// kill legs, returned by the halt admin endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HaltOutcome {
    /// The agent label that was halted.
    pub agent_label: String,
    /// Ids of the use tokens revoked by the halt.
    pub revoked_tokens: Vec<String>,
    /// Id of the installed per-agent kill policy.
    pub deny_policy_id: String,
    /// Whether the kill policy is active in the live engine now (true), or only
    /// persisted and pending the next refresh on this process (false).
    pub policy_active: bool,
    /// In-flight sessions for the agent in this process at halt time.
    pub in_flight: Vec<crate::session::SessionEntry>,
    /// How many abort callbacks were fired.
    pub callbacks_fired: usize,
}

/// Authentication context for a (possibly approval-gated) execution.
///
/// Carries the permission/scope source (`auth`) and, when a use token is driving
/// the request, the **whole token** so the server can authoritatively enforce
/// its credential *and* action scope at the seam where the token is spent and
/// consume it — a single source of truth. Also carries the force-approval flag
/// and the requester identity for the approval record.
#[derive(Default)]
pub struct ExecAuth {
    /// Real (API key) or synthesized (use token) auth result. `None` = local.
    pub auth: Option<AuthResult>,
    /// The use token driving this request, if any (single source of truth for
    /// scope enforcement and consumption).
    pub use_token: Option<UseToken>,
    /// Force human approval for this request (e.g. a token's `require_approval`).
    pub force_approval: bool,
    /// Who/what made the request, for the approval record.
    pub requester: RequesterInfo,
}

impl ExecAuth {
    /// Build an `ExecAuth` for an API-key-authenticated request.
    pub fn from_api_key(auth: AuthResult) -> Self {
        let requester = RequesterInfo {
            principal_kind: "api_key".to_string(),
            principal_id: Some(auth.api_key.id.clone()),
            principal_name: Some(auth.api_key.name.clone()),
            role: Some(auth.role.name.clone()),
            owner: auth.api_key.owner_identity.clone(),
        };
        Self {
            auth: Some(auth),
            use_token: None,
            force_approval: false,
            requester,
        }
    }

    /// Build an `ExecAuth` for a use-token-authenticated request. Derives the
    /// synthesized auth, the consume target, the force-approval flag, and the
    /// requester from the one token, so they cannot diverge.
    pub fn from_use_token(token: UseToken) -> Self {
        let requester = RequesterInfo {
            principal_kind: "use_token".to_string(),
            principal_id: Some(token.id.clone()),
            principal_name: Some(token.name.clone()),
            role: None,
            owner: token.owner_identity.clone(),
        };
        Self {
            auth: Some(AuthResult::for_use_token(&token)),
            force_approval: token.require_approval,
            requester,
            use_token: Some(token),
        }
    }
}

/// Error from [`VultrinoServer::run_action`], tagged with whether the
/// side-effecting `plugin.execute` had begun.
///
/// `committed = false` means the failure happened during preflight (plugin not
/// loaded, invalid params, unusable token) — nothing ran, so resuming an
/// approval can safely retry. `committed = true` means the plugin was invoked
/// and the action may have had an external effect — it must not be retried.
struct RunError {
    /// True only when retrying could plausibly succeed: a *transient* preflight
    /// failure such as a plugin that isn't loaded yet. A *permanent* preflight
    /// failure (unusable use token, invalid params, missing credential) or a
    /// committed `plugin.execute` failure sets this false — a resumed approval is
    /// then finalized terminally instead of busy-polling forever.
    retryable: bool,
    error: VultrinoError,
}

impl RunError {
    /// A transient preflight failure (e.g. plugin not loaded) — safe to retry.
    fn retryable(error: VultrinoError) -> Self {
        Self {
            retryable: true,
            error,
        }
    }
    /// A permanent preflight failure (unusable token, bad params, missing
    /// credential) — nothing ran, but retrying won't help.
    fn terminal(error: VultrinoError) -> Self {
        Self {
            retryable: false,
            error,
        }
    }
    /// The plugin began executing and then failed — may have side-effected, so
    /// it must not be retried.
    fn committed(error: VultrinoError) -> Self {
        Self {
            retryable: false,
            error,
        }
    }
}

/// The outcome of gating a request, produced once by
/// [`VultrinoServer::prepare_execution`] and consumed by either the buffered
/// (`run_action`) or the streaming (`run_action_streaming`) tail — so both share
/// the EXACT same gate (no streaming-specific enforcement drift).
enum PreparedAction {
    /// Gated on human approval; nothing ran.
    Pending(Box<ApprovalRequest>),
    /// Passed every gate; carries everything an action tail needs to run.
    Ready(Box<ReadyAction>),
}

/// A resolved, gate-passed action ready for its side-effecting tail.
struct ReadyAction {
    credential: Credential,
    plugin_name: String,
    action_name: String,
    params: serde_json::Value,
    context: RequestContext,
    use_token_id: Option<String>,
}

/// Metering attribution captured before `context`/`credential` move into the
/// plugin request, so the streamed-stream finalizer can emit the V13a/V13b
/// `meter.observed` events after the stream ends — the same subject/timestamp the
/// buffered path uses (see [`emit_meter`]).
#[derive(Clone)]
struct MeterAttribution {
    request_id: String,
    /// V4 principal: agent label, else key/token id, else credential alias.
    principal: String,
    /// The action's request timestamp (leria's bucketing clock).
    occurred_at: chrono::DateTime<chrono::Utc>,
    /// V11 tenant tag (the credential's tenant, which must match the principal's).
    tenant: Option<String>,
    credential_alias: String,
    provider: Option<String>,
    region: Option<String>,
    channel: Option<String>,
}

/// A gate-passed streaming execution: the response head (status + already-scrubbed
/// headers) plus the scrubbed body stream the web layer wraps in an axum
/// `Body::from_stream`.
pub struct StreamingExecution {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: ScrubbedBodyStream,
}

/// Streaming analogue of [`ExecutionOutcome`]: a started stream, or a pending
/// approval (an LLM call routed to approval did not run — surfaced honestly).
pub enum StreamingOutcome {
    Streaming(StreamingExecution),
    Pending(Box<ApprovalRequest>),
}

/// Emit the V13a `api-calls=1` meter event (always) and — when a token-usage split
/// is known — the V13b priced token event, for a metered action. A free async fn
/// over the outbox (`storage`) handle so it can run from BOTH the buffered
/// `run_action` tail and the streaming finalizer (which outlives `run_action`'s
/// frame and so can't borrow `&self`); the two paths therefore emit identical
/// payloads via the same builders. Best-effort, exactly like
/// [`VultrinoServer::emit_event`] — a metering/outbox hiccup never fails the action.
async fn emit_meter(
    storage: &Arc<dyn StorageBackend>,
    attr: &MeterAttribution,
    usage: Option<crate::outbox::TokenUsage>,
    model: Option<&str>,
) {
    let add_dimensions = |mut payload: serde_json::Value| {
        if let Some(dims) = payload
            .get_mut("dims")
            .and_then(serde_json::Value::as_object_mut)
        {
            for (name, value) in [
                ("provider", attr.provider.as_ref()),
                ("region", attr.region.as_ref()),
                ("channel", attr.channel.as_ref()),
            ] {
                if let Some(value) = value {
                    dims.insert(name.to_string(), serde_json::Value::String(value.clone()));
                }
            }
        }
        payload
    };
    // V13a: exactly one api-calls=1 observation for the admitted+executed call.
    if let Err(e) = storage
        .append_event(
            &attr.principal,
            crate::outbox::EVENT_METER_OBSERVED,
            add_dimensions(crate::outbox::meter_observed_payload(
                &attr.request_id,
                &attr.principal,
                attr.occurred_at,
                attr.tenant.as_deref(),
                &attr.credential_alias,
                None,
            )),
        )
        .await
    {
        warn!(error = %e, "failed to append V13a meter event");
    }

    // V13b: the priced token event (asset=usd + tokens split), only when a usage
    // split was parsed (a streamed turn with no usage trailer emits V13a only).
    if let Some(usage) = usage {
        if let Err(e) = storage
            .append_event(
                &attr.principal,
                crate::outbox::EVENT_METER_OBSERVED,
                add_dimensions(crate::outbox::meter_tokens_payload(
                    &attr.request_id,
                    &attr.principal,
                    attr.occurred_at,
                    attr.tenant.as_deref(),
                    &attr.credential_alias,
                    model,
                    usage,
                )),
            )
            .await
        {
            warn!(error = %e, "failed to append V13b token meter event");
        }
    }
}

/// Wrap a fully-buffered (and already egress-scrubbed) [`ExecuteResponse`] as a
/// single-chunk [`StreamingExecution`]. Used when a `stream:true` request must be
/// served buffered — an operator block/redact egress rule applies, so incremental
/// scrub can't honor it. Framing headers are stripped (axum frames from the bytes).
fn buffered_as_stream(resp: ExecuteResponse) -> StreamingExecution {
    let ExecuteResponse {
        status,
        mut headers,
        body,
        ..
    } = resp;
    headers.retain(|k, _| {
        !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")
    });
    let chunk = Bytes::from(body);
    StreamingExecution {
        status,
        headers,
        body: Box::pin(futures::stream::once(async move {
            Ok::<Bytes, std::io::Error>(chunk)
        })),
    }
}

/// Emits the metering events for a streamed call EXACTLY ONCE, on whichever of two
/// paths wins (connector M1, V13b on streams):
/// - **clean end / in-band error:** the adaptor calls [`Self::finalize`] with the
///   parsed usage (a complete trailer) or `None` (a truncated turn with no trailer →
///   V13a only).
/// - **client disconnect / panic:** the adaptor's generator future is dropped
///   mid-await so `finalize` never runs; `Drop` then spawns the emit (a sync `Drop`
///   can't await, hence the detached task). It emits V13b when a complete usage
///   trailer was already parsed and recorded via [`Self::record_usage`] BEFORE the
///   disconnect (so a disconnect right after the trailer doesn't under-count),
///   otherwise V13a-only.
///
/// An `AtomicBool` makes the two paths mutually exclusive, so V13a fires once and
/// only once for the call.
struct StreamFinalizer {
    storage: Arc<dyn StorageBackend>,
    attribution: MeterAttribution,
    emitted: std::sync::atomic::AtomicBool,
    /// The most-recent COMPLETE usage trailer parsed from the stream (+ resolved
    /// model), recorded each chunk by the generator. Read by `Drop` so a client
    /// disconnect AFTER the trailer arrived still meters V13b. `None` until a complete
    /// split is seen.
    carried: parking_lot::Mutex<Option<(crate::outbox::TokenUsage, Option<String>)>>,
}

impl StreamFinalizer {
    fn new(storage: Arc<dyn StorageBackend>, attribution: MeterAttribution) -> Self {
        Self {
            storage,
            attribution,
            emitted: std::sync::atomic::AtomicBool::new(false),
            carried: parking_lot::Mutex::new(None),
        }
    }

    /// Record the latest COMPLETE usage trailer (from `UsageAccumulator::snapshot`) so a
    /// subsequent client disconnect before a terminus still emits V13b in `Drop` rather
    /// than under-counting to V13a-only. Cheap; called once per chunk that completes the
    /// split (idempotent thereafter — last value wins).
    fn record_usage(&self, usage: crate::outbox::TokenUsage, model: Option<String>) {
        *self.carried.lock() = Some((usage, model));
    }

    /// Emit the meter events inline at a known stream terminus. `usage` is `Some` when a
    /// complete token split was parsed (a clean EOF, OR a non-clean terminus that still
    /// had the full trailer); a genuinely partial stream passes `None` (V13a only).
    async fn finalize(&self, usage: Option<crate::outbox::TokenUsage>, model: Option<String>) {
        if self.emitted.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        emit_meter(&self.storage, &self.attribution, usage, model.as_deref()).await;
    }
}

impl Drop for StreamFinalizer {
    fn drop(&mut self) {
        // Disconnect/panic before a terminus: emit via a detached task (Drop can't
        // await). No-op if finalize() already emitted. If a complete usage trailer was
        // recorded before the disconnect, emit V13b (usage); else V13a-only.
        if !self.emitted.swap(true, std::sync::atomic::Ordering::SeqCst) {
            // Only spawn when a runtime is live: dropping the body during runtime
            // shutdown would make `tokio::spawn` panic. Metering is best-effort
            // (fail-open), so skipping the emit on shutdown is acceptable.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let storage = Arc::clone(&self.storage);
                let attribution = self.attribution.clone();
                let (usage, model) = match self.carried.lock().take() {
                    Some((u, m)) => (Some(u), m),
                    None => (None, None),
                };
                handle.spawn(async move {
                    emit_meter(&storage, &attribution, usage, model.as_deref()).await
                });
            }
        }
    }
}

/// Outbox delivery counters (observability item 4 / #3). Per-process,
/// in-memory (resets on restart) — the same idiom as
/// [`VultrinoServer::unauthorized_attempts`]. Held behind an `Arc` (rather than
/// as a plain field read only through `&VultrinoServer`) because the
/// background delivery loop (`deliver_outbox_once`/`deliver_outbox_periodically`)
/// is a free function spawned in `main.rs` from `storage` + `config` alone —
/// it runs before, and independently of, any `Arc<VultrinoServer>` wrapping —
/// so the counters are threaded to it explicitly via `VultrinoServer::outbox_metrics()`
/// rather than through `&self`.
#[derive(Default)]
pub struct OutboxMetrics {
    delivered: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    dead_lettered: std::sync::atomic::AtomicU64,
    /// Sequence of the most recently *successfully* delivered event. 0 (a
    /// sequence no real event ever has — sequences start at 1) until the first
    /// success.
    last_delivered_sequence: std::sync::atomic::AtomicU64,
}

/// Point-in-time snapshot of [`OutboxMetrics`] for the JSON metrics read-back.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct OutboxMetricsSnapshot {
    pub delivered: u64,
    pub failed: u64,
    pub dead_lettered: u64,
    pub last_delivered_sequence: u64,
}

impl OutboxMetrics {
    fn record_delivered(&self, sequence: u64) {
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_delivered_sequence
            .store(sequence, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_failed(&self) {
        self.failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_dead_lettered(&self) {
        self.dead_lettered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Snapshot the counters for the JSON `/api/v1/metrics` read-back.
    pub fn snapshot(&self) -> OutboxMetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        OutboxMetricsSnapshot {
            delivered: self.delivered.load(Relaxed),
            failed: self.failed.load(Relaxed),
            dead_lettered: self.dead_lettered.load(Relaxed),
            last_delivered_sequence: self.last_delivered_sequence.load(Relaxed),
        }
    }
}

/// Main Vultrino server
pub struct VultrinoServer {
    /// Configuration
    config: Config,
    /// Credential resolver
    resolver: CredentialResolver,
    /// Plugin registry
    plugins: Arc<PluginRegistry>,
    /// Policy engine
    policy_engine: Arc<PolicyEngine>,
    /// Storage backend
    storage: Arc<dyn StorageBackend>,
    /// Authentication manager
    auth_manager: Arc<AuthManager>,
    /// Whether authentication is required
    require_auth: bool,
    /// Action approval configuration
    approval_config: crate::approval::ApprovalConfig,
    /// Out-of-band approval notifiers (Telegram, webhook, ...)
    notifiers: Vec<Arc<dyn ApprovalNotifier>>,
    /// In-flight execution registry (V6).
    sessions: Arc<crate::session::SessionRegistry>,
    /// Registered harness abort callbacks, fired on halt (V6).
    halt_callbacks: parking_lot::RwLock<Vec<Arc<dyn crate::session::HaltCallback>>>,
    /// Count of unauthorized (policy/scope-denied) tool-call attempts (V12 metrics).
    /// Per-process, in-memory (resets on restart), like the rate-limit counters.
    unauthorized_attempts: std::sync::atomic::AtomicU64,
    /// Inbound workload-identity resolver (V10/R6): resolves an SVID/OIDC document
    /// presented in a configured request header into the principal evaluated by
    /// policy. `None` = no resolver wired.
    inbound_identity: Option<InboundIdentity>,
    /// Coalescing gate for the R3 `policy.denied` DETECT event: `subject -> last
    /// emit time`. A denial *storm* (e.g. a compromised agent hammering blocked
    /// calls) would otherwise turn every denial into a signed-outbox vault write
    /// under the cross-process lock; this bounds it to one durable detect event per
    /// subject per window. The always-on atomic counter still counts every attempt,
    /// and MTTD only needs the first detection in the window.
    detect_emit_gate: parking_lot::RwLock<std::collections::HashMap<String, std::time::Instant>>,
    /// Outbox delivery counters (observability item 4 / #3). `Arc`-shared with
    /// the free-standing `deliver_outbox_periodically` background loop (see
    /// [`OutboxMetrics`]'s doc) via [`Self::outbox_metrics`].
    outbox_metrics: Arc<OutboxMetrics>,
    /// averin seal-client (plan 086, the "fourth contract"). `None` unless
    /// `[averin] enabled = true`. When set, it is the SINGLE shared instance: its
    /// in-memory `token.id -> {capability, PoP key}` map is written by the mint
    /// hook (`api_create_token`, via [`Self::averin`]) and read by the execute
    /// hook in [`Self::run_action`], so both must go through this one client.
    /// Default-off: `None`, and both hooks are no-ops — `/execute` and mint stay
    /// byte-identical to today. See `docs/dev/averin-sealing.md`.
    averin: Option<Arc<crate::averin::AverinClient>>,
}

/// A wired inbound workload-identity resolver (V10/R6): the request header to
/// read the (already transport-verified) document from, plus the resolver that
/// maps it to a [`crate::identity::WorkloadIdentity`].
struct InboundIdentity {
    /// Lower-cased header name carrying the verified document/claims.
    header: String,
    resolver: Arc<dyn crate::identity::IdentityResolver>,
}

impl VultrinoServer {
    /// Create a new Vultrino server
    pub fn new(
        config: Config,
        storage: Arc<dyn StorageBackend>,
        resolver: CredentialResolver,
    ) -> Self {
        let plugins = Arc::new(PluginRegistry::new());
        let policy_engine = Arc::new(PolicyEngine::new());
        let auth_manager = Arc::new(AuthManager::new());

        // Load policies from config
        policy_engine.load_policies(config.policies.clone());

        // Wire the engine-level default decision (V2): fail-closed unless the
        // operator explicitly opts into legacy fail-open.
        let default_deny = matches!(
            config.enforcement.default_action,
            crate::config::EnforcementDefault::Deny
        );
        policy_engine.set_default_deny(default_deny);

        // Surface the two dangerous zero-policy postures loudly at startup,
        // since either is almost always a misconfiguration that would otherwise
        // be discovered only via behavior (a flood of denials, or — worse —
        // silent fail-open).
        if let Some(msg) =
            zero_policy_enforcement_warning(default_deny, !config.policies.is_empty())
        {
            warn!("{}", msg);
        }

        // By default, don't require auth in local mode
        let require_auth = config.server.mode == crate::config::ServerMode::Server;

        // Build approval subsystem from config
        let approval_config = config.approval.clone();
        let notifiers = crate::approval::build_notifiers(&approval_config);

        // Warn operators about approval configs that gate actions but can't
        // actually deliver a request to a human out of band.
        if approval_config.enabled {
            if notifiers.is_empty() {
                warn!(
                    "approvals are enabled with no notifier configured — pending requests are \
                     only visible via the web admin panel (`vultrino web`)"
                );
            } else if approval_config.public_base_url.is_none() {
                warn!(
                    "approvals have a notifier but no public_base_url — Telegram/webhook \
                     approve/deny links can't be built; approvals must be decided in the admin panel"
                );
            }
        }

        // V10/R6: build the inbound workload-identity resolver from config.
        let inbound_identity = config.identity.as_ref().map(|ic| {
            use crate::config::IdentityResolverKind;
            use crate::identity::{IdentityResolver, OidcResolver, SpiffeResolver};
            let resolver: Arc<dyn IdentityResolver> = match ic.kind {
                IdentityResolverKind::Spiffe => Arc::new(SpiffeResolver::new(ic.allowed.clone())),
                IdentityResolverKind::Oidc => Arc::new(OidcResolver::new(ic.allowed.clone())),
            };
            InboundIdentity {
                header: ic.header.clone(),
                resolver,
            }
        });

        // averin seal-client (plan 086). Built once here (before `config` moves
        // into Self) so the SAME instance — and its shared PoP map — backs both
        // the mint hook and the execute hook. `Ok(None)` when disabled (the
        // default) → no-op hooks; an init error disables it (never fails startup).
        let averin = match crate::averin::AverinClient::new(config.averin.clone()) {
            Ok(client) => client.map(Arc::new),
            Err(e) => {
                warn!(error = %e, "averin seal-client disabled: config invalid");
                None
            }
        };

        Self {
            config,
            resolver,
            plugins,
            policy_engine,
            storage,
            auth_manager,
            require_auth,
            approval_config,
            notifiers,
            sessions: Arc::new(crate::session::SessionRegistry::new()),
            halt_callbacks: parking_lot::RwLock::new(Vec::new()),
            unauthorized_attempts: std::sync::atomic::AtomicU64::new(0),
            inbound_identity,
            detect_emit_gate: parking_lot::RwLock::new(std::collections::HashMap::new()),
            outbox_metrics: Arc::new(OutboxMetrics::default()),
            averin,
        }
    }

    /// The averin seal-client, if `[averin] enabled = true`. `None` otherwise
    /// (the default). The mint hook in `api_create_token` calls this to seal a
    /// `POST /v2/grants` on token issuance; the execute hook uses `self.averin`
    /// directly. Returns a cheap `Arc` clone so the caller can `await` off it.
    pub fn averin(&self) -> Option<Arc<crate::averin::AverinClient>> {
        self.averin.clone()
    }

    /// Plan 087 FIX 2 — the SINGLE grant-before-issue seal for EVERY in-process mint
    /// surface (JSON admin API, web console, workload exchange). Centralizing it here
    /// means the token→PoP grant is recorded for a token minted on ANY of them, so its
    /// first `/execute` no longer seals `NoGrant` (Observe: a fail-open logged gap;
    /// RequireEvidence: consume-then-deny that burns the token). No-op unless `[averin]
    /// enabled = true` (`self.averin == None`), so mint stays byte-identical to today.
    /// Best-effort + fail-open (a seal failure NEVER fails the mint — a token is a
    /// vultrino artifact whose existence must not depend on averin's uptime).
    ///
    /// SYNCHRONOUS by design (mint is the control plane, not the `/execute` hot path):
    /// the grant record + PoP entry MUST be on record before the token is handed back,
    /// or the agent's first `/execute` could race ahead of the grant seal. The
    /// out-of-process **CLI** mint cannot populate THIS process's in-memory PoP map, so
    /// it warns instead of silently issuing an unsealed token — see
    /// `docs/dev/averin-sealing.md` §11.
    pub async fn seal_mint(&self, token: &UseToken) {
        if let Some(av) = &self.averin {
            let scope = token.credential_scope.clone();
            let action = token
                .action_scope
                .clone()
                .unwrap_or_else(|| "db.query:orders-ro".to_string());
            av.on_mint(&token.id, &scope, &action, token.max_uses).await;
        }
    }

    /// The inbound header to read a verified workload-identity document from, if a
    /// resolver is wired (V10/R6). Lower-cased for case-insensitive matching.
    pub fn identity_header(&self) -> Option<&str> {
        self.inbound_identity.as_ref().map(|i| i.header.as_str())
    }

    /// Resolve an inbound (already transport-verified) identity document into a
    /// [`crate::identity::WorkloadIdentity`] (V10/R6). Returns `None` when no
    /// resolver is wired or the document is malformed / untrusted (logged) — the
    /// caller then falls back to the static `vk_`/`vut_` principal (fail-safe: a
    /// bad document can't elevate, only fail to refine).
    pub fn resolve_identity(&self, document: &str) -> Option<crate::identity::WorkloadIdentity> {
        let inbound = self.inbound_identity.as_ref()?;
        match inbound.resolver.resolve(document) {
            Ok(id) => Some(id),
            Err(e) => {
                warn!(error = %e, "inbound workload-identity resolution failed — using static principal");
                None
            }
        }
    }

    /// Create a server with a custom auth manager (for loading from storage)
    pub fn with_auth_manager(mut self, auth_manager: AuthManager) -> Self {
        self.auth_manager = Arc::new(auth_manager);
        self
    }

    /// Set whether authentication is required
    pub fn with_require_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    /// Load all installed WASM plugins
    pub async fn load_plugins(&self) -> Result<(), VultrinoError> {
        use crate::plugins::{PluginInstaller, PluginLoader};

        let installer = PluginInstaller::default();
        let installed = installer.list().await.map_err(|e| {
            VultrinoError::Plugin(crate::plugins::PluginError::Installation(e.to_string()))
        })?;

        let loader = PluginLoader::default();

        for info in installed {
            if !info.enabled {
                continue;
            }

            match loader.load_plugin(&info.directory).await {
                Ok(plugin) => {
                    tracing::info!(plugin = %info.manifest.plugin.name, "Loaded plugin");
                    self.plugins.register(plugin);
                }
                Err(e) => {
                    tracing::warn!(plugin = %info.manifest.plugin.name, error = %e, "Failed to load plugin");
                }
            }
        }

        Ok(())
    }

    /// Execute a request through Vultrino (no authentication / local use).
    ///
    /// If the action requires approval, this returns a `202` response whose body
    /// describes the pending approval (see [`ExecutionOutcome::into_response`]).
    pub async fn execute(&self, request: ExecuteRequest) -> Result<ExecuteResponse, VultrinoError> {
        self.execute_with_auth(request, None).await
    }

    /// Execute a request with optional API-key authentication.
    ///
    /// Backwards-compatible wrapper that collapses the [`ExecutionOutcome`] into
    /// an [`ExecuteResponse`]. Callers that want to distinguish a pending
    /// approval from a completed action (e.g. the MCP layer) should call
    /// [`Self::execute_gated`] directly.
    pub async fn execute_with_auth(
        &self,
        request: ExecuteRequest,
        auth: Option<&AuthResult>,
    ) -> Result<ExecuteResponse, VultrinoError> {
        let exec_auth = match auth {
            Some(a) => ExecAuth::from_api_key(a.clone()),
            None => ExecAuth::default(),
        };
        Ok(self
            .execute_gated(request, exec_auth)
            .await?
            .into_response())
    }

    /// Run the full gating decision for a request **without** running the action.
    ///
    /// This is the single, shared gate: permission/scope checks, use-token
    /// credential+action scope, V11 tenant isolation, policy `evaluate_full`
    /// (URL/method/rate-limit/principal/spend), V12 dual-control, and approval
    /// gating. Both the buffered ([`Self::execute_gated`]) and the streaming
    /// ([`Self::execute_gated_streaming`]) entry points call this so streaming can
    /// **never** diverge from the buffered enforcement — only how the response body
    /// is fetched differs.
    ///
    /// Approval is required when **any** of these hold:
    /// - the credential is flagged with metadata `require_approval = "true"`,
    /// - a matching policy returns `Prompt`,
    /// - the auth context forces it (e.g. a use token with `require_approval`).
    ///
    /// When gated, the action does **not** run: an [`ApprovalRequest`] is created,
    /// persisted, and announced to notifiers, and [`PreparedAction::Pending`] is
    /// returned. Otherwise a [`PreparedAction::Ready`] carries everything the action
    /// tail needs — the use token is NOT consumed here, the tail reserves it
    /// fail-closed just before the side effect (identical on both paths).
    async fn prepare_execution(
        &self,
        request: ExecuteRequest,
        exec_auth: ExecAuth,
    ) -> Result<PreparedAction, VultrinoError> {
        let mut context = RequestContext::new();

        // Permission + scope checks (only when authenticated).
        if let Some(auth_result) = &exec_auth.auth {
            context = context.with_auth(auth_result);

            if !auth_result.has_permission(Permission::Execute) {
                return Err(VultrinoError::PolicyDenied(
                    "Missing 'execute' permission".to_string(),
                ));
            }
            if !auth_result.can_access_credential(&request.credential) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Access denied to credential: {}",
                    request.credential
                )));
            }
        }

        // Resolve credential and normalize the action. A govder action label
        // (V8) resolves to the canonical `plugin.action`; the label (if any) is
        // surfaced to the approver/audit.
        let credential = self.resolver.resolve(&request.credential).await?;
        let (canonical_action, action_label) = self.config.resolve_action(&request.action);
        let (plugin_name, action_name) = parse_action(&canonical_action)?;
        let full_action = format!("{}.{}", plugin_name, action_name);

        // Authoritative use-token scope enforcement at the seam where the token
        // is actually spent — both credential and action scope, so the token's
        // single-action restriction is defended in depth rather than only at the
        // (MCP/HTTP) edge. The action scope is satisfied by either the presented
        // form (which may be a govder label) or the resolved canonical action.
        if let Some(token) = &exec_auth.use_token {
            if !token.allows_credential(&credential.alias) {
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to credential '{}'",
                    credential.alias
                )));
            }
            if !token.allows_action(&request.action) && !token.allows_action(&full_action) {
                // Surface both forms when the presented action was a label, so
                // the diagnostic isn't confusing under a label-scoped token.
                let shown = if action_label.is_some() {
                    format!("'{}' (resolved to '{}')", request.action, full_action)
                } else {
                    format!("'{}'", full_action)
                };
                return Err(VultrinoError::PolicyDenied(format!(
                    "Use token is not scoped to action {}",
                    shown
                )));
            }
        }

        // V11 tenant isolation: a principal may only use credentials in its own
        // tenant; an untenanted credential is shared. A credential is tenant-tagged
        // via its `tenant` metadata. Cross-tenant access is denied regardless of
        // the tenant's enforce/observe mode (isolation is not observable-away).
        let principal_tenant = exec_auth
            .auth
            .as_ref()
            .and_then(|a| a.api_key.tenant.clone());
        // Trim the credential's tenant tag and treat blank as untenanted (shared),
        // symmetric with the trimmed-at-mint principal tenant.
        let cred_tenant = credential
            .metadata
            .get("tenant")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        if let Some(cred_tenant) = cred_tenant {
            if principal_tenant.as_deref() != Some(cred_tenant) {
                self.record_unauthorized_attempt();
                let reason = format!(
                    "credential '{}' belongs to tenant '{}' and is not accessible to this principal",
                    credential.alias, cred_tenant
                );
                // R3: emit a timestamped DETECT event (see below) for this
                // cross-tenant isolation denial too.
                let ak = exec_auth.auth.as_ref().map(|a| &a.api_key);
                self.emit_policy_denied(
                    ak.and_then(|k| k.agent_label.as_deref()),
                    ak.map(|k| k.id.as_str()),
                    &credential.alias,
                    &full_action,
                    principal_tenant.as_deref(),
                    &reason,
                    "cross_tenant_isolation",
                )
                .await;
                return Err(VultrinoError::PolicyDenied(reason));
            }
        }

        // Evaluate policy (URL / method / rate limits / principal / spend). A
        // `Prompt` decision routes into the approval flow rather than failing.
        let url = request.params.get("url").and_then(|v| v.as_str());
        let method = request.params.get("method").and_then(|v| v.as_str());
        // V4: the resolved principal (key/token id + agent label) for
        // principal_pattern matching.
        let principal = exec_auth.auth.as_ref().map(|a| crate::policy::Principal {
            id: a.api_key.id.clone(),
            agent_label: a.api_key.agent_label.clone(),
            // V10: the IdP-resolvable human owner of this NHI, when bound.
            owner: a.api_key.owner_identity.clone(),
            // V10/R6: a resolved inbound SVID/OIDC subject, as an ADDITIONAL match
            // dimension — it never replaces `id`, so a halt keyed on the credential
            // id/label still holds when a workload identity is presented.
            workload_id: a.api_key.workload_id.clone(),
        });
        // V3: the extracted spend attempt (amount + asset) for SpendCap.
        let spend = crate::policy::extract_spend(
            &self.config.spend_extractors,
            &full_action,
            &credential.alias,
            &request.params,
        );
        let eval_input = crate::policy::EvalInput {
            credential_alias: &credential.alias,
            url,
            method,
            // The business action label (V8) for the connector ActionMatch dimension.
            action: Some(request.action.as_str()),
            principal: principal.as_ref(),
            spend: spend.as_ref(),
        };
        let decision = self.policy_engine.evaluate_full(&eval_input);

        // V12: a dual-control token forces the action through the approval flow
        // (M-of-N), even when policy would Allow it and the credential doesn't
        // require approval — dual control must not be bypassable on the Allow path.
        let dual_control = exec_auth
            .use_token
            .as_ref()
            .map(|t| t.dual_control)
            .unwrap_or(false);
        let mut needs_approval = exec_auth.force_approval || dual_control;
        match decision {
            crate::policy::PolicyDecision::Allow => {}
            crate::policy::PolicyDecision::Deny(reason) => {
                self.record_unauthorized_attempt();
                // V11 observe mode: an observe-only tenant's denials are recorded
                // and emitted but NOT blocked — the action runs anyway, so a team
                // can onboard in observe-only while another enforces on the same
                // vultrino. NEVER downgraded (security/financial boundaries hold
                // even in observe): cross-tenant isolation (above), a V6 halt/kill
                // switch, and SpendCap/RateLimit resource guards.
                if self.config.tenant_mode(principal_tenant.as_deref())
                    == crate::config::TenantMode::Observe
                    && !self.policy_engine.is_halted(&eval_input)
                    && !self.policy_engine.has_resource_guard(&eval_input)
                {
                    warn!(
                        tenant = ?principal_tenant,
                        credential = %credential.alias,
                        action = %full_action,
                        reason = %reason,
                        "observe-mode: policy would DENY but tenant is observe-only — allowing"
                    );
                    self.emit_event(
                        principal_tenant.as_deref().unwrap_or("-"),
                        crate::outbox::EVENT_POLICY_OBSERVED_DENIAL,
                        serde_json::json!({
                            "tenant": principal_tenant,
                            "credential": credential.alias,
                            "action": full_action,
                            "reason": reason,
                            "would_have": "deny",
                            "outcome": "allowed_observe_mode",
                        }),
                    )
                    .await;
                    // Fall through to Allow (do not return, do not gate).
                } else {
                    // R3 (V12a): emit a timestamped DETECT event for the enforce-mode
                    // denial — the headline path that previously only bumped a
                    // counter. Its created_at is a per-incident detected_at, paired
                    // (same subject) with a later agent.halted contained_at for MTTD.
                    self.emit_policy_denied(
                        principal.as_ref().and_then(|p| p.agent_label.as_deref()),
                        principal.as_ref().map(|p| p.id.as_str()),
                        &credential.alias,
                        &full_action,
                        principal_tenant.as_deref(),
                        &reason,
                        "policy",
                    )
                    .await;
                    return Err(VultrinoError::PolicyDenied(reason));
                }
            }
            crate::policy::PolicyDecision::Prompt => {
                needs_approval = true;
            }
        }

        // Credential-level opt-in: `vultrino meta set <cred> require_approval true`.
        if credential
            .metadata
            .get("require_approval")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            needs_approval = true;
        }

        if needs_approval {
            if !self.approval_config.enabled {
                return Err(VultrinoError::PolicyDenied(
                    "This action requires human approval, but approvals are not enabled on this \
                     Vultrino instance"
                        .to_string(),
                ));
            }

            // Open an approval request. The use token is NOT consumed yet — it is
            // reserved when the approved action actually runs. The criticality
            // class (V5) drives the escalation/expiry SLA windows.
            let criticality = self
                .approval_config
                .criticality_for(&credential.alias, &full_action);
            let sla = self.approval_config.sla_for(criticality);
            // V10: record the requester's IdP-resolvable owner (if bound) on the
            // approval so separation-of-duty compares the approver against the
            // directory owner, not just the agent label.
            let mut requester = exec_auth.requester.clone();
            if requester.owner.is_none() {
                requester.owner = principal.as_ref().and_then(|p| p.owner.clone());
            }
            let trusted_irreversible = self
                .trusted_irreversible_for_action(&full_action, action_label.as_deref())
                .await;
            // Extract the capability's declared approval-preview fields from the
            // SAME params that will execute (never a separate/mutable copy), so
            // the approver sees exactly what will run. None when the backing
            // capability declares no `approval_preview` spec (unchanged fallback
            // to `summary`).
            let preview = self
                .approval_preview_for_action(&full_action, action_label.as_deref(), &request.params)
                .await;
            let (mut approval, decision_token) = ApprovalRequest::open(NewApproval {
                credential: credential.alias.clone(),
                action: full_action.clone(),
                params: request.params.clone(),
                requester,
                use_token_id: exec_auth.use_token.as_ref().map(|t| t.id.clone()),
                principal_id: principal.as_ref().map(|p| p.id.clone()),
                agent_label: principal.as_ref().and_then(|p| p.agent_label.clone()),
                // R4: partition approval visibility/decision by the opener's tenant.
                tenant: principal_tenant.clone(),
                // R6: snapshot the resolved workload identity for resume re-eval.
                workload_id: principal.as_ref().and_then(|p| p.workload_id.clone()),
                preview,
                action_label: action_label.clone(),
                dual_control,
                criticality,
                trusted_irreversible: Some(trusted_irreversible),
                escalate_after: sla.escalate_after(),
                escalate_window: sla.escalate_window(),
                oob_identity: self.approval_config.oob_approver_identity.clone(),
                reauth_interval_secs: self.approval_config.reauth_interval_secs,
                // V12: dual control requires a second distinct approver (M-of-N,
                // M defaulting to 2). A single-approval request needs just one.
                required_approvals: if dual_control {
                    self.approval_config.dual_control_approvers.max(2)
                } else {
                    1
                },
            });
            // Spend is extracted by the trusted policy layer above. Stamp it only
            // after opening so requester-authored params can never supply these
            // grant-cap facts.
            approval.trusted_spend_amount_minor = spend
                .as_ref()
                .map(|s| i64::try_from(s.amount).unwrap_or(i64::MAX));
            approval.trusted_spend_asset = spend.as_ref().map(|s| s.asset.clone());

            // Bound the number of *pending* approvals a use token can open: each
            // open reserves a future use, so outstanding pending approvals plus
            // already-consumed uses must not exceed max_uses — otherwise a
            // single-use token could spawn an unbounded approval/notifier flood
            // (only execution is fail-closed otherwise). The count-and-insert is
            // atomic under the storage lock, so two concurrent opens (web + MCP)
            // can't both pass a stale count.
            let reservation = exec_auth
                .use_token
                .as_ref()
                .and_then(|t| t.max_uses.map(|max| (t.id.clone(), max)));
            match reservation {
                Some((token_id, max)) => {
                    self.storage
                        .store_approval_reserving(&approval, &token_id, max)
                        .await
                        .map_err(|e| match e {
                            crate::storage::StorageError::Conflict(_) => VultrinoError::PolicyDenied(
                                "This use token has no remaining capacity for a new pending approval".to_string(),
                            ),
                            other => other.into(),
                        })?;
                }
                None => self.storage.store_approval(&approval).await?,
            }
            self.dispatch_notifications(&approval, &decision_token)
                .await;
            // V9: emit the requested event to the signed outbox.
            self.emit_event(
                &approval.id,
                crate::outbox::EVENT_APPROVAL_REQUESTED,
                serde_json::json!({
                    "approval_id": approval.id,
                    "credential": approval.credential,
                    "action": approval.action,
                    "summary": approval.summary,
                    "requested_by": approval.requester.describe(),
                    "criticality": approval.criticality.to_string(),
                    // V11/R4: per-approval tenant on first-sight so govder routes to the
                    // named Owner (webhook.go newRecord). None → null (untenanted/shared).
                    "tenant": approval.tenant,
                }),
            )
            .await;

            info!(
                approval_id = %approval.id,
                credential = %credential.alias,
                action = %full_action,
                "Action gated on human approval"
            );

            return Ok(PreparedAction::Pending(Box::new(approval)));
        }

        // Passed every gate. Hand the resolved action to the caller's tail — the
        // buffered `run_action` (via `execute_gated`) or the streaming
        // `run_action_streaming` (via `execute_gated_streaming`). The use token is
        // NOT consumed here; the tail reserves it fail-closed just before the side
        // effect, identical on both paths.
        Ok(PreparedAction::Ready(Box::new(ReadyAction {
            credential,
            plugin_name: plugin_name.to_string(),
            action_name: action_name.to_string(),
            params: request.params.clone(),
            context,
            use_token_id: exec_auth.use_token.as_ref().map(|t| t.id.clone()),
        })))
    }

    /// Execute a request, gating it on human approval when required (buffered).
    ///
    /// Thin tail over [`Self::prepare_execution`]: gate, then either return the
    /// pending approval or run the action whole via [`Self::run_action`]. This is
    /// the original `execute_gated` behavior and signature, unchanged for callers.
    pub async fn execute_gated(
        &self,
        request: ExecuteRequest,
        exec_auth: ExecAuth,
    ) -> Result<ExecutionOutcome, VultrinoError> {
        match self.prepare_execution(request, exec_auth).await? {
            PreparedAction::Pending(approval) => Ok(ExecutionOutcome::Pending(approval)),
            PreparedAction::Ready(ready) => {
                let ReadyAction {
                    credential,
                    plugin_name,
                    action_name,
                    params,
                    context,
                    use_token_id,
                } = *ready;
                let response = self
                    .run_action(
                        credential,
                        &plugin_name,
                        &action_name,
                        params,
                        context,
                        use_token_id.as_deref(),
                    )
                    .await
                    .map_err(|re| re.error)?;
                Ok(ExecutionOutcome::Completed(response))
            }
        }
    }

    /// Plan 087 FIX 1 — the SHARED averin use-seal hook for BOTH the buffered
    /// ([`Self::run_action`]) and streaming ([`Self::run_action_streaming`]) execute
    /// paths. Called AFTER the use token is consumed (the point of no return) and
    /// BEFORE `plugin.execute*`, so a `stream: true` request gets exactly the seal a
    /// buffered one does — the two paths cannot drift.
    ///
    /// - `Observe` (default): fire-and-forget off the hot path via `spawn_use_seal`
    ///   (bounded fan-out, dropped fail-open on saturation). Returns `Ok(())` ALWAYS,
    ///   so the action always proceeds — an averin outage never stalls or fails it.
    /// - `RequireEvidence` (opt-in, per-resource): AWAIT the seal; on failure return
    ///   `Err` so the caller DENIES the action before any side effect (buffered:
    ///   returns the error; streaming: denies BEFORE the SSE body opens). This closes
    ///   the strict-mode fail-OPEN hole the streaming path previously had.
    ///
    /// Callers reach this only inside `if let (Some(av), Some(tid)) = (&self.averin,
    /// use_token_id)`, so `[averin] enabled = false` (the default) skips it — and the
    /// `params_bytes` serialization — entirely, keeping the default-off path
    /// byte-identical. Takes OWNED `params_bytes` (FIX 3b): the buffer moves into the
    /// seal instead of being copied again.
    ///
    /// Plan 088 D5c — `use_sequence_number` (the `consume_use_token` post-increment `uses`,
    /// 1-based) and `request_id` are threaded through here from both call sites so they are
    /// available at the ONE hook both execute paths share, ready for the durable enqueue
    /// (`Step 5`, not wired yet — this step only carries the values, matching the
    /// `let _ = (grant_id, agent_pubkey)` reserved-field idiom already used in
    /// `crate::averin::AverinClient::seal_use`). Neither the Observe fire-and-forget nor the
    /// RequireEvidence synchronous seal reads them today: both still call
    /// `spawn_use_seal`/`on_execute` exactly as before, so the `durable = false` (087) wire
    /// body is unaffected.
    async fn seal_after_consume(
        &self,
        av: &crate::averin::AverinClient,
        token_id: &str,
        params_bytes: Vec<u8>,
        use_sequence_number: u32,
        request_id: &str,
    ) -> Result<(), RunError> {
        // Reserved for the plan 088 Step 5 durable enqueue (D5c's use_sequence_number + D5b's
        // per-execute idempotency key); this step only threads them this far.
        let _ = (use_sequence_number, request_id);
        match av.mode() {
            crate::averin::AverinMode::Observe => {
                av.spawn_use_seal(token_id, params_bytes);
                Ok(())
            }
            crate::averin::AverinMode::RequireEvidence => {
                av.on_execute(token_id, params_bytes).await.map_err(|e| {
                    RunError::terminal(VultrinoError::PolicyDenied(format!(
                        "averin evidence seal required but failed (require_evidence): {e}"
                    )))
                })
            }
        }
    }

    /// Run a plugin action against a resolved credential.
    ///
    /// This is the shared core invoked both by the immediate path
    /// ([`Self::execute_gated`]) and the deferred path after approval
    /// ([`Self::resume_approved`]). It does **not** evaluate approval policy —
    /// that decision has already been made by the caller.
    ///
    /// Ordering matters: the plugin is resolved and params validated *before*
    /// the use token is consumed, so a not-loaded plugin or bad params never
    /// burns a use. The token is then reserved (fail-closed) immediately before
    /// `plugin.execute`, which is the point of no return. Errors are tagged with
    /// [`RunError::committed`] so a caller resuming an approval can tell a
    /// retryable preflight failure from a terminal post-side-effect one.
    async fn run_action(
        &self,
        credential: Credential,
        plugin_name: &str,
        action_name: &str,
        params: serde_json::Value,
        context: RequestContext,
        use_token_id: Option<&str>,
    ) -> Result<ExecuteResponse, RunError> {
        // Preflight (no side effects yet, no token consumed): resolve + validate.
        // A not-loaded plugin is *transient* (it may load later → retryable);
        // invalid params are *permanent* (a retry can't fix them → terminal).
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
            RunError::retryable(VultrinoError::Plugin(
                crate::plugins::PluginError::NotFound(plugin_name.to_string()),
            ))
        })?;
        plugin
            .validate_params(action_name, &params)
            .map_err(|e| RunError::terminal(e.into()))?;

        // Reserve the use token atomically, fail-closed, just before the side
        // effect. A failure here (exhausted/expired/revoked) means nothing ran
        // AND the token will never become usable, so it is terminal — a resumed
        // approval finalizes with the error rather than retrying forever.
        //
        // Plan 088 D5c — CAPTURE the post-increment `uses` (1-based: the token's first
        // execute consumes `uses == 1`, its second `uses == 2`, …) instead of discarding it:
        // this is the authoritative `use_sequence_number` a bounded-reuse (`--uses N`)
        // capability's durable seal must carry (averin requires it in `[1, use_limit]`,
        // `resourceshim.go:233-259`). Defaults to 0 (never read) when there is no use token.
        let mut use_sequence_number: u32 = 0;
        if let Some(tid) = use_token_id {
            let consumed = self.storage.consume_use_token(tid).await.map_err(|e| {
                RunError::terminal(VultrinoError::PolicyDenied(format!(
                    "Use token cannot be used: {}",
                    e
                )))
            })?;
            use_sequence_number = consumed.uses;
        }

        let request_id = context.request_id.clone();
        let credential_id = credential.id.clone();
        let credential_alias = credential.alias.clone();
        let credential_metadata = credential.metadata.clone();
        let credential_created_at = credential.created_at;
        // V13a: capture the metering attribution before `context`/`credential`
        // move into the plugin request. `principal` is the V4 agent_label falling
        // back to the vk_/vut_ id, then the credential alias as a last resort
        // (the same subject the outbox uses). `occurred_at` is the action's
        // request timestamp (leria's bucketing clock). `meter_tenant` is the
        // credential's V11 tenant tag (which, when set, must match the principal's
        // tenant — enforced above — so it is the action's tenant).
        let meter_principal = context
            .agent_label
            .clone()
            .or_else(|| context.api_key_id.clone())
            .unwrap_or_else(|| credential_alias.clone());
        let meter_occurred_at = context.timestamp;
        let meter_tenant = credential_metadata
            .get("tenant")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        // V13b: capture the request-side `model` (if any) before `params` moves
        // into the plugin request. The model selects leria's rate card; we prefer
        // the model the provider echoes in the RESPONSE (parsed below, pre-scrub),
        // falling back to this request-side value.
        let meter_request_model = params
            .get("body")
            .and_then(|b| b.get("model"))
            .or_else(|| params.get("model"))
            .and_then(|m| m.as_str())
            .map(str::to_string);
        let meter_provider = params
            .get("_feir_provider")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let meter_region = params
            .get("_feir_region")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let meter_channel = params
            .get("_feir_channel")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // Capture the credential's secret material before it moves into the
        // plugin request, so we can scrub it from the response (V7 egress).
        let secret_material = credential.data.secret_material();
        let full_action = format!("{}.{}", plugin_name, action_name);

        // V6: record this execution as in-flight for the duration of the action
        // (and egress). The RAII guard deregisters on drop — including on error
        // or panic — so the registry reflects only genuinely running work, and a
        // halt can see what an agent is doing and fire its abort callbacks.
        // Buffered execution ignores the abort handle (a single buffered
        // plugin.execute isn't chunk-interruptible; halt's token-revoke + kill-policy
        // legs still apply). The streaming path uses it (run_action_streaming).
        let (_session, _abort) = self.sessions.begin(crate::session::SessionEntry {
            session_id: request_id.clone(),
            agent_label: context.agent_label.clone(),
            principal_id: context.api_key_id.clone(),
            token_id: use_token_id.map(|s| s.to_string()),
            credential: credential_alias.clone(),
            action: full_action.clone(),
            started_at: chrono::Utc::now(),
        });

        // averin seal (plan 086/087, the "fourth contract"): a use receipt sealed
        // into averin's tamper-evident DAG. Default-off (`self.averin == None`) →
        // skipped ENTIRELY, so with `[averin] enabled = false` (the production
        // default) `/execute` is byte-identical to today. Fail-mode is the client's:
        //
        //   - Observe (fail-open, the default): plan 087 makes this ASYNC and OFF
        //     the hot path. `spawn_use_seal` fires-and-forgets the `POST /v2/use`
        //     so `plugin.execute` NEVER waits on averin; the fan-out is bounded
        //     (`max_inflight_seals`) and dropped fail-open on saturation, and a
        //     failed/dropped seal alarms (AVERIN-SEAL-FAILED/DROPPED) and is
        //     independently detected by plan 085. `plugin.execute` proceeds
        //     regardless — an averin outage cannot stall or fail a governed action.
        //
        //   - RequireEvidence (fail-closed, opt-in per-resource only): SYNCHRONOUS
        //     by design — we await the seal BEFORE `plugin.execute` (the point of
        //     no return) and block the action if it fails. Consume-before-seal
        //     caveat (unchanged, out of scope for 087): the vut_ token was already
        //     consumed above, so a strict block here burns it; fixing that ordering
        //     is a separate change. This caveat is UNREACHABLE in the default
        //     (Observe) posture because the async path never blocks.
        if let (Some(av), Some(tid)) = (&self.averin, use_token_id) {
            let params_bytes = serde_json::to_vec(&params).unwrap_or_default();
            // Plan 087 FIX 1 — the mode-dependent seal hook now lives in ONE shared
            // helper so the buffered and streaming execute paths cannot drift. In
            // RequireEvidence a seal failure returns Err and DENIES the action here
            // (before `plugin.execute` — the point of no return). Plan 088 D5c threads
            // this execute's `use_sequence_number` + `request_id` through too.
            self.seal_after_consume(av, tid, params_bytes, use_sequence_number, &request_id)
                .await?;
        }

        let plugin_request = crate::plugins::PluginRequest {
            credential,
            action: action_name.to_string(),
            params,
            context,
        };

        // Point of no return: the action may now have side effects.
        let mut response = plugin
            .execute(plugin_request)
            .await
            .map_err(|e| RunError::committed(e.into()))?;

        // V13b (leria metering, token counts): read the provider usage block from
        // the RAW response body NOW — BEFORE `scrub_response` (below) redacts /
        // withholds / replaces it. Reading post-scrub would see redacted bytes and
        // UNDER-COUNT, and under-counting is the dangerous direction (a low count
        // keeps leria's cumulative ceiling below its limit → budgets never fire →
        // unbounded spend). The *emit* still happens post-scrub at the V13a hook;
        // only this *read* must precede scrub. Best-effort, counts + model only —
        // no prompt/body/secret retained. v1 limitation: non-streamed responses
        // only (a streamed response without a usage trailer yields None → only the
        // V13a api-calls=1 event fires for that call). A non-LLM action (no `usage`
        // block) likewise yields None.
        let meter_token_usage = crate::outbox::parse_token_usage(&response.body);
        let meter_model = meter_token_usage.and_then(|_| {
            crate::outbox::extract_model(&response.body, &serde_json::Value::Null)
                .or_else(|| meter_request_model.clone())
        });

        // V7 egress controls (before the body ever reaches the agent): fail
        // closed on a still-compressed body, else scrub the credential's own
        // reflected secret and apply operator egress classification, dropping
        // stale framing if the body changed. See `egress::scrub_response`.
        crate::egress::scrub_response(
            &mut response,
            &secret_material,
            &credential_alias,
            &self.config.egress,
            &full_action,
        );

        // Persist any credential update (e.g. OAuth2 token refresh).
        if let Some(updated_data) = &response.updated_credential {
            let updated_credential = crate::Credential {
                id: credential_id,
                alias: credential_alias.clone(),
                credential_type: updated_data.credential_type(),
                data: updated_data.clone(),
                metadata: credential_metadata,
                created_at: credential_created_at,
                updated_at: chrono::Utc::now(),
            };

            if let Err(e) = self.storage.store(&updated_credential).await {
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Failed to persist updated credential (token refresh)"
                );
            }
            // V7/V9: emit an observable rotation event to the signed outbox so a
            // govder subscriber sees in-path token rotation.
            info!(
                event = "credential.rotated",
                credential = %credential_alias,
                credential_type = %updated_data.credential_type(),
                request_id = %request_id,
                "credential rotated in-path (e.g. OAuth2 token refresh)"
            );
            self.emit_event(
                &credential_alias,
                crate::outbox::EVENT_CREDENTIAL_ROTATED,
                serde_json::json!({
                    "credential": credential_alias,
                    "credential_type": updated_data.credential_type().to_string(),
                }),
            )
            .await;
        }

        // V13a/V13b (leria metering): this action was ADMITTED + executed. Emit the
        // V13a `api-calls=1` event (always) and — when the RAW pre-scrub body carried
        // a parseable provider usage block — the V13b priced token event, via the
        // SHARED [`emit_meter`] (the streaming path emits the same payloads through
        // the same builders, so the two can't drift). Best-effort: an outbox hiccup
        // must not fail the action. `meter_token_usage` was read pre-scrub above;
        // `meter_*` attribution was captured before `context`/`credential` moved.
        let attribution = MeterAttribution {
            request_id: request_id.clone(),
            principal: meter_principal,
            occurred_at: meter_occurred_at,
            tenant: meter_tenant,
            credential_alias: credential_alias.clone(),
            provider: meter_provider,
            region: meter_region,
            channel: meter_channel,
        };
        emit_meter(
            &self.storage,
            &attribution,
            meter_token_usage,
            meter_model.as_deref(),
        )
        .await;

        // NOTE: rate-limit slots are charged ONCE at admission — the live policy
        // evaluation (evaluate_full, record=true) calls check_rate_limit when a
        // RateLimit condition matches. A second post-execution record_request here
        // double-charged every successful call (a max=2 policy then admitted only
        // one immediate call, and approval-resumed actions were charged twice).
        // The admission-time charge is authoritative; do not re-charge here.
        // (Codex pass 4.)

        info!(
            request_id = %request_id,
            credential = %credential_alias,
            action = %format!("{}.{}", plugin_name, action_name),
            status = response.status,
            "Request executed"
        );

        Ok(response)
    }

    /// Execute a request, gating it on approval, with the response body delivered
    /// **incrementally** (connector M1, streaming LLM proxy).
    ///
    /// Identical gate to [`Self::execute_gated`] (via the shared
    /// [`Self::prepare_execution`]); only the action tail differs — it runs
    /// [`Self::run_action_streaming`] instead of `run_action`. An approval-gated
    /// request returns [`StreamingOutcome::Pending`] *before any upstream byte is
    /// fetched* (the surface that must never open an SSE body before the gate).
    pub async fn execute_gated_streaming(
        &self,
        request: ExecuteRequest,
        exec_auth: ExecAuth,
    ) -> Result<StreamingOutcome, VultrinoError> {
        match self.prepare_execution(request, exec_auth).await? {
            PreparedAction::Pending(approval) => Ok(StreamingOutcome::Pending(approval)),
            PreparedAction::Ready(ready) => {
                let ReadyAction {
                    credential,
                    plugin_name,
                    action_name,
                    params,
                    context,
                    use_token_id,
                } = *ready;
                let full_action = format!("{}.{}", plugin_name, action_name);
                // An operator `block`/`redact_patterns` egress rule on this
                // (credential, action) can't be honored incrementally, so serve
                // BUFFERED (full whole-body egress runs) as a single chunk — a safe,
                // documented fallback rather than a partial scrub.
                if !crate::egress::stream_is_egress_safe(
                    &self.config.egress,
                    &credential.alias,
                    &full_action,
                ) {
                    let response = self
                        .run_action(
                            credential,
                            &plugin_name,
                            &action_name,
                            params,
                            context,
                            use_token_id.as_deref(),
                        )
                        .await
                        .map_err(|re| re.error)?;
                    return Ok(StreamingOutcome::Streaming(buffered_as_stream(response)));
                }
                let exec = self
                    .run_action_streaming(
                        credential,
                        &plugin_name,
                        &action_name,
                        params,
                        context,
                        use_token_id.as_deref(),
                    )
                    .await
                    .map_err(|re| re.error)?;
                Ok(StreamingOutcome::Streaming(exec))
            }
        }
    }

    /// Streaming analogue of [`Self::run_action`]: same fail-closed preamble
    /// (preflight → consume use token → in-flight session begin), but the plugin
    /// returns a [`crate::StreamingResponse`] and the body is forwarded through an
    /// incremental egress scrub before reaching the agent.
    ///
    /// The preamble (validate, consume use token, capture metering attribution) is
    /// identical to `run_action`; only the post-plugin half diverges. The
    /// [`crate::session::SessionGuard`] is **moved into the returned stream** so it
    /// lives until the last byte (the V6 registry reflects genuinely live streams).
    /// The V13a meter event is emitted from the stream finalizer (so a streamed call
    /// still meters), via the shared [`emit_meter`]. (Streamed V13b token counts,
    /// `include_usage` injection, and per-session halt/abort + DoS caps are layered
    /// on in later phases.)
    async fn run_action_streaming(
        &self,
        credential: Credential,
        plugin_name: &str,
        action_name: &str,
        params: serde_json::Value,
        context: RequestContext,
        use_token_id: Option<&str>,
    ) -> Result<StreamingExecution, RunError> {
        // Preflight (no side effects, no token consumed): resolve + validate.
        let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
            RunError::retryable(VultrinoError::Plugin(
                crate::plugins::PluginError::NotFound(plugin_name.to_string()),
            ))
        })?;
        plugin
            .validate_params(action_name, &params)
            .map_err(|e| RunError::terminal(e.into()))?;

        // Reserve the use token atomically, fail-closed, BEFORE the first byte —
        // the point of no return, identical to the buffered path.
        //
        // Plan 088 D5c — CAPTURE the post-increment `uses` (the authoritative
        // `use_sequence_number`), identical to `run_action`'s capture (see the comment
        // there); defaults to 0 (never read) when there is no use token.
        let mut use_sequence_number: u32 = 0;
        if let Some(tid) = use_token_id {
            let consumed = self.storage.consume_use_token(tid).await.map_err(|e| {
                RunError::terminal(VultrinoError::PolicyDenied(format!(
                    "Use token cannot be used: {}",
                    e
                )))
            })?;
            use_sequence_number = consumed.uses;
        }

        let request_id = context.request_id.clone();
        let credential_id = credential.id.clone();
        let credential_alias = credential.alias.clone();
        let credential_metadata = credential.metadata.clone();
        let credential_created_at = credential.created_at;
        // Metering attribution (captured before `context`/`credential` move into the
        // plugin request), identical derivation to the buffered path.
        let meter_principal = context
            .agent_label
            .clone()
            .or_else(|| context.api_key_id.clone())
            .unwrap_or_else(|| credential_alias.clone());
        let attribution = MeterAttribution {
            request_id: request_id.clone(),
            principal: meter_principal,
            occurred_at: context.timestamp,
            tenant: credential_metadata
                .get("tenant")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            credential_alias: credential_alias.clone(),
            provider: params
                .get("_feir_provider")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            region: params
                .get("_feir_region")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            channel: params
                .get("_feir_channel")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        // Capture the request-side model BEFORE `params` moves into the plugin
        // request, mirroring the buffered path. The streamed usage tap prefers the
        // model the provider echoes in the stream, but many streamed shapes omit a
        // top-level `model`; without this fallback V13b would emit no `dims.model_ref`
        // and leria would price the call CLOSED → token under-count (the dangerous
        // direction). The buffered path already falls back this way.
        let meter_request_model = params
            .get("body")
            .and_then(|b| b.get("model"))
            .or_else(|| params.get("model"))
            .and_then(|m| m.as_str())
            .map(str::to_string);
        // Capture the credential's secret material to scrub from the streamed body
        // + headers, before `credential` moves into the plugin request.
        let secret_material = credential.data.secret_material();
        let full_action = format!("{}.{}", plugin_name, action_name);

        // V6: register this stream as in-flight. The guard is MOVED into the stream
        // adaptor below so it deregisters when the stream ends (not at this fn's
        // return), making the registry reflect genuinely live streams. The abort
        // handle is `select!`ed in the adaptor so a halt cancels the stream mid-flight.
        let (session_guard, abort) = self.sessions.begin(crate::session::SessionEntry {
            session_id: request_id.clone(),
            agent_label: context.agent_label.clone(),
            principal_id: context.api_key_id.clone(),
            token_id: use_token_id.map(|s| s.to_string()),
            credential: credential_alias.clone(),
            action: full_action.clone(),
            started_at: chrono::Utc::now(),
        });

        // averin use-seal (plan 086/087, the "fourth contract") — SHARED with the
        // buffered `run_action` via [`Self::seal_after_consume`], so a STREAMING
        // execute is sealed exactly like a buffered one (plan 087 FIX 1: the streaming
        // path previously had NO seal hook, so a `stream: true` request bypassed the
        // seal and RequireEvidence failed OPEN for streams). Default-off
        // (`self.averin == None`) → skipped entirely, byte-identical to today. In
        // RequireEvidence the seal is AWAITED and a failure DENIES here — BEFORE
        // `plugin.execute_streaming` (the point of no return) opens the upstream
        // stream, so strict mode now fails CLOSED on streams too. Must precede the
        // `params` move into `plugin_request` below.
        if let (Some(av), Some(tid)) = (&self.averin, use_token_id) {
            let params_bytes = serde_json::to_vec(&params).unwrap_or_default();
            // Plan 088 D5c — threads this execute's `use_sequence_number` + `request_id`
            // through too, identical to the buffered path.
            self.seal_after_consume(av, tid, params_bytes, use_sequence_number, &request_id)
                .await?;
        }

        let plugin_request = crate::plugins::PluginRequest {
            credential,
            action: action_name.to_string(),
            params,
            context,
        };

        // Point of no return: open the upstream stream.
        let streaming = plugin
            .execute_streaming(plugin_request)
            .await
            .map_err(|e| RunError::committed(e.into()))?;

        let status = streaming.status;

        // Fail closed on a residual-compressed body (an encoding the HTTP client
        // didn't decode, e.g. zstd): it's opaque to the secret scrubber, so withhold
        // it rather than forward un-scrubbable bytes. Decided from the head, before
        // any body byte. (reqwest auto-decodes gzip/deflate/br and strips the header,
        // so this is the rare exotic-codec case.) Still meters V13a.
        if crate::egress::headers_indicate_compression(&streaming.headers) {
            warn!(
                request_id = %request_id,
                credential = %credential_alias,
                "streamed response is compressed and cannot be scrubbed — withholding"
            );
            emit_meter(&Arc::clone(&self.storage), &attribution, None, None).await;
            let placeholder = Bytes::from_static(
                b"[vultrino: streamed response withheld - a compressed body could not be scrubbed for secrets]",
            );
            return Ok(StreamingExecution {
                status,
                headers: std::collections::HashMap::from([(
                    "content-type".to_string(),
                    "text/plain".to_string(),
                )]),
                // Move the V6 guard into the (single-chunk) body so the in-flight
                // session deregisters when the placeholder is drained, not at this
                // early return — symmetric with the main streaming path.
                body: Box::pin(futures::stream::once(async move {
                    let _guard = session_guard;
                    Ok::<Bytes, std::io::Error>(placeholder)
                })),
            });
        }

        // Persist any credential update (e.g. OAuth2 refresh), known before the body
        // streams — identical to the buffered path.
        if let Some(updated_data) = &streaming.updated_credential {
            let updated_credential = crate::Credential {
                id: credential_id,
                alias: credential_alias.clone(),
                credential_type: updated_data.credential_type(),
                data: updated_data.clone(),
                metadata: credential_metadata,
                created_at: credential_created_at,
                updated_at: chrono::Utc::now(),
            };
            if let Err(e) = self.storage.store(&updated_credential).await {
                warn!(request_id = %request_id, error = %e, "Failed to persist updated credential (token refresh)");
            }
            self.emit_event(
                &credential_alias,
                crate::outbox::EVENT_CREDENTIAL_ROTATED,
                serde_json::json!({
                    "credential": credential_alias,
                    "credential_type": updated_data.credential_type().to_string(),
                }),
            )
            .await;
        }

        // Scrub the response HEADERS before the head commits to the wire (a secret
        // reflected in a provider header would otherwise escape — the streaming head
        // is sent before any body byte), then strip framing headers a re-chunked /
        // redacted body would invalidate (axum frames from the emitted bytes).
        let mut headers = streaming.headers;
        let forms = crate::egress::derive_secret_forms(&secret_material);
        crate::egress::scrub_headers(&mut headers, &forms, &credential_alias);
        headers.retain(|k, _| {
            !k.eq_ignore_ascii_case("content-length")
                && !k.eq_ignore_ascii_case("transfer-encoding")
        });
        drop(forms);

        info!(
            request_id = %request_id,
            credential = %credential_alias,
            action = %full_action,
            status,
            "Streaming request started"
        );

        // Build the body adaptor: hold the session guard for the stream's life, tee
        // each RAW chunk to the usage accumulator (pre-scrub) AND the incremental
        // scrubber (emit), enforce the DoS caps, honor a mid-stream halt, and run the
        // metering finalizer when the stream terminates.
        let caps = &self.config.llm_proxy;
        let max_line = caps.stream_max_line_bytes;
        let max_bytes = caps.stream_max_bytes;
        let idle = (caps.stream_idle_timeout_secs > 0)
            .then(|| std::time::Duration::from_secs(caps.stream_idle_timeout_secs));
        let total = (caps.stream_total_timeout_secs > 0)
            .then(|| std::time::Duration::from_secs(caps.stream_total_timeout_secs));
        let upstream = streaming.body;
        let alias_for_stream = credential_alias.clone();
        let finalizer = StreamFinalizer::new(Arc::clone(&self.storage), attribution);
        let body = async_stream::stream! {
            // Held for the stream's whole life → deregisters on completion/drop.
            let _guard = session_guard;
            // `finalizer`'s Drop emits V13a-only if the consumer disconnects before a
            // terminus (the generator is dropped mid-await and the code below never
            // reaches `finalize`).
            let finalizer = finalizer;
            let mut scrubber =
                crate::egress::StreamScrubber::new(&secret_material, &alias_for_stream, max_line);
            let mut usage_acc = crate::outbox::UsageAccumulator::new(max_line);
            let mut upstream = upstream;
            let mut clean = true;
            let mut total_bytes: u64 = 0;
            let deadline = total.map(|d| tokio::time::Instant::now() + d);

            loop {
                // Race the next upstream chunk against: a mid-stream halt (V6), the
                // total-duration cap, and the idle cap. `biased` checks halt first.
                let step = {
                    let next = upstream.next();
                    tokio::pin!(next);
                    tokio::select! {
                        biased;
                        _ = abort.notified() => StreamStep::Halted,
                        _ = async {
                            match deadline {
                                Some(d) => tokio::time::sleep_until(d).await,
                                None => std::future::pending::<()>().await,
                            }
                        } => StreamStep::TotalTimeout,
                        r = async {
                            match idle {
                                Some(d) => tokio::time::timeout(d, next.as_mut()).await.map_err(|_| ()),
                                None => Ok(next.as_mut().await),
                            }
                        } => match r {
                            Err(()) => StreamStep::IdleTimeout,
                            Ok(None) => StreamStep::CleanEof,
                            Ok(Some(Ok(chunk))) => StreamStep::Chunk(chunk),
                            Ok(Some(Err(_))) => StreamStep::UpstreamError,
                        },
                    }
                };

                match step {
                    StreamStep::CleanEof => break,
                    StreamStep::Halted => {
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(SSE_HALT_FRAME));
                        clean = false;
                        break;
                    }
                    StreamStep::IdleTimeout
                    | StreamStep::TotalTimeout
                    | StreamStep::UpstreamError => {
                        // Generic in-band SSE error, never the detail (the buffered path
                        // withholds upstream Err detail too).
                        yield Ok(Bytes::from_static(SSE_ERROR_FRAME));
                        clean = false;
                        break;
                    }
                    StreamStep::Chunk(chunk) => {
                        total_bytes = total_bytes.saturating_add(chunk.len() as u64);
                        if max_bytes > 0 && total_bytes > max_bytes {
                            yield Ok(Bytes::from_static(SSE_ERROR_FRAME));
                            clean = false;
                            break;
                        }
                        // Tee: usage tap reads the RAW chunk (pre-scrub, symmetric with
                        // the buffered path's pre-scrub usage read); the scrubber emits.
                        usage_acc.push(&chunk);
                        // Carry a COMPLETE trailer into the finalizer so a client
                        // disconnect right after the usage frame still meters V13b
                        // (Drop reads this) rather than under-counting to V13a-only.
                        if let Some((u, m)) = usage_acc.snapshot() {
                            finalizer.record_usage(u, m.or_else(|| meter_request_model.clone()));
                        }
                        match scrubber.push(&chunk) {
                            Ok(out) => {
                                if !out.is_empty() {
                                    yield Ok(Bytes::from(out));
                                }
                            }
                            Err(_) => {
                                // Scrub fail-closed (e.g. buffer cap).
                                yield Ok(Bytes::from_static(SSE_ERROR_FRAME));
                                clean = false;
                                break;
                            }
                        }
                    }
                }
            }

            if clean {
                if let Ok(out) = scrubber.finish() {
                    if !out.is_empty() {
                        yield Ok(Bytes::from(out));
                    }
                }
                // Clean EOF: emit V13a + (when a usage split was parsed) the V13b
                // priced token event — identical shape to the buffered path. Prefer
                // the model the provider echoed in the stream; fall back to the
                // request-side model so `dims.model_ref` is present whenever the
                // buffered path would have had it (no stream-only pricing gap).
                let (usage, stream_model) = usage_acc.finish();
                let model = stream_model.or(meter_request_model);
                finalizer.finalize(usage, model).await;
            } else {
                // Truncated/halted/errored turn. A genuinely partial stream has no
                // trustworthy usage trailer and meters V13a only (emitting partial
                // counts would under-count, the dangerous direction). BUT if the
                // provider's usage trailer ALREADY arrived before this terminus (e.g. an
                // idle/total timeout or upstream error AFTER the usage + [DONE] frames),
                // `finish` returns the COMPLETE split — trust it and still emit V13b
                // (a parsed-complete trailer is authoritative regardless of how the
                // stream ended; dropping it would under-count).
                let (usage, stream_model) = usage_acc.finish();
                let model = stream_model.or(meter_request_model);
                finalizer.finalize(usage, model).await;
            }
            // _guard + finalizer drop here (finalizer already emitted → Drop no-op).
        };

        Ok(StreamingExecution {
            status,
            headers,
            body: Box::pin(body),
        })
    }

    /// Run a previously-approved action. Builds the request from the stored
    /// approval and executes it (consuming the use token, if any).
    async fn resume_approved(
        &self,
        approval: &ApprovalRequest,
    ) -> Result<ExecuteResponse, RunError> {
        // V11 note: cross-tenant credential isolation is enforced at request time
        // in `execute_gated` (before an approval is ever opened), so a cross-tenant
        // request can't create an approval to resume. The resume re-evaluates
        // policy but does NOT re-check tenant isolation — a credential whose
        // `tenant` metadata is changed *between* approval and resume is not
        // re-validated here (a narrow operator-action window; an emergency stop
        // should push a Deny/halt, which the resume policy re-eval does honor).
        // Likewise the V11 *observe* downgrade is an open-time/live-path concept
        // (the approval record doesn't carry the opener's tenant), so an
        // observe-tenant action that is BOTH policy-denied AND approval-gated is
        // enforced (fail-closed) on resume rather than observed-away — a safe
        // over-block, not a bypass.
        //
        // A credential that has gone missing, or an unparseable action, won't
        // recover on retry → terminal.
        let credential = self
            .resolver
            .resolve(&approval.credential)
            .await
            .map_err(RunError::terminal)?;
        let (plugin_name, action_name) =
            parse_action(&approval.action).map_err(RunError::terminal)?;
        let mut context = RequestContext::new();

        // Re-evaluate policy at execution time so the deferred path still
        // enforces hard *deny* gates — a human approval is not a policy bypass.
        // NOTE (policy-change interaction): policy is re-evaluated read-only at
        // resume, so a policy change between approval and execution applies. If
        // the matching policy is removed (un-policied → fail-closed `no_policy`)
        // OR a new Deny is pushed for the credential/agent (e.g. an emergency
        // kill via the admin API, propagated by the periodic refresh), the
        // resume is denied. That is intentional: a policy revoked or a Deny
        // pushed mid-flight must stop the pending action, not let an
        // already-approved request slip through un-governed. Only `Deny` blocks
        // here — a `Prompt` is already satisfied by the human's approval.
        // This is the READ-ONLY evaluation: rate limits were already counted when
        // the request first opened the approval, so re-counting here would
        // double-charge and could spuriously deny an already-approved action. A
        // `Prompt` is already satisfied (the human approved), so only `Deny`
        // blocks; the use token is left unconsumed when it does.
        let url = approval.params.get("url").and_then(|v| v.as_str());
        let method = approval.params.get("method").and_then(|v| v.as_str());
        // Rebuild the principal (V4) and spend (V3) from the recorded approval so
        // per-agent denies and spend caps are re-evaluated at resume. Spend is
        // checked read-only here (per-action, stateless — it was already checked at
        // open; there is no ledger to re-charge after R1).
        // NOTE: the agent_label is point-in-time (snapshotted at open); a per-
        // agent Deny created by binding a *new* label to the token after the
        // approval opened won't re-fire at resume — deny by token id or by the
        // credential to stop an in-flight approval regardless. The principal id
        // is taken from the explicit `approval.principal_id` (set at open), not
        // derived from the requester, so per-agent denies re-evaluate reliably.
        // Fall back to the requester's principal id for approvals persisted
        // before `principal_id` existed. (When both are None — e.g. a local,
        // principal-less requester — per-agent policies correctly don't apply.)
        let principal_id = approval
            .principal_id
            .as_ref()
            .or(approval.requester.principal_id.as_ref())
            .cloned();
        // V13a metering attribution (fix): seed the meter/in-flight-session identity
        // from the approval record BEFORE `run_action` derives `meter_principal`.
        // `run_action` resolves the meter subject as
        // `context.agent_label → context.api_key_id → credential_alias`; on the empty
        // resume context it fell all the way back to the CREDENTIAL ALIAS, so every
        // approval-gated call was metered against the shared credential instead of the
        // requesting AGENT — a per-agent under-count (leria budgets never saw the
        // approval-gated spend). Attribution ONLY: rate limits are deliberately NOT
        // re-charged on resume (the RateLimit condition runs read-only here,
        // record=false), so this changes who the spend is attributed to, not whether
        // any limit is re-consumed.
        context.agent_label = approval.agent_label.clone();
        context.api_key_id = principal_id.clone();
        let principal = principal_id.map(|id| crate::policy::Principal {
            id,
            agent_label: approval.agent_label.clone(),
            // Owner doesn't affect policy matching (only SoD, computed at decide
            // time on the requester record), so it isn't needed for the resume gate.
            owner: None,
            // V10/R6: re-thread the resolved workload identity snapshotted at open,
            // so a principal_pattern Deny targeting an SVID/OIDC subject re-fires on
            // resume too.
            workload_id: approval.workload_id.clone(),
        });
        // Spend was checked read-only at resume; it was checked (per-action,
        // stateless — there is no ledger after R1) when the approval opened. The
        // read-only resume re-enforces only hard deny gates and never re-charges,
        // so no spend attempt is needed. A spend cap *changed* after the approval
        // opened therefore does not re-bind to this in-flight action; an operator
        // who needs to stop such an in-flight approval should push an explicit Deny.
        if let crate::policy::PolicyDecision::Deny(reason) = self
            .policy_engine
            .evaluate_readonly_full(&crate::policy::EvalInput {
                credential_alias: &credential.alias,
                url,
                method,
                // Re-bind the approved action so an ActionMatch rule re-fires
                // correctly on resume (the approved action matches its own rule; a
                // Deny pushed mid-flight still blocks). Present the ORIGINAL business
                // verb (the action_label the requester presented, e.g. "telegram.send"),
                // not the resolved canonical plugin action ("http.request"): the
                // live-path eval at open matched on `request.action` (the label), and a
                // connector policy's ActionMatch rule is keyed on that business verb.
                // Using the canonical action here would fall through to default-deny for
                // every label-mapped action after approval. Dispatch still uses the
                // canonical `approval.action` (parse_action above).
                action: Some(
                    approval
                        .action_label
                        .as_deref()
                        .unwrap_or(approval.action.as_str()),
                ),
                principal: principal.as_ref(),
                spend: None,
            })
        {
            // R3: a Deny/kill pushed between approval-open and resume re-fires here —
            // one of the more security-relevant enforce-mode denials (operator
            // stopped an in-flight action). Emit the same timestamped DETECT event
            // and bump the counter as the live deny sites, so an incident first
            // caught at resume isn't invisible to MTTD/the unauthorized-attempts metric.
            self.record_unauthorized_attempt();
            self.emit_policy_denied(
                principal.as_ref().and_then(|p| p.agent_label.as_deref()),
                principal.as_ref().map(|p| p.id.as_str()),
                &credential.alias,
                &approval.action,
                approval.tenant.as_deref(),
                &reason,
                "policy_resume",
            )
            .await;
            return Err(RunError::terminal(VultrinoError::PolicyDenied(reason)));
        }

        self.run_action(
            credential,
            plugin_name,
            action_name,
            approval.params.clone(),
            context,
            approval.use_token_id.as_deref(),
        )
        .await
    }

    /// Look up an approval and, if it has been approved but not yet run, execute
    /// it now and record the result. This is the polling entry point an agent
    /// calls via `check_approval` (MCP), `GET /api/v1/approvals/{id}` (HTTP), or
    /// `vultrino approval status` (CLI).
    ///
    /// `expected_principal`, when `Some`, must match the approval's requester —
    /// the ownership check happens **before** any execution, so a non-owner can
    /// never trigger another principal's approved action. Pass `None` for a
    /// trusted local caller (CLI/admin).
    ///
    /// Storage is reloaded first so a decision made by another process (the web
    /// admin panel, a Telegram button) is picked up.
    pub async fn check_and_resume_approval(
        &self,
        id: &str,
        expected_principal: Option<&str>,
    ) -> Result<ApprovalRequest, VultrinoError> {
        // Best-effort: pick up cross-process decisions.
        let _ = self.storage.reload().await;

        let approval =
            self.storage.get_approval(id).await?.ok_or_else(|| {
                VultrinoError::InvalidRequest(format!("Approval not found: {}", id))
            })?;

        // Ownership check BEFORE any side effect: a non-owner must not be able to
        // trigger execution of someone else's approved action.
        if let Some(pid) = expected_principal {
            if approval.requester.principal_id.as_deref() != Some(pid) {
                return Err(VultrinoError::PolicyDenied(
                    "This approval was requested by a different principal; you are not authorized \
                     to access it"
                        .to_string(),
                ));
            }
        }

        // Advance the SLA lifecycle on poll (V5) — atomically under the storage
        // lock so we never overwrite a decision committed concurrently by another
        // process with a stale local copy. This escalates a pending request past
        // its first window, expires one past its final deadline, and expires an
        // approved-but-unrun grant whose continuous-reauth window lapsed.
        let mut approval = self.storage.poll_refresh_approval(id).await?;
        // Surface the new state to the polling agent unless it's an executable
        // (Approved + not yet run) grant, which we run below.
        if approval.status != ApprovalStatus::Approved || approval.executed {
            return Ok(approval);
        }

        // Approved but not yet executed → run it now (claiming first to avoid a
        // double-run if two polls race).
        if approval.status == ApprovalStatus::Approved && !approval.executed {
            match self.storage.claim_approval_for_execution(id).await? {
                Some(claim) => {
                    let epoch = claim.epoch;
                    let mut claimed = claim.approval;

                    // FAIL-CLOSED at-most-once (#8): a STALE re-take means the
                    // original worker set `executing` and then vanished (crashed
                    // mid-flight). Its side effect may ALREADY have fired, so we must
                    // NOT re-run `resume_approved` — that would risk a duplicate
                    // effect. Finalize the grant TERMINALLY as "outcome unknown"; the
                    // requester must re-approve to retry (an idempotency decision it
                    // now owns, rather than us silently double-firing).
                    if claim.stale_retake {
                        claimed.result_status = None;
                        claimed.result_body = None;
                        claimed.result_error = Some(
                            "outcome unknown — original worker lost mid-execution; \
                             re-approve to retry"
                                .to_string(),
                        );
                        claimed.executed = true;
                        claimed.executing = false;
                        claimed.executing_since = None;
                        // Commit under the epoch CAS; if yet another claim raced in,
                        // return the authoritative state rather than clobbering it.
                        if self.storage.finalize_execution(id, epoch, &claimed).await? {
                            return Ok(claimed);
                        }
                        return Ok(self.storage.get_approval(id).await?.unwrap_or(claimed));
                    }

                    // Fresh claim. Run the (possibly slow) action while heartbeating
                    // the claim, so a live worker's claim is never judged stale and
                    // re-run by another process. Resume against a clone so `claimed`
                    // stays free to mutate with the result. The select cancels the
                    // heartbeat loop as soon as the action finishes.
                    let resume_input = claimed.clone();
                    let hb_storage = self.storage.clone();
                    let hb_id = id.to_string();
                    let resume_fut = self.resume_approved(&resume_input);
                    tokio::pin!(resume_fut);
                    let outcome = loop {
                        tokio::select! {
                            r = &mut resume_fut => break r,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(
                                EXECUTION_HEARTBEAT_SECS,
                            )) => {
                                let _ = hb_storage.heartbeat_approval(&hb_id).await;
                            }
                        }
                    };

                    match outcome {
                        Ok(resp) => {
                            claimed.result_status = Some(resp.status);
                            // The full body already went to the live caller; cap
                            // what we persist into the (encrypted) vault so a large
                            // response can't bloat the approval record unbounded.
                            claimed.result_body = Some(cap_result_body(&resp.body));
                            claimed.result_error = None;
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        // Not retryable: either the plugin ran and may have
                        // side-effected (committed), or a permanent preflight
                        // failure (unusable token, bad params, missing credential).
                        // Finalize terminally so the agent isn't told to poll forever.
                        Err(re) if !re.retryable => {
                            claimed.result_error = Some(re.error.to_string());
                            claimed.executed = true;
                            claimed.executing = false;
                            claimed.executing_since = None;
                        }
                        // Transient preflight failure (e.g. plugin not loaded yet) —
                        // nothing ran. Release the claim and leave it un-executed so
                        // a later poll can retry.
                        Err(re) => {
                            claimed.executing = false;
                            claimed.executing_since = None;
                            claimed.result_error = Some(format!(
                                "could not start the approved action (will retry on next check): {}",
                                re.error
                            ));
                        }
                    }
                    // At-most-once commit under the epoch CAS (#8), replacing the
                    // former blind `update_approval`. If this claim was superseded
                    // (we stalled past the stale window despite heartbeating and were
                    // re-taken), refuse to overwrite the re-taker's terminal outcome
                    // and surface the authoritative state instead.
                    if self.storage.finalize_execution(id, epoch, &claimed).await? {
                        return Ok(claimed);
                    }
                    return Ok(self.storage.get_approval(id).await?.unwrap_or(claimed));
                }
                None => {
                    // Another worker owns/owned execution; return the latest.
                    approval = self.storage.get_approval(id).await?.unwrap_or(approval);
                }
            }
        }

        Ok(approval)
    }

    /// Deliver an approval to all configured notifiers (best-effort).
    async fn dispatch_notifications(&self, approval: &ApprovalRequest, decision_token: &str) {
        if self.notifiers.is_empty() {
            return;
        }
        let base = self
            .approval_config
            .public_base_url
            .as_deref()
            .unwrap_or("");
        let links = approval.links(base, decision_token);
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify(approval, &links).await {
                warn!(
                    channel = notifier.channel(),
                    approval_id = %approval.id,
                    error = %e,
                    "Failed to deliver approval notification"
                );
            }
        }
    }

    /// One iteration of the approval SLA sweep (V5): re-read the vault, advance
    /// every open request through its lifecycle (escalate / expire), and re-ping
    /// the notifiers for those that escalated. Returns the sweep result.
    pub async fn sweep_approvals_once(
        &self,
    ) -> Result<crate::storage::ApprovalSweep, crate::storage::StorageError> {
        run_approval_sweep(
            &self.storage,
            &self.notifiers,
            self.approval_config.public_base_url.as_deref(),
        )
        .await
    }

    /// Whether the approval subsystem is enabled.
    pub fn approvals_enabled(&self) -> bool {
        self.approval_config.enabled
    }

    /// Get a reference to the storage backend
    pub fn storage(&self) -> &Arc<dyn StorageBackend> {
        &self.storage
    }

    /// Get a reference to the in-flight session registry (V6).
    pub fn sessions(&self) -> &Arc<crate::session::SessionRegistry> {
        &self.sessions
    }

    /// Record an unauthorized tool-call attempt — one blocked by the policy
    /// engine (V12 metrics).
    fn record_unauthorized_attempt(&self) {
        self.unauthorized_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Count of unauthorized (policy-denied) tool-call attempts since start (V12).
    pub fn unauthorized_attempts(&self) -> u64 {
        self.unauthorized_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Shared outbox delivery counters (observability item 4 / #3) — cloned
    /// (cheap, `Arc`) so callers (the JSON metrics read-back, and `main.rs`
    /// wiring the background delivery loop) can hold it independently of
    /// `&VultrinoServer`.
    pub fn outbox_metrics(&self) -> Arc<OutboxMetrics> {
        self.outbox_metrics.clone()
    }

    /// Best-effort append of an event to the signed outbox (V9). Never fails the
    /// calling operation — an event-log problem must not block the action it
    /// describes (the action's own success is the source of truth).
    pub async fn emit_event(&self, subject: &str, event_type: &str, payload: serde_json::Value) {
        if let Err(e) = self
            .storage
            .append_event(subject, event_type, payload)
            .await
        {
            warn!(error = %e, event_type, "failed to append outbox event");
        }
    }

    /// Emit a timestamped DETECT event for an enforce-mode denial (R3/V12a).
    ///
    /// The event's `created_at` (stamped by the outbox under the lock) is the
    /// per-incident **`detected_at`**. The subject is the offending agent label
    /// (falling back to the principal id, then the credential). It is **best-effort
    /// paired** with [`crate::outbox::EVENT_AGENT_HALTED`]: when an agent is halted
    /// by the same label/id its detect (`policy.denied`) and contain (`agent.halted`)
    /// events share a subject, giving an MTTD/MTTC measurement. (A halt targeting a
    /// different key than the denial's subject won't share a subject — the pairing
    /// is a convenience, not a guarantee.)
    ///
    /// Emission is **coalesced** per subject (see `detect_emit_gate`): a denial
    /// storm produces one durable event per subject per window, not one vault write
    /// per blocked call. The caller bumps the always-on atomic counter regardless,
    /// so no attempt is undercounted.
    #[allow(clippy::too_many_arguments)]
    async fn emit_policy_denied(
        &self,
        agent_label: Option<&str>,
        principal_id: Option<&str>,
        credential_alias: &str,
        full_action: &str,
        tenant: Option<&str>,
        reason: &str,
        kind: &str,
    ) {
        let subject = agent_label.or(principal_id).unwrap_or(credential_alias);
        // Coalesce: at most one detect event per subject per window. Prune stale
        // entries on the way so the gate is bounded by distinct subjects in-window.
        const DETECT_EMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
        {
            let now = std::time::Instant::now();
            let mut gate = self.detect_emit_gate.write();
            gate.retain(|_, t| now.duration_since(*t) < DETECT_EMIT_WINDOW);
            if gate.contains_key(subject) {
                return; // already emitted a detect event for this subject this window
            }
            gate.insert(subject.to_string(), now);
        }
        self.emit_event(
            subject,
            crate::outbox::EVENT_POLICY_DENIED,
            serde_json::json!({
                "credential": credential_alias,
                "action": full_action,
                "tenant": tenant,
                "agent_label": agent_label,
                "principal_id": principal_id,
                "reason": reason,
                "kind": kind,
                "outcome": "denied",
            }),
        )
        .await;
    }

    /// List approvals visible to an admin acting in tenant `acting` (V11/R4).
    /// `acting == None` is a global admin (sees all); a tenant-scoped admin sees
    /// only its own tenant's approvals plus untenanted (shared) ones. Used by the
    /// tenant-scoped admin metrics read-back; the primitive is
    /// [`ApprovalRequest::visible_to_tenant`], which any future tenant-scoped
    /// decision surface gates on (the web panel is a global console).
    pub async fn list_approvals_for_tenant(
        &self,
        acting: Option<&str>,
    ) -> Result<Vec<ApprovalRequest>, VultrinoError> {
        let mut approvals = self.storage.list_approvals().await?;
        approvals.retain(|a| a.visible_to_tenant(acting));
        Ok(approvals)
    }

    /// Whether the given principal (a `vk_`/`vut_` resolved [`AuthResult`]) would
    /// be permitted to invoke a capability — used by the MCP server to filter
    /// `tools/list` so an agent only sees the named tools its policy ALLOWS
    /// (connector M1). This is a **read-only, no-side-effect** check that reuses
    /// the SAME enforcement decisions `execute_gated` makes — credential access,
    /// V11 tenant isolation, and the policy engine — so a tool that wouldn't run
    /// can never appear in the list (and conversely a listed tool is the same one
    /// `execute_gated` would admit). It does NOT charge rate limits or extract a
    /// concrete spend amount (there are no LLM args yet at list time), so a
    /// capability gated only by a per-action SpendCap is treated as *not yet
    /// listable-allowed* (fail-closed: SpendCap with no extracted amount denies).
    ///
    /// A `None` auth (local/trusted caller) is permitted to see every capability.
    pub async fn capability_allowed_for(
        &self,
        auth: Option<&AuthResult>,
        capability: &crate::capability::Capability,
    ) -> bool {
        // Resolve the capability's credential + canonical action exactly as the
        // execute path does, so the credential alias and action seen by policy
        // match the live decision. A missing credential or unparseable action
        // means the capability can never run → not listable.
        let credential = match self.resolver.resolve(&capability.credential_ref).await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let (canonical_action, _label) = self.config.resolve_action(&capability.action);
        // Resolve only to confirm the action is well-formed (an unparseable action
        // can never run → not listable). Policy matches on the credential alias +
        // url/method + principal; the action string itself is enforced through the
        // use-token's action scope at execute time, not here.
        if parse_action(&canonical_action).is_err() {
            return false;
        }

        if let Some(auth) = auth {
            // Same permission + credential-access gate execute_gated applies.
            if !auth.has_permission(Permission::Execute) {
                return false;
            }
            if !auth.can_access_credential(&credential.alias) {
                return false;
            }
            // V11 tenant isolation: a tenant-tagged credential is only usable by a
            // principal in the same tenant (never observable-away).
            let principal_tenant = auth.api_key.tenant.as_deref();
            let cred_tenant = credential
                .metadata
                .get("tenant")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            if let Some(ct) = cred_tenant {
                if principal_tenant != Some(ct) {
                    return false;
                }
            }
        }

        // Build the principal (V4) for principal_pattern matching, exactly like
        // execute_gated.
        let principal = auth.map(|a| crate::policy::Principal {
            id: a.api_key.id.clone(),
            agent_label: a.api_key.agent_label.clone(),
            owner: a.api_key.owner_identity.clone(),
            workload_id: a.api_key.workload_id.clone(),
        });
        // Read-only policy evaluation: no rate-limit charge, no spend extracted.
        // We pass the capability's target url/method (if pinned) so a url/method
        // gated allow rule can match at list time.
        let url = capability.target.url_glob.as_deref();
        let method = capability.target.methods.first().map(|m| m.as_str());
        let decision = self
            .policy_engine
            .evaluate_readonly_full(&crate::policy::EvalInput {
                credential_alias: &credential.alias,
                url,
                method,
                // The cap's own action label, so its ActionMatch rule matches and the
                // granted cap remains listable (without it the connector dimension would
                // hide every granted capability at tools/list).
                action: Some(capability.action.as_str()),
                principal: principal.as_ref(),
                spend: None,
            });
        // A `Prompt` (approval-gated) capability is still listable — the agent can
        // call it and will be told to await approval, exactly like a generic gated
        // tool. Only an outright `Deny` hides it.
        !matches!(decision, crate::policy::PolicyDecision::Deny(_))
    }

    /// Trusted irreversibility for D3 floors: resolve from stored capability metadata
    /// (not requester-authored params). Matches canonical action or govder label.
    async fn trusted_irreversible_for_action(
        &self,
        canonical_action: &str,
        action_label: Option<&str>,
    ) -> bool {
        let _ = self.storage.reload().await;
        let caps = match self.storage.list_capabilities().await {
            Ok(caps) => caps,
            Err(error) => {
                // This stamp decides whether a machine may replace a human. An
                // unavailable catalog must therefore fail to the human floor.
                tracing::error!(%error, "capability lookup failed while deriving trusted irreversibility");
                return true;
            }
        };

        // Prefer the exact govder action label. Several capabilities commonly
        // resolve to the same canonical plugin verb (for example http.request),
        // so returning the first canonical match can pick a reversible sibling
        // for an irreversible capability. When only the canonical form is known,
        // use the strictest matching value; no match also fails to the human floor.
        if let Some(label) = action_label.map(str::trim).filter(|s| !s.is_empty()) {
            let exact: Vec<_> = caps
                .iter()
                .filter(|cap| {
                    let (_, configured_label) = self.config.resolve_action(&cap.action);
                    cap.action.trim() == label || configured_label.as_deref() == Some(label)
                })
                .collect();
            if !exact.is_empty() {
                return exact.iter().any(|cap| {
                    crate::approval::reversibility_requires_human_floor(&cap.reversibility)
                });
            }
        }

        let canonical: Vec<_> = caps
            .iter()
            .filter(|cap| self.config.resolve_action(&cap.action).0 == canonical_action)
            .collect();
        if canonical.is_empty() {
            tracing::warn!(%canonical_action, ?action_label,
                "no capability metadata matched approval action; requiring human floor");
            return true;
        }
        canonical
            .iter()
            .any(|cap| crate::approval::reversibility_requires_human_floor(&cap.reversibility))
    }

    /// Extract the approval-preview VALUES for an action being gated, if its
    /// backing capability declares an `approval_preview` spec. Looks up the
    /// capability the SAME way [`Self::trusted_irreversible_for_action`] does
    /// (prefer an exact `action_label` match, else the first capability whose
    /// resolved canonical action matches). Returns `None` when no matching
    /// capability is found, or it has no `approval_preview` spec — the caller
    /// then falls back to the existing `summary` line, unchanged.
    ///
    /// SECURITY: `params` must be the SAME params that will execute (not a
    /// separate/mutable copy) — the approver must see what will actually run.
    async fn approval_preview_for_action(
        &self,
        canonical_action: &str,
        action_label: Option<&str>,
        params: &serde_json::Value,
    ) -> Option<crate::capability::ApprovalPreview> {
        let _ = self.storage.reload().await;
        let caps = match self.storage.list_capabilities().await {
            Ok(caps) => caps,
            Err(error) => {
                tracing::error!(%error, "capability lookup failed while deriving approval preview");
                return None;
            }
        };

        if let Some(label) = action_label.map(str::trim).filter(|s| !s.is_empty()) {
            let exact = caps.iter().find(|cap| {
                let (_, configured_label) = self.config.resolve_action(&cap.action);
                cap.action.trim() == label || configured_label.as_deref() == Some(label)
            });
            if let Some(cap) = exact {
                return cap
                    .approval_preview
                    .as_ref()
                    .map(|spec| crate::capability::extract_preview(spec, params));
            }
        }

        let cap = caps
            .iter()
            .find(|cap| self.config.resolve_action(&cap.action).0 == canonical_action)?;
        cap.approval_preview
            .as_ref()
            .map(|spec| crate::capability::extract_preview(spec, params))
    }

    /// List the capabilities a principal is permitted to see (connector M1). The
    /// MCP server turns each into a named tool. Storage is reloaded first so a
    /// capability created via the admin API (another process) is visible.
    pub async fn list_capabilities_for(
        &self,
        auth: Option<&AuthResult>,
    ) -> Vec<crate::capability::Capability> {
        let _ = self.storage.reload().await;
        let all = self.storage.list_capabilities().await.unwrap_or_default();
        let mut allowed = Vec::new();
        for capability in all {
            if self.capability_allowed_for(auth, &capability).await {
                allowed.push(capability);
            }
        }
        allowed
    }

    /// Resolve the **LLM-proxy** capability a principal may use (connector M1,
    /// decision 5) — the model channel backing `POST /llm`. It reuses the SAME
    /// read-only enforcement [`Self::capability_allowed_for`] applies (credential
    /// access, V11 tenant isolation, default-deny policy), so an agent can only
    /// route its model traffic through a capability it is actually granted.
    ///
    /// The legacy resolver succeeds only when exactly one channel is allowed.
    /// Selecting the first storage row would make cross-provider fallback use a
    /// nondeterministic credential, so ambiguity now fails closed.
    pub async fn resolve_llm_proxy_for(
        &self,
        auth: Option<&AuthResult>,
    ) -> Option<crate::capability::Capability> {
        let _ = self.storage.reload().await;
        let all = self.storage.list_capabilities().await.unwrap_or_default();
        let mut matched = Vec::new();
        for capability in all {
            if !capability.is_llm_proxy() {
                continue;
            }
            if self.capability_allowed_for(auth, &capability).await {
                matched.push(capability);
            }
        }
        if matched.len() == 1 {
            matched.pop()
        } else {
            None
        }
    }

    /// Resolve an explicit model channel by stable capability id or channel
    /// name. With no name, compatibility `/llm` is accepted only for one channel.
    pub async fn resolve_llm_proxy_channel_for(
        &self,
        auth: Option<&AuthResult>,
        channel: Option<&str>,
    ) -> Result<crate::capability::Capability, String> {
        let _ = self.storage.reload().await;
        let all = self.storage.list_capabilities().await.unwrap_or_default();
        let mut allowed = Vec::new();
        for capability in all {
            if capability.is_llm_proxy() && self.capability_allowed_for(auth, &capability).await {
                allowed.push(capability);
            }
        }
        match channel {
            Some(name) => allowed
                .into_iter()
                .find(|c| c.id == name || c.tool_name == name)
                .ok_or_else(|| format!("Model channel '{name}' is not granted")),
            None if allowed.len() == 1 => Ok(allowed.remove(0)),
            None if allowed.is_empty() => {
                Err("No LLM-proxy capability is provisioned for this principal".to_string())
            }
            None => {
                Err("Multiple model channels are granted; use /llm/channels/{channel}".to_string())
            }
        }
    }

    /// Look up a stored capability by its MCP tool name (connector M1). Reloads
    /// storage first to pick up a capability registered by another process.
    pub async fn capability_by_tool_name(
        &self,
        tool_name: &str,
    ) -> Option<crate::capability::Capability> {
        let _ = self.storage.reload().await;
        self.storage
            .list_capabilities()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|c| c.tool_name == tool_name)
    }

    /// Register a harness abort callback fired on halt (V6).
    pub fn register_halt_callback(&self, cb: Arc<dyn crate::session::HaltCallback>) {
        self.halt_callbacks.write().push(cb);
    }

    /// Halt an agent (V6 kill switch). Three legs:
    /// 1. **Revoke the agent's use tokens** — storage-authoritative and re-checked
    ///    under the vault lock on every gated call, so it takes effect immediately
    ///    across processes.
    /// 2. **Install an authoritative per-agent kill policy** (`principal_pattern`
    ///    = the label) — covers API-key-authed agents that carry no token. As a
    ///    `kill` policy it overrides any allow rule (it can't be ordered around),
    ///    and it propagates to other processes via the policy refresh.
    /// 3. **Fire registered abort callbacks** for the agent's in-flight sessions
    ///    in *this* process (the registry is per-process). Without a harness abort
    ///    primitive the achievable guarantee is "deny the next gated call"; a
    ///    registered callback can additionally preempt in-flight work.
    pub async fn halt_agent(&self, label: &str) -> Result<HaltOutcome, VultrinoError> {
        let label = label.trim();
        // The label must be a literal principal identifier (an agent label or a
        // key/token id), NOT a glob — otherwise a halt of `*` or `bot-*` would
        // silently deny an entire fleet, since `principal_pattern` is glob-matched.
        // `validate_agent_label` enforces the same `[A-Za-z0-9._-]`, non-empty,
        // ≤128 shape that labels and ids already satisfy, and rejects `*?[]`.
        crate::auth::validate_agent_label(label)
            .map_err(|e| VultrinoError::InvalidRequest(format!("invalid agent label: {e}")))?;

        // Leg 1: revoke every (still-active) use token of this target — matched by
        // the token's agent label OR its id, so halting a label-less agent by its
        // token id revokes that token (consistent with the kill policy, which
        // matches the principal id too). Token ids are prefixed (`vut_…`) and
        // agent labels are not, so `t.id == label` can't collide with a label.
        let tokens = self.storage.list_use_tokens().await?;
        let mut revoked_tokens = Vec::new();
        for t in tokens
            .iter()
            .filter(|t| !t.revoked && (t.agent_label.as_deref() == Some(label) || t.id == label))
        {
            self.storage.set_use_token_revoked(&t.id).await?;
            revoked_tokens.push(t.id.clone());
        }

        // Leg 2: install the authoritative kill policy (fixed id → idempotent).
        let deny_policy_id = format!("halt:{}", label);
        let policy = crate::policy::Policy::kill_switch(deny_policy_id.clone(), label);
        self.storage.store_policy(&policy).await?;
        let policy_active = match self.reload_policies().await {
            Ok(()) => true,
            Err(e) => {
                // The kill policy persisted but the live engine didn't reload; it
                // will apply within the refresh window. Surface it but don't fail
                // the halt — the token revocation (leg 1) already took effect.
                warn!(error = %e, agent = %label, "halt kill policy stored but engine reload failed");
                false
            }
        };

        // Leg 3: cancel + notify what this process has in flight — matched by the
        // same target as the kill policy (label OR principal/token id), so a by-id
        // halt aborts a label-less agent's sessions too.
        let in_flight = self.sessions.for_halt_target(label);
        // 3a: signal the per-session abort so an in-flight STREAM tears down within
        // one chunk (the streaming adaptor `select!`s on its handle). This is the
        // concrete in-process preemption — beyond "deny the next gated call".
        let streams_signalled = self.sessions.signal_halt(label);
        if streams_signalled > 0 {
            info!(agent = %label, streams = streams_signalled, "signalled in-flight streams to abort");
        }
        // 3b: fire registered harness abort callbacks (external integrations). Each
        // is best-effort and time-bounded (a hanging integration can't block the
        // halt — legs 1 & 2 have already taken effect).
        let callbacks = self.halt_callbacks.read().clone();
        for cb in &callbacks {
            if tokio::time::timeout(
                std::time::Duration::from_secs(HALT_CALLBACK_TIMEOUT_SECS),
                cb.on_halt(label, &in_flight),
            )
            .await
            .is_err()
            {
                warn!(callback = cb.name(), agent = %label, "halt abort callback timed out");
            }
        }

        // V9: emit the halt event to the signed outbox.
        self.emit_event(
            label,
            crate::outbox::EVENT_AGENT_HALTED,
            serde_json::json!({
                "agent_label": label,
                "revoked_tokens": revoked_tokens.len(),
                "deny_policy_id": deny_policy_id,
                "in_flight": in_flight.len(),
            }),
        )
        .await;

        info!(
            agent = %label,
            revoked_tokens = revoked_tokens.len(),
            in_flight = in_flight.len(),
            callbacks = callbacks.len(),
            policy_active,
            "agent halted"
        );

        Ok(HaltOutcome {
            agent_label: label.to_string(),
            revoked_tokens,
            deny_policy_id,
            policy_active,
            in_flight,
            callbacks_fired: callbacks.len(),
        })
    }

    /// Lift a previously-installed halt (V6): remove the per-agent kill policy and
    /// reload. Already-revoked tokens stay revoked (revocation is permanent — mint
    /// fresh tokens to resume). Returns whether a kill policy was present.
    pub async fn unhalt_agent(&self, label: &str) -> Result<bool, VultrinoError> {
        let label = label.trim();
        crate::auth::validate_agent_label(label)
            .map_err(|e| VultrinoError::InvalidRequest(format!("invalid agent label: {e}")))?;
        // Distinguish "no halt was present" (Ok false) from a real storage failure
        // (propagate) — the latter must not be reported as a successful no-op.
        let removed = match self.storage.delete_policy(&format!("halt:{}", label)).await {
            Ok(()) => true,
            Err(crate::storage::StorageError::PolicyNotFound(_)) => false,
            Err(e) => return Err(e.into()),
        };
        self.reload_policies().await?;
        Ok(removed)
    }

    /// Get a reference to the plugin registry
    pub fn plugins(&self) -> &Arc<PluginRegistry> {
        &self.plugins
    }

    /// Get a reference to the policy engine
    pub fn policy_engine(&self) -> &Arc<PolicyEngine> {
        &self.policy_engine
    }

    /// Reload the policy engine from the **union** of the static config policies
    /// and the admin-API-managed stored policies (V1). Called once at startup
    /// and after every admin policy mutation so a runtime push takes effect
    /// without a restart. Config policies remain declarative/code-managed; the
    /// admin API only adds, edits, or removes *stored* policies (by id).
    pub async fn reload_policies(&self) -> Result<(), VultrinoError> {
        let stored = self.storage.list_stored_policies().await?;
        self.policy_engine
            .load_policies(merge_policies(&self.config.policies, stored));
        Ok(())
    }

    /// Get the server configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the auth manager
    pub fn auth_manager(&self) -> &Arc<AuthManager> {
        &self.auth_manager
    }

    /// Check if authentication is required
    pub fn requires_auth(&self) -> bool {
        self.require_auth
    }
}

/// Max bytes of an action response body persisted into an approval record. The
/// full body is returned to the live caller; only the stored copy is capped.
const MAX_STORED_RESULT_BODY: usize = 64 * 1024;

/// Render a response body for storage in an approval record, truncating to
/// [`MAX_STORED_RESULT_BODY`] on a UTF-8 boundary with a marker.
fn cap_result_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if text.len() <= MAX_STORED_RESULT_BODY {
        return text.into_owned();
    }
    let mut end = MAX_STORED_RESULT_BODY;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[truncated {} bytes]", &text[..end], text.len() - end)
}

/// Default interval for the background policy refresh on long-running servers.
pub const POLICY_REFRESH_SECS: u64 = 5;

/// Default interval for the background approval SLA sweep (V5).
pub const APPROVAL_SWEEP_SECS: u64 = 15;

/// Default interval for the background event-outbox delivery pass (V9).
pub const OUTBOX_DELIVERY_SECS: u64 = 5;

/// Run GC on this many delivery passes (so it isn't on the hot delivery path).
const OUTBOX_GC_EVERY: u64 = 60;

/// Default interval for the background intent-staged-event reconcile (D1). Short, since it only does
/// in-memory work when there are no orphaned intents (the common case is a no-op early return).
pub const PENDING_DRAIN_SECS: u64 = 5;

/// Max events delivered per pass (V9), to bound a single pass's work.
const OUTBOX_BATCH: usize = 64;

/// How long a claimed-for-delivery event is leased (V9) — comfortably longer
/// than the per-request timeout, so a live deliverer's claim isn't judged stale,
/// but short enough that a crashed deliverer's events are re-claimable promptly.
const OUTBOX_LEASE_SECS: u64 = 30;

/// One pass of outbox delivery (V9): deliver the next deliverable event per
/// subject (per-subject ordering preserved), each signed with the shared HMAC
/// secret, recording success / failure (→ retry → dead-letter). A no-op when no
/// URL/secret is configured (events are still appended + replayable via the API).
///
/// `metrics` (observability item 4 / #3) is updated for every attempt: a
/// failed delivery attempt is `warn!`-logged (subject/sequence/attempts/error)
/// and counted; a delivery that exhausts `max_attempts` and transitions to
/// `DeadLettered` is additionally `error!`-logged (previously fully silent —
/// the only prior log was on a *recording* failure, not a *delivery* failure).
pub async fn deliver_outbox_once(
    storage: &Arc<dyn StorageBackend>,
    config: &crate::outbox::OutboxConfig,
    client: &reqwest::Client,
    metrics: &OutboxMetrics,
) -> Result<(), crate::storage::StorageError> {
    let (Some(url), Some(secret)) = (config.url.as_deref(), config.hmac_secret.as_deref()) else {
        return Ok(());
    };
    // Claim and deliver ONE event at a time (up to a per-pass bound): each event
    // is leased immediately before its single POST, so its lease (>> the request
    // timeout) always covers that POST. Claiming a whole batch up front would let
    // a later event's lease expire while earlier (slow) POSTs run, re-opening the
    // cross-process double-delivery window. The claim+lease is atomic under the fd
    // lock, so a second process (web vs MCP) can't also take the same event.
    // Per-subject ordering still holds: a subject whose head is leased is skipped,
    // so each claim returns a different subject's head (round-robin, FIFO per
    // subject). Cost is one extra lock acquisition per event vs a batch — fine for
    // an outbox where the network POST dominates.
    for _ in 0..OUTBOX_BATCH {
        let mut claimed = storage
            .claim_deliverable_events(1, OUTBOX_LEASE_SECS)
            .await?;
        debug_assert!(claimed.len() <= 1, "claim(1) must return at most one event");
        let Some(event) = claimed.pop() else {
            break;
        };
        let body = serde_json::to_vec(&event.delivery_body()).unwrap_or_default();
        let signature = crate::outbox::sign_body(secret, &body);
        let outcome = client
            .post(url)
            .header("Govder-Signature", signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        let (success, error) = match outcome {
            Ok(resp) if resp.status().is_success() => (true, None),
            Ok(resp) => (false, Some(format!("delivery returned {}", resp.status()))),
            // Strip the URL from the transport error so it never logs a secret.
            Err(e) => (false, Some(e.without_url().to_string())),
        };
        if success {
            metrics.record_delivered(event.sequence);
        } else {
            metrics.record_failed();
            // Previously silent: a misaligned HMAC secret (401) or a dead consumer
            // (connection refused) produced no log at all until (if ever) the event
            // was dead-lettered. `error` was already redacted above (no URL/secret).
            warn!(
                status = "failed",
                subject = %event.subject,
                sequence = event.sequence,
                attempts = event.attempts,
                error = error.as_deref().unwrap_or("unknown"),
                "outbox delivery attempt failed"
            );
        }
        // A record failure must not abort the whole pass (the POST may have
        // succeeded; bailing here would leave it leased and re-deliver later).
        match storage
            .record_event_delivery(event.sequence, success, error, config.max_attempts)
            .await
        {
            Ok(true) => {
                // Previously fully silent (no log, no metric, no counter).
                metrics.record_dead_lettered();
                error!(
                    subject = %event.subject,
                    sequence = event.sequence,
                    attempts = event.attempts + 1,
                    "outbox event dead-lettered after exhausting delivery attempts"
                );
            }
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, sequence = event.sequence, "failed to record outbox delivery outcome");
            }
        }
    }
    Ok(())
}

/// Background loop driving outbox delivery + periodic GC (V9). Always runs (when
/// the feature is wired) so the always-on event log is bounded by retention even
/// if push delivery is unconfigured; it pushes only when a URL + secret are set.
/// Safe to run in more than one process over the shared vault — per-subject
/// delivery and the monotonic sequence are atomic under the fd lock.
pub async fn deliver_outbox_periodically(
    storage: Arc<dyn StorageBackend>,
    config: crate::outbox::OutboxConfig,
    interval: std::time::Duration,
    metrics: Arc<OutboxMetrics>,
) {
    // A per-request timeout so one slow consumer can't stall the whole pass; the
    // lease (re-claimable once stale) covers an event whose POST times out.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let mut ticks: u64 = 0;
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = deliver_outbox_once(&storage, &config, &client, &metrics).await {
            warn!(error = %e, "outbox delivery pass failed");
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(OUTBOX_GC_EVERY) {
            if let Err(e) = storage.gc_outbox(config.retention_secs).await {
                warn!(error = %e, "outbox GC failed");
            }
            // Same tick: bound the vault's unbounded maps (#2) — shed terminal approval result
            // bodies past their window and drop dead use tokens past the grace. Cheap no-op (no
            // write) when nothing is prunable, so it is safe on every GC tick.
            if let Err(e) = storage.gc_vault().await {
                warn!(error = %e, "vault GC failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// plan 088 Step 3b — the averin durable-queue delivery worker
// ---------------------------------------------------------------------------------------------
//
// A SIBLING of `deliver_outbox_once` above, never a branch of it (plan 088 D1): averin needs two
// endpoints, per-endpoint JSON bodies, and a per-record Ed25519 PoP signature — the govder
// outbox's fixed HMAC `delivery_body`/`OutboxConfig` model cannot express that, so this worker
// builds its own request bodies and reuses only `AverinClient`'s transport (`post`/`config`).
//
// Cross-process note (Step 3a, Option A): the averin queue is single-writer-PROCESS — exactly one
// live process holds the queue directory's exclusive `flock` (`FileStorage::averin_queue()` is
// `Some` only for that process; every other process seals via the 087 async fail-open path
// instead). So this worker runs entirely IN the queue-owning process and reads THAT process's own
// in-memory queue map — there is no cross-process worker reconciliation to build here.

/// Max events delivered per [`deliver_averin_outbox_once`] pass, mirroring [`OUTBOX_BATCH`]'s role
/// for the govder outbox — bounds a single pass's work.
const AVERIN_OUTBOX_BATCH: usize = 64;

/// How long a claimed-for-delivery averin event is leased, mirroring [`OUTBOX_LEASE_SECS`]'s role:
/// comfortably longer than an averin request's timeout, short enough that a stuck/panicked task's
/// events are promptly re-claimable. The queue has no cross-process claimant (Step 3a), so this
/// guards only against a stuck task within THIS same process.
const AVERIN_OUTBOX_LEASE_SECS: u64 = 30;

/// Run a synchronous, potentially fsync-blocking [`crate::storage::AverinQueue`] call without
/// stalling a multi-thread tokio runtime's worker for the whole wait — the exact "match runtime
/// flavor" idiom `PopKeyStore`/`AverinDeadLetterStore` already use for their own blocking file I/O
/// (`tokio::task::block_in_place` panics on a `current_thread` runtime, hence the match).
fn run_averin_queue_blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::current().runtime_flavor() {
        RuntimeFlavor::CurrentThread => f(),
        _ => tokio::task::block_in_place(f),
    }
}

/// Rebuild + deliver one `"averin.grant"` event (plan 088 D3). Every field the grant request needs
/// (`action`/`scope`/`use_limit`) already lives in the PoP-key entry a future enqueue site inserts
/// at mint time (Step 5, not built yet — Step 3b's tests insert entries directly); the event's OWN
/// payload carries nothing this worker reads today (reserved for future audit/debugging fields).
/// On success, writes averin's `{grant_id, capability}` back into the popkey entry (D3's
/// `GrantResolved` write-back) AND durably records the SAME resolution in the queue's own journal
/// (`AverinQueue::resolve_grant`) so a crash between the two writes is reconcilable on replay.
async fn deliver_averin_grant(
    event: &crate::outbox::OutboxEvent,
    queue: &crate::storage::AverinQueue,
    popkeys: &crate::storage::PopKeyStore,
    averin_client: &crate::averin::AverinClient,
) -> Result<(), String> {
    let token_id = event.subject.clone();
    let entry = popkeys
        .get(&token_id)
        .await
        .map_err(|e| format!("popkey lookup failed: {e}"))?
        .ok_or_else(|| format!("no PoP-key entry for token {token_id} (grant cannot be rebuilt)"))?;

    let keypair = crate::averin::pop::PopKeypair::from_seed_bytes(&entry.pop_seed);
    let agent_pubkey = keypair.agent_pubkey_b64();
    let agent_id = format!("vultrino:{token_id}");
    let resource = averin_client.config().resource_id.clone();

    let challenge = crate::averin::pop::grant_challenge(
        &entry.action,
        &agent_id,
        &agent_pubkey,
        &resource,
        &entry.scope,
    );
    let agent_sig = keypair.sign_b64(&challenge);

    // Mirrors `AverinClient::seal_grant`'s exact body shape (`src/averin/mod.rs`) — same fields,
    // same `scope_class`/`use_limit` derivation — rebuilt here from the entry instead of the
    // in-memory `pop` map `seal_grant` uses (this worker never touches that map; D1).
    let scope_class = entry.use_limit.filter(|n| *n > 1).map(|_| "bounded_reuse");
    let body = serde_json::json!({
        "idempotency_key": token_id,
        "project_id": averin_client.config().project_id,
        "session_id": averin_client.config().session_id,
        "agent_id": agent_id,
        "action": entry.action,
        "resource": resource,
        "scope": entry.scope,
        "scope_class": scope_class,
        "use_limit": entry.use_limit.filter(|n| *n > 1).unwrap_or(0),
        "agent_pubkey": agent_pubkey,
        "agent_sig": agent_sig,
        "ttl_seconds": averin_client.config().grant_ttl_secs,
    });

    let resp = averin_client
        .post("/v2/grants", &body)
        .await
        .map_err(|e| e.to_string())?;
    let grant_id = resp
        .get("grant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin grant response missing grant_id".to_string())?
        .to_string();
    let capability = resp
        .get("capability")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin grant response missing capability".to_string())?
        .to_string();

    let delivered_at = chrono::Utc::now();
    let expires_at = Some(
        delivered_at + chrono::Duration::seconds(i64::from(averin_client.config().grant_ttl_secs)),
    );

    popkeys
        .grant_resolved(
            &token_id,
            capability.clone(),
            grant_id.clone(),
            delivered_at,
            expires_at,
        )
        .await
        .map_err(|e| format!("popkey grant_resolved write-back failed: {e}"))?;

    run_averin_queue_blocking(|| queue.resolve_grant(&token_id, &grant_id, &capability))
        .map_err(|e| format!("queue GrantResolved append failed: {e}"))?;

    Ok(())
}

/// Rebuild + deliver one `"averin.use"` event. Per D3, this event only ever becomes head-of-line
/// deliverable AFTER its subject's grant has delivered (the same-subject FIFO in
/// `earliest_pending_per_subject`), so the popkey entry's `grant_id`/`capability` are expected to
/// already be populated; if they are not (defensive — should never happen under that ordering
/// guarantee) this fails the attempt (retried, eventually quarantined like any other persistent
/// failure) rather than panicking.
///
/// Plan 088 Step 4 (D5/D5b/D5c) — a deterministic, idempotent rebuild. The `averin.use` event's
/// payload shape is `{params, nonce, params_nonce, request_id, use_sequence_number}` (Step 5
/// populates it at enqueue; Step 3b's + this step's tests construct it directly). Every field is
/// read VERBATIM from the STORED event — none regenerated — so a retry of the SAME event (a
/// worker re-attempt after losing the response to a prior, already-committed POST) rebuilds the
/// EXACT same `params_commitment`/`use_sig` (Ed25519 signing is deterministic, RFC 8032) and
/// averin's `storedUseMatchesRequest` (`server.go:1990`) sees an honest retry (`idempotent:
/// true`), never a 409 that would wrongly quarantine an already-sealed use (D5).
///
/// D5b: the idempotency key includes `request_id` (`"{token_id}:use:{request_id}"`, NOT the bare
/// `"{token_id}:use"` the synchronous 087 path still uses) so a `--uses N` token's N distinct
/// executes (N distinct `request_id`s) stay N distinct averin records, while a retry of the SAME
/// event (same `request_id`) reuses the same key and dedups.
///
/// D5c: `use_sequence_number` (the `consume_use_token` post-increment `uses`, captured at
/// `src/server/mod.rs`'s execute call sites) rides verbatim into the body. averin ignores it for
/// non-bounded scope classes, so it is always included.
async fn deliver_averin_use(
    event: &crate::outbox::OutboxEvent,
    popkeys: &crate::storage::PopKeyStore,
    averin_client: &crate::averin::AverinClient,
) -> Result<(), String> {
    let token_id = event.subject.clone();
    let entry = popkeys
        .get(&token_id)
        .await
        .map_err(|e| format!("popkey lookup failed: {e}"))?
        .ok_or_else(|| format!("no PoP-key entry for token {token_id} (use cannot be rebuilt)"))?;

    let (grant_id, capability) = match (entry.grant_id.clone(), entry.capability.clone()) {
        (Some(g), Some(c)) => (g, c),
        _ => {
            return Err(format!(
                "use for token {token_id} is head-of-line but its grant has not resolved yet \
                 (unexpected under D3's per-subject ordering)"
            ))
        }
    };

    let params = event
        .payload
        .get("params")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin.use event payload missing params".to_string())?
        .as_bytes()
        .to_vec();
    // D5 — STORED, never regenerated: the whole point is that these are the SAME bytes on
    // every delivery attempt for this event.
    let nonce = event
        .payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin.use event payload missing nonce".to_string())?
        .to_string();
    let params_nonce = event
        .payload
        .get("params_nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin.use event payload missing params_nonce".to_string())?
        .to_string();
    // D5b — the per-execute idempotency-key discriminator.
    let request_id = event
        .payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "averin.use event payload missing request_id".to_string())?
        .to_string();
    // D5c — the bounded-reuse sequence number; averin ignores it for non-bounded scopes.
    let use_sequence_number = event
        .payload
        .get("use_sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "averin.use event payload missing use_sequence_number".to_string())?;

    let keypair = crate::averin::pop::PopKeypair::from_seed_bytes(&entry.pop_seed);
    let use_pop = crate::averin::build_use_pop(
        &keypair,
        &capability,
        &grant_id,
        &averin_client.config().resource_id,
        &entry.action,
        &params,
        &nonce,
        &params_nonce,
    )
    .map_err(|e| e.to_string())?;

    // Mirrors `AverinClient::seal_use`'s body shape, rebuilt from the popkey entry + this event's
    // STORED fields instead of the in-memory `pop` map (this worker never touches it; D1) — plus
    // the D5b per-execute idempotency key and the D5c `use_sequence_number`.
    let body = serde_json::json!({
        "idempotency_key": format!("{token_id}:use:{request_id}"),
        "project_id": averin_client.config().project_id,
        "session_id": averin_client.config().session_id,
        "capability": capability,
        "use_sig": use_pop.use_sig,
        "action": entry.action,
        "params": String::from_utf8_lossy(&params),
        "nonce": nonce,
        "params_nonce": params_nonce,
        "use_sequence_number": use_sequence_number,
    });

    averin_client
        .post("/v2/use", &body)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// One pass of averin durable-queue delivery (plan 088 Step 3b): claim the earliest-pending event
/// per subject (subject == `token.id`, so a grant always delivers before its use — D3's automatic
/// head-of-line join), route it by `event_type`, POST it to averin, and record the outcome.
///
/// **Dead-letter handling (D4, the finding-#2 fix)**: `OutboxStore::gc`'s contiguous-prefix prune
/// (`take_while` stopping at the first non-`Delivered` event) would let a single `DeadLettered`
/// event freeze retention of every LATER event for every subject — for this queue that would mean
/// unbounded retention of later uses' raw `params`. So a dead-letter transition here MOVES the
/// record out of the active queue into `quarantine` (a separate, independently-retention-bounded
/// store): the active queue records the sequence as terminal (GC/compaction-reclaimable) and the
/// SUBJECT advances normally (its own later events, if any, are unaffected — `DeadLettered`, like
/// `Delivered`, is terminal to `earliest_pending_per_subject`'s head-of-line check) — and, just as
/// important, OTHER subjects were never blocked by it in the first place (per-subject head-of-line
/// is independent per subject already); this worker's job is only to ensure ITS OWN error handling
/// (a failed quarantine move, a failed `record_delivery` write) never aborts the whole pass via `?`
/// and so never prevents later subjects' events from being claimed in the same or a later pass.
///
/// Runs entirely IN the queue-owning process (Step 3a: single-writer-PROCESS via an exclusive
/// `flock`) — there is no cross-process worker reconciliation here, only this process's own
/// in-memory queue map.
pub async fn deliver_averin_outbox_once(
    queue: &crate::storage::AverinQueue,
    popkeys: &crate::storage::PopKeyStore,
    quarantine: &crate::storage::AverinDeadLetterStore,
    averin_client: &crate::averin::AverinClient,
    max_attempts: u32,
) -> Result<(), crate::storage::StorageError> {
    for _ in 0..AVERIN_OUTBOX_BATCH {
        let mut claimed = run_averin_queue_blocking(|| queue.claim(1, AVERIN_OUTBOX_LEASE_SECS))?;
        let Some(event) = claimed.pop() else {
            break;
        };

        let outcome: Result<(), String> = match event.event_type.as_str() {
            "averin.grant" => deliver_averin_grant(&event, queue, popkeys, averin_client).await,
            "averin.use" => deliver_averin_use(&event, popkeys, averin_client).await,
            other => Err(format!("unknown averin durable event_type {other:?}")),
        };

        let (success, error) = match outcome {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e)),
        };
        if !success {
            warn!(
                target: "averin_seal",
                subject = %event.subject,
                sequence = event.sequence,
                event_type = %event.event_type,
                attempts = event.attempts,
                error = error.as_deref().unwrap_or("unknown"),
                "averin durable delivery attempt failed"
            );
        }

        let sequence = event.sequence;
        let record_result = run_averin_queue_blocking(|| {
            queue.record_delivery(sequence, success, error.clone(), max_attempts)
        });
        match record_result {
            Ok(true) => {
                // Dead-letter transition: fetch the authoritative terminal record
                // `record_delivery` just durably committed (its final `attempts`/`last_error`/
                // `delivery`) rather than reusing the pre-attempt `event` snapshot, then MOVE it
                // into quarantine (D4). Never logs `params`/`pop_seed` — token/project context only.
                let final_event = queue.get(sequence).unwrap_or(event);
                error!(
                    target: "averin_seal",
                    subject = %final_event.subject,
                    sequence,
                    event_type = %final_event.event_type,
                    attempts = final_event.attempts,
                    project_id = %averin_client.config().project_id,
                    "AVERIN-SEAL-DEADLETTERED averin durable event exhausted delivery attempts — \
                     moved to quarantine"
                );
                if let Err(qe) = quarantine.quarantine(final_event, chrono::Utc::now()).await {
                    // Never propagated via `?`: a quarantine-move failure must not abort the rest
                    // of this pass (that would resurrect exactly the freeze D4 exists to prevent).
                    warn!(
                        target: "averin_seal",
                        error = %qe,
                        sequence,
                        "failed to move dead-lettered averin event into quarantine (it stays \
                         terminal in the active queue; a later pass should retry the move)"
                    );
                }
            }
            Ok(false) => {}
            Err(e) => {
                warn!(
                    target: "averin_seal",
                    error = %e,
                    sequence,
                    "failed to record averin durable delivery outcome"
                );
            }
        }
    }
    Ok(())
}

/// Background loop that reconciles intent-staged events (D1 transactional outbox) to the outbox on a
/// periodic tick. Coupled emits (approval decisions / lifecycle transitions) drain inline right after
/// committing, and startup reconciles once; this tick is the SAFETY NET that bounds an orphaned
/// intent's lifetime to one interval when an inline drain failed (a transient outbox.enc I/O error)
/// on a long-lived process with no further approval traffic — so a committed decision's signed event
/// is delivered within seconds rather than only at the next restart. A no-op (early in-memory return)
/// when nothing is staged, so it is cheap to run every tick. Safe to run in more than one process:
/// the drain is idempotent (each staged event carries a dedup_id; append_deduped won't duplicate).
pub async fn drain_pending_events_periodically(
    storage: Arc<dyn StorageBackend>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = storage.reconcile_pending_events().await {
            warn!(error = %e, "intent-staged event reconcile pass failed");
        }
        // Surface a persistent backlog: a non-zero pending count after a reconcile means the outbox
        // store is unwritable — the staged events are committed-but-undelivered AND each new coupled
        // emit re-encrypts the whole secrets vault (the staging record lives there), re-opening the
        // O(vault-size) cost the v6→v7 split removed. Log the count so a stuck outbox is alertable
        // rather than silently churning the vault. (No-op/cheap when the backlog is 0, the common case.)
        match storage.pending_event_count().await {
            Ok(0) => {}
            Ok(pending) => warn!(
                pending,
                "intent-staged events remain undrained — the outbox store may be unwritable; the secrets \
                 vault is re-encrypted on every new coupled emit until this clears"
            ),
            Err(e) => warn!(error = %e, "could not read the intent-staged event backlog"),
        }
    }
}

/// One iteration of the approval SLA sweep (V5): re-read the vault, advance every
/// open request (escalate / expire) atomically, and re-ping the notifiers for
/// those that newly escalated. Free-standing so either the web or MCP process can
/// drive it over the shared, fd-locked vault.
pub async fn run_approval_sweep(
    storage: &Arc<dyn StorageBackend>,
    notifiers: &[Arc<dyn ApprovalNotifier>],
    public_base_url: Option<&str>,
) -> Result<crate::storage::ApprovalSweep, crate::storage::StorageError> {
    storage.reload().await?;
    let sweep = storage.sweep_approval_lifecycle().await?;
    for approval in &sweep.escalated {
        notify_escalation(notifiers, public_base_url, approval).await;
    }
    if !sweep.escalated.is_empty() || !sweep.expired.is_empty() {
        info!(
            escalated = sweep.escalated.len(),
            expired = sweep.expired.len(),
            "approval SLA sweep advanced lifecycle"
        );
    }
    Ok(sweep)
}

/// Re-notify the configured channels that an approval escalated (V5). The
/// plaintext decision token is not stored, so an escalation re-ping carries only
/// the panel link — the approver decides in the panel. The notifiers key their
/// payload off the request's `Escalated` status (e.g. webhook emits
/// `approval.escalated`), so this is not mislabelled as a fresh request.
async fn notify_escalation(
    notifiers: &[Arc<dyn ApprovalNotifier>],
    public_base_url: Option<&str>,
    approval: &ApprovalRequest,
) {
    if notifiers.is_empty() {
        return;
    }
    let base = public_base_url.unwrap_or("");
    let links = ApprovalLinks {
        approve_url: String::new(),
        deny_url: String::new(),
        panel_url: format!("{}/approvals", base.trim_end_matches('/')),
    };
    for notifier in notifiers {
        if let Err(e) = notifier.notify(approval, &links).await {
            warn!(
                channel = notifier.channel(),
                approval_id = %approval.id,
                error = %e,
                "Failed to deliver escalation notification"
            );
        }
    }
}

/// Background loop that periodically advances open approvals through their SLA
/// lifecycle (V5): escalate those past their first window, expire those past
/// their final deadline, and re-ping notifiers on escalation. Lazy advancement
/// also happens on each agent poll, so this loop is what drives escalation/expiry
/// for requests nobody is actively polling. Safe to run in more than one process
/// over the shared vault: the lifecycle advance is atomic under the fd lock, so
/// only the process that wins the escalation transition re-notifies.
pub async fn sweep_approvals_periodically(
    storage: Arc<dyn StorageBackend>,
    notifiers: Vec<Arc<dyn ApprovalNotifier>>,
    public_base_url: Option<String>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = run_approval_sweep(&storage, &notifiers, public_base_url.as_deref()).await {
            warn!(error = %e, "periodic approval SLA sweep failed");
        }
    }
}

/// Background loop that periodically re-reads the vault from disk and reloads
/// the policy engine from the union of config + stored policies.
///
/// This is how a long-running process that does **not** serve the admin API
/// (notably the MCP server, and a second web replica) picks up policies pushed
/// via the admin API on another process — bounded by `interval`, rather than
/// only at restart. The web process that serves the admin API reloads
/// synchronously on each write, so it is always current.
///
/// Note: this gives policy changes *bounded-staleness* propagation, not instant.
/// For an **immediate** kill, revoke the use token — that is storage-
/// authoritative and re-checked under the lock on every gated call.
pub async fn refresh_policies_periodically(
    storage: Arc<dyn StorageBackend>,
    engine: Arc<PolicyEngine>,
    config_policies: Vec<crate::policy::Policy>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = refresh_policies_once(&storage, &engine, &config_policies).await {
            warn!(error = %e, "periodic policy refresh failed");
        }
    }
}

/// One iteration of the cross-process policy refresh: re-read the vault from
/// disk and reload the engine from the config+stored union. Separated from the
/// loop for testability.
pub async fn refresh_policies_once(
    storage: &Arc<dyn StorageBackend>,
    engine: &PolicyEngine,
    config_policies: &[crate::policy::Policy],
) -> Result<(), crate::storage::StorageError> {
    storage.reload().await?;
    let stored = storage.list_stored_policies().await?;
    engine.load_policies(merge_policies(config_policies, stored));
    Ok(())
}

/// Background loop that periodically rebuilds the shared [`AuthManager`] from the
/// vault, so a `vk_` API key revoked/expired — or a role narrowed — via the admin
/// API on *another* process (the web writer, or an HA web replica) stops
/// authenticating on THIS process within `interval`, rather than only after a
/// restart. This is the API-key/role analogue of [`refresh_policies_periodically`].
///
/// Note: like policies, this gives `vk_` revocation **bounded-staleness**
/// propagation, not instant. Use tokens (`vut_`) remain immediate — they are
/// re-read from storage and re-checked under the vault lock on every gated call.
pub async fn refresh_auth_periodically(
    storage: Arc<dyn StorageBackend>,
    auth_manager: Arc<tokio::sync::RwLock<AuthManager>>,
    interval: std::time::Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = refresh_auth_once(&storage, &auth_manager).await {
            warn!(error = %e, "periodic auth refresh failed");
        }
    }
}

/// One iteration of the cross-process auth refresh: re-read the vault from disk and
/// rebuild the shared `AuthManager` from the stored roles + API keys. Rebuilding via
/// [`AuthManager::from_data`] swaps the whole manager under the write lock in one
/// assignment, so no half-updated key/role map is ever observable (mirrors
/// `web::api::refresh_auth_data`, which the admin write handlers call synchronously
/// on the process that serves them). Separated from the loop for testability.
///
/// Fail-closed on error: the `?` returns before the write lock is taken, so a
/// storage error keeps the previous (last-known-good) manager rather than clearing
/// the map (which would deny every key) — the loop logs and retries next tick.
pub async fn refresh_auth_once(
    storage: &Arc<dyn StorageBackend>,
    auth_manager: &Arc<tokio::sync::RwLock<AuthManager>>,
) -> Result<(), crate::storage::StorageError> {
    storage.reload().await?;
    let stored_roles = storage.list_roles().await?;
    let stored_keys = storage.list_api_keys().await?;
    let mut guard = auth_manager.write().await;
    *guard = AuthManager::from_data(stored_roles, stored_keys);
    Ok(())
}

/// Merge static config policies with admin-managed stored policies into the
/// engine's policy set: config first, then stored.
///
/// We deliberately do **not** dedup by id. Dropping a policy on an id collision
/// could silently drop a stored `Deny` — fail-open in a default-deny system.
/// The evaluator already handles multiple matching policies, so keeping both is
/// safe; and the admin API manages stored policies by id independently (a config
/// policy that coincidentally shares an id is config-managed and unaffected by
/// an API delete/PUT). Order is preserved since evaluation is order-sensitive.
pub fn merge_policies(
    config_policies: &[crate::policy::Policy],
    stored: Vec<crate::policy::Policy>,
) -> Vec<crate::policy::Policy> {
    let mut all = Vec::with_capacity(config_policies.len() + stored.len());
    all.extend_from_slice(config_policies);
    all.extend(stored);
    all
}

/// The startup warning (if any) for a given enforcement posture and whether any
/// policies are configured. Extracted as a pure function so the decision is
/// unit-testable without capturing log output. Both zero-policy postures are
/// dangerous misconfigurations worth surfacing loudly.
fn zero_policy_enforcement_warning(default_deny: bool, has_policies: bool) -> Option<&'static str> {
    if has_policies {
        return None;
    }
    Some(if default_deny {
        "enforcement default_action is 'deny' but no policies are configured — ALL credential \
         use will be denied until an allow policy is added (via config or the admin API). Set \
         `[enforcement] default_action = \"allow\"` to opt into the legacy fail-open behavior."
    } else {
        "enforcement default_action is 'allow' and no policies are configured — FAIL-OPEN: every \
         credential is usable by any principal with execute access, with no per-credential \
         restriction. Add allow/deny policies, or set `[enforcement] default_action = \"deny\"` \
         for the secure default."
    })
}

/// Parse action string into plugin name and action name
/// Format: "plugin.action" or just "action" (defaults to http plugin)
fn parse_action(action: &str) -> Result<(&str, &str), VultrinoError> {
    if let Some((plugin, action)) = action.split_once('.') {
        Ok((plugin, action))
    } else {
        // Default to http plugin
        Ok(("http", action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn irreversibility_test_server() -> (VultrinoServer, Arc<dyn StorageBackend>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        std::mem::forget(dir);
        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::FileStorage::new(&path, &secrecy::SecretString::from("test-password"))
                .await
                .unwrap(),
        );
        let server = VultrinoServer::new(
            Config::default(),
            storage.clone(),
            CredentialResolver::new(storage.clone()),
        );
        (server, storage)
    }

    #[test]
    fn test_parse_action() {
        let (plugin, action) = parse_action("http.request").unwrap();
        assert_eq!(plugin, "http");
        assert_eq!(action, "request");

        let (plugin, action) = parse_action("crypto.sign").unwrap();
        assert_eq!(plugin, "crypto");
        assert_eq!(action, "sign");

        // Default to http
        let (plugin, action) = parse_action("request").unwrap();
        assert_eq!(plugin, "http");
        assert_eq!(action, "request");
    }

    #[test]
    fn test_merge_policies_keeps_both_never_drops_stored() {
        use crate::policy::Policy;
        let mut c = Policy::allow_all("cfg", "*");
        c.id = "shared".to_string();
        let mut s_dup = Policy::deny_all("stored-dup", "*");
        s_dup.id = "shared".to_string(); // same id as config — must NOT be dropped
        let s_new = Policy::deny_all("stored-new", "x-*");

        let merged = merge_policies(&[c], vec![s_dup, s_new]);
        // Nothing is dropped on an id collision — a stored Deny is never silently
        // lost (that would be fail-open). Config comes first; order preserved.
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].name, "cfg");
        assert!(merged.iter().any(|p| p.name == "stored-dup"));
        assert!(merged.iter().any(|p| p.name == "stored-new"));
    }

    #[test]
    fn test_zero_policy_enforcement_warning() {
        // Deny + no policies → "everything denied" warning.
        assert!(zero_policy_enforcement_warning(true, false)
            .unwrap()
            .contains("will be denied"));
        // Allow + no policies → fail-open warning.
        assert!(zero_policy_enforcement_warning(false, false)
            .unwrap()
            .contains("FAIL-OPEN"));
        // With policies configured, no warning regardless of posture.
        assert!(zero_policy_enforcement_warning(true, true).is_none());
        assert!(zero_policy_enforcement_warning(false, true).is_none());
    }

    #[tokio::test]
    async fn trusted_irreversibility_uses_strictest_canonical_match_and_fails_unknown_closed() {
        use crate::capability::{Capability, CapabilityTarget};
        let (server, storage) = irreversibility_test_server().await;
        for (id, reversibility) in [
            ("a-reversible", "reversible"),
            ("b-irreversible", "irreversible"),
        ] {
            storage
                .store_capability(&Capability {
                    id: id.to_string(),
                    tool_name: id.replace('-', "_"),
                    description: id.to_string(),
                    action: "http.request".to_string(),
                    plugin: Some("http".to_string()),
                    target: CapabilityTarget::default(),
                    credential_ref: "cred".to_string(),
                    input_schema: serde_json::json!({}),
                    reversibility: reversibility.to_string(),
                    llm: None,
                    approval_preview: None,
                })
                .await
                .unwrap();
        }
        assert!(
            server
                .trusted_irreversible_for_action("http.request", None)
                .await
        );
        assert!(
            server
                .trusted_irreversible_for_action("unknown.action", None)
                .await
        );
    }
}

/// Tests for plan 088 Step 3b's `deliver_averin_outbox_once` (+ its `deliver_averin_grant`/
/// `deliver_averin_use` routing helpers), against a RESPONDING fake averin. Adapted from
/// `src/averin/mod.rs`'s `blocked_averin` — a raw `tokio::net::TcpListener` that accepts and never
/// answers — into an axum router that actually answers `/v2/grants`/`/v2/use` (axum is already a
/// main dependency of this crate for the real server, so this needs no new dependency).
#[cfg(test)]
mod averin_worker_tests {
    use super::*;
    use crate::averin::{AverinClient, AverinConfig};
    use crate::crypto::MasterKey;
    use crate::outbox::{DeliveryState, OutboxEvent};
    use crate::storage::{AverinDeadLetterStore, AverinQueue, PopKeyEntry, PopKeyStore, QuarantineStatus};
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::collections::{HashMap, HashSet};

    /// What the fake averin observed, in receipt order (a single shared log across BOTH
    /// endpoints — the only way a test can assert grant-BEFORE-use ordering, not just presence)
    /// plus two failure-injection sets so a test can force a specific subject's grant or use to
    /// fail deterministically (no real network outage needed to test the retry/dead-letter path).
    #[derive(Default)]
    struct FakeAverinState {
        call_log: parking_lot::Mutex<Vec<String>>,
        /// `agent_id` values whose `/v2/grants` call should return 500.
        fail_grant_agents: parking_lot::Mutex<HashSet<String>>,
        /// `action` values whose `/v2/use` call should return 500.
        fail_use_actions: parking_lot::Mutex<HashSet<String>>,
        /// Plan 088 Step 4 (D5) — every `/v2/use` request body received, IN ORDER, regardless of
        /// whether it was a fresh use or an idempotent replay — so a test can assert two POST
        /// bodies for the SAME retried event are byte-identical (D5's determinism contract).
        use_request_bodies: parking_lot::Mutex<Vec<serde_json::Value>>,
        /// `idempotency_key -> (the first body seen under it, the record_id minted for it)` —
        /// mirrors averin's real `storedUseMatchesRequest` (`server.go:1990`): a repeat key with
        /// a MATCHING body is an honest retry (return the same record, `idempotent: true`); a
        /// repeat key with a DIFFERENT body is the real 409 conflict (`:1994`/`:2035`).
        use_by_idempotency_key: parking_lot::Mutex<HashMap<String, (serde_json::Value, String)>>,
    }

    async fn fake_grants(
        State(state): State<Arc<FakeAverinState>>,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let agent_id = body
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if state.fail_grant_agents.lock().contains(&agent_id) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "forced grant failure"})),
            );
        }
        state.call_log.lock().push(format!("grant:{agent_id}"));
        let grant_id = format!("grant-{agent_id}");
        // `credential_binding` (src/averin/pop.rs) splits at the first '.' and base64url-decodes
        // the payload half — so, unlike a real averin capability, this fake's payload half must
        // ITSELF be valid base64url (a plain "cap-{agent_id}" would fail to decode, since agent_id
        // contains ':').
        use base64::Engine;
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(agent_id.as_bytes());
        let capability = format!("{payload_b64}.sig");
        (
            StatusCode::OK,
            Json(serde_json::json!({"grant_id": grant_id, "capability": capability})),
        )
    }

    async fn fake_use(
        State(state): State<Arc<FakeAverinState>>,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let action = body
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if state.fail_use_actions.lock().contains(&action) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "forced use failure"})),
            );
        }
        // Plan 088 Step 4 (D5) — record EVERY request body received, regardless of what happens
        // next, so a test can compare two attempts byte-for-byte.
        state.use_request_bodies.lock().push(body.clone());

        let idempotency_key = body
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        {
            let mut by_key = state.use_by_idempotency_key.lock();
            if let Some((prior_body, record_id)) = by_key.get(&idempotency_key) {
                if *prior_body == body {
                    // An honest retry (D5): the SAME operation replayed under the SAME key —
                    // return the already-sealed record, mirroring averin's idempotent dedup.
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({"record": {"record_id": record_id}, "idempotent": true})),
                    );
                }
                // A DIFFERENT operation reusing an already-claimed key — averin's real 409.
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": "idempotency key reused with a mismatched request"})),
                );
            }
            let capability = body
                .get("capability")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut log = state.call_log.lock();
            log.push(format!("use:{capability}"));
            let record_id = format!("rec-{}", log.len());
            drop(log);
            by_key.insert(idempotency_key, (body, record_id.clone()));
            (
                StatusCode::OK,
                Json(serde_json::json!({"record": {"record_id": record_id}})),
            )
        }
    }

    /// Stand up a RESPONDING fake averin on an ephemeral local port. Returns its base_url plus the
    /// shared observation/failure-injection state a test manipulates.
    async fn responding_averin() -> (String, Arc<FakeAverinState>) {
        let state = Arc::new(FakeAverinState::default());
        let app = Router::new()
            .route("/v2/grants", post(fake_grants))
            .route("/v2/use", post(fake_use))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), state)
    }

    fn test_client(base_url: &str) -> AverinClient {
        AverinClient::new(AverinConfig {
            enabled: true,
            base_url: base_url.to_string(),
            resource_id: "orders-db".to_string(),
            ..AverinConfig::default()
        })
        .expect("client builds")
        .expect("client is Some when enabled")
    }

    fn test_stores(dir: &std::path::Path) -> (AverinQueue, PopKeyStore, AverinDeadLetterStore) {
        let key = Arc::new(MasterKey::from_bytes(vec![5u8; 32]).unwrap());
        let queue = AverinQueue::open(dir.join("averin-queue"), Arc::clone(&key)).unwrap();
        let popkeys = PopKeyStore::new(dir.join("averin-popkeys.enc"), Arc::clone(&key));
        let deadletter = AverinDeadLetterStore::new(dir.join("averin-deadletter.enc"), key);
        (queue, popkeys, deadletter)
    }

    fn popkey_entry(action: &str, scope: &str) -> PopKeyEntry {
        PopKeyEntry {
            pop_seed: [7u8; 32],
            action: action.to_string(),
            scope: scope.to_string(),
            use_limit: None,
            capability: None,
            grant_id: None,
            minted_at: chrono::Utc::now(),
            grant_delivered_at: None,
            grant_expires_at: None,
            abandoned: false,
        }
    }

    /// Plan 088 Step 4 (D5/D5b/D5c) — the `averin.use` event's full payload shape:
    /// `{params, nonce, params_nonce, request_id, use_sequence_number}`. `deliver_averin_use`
    /// requires all five fields (a real enqueue, Step 5, will populate them); `params_nonce`
    /// must be 64 lowercase hex chars (`pop::params_commitment` validates it strictly), `nonce`
    /// may be any non-empty string. Distinct `request_id`s give distinct D5b idempotency keys; a
    /// retry of the SAME logical event reuses the SAME `request_id` (see the dedicated retry
    /// test below, which reuses one whole event rather than this helper twice).
    fn use_payload(params: &str, request_id: &str, use_sequence_number: u32) -> serde_json::Value {
        serde_json::json!({
            "params": params,
            "nonce": format!("nonce-{request_id}"),
            "params_nonce": "ab".repeat(32),
            "request_id": request_id,
            "use_sequence_number": use_sequence_number,
        })
    }

    #[tokio::test]
    async fn averin_worker_delivers_grant_then_use_in_order_for_one_subject() {
        let dir = tempfile::tempdir().unwrap();
        let (queue, popkeys, deadletter) = test_stores(dir.path());
        let (base_url, fake) = responding_averin().await;
        let client = test_client(&base_url);

        popkeys
            .insert("tok-1", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        let grant_seq = queue
            .append("tok-1", "averin.grant", serde_json::json!({}))
            .unwrap();
        let use_seq = queue
            .append("tok-1", "averin.use", use_payload("hello-world", "req-1", 1))
            .unwrap();
        assert!(grant_seq < use_seq);

        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();

        // Both delivered — nothing left pending for this subject.
        assert!(queue.deliverable(10).is_empty());
        assert_eq!(
            queue.get(grant_seq).unwrap().delivery,
            DeliveryState::Delivered
        );
        assert_eq!(
            queue.get(use_seq).unwrap().delivery,
            DeliveryState::Delivered
        );

        // The grant resolution landed in BOTH the popkey store (D3 write-back) and the queue's own
        // journal (`GrantResolved`, the reconciliation source on a crash between the two writes).
        let entry = popkeys.get("tok-1").await.unwrap().unwrap();
        assert!(entry.grant_id.is_some());
        assert!(entry.capability.is_some());
        assert!(entry.grant_delivered_at.is_some());
        assert_eq!(
            queue.resolved_grant("tok-1"),
            Some((
                entry.grant_id.clone().unwrap(),
                entry.capability.clone().unwrap()
            ))
        );

        // Ordering: the grant call landed in the fake's log BEFORE the use call.
        let log = fake.call_log.lock().clone();
        assert_eq!(
            log.len(),
            2,
            "exactly one grant + one use reached the fake averin: {log:?}"
        );
        assert!(log[0].starts_with("grant:"), "grant must be first: {log:?}");
        assert!(log[1].starts_with("use:"), "use must follow its grant: {log:?}");

        assert!(deadletter.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn averin_worker_withholds_use_until_its_grant_delivers() {
        let dir = tempfile::tempdir().unwrap();
        let (queue, popkeys, deadletter) = test_stores(dir.path());
        let (base_url, fake) = responding_averin().await;
        let client = test_client(&base_url);

        let agent_id = "vultrino:tok-2";
        fake.fail_grant_agents.lock().insert(agent_id.to_string());

        popkeys
            .insert("tok-2", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        queue
            .append("tok-2", "averin.grant", serde_json::json!({}))
            .unwrap();
        queue
            .append("tok-2", "averin.use", use_payload("p", "req-2", 1))
            .unwrap();

        // Pass 1: the grant fails (forced 500). The use must NEVER even be attempted while its
        // grant is still Pending — D3's per-subject head-of-line ordering, exercised under an
        // adversarial (failing) grant rather than just the happy-path enqueue order.
        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();
        assert!(
            fake.call_log.lock().is_empty(),
            "the use must not reach averin while its grant is still pending: {:?}",
            fake.call_log.lock()
        );
        let deliverable = queue.deliverable(10);
        assert_eq!(deliverable.len(), 1, "only the grant is head-of-line");
        assert_eq!(deliverable[0].event_type, "averin.grant");
        assert!(popkeys
            .get("tok-2")
            .await
            .unwrap()
            .unwrap()
            .grant_id
            .is_none());

        // A second pass, still with the grant failing, must ALSO never let the use slip through
        // (the withholding isn't a one-shot accident of pass 1's particular claim order) — the
        // failed grant is now leased/backed off, so this pass claims nothing at all and is a no-op,
        // which is itself the point: there is no path from "grant not yet delivered" to "use
        // attempted" in this worker.
        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();
        assert!(
            fake.call_log.lock().is_empty(),
            "still nothing reached averin while the grant remains undelivered: {:?}",
            fake.call_log.lock()
        );

        // Once the grant genuinely succeeds (a fresh subject, so no backoff lease to wait out),
        // grant-then-use deliver in order for it — the SAME property test 1 already covers,
        // confirming this isn't a client/fake wiring bug specific to tok-2.
        fake.fail_grant_agents.lock().remove(agent_id);
        popkeys
            .insert("tok-2b", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        queue
            .append("tok-2b", "averin.grant", serde_json::json!({}))
            .unwrap();
        queue
            .append("tok-2b", "averin.use", use_payload("p", "req-2b", 1))
            .unwrap();
        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();
        let log = fake.call_log.lock().clone();
        assert_eq!(log.len(), 2, "tok-2b's grant + use both land: {log:?}");
        assert!(log[0].starts_with("grant:"));
        assert!(log[1].starts_with("use:"));
    }

    #[tokio::test]
    async fn averin_worker_deadletter_quarantines_one_subject_without_blocking_others() {
        let dir = tempfile::tempdir().unwrap();
        let (queue, popkeys, deadletter) = test_stores(dir.path());
        let (base_url, fake) = responding_averin().await;
        let client = test_client(&base_url);

        // Subject A's use always fails; B and C succeed normally.
        fake.fail_use_actions.lock().insert("action-A".to_string());

        for (subject, action) in [("A", "action-A"), ("B", "action-B"), ("C", "action-C")] {
            popkeys
                .insert(subject, popkey_entry(action, "read:orders"))
                .await
                .unwrap();
            queue
                .append(subject, "averin.grant", serde_json::json!({}))
                .unwrap();
            queue
                .append(
                    subject,
                    "averin.use",
                    use_payload("p", &format!("req-{subject}"), 1),
                )
                .unwrap();
        }

        // max_attempts=1: A's use dead-letters on its FIRST failed attempt (no backoff wait
        // needed), all within this ONE pass — B/C's events are all claimable in the same pass too
        // (the 64-event batch bound comfortably covers these 6 events).
        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 1)
            .await
            .unwrap();

        // A's use is quarantined — MOVED out of the active queue, not a frozen tombstone.
        let quarantined = deadletter.list().await.unwrap();
        assert_eq!(
            quarantined.len(),
            1,
            "exactly A's use is quarantined: {quarantined:?}"
        );
        assert_eq!(quarantined[0].event.subject, "A");
        assert_eq!(quarantined[0].event.event_type, "averin.use");
        assert_eq!(quarantined[0].status, QuarantineStatus::Open);

        // B and C were NOT blocked by A's dead-letter: both delivered within the SAME pass.
        let log = fake.call_log.lock().clone();
        let use_count = log.iter().filter(|l| l.starts_with("use:")).count();
        assert_eq!(use_count, 2, "B and C's uses both reached averin: {log:?}");
        let grant_count = log.iter().filter(|l| l.starts_with("grant:")).count();
        assert_eq!(grant_count, 3, "all three subjects' grants delivered: {log:?}");

        // Nothing left Pending anywhere: A's grant Delivered + A's use DeadLettered (terminal, so
        // it no longer blocks anything, including this subject's OWN later events, let alone B/C's
        // — the exact `OutboxStore::gc` contiguous-prefix freeze this plan's D4 avoids).
        assert!(queue.deliverable(10).is_empty());
    }

    #[tokio::test]
    async fn averin_worker_unknown_event_type_fails_closed_without_blocking_the_pass() {
        // Defensive: an unrecognized event_type must not panic and must not silently "succeed" —
        // it fails the attempt (retried/eventually quarantined like any other failure) and must
        // not stop a later subject's event in the same pass from being processed.
        let dir = tempfile::tempdir().unwrap();
        let (queue, popkeys, deadletter) = test_stores(dir.path());
        let (base_url, _fake) = responding_averin().await;
        let client = test_client(&base_url);

        queue
            .append("weird", "averin.mystery", serde_json::json!({}))
            .unwrap();
        popkeys
            .insert("normal", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        queue
            .append("normal", "averin.grant", serde_json::json!({}))
            .unwrap();

        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();

        // The unknown-type event stays Pending after one failed attempt (not Delivered, not yet
        // DeadLettered at max_attempts=8) — `deliverable()` ignores lease (a read-only peek), so
        // it still shows up; the "normal" subject's grant is gone from this list because it
        // Delivered (terminal, no longer Pending).
        let remaining = queue.deliverable(10);
        assert_eq!(
            remaining.len(),
            1,
            "only the still-pending unknown-type event remains: {remaining:?}"
        );
        assert_eq!(remaining[0].subject, "weird");
        // The unknown event stayed Pending (retried later), never Delivered/DeadLettered on its
        // very first attempt; the normal subject's grant delivered in the SAME pass regardless.
        assert!(
            popkeys
                .get("normal")
                .await
                .unwrap()
                .unwrap()
                .grant_id
                .is_some(),
            "the unrelated subject's grant still delivered in the same pass"
        );
    }

    /// Plan 088 Step 4 (D5, adversarial finding #3's exact scenario): a durable use is
    /// delivered, then the worker RETRIES the SAME event (e.g. it lost the response to a POST
    /// averin had already committed). `deliver_averin_use` reads only STORED fields
    /// (`nonce`/`params_nonce`/`params`/`request_id`/`use_sequence_number`) and never
    /// regenerates them, so the two attempts must produce byte-identical POST bodies — which is
    /// exactly what lets the fake (mirroring averin's real `storedUseMatchesRequest`,
    /// `server.go:1990`) treat the second call as an honest retry (`idempotent: true`) instead
    /// of a 409 that would wrongly quarantine an already-sealed use.
    #[tokio::test]
    async fn averin_worker_use_retry_of_same_event_is_byte_identical_and_idempotent_not_409() {
        let dir = tempfile::tempdir().unwrap();
        let (_queue, popkeys, _deadletter) = test_stores(dir.path());
        let (base_url, fake) = responding_averin().await;
        let client = test_client(&base_url);

        popkeys
            .insert("tok-retry", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        popkeys
            .grant_resolved(
                "tok-retry",
                "AAAA.sig".to_string(),
                "grant-retry".to_string(),
                chrono::Utc::now(),
                None,
            )
            .await
            .unwrap();

        let event = OutboxEvent {
            sequence: 1,
            subject: "tok-retry".to_string(),
            event_type: "averin.use".to_string(),
            payload: use_payload("hello", "req-retry", 1),
            created_at: chrono::Utc::now(),
            delivery: DeliveryState::Pending,
            attempts: 0,
            leased_until: None,
            last_attempt_at: None,
            last_error: None,
            dedup_id: None,
        };

        deliver_averin_use(&event, &popkeys, &client)
            .await
            .expect("first delivery succeeds");
        deliver_averin_use(&event, &popkeys, &client)
            .await
            .expect("a retry of the SAME event must ALSO succeed (idempotent, not a 409)");

        let bodies = fake.use_request_bodies.lock().clone();
        assert_eq!(
            bodies.len(),
            2,
            "both attempts reached the fake averin: {bodies:?}"
        );
        assert_eq!(
            bodies[0], bodies[1],
            "a retry of the SAME event must produce a byte-identical POST body (nonce, \
             params_nonce, use_sig, idempotency_key — the D5 determinism contract)"
        );
        // Exactly one averin record was actually minted; the retry deduped rather than
        // spuriously creating a second one.
        let use_calls = fake
            .call_log
            .lock()
            .iter()
            .filter(|l| l.starts_with("use:"))
            .count();
        assert_eq!(
            use_calls, 1,
            "the retry must dedup at averin, not mint a second record"
        );
    }

    /// Plan 088 Step 4 (D5b/D5c) — a bounded-reuse (`--uses N`) token's DISTINCT executes (each
    /// with its own `request_id`) must land at averin as DISTINCT idempotency keys carrying
    /// their correct 1-based `use_sequence_number` — never collapsed into one record the way the
    /// bare 087-era `"{token_id}:use"` key would (D5b), and never omitting the sequence number
    /// bounded-reuse capabilities require (D5c).
    #[tokio::test]
    async fn averin_worker_multi_use_token_gets_distinct_keys_and_sequence_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let (queue, popkeys, deadletter) = test_stores(dir.path());
        let (base_url, fake) = responding_averin().await;
        let client = test_client(&base_url);

        popkeys
            .insert("tok-multi", popkey_entry("db.query:orders-ro", "read:orders"))
            .await
            .unwrap();
        queue
            .append("tok-multi", "averin.grant", serde_json::json!({}))
            .unwrap();
        queue
            .append("tok-multi", "averin.use", use_payload("p1", "req-1", 1))
            .unwrap();
        queue
            .append("tok-multi", "averin.use", use_payload("p2", "req-2", 2))
            .unwrap();

        // One pass: the 64-event batch bound comfortably covers grant + both uses for this one
        // subject, each becoming head-of-line in turn as the previous one delivers (D3).
        deliver_averin_outbox_once(&queue, &popkeys, &deadletter, &client, 8)
            .await
            .unwrap();

        let bodies = fake.use_request_bodies.lock().clone();
        assert_eq!(
            bodies.len(),
            2,
            "both distinct uses reached averin: {bodies:?}"
        );

        let key1 = bodies[0]["idempotency_key"].as_str().unwrap();
        let key2 = bodies[1]["idempotency_key"].as_str().unwrap();
        assert_eq!(key1, "tok-multi:use:req-1");
        assert_eq!(key2, "tok-multi:use:req-2");
        assert_ne!(
            key1, key2,
            "distinct executes must get DISTINCT idempotency keys (D5b)"
        );

        assert_eq!(bodies[0]["use_sequence_number"].as_u64(), Some(1));
        assert_eq!(bodies[1]["use_sequence_number"].as_u64(), Some(2));

        assert!(queue.deliverable(10).is_empty());
        assert!(deadletter.list().await.unwrap().is_empty());
    }
}
