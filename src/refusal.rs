//! Gateway refusals as sealed records (feir-ops#1, "refusals on proof").
//!
//! Every time the gateway refuses an authenticated agent (not granted, policy deny, kill fence,
//! rate or spend cap, cross tenant, unusable token, LLM channel rules, strict capability mode,
//! approvals off, a decision that could not be established) the refusal is *noted* here and later
//! sealed by averin as a `gateway-refusal` record through `POST /v2/refusals`.
//!
//! Two properties are the whole point of this module:
//!
//! * **Noting never blocks and never changes the refusal.** [`RefusalRecorder::note`] is
//!   synchronous: one mutex, O(1) map work, no await, no I/O, no allocation that can fail the
//!   caller. The error the caller returns is untouched; sealing happens later in a background
//!   drain ([`crate::averin::AverinClient::drain_refusals_once`]).
//! * **Volume is bounded, counts are exact.** One record per (agent, action, reason class, entry
//!   point) per window (the first refusal of a window is sealed at the next drain, the rest of the
//!   window coalesce into one tail record), then a global token bucket. When the bucket is empty
//!   the refusals merge into one summary record with exact per-class counts. A storm therefore
//!   cannot push an averin month past its size cap.
//!
//! Nothing here ever carries params, a URL, a payload, vultrino's free-text refusal reason, or any
//! token material. The record is built from closed vocabularies plus two sanitized names.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

/// The closed reason classes. The spellings are the wire vocabulary of averin's
/// `vectors/refusal-classes.v1.json` (vendored in `vectors/`, pinned by a test below).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefusalClass {
    /// No permission, credential not accessible, token not scoped to the credential or action,
    /// tool not available to a use token or unknown, /llm channel or model not granted.
    NotGranted,
    /// A policy rule or the default action denied the request.
    PolicyDeny,
    /// A kill switch or the P3 epoch fence refused the work.
    KillFence,
    /// A RateLimit guard refused the request.
    RateLimit,
    /// A SpendCap guard refused the request.
    SpendCap,
    /// V11 tenant isolation.
    CrossTenant,
    /// A valid token that is revoked, expired or used up.
    TokenUnusable,
    /// An LLM credential used off the /llm channel.
    LlmChannelOnly,
    /// /llm model without a price.
    ModelUnpriced,
    /// /llm price modifier without a price.
    ModifierUnpriced,
    /// /llm provider disabled.
    ProviderDisabled,
    /// Strict declared-capability mode and the action has no exact declaration.
    CapabilityUndeclared,
    /// Approval required but approvals are off.
    ApprovalUnavailable,
    /// Fail-closed: the catalog, the vault kill-fence read, govder's recipe, the permit kernel or
    /// the evidence floor could not establish a decision.
    DecisionUnavailable,
}

impl RefusalClass {
    /// Every class, in vocabulary order.
    pub const ALL: [RefusalClass; 14] = [
        Self::NotGranted,
        Self::PolicyDeny,
        Self::KillFence,
        Self::RateLimit,
        Self::SpendCap,
        Self::CrossTenant,
        Self::TokenUnusable,
        Self::LlmChannelOnly,
        Self::ModelUnpriced,
        Self::ModifierUnpriced,
        Self::ProviderDisabled,
        Self::CapabilityUndeclared,
        Self::ApprovalUnavailable,
        Self::DecisionUnavailable,
    ];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotGranted => "not_granted",
            Self::PolicyDeny => "policy_deny",
            Self::KillFence => "kill_fence",
            Self::RateLimit => "rate_limit",
            Self::SpendCap => "spend_cap",
            Self::CrossTenant => "cross_tenant",
            Self::TokenUnusable => "token_unusable",
            Self::LlmChannelOnly => "llm_channel_only",
            Self::ModelUnpriced => "model_unpriced",
            Self::ModifierUnpriced => "modifier_unpriced",
            Self::ProviderDisabled => "provider_disabled",
            Self::CapabilityUndeclared => "capability_undeclared",
            Self::ApprovalUnavailable => "approval_unavailable",
            Self::DecisionUnavailable => "decision_unavailable",
        }
    }
}

/// The entry point a refused request came in through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RefusalEntry {
    /// An MCP `tools/call` (stdio or HTTP).
    Mcp,
    /// `POST /api/v1/execute`, and any other direct `execute_gated` caller.
    #[default]
    Execute,
    /// The metered LLM proxy, `POST /llm`.
    Llm,
    /// The deferred execution of an approved request.
    ApprovalResume,
}

impl RefusalEntry {
    /// Every entry point, in vocabulary order.
    pub const ALL: [RefusalEntry; 4] = [Self::Mcp, Self::Execute, Self::Llm, Self::ApprovalResume];

    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Execute => "execute",
            Self::Llm => "llm",
            Self::ApprovalResume => "approval_resume",
        }
    }
}

/// Maximum length of an agent, action or credential name in the record (averin's bound).
const MAX_NAME_LEN: usize = 128;

/// The literal averin stores for a name outside the plain-identifier set.
pub const INVALID_NAME: &str = "invalid_name";

/// Admit only a short plain identifier (`[A-Za-z0-9._:-]{1,128}`, averin's rule) that does not look
/// like gateway token material. Anything else becomes [`INVALID_NAME`]: an agent-supplied tool or
/// action name reaches a permanent record only through this filter.
pub fn sanitize_name(name: &str) -> String {
    let plain = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    // A presented bearer (`vk_...` / `vut_...`) pasted into a name must never be sealed.
    let looks_like_secret = name.contains("vk_") || name.contains("vut_");
    if plain && !looks_like_secret {
        name.to_string()
    } else {
        INVALID_NAME.to_string()
    }
}

/// Who was refused, where, for what. Built at the refusal site from values the gateway resolved
/// itself (the stored principal row, the resolved credential alias, the canonical action) or, before
/// resolution, from the presented action name (sanitized by [`RefusalCtx::sanitized`]).
#[derive(Debug, Clone)]
pub struct RefusalCtx {
    /// The entry point.
    pub entry: RefusalEntry,
    /// The enforcement principal: the token or key `agent_label`, else `vultrino:<id>`. `None`
    /// when there is no authenticated principal (local use): nothing is noted then, because there
    /// is no agent to attribute the attempt to.
    pub agent: Option<String>,
    /// The resolved credential alias; `None` until the credential is resolved.
    pub credential: Option<String>,
    /// The canonical action, or the presented tool or action name before canonicalization.
    pub action: String,
}

impl RefusalCtx {
    /// A context for `entry`. `principal` is `(principal_id, agent_label)` of the authenticated
    /// caller as the stored row records it.
    pub fn new(entry: RefusalEntry, principal: Option<(&str, Option<&str>)>, action: &str) -> Self {
        Self {
            entry,
            agent: principal.map(|(id, label)| agent_name(id, label)),
            credential: None,
            action: action.to_string(),
        }
    }

    /// The same context once the credential and canonical action are resolved.
    pub fn resolved(mut self, credential: &str, action: &str) -> Self {
        self.credential = Some(credential.to_string());
        self.action = action.to_string();
        self
    }

    /// The same context with a different entry point (an approval resumed through another door).
    pub fn with_entry(mut self, entry: RefusalEntry) -> Self {
        self.entry = entry;
        self
    }

    /// The names as they will be sealed.
    pub fn sanitized(&self) -> Option<(String, String, Option<String>)> {
        let agent = self.agent.as_ref()?;
        Some((
            sanitize_name(agent),
            sanitize_name(&self.action),
            self.credential.as_deref().map(sanitize_name),
        ))
    }
}

/// The enforcement label, else `vultrino:<principal id>` (the use-receipt agent shape).
fn agent_name(id: &str, label: Option<&str>) -> String {
    match label.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) if sanitize_name(l) != INVALID_NAME => l.to_string(),
        _ => format!("vultrino:{id}"),
    }
}

/// Recorder settings (`[averin] seal_refusals`, `refusal_window_secs`, `refusal_burst`,
/// `refusal_records_per_hour`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalSettings {
    /// Master switch. Off: refusals are counted in metrics only and never sealed.
    pub enabled: bool,
    /// Coalescing window.
    pub window: Duration,
    /// Token bucket burst (records).
    pub burst: u32,
    /// Token bucket refill, records per hour.
    pub per_hour: u32,
}

impl Default for RefusalSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Duration::from_secs(10),
            burst: 60,
            per_hour: 20,
        }
    }
}

/// Ceilings on the three operator settings. The record budget is the month-size bound of the
/// design, a safety property and not a tuning knob: a larger configured value is clamped to these
/// (at most about 43,000 records a month per process at the ceiling).
pub const MAX_REFUSAL_BURST: u32 = 240;
pub const MAX_REFUSAL_RECORDS_PER_HOUR: u32 = 60;
pub const MAX_REFUSAL_WINDOW_SECS: u64 = 300;

/// Distinct (agent, action, class, entry) windows open at once. A key beyond this merges into the
/// summary, so the map cannot grow without bound under a distinct-key flood.
pub const MAX_OPEN_WINDOWS: usize = 1024;

/// Records waiting for the drain. The bucket already bounds how many can be produced; this is a
/// second, absolute bound so a stuck drain cannot grow memory. Past it a record is dropped with a
/// counted `refusal_budget_overflow` gap.
pub const MAX_READY: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    agent: String,
    action: String,
    class: RefusalClass,
    entry: RefusalEntry,
}

/// The tail of one open window: refusals after the first, sealed together when the window closes.
#[derive(Debug)]
struct Window {
    started: Instant,
    credential: Option<String>,
    /// A later refusal in this window named a different credential (or none) than the first. The
    /// tail then names no credential: it must not say `credential=a` for attempts on `b`.
    credential_mixed: bool,
    tail_attempts: u64,
    tail_first_at: Option<DateTime<Utc>>,
    tail_last_at: Option<DateTime<Utc>>,
}

/// One record waiting to be sealed.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// The idempotency key. Random and unguessable by a peer writer; kept across retries so a
    /// retry after a lost response replays instead of duplicating.
    pub idem: String,
    /// Sanitized agent. `vultrino:multiple` on a summary that merged more than one agent.
    pub agent: String,
    /// Sanitized action. `*` on a summary.
    pub action: String,
    /// `None` on a summary.
    pub entry: Option<RefusalEntry>,
    /// `None` on a summary.
    pub class: Option<RefusalClass>,
    /// Sanitized resolved credential alias.
    pub credential: Option<String>,
    /// How many refusals this record stands for.
    pub attempts: u64,
    /// First refusal.
    pub first_at: DateTime<Utc>,
    /// Last refusal.
    pub last_at: DateTime<Utc>,
    /// Per-class counts of a summary; `None` on an individual record.
    pub by_class: Option<BTreeMap<&'static str, u64>>,
    /// Drain ticks this record has already failed to seal.
    pub tries: u32,
}

/// Exact-count merge of refusals the bucket would not admit as their own record.
#[derive(Debug, Default)]
struct Summary {
    by_class: BTreeMap<&'static str, u64>,
    attempts: u64,
    agents: Vec<String>,
    first_at: Option<DateTime<Utc>>,
    last_at: Option<DateTime<Utc>>,
}

impl Summary {
    fn is_empty(&self) -> bool {
        self.attempts == 0
    }

    fn merge(
        &mut self,
        class: RefusalClass,
        attempts: u64,
        agent: &str,
        first: DateTime<Utc>,
        last: DateTime<Utc>,
    ) {
        *self.by_class.entry(class.as_str()).or_insert(0) += attempts;
        self.attempts += attempts;
        // Two distinct agents are enough to say "multiple"; no need to remember more.
        if self.agents.len() < 2 && !self.agents.iter().any(|a| a == agent) {
            self.agents.push(agent.to_string());
        }
        self.first_at = Some(self.first_at.map_or(first, |f| f.min(first)));
        self.last_at = Some(self.last_at.map_or(last, |l| l.max(last)));
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    burst: f64,
    per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: u32, per_hour: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            burst: f64::from(burst),
            per_sec: f64::from(per_hour) / 3600.0,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now.max(self.last);
        self.tokens = (self.tokens + dt * self.per_sec).min(self.burst);
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct State {
    open: HashMap<Key, Window>,
    ready: VecDeque<Outgoing>,
    summary: Summary,
    bucket: Bucket,
    /// Records dropped past [`MAX_READY`] since the last drain, as `(class, attempts, agent)`.
    overflow: Vec<(RefusalClass, u64, String)>,
}

/// Counters, read by tests and the metrics route.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RefusalCounters {
    /// Refusals noted (every attributable refusal, whether or not it is sealed).
    pub noted: u64,
    /// Records sealed by averin.
    pub sealed: u64,
    /// Refusals folded into an open window instead of their own record.
    pub coalesced: u64,
    /// Refusals folded into a summary because the budget or window cap was reached.
    pub summarized: u64,
    /// Records that could not be sealed (each is also an `evidence.receipt_gap`).
    pub unsealed: u64,
}

/// The refusal recorder: notes synchronously, hands due records to the drain.
pub struct RefusalRecorder {
    settings: RefusalSettings,
    state: Mutex<State>,
    counters: Mutex<RefusalCounters>,
}

impl std::fmt::Debug for RefusalRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefusalRecorder")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl RefusalRecorder {
    /// A recorder with `settings`.
    pub fn new(settings: RefusalSettings) -> Self {
        Self::new_at(settings, Instant::now())
    }

    fn new_at(settings: RefusalSettings, now: Instant) -> Self {
        Self {
            settings,
            state: Mutex::new(State {
                open: HashMap::new(),
                ready: VecDeque::new(),
                summary: Summary::default(),
                bucket: Bucket::new(settings.burst, settings.per_hour, now),
                overflow: Vec::new(),
            }),
            counters: Mutex::new(RefusalCounters::default()),
        }
    }

    /// The settings in force.
    pub fn settings(&self) -> RefusalSettings {
        self.settings
    }

    /// A snapshot of the counters.
    pub fn counters(&self) -> RefusalCounters {
        *self.counters.lock()
    }

    /// Note one refusal. Synchronous and O(1): no await, no I/O. Never fails, never blocks on
    /// anything but a short-held mutex.
    pub fn note(&self, ctx: &RefusalCtx, class: RefusalClass) {
        self.note_at(ctx, class, Instant::now(), Utc::now());
    }

    pub(crate) fn note_at(
        &self,
        ctx: &RefusalCtx,
        class: RefusalClass,
        now: Instant,
        wall: DateTime<Utc>,
    ) {
        let Some((agent, action, credential)) = ctx.sanitized() else {
            return;
        };
        self.counters.lock().noted += 1;
        if !self.settings.enabled {
            return;
        }
        let key = Key {
            agent,
            action,
            class,
            entry: ctx.entry,
        };
        let mut st = self.state.lock();
        // A window that has run its length closes first (its tail becomes a record), then this
        // refusal opens the next one.
        let expired = st
            .open
            .get(&key)
            .is_some_and(|w| now.saturating_duration_since(w.started) >= self.settings.window);
        if expired {
            self.close_window(&mut st, &key, now);
        }
        let folded = match st.open.get_mut(&key) {
            Some(w) => {
                if w.credential != credential {
                    w.credential_mixed = true;
                }
                w.tail_attempts += 1;
                w.tail_first_at.get_or_insert(wall);
                w.tail_last_at = Some(wall);
                true
            }
            None => false,
        };
        if folded {
            drop(st);
            self.counters.lock().coalesced += 1;
            return;
        }
        if st.open.len() >= MAX_OPEN_WINDOWS {
            self.to_summary(&mut st, class, 1, &key.agent, wall, wall);
            return;
        }
        st.open.insert(
            key.clone(),
            Window {
                started: now,
                credential: credential.clone(),
                credential_mixed: false,
                tail_attempts: 0,
                tail_first_at: None,
                tail_last_at: None,
            },
        );
        // The first refusal of a window is its own record, at the next drain.
        self.admit(
            &mut st,
            Outgoing {
                idem: new_idem(),
                agent: key.agent.clone(),
                action: key.action.clone(),
                entry: Some(key.entry),
                class: Some(class),
                credential,
                attempts: 1,
                first_at: wall,
                last_at: wall,
                by_class: None,
                tries: 0,
            },
            now,
        );
    }

    /// Spend a bucket token on `rec` or, when none is available (or a summary is already waiting
    /// for the next token), merge it into the summary. Called with the state lock held.
    fn admit(&self, st: &mut State, rec: Outgoing, now: Instant) {
        // While a summary waits it has first claim on the next token, so individual records
        // cannot starve it.
        let may_take = st.summary.is_empty();
        if may_take && st.bucket.try_take(now) {
            self.push_ready(st, rec);
        } else {
            let class = rec.class.expect("an individual record has a class");
            self.to_summary(
                st,
                class,
                rec.attempts,
                &rec.agent,
                rec.first_at,
                rec.last_at,
            );
        }
    }

    fn to_summary(
        &self,
        st: &mut State,
        class: RefusalClass,
        attempts: u64,
        agent: &str,
        first: DateTime<Utc>,
        last: DateTime<Utc>,
    ) {
        st.summary.merge(class, attempts, agent, first, last);
        self.counters.lock().summarized += attempts;
    }

    fn push_ready(&self, st: &mut State, rec: Outgoing) {
        if st.ready.len() >= MAX_READY {
            // Absolute bound reached: not silent, a counted gap at the next drain.
            if let (Some(class), agent) = (rec.class, rec.agent.clone()) {
                st.overflow.push((class, rec.attempts, agent));
            } else if let Some(by) = &rec.by_class {
                for c in RefusalClass::ALL {
                    if let Some(n) = by.get(c.as_str()) {
                        st.overflow.push((c, *n, rec.agent.clone()));
                    }
                }
            }
            return;
        }
        st.ready.push_back(rec);
    }

    /// Close `key`'s window: its tail (if any) becomes a record, subject to the budget.
    fn close_window(&self, st: &mut State, key: &Key, now: Instant) {
        let Some(w) = st.open.remove(key) else {
            return;
        };
        if w.tail_attempts == 0 {
            return;
        }
        let (first, last) = (
            w.tail_first_at.unwrap_or_else(Utc::now),
            w.tail_last_at.unwrap_or_else(Utc::now),
        );
        self.admit(
            st,
            Outgoing {
                idem: new_idem(),
                agent: key.agent.clone(),
                action: key.action.clone(),
                entry: Some(key.entry),
                class: Some(key.class),
                credential: if w.credential_mixed {
                    None
                } else {
                    w.credential
                },
                attempts: w.tail_attempts,
                first_at: first,
                last_at: last,
                by_class: None,
                tries: 0,
            },
            now,
        );
    }

    /// Records due for sealing now: closes every window that has run its length, gives a waiting
    /// summary the next token, and hands over up to `max` records plus the overflow drops.
    pub fn take_due(&self, max: usize) -> (Vec<Outgoing>, Vec<(RefusalClass, u64, String)>) {
        self.take_due_at(max, Instant::now())
    }

    pub(crate) fn take_due_at(
        &self,
        max: usize,
        now: Instant,
    ) -> (Vec<Outgoing>, Vec<(RefusalClass, u64, String)>) {
        let mut st = self.state.lock();
        let expired: Vec<Key> = st
            .open
            .iter()
            .filter(|(_, w)| now.saturating_duration_since(w.started) >= self.settings.window)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.close_window(&mut st, &key, now);
        }
        if !st.summary.is_empty() && st.bucket.try_take(now) {
            let s = std::mem::take(&mut st.summary);
            let agent = if s.agents.len() > 1 {
                "vultrino:multiple".to_string()
            } else {
                s.agents
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "vultrino:multiple".to_string())
            };
            let rec = Outgoing {
                idem: new_idem(),
                agent,
                action: "*".to_string(),
                entry: None,
                class: None,
                credential: None,
                attempts: s.attempts,
                first_at: s.first_at.unwrap_or_else(Utc::now),
                last_at: s.last_at.unwrap_or_else(Utc::now),
                by_class: Some(s.by_class),
                tries: 0,
            };
            self.push_ready(&mut st, rec);
        }
        let n = max.min(st.ready.len());
        let batch: Vec<Outgoing> = st.ready.drain(..n).collect();
        let overflow = std::mem::take(&mut st.overflow);
        (batch, overflow)
    }

    /// Put records back at the front of the queue after a failed attempt (they keep their
    /// idempotency key). The bound is the same: past [`MAX_READY`] they are returned as dropped.
    pub fn requeue(&self, recs: Vec<Outgoing>) -> Vec<Outgoing> {
        let mut st = self.state.lock();
        let mut dropped = Vec::new();
        for rec in recs.into_iter().rev() {
            if st.ready.len() >= MAX_READY {
                dropped.push(rec);
            } else {
                st.ready.push_front(rec);
            }
        }
        dropped
    }

    /// Count one record sealed.
    pub(crate) fn count_sealed(&self) {
        self.counters.lock().sealed += 1;
    }

    /// Count one record that could not be sealed.
    pub(crate) fn count_unsealed(&self) {
        self.counters.lock().unsealed += 1;
    }

    /// Close every open window now, whatever its age, so each tail becomes a record (subject to
    /// the budget). Used when the process is stopping: a tail still inside its window would
    /// otherwise be lost with the process.
    pub fn close_all_windows(&self) {
        self.close_all_windows_at(Instant::now());
    }

    pub(crate) fn close_all_windows_at(&self, now: Instant) {
        let mut st = self.state.lock();
        let keys: Vec<Key> = st.open.keys().cloned().collect();
        for key in keys {
            self.close_window(&mut st, &key, now);
        }
    }

    /// Take everything still waiting (ready records and any summary) without sealing it, for the
    /// shutdown path to turn into counted gaps.
    pub fn take_all_pending(&self) -> Vec<Outgoing> {
        let mut st = self.state.lock();
        let mut out: Vec<Outgoing> = st.ready.drain(..).collect();
        if !st.summary.is_empty() {
            let s = std::mem::take(&mut st.summary);
            let agent = if s.agents.len() > 1 {
                "vultrino:multiple".to_string()
            } else {
                s.agents
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "vultrino:multiple".to_string())
            };
            out.push(Outgoing {
                idem: new_idem(),
                agent,
                action: "*".to_string(),
                entry: None,
                class: None,
                credential: None,
                attempts: s.attempts,
                first_at: s.first_at.unwrap_or_else(Utc::now),
                last_at: s.last_at.unwrap_or_else(Utc::now),
                by_class: Some(s.by_class),
                tries: 0,
            });
        }
        out
    }

    /// Whether anything is waiting (open windows with a tail, ready records, a summary).
    pub fn has_pending(&self) -> bool {
        let st = self.state.lock();
        !st.ready.is_empty()
            || !st.summary.is_empty()
            || st.open.values().any(|w| w.tail_attempts > 0)
    }
}

fn new_idem() -> String {
    format!("vultrino-refusal-{}", uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(agent: &str, action: &str) -> RefusalCtx {
        RefusalCtx::new(RefusalEntry::Mcp, Some((agent, Some(agent))), action)
    }

    fn recorder(burst: u32, per_hour: u32) -> (RefusalRecorder, Instant) {
        let t0 = Instant::now();
        (
            RefusalRecorder::new_at(
                RefusalSettings {
                    enabled: true,
                    window: Duration::from_secs(10),
                    burst,
                    per_hour,
                },
                t0,
            ),
            t0,
        )
    }

    /// The vendored vocabulary file is the source of truth for the spellings.
    #[test]
    fn vocabulary_matches_the_vendored_averin_file() {
        let raw = include_str!("../vectors/refusal-classes.v1.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let classes: Vec<&str> = v["reason_classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = RefusalClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            classes, ours,
            "reason classes drifted from averin's vocabulary"
        );
        let entries: Vec<&str> = v["entry_points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = RefusalEntry::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            entries, ours,
            "entry points drifted from averin's vocabulary"
        );
    }

    #[test]
    fn names_outside_the_plain_set_become_invalid_name() {
        assert_eq!(sanitize_name("http.request"), "http.request");
        assert_eq!(sanitize_name("ep_abc-1:2"), "ep_abc-1:2");
        assert_eq!(sanitize_name(""), INVALID_NAME);
        assert_eq!(sanitize_name("has space"), INVALID_NAME);
        assert_eq!(sanitize_name("a/b"), INVALID_NAME);
        assert_eq!(sanitize_name(&"x".repeat(129)), INVALID_NAME);
        // A bearer pasted into a name is never sealed even though it is a plain identifier.
        assert_eq!(sanitize_name("vut_0123456789abcdef"), INVALID_NAME);
        assert_eq!(sanitize_name("do.vk_0123456789abcdef"), INVALID_NAME);
    }

    #[test]
    fn no_principal_notes_nothing() {
        let (r, t0) = recorder(60, 20);
        let c = RefusalCtx::new(RefusalEntry::Execute, None, "http.request");
        r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        assert_eq!(r.counters().noted, 0);
        assert!(!r.has_pending());
    }

    #[test]
    fn first_refusal_is_its_own_record_and_the_window_tail_is_one_more() {
        let (r, t0) = recorder(60, 20);
        let c = ctx("ep_a", "http.request");
        for _ in 0..1000 {
            r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        }
        let (first, _) = r.take_due_at(100, t0 + Duration::from_secs(1));
        assert_eq!(
            first.len(),
            1,
            "the first refusal is sealed at the next drain"
        );
        assert_eq!(first[0].attempts, 1);
        let (tail, _) = r.take_due_at(100, t0 + Duration::from_secs(11));
        assert_eq!(tail.len(), 1, "the rest of the window is one record");
        assert_eq!(tail[0].attempts, 999);
        assert_eq!(first[0].attempts + tail[0].attempts, 1000);
        assert_ne!(first[0].idem, tail[0].idem);
        assert_eq!(r.counters().noted, 1000);
        assert_eq!(r.counters().coalesced, 999);
    }

    /// The window key has no credential, so a tail that merged refusals on two credentials must
    /// not name the first one: that would be a wrong statement in a permanent record.
    #[test]
    fn a_tail_that_mixed_credentials_names_none() {
        let (r, t0) = recorder(60, 20);
        let on = |cred: &str| ctx("ep_a", "http.request").resolved(cred, "http.request");
        r.note_at(&on("cred-a"), RefusalClass::PolicyDeny, t0, Utc::now());
        r.note_at(&on("cred-b"), RefusalClass::PolicyDeny, t0, Utc::now());
        r.note_at(&on("cred-b"), RefusalClass::PolicyDeny, t0, Utc::now());
        let (first, _) = r.take_due_at(100, t0 + Duration::from_secs(1));
        assert_eq!(first[0].credential.as_deref(), Some("cred-a"));
        let (tail, _) = r.take_due_at(100, t0 + Duration::from_secs(11));
        assert_eq!(tail[0].attempts, 2);
        assert_eq!(tail[0].credential, None, "the tail spans two credentials");
    }

    /// A tail on one credential keeps naming it.
    #[test]
    fn a_tail_on_one_credential_keeps_naming_it() {
        let (r, t0) = recorder(60, 20);
        let c = ctx("ep_a", "http.request").resolved("cred-a", "http.request");
        for _ in 0..3 {
            r.note_at(&c, RefusalClass::PolicyDeny, t0, Utc::now());
        }
        let _ = r.take_due_at(100, t0 + Duration::from_secs(1));
        let (tail, _) = r.take_due_at(100, t0 + Duration::from_secs(11));
        assert_eq!(tail[0].credential.as_deref(), Some("cred-a"));
    }

    /// Stopping the process closes every window, so a tail still inside its window is a record.
    #[test]
    fn closing_all_windows_turns_every_open_tail_into_a_record() {
        let (r, t0) = recorder(60, 20);
        let c = ctx("ep_a", "http.request");
        for _ in 0..5 {
            r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        }
        let (first, _) = r.take_due_at(100, t0 + Duration::from_secs(1));
        assert_eq!(first.len(), 1);
        r.close_all_windows_at(t0 + Duration::from_secs(2));
        let (tail, _) = r.take_due_at(100, t0 + Duration::from_secs(2));
        assert_eq!(tail.len(), 1, "the open tail was closed early");
        assert_eq!(tail[0].attempts, 4);
    }

    #[test]
    fn distinct_keys_are_distinct_records_until_the_bucket_is_empty_then_one_exact_summary() {
        let (r, t0) = recorder(3, 0);
        for i in 0..10 {
            let c = ctx("ep_a", &format!("tool.a{i}"));
            r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        }
        let (batch, _) = r.take_due_at(100, t0);
        // 3 individual records took the burst; the other 7 wait in the summary (no token for it).
        assert_eq!(batch.len(), 3);
        assert!(r.has_pending());
        // With a token the summary takes the next one and the counts are exact.
        let t1 = t0 + Duration::from_secs(3600);
        let (r2, _) = recorder(3, 3600);
        for i in 0..10 {
            let c = ctx("ep_a", &format!("tool.a{i}"));
            r2.note_at(&c, RefusalClass::PolicyDeny, t0, Utc::now());
        }
        let (b0, _) = r2.take_due_at(100, t0);
        assert_eq!(b0.len(), 3);
        let (b1, _) = r2.take_due_at(100, t1);
        let summary = b1.iter().find(|o| o.by_class.is_some()).expect("a summary");
        assert_eq!(summary.attempts, 7);
        assert_eq!(summary.by_class.as_ref().unwrap()["policy_deny"], 7);
        assert_eq!(summary.action, "*");
        assert_eq!(summary.agent, "ep_a");
        assert!(summary.entry.is_none() && summary.class.is_none());
    }

    #[test]
    fn a_window_tail_merged_into_the_summary_keeps_its_exact_count() {
        // One token: the first refusal takes it. The other 5 of the window are a tail, which at the
        // window's close finds the bucket empty and merges into the summary as ONE entry of 5.
        let (r, t0) = recorder(1, 1);
        let c = ctx("ep_a", "x.y");
        for _ in 0..6 {
            r.note_at(&c, RefusalClass::PolicyDeny, t0, Utc::now());
        }
        let (first, _) = r.take_due_at(10, t0 + Duration::from_secs(11));
        assert_eq!(first.len(), 1, "only the first refusal had a token");
        assert_eq!(first[0].attempts, 1);
        let (later, _) = r.take_due_at(10, t0 + Duration::from_secs(3700));
        let summary = later
            .iter()
            .find(|o| o.by_class.is_some())
            .expect("a summary");
        assert_eq!(summary.attempts, 5, "the tail's count survives the merge");
        assert_eq!(summary.by_class.as_ref().unwrap()["policy_deny"], 5);
        assert_eq!(first[0].attempts + summary.attempts, 6, "nothing is lost");
    }

    #[test]
    fn a_summary_over_two_agents_is_vultrino_multiple() {
        // One token in the bucket: the first refusal takes it, the next two merge.
        let (r, t0) = recorder(1, 3600);
        r.note_at(
            &ctx("ep_a", "x.y"),
            RefusalClass::NotGranted,
            t0,
            Utc::now(),
        );
        r.note_at(&ctx("ep_b", "x.y"), RefusalClass::KillFence, t0, Utc::now());
        r.note_at(&ctx("ep_c", "x.y"), RefusalClass::KillFence, t0, Utc::now());
        let (b, _) = r.take_due_at(10, t0 + Duration::from_secs(3600));
        let summary = b.iter().find(|o| o.by_class.is_some()).expect("a summary");
        assert_eq!(summary.agent, "vultrino:multiple");
        assert_eq!(summary.attempts, 2);
        assert_eq!(summary.by_class.as_ref().unwrap()["kill_fence"], 2);
        assert!(b.iter().any(|o| o.agent == "ep_a" && o.attempts == 1));
    }

    #[test]
    fn open_windows_are_capped() {
        let (r, t0) = recorder(100_000, 0);
        for i in 0..(MAX_OPEN_WINDOWS + 50) {
            let c = ctx("ep_a", &format!("tool.t{i}"));
            r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        }
        assert!(r.state.lock().open.len() <= MAX_OPEN_WINDOWS);
        assert_eq!(r.counters().summarized, 50);
    }

    #[test]
    fn disabled_recorder_counts_but_never_queues() {
        let t0 = Instant::now();
        let r = RefusalRecorder::new_at(
            RefusalSettings {
                enabled: false,
                ..RefusalSettings::default()
            },
            t0,
        );
        r.note_at(
            &ctx("ep_a", "x.y"),
            RefusalClass::NotGranted,
            t0,
            Utc::now(),
        );
        assert_eq!(r.counters().noted, 1);
        assert!(!r.has_pending());
    }

    #[test]
    fn ready_queue_is_bounded_and_overflow_is_reported() {
        let (r, t0) = recorder(100_000, 0);
        for i in 0..(MAX_READY + 5) {
            let c = ctx("ep_a", &format!("tool.t{i}"));
            r.note_at(&c, RefusalClass::NotGranted, t0, Utc::now());
        }
        let (batch, overflow) = r.take_due_at(10_000, t0);
        assert_eq!(batch.len(), MAX_READY);
        assert_eq!(overflow.len(), 5);
    }
}
