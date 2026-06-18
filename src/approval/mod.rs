//! Human-in-the-loop action approvals.
//!
//! Some authenticated actions are too consequential to let an agent run
//! unsupervised. When an action requires approval, Vultrino does **not** execute
//! it. Instead it records an [`ApprovalRequest`], hands the agent an
//! `approval_id`, and waits. A human approves or denies it — in the admin panel,
//! via a Telegram button, or via a link delivered by webhook/email — and only
//! then does the action run, with the result delivered back to the agent the
//! next time it polls.
//!
//! ## The flow, from the agent's side
//! 1. Agent calls a tool (e.g. `http_request`). The response is **not** the API
//!    result — it's a clearly-labelled "approval required" message with an
//!    `approval_id` and instructions to poll `check_approval`.
//! 2. Agent polls `check_approval` with that id. While `pending`, it keeps
//!    waiting. If `denied`, it stops. If `approved`, the action executes
//!    (lazily, in the serving process) and the real result is returned.
//!
//! ## Out-of-band approval (Telegram / webhook / email)
//! Each request carries a single-**decision** capability token (only its hash is
//! stored): it authorizes one approve/deny while the request is pending and is
//! moot once a decision is recorded (the request is no longer pending) or the
//! TTL elapses. Approve/deny links embedding that token point at the web
//! server's `/approvals/{id}/decide` endpoint, so a Telegram inline button or an
//! email link can authorize a decision without a logged-in session. Because the
//! token travels in the link, set `public_base_url` to an HTTPS address and
//! avoid logging request URIs at DEBUG.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

/// Lifecycle state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting a human decision, within the first SLA window.
    Pending,
    /// The first SLA window elapsed without a decision; re-notified and awaiting
    /// a decision within a second, bounded window before it auto-denies (V5).
    Escalated,
    /// A human approved it; the action may run.
    Approved,
    /// A human rejected it; the action will never run.
    Denied,
    /// No decision was made before the request's final deadline elapsed.
    Expired,
}

impl ApprovalStatus {
    /// Whether a decision can still be made (the request is awaiting a human).
    pub fn is_open(&self) -> bool {
        matches!(self, ApprovalStatus::Pending | ApprovalStatus::Escalated)
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Escalated => "escalated",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Expired => "expired",
        };
        write!(f, "{}", s)
    }
}

/// Criticality class of a gated action (V5). Drives the SLA windows: higher
/// criticality escalates and auto-denies faster. The per-class windows live in
/// [`ApprovalConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityClass {
    /// Low-risk: long windows.
    Low,
    /// Default class.
    #[default]
    Medium,
    /// High-risk: short windows.
    High,
    /// Highest-risk: shortest windows.
    Critical,
}

impl std::fmt::Display for CriticalityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CriticalityClass::Low => "low",
            CriticalityClass::Medium => "medium",
            CriticalityClass::High => "high",
            CriticalityClass::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

/// The result of advancing an approval through its SLA lifecycle (V5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleChange {
    /// No state change.
    None,
    /// Pending → Escalated (first window elapsed); the caller should re-notify.
    Escalated,
    /// Pending/Escalated → Expired (final deadline elapsed).
    Expired,
}

/// Who/what requested the gated action (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequesterInfo {
    /// `api_key`, `use_token`, or `local`.
    pub principal_kind: String,
    /// Stable id of the principal (api key id / use token id), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Human label of the principal, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_name: Option<String>,
    /// Role name, if the principal was an API key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl Default for RequesterInfo {
    fn default() -> Self {
        Self::local()
    }
}

impl RequesterInfo {
    /// A local (CLI, no auth) requester.
    pub fn local() -> Self {
        Self {
            principal_kind: "local".to_string(),
            principal_id: None,
            principal_name: None,
            role: None,
        }
    }

    /// Short human description, e.g. `api key "deploy-agent"` or `local`.
    pub fn describe(&self) -> String {
        match self.principal_name.as_deref() {
            Some(name) => format!("{} \"{}\"", self.principal_kind.replace('_', " "), name),
            None => self.principal_kind.replace('_', " "),
        }
    }
}

/// Parameters for opening a new approval request.
#[derive(Debug, Clone)]
pub struct NewApproval {
    pub credential: String,
    pub action: String,
    pub params: serde_json::Value,
    pub requester: RequesterInfo,
    pub use_token_id: Option<String>,
    /// Resolved principal id (V4), for per-agent policy re-evaluation at resume.
    pub principal_id: Option<String>,
    /// Agent label of the requesting principal (V4), for per-agent policy
    /// re-evaluation at resume.
    pub agent_label: Option<String>,
    /// govder business-verb label for the action (V8), for the approver summary.
    pub action_label: Option<String>,
    /// Whether the action requires dual control (V8 strictness).
    pub dual_control: bool,
    /// Criticality class of this action (V5), recorded for SLA/analytics.
    pub criticality: CriticalityClass,
    /// First SLA window: Pending → Escalated after this elapses (V5).
    pub escalate_after: chrono::Duration,
    /// Second SLA window: Escalated → Expired this long after escalation (V5).
    /// The final deadline is `now + escalate_after + escalate_window`.
    pub escalate_window: chrono::Duration,
    /// Named identity an out-of-band decision link is bound to (V5). Recorded as
    /// the approver identity when the decision arrives via the OOB link, so a
    /// decision is never attributed to a bare anonymous capability token.
    pub oob_identity: Option<String>,
    /// Optional continuous re-authorization interval (V5): an approved grant that
    /// has not run within this window must be re-approved before it executes.
    pub reauth_interval_secs: Option<u64>,
}

/// A human decision on an approval request (V5). Carries the channel it arrived
/// on plus the **authenticated approver identity** (panel session user, or the
/// named identity an out-of-band link was bound to) so every decision is
/// attributable and separation-of-duty is computable.
#[derive(Debug, Clone)]
pub struct Decision {
    /// Channel the decision arrived on (`admin panel`, `out-of-band link`, ...).
    pub channel: String,
    /// Authenticated identity of the approver. Must be non-empty.
    pub approver_identity: String,
    /// Optional free-text note.
    pub note: Option<String>,
    /// When true, a self-approval (SoD violation) is **rejected** rather than
    /// merely recorded (V5). Set from `enforce_separation_of_duty` config.
    pub enforce_sod: bool,
}

impl Decision {
    /// A decision made by an authenticated approver on a named channel.
    pub fn new(channel: impl Into<String>, approver_identity: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            approver_identity: approver_identity.into(),
            note: None,
            enforce_sod: false,
        }
    }

    /// Attach a free-text note.
    pub fn with_note(mut self, note: Option<String>) -> Self {
        self.note = note;
        self
    }

    /// Reject (rather than only record) a self-approval SoD violation.
    pub fn enforcing_sod(mut self, enforce: bool) -> Self {
        self.enforce_sod = enforce;
        self
    }
}

/// A request for a human to approve (or deny) a specific authenticated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique id, format `appr_<uuid>` — this is what the agent polls with.
    pub id: String,
    /// Current lifecycle state.
    pub status: ApprovalStatus,
    /// Credential alias the action would use.
    pub credential: String,
    /// Fully-qualified action (`http.request`, `postgres.run_sql`, ...).
    pub action: String,
    /// Action parameters (no credential secrets) — what the approver reviews.
    pub params: serde_json::Value,
    /// Human one-liner describing the action.
    pub summary: String,
    /// Who requested it.
    pub requester: RequesterInfo,
    /// Use token to consume on execution, if the request was token-authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_token_id: Option<String>,
    /// Resolved principal id of the requester (V4), recorded explicitly (not
    /// derived from `requester`) so per-agent policies re-evaluate correctly at
    /// resume regardless of how the requester was constructed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Agent label of the requesting principal (V4), recorded so a per-agent
    /// policy is re-evaluated correctly when the approved action resumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<String>,
    /// govder business-verb label for the action (V8), shown to the approver
    /// instead of the canonical `plugin.action` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_label: Option<String>,
    /// Whether this action requires dual control (V8 strictness `direct`);
    /// enforced by the approval layer in V12.
    #[serde(default)]
    pub dual_control: bool,
    /// Criticality class (V5) — drives the escalation/expiry windows and is
    /// recorded for separation-of-duty / complacency analytics.
    #[serde(default)]
    pub criticality: CriticalityClass,
    pub created_at: DateTime<Utc>,
    /// First SLA boundary (V5): when Pending auto-escalates to Escalated.
    #[serde(default)]
    pub escalate_at: DateTime<Utc>,
    /// When the request actually escalated (V5), if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_at: Option<DateTime<Utc>>,
    /// Final deadline: when the request auto-expires (denies) if still undecided.
    pub expires_at: DateTime<Utc>,
    /// Named identity an out-of-band decision link is bound to (V5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oob_identity: Option<String>,
    /// Optional continuous re-authorization interval in seconds (V5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauth_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// Channel that decided it (`admin panel`, `telegram`, `out-of-band link`...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// Authenticated approver identity captured at decision time (V5): the IdP
    /// subject / panel session user, or the named identity an OOB link was bound
    /// to. Required for a human decision; absent only for system expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_identity: Option<String>,
    /// Separation-of-duty outcome recorded at decision time (V5): `Some(true)`
    /// when the approver was the requesting agent itself (a self-approval),
    /// `Some(false)` when distinct, `None` when not computable. Recorded on every
    /// human decision so SoD is observable even when not hard-enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sod_violation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_note: Option<String>,
    /// SHA-256 of the out-of-band decision token (plaintext is shown only in
    /// the notification links).
    pub decision_token_hash: String,
    /// Set while a serving process is executing the approved action, to keep two
    /// concurrent polls from running it twice.
    #[serde(default)]
    pub executing: bool,
    /// When the current execution claim was taken. Used to detect and recover a
    /// stale claim left behind by a crashed worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executing_since: Option<DateTime<Utc>>,
    /// Whether the approved action has run.
    #[serde(default)]
    pub executed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_error: Option<String>,
}

impl ApprovalRequest {
    /// Open a new pending request. Returns the request plus the **plaintext**
    /// decision token (only its hash is stored on the request).
    pub fn open(params: NewApproval) -> (ApprovalRequest, String) {
        let now = Utc::now();
        let (decision_token, decision_token_hash) = generate_decision_token();
        // Show the govder business verb to the approver when present, else the
        // canonical plugin.action.
        let display_action = params.action_label.as_deref().unwrap_or(&params.action);
        let summary = summarize(&params.credential, display_action, &params.params);

        let request = ApprovalRequest {
            id: format!("appr_{}", uuid::Uuid::new_v4()),
            status: ApprovalStatus::Pending,
            credential: params.credential,
            action: params.action,
            params: params.params,
            summary,
            requester: params.requester,
            use_token_id: params.use_token_id,
            principal_id: params.principal_id,
            agent_label: params.agent_label,
            action_label: params.action_label,
            dual_control: params.dual_control,
            criticality: params.criticality,
            created_at: now,
            escalate_at: now + params.escalate_after,
            escalated_at: None,
            expires_at: now + params.escalate_after + params.escalate_window,
            oob_identity: params.oob_identity,
            reauth_interval_secs: params.reauth_interval_secs,
            decided_at: None,
            decided_by: None,
            approver_identity: None,
            sod_violation: None,
            decision_note: None,
            decision_token_hash,
            executing: false,
            executing_since: None,
            executed: false,
            result_status: None,
            result_body: None,
            result_error: None,
        };

        (request, decision_token)
    }

    /// Whether the final deadline has elapsed (independent of stored status).
    pub fn is_past_ttl(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Advance the request through its SLA lifecycle (V5): an open request first
    /// escalates (after the first window) and then expires (after the second).
    /// Returns what changed so the caller can persist + re-notify on escalation.
    pub fn advance_lifecycle(&mut self) -> LifecycleChange {
        if !self.status.is_open() {
            return LifecycleChange::None;
        }
        let now = Utc::now();
        // Final deadline takes priority: an open request past expiry is denied,
        // whether or not it had escalated.
        if now >= self.expires_at {
            self.status = ApprovalStatus::Expired;
            self.decided_at = Some(now);
            self.decided_by = Some("system (expired)".to_string());
            return LifecycleChange::Expired;
        }
        if self.status == ApprovalStatus::Pending && now >= self.escalate_at {
            self.status = ApprovalStatus::Escalated;
            self.escalated_at = Some(now);
            return LifecycleChange::Escalated;
        }
        LifecycleChange::None
    }

    /// If past the final deadline, flip an open request to `Expired`. Returns
    /// true if it became expired. (Convenience over [`Self::advance_lifecycle`]
    /// for callers that only care about expiry.)
    pub fn expire_if_due(&mut self) -> bool {
        if self.status.is_open() && self.is_past_ttl() {
            self.status = ApprovalStatus::Expired;
            self.decided_at = Some(Utc::now());
            self.decided_by = Some("system (expired)".to_string());
            true
        } else {
            false
        }
    }

    /// Mark approved. Errors if the request is no longer open or the approver
    /// identity is missing (V5: every decision must carry one).
    pub fn approve(&mut self, decision: Decision) -> Result<(), ApprovalError> {
        self.transition(ApprovalStatus::Approved, decision)
    }

    /// Mark denied. Errors if the request is no longer open or the approver
    /// identity is missing (V5).
    pub fn deny(&mut self, decision: Decision) -> Result<(), ApprovalError> {
        self.transition(ApprovalStatus::Denied, decision)
    }

    fn transition(&mut self, to: ApprovalStatus, decision: Decision) -> Result<(), ApprovalError> {
        // V5: a human decision must carry an authenticated approver identity, so
        // every decision is attributable and SoD is computable. Reject blanks.
        let identity = decision.approver_identity.trim().to_string();
        if identity.is_empty() {
            return Err(ApprovalError::MissingApproverIdentity);
        }
        if self.is_past_ttl() {
            self.expire_if_due();
            return Err(ApprovalError::Expired);
        }
        // A decision is valid in either open state (Pending or Escalated).
        if !self.status.is_open() {
            return Err(ApprovalError::AlreadyDecided(self.status));
        }
        // Set the approver before computing SoD (which reads `approver_identity`).
        self.approver_identity = Some(identity);
        let sod_violation = self.violates_sod();
        // Optionally hard-reject a self-*approval* (a self-denial is harmless, so
        // only Approved is gated); either way the outcome is recorded so the
        // violation is observable. On rejection, clear the approver we just set so
        // the request stays cleanly undecided.
        if decision.enforce_sod && to == ApprovalStatus::Approved && sod_violation == Some(true) {
            self.approver_identity = None;
            return Err(ApprovalError::SeparationOfDuty);
        }
        self.status = to;
        self.decided_at = Some(Utc::now());
        self.decided_by = Some(decision.channel);
        self.sod_violation = sod_violation;
        self.decision_note = decision.note;
        Ok(())
    }

    /// Separation-of-duty check (V5): whether the approver's identity collides
    /// with the requesting agent's own identity (approver == requester), i.e. an
    /// agent self-approving. `None` when either identity is unknown (not
    /// computable). A `Some(true)` is a SoD violation.
    pub fn violates_sod(&self) -> Option<bool> {
        let approver = self.approver_identity.as_deref()?.trim();
        // The requester's "owner" identity: prefer the human/agent label, then
        // the stable principal id.
        let owner = self
            .requester
            .principal_name
            .as_deref()
            .or(self.agent_label.as_deref())
            .or(self.principal_id.as_deref())
            .or(self.requester.principal_id.as_deref())?
            .trim();
        if approver.is_empty() || owner.is_empty() {
            return None;
        }
        Some(approver.eq_ignore_ascii_case(owner))
    }

    /// Expire an approved-but-unrun grant whose continuous-reauth window lapsed
    /// (V5), **preserving** the original approver attribution (`decided_by` /
    /// `approver_identity` / `decided_at` / `sod_violation`) and recording the
    /// lapse in the decision note — so the audit trail still shows who approved
    /// the grant before it went stale, rather than overwriting it with a system
    /// actor. Use this (not a raw `status = Expired`) for the reauth path.
    pub fn expire_reauth_lapsed(&mut self) {
        self.status = ApprovalStatus::Expired;
        let lapse = "re-authorization window lapsed before execution";
        self.decision_note = Some(match self.decision_note.take() {
            Some(note) if !note.is_empty() => format!("{note} | {lapse}"),
            _ => lapse.to_string(),
        });
    }

    /// Continuous re-authorization check (V5): whether an approved-but-not-yet-run
    /// grant has gone stale — i.e. more than `reauth_interval_secs` elapsed since
    /// the decision — and so must be re-approved before it may execute. `false`
    /// when no interval is configured or the grant is fresh.
    pub fn needs_reauth(&self) -> bool {
        let Some(interval) = self.reauth_interval_secs else {
            return false;
        };
        if self.status != ApprovalStatus::Approved || self.executed {
            return false;
        }
        let Some(decided_at) = self.decided_at else {
            return false;
        };
        (Utc::now() - decided_at).num_seconds() > interval as i64
    }

    /// Constant-time check of a presented out-of-band decision token.
    pub fn verify_decision_token(&self, token: &str) -> bool {
        let presented = hash_decision_token(token);
        let a = presented.as_bytes();
        let b = self.decision_token_hash.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Build approve/deny/panel links for notifications, given the public base
    /// URL and the plaintext decision token from [`ApprovalRequest::open`].
    pub fn links(&self, base_url: &str, decision_token: &str) -> ApprovalLinks {
        let base = base_url.trim_end_matches('/');
        let enc = urlencoding::encode(decision_token);
        ApprovalLinks {
            approve_url: format!("{}/approvals/{}/decide?token={}&decision=approve", base, self.id, enc),
            deny_url: format!("{}/approvals/{}/decide?token={}&decision=deny", base, self.id, enc),
            panel_url: format!("{}/approvals", base),
        }
    }
}

/// Errors when transitioning an approval request.
#[derive(Debug, Clone, Error)]
pub enum ApprovalError {
    #[error("approval request has already been {0}")]
    AlreadyDecided(ApprovalStatus),
    #[error("approval request has expired")]
    Expired,
    #[error("approval request not found")]
    NotFound,
    #[error("invalid decision token")]
    InvalidToken,
    #[error("a decision requires an authenticated approver identity")]
    MissingApproverIdentity,
    #[error("separation of duty: the approver may not be the requesting agent")]
    SeparationOfDuty,
}

/// Links embedded in out-of-band notifications.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalLinks {
    pub approve_url: String,
    pub deny_url: String,
    pub panel_url: String,
}

/// Build a human-readable one-line summary of a gated action.
pub fn summarize(credential: &str, action: &str, params: &serde_json::Value) -> String {
    // HTTP-style requests: surface method + URL.
    let method = params.get("method").and_then(|v| v.as_str());
    let url = params.get("url").and_then(|v| v.as_str());
    if let (Some(method), Some(url)) = (method, url) {
        return format!("{} {} (via {})", method.to_uppercase(), url, credential);
    }
    if let Some(url) = url {
        return format!("{} (via {})", url, credential);
    }
    format!("{} on {}", action, credential)
}

// ==================== Decision token helpers ====================

fn generate_decision_token() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_decision_token(&token);
    (token, hash)
}

fn hash_decision_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    STANDARD.encode(hasher.finalize())
}

// ==================== Configuration ====================

/// Per-criticality SLA windows (V5): the first window is Pending → Escalated,
/// the second is Escalated → Expired.
#[derive(Debug, Clone, Copy)]
pub struct CriticalitySla {
    /// Seconds before an undecided Pending request escalates.
    pub escalate_after_secs: u64,
    /// Seconds after escalation before the request auto-expires (denies).
    pub escalate_window_secs: u64,
}

impl CriticalitySla {
    /// First window as a duration.
    pub fn escalate_after(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.escalate_after_secs.max(1) as i64)
    }
    /// Second window as a duration.
    pub fn escalate_window(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.escalate_window_secs.max(1) as i64)
    }
}

/// A rule mapping a `(credential, action)` to a criticality class (V5). The
/// first matching rule wins; an unmatched action gets [`CriticalityClass::Medium`].
#[derive(Debug, Clone)]
pub struct CriticalityRule {
    pub credential_pattern: glob::Pattern,
    pub action_pattern: glob::Pattern,
    pub class: CriticalityClass,
}

/// Runtime configuration for the approval subsystem.
#[derive(Debug, Clone, Default)]
pub struct ApprovalConfig {
    /// Whether approvals are enabled. When false, actions that would require
    /// approval are denied instead (fail-closed).
    pub enabled: bool,
    /// Default time-to-live for a pending request, in seconds. Retained as the
    /// `Medium`-class total window when no per-class SLA override is set.
    pub ttl_secs: u64,
    /// Public base URL of the web server (e.g. `https://vault.example.com`),
    /// used to build approve/deny links for Telegram/webhook/email.
    pub public_base_url: Option<String>,
    /// Telegram bot notifier configuration.
    pub telegram: Option<TelegramConfig>,
    /// Generic webhook notifier configuration.
    pub webhook: Option<WebhookConfig>,
    /// Per-class SLA overrides (V5). A class absent here uses the built-in
    /// default from [`ApprovalConfig::default_sla`].
    pub sla_overrides: std::collections::HashMap<CriticalityClass, CriticalitySla>,
    /// Rules assigning a criticality class to a `(credential, action)` (V5).
    pub criticality_rules: Vec<CriticalityRule>,
    /// Named identity an out-of-band decision link is bound to (V5). Recorded as
    /// the approver when a decision arrives via the OOB link. Defaults to a
    /// generic `out-of-band` label when unset.
    pub oob_approver_identity: Option<String>,
    /// Optional continuous re-authorization interval in seconds (V5): an approved
    /// grant not run within this window must be re-approved before it executes.
    pub reauth_interval_secs: Option<u64>,
    /// When true, a self-approval (approver == requesting agent) is **rejected**
    /// at decision time (V5); otherwise it is recorded + logged but allowed.
    pub enforce_separation_of_duty: bool,
}

impl ApprovalConfig {
    /// Effective default TTL as a `chrono::Duration`. `ttl_secs == 0` is treated
    /// as the sentinel for "use the default of 1 hour" (a zero-TTL approval would
    /// expire before anyone could decide).
    pub fn ttl(&self) -> chrono::Duration {
        let secs = if self.ttl_secs == 0 { 3600 } else { self.ttl_secs };
        chrono::Duration::seconds(secs as i64)
    }

    /// Built-in default SLA per class (V5): higher criticality escalates and
    /// expires faster. The `Medium` class honors the legacy `ttl_secs` as its
    /// total window (split evenly between the two phases) so existing configs
    /// keep their effective deadline.
    pub fn default_sla(&self, class: CriticalityClass) -> CriticalitySla {
        match class {
            CriticalityClass::Low => CriticalitySla {
                escalate_after_secs: 4 * 3600,
                escalate_window_secs: 4 * 3600,
            },
            CriticalityClass::Medium => {
                // Split the legacy total window across the two phases so existing
                // configs keep their effective deadline. Floor the total at 2s so
                // each phase is a non-zero whole second (a 0s window is what the
                // config validator rejects for explicit overrides — keep derived
                // defaults to the same shape).
                let total = if self.ttl_secs == 0 { 3600 } else { self.ttl_secs.max(2) };
                let half = (total / 2).max(1);
                CriticalitySla {
                    escalate_after_secs: half,
                    escalate_window_secs: total.saturating_sub(half),
                }
            }
            CriticalityClass::High => CriticalitySla {
                escalate_after_secs: 15 * 60,
                escalate_window_secs: 15 * 60,
            },
            CriticalityClass::Critical => CriticalitySla {
                escalate_after_secs: 5 * 60,
                escalate_window_secs: 5 * 60,
            },
        }
    }

    /// Effective SLA for a class: the override if present, else the default.
    pub fn sla_for(&self, class: CriticalityClass) -> CriticalitySla {
        self.sla_overrides.get(&class).copied().unwrap_or_else(|| self.default_sla(class))
    }

    /// Criticality class for a `(credential, action)` — first matching rule, or
    /// [`CriticalityClass::Medium`] (V5).
    pub fn criticality_for(&self, credential: &str, action: &str) -> CriticalityClass {
        self.criticality_rules
            .iter()
            .find(|r| r.credential_pattern.matches(credential) && r.action_pattern.matches(action))
            .map(|r| r.class)
            .unwrap_or_default()
    }
}

/// Telegram bot notifier config.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

/// Generic webhook notifier config.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    /// Optional `Authorization` header value to send with the webhook POST.
    pub auth_header: Option<String>,
}

// ==================== Notifiers ====================

/// Error delivering an approval notification.
#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("notification transport error: {0}")]
    Transport(String),
    #[error("notifier misconfigured: {0}")]
    Config(String),
}

/// A channel that can tell a human a new approval is waiting.
#[async_trait::async_trait]
pub trait ApprovalNotifier: Send + Sync {
    /// Channel name for logging (e.g. `telegram`).
    fn channel(&self) -> &'static str;
    /// Deliver a notification for `approval`, embedding `links`.
    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError>;
}

/// Build the set of notifiers configured in `cfg`.
pub fn build_notifiers(cfg: &ApprovalConfig) -> Vec<std::sync::Arc<dyn ApprovalNotifier>> {
    let mut notifiers: Vec<std::sync::Arc<dyn ApprovalNotifier>> = Vec::new();
    if let Some(tg) = &cfg.telegram {
        notifiers.push(std::sync::Arc::new(TelegramNotifier::new(tg.clone())));
    }
    if let Some(wh) = &cfg.webhook {
        notifiers.push(std::sync::Arc::new(WebhookNotifier::new(wh.clone())));
    }
    notifiers
}

/// Telegram bot notifier: sends a message with inline Approve/Deny URL buttons.
pub struct TelegramNotifier {
    config: TelegramConfig,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ApprovalNotifier for TelegramNotifier {
    fn channel(&self) -> &'static str {
        "telegram"
    }

    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError> {
        let api = format!("https://api.telegram.org/bot{}/sendMessage", self.config.bot_token);

        // V5: reflect escalation in the header so a re-ping reads as escalated.
        let header = if approval.status == ApprovalStatus::Escalated {
            "Vultrino approval ESCALATED - still needs a decision"
        } else {
            "Vultrino approval needed"
        };
        let text = format!(
            "\u{1F510} <b>{}</b>\n\n{}\n\nRequested by: {}\nApproval ID: <code>{}</code>\nExpires: {}",
            header,
            html_escape(&approval.summary),
            html_escape(&approval.requester.describe()),
            html_escape(&approval.id),
            approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
        );

        // Telegram inline-keyboard `url` buttons require absolute http(s) URLs.
        // Only attach buttons when we have a real base URL to point at.
        let mut body = serde_json::json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        if links.approve_url.starts_with("http") {
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[
                    { "text": "\u{2705} Approve", "url": links.approve_url },
                    { "text": "\u{274C} Deny", "url": links.deny_url },
                ]]
            });
        }

        let resp = self
            .client
            .post(&api)
            .json(&body)
            .send()
            .await
            // The bot token is in the request URL path; strip the URL from the
            // error so a transport failure never logs the secret.
            .map_err(|e| NotifyError::Transport(e.without_url().to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(NotifyError::Transport(format!(
                "telegram returned {}: {}",
                status, detail
            )));
        }
        Ok(())
    }
}

/// Build the JSON body a [`WebhookNotifier`] POSTs for an approval (V5). The
/// `event` reflects the request's current state so an escalation re-ping
/// (`status == Escalated`) is not mislabelled as a fresh `approval.requested`,
/// and empty decision links (carried by an escalation re-ping, which doesn't
/// re-issue the one-time token) are omitted rather than serialized as `""`.
/// Errors for a non-open status, which is never a live notify path.
fn webhook_payload(
    approval: &ApprovalRequest,
    links: &ApprovalLinks,
) -> Result<serde_json::Value, NotifyError> {
    let event = match approval.status {
        ApprovalStatus::Pending => "approval.requested",
        ApprovalStatus::Escalated => "approval.escalated",
        other => {
            return Err(NotifyError::Config(format!(
                "refusing to notify for non-open approval status {other}"
            )))
        }
    };
    let mut links_json = serde_json::json!({ "panel_url": links.panel_url });
    if links.approve_url.starts_with("http") {
        links_json["approve_url"] = serde_json::json!(links.approve_url);
        links_json["deny_url"] = serde_json::json!(links.deny_url);
    }
    Ok(serde_json::json!({
        "event": event,
        "approval": {
            "id": approval.id,
            "status": approval.status.to_string(),
            "summary": approval.summary,
            "credential": approval.credential,
            "action": approval.action,
            "criticality": approval.criticality.to_string(),
            "requested_by": approval.requester.describe(),
            "created_at": approval.created_at,
            "expires_at": approval.expires_at,
        },
        "links": links_json,
    }))
}

/// Generic webhook notifier: POSTs the approval + links as JSON to a URL.
///
/// Point it at an email-sending service, Slack, Zapier, or your own endpoint to
/// turn an approval into an email confirmation link, a chat message, etc.
pub struct WebhookNotifier {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookNotifier {
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ApprovalNotifier for WebhookNotifier {
    fn channel(&self) -> &'static str {
        "webhook"
    }

    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError> {
        let payload = webhook_payload(approval, links)?;

        let mut req = self.client.post(&self.config.url).json(&payload);
        if let Some(auth) = &self.config.auth_header {
            req = req.header(reqwest::header::AUTHORIZATION, auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| NotifyError::Transport(e.without_url().to_string()))?;

        if !resp.status().is_success() {
            return Err(NotifyError::Transport(format!(
                "webhook returned {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Minimal HTML escaping for Telegram `parse_mode: HTML`.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_approval() -> (ApprovalRequest, String) {
        ApprovalRequest::open(NewApproval {
            credential: "stripe-prod".to_string(),
            action: "http.request".to_string(),
            params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
            requester: RequesterInfo {
                principal_kind: "api_key".to_string(),
                principal_id: Some("k1".to_string()),
                principal_name: Some("agent".to_string()),
                role: Some("executor".to_string()),
            },
            use_token_id: None,
            principal_id: Some("k1".to_string()),
            agent_label: None,
            action_label: None,
            dual_control: false,
            criticality: CriticalityClass::Medium,
            escalate_after: chrono::Duration::minutes(30),
            escalate_window: chrono::Duration::minutes(30),
            oob_identity: None,
            reauth_interval_secs: None,
        })
    }

    #[test]
    fn test_summarize_http() {
        let s = summarize(
            "stripe-prod",
            "http.request",
            &serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        );
        assert!(s.contains("POST"));
        assert!(s.contains("stripe-prod"));
        assert!(s.contains("api.stripe.com"));
    }

    #[test]
    fn test_summarize_generic() {
        let s = summarize("db-prod", "postgres.run_sql", &serde_json::json!({}));
        assert_eq!(s, "postgres.run_sql on db-prod");
    }

    #[test]
    fn test_open_is_pending_with_summary() {
        let (a, token) = new_approval();
        assert_eq!(a.status, ApprovalStatus::Pending);
        assert!(a.id.starts_with("appr_"));
        assert!(!a.executed);
        assert!(a.summary.contains("api.stripe.com"));
        assert!(!token.is_empty());
    }

    #[test]
    fn test_decision_token_roundtrip() {
        let (a, token) = new_approval();
        assert!(a.verify_decision_token(&token));
        assert!(!a.verify_decision_token("wrong-token"));
        // Hash is stored, not the plaintext.
        assert_ne!(a.decision_token_hash, token);
    }

    #[test]
    fn test_approve_then_cannot_redecide() {
        let (mut a, _) = new_approval();
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert!(a.decided_at.is_some());
        assert_eq!(a.approver_identity.as_deref(), Some("alice"));

        let err = a.deny(Decision::new("admin panel", "bob")).unwrap_err();
        assert!(matches!(err, ApprovalError::AlreadyDecided(ApprovalStatus::Approved)));
    }

    #[test]
    fn test_expired_cannot_be_approved() {
        let (mut a, _) = new_approval();
        a.expires_at = Utc::now() - chrono::Duration::minutes(1);
        let err = a.approve(Decision::new("admin panel", "alice")).unwrap_err();
        assert!(matches!(err, ApprovalError::Expired));
        assert_eq!(a.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_decision_requires_approver_identity() {
        // V5: a blank approver identity is rejected — every decision must be
        // attributable.
        let (mut a, _) = new_approval();
        let err = a.approve(Decision::new("admin panel", "   ")).unwrap_err();
        assert!(matches!(err, ApprovalError::MissingApproverIdentity));
        assert_eq!(a.status, ApprovalStatus::Pending, "must remain undecided");
        // A real identity succeeds and is trimmed/recorded.
        a.deny(Decision::new("admin panel", " carol ")).unwrap();
        assert_eq!(a.approver_identity.as_deref(), Some("carol"));
    }

    #[test]
    fn test_lifecycle_escalates_then_expires() {
        // V5: a high-criticality-style two-window lifecycle. Drive the clock by
        // back-dating the boundaries.
        let (mut a, _) = new_approval();
        // Not yet at the first window → no change.
        assert_eq!(a.advance_lifecycle(), LifecycleChange::None);
        assert_eq!(a.status, ApprovalStatus::Pending);

        // First window elapsed, still before the deadline → escalate.
        a.escalate_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(a.advance_lifecycle(), LifecycleChange::Escalated);
        assert_eq!(a.status, ApprovalStatus::Escalated);
        assert!(a.escalated_at.is_some());
        // Idempotent: escalating again is a no-op while before the deadline.
        assert_eq!(a.advance_lifecycle(), LifecycleChange::None);

        // An escalated request can still be decided.
        assert!(a.status.is_open());

        // Final deadline elapsed → expire (deny).
        a.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(a.advance_lifecycle(), LifecycleChange::Expired);
        assert_eq!(a.status, ApprovalStatus::Expired);
        // A decided request is never advanced again.
        assert_eq!(a.advance_lifecycle(), LifecycleChange::None);
    }

    #[test]
    fn test_lifecycle_skips_escalation_when_past_deadline() {
        // If both boundaries are already past, expiry wins (no spurious escalate).
        let (mut a, _) = new_approval();
        a.escalate_at = Utc::now() - chrono::Duration::minutes(2);
        a.expires_at = Utc::now() - chrono::Duration::minutes(1);
        assert_eq!(a.advance_lifecycle(), LifecycleChange::Expired);
        assert_eq!(a.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_escalated_request_can_be_approved() {
        let (mut a, _) = new_approval();
        a.escalate_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(a.advance_lifecycle(), LifecycleChange::Escalated);
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_sod_violation_computable() {
        // requester principal_name = "agent"; approver "agent" → SoD violation.
        let (mut a, _) = new_approval();
        assert_eq!(a.violates_sod(), None, "no decision yet → not computable");
        a.approve(Decision::new("admin panel", "AGENT")).unwrap();
        assert_eq!(a.violates_sod(), Some(true), "approver == requester owner");

        // A distinct approver satisfies SoD.
        let (mut b, _) = new_approval();
        b.deny(Decision::new("admin panel", "secops-oncall")).unwrap();
        assert_eq!(b.violates_sod(), Some(false));
    }

    #[test]
    fn test_sod_recorded_always_and_enforced_when_configured() {
        // Recorded but allowed by default.
        let (mut a, _) = new_approval();
        a.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(a.sod_violation, Some(true));
        assert_eq!(a.status, ApprovalStatus::Approved, "allowed when not enforcing");

        // Hard-reject a self-approval when enforcing; the request stays undecided
        // and the approver is cleared.
        let (mut b, _) = new_approval();
        let err = b
            .approve(Decision::new("admin panel", "AGENT").enforcing_sod(true))
            .unwrap_err();
        assert!(matches!(err, ApprovalError::SeparationOfDuty));
        assert_eq!(b.status, ApprovalStatus::Pending);
        assert!(b.approver_identity.is_none());

        // A distinct approver passes even when enforcing.
        b.approve(Decision::new("admin panel", "secops").enforcing_sod(true)).unwrap();
        assert_eq!(b.status, ApprovalStatus::Approved);
        assert_eq!(b.sod_violation, Some(false));

        // A self-*denial* is harmless and is never blocked, even when enforcing.
        let (mut c, _) = new_approval();
        c.deny(Decision::new("admin panel", "agent").enforcing_sod(true)).unwrap();
        assert_eq!(c.status, ApprovalStatus::Denied);
        assert_eq!(c.sod_violation, Some(true), "recorded even on deny");
    }

    #[test]
    fn test_needs_reauth() {
        let (mut a, _) = new_approval();
        a.reauth_interval_secs = Some(60);
        // Not approved yet → no reauth.
        assert!(!a.needs_reauth());
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        // Fresh decision → no reauth.
        assert!(!a.needs_reauth());
        // Back-date the decision past the interval → stale → needs reauth.
        a.decided_at = Some(Utc::now() - chrono::Duration::seconds(61));
        assert!(a.needs_reauth());
        // Once executed, it's spent → no reauth.
        a.executed = true;
        assert!(!a.needs_reauth());
    }

    #[test]
    fn test_webhook_payload_event_and_links_by_status() {
        let (mut a, token) = new_approval();
        let links = a.links("https://vault.example.com", &token);

        // Pending → approval.requested with real decision links.
        let p = webhook_payload(&a, &links).unwrap();
        assert_eq!(p["event"], "approval.requested");
        assert!(p["links"]["approve_url"].is_string());
        assert_eq!(p["approval"]["status"], "pending");

        // Escalated → approval.escalated; a panel-only link set omits approve/deny.
        a.status = ApprovalStatus::Escalated;
        let panel_only = ApprovalLinks {
            approve_url: String::new(),
            deny_url: String::new(),
            panel_url: "https://vault.example.com/approvals".to_string(),
        };
        let e = webhook_payload(&a, &panel_only).unwrap();
        assert_eq!(e["event"], "approval.escalated");
        assert!(e["links"].get("approve_url").is_none(), "blank links omitted");
        assert!(e["links"]["panel_url"].is_string());

        // A decided/closed status is not a live notify path → Config error.
        a.status = ApprovalStatus::Approved;
        assert!(matches!(webhook_payload(&a, &links), Err(NotifyError::Config(_))));
    }

    #[test]
    fn test_sla_windows_per_class() {
        let mut cfg = ApprovalConfig { ttl_secs: 7200, ..Default::default() };
        // Critical escalates faster than Low.
        let crit = cfg.sla_for(CriticalityClass::Critical);
        let low = cfg.sla_for(CriticalityClass::Low);
        assert!(crit.escalate_after_secs < low.escalate_after_secs);
        // Medium honors the legacy ttl_secs as its total window.
        let med = cfg.sla_for(CriticalityClass::Medium);
        assert_eq!(med.escalate_after_secs + med.escalate_window_secs, 7200);
        // An override takes precedence.
        cfg.sla_overrides.insert(
            CriticalityClass::High,
            CriticalitySla { escalate_after_secs: 1, escalate_window_secs: 2 },
        );
        assert_eq!(cfg.sla_for(CriticalityClass::High).escalate_after_secs, 1);
    }

    #[test]
    fn test_links_embed_token_and_id() {
        let (a, token) = new_approval();
        let links = a.links("https://vault.example.com/", &token);
        assert!(links.approve_url.contains(&a.id));
        assert!(links.approve_url.contains("decision=approve"));
        assert!(links.deny_url.contains("decision=deny"));
        assert!(links.panel_url.ends_with("/approvals"));
    }
}
