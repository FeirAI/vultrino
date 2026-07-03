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

impl CriticalityClass {
    /// Govder risk_tier wire value (plan 031 D3 cross-plane contract).
    pub fn to_govder_risk_tier(self) -> &'static str {
        match self {
            CriticalityClass::Low => "Low",
            CriticalityClass::Medium => "Medium",
            CriticalityClass::High => "High",
            CriticalityClass::Critical => "Extreme",
        }
    }
}

/// Whether the approval action is irreversible (plan 031 D3 floor input).
/// Uses the trusted stamp from capability/policy at open time — requester-authored
/// `params.irreversible` is ignored for delegate/human floor evaluation.
pub fn approval_irreversible(a: &ApprovalRequest) -> bool {
    a.trusted_irreversible
}

/// Map a capability/policy reversibility label to the D3 irreversible floor.
pub fn reversibility_requires_human_floor(reversibility: &str) -> bool {
    matches!(
        reversibility.trim(),
        "irreversible" | "partially-reversible" | "partially_reversible"
    )
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
    /// Human/directory owner bound to the requesting NHI (V10): the IdP-resolvable
    /// owner (OIDC `sub` / SCIM id). The most precise "requester's owner" for
    /// separation-of-duty when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
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
            owner: None,
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

/// serde default for `required_approvals` (pre-V12 records were single-approval).
fn one() -> u32 {
    1
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
    /// Trusted irreversibility stamp from capability/policy at open (D3 floor).
    pub trusted_irreversible: Option<bool>,
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
    /// Number of **distinct** approvers required before the action runs (V12
    /// dual-control / M-of-N). 1 = a single approval; 2+ = dual control. Derived
    /// from the `dual_control` flag (and any configured M).
    pub required_approvals: u32,
    /// Tenant of the opening principal (V11/R4), snapshotted so approval
    /// visibility and decision are partitioned by tenant. `None` = untenanted
    /// (shared — visible to every admin, like an untenanted credential).
    pub tenant: Option<String>,
    /// Resolved workload-identity subject of the opener (V10/R6), snapshotted so a
    /// `principal_pattern` Deny targeting an SVID/OIDC subject re-fires on resume.
    pub workload_id: Option<String>,
}

fn default_approver_kind() -> String {
    "human".to_string()
}

/// One approver's sign-off on a dual-control (M-of-N) approval (V12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signoff {
    /// Authenticated identity of this approver.
    pub approver_identity: String,
    /// Channel the sign-off arrived on.
    pub channel: String,
    pub decided_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Kind of approver (`human` or `delegate-agent`).
    #[serde(default = "default_approver_kind")]
    pub approver_kind: String,
    /// DelegationGrant reference when `approver_kind` is `delegate-agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_grant_ref: Option<String>,
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
    /// Kind of approver (`human` or `delegate-agent`).
    pub approver_kind: String,
    /// DelegationGrant reference when `approver_kind` is `delegate-agent`.
    pub delegation_grant_ref: Option<String>,
}

impl Decision {
    /// A decision made by an authenticated approver on a named channel.
    pub fn new(channel: impl Into<String>, approver_identity: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            approver_identity: approver_identity.into(),
            note: None,
            enforce_sod: false,
            approver_kind: default_approver_kind(),
            delegation_grant_ref: None,
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

    /// Mark this decision as arriving from a delegate agent (plan 031).
    pub fn as_delegate(mut self, grant_ref: impl Into<String>) -> Self {
        self.approver_kind = "delegate-agent".to_string();
        self.delegation_grant_ref = Some(grant_ref.into());
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
    /// Tenant of the opening principal (V11/R4): approval visibility and decision
    /// are partitioned by it. `None` = untenanted (shared — visible to every
    /// admin). Snapshotted at open from the requesting principal's tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Resolved workload-identity subject of the opener (V10/R6), recorded so a
    /// `principal_pattern` Deny on an SVID/OIDC subject re-fires when the action
    /// resumes (the resume principal carries it as a match dimension).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    /// govder business-verb label for the action (V8), shown to the approver
    /// instead of the canonical `plugin.action` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_label: Option<String>,
    /// Whether this action requires dual control (V8 strictness `direct`),
    /// enforced via `required_approvals` (V12).
    #[serde(default)]
    pub dual_control: bool,
    /// Distinct approvers required before the action runs (V12 M-of-N). 1 = single
    /// approval; 2+ = dual control. Defaults to 1 for pre-V12 records.
    #[serde(default = "one")]
    pub required_approvals: u32,
    /// Recorded approver sign-offs (V12). For a single-approval request this holds
    /// the one decision; for dual control it accumulates distinct approvers until
    /// `required_approvals` is met.
    #[serde(default)]
    pub signoffs: Vec<Signoff>,
    /// Criticality class (V5) — drives the escalation/expiry windows and is
    /// recorded for separation-of-duty / complacency analytics.
    #[serde(default)]
    pub criticality: CriticalityClass,
    /// Trusted irreversibility from capability/policy at open (D3); not requester params.
    #[serde(default)]
    pub trusted_irreversible: bool,
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
            tenant: params.tenant,
            workload_id: params.workload_id,
            action_label: params.action_label,
            dual_control: params.dual_control,
            required_approvals: params.required_approvals.max(1),
            signoffs: Vec::new(),
            criticality: params.criticality,
            trusted_irreversible: params.trusted_irreversible.unwrap_or(false),
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

    /// Whether this approval is visible to (and decidable by) an admin acting in
    /// tenant `acting` (V11/R4). Partitioning rules, paralleling credential
    /// isolation:
    /// - a **global** admin (`acting == None`) sees every approval;
    /// - an **untenanted** approval (`self.tenant == None`) is shared — visible to
    ///   every admin (like an untenanted credential);
    /// - otherwise the acting tenant must match the approval's tenant, so an admin
    ///   in tenant A can never see or decide tenant B's approval.
    pub fn visible_to_tenant(&self, acting: Option<&str>) -> bool {
        match acting {
            None => true,
            Some(a) => match self.tenant.as_deref() {
                None => true,
                Some(t) => t == a,
            },
        }
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
        let now = Utc::now();
        let sod = self.sod_for(&identity);

        if to == ApprovalStatus::Denied {
            // A single veto denies, regardless of how many approvals were gathered
            // (M-of-N is for granting, not denying). A self-denial is harmless.
            self.signoffs.push(Signoff {
                approver_identity: identity.clone(),
                channel: decision.channel.clone(),
                decided_at: now,
                note: decision.note.clone(),
                approver_kind: decision.approver_kind.clone(),
                delegation_grant_ref: decision.delegation_grant_ref.clone(),
            });
            self.status = ApprovalStatus::Denied;
            self.decided_at = Some(now);
            self.decided_by = Some(decision.channel);
            self.approver_identity = Some(identity);
            // Sticky-true, consistent with the approval path.
            self.sod_violation = match (self.sod_violation, sod) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (a, b) => a.or(b),
            };
            self.decision_note = decision.note;
            return Ok(());
        }

        // Approval path (V12 dual-control / M-of-N).
        // Optionally hard-reject a self-approval (don't record it; the request
        // stays cleanly awaiting other approvers).
        if decision.enforce_sod && sod == Some(true) {
            return Err(ApprovalError::SeparationOfDuty);
        }
        // Hard-SoD M-of-N (in-lock, TOCTOU-safe): when more than one distinct
        // approver is required, a SECOND sign-off may not come from the SAME
        // aggregator key as an existing one. The api-layer fast-fail also checks
        // this, but it is racy across concurrent requests; this check runs inside
        // the storage write lock (transition() executes under locked_mutate), so
        // two concurrent same-key decisions can't both slip through. Only applies
        // to aggregator-asserted identities (`agg:<key-id>:…`); bare identities
        // are unaffected. The aggregator's claim of distinct HUMAN operators is
        // unverifiable, so under hard SoD one key counts once.
        if decision.enforce_sod && self.effective_required_approvals() > 1 {
            if let Some(prefix) = aggregator_key_prefix(&identity) {
                if self
                    .signoffs
                    .iter()
                    .any(|s| s.approver_identity.starts_with(prefix))
                {
                    return Err(ApprovalError::SameAggregatorKey);
                }
            }
        }
        // Approvers must be DISTINCT — the same identity can't satisfy two of the
        // required M sign-offs.
        if self
            .signoffs
            .iter()
            .any(|s| s.approver_identity.eq_ignore_ascii_case(&identity))
        {
            return Err(ApprovalError::DuplicateApprover);
        }
        self.signoffs.push(Signoff {
            approver_identity: identity.clone(),
            channel: decision.channel.clone(),
            decided_at: now,
            note: decision.note.clone(),
            approver_kind: decision.approver_kind.clone(),
            delegation_grant_ref: decision.delegation_grant_ref.clone(),
        });
        self.approver_identity = Some(identity);
        // Sticky SoD: a violation by ANY of the M approvers flags the decision.
        self.sod_violation = match (self.sod_violation, sod) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (a, b) => a.or(b),
        };
        // Threshold met → grant; otherwise stay open awaiting more distinct
        // approvers. Use the authoritative threshold (dual_control forces >= 2).
        if self.signoffs.len() as u32 >= self.effective_required_approvals() {
            self.status = ApprovalStatus::Approved;
            self.decided_at = Some(now);
            self.decided_by = Some(decision.channel);
            self.decision_note = decision.note;
        }
        Ok(())
    }

    /// The authoritative number of distinct approvers this request needs (V12).
    /// `dual_control` is the source of truth: it forces at least 2 even if
    /// `required_approvals` is stale (e.g. a pre-V12 record that serialized
    /// `dual_control: true` before `required_approvals` existed and so defaults to
    /// 1 — it must NOT be runnable on a single approval after upgrade).
    pub fn effective_required_approvals(&self) -> u32 {
        if self.dual_control {
            self.required_approvals.max(2)
        } else {
            self.required_approvals.max(1)
        }
    }

    /// How many more distinct approvals this request needs before it is granted
    /// (V12). 0 once the threshold is met.
    pub fn approvals_remaining(&self) -> u32 {
        self.effective_required_approvals()
            .saturating_sub(self.signoffs.len() as u32)
    }

    /// Separation-of-duty check (V5): whether the (final) approver collides with
    /// the requesting agent's own identity. `None` when not computable.
    pub fn violates_sod(&self) -> Option<bool> {
        self.sod_for(self.approver_identity.as_deref()?)
    }

    /// Whether a candidate approver identity collides with the requesting agent's
    /// own identity (a self-approval). `None` when either side is unknown.
    fn sod_for(&self, candidate: &str) -> Option<bool> {
        // An aggregator-asserted identity (`agg:<key-id>:<operator>`) must be
        // compared by its BARE operator, not the namespaced wrapper — otherwise a
        // self-approval (operator == the requester's owner/label) would never
        // match the requester identities and SoD would fail OPEN on exactly the
        // aggregator surface. Bare identities pass through unchanged.
        let approver = bare_approver_identity(candidate).trim();
        if approver.is_empty() {
            return None;
        }
        // Compare the approver against EVERY known identity of the requesting
        // agent — the IdP-resolvable directory owner (V10), the human/agent label,
        // and the stable principal id — so a self-approval under ANY of them is a
        // violation (not just the highest-precedence one). A blank identity is
        // skipped rather than treated as "the owner" (so it can't poison the result
        // to not-computable).
        let identities = [
            self.requester.owner.as_deref(),
            self.requester.principal_name.as_deref(),
            self.agent_label.as_deref(),
            self.principal_id.as_deref(),
            self.requester.principal_id.as_deref(),
        ];
        let known: Vec<&str> = identities
            .into_iter()
            .flatten()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if known.is_empty() {
            return None; // not computable
        }
        Some(known.iter().any(|id| id.eq_ignore_ascii_case(approver)))
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
    #[error("dual control: this approver has already signed off on this request")]
    DuplicateApprover,
    /// Hard-SoD M-of-N: a second sign-off arrived under the SAME aggregator key
    /// as an existing one. Distinctness across different human operators on ONE
    /// aggregator key is only a CLAIM the aggregator makes (vultrino can't verify
    /// it), so under hard SoD one key may not satisfy two of the M sign-offs.
    #[error("separation of duty: this aggregator key already supplied a sign-off; a distinct co-approver must use a different key")]
    SameAggregatorKey,
}

/// Prefix that marks an **aggregator-asserted** approver identity recorded by the
/// product-aggregator JSON surface: `agg:<acting-api-key-id>:<operator>`. The
/// operator is a CLAIM the aggregator makes; the api-key id segment records WHICH
/// key asserted it. Used to (a) compute SoD against the bare operator and (b)
/// detect two sign-offs from the same key under hard M-of-N SoD.
pub const AGG_IDENTITY_PREFIX: &str = "agg:";

/// If `identity` is an aggregator-asserted identity (`agg:<key-id>:<operator>`),
/// return the un-namespaced operator (everything after the second colon) for SoD
/// comparison; otherwise return it unchanged. A malformed `agg:`-prefixed value
/// with no second colon is returned as-is (treated as an opaque identity).
fn bare_approver_identity(identity: &str) -> &str {
    let Some(rest) = identity.strip_prefix(AGG_IDENTITY_PREFIX) else {
        return identity;
    };
    // `rest` is `<key-id>:<operator>`; the operator is after the FIRST colon here
    // (the second colon overall). `<key-id>` is a UUID with no colons.
    match rest.split_once(':') {
        Some((_key_id, operator)) => operator,
        None => identity, // malformed; leave opaque
    }
}

/// The aggregator-key prefix (`agg:<key-id>:`) of an aggregator-asserted identity,
/// or `None` for a bare (non-aggregator) identity. Two sign-offs sharing this
/// prefix came from the same acting api key.
fn aggregator_key_prefix(identity: &str) -> Option<&str> {
    let rest = identity.strip_prefix(AGG_IDENTITY_PREFIX)?;
    // Keep through the second overall colon: `agg:<key-id>:`.
    let key_id_len = rest.find(':')?;
    Some(&identity[..AGG_IDENTITY_PREFIX.len() + key_id_len + 1])
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
    /// the approver when a decision arrives via the OOB link. **Required when a
    /// notifier is configured** (R2): config load rejects an unset value with a
    /// notifier present, and the OOB route refuses a decision rather than recording
    /// an anonymous `out-of-band` label — so a verdict is never unattributable.
    pub oob_approver_identity: Option<String>,
    /// Optional continuous re-authorization interval in seconds (V5): an approved
    /// grant not run within this window must be re-approved before it executes.
    pub reauth_interval_secs: Option<u64>,
    /// When true, a self-approval (approver == requesting agent) is **rejected**
    /// at decision time (V5); otherwise it is recorded + logged but allowed.
    pub enforce_separation_of_duty: bool,
    /// Number of distinct approvers a dual-control request requires (V12 M-of-N).
    /// Defaults to 2; only takes effect for requests flagged `dual_control`.
    pub dual_control_approvers: u32,
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

/// approval_notifier_client builds the client the approval notifiers use. Notifiers
/// POST decision-bearing payloads (the approve/deny links carry capability tokens)
/// plus an optional Authorization header to OPERATOR-configured endpoints. Those
/// endpoints may legitimately be internal (a private collector), so we do NOT apply
/// the agent-egress private-IP SSRF resolver here. But we DO disable redirects: a 3xx
/// from the configured endpoint must not carry the decision token / auth header to an
/// unintended target (Codex medium).
fn approval_notifier_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build approval notifier client")
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
            client: approval_notifier_client(),
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
            // Consistency with the signed-outbox path; govder tolerates
            // approval.tenant. None → null (untenanted/shared).
            "tenant": approval.tenant,
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
            client: approval_notifier_client(),
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
                owner: None,
            },
            use_token_id: None,
            principal_id: Some("k1".to_string()),
            agent_label: None,
            tenant: None,
            workload_id: None,
            action_label: None,
            dual_control: false,
            criticality: CriticalityClass::Medium,
            trusted_irreversible: None,
            escalate_after: chrono::Duration::minutes(30),
            escalate_window: chrono::Duration::minutes(30),
            oob_identity: None,
            reauth_interval_secs: None,
            required_approvals: 1,
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
    fn test_dual_control_requires_distinct_approvers() {
        // V12 M-of-N: a dual-control request needs 2 DISTINCT approvers.
        let (mut a, _) = new_approval();
        a.required_approvals = 2;
        // First approver → recorded, still pending (1 of 2).
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending, "1 of 2 → still pending");
        assert_eq!(a.signoffs.len(), 1);
        assert_eq!(a.approvals_remaining(), 1);
        // The same approver can't satisfy the second sign-off (case-insensitive).
        let err = a.approve(Decision::new("admin panel", "ALICE")).unwrap_err();
        assert!(matches!(err, ApprovalError::DuplicateApprover));
        assert_eq!(a.status, ApprovalStatus::Pending, "duplicate doesn't advance");
        assert_eq!(a.signoffs.len(), 1);
        // A second DISTINCT approver meets the threshold → Approved.
        a.approve(Decision::new("admin panel", "bob")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert_eq!(a.signoffs.len(), 2);
        assert_eq!(a.approvals_remaining(), 0);
    }

    #[test]
    fn test_pre_v12_dual_control_record_still_requires_two() {
        // Upgrade path: a pre-V12 record serialized `dual_control: true` before
        // `required_approvals` existed, so it deserializes with the field defaulting
        // to 1. It must NOT be runnable on a single approval — dual_control is the
        // authoritative source of the threshold.
        let (mut a, _) = new_approval();
        a.dual_control = true;
        a.required_approvals = 2;
        let mut v = serde_json::to_value(&a).unwrap();
        v.as_object_mut().unwrap().remove("required_approvals"); // pre-V12: absent
        let restored: ApprovalRequest = serde_json::from_value(v).unwrap();
        assert_eq!(restored.required_approvals, 1, "serde default for the absent field");
        assert_eq!(restored.effective_required_approvals(), 2, "dual_control forces >= 2");

        // A single approval does NOT grant it.
        let mut r = restored;
        r.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(r.status, ApprovalStatus::Pending, "single approval must not grant dual control");
        r.approve(Decision::new("admin panel", "bob")).unwrap();
        assert_eq!(r.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_deny_path_sod_is_sticky_true() {
        // V12: the deny path records SoD sticky-true (a later violating decision
        // must not be lost under a prior Some(false) — the bug the `.or()` had).
        let (mut a, _) = new_approval(); // requester owner = "agent"
        a.required_approvals = 2;
        a.approve(Decision::new("admin panel", "alice")).unwrap(); // alice != agent → false
        assert_eq!(a.sod_violation, Some(false));
        a.deny(Decision::new("admin panel", "agent")).unwrap(); // self-deny → violation
        assert_eq!(a.status, ApprovalStatus::Denied);
        assert_eq!(a.sod_violation, Some(true), "deny SoD must be sticky-true over a prior false");
    }

    #[test]
    fn test_dual_control_single_deny_vetoes() {
        // One veto denies, regardless of how many approvals were gathered.
        let (mut a, _) = new_approval();
        a.required_approvals = 2;
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        a.deny(Decision::new("admin panel", "carol")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Denied);
        // No further decision is accepted once denied.
        assert!(a.approve(Decision::new("admin panel", "dave")).is_err());
    }

    #[test]
    fn test_dual_control_enforce_sod_rejects_self_among_approvers() {
        // With SoD enforced, a self-approval by the requester ('agent') is rejected
        // and does NOT count toward the M-of-N threshold.
        let (mut a, _) = new_approval(); // requester principal_name = "agent"
        a.required_approvals = 2;
        let err = a
            .approve(Decision::new("admin panel", "agent").enforcing_sod(true))
            .unwrap_err();
        assert!(matches!(err, ApprovalError::SeparationOfDuty));
        assert_eq!(a.signoffs.len(), 0, "self-approval not recorded");
        // Two distinct non-requester approvers still grant it.
        a.approve(Decision::new("admin panel", "alice").enforcing_sod(true)).unwrap();
        a.approve(Decision::new("admin panel", "bob").enforcing_sod(true)).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_aggregator_identity_helpers() {
        // Bare identity passes through unchanged.
        assert_eq!(bare_approver_identity("alice@example.com"), "alice@example.com");
        assert_eq!(aggregator_key_prefix("alice@example.com"), None);
        // agg:<key-id>:<operator> → bare operator + key prefix.
        let id = "agg:11111111-2222-3333-4444-555555555555:alice@example.com";
        assert_eq!(bare_approver_identity(id), "alice@example.com");
        assert_eq!(
            aggregator_key_prefix(id),
            Some("agg:11111111-2222-3333-4444-555555555555:")
        );
        // An operator containing a colon is preserved whole (only the FIRST two
        // colons are structural: agg: and the key-id terminator).
        let weird = "agg:key-1:a:b@example.com";
        assert_eq!(bare_approver_identity(weird), "a:b@example.com");
        assert_eq!(aggregator_key_prefix(weird), Some("agg:key-1:"));
        // Malformed agg: with no second colon is left opaque (no false strip).
        assert_eq!(bare_approver_identity("agg:no-second-colon"), "agg:no-second-colon");
        assert_eq!(aggregator_key_prefix("agg:no-second-colon"), None);
    }

    #[test]
    fn test_sod_computed_against_bare_operator_of_aggregator_identity() {
        // [#2 regression] An NHI whose OWNER is alice@ approved by human alice@ via
        // the aggregator (recorded as `agg:<key>:alice@`) is a self-approval — SoD
        // must be computed against the BARE operator, not the namespaced wrapper,
        // or it would fail OPEN on exactly this surface.
        let (mut a, _) = new_approval();
        a.requester.owner = Some("alice@example.com".to_string());
        // Not enforcing: the violation must still be RECORDED (observable).
        let agg_self = "agg:key-123:alice@example.com";
        a.approve(Decision::new("json-api", agg_self)).unwrap();
        assert_eq!(
            a.sod_violation,
            Some(true),
            "aggregator self-approval (owner == operator) must be flagged"
        );

        // Enforcing: the same self-approval is REJECTED (not merely recorded).
        let (mut b, _) = new_approval();
        b.requester.owner = Some("alice@example.com".to_string());
        let err = b
            .approve(Decision::new("json-api", agg_self).enforcing_sod(true))
            .unwrap_err();
        assert!(matches!(err, ApprovalError::SeparationOfDuty));
        assert_eq!(b.status, ApprovalStatus::Pending, "self-approval not recorded");

        // A genuinely DIFFERENT operator on the aggregator surface is clean.
        let (mut c, _) = new_approval();
        c.requester.owner = Some("alice@example.com".to_string());
        c.approve(Decision::new("json-api", "agg:key-123:bob@example.com").enforcing_sod(true))
            .unwrap();
        assert_eq!(c.sod_violation, Some(false), "distinct operator satisfies SoD");
        assert_eq!(c.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_hard_sod_rejects_second_signoff_from_same_aggregator_key() {
        // [#7 in-lock] Under hard SoD on a 2-of-N approval, two sign-offs from the
        // SAME aggregator key (same `agg:<key-id>:` prefix, different operators)
        // must NOT both count — the second is rejected, leaving the request open
        // with a single recorded sign-off.
        let (mut a, _) = new_approval();
        a.required_approvals = 2;
        a.approve(Decision::new("json-api", "agg:keyA:alice@example.com").enforcing_sod(true))
            .unwrap();
        assert_eq!(a.signoffs.len(), 1);
        assert_eq!(a.status, ApprovalStatus::Pending);
        let err = a
            .approve(Decision::new("json-api", "agg:keyA:bob@example.com").enforcing_sod(true))
            .unwrap_err();
        assert!(matches!(err, ApprovalError::SameAggregatorKey));
        assert_eq!(a.signoffs.len(), 1, "the same-key second sign-off was not recorded");
        assert_eq!(a.status, ApprovalStatus::Pending);
        // A DIFFERENT aggregator key completes the threshold.
        a.approve(Decision::new("json-api", "agg:keyB:carol@example.com").enforcing_sod(true))
            .unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert_eq!(a.signoffs.len(), 2);
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
    fn test_sod_uses_directory_owner_when_present() {
        // V10: when the requesting NHI has a bound directory owner, SoD compares
        // the approver to that owner (the most precise "requester's owner"), not
        // just the agent label.
        let (mut a, _) = new_approval(); // principal_name "agent"
        a.requester.owner = Some("alice@example.com".to_string());
        a.approve(Decision::new("admin panel", "ALICE@example.com")).unwrap();
        assert_eq!(a.violates_sod(), Some(true), "approver == bound owner → SoD violation");

        // SoD checks ALL the agent's identities: approving under the agent's own
        // name (not the owner) is still a self-approval.
        let (mut b, _) = new_approval(); // principal_name "agent"
        b.requester.owner = Some("alice@example.com".to_string());
        b.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(b.violates_sod(), Some(true), "self-approval under any identity is flagged");

        // A genuinely distinct approver (neither the owner nor the agent) is clean.
        let (mut c, _) = new_approval();
        c.requester.owner = Some("alice@example.com".to_string());
        c.approve(Decision::new("admin panel", "secops-oncall")).unwrap();
        assert_eq!(c.violates_sod(), Some(false), "distinct approver satisfies SoD");

        // A blank owner must NOT poison the result to not-computable — SoD falls
        // through to the agent's other identities (the old `.or()` chain bug).
        let (mut d, _) = new_approval(); // principal_name "agent"
        d.requester.owner = Some("   ".to_string());
        d.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(d.violates_sod(), Some(true), "blank owner doesn't poison SoD to None");
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
    fn test_expire_reauth_lapsed_preserves_approver_attribution() {
        // Approved with a note → reauth lapse keeps the approver and appends the
        // lapse reason (the append arm), never overwriting with a system actor.
        let (mut a, _) = new_approval();
        a.approve(Decision::new("admin panel", "alice").with_note(Some("ok by me".to_string())))
            .unwrap();
        let decided_at = a.decided_at;
        a.expire_reauth_lapsed();
        assert_eq!(a.status, ApprovalStatus::Expired);
        assert_eq!(a.decided_by.as_deref(), Some("admin panel"), "channel preserved");
        assert_eq!(a.approver_identity.as_deref(), Some("alice"), "approver preserved");
        assert_eq!(a.decided_at, decided_at, "decision time preserved");
        let note = a.decision_note.as_deref().unwrap();
        assert!(note.contains("ok by me"), "original note kept: {note}");
        assert!(note.contains("re-authorization"), "lapse appended: {note}");

        // No prior note → just the lapse reason (the default arm).
        let (mut b, _) = new_approval();
        b.approve(Decision::new("admin panel", "bob")).unwrap();
        b.expire_reauth_lapsed();
        assert_eq!(b.decision_note.as_deref(), Some("re-authorization window lapsed before execution"));
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
    fn webhook_payload_carries_tenant() {
        let (mut approval, token) = new_approval();
        let links = approval.links("https://vault.example.com", &token);

        // Untenanted (new_approval sets tenant: None) → nested approval.tenant is null.
        let p = webhook_payload(&approval, &links).expect("pending payload builds");
        assert!(p["approval"].get("tenant").is_some(), "nested tenant key present");
        assert!(p["approval"]["tenant"].is_null(), "untenanted ⇒ null");

        // Tenanted → the nested key carries the tenant string.
        approval.tenant = Some("acme".to_string());
        let p2 = webhook_payload(&approval, &links).expect("pending payload builds");
        assert_eq!(p2["approval"]["tenant"], "acme");
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
