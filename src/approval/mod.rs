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

/// Fallback execute-by window for an approved-but-unrun grant when no explicit
/// continuous re-authorization interval is configured (24h). An `Approved` request
/// is not `is_open()`, so its `expires_at` guard stops firing the moment it is
/// approved — leaving `needs_reauth` as the ONLY bound on how long a granted-but-
/// never-executed action stays runnable. Without this, an unexecuted grant would be
/// executable forever. Generous by design: it must not clip a legitimately
/// long-lived approval, only ensure a forgotten one lapses *observably* (it emits
/// the same `EVENT_APPROVAL_EXPIRED` audit as a re-auth lapse). An operator who
/// wants a tighter window sets `reauth_interval_secs`.
pub const DEFAULT_UNRUN_GRANT_WINDOW_SECS: u64 = 24 * 60 * 60;

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

/// Whether the use token that would execute an approved action is still usable —
/// the caller's lookup result, so [`execution_state_at_decision`] stays pure.
///
/// The four states are deliberately distinct: `Unknown` must NEVER collapse into
/// `Usable` (that is how a storage blip becomes a false "this will run"), and
/// `NotApplicable` must never collapse into `Unusable` (a local/API-key caller
/// needs no use token, so its absence is not a defect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCheck {
    /// The request names no use token: execution does not depend on one.
    NotApplicable,
    /// Loaded and usable right now.
    Usable,
    /// Loaded and NOT usable, with the reason (expired / revoked / exhausted), or
    /// named by the request but no longer present in the vault.
    Unusable(String),
    /// The lookup itself failed — genuinely undetermined, claimed neither way.
    Unknown,
}

/// What a caller may TRUTHFULLY claim about EXECUTION at the instant a decision was
/// recorded (plan 103 §10h FINDING 4, layer 3).
///
/// Recording a decision and running the action are two separate events in this
/// design: `POST /api/v1/approvals/{id}/decision` only commits the sign-off, and the
/// requesting agent's next poll is what actually executes. The decision response
/// therefore carried `executed: false` on EVERY successful grant, which the product
/// UI collapsed into one green "Approved. Recorded just now." receipt — the same
/// receipt it painted for an approval whose action had already failed. An approver
/// signed an irreversible refund, saw success, and nothing ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    /// This state implies nothing about execution: the request is still open, or was
    /// denied/expired (in which case nothing was supposed to run).
    NotApplicable,
    /// The action RAN and reported success.
    Executed,
    /// The action was attempted and FAILED terminally. Never a completed action.
    Failed,
    /// Granted; nothing has run yet. The outcome is genuinely unknown, so a caller
    /// may claim the DECISION was recorded and must not claim the ACTION happened.
    AwaitingExecution,
    /// Granted, but it can no longer run: the credential that would execute it is
    /// expired / revoked / exhausted / gone. This is the FINDING 4 state — the one
    /// that read as success while the action was already impossible.
    Blocked,
}

impl ExecutionState {
    /// Stable wire word (mirrored by feir-os `brokerapi.Decision.ExecutionState`).
    pub fn as_wire(self) -> &'static str {
        match self {
            ExecutionState::NotApplicable => "not_applicable",
            ExecutionState::Executed => "executed",
            ExecutionState::Failed => "failed",
            ExecutionState::AwaitingExecution => "awaiting_execution",
            ExecutionState::Blocked => "blocked",
        }
    }
}

/// Classify what may be claimed about execution for `a`, given the lookup result for
/// the use token that would execute it. Pure: all I/O belongs to the caller.
///
/// The returned reason is present whenever one is KNOWN (the recorded
/// `result_error`, or why the credential is unusable) and is always safe to show an
/// approver — it is vultrino's own text, never requester-authored params.
pub fn execution_state_at_decision(
    a: &ApprovalRequest,
    credential: &CredentialCheck,
) -> (ExecutionState, Option<String>) {
    // Open / denied / expired: nothing was supposed to run, so there is no execution
    // claim to make either way.
    if a.status != ApprovalStatus::Approved {
        return (ExecutionState::NotApplicable, None);
    }
    if a.executed {
        return match &a.result_error {
            // Terminal and failed — INCLUDING the "outcome unknown, re-approve to
            // retry" finalize, whose text says so explicitly. Never "completed".
            Some(err) => (ExecutionState::Failed, Some(err.clone())),
            None => (ExecutionState::Executed, None),
        };
    }
    // Granted but not run. A dead credential means it CANNOT run — surface that
    // rather than an optimistic "awaiting", which is the exact misreport measured.
    if let CredentialCheck::Unusable(reason) = credential {
        return (ExecutionState::Blocked, Some(reason.clone()));
    }
    // A retryable start failure leaves `executed = false` WITH a recorded reason:
    // still awaiting, but the reason is known and must not be swallowed.
    (ExecutionState::AwaitingExecution, a.result_error.clone())
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
    /// Per-capability approval preview, extracted at open time from the SAME
    /// `params` above per the backing capability's `approval_preview` spec (if
    /// any). `None` when the capability declares no spec — the approver falls
    /// back to `summary`.
    pub preview: Option<crate::capability::ApprovalPreview>,
    /// The govder-authored `ApprovalRule` for this (agent, action_class), fetched
    /// at open (plan 100 P2 Phase D; approval-recipes.md §6 D5). `None` when govder
    /// has no rule configured (or is unreachable/unconfigured) — the numeric
    /// threshold applies, byte-identical to today.
    pub approval_rule: Option<ApprovalRule>,
}

fn default_approver_kind() -> String {
    "human".to_string()
}

/// serde default for `Signoff::approve` (pre-Phase-D records never carried this
/// field — see that field's doc for why `true` is the safe default).
fn default_true() -> bool {
    true
}

/// Approver class for approval-recipe slot matching (plan 100 P2 Phase D;
/// docs/design/approval-recipes.md §2 D1). Mirrors govder's
/// `internal/enums.ApproverClass` wire values exactly (`senior` / `teammate` /
/// `agent-reviewer`) so a rule fetched from `GET /v1/oversight/gates/rule` round-trips
/// without translation. `Unknown` is a deserialize-only catch-all (`#[serde(other)]`):
/// an unrecognized class value on a fetched `RecipeTerm` must disqualify only THAT
/// recipe (see `recipe_well_formed`), never fail the whole `ApprovalRule` fetch —
/// govder's own `recipeComposition` has the same "malformed recipe is skipped, not a
/// hard error" contract. `Unknown` never satisfies any slot and is never intentionally
/// produced by [`ApproverClass::parse_wire`] (the `DecideReq` boundary resolves an
/// unrecognized wire string to `None`, not `Unknown` — see that method's doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApproverClass {
    /// A human whose IdP groups intersect the org's configured senior-groups list
    /// AND who holds the `approve` action.
    Senior,
    /// Any human whose groups grant the `approve` action.
    Teammate,
    /// A delegate agent holding an active `DelegationGrant` whose scope covers the
    /// action. Counts exactly 1 in v1 (model-tiered counting is deferred).
    AgentReviewer,
    /// Deserialize-only catch-all for an unrecognized wire value (see doc above).
    #[serde(other)]
    Unknown,
}

impl ApproverClass {
    /// Whether the class is human-accountable (`senior`/`teammate`) as opposed to
    /// `agent-reviewer`/`Unknown` — mirrors govder's `ApproverClass.IsHuman`.
    pub fn is_human(self) -> bool {
        matches!(self, ApproverClass::Senior | ApproverClass::Teammate)
    }

    /// Parse a wire class string resolved by the feir-os broker from VERIFIED IdP
    /// groups (docs/design/approval-recipes.md §6 D5 "human-class evidence
    /// contract"). Returns `None` for blank/unrecognized input — an unresolved class
    /// is never counted toward a stamped `ApprovalRule` (fail-closed; mirrors
    /// govder's `ApproverClass.Valid()` gate in `classifySignOffs`). Deliberately
    /// distinct from the `Unknown` deserialize variant above: a sign-off with an
    /// unparseable class is simply unresolved (`None`), never stored as `Unknown`.
    pub fn parse_wire(s: &str) -> Option<Self> {
        match s.trim() {
            "senior" => Some(ApproverClass::Senior),
            "teammate" => Some(ApproverClass::Teammate),
            "agent-reviewer" => Some(ApproverClass::AgentReviewer),
            _ => None,
        }
    }
}

/// The sub-Extreme partial-dissent semantics knob on an [`ApprovalRule`] (P2 build
/// decision #1, approval-recipes.md). Extreme risk (`CriticalityClass::Critical`) and
/// any irreversible action ALWAYS behave as `DenyOnAnyDeny` regardless of this field
/// (`ApprovalRequest::transition` forces it) — see approval-recipes.md §3/§5 D4a.
/// Deserializes fail-closed: any value other than the exact
/// `majority-with-dissent-recorded` string (including a missing field, an empty
/// string, or a future/unknown value) becomes `DenyOnAnyDeny`, mirroring govder's
/// `RecipeDecisionMode.Valid()` fallback in `evaluateApprovalRule` — but resolved ONCE
/// at deserialize time here rather than re-checked at every evaluation, since Rust's
/// enum makes an invalid in-memory value unrepresentable (a divergence-by-construction
/// from govder's raw-string type, not a behavior difference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RecipeDecisionMode {
    /// DEFAULT (conservative/fail-closed): any single explicit deny halts collection
    /// regardless of the accumulated positive count. `#[default]` is the fail-closed
    /// choice and must stay on this variant: `RecipeDecisionMode::default()` is what a
    /// recipe with no explicit `decision_mode` gets.
    #[default]
    DenyOnAnyDeny,
    /// Opt-in per org: the recipe may still be satisfied by its required positive set
    /// even with a dissenter. The dissent is always recorded on the sign-off set,
    /// never lost.
    MajorityWithDissentRecorded,
}

impl<'de> Deserialize<'de> for RecipeDecisionMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Any non-string, unrecognized, or empty value falls back to the
        // conservative default rather than erroring — a malformed decision_mode
        // must never make the whole ApprovalRule fetch fail (fail-closed).
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(match value.as_str() {
            Some("majority-with-dissent-recorded") => {
                RecipeDecisionMode::MajorityWithDissentRecorded
            }
            _ => RecipeDecisionMode::DenyOnAnyDeny,
        })
    }
}

/// One alternative sign-off composition within an [`ApprovalRule`] (plan 100 P2 Phase
/// D). A recipe is satisfied when the accumulated sign-off set can be injectively
/// assigned to its terms, senior slots first — see [`recipe_satisfied`]'s doc for the
/// swap-argument proof (approval-recipes.md §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recipe {
    pub terms: Vec<RecipeTerm>,
}

/// One class + count slot in a [`Recipe`], e.g. `{class: senior, count: 1}`. Multiple
/// terms of the same class within one recipe are additive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeTerm {
    pub class: ApproverClass,
    pub count: u32,
}

/// The govder-authored approval-recipe rule (plan 100 P2 Phase D;
/// docs/design/approval-recipes.md §6 D5). govder is the system of record — it
/// validates every recipe against the action's risk-tier/autonomy/irreversibility
/// floor at write time AND re-validates it at its own terminal re-check; vultrino
/// receives this ALREADY-VALIDATED shape at approval-open (`GET
/// /v1/oversight/gates/rule`), stamps it onto the `ApprovalRequest`, and evaluates
/// SATISFACTION ONLY in-lock (`ApprovalRequest::transition`) — it never re-derives the
/// D2 risk-tier floor (that would risk Rust/Go drift; see [`approval_rule_satisfied`]'s
/// doc for exactly which D4 axes vultrino does and does not evaluate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRule {
    /// Alternative sign-off compositions; the approval is granted when the
    /// accumulated sign-off set satisfies AT LEAST ONE recipe in full.
    pub recipes: Vec<Recipe>,
    /// The partial-dissent semantics knob (see [`RecipeDecisionMode`]).
    #[serde(default)]
    pub decision_mode: RecipeDecisionMode,
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
    /// RESOLVED approver class, received from the caller (feir-os broker, from
    /// VERIFIED IdP groups) and recorded as a snapshot-at-sign-off value — vultrino
    /// trusts + records it, never re-resolves it later (plan 100 P2 Phase D;
    /// approval-recipes.md §6 D5 "human-class evidence contract"). `None` when the
    /// caller didn't supply one (every pre-Phase-D caller, and the admin panel/
    /// OOB-link/CLI decision paths): such a sign-off is never counted toward a
    /// stamped `ApprovalRule` (fail-closed), though it still counts toward the plain
    /// numeric threshold when no rule is stamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_class: Option<ApproverClass>,
    /// Controller-domain key for D4(f) collapse (agent-reviewer sign-offs sharing a
    /// controller count as ONE toward any recipe) — the grant's delegator (human) or
    /// the delegate `AgentRecord`'s owner, resolved and snapshotted by the caller at
    /// sign-off time. Ignored for human sign-offs. `None`/blank collapses into a
    /// single sentinel "unknown controller" domain at evaluation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// Whether this sign-off was itself an approve (`true`) or an explicit
    /// deny/dissent (`false`). Recipe evaluation counts only `true` entries toward
    /// any recipe — see `ApprovalRequest::transition`'s
    /// `RecipeDecisionMode::MajorityWithDissentRecorded` handling. Defaults to
    /// `true` for records predating this field: before Phase D a deny was ALWAYS
    /// immediately terminal, so every `Signoff` still reachable on an OPEN request
    /// was necessarily an approval; the one historical exception (the trailing
    /// `Signoff` on an already-`Denied` request) is inert, since a `Denied`
    /// request's sign-offs are never re-evaluated.
    #[serde(default = "default_true")]
    pub approve: bool,
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
    /// Resolved approver class for recipe satisfaction (plan 100 P2 Phase D; see
    /// [`Signoff::resolved_class`]).
    pub resolved_class: Option<ApproverClass>,
    /// Controller-domain key for recipe D4(f) collapse (plan 100 P2 Phase D; see
    /// [`Signoff::controller`]).
    pub controller: Option<String>,
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
            resolved_class: None,
            controller: None,
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

    /// Attach the resolved approver class (plan 100 P2 Phase D recipe satisfaction).
    pub fn with_resolved_class(mut self, class: ApproverClass) -> Self {
        self.resolved_class = Some(class);
        self
    }

    /// Attach the controller-domain key (plan 100 P2 Phase D D4(f) collapse).
    pub fn with_controller(mut self, controller: impl Into<String>) -> Self {
        self.controller = Some(controller.into());
        self
    }
}

/// Unforgeable evidence that a grant was **re-derived from the persisted
/// sign-off set** and held (Stage 1 V2).
///
/// The type carries no public constructor, no `Clone`, no `Copy`, no `Default`
/// and no `Deserialize`. Its single field is private and its only producer is
/// [`ApprovalRequest::grant_witness`]. Therefore *possession of a `Granted` is
/// itself the proof* — a caller cannot manufacture one, cannot deserialize one
/// out of the vault, and cannot duplicate one it was handed.
///
/// Everything that actually runs an approved action requires one by value or by
/// reference ([`crate::storage::ExecutionClaim`] holds one;
/// `VultrinoServer::resume_approved` takes one), so **"execute an approved action
/// without a re-derived grant" is not expressible** — it is a type error, not a
/// convention. That is the founder's sentence in type form: no action executes
/// unless the sign-off set that vultrino actually holds satisfies the rule.
///
/// # What it is not
///
/// It is not a capability token and it is not unforgeable across a process
/// boundary — it never leaves the process and is never serialized. It is a
/// compile-time obligation on in-process control flow. The cross-process half is
/// the re-derivation itself, which is why the witness is minted from stored bytes
/// rather than handed down from `transition`.
///
/// # The demonstration that the seal is load-bearing
///
/// Everything below is a **doc-test**. rustdoc compiles each snippet as a
/// standalone crate that depends on `vultrino` — which is precisely the adversary
/// the seal is aimed at ("a downstream consumer of the `vultrino` crate") — and
/// `compile_fail` makes rustdoc **fail the test if the snippet compiles**. So
/// "the bad state cannot be constructed" is re-checked by the compiler on every
/// `cargo test`, rather than asserted in a comment. Measured on this toolchain
/// (rustc 1.92.0): turning the positive control below into a `compile_fail`
/// makes the doc-test suite go red, so `compile_fail` itself binds.
///
/// ## Why there is a positive control, and why it is shaped the way it is
///
/// A `compile_fail` test passes when the snippet fails to compile **for any
/// reason at all**. A renamed module, a moved type, a typo in a path — any of
/// those silently converts every one of the five tests below into a test that
/// passes while checking nothing. That is this codebase's measured failure class
/// (*a control that reads as live and is inert*), so a bare pile of
/// `compile_fail` snippets would be an instance of the very defect this work
/// exists to close.
///
/// **The obvious fix does not work, and it was measured rather than assumed.**
/// rustdoc accepts `` ```compile_fail,E0616 ``, which reads as pinning the
/// *reason*. On stable rustc 1.92.0 it does not: replacing a snippet's real
/// `E0599` with a deliberately wrong `E0424` left the suite green. **The error
/// code annotation is inert here — do not use it as a pin anywhere in this
/// repository.**
///
/// So the reason is pinned structurally instead. The positive control below
/// names **every symbol** and exercises **every syntactic shape** the five
/// failing snippets use — `&mut ApprovalRequest`, a `GrantBasis` struct-variant
/// literal, `Vec::<Signoff>::push`, a `Granted` in a signature — and it **must
/// compile**. Each failing snippet then differs from it by exactly one token: the
/// sealed operation. If a rename or a bad path were the real cause of a failure,
/// the positive control would fail too and the suite would go red.
///
/// ```
/// use vultrino::approval::{ApprovalRequest, ApprovalStatus, GrantBasis, Granted, Signoff};
///
/// // Every shape the compile_fail snippets below use, in its sanctioned form.
/// fn sanctioned(a: &mut ApprovalRequest, s: Signoff) -> (ApprovalStatus, usize, Option<Granted>) {
///     let mut local: Vec<Signoff> = Vec::new();
///     local.push(s);                      // `push` on a Vec<Signoff> is fine...
///     let _ = local.len();                // ...it is `a.signoffs` that is sealed.
///     let _basis = GrantBasis::NumericThreshold { need: 1, have: 1 };
///     (a.status(), a.signoffs().len(), a.grant_witness())
/// }
/// fn holds_a_grant(_g: &Granted) {}
/// ```
///
/// A downstream holder of `&mut ApprovalRequest` **cannot write the status**.
/// This is the exact one-liner plan 105 §2.3 names: it would bypass, in one
/// compile-clean line, the blank-identity check, the TTL check, the SoD guard,
/// the same-aggregator-key guard, the duplicate-approver guard, and recipe
/// satisfaction:
///
/// ```compile_fail
/// use vultrino::approval::{ApprovalRequest, ApprovalStatus};
/// fn forge(a: &mut ApprovalRequest) {
///     a.status = ApprovalStatus::Approved;
/// }
/// ```
///
/// Nor **read** it as a field, so no consumer can come to depend on the field's
/// existence and make a future re-sealing a breaking change:
///
/// ```compile_fail
/// use vultrino::approval::{ApprovalRequest, ApprovalStatus};
/// fn peek(a: &ApprovalRequest) -> ApprovalStatus {
///     a.status
/// }
/// ```
///
/// Nor **fabricate the evidence** the grant is derived from — sealing the
/// conclusion while leaving the premise writable would be the same hole with an
/// extra step:
///
/// ```compile_fail
/// use vultrino::approval::{ApprovalRequest, Signoff};
/// fn stuff(a: &mut ApprovalRequest, s: Signoff) {
///     a.signoffs.push(s);
/// }
/// ```
///
/// Nor **construct a `Granted` directly**, which is what makes possession of one
/// evidence rather than decoration:
///
/// ```compile_fail
/// use vultrino::approval::{GrantBasis, Granted};
/// fn forge_grant() -> Granted {
///     Granted { basis: GrantBasis::NumericThreshold { need: 1, have: 1 } }
/// }
/// ```
///
/// Nor **duplicate one it was legitimately handed**, which is what keeps a single
/// grant from authorising two executions:
///
/// ```compile_fail
/// use vultrino::approval::Granted;
/// fn duplicate(g: &Granted) -> Granted {
///     g.clone()
/// }
/// ```
///
/// # What this does NOT prove, stated so nobody reads it as more
///
/// It is rung 1 for *every module outside `src/approval/mod.rs` and every
/// downstream crate*. Inside this module the six write sites remain, and their
/// correctness is a rung-2/3 claim carried by the lifecycle enumeration and the
/// cross-language conformance suite, not by the type system. And it says nothing
/// about an adversary who edits the vault ciphertext: that adversary is met by
/// [`ApprovalRequest::grant_witness`]'s re-derivation, one rung lower, and the
/// residual is recorded in `docs/dev/LIMITATIONS.md`.
#[derive(Debug)]
#[must_use = "a Granted is the authority to execute; dropping it silently discards the grant"]
pub struct Granted {
    #[allow(dead_code)] // carried for diagnostics/audit; the VALUE's existence is the claim
    basis: GrantBasis,
    binding: crate::formal_kernel::ExecutionBinding,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

impl Granted {
    /// Why the grant held — for logs and for the audit record. Never a decision
    /// input: the *existence* of the `Granted` is the decision.
    pub fn basis(&self) -> &GrantBasis {
        &self.basis
    }

    pub(crate) fn binding(&self) -> &crate::formal_kernel::ExecutionBinding {
        &self.binding
    }

    pub(crate) fn issued_at_unix_seconds(&self) -> i64 {
        self.issued_at_unix_seconds
    }

    pub(crate) fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }
}

/// The predicate that produced a [`Granted`]. Subsumes plan 104 rank 13 / N-2a
/// (*"`Approved` carries no evidence of why"*): the grant now names its own
/// reason, so an audit consumer reads it rather than trusting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantBasis {
    /// No rule was stamped; the V12 numeric threshold cleared.
    NumericThreshold { need: u32, have: u32 },
    /// A govder-stamped [`ApprovalRule`] was satisfied by the stored sign-offs.
    Recipe {
        recipes: usize,
        counted_signoffs: usize,
    },
}

/// A request for a human to approve (or deny) a specific authenticated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique id, format `appr_<uuid>` — this is what the agent polls with.
    pub id: String,
    /// Current lifecycle state.
    ///
    /// **SEALED (Stage 1 V2).** This field was `pub` until 2026-07-29. A public
    /// mutable field on a public struct in a library crate meant any holder of a
    /// `&mut ApprovalRequest` — a new call site in another module, or any
    /// downstream consumer of the `vultrino` crate — could write
    /// `approval.status = ApprovalStatus::Approved` in one compile-clean line and
    /// bypass, at once: the blank-identity check, the TTL check, the SoD guard,
    /// the same-aggregator-key guard, the duplicate-approver guard, and recipe
    /// satisfaction. The discipline existed (every production write was already
    /// inside this module) but it was enforced by convention, not by the compiler.
    ///
    /// Now: read it with [`ApprovalRequest::status`]; write it only through
    /// [`ApprovalRequest::transition`] and the lifecycle helpers in this module.
    /// Outside `src/approval/mod.rs` **no** write is expressible at all — that is
    /// a compiler-checked fact, not a grep.
    ///
    /// Serde still round-trips it (the derive expands in this module, so field
    /// privacy does not affect it), which is precisely why sealing is necessary
    /// but not sufficient — see [`Granted`] for the half the type system cannot
    /// reach across the vault boundary.
    status: ApprovalStatus,
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
    /// Extracted approval-preview VALUES (action-type-specific fields, e.g. a
    /// Telegram message's `text` + `chat_id`), computed once at open time from
    /// the executing `params` per the backing capability's declared spec.
    /// Exposes ONLY the declared field values — never the raw `params`, never
    /// the credential. `None` when the capability declares no
    /// `approval_preview` (unchanged fallback to `summary`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<crate::capability::ApprovalPreview>,
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
    ///
    /// **SEALED (Stage 1 V2), for the same reason [`Self::status`] is.** The
    /// sign-off set is the *evidence* the grant rests on; leaving it publicly
    /// mutable while sealing `status` would seal the conclusion and leave the
    /// premise writable, which is the weaker half of the same hole (push a
    /// fabricated `Signoff`, then let `transition` grant honestly on it). Read it
    /// with [`ApprovalRequest::signoffs`]; it is appended only by
    /// [`ApprovalRequest::transition`], after every guard has run.
    #[serde(default)]
    signoffs: Vec<Signoff>,
    /// The govder-authored `ApprovalRule` stamped at open (plan 100 P2 Phase D;
    /// approval-recipes.md §6 D5). `None` preserves today's numeric-threshold
    /// behavior byte-identically — recipes are strictly opt-in per action class.
    /// When present, `transition()` evaluates recipe satisfaction IN-LOCK against
    /// this stamped copy instead of the numeric threshold (govder does its own
    /// terminal re-validation independently; see [`approval_rule_satisfied`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_rule: Option<ApprovalRule>,
    /// Govder-AUTHORITATIVE risk tier for the recipe deny-wins force (Codex P2 review
    /// BLOCKER 5), stamped from `GET /v1/oversight/gates/rule` ALONGSIDE
    /// `approval_rule` — NOT vultrino's LOCAL [`Self::criticality`] (which can diverge
    /// from govder). Only consulted when `approval_rule` is `Some`. Wire values are
    /// `Low`/`Medium`/`High`/`Extreme`; `""` (govder could not resolve) or any
    /// unparseable value is treated as Extreme (fail-closed) by
    /// [`Self::recipe_forces_deny_on_any_deny`]. Defaults to `""` on older records —
    /// the fail-closed direction (a stamped rule with no risk facts forces
    /// deny-on-any-deny).
    #[serde(default)]
    pub authoritative_risk_tier: String,
    /// Govder-AUTHORITATIVE irreversibility for the recipe deny-wins force (Codex P2
    /// review BLOCKER 5). NOT vultrino's LOCAL [`Self::trusted_irreversible`]
    /// (capability-metadata stamp). Only consulted when `approval_rule` is `Some`.
    #[serde(default)]
    pub authoritative_irreversible: bool,
    /// Criticality class (V5) — drives the escalation/expiry windows and is
    /// recorded for separation-of-duty / complacency analytics.
    #[serde(default)]
    pub criticality: CriticalityClass,
    /// Trusted irreversibility from capability/policy at open (D3); not requester params.
    #[serde(default)]
    pub trusted_irreversible: bool,
    /// Trusted spend facts from the policy extractor at open (D3 grant caps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_spend_amount_minor: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_spend_asset: Option<String>,
    /// End of the delegator's veto window for a delegate-approved action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_veto_until: Option<DateTime<Utc>>,
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
    /// Monotonic execution-claim fence (#8). Incremented under the storage lock on
    /// every claim (fresh OR stale re-take), so a terminal write can be committed
    /// with a compare-and-set: a worker whose claim was superseded (it crashed and
    /// was re-taken) finds the epoch advanced and its blind finalize is rejected
    /// rather than overwriting the re-taker's outcome.
    #[serde(default)]
    pub execution_epoch: u64,
}

/// The tenant partition primitive (V11/R4): whether an admin acting in tenant
/// `acting` may see or act on a resource tagged `resource_tenant`. A **global**
/// (operator) admin — `acting == None` — acts on everything; an **untenanted**
/// (shared) resource — `resource_tenant == None` — is actable by anyone;
/// otherwise the tenants must match exactly. This is the single source of truth
/// the admin API and the storage-lock re-checks reuse, so approval / token /
/// credential scoping can never drift apart.
pub fn tenant_may_act(acting: Option<&str>, resource_tenant: Option<&str>) -> bool {
    match acting {
        None => true,
        Some(a) => match resource_tenant {
            None => true,
            Some(t) => t == a,
        },
    }
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
            preview: params.preview,
            action_label: params.action_label,
            dual_control: params.dual_control,
            required_approvals: params.required_approvals.max(1),
            signoffs: Vec::new(),
            approval_rule: params.approval_rule,
            // Govder-authoritative risk facts default to empty/false here; the
            // server stamps them from the rule-fetch response right after open()
            // (alongside the trusted-spend stamps). An empty `authoritative_risk_tier`
            // forces deny-on-any-deny (fail-closed) — see
            // `recipe_forces_deny_on_any_deny`.
            authoritative_risk_tier: String::new(),
            authoritative_irreversible: false,
            criticality: params.criticality,
            trusted_irreversible: params.trusted_irreversible.unwrap_or(false),
            trusted_spend_amount_minor: None,
            trusted_spend_asset: None,
            delegate_veto_until: None,
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
            execution_epoch: 0,
        };

        (request, decision_token)
    }

    /// Current lifecycle state. Read-only accessor for the sealed
    /// [`Self::status`] field (Stage 1 V2).
    pub fn status(&self) -> ApprovalStatus {
        self.status
    }

    /// The recorded sign-off set, in the order it accumulated. Read-only accessor
    /// for the sealed [`Self::signoffs`] field (Stage 1 V2).
    pub fn signoffs(&self) -> &[Signoff] {
        &self.signoffs
    }

    /// Re-establish the persisted approval invariants after decryption and
    /// deserialization, before the record becomes reachable by the server.
    ///
    /// Serde can reconstruct private fields from bytes, so field privacy alone
    /// does not protect the vault boundary. This check deliberately rejects
    /// impossible or execution-ambiguous shapes rather than repairing them.
    pub(crate) fn validate_vault_shape(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty()
            || self.credential.trim().is_empty()
            || self.action.trim().is_empty()
            || self.decision_token_hash.trim().is_empty()
        {
            return Err("approval identity/action fields must be non-blank");
        }
        if self.escalate_at < self.created_at || self.expires_at < self.escalate_at {
            return Err("approval lifecycle timestamps are out of order");
        }
        for signoff in &self.signoffs {
            if bare_approver_identity(&signoff.approver_identity)
                .trim()
                .is_empty()
            {
                return Err("approval contains an unnamed sign-off principal");
            }
            if signoff.channel.trim().is_empty() {
                return Err("approval contains a blank sign-off channel");
            }
            match signoff.approver_kind.trim() {
                "human" => {
                    if matches!(
                        signoff.resolved_class,
                        Some(ApproverClass::AgentReviewer | ApproverClass::Unknown)
                    ) {
                        return Err("human sign-off has an incompatible resolved class");
                    }
                }
                "delegate-agent" => {
                    if signoff.resolved_class != Some(ApproverClass::AgentReviewer)
                        || signoff
                            .delegation_grant_ref
                            .as_deref()
                            .map(str::trim)
                            .unwrap_or_default()
                            .is_empty()
                    {
                        return Err("delegate sign-off lacks its class or delegation grant");
                    }
                }
                _ => return Err("approval contains an unknown approver kind"),
            }
        }

        if self.executing && self.executed {
            return Err("approval cannot be executing and executed simultaneously");
        }
        if self.executing != self.executing_since.is_some() {
            return Err("approval execution claim timestamp is inconsistent");
        }
        if (self.executing || self.executed) && self.status != ApprovalStatus::Approved {
            return Err("only an approved request may execute");
        }
        if self.executed && self.result_status.is_none() && self.result_error.is_none() {
            return Err("executed approval has no recorded outcome");
        }

        match self.status {
            ApprovalStatus::Pending => {
                if self.escalated_at.is_some() || self.decided_at.is_some() {
                    return Err("pending approval carries a later lifecycle timestamp");
                }
            }
            ApprovalStatus::Escalated => {
                if self.escalated_at.is_none() || self.decided_at.is_some() {
                    return Err("escalated approval timestamps are inconsistent");
                }
            }
            ApprovalStatus::Approved => {
                if self.decided_at.is_none()
                    || self
                        .decided_by
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                    || self
                        .approver_identity
                        .as_deref()
                        .map(bare_approver_identity)
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                    || self.grant_witness().is_none()
                {
                    return Err("approved status is not backed by executable grant evidence");
                }
            }
            ApprovalStatus::Denied | ApprovalStatus::Expired => {
                if self.decided_at.is_none()
                    || self
                        .decided_by
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                {
                    return Err("terminal approval lacks decision attribution");
                }
            }
        }
        Ok(())
    }

    /// Re-derive the grant from the PERSISTED state and, if it holds, mint the
    /// one witness that the execution path requires. `None` means **refuse**.
    ///
    /// # Why this exists, and why sealing the field alone is not enough
    ///
    /// Sealing [`Self::status`] makes an illegal *in-memory* write inexpressible.
    /// It does nothing about the vault: `ApprovalRequest` is `Deserialize`, and a
    /// deserialize reconstructs `status` **from bytes**, so a type-level state
    /// parameter cannot survive the round-trip (this is the structural blocker
    /// that rules out textbook typestate — plan 105 §2.3 blocker 1). The persisted
    /// transition — the one that matters across a crash, or between two processes
    /// — is out of reach of the type system by construction.
    ///
    /// So the invariant is re-established at the only point where it is
    /// load-bearing: **immediately before execution**, from the stored evidence,
    /// under the storage write lock. `Granted` is the proof object. Its
    /// constructor is private to this module and it is neither `Clone` nor
    /// `Copy` nor `Default` nor `Deserialize`, so the ONLY way any caller
    /// anywhere can obtain one is to call this function and have it say yes.
    ///
    /// # What it re-derives, and what it deliberately does not
    ///
    /// It re-runs exactly the predicate `transition` granted on:
    /// [`approval_rule_satisfied`] against the stamped rule when one is present,
    /// otherwise the numeric threshold. That is E1's clause — *the sign-off set
    /// vultrino held when it wrote `Approved` satisfies at least one whole recipe*
    /// — and re-deriving it is total and deterministic (the sign-off set is frozen
    /// once the request leaves an open state, and neither predicate reads a clock).
    ///
    /// It does **not** re-run the *decision-time* guards (TTL, SoD, the
    /// same-aggregator-key guard, duplicate-approver). Those are properties of the
    /// act of deciding, not of the resulting evidence, and cannot be recomputed
    /// from a stored record. Their bypass remains inexpressible only inside this
    /// crate's compile unit; see `LIMITATIONS.md`.
    ///
    /// # Fail-closed direction
    ///
    /// A record whose stored `status` is `Approved` but whose stored sign-off set
    /// does not satisfy its stored rule yields `None` and therefore does not run.
    /// That includes a pre-V12 record with an empty `signoffs` array, which is the
    /// one benign shape this refuses; it is refused deliberately, because
    /// "approved, with no recorded evidence of by whom" is exactly the state a
    /// vault edit produces and there is no way to tell the two apart from the
    /// record.
    pub fn grant_witness(&self) -> Option<Granted> {
        self.grant_witness_inner(self.execution_epoch, false)
    }

    /// Production witness bound to the epoch the storage lock is about to
    /// commit. Unlike the test-facing re-derivation above, this requires a real
    /// decision timestamp and a still-live execute-by window.
    pub(crate) fn grant_witness_for_epoch(&self, epoch: u64) -> Option<Granted> {
        self.grant_witness_inner(epoch, true)
    }

    fn grant_witness_inner(&self, epoch: u64, require_live_decision: bool) -> Option<Granted> {
        if self.status != ApprovalStatus::Approved {
            return None;
        }
        let basis = match &self.approval_rule {
            None => {
                let need = self.effective_required_approvals();
                let positives: Vec<&Signoff> = self.signoffs.iter().filter(|s| s.approve).collect();
                let have = positives.len() as u32;
                if have < need {
                    return None;
                }
                // Re-derive the evidence properties a persisted status byte
                // cannot establish: every counting principal is named and
                // distinct. For M-of-N, one aggregator key may contribute at
                // most once; a vault edit cannot fabricate two operators behind
                // the same controller and have both counted.
                let mut identities = std::collections::HashSet::new();
                let mut aggregator_keys = std::collections::HashSet::new();
                for signoff in positives {
                    let identity = bare_approver_identity(&signoff.approver_identity)
                        .trim()
                        .to_ascii_lowercase();
                    if identity.is_empty() || !identities.insert(identity) {
                        return None;
                    }
                    if need > 1 {
                        if let Some(prefix) = aggregator_key_prefix(&signoff.approver_identity) {
                            if !aggregator_keys.insert(prefix.to_ascii_lowercase()) {
                                return None;
                            }
                        }
                    }
                }
                GrantBasis::NumericThreshold { need, have }
            }
            Some(rule) => {
                if !approval_rule_satisfied(rule, &self.signoffs) {
                    return None;
                }
                // Re-establish controller separation from persisted evidence.
                // One aggregator key cannot manufacture multiple human subjects
                // for a recipe, even if a vault edit bypassed `transition`.
                let mut aggregator_keys = std::collections::HashSet::new();
                for signoff in &self.signoffs {
                    if self.contributes_positive_slot(signoff.approve, signoff.resolved_class) {
                        if let Some(prefix) = aggregator_key_prefix(&signoff.approver_identity) {
                            if !aggregator_keys.insert(prefix.to_ascii_lowercase()) {
                                return None;
                            }
                        }
                    }
                }
                GrantBasis::Recipe {
                    recipes: rule.recipes.len(),
                    counted_signoffs: self.signoffs.iter().filter(|s| s.approve).count(),
                }
            }
        };

        let issued_at = match self.decided_at {
            Some(value) => value,
            None if require_live_decision => return None,
            None => self.created_at,
        };
        let window = self
            .reauth_interval_secs
            .filter(|&seconds| seconds > 0)
            .unwrap_or(DEFAULT_UNRUN_GRANT_WINDOW_SECS);
        let expires_at = issued_at + chrono::Duration::seconds(i64::try_from(window).ok()?);
        if require_live_decision && Utc::now() >= expires_at {
            return None;
        }

        Some(Granted {
            basis,
            binding: self.execution_binding(epoch)?,
            issued_at_unix_seconds: issued_at.timestamp(),
            expires_at_unix_seconds: expires_at.timestamp(),
        })
    }

    /// Exact eight-field approval binding shared with the Lean model.
    pub(crate) fn execution_binding(
        &self,
        epoch: u64,
    ) -> Option<crate::formal_kernel::ExecutionBinding> {
        let params = serde_json::to_vec(&self.params).ok()?;
        let rule = match &self.approval_rule {
            Some(rule) => serde_json::to_vec(&serde_json::json!({
                "mode": "recipe",
                "approval_rule": rule,
                "authoritative_risk_tier": self.authoritative_risk_tier,
                "authoritative_irreversible": self.authoritative_irreversible,
            }))
            .ok()?,
            None => serde_json::to_vec(&serde_json::json!({
                "mode": "numeric",
                "required_approvals": self.effective_required_approvals(),
            }))
            .ok()?,
        };
        Some(crate::formal_kernel::ExecutionBinding::new(
            self.id.clone(),
            epoch,
            self.tenant.clone().unwrap_or_default(),
            self.principal_id
                .clone()
                .or_else(|| self.requester.principal_id.clone())
                .unwrap_or_default(),
            self.credential.clone(),
            self.action.clone(),
            crate::formal_kernel::digest_bytes(&params),
            crate::formal_kernel::digest_bytes(&rule),
        ))
    }

    /// Test-only escape hatch for the sealed [`Self::status`] field.
    ///
    /// Gated on `cfg(test)`, so it does not exist in any shipped binary and
    /// cannot be called by a downstream consumer of the crate: the rung-1 claim
    /// "no production write site outside this module" is unaffected by it. It
    /// exists so that in-crate tests in sibling modules can still fabricate the
    /// adversarial records they are *supposed* to fabricate (a stale approved
    /// grant, a vault record with a forged status) without any of them being able
    /// to do so by accident.
    #[cfg(test)]
    pub(crate) fn set_status_for_test(&mut self, status: ApprovalStatus) {
        self.status = status;
    }

    /// Test-only escape hatch for the sealed [`Self::signoffs`] field. Same
    /// `cfg(test)` reasoning as [`Self::set_status_for_test`].
    #[cfg(test)]
    pub(crate) fn set_signoffs_for_test(&mut self, signoffs: Vec<Signoff>) {
        self.signoffs = signoffs;
    }

    /// Test-only append to the sealed [`Self::signoffs`] field. Same `cfg(test)`
    /// reasoning as [`Self::set_status_for_test`].
    #[cfg(test)]
    pub(crate) fn push_signoff_for_test(&mut self, signoff: Signoff) {
        self.signoffs.push(signoff);
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
        tenant_may_act(acting, self.tenant.as_deref())
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

    /// Whether a stamped recipe rule must behave as `deny-on-any-deny` regardless of
    /// its configured `decision_mode` knob (approval-recipes.md §3/§5 D4a; Codex P2
    /// review BLOCKER 5). Uses govder's AUTHORITATIVE facts stamped at fetch
    /// ([`Self::authoritative_irreversible`] / [`Self::authoritative_risk_tier`]) —
    /// NEVER vultrino's LOCAL [`Self::criticality`] / [`Self::trusted_irreversible`],
    /// which can diverge from govder (the divergence where a majority-mode deny went
    /// non-terminal because vultrino locally classified an authoritatively-Extreme
    /// action as Medium). Mirrors govder's
    /// `forceDenyOnAnyDeny := irreversible || riskTier == Extreme`, extended per the
    /// review so an empty/unparseable `authoritative_risk_tier` is treated as Extreme
    /// (fail-closed).
    fn recipe_forces_deny_on_any_deny(&self) -> bool {
        self.authoritative_irreversible
            || risk_tier_forces_deny_on_any_deny(&self.authoritative_risk_tier)
    }

    fn transition(&mut self, to: ApprovalStatus, decision: Decision) -> Result<(), ApprovalError> {
        // V5: a human decision must carry an authenticated approver identity, so
        // every decision is attributable and SoD is computable. Reject blanks.
        let identity = decision.approver_identity.trim().to_string();
        // The namespaced aggregator spelling is transport provenance, not the
        // human principal. Reject an empty BARE subject here so the numeric and
        // recipe paths cannot record `agg:<key>:` as an approving person and
        // only discover the mismatch when the execution grant is re-derived.
        if bare_approver_identity(&identity).trim().is_empty() {
            return Err(ApprovalError::MissingApproverIdentity);
        }
        if self.is_past_ttl() {
            self.expire_if_due();
            return Err(ApprovalError::Expired);
        }
        let now = Utc::now();
        // A human may veto a delegate-approved action until its deferred execution
        // window closes. Outside that one transition, a decision is valid only in
        // an open state (Pending or Escalated).
        let is_delegate_veto = to == ApprovalStatus::Denied
            && self.status == ApprovalStatus::Approved
            && !self.executed
            && self.delegate_veto_until.map(|t| now < t).unwrap_or(false)
            && decision.approver_kind != "delegate-agent";
        if !self.status.is_open() && !is_delegate_veto {
            return Err(ApprovalError::AlreadyDecided(self.status));
        }
        let sod = self.sod_for(&identity);

        if to == ApprovalStatus::Denied {
            // Plan 100 P2 Phase D: with a stamped ApprovalRule in
            // `RecipeDecisionMode::MajorityWithDissentRecorded`, a dissent is
            // recorded but does NOT by itself terminate the request — the recipe
            // may still be satisfiable by the remaining positive sign-offs
            // (approval-recipes.md §3 P2 build decision #1). This carve-out NEVER
            // applies to:
            //  - the numeric-threshold path (no rule stamped) — deny-wins stays
            //    verbatim, byte-identical parity with today;
            //  - Extreme risk or an irreversible action (forced deny-on-any-deny
            //    regardless of the configured knob — approval-recipes.md §3/§5 D4a);
            //    this force now reads govder's AUTHORITATIVE facts, NOT vultrino's
            //    LOCAL criticality (Codex P2 review BLOCKER 5);
            //  - a veto of an ALREADY-Approved request (`is_delegate_veto`) —
            //    vetoing is always terminal, never a "dissent" on a still-open
            //    collection.
            let terminal_deny = is_delegate_veto
                || match &self.approval_rule {
                    None => true,
                    Some(rule) => {
                        self.recipe_forces_deny_on_any_deny()
                            || rule.decision_mode == RecipeDecisionMode::DenyOnAnyDeny
                    }
                };
            // A single veto denies, regardless of how many approvals were gathered
            // (M-of-N is for granting, not denying). A self-denial is harmless. The
            // sign-off is recorded either way — dissent is NEVER lost, even when it
            // doesn't (yet) terminate the request.
            self.signoffs.push(Signoff {
                approver_identity: identity.clone(),
                channel: decision.channel.clone(),
                decided_at: now,
                note: decision.note.clone(),
                approver_kind: decision.approver_kind.clone(),
                delegation_grant_ref: decision.delegation_grant_ref.clone(),
                resolved_class: decision.resolved_class,
                controller: decision.controller.clone(),
                approve: false,
            });
            // Sticky-true, consistent with the approval path.
            self.sod_violation = match (self.sod_violation, sod) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (a, b) => a.or(b),
            };
            if !terminal_deny {
                // Dissent recorded; the request stays open awaiting more sign-offs.
                return Ok(());
            }
            self.status = ApprovalStatus::Denied;
            self.decided_at = Some(now);
            self.decided_by = Some(decision.channel);
            self.approver_identity = Some(identity);
            self.decision_note = decision.note;
            return Ok(());
        }

        // Approval path (V12 dual-control / M-of-N, and plan 100 P2 Phase D recipes).
        // Optionally hard-reject a self-approval (don't record it; the request
        // stays cleanly awaiting other approvers).
        if decision.enforce_sod && sod == Some(true) {
            return Err(ApprovalError::SeparationOfDuty);
        }
        // Controller separation for M-of-N (in-lock, TOCTOU-safe): one aggregator
        // key may contribute AT MOST ONE positive recipe slot — the aggregator's
        // claim of distinct HUMAN operators is unverifiable, so a SECOND
        // positive-contributing sign-off from the SAME key is rejected. The
        // api-layer fast-fail mirrors this, but is racy across concurrent
        // requests; this check runs inside the storage write lock (transition()
        // executes under locked_mutate), so two concurrent same-key decisions
        // can't both slip through. Only aggregator-asserted identities
        // (`agg:<key-id>:…`) are affected; bare identities are unaffected.
        //
        // The guard keys on POSITIVE, SLOT-CONTRIBUTING sign-offs on BOTH sides
        // (contributes_positive_slot): a recorded majority-mode DISSENT, or a
        // positive whose class the recipe does not use, neither contributes nor
        // poisons the key (Codex RE-REVIEW-4 — the per-tenant-key permanent-veto
        // regression). This positive-contributing sign-off is being added now, so
        // its own contribution is evaluated with approve=true.
        if self.same_aggregator_key_guard_active(decision.enforce_sod)
            && self.contributes_positive_slot(true, decision.resolved_class)
        {
            if let Some(prefix) = aggregator_key_prefix(&identity) {
                if self.signoffs.iter().any(|s| {
                    s.approver_identity.starts_with(prefix)
                        && self.contributes_positive_slot(s.approve, s.resolved_class)
                }) {
                    return Err(ApprovalError::SameAggregatorKey);
                }
            }
        }
        // Approvers must be DISTINCT — the same identity can't satisfy two of the
        // required M sign-offs (nor dissent once and later approve, or vice versa).
        let bare_identity = bare_approver_identity(&identity).trim();
        if self.signoffs.iter().any(|s| {
            bare_approver_identity(&s.approver_identity)
                .trim()
                .eq_ignore_ascii_case(bare_identity)
        }) {
            return Err(ApprovalError::DuplicateApprover);
        }
        self.signoffs.push(Signoff {
            approver_identity: identity.clone(),
            channel: decision.channel.clone(),
            decided_at: now,
            note: decision.note.clone(),
            approver_kind: decision.approver_kind.clone(),
            delegation_grant_ref: decision.delegation_grant_ref.clone(),
            resolved_class: decision.resolved_class,
            controller: decision.controller.clone(),
            approve: true,
        });
        self.approver_identity = Some(identity);
        // Sticky SoD: a violation by ANY of the M approvers flags the decision.
        self.sod_violation = match (self.sod_violation, sod) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (a, b) => a.or(b),
        };
        // Threshold met → grant; otherwise stay open awaiting more distinct
        // approvers/recipe slots. A stamped ApprovalRule REPLACES the numeric
        // threshold with in-lock recipe satisfaction (plan 100 P2 Phase D); with
        // no rule, the authoritative numeric threshold is unchanged (dual_control
        // forces >= 2) — byte-identical parity with today.
        let granted = match &self.approval_rule {
            None => self.signoffs.len() as u32 >= self.effective_required_approvals(),
            Some(rule) => approval_rule_satisfied(rule, &self.signoffs),
        };
        if granted {
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

    /// Whether the "one aggregator key counts once" guard is ACTIVE for this
    /// request. It applies whenever MORE THAN ONE distinct approver can be
    /// required to grant: either the numeric threshold is > 1, or a recipe rule
    /// is stamped. The `enforce_sod` argument is retained for API compatibility;
    /// it governs requester-vs-approver self approval, not whether one controller
    /// may fabricate M distinct people.
    ///
    /// The recipe arm is load-bearing (Codex P2 RE-REVIEW-3 BLOCKER 1): a stamped
    /// rule REPLACES the numeric threshold in `transition`'s grant check, but
    /// `effective_required_approvals()` still reflects ONLY `dual_control`/
    /// `required_approvals` — which stays 1 for an ordinary `require_approval`
    /// token. Gating the same-key guard on `effective_required_approvals() > 1`
    /// alone therefore SKIPS it for a `{teammate:2}` (or any multi-slot) recipe
    /// opened with an ordinary token, letting ONE aggregator key invent two
    /// distinct operator names to fill both human slots — one key fabricating
    /// M-of-N. The aggregator's claim of distinct operators is unverifiable
    /// regardless of the optional self-approval policy, so ANY stamped recipe
    /// makes one key count once, regardless of the recipe's exact slot counts:
    /// the guard only ever rejects a SECOND same-key sign-off, and a single-slot
    /// recipe is already granted by the first (a second sign-off is superfluous),
    /// so activating for all recipes never wrongly blocks a legitimate grant.
    pub fn same_aggregator_key_guard_active(&self, _enforce_sod: bool) -> bool {
        self.approval_rule.is_some() || self.effective_required_approvals() > 1
    }

    /// Whether a sign-off with this `approve`/`class` CONTRIBUTES a positive slot
    /// toward the request's threshold — the exact unit the hard-SoD
    /// same-aggregator-key guard protects (Codex P2 RE-REVIEW-4). A DISSENT
    /// (approve=false) contributes nothing. Under a stamped recipe, a positive
    /// contributes only if its resolved class is named by SOME recipe term (a
    /// teammate positive on a `{senior:1}` rule fills no slot); with no recipe,
    /// every positive counts toward the numeric M-of-N.
    ///
    /// The guard rejects a new positive-contributing sign-off from an aggregator
    /// key that ALREADY holds a positive-contributing one — enforcing "one key
    /// contributes AT MOST one positive slot", NOT "one key may record only one
    /// verdict". The prior (RE-REVIEW-4 blocker) form keyed on ANY existing
    /// sign-off sharing the key, so a recorded majority-mode DISSENT — or a
    /// positive of a class the recipe does not use — poisoned the per-tenant key
    /// (Feir OS uses ONE vultrino key per tenant, not per human) into a permanent
    /// veto: a distinct real approver on the same key could never complete the
    /// recipe. Restricting BOTH the new and the existing sign-off to
    /// positive-and-contributing closes that without reopening same-key
    /// fabrication (two counting positives from one key still collide).
    pub fn contributes_positive_slot(&self, approve: bool, class: Option<ApproverClass>) -> bool {
        if !approve {
            return false;
        }
        match &self.approval_rule {
            None => true, // numeric M-of-N: every positive is a vote
            Some(rule) => match class {
                // Uses class_fills_a_slot — the SAME hierarchy + satisfiability logic
                // recipe_satisfied counts by — so a Senior on a `{teammate:N}` recipe
                // is (correctly) contributing (senior ⊇ teammate) and cannot slip the
                // guard, while a positive toward an unsatisfiable branch is not
                // (Codex RE-REVIEW-5). A bare `.class == term.class` scan here was the
                // fabrication/over-rejection bug.
                Some(c) => rule.recipes.iter().any(|r| class_fills_a_slot(r, c)),
                None => false, // unresolved class fills no recipe slot
            },
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
    /// grant has gone stale — i.e. more than its effective execute-by window elapsed
    /// since the decision — and so must be re-approved before it may execute. `false`
    /// when the grant is fresh, already executed, or not approved.
    ///
    /// The effective window is the configured `reauth_interval_secs` when set to a
    /// positive value, otherwise [`DEFAULT_UNRUN_GRANT_WINDOW_SECS`]. Bounding the
    /// unset case matters because an `Approved` request is not `is_open()`, so
    /// `advance_lifecycle`'s `expires_at` guard never re-fires once approved — this is
    /// the sole bound on an approved-but-unrun grant, and an unbounded one would stay
    /// executable forever. A stored `Some(0)` (e.g. a pre-fix vault record) is treated
    /// as "disabled" and likewise falls back to the default, so it can never render a
    /// grant stale ~1s after approval.
    pub fn needs_reauth(&self) -> bool {
        if self.status != ApprovalStatus::Approved || self.executed {
            return false;
        }
        let Some(decided_at) = self.decided_at else {
            return false;
        };
        let window = self
            .reauth_interval_secs
            .filter(|&s| s > 0)
            .unwrap_or(DEFAULT_UNRUN_GRANT_WINDOW_SECS);
        (Utc::now() - decided_at).num_seconds() > window as i64
    }

    /// A delegate approval is intentionally non-executable until the delegator's
    /// veto interval elapses.
    pub fn veto_pending(&self) -> bool {
        self.status == ApprovalStatus::Approved
            && !self.executed
            && self
                .delegate_veto_until
                .map(|t| Utc::now() < t)
                .unwrap_or(false)
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
            approve_url: format!(
                "{}/approvals/{}/decide?token={}&decision=approve",
                base, self.id, enc
            ),
            deny_url: format!(
                "{}/approvals/{}/decide?token={}&decision=deny",
                base, self.id, enc
            ),
            panel_url: format!("{}/approvals", base),
        }
    }
}

// ==================== Approval-recipe in-lock evaluator (plan 100 P2 Phase D) ====

/// Evaluate whether `rule` is satisfied by the accumulated `signoffs` — vultrino's
/// RACE-SAFE, in-lock RUNTIME evaluator (called from `ApprovalRequest::transition`,
/// which always runs under the storage write lock — see `storage/file.rs`'s
/// `decide_approval_atomic`/`locked_mutate`). Mirrors govder's
/// `internal/oversight/recipes.go` `evaluateApprovalRule`/`recipeSatisfied` for the
/// axes vultrino can evaluate WITHOUT a govder store round-trip:
///
/// - positive-only (a deny/dissent sign-off never counts toward a recipe — the
///   deny-wins / dissent-recorded split happens in `transition()` before this is
///   ever called for the approval path);
/// - D4(b) distinct-principal dedupe;
/// - D4(f) agent-reviewer controller-domain collapse;
/// - D2 injective senior-first slot matching (`recipe_satisfied`).
///
/// It deliberately does **NOT** re-derive: the D2 risk-tier floor (govder validates
/// this at write time AND at its own terminal re-validation — re-deriving it here
/// would risk Rust/Go drift), D4(c) the per-sign-off grant-floor recheck (needs
/// govder's `EvaluateDecision`; the delegate-decide path already consults it
/// per-signoff, see `web/api.rs::api_delegate_decide_approval`), D4(d) pairwise-
/// lineage-unrelatedness, or D4(e) requester exclusion (both need govder's agent-
/// hierarchy store, which vultrino does not have). Those three axes stay govder's
/// job at write time and terminal re-validation (docs/design/approval-recipes.md §6
/// D5) — a divergence from the ORIGINAL Phase-C/D design sketch (which had asked for
/// D4(d) in-lock too), recorded here explicitly rather than silently narrowed.
///
/// A malformed sign-off (blank identity, an unresolved/unknown class, an
/// agent-reviewer with no grant ref, or a kind/class mismatch) is silently dropped —
/// never counted, never erroring the whole evaluation (fail-closed per-entry, mirrors
/// govder's `classifySignOffs`). A structurally malformed recipe (no terms, a
/// non-positive count, or an unknown class) is permanently disqualified — skipped,
/// per `recipeComposition`. If every recipe is disqualified this way, the rule can
/// never be satisfied (fail-closed): the request simply stays open, never auto-denied
/// (deny-wins already handles denial separately in `transition()`).
fn approval_rule_satisfied(rule: &ApprovalRule, signoffs: &[Signoff]) -> bool {
    let mut humans: Vec<&Signoff> = Vec::new();
    let mut agent_reviewers: Vec<&Signoff> = Vec::new();
    for so in signoffs.iter().filter(|s| s.approve) {
        // Stage 1 V4. This guard MUST read the same function the D4(b)
        // distinctness key reads (`bare_approver_identity`), because those two are
        // the pair that decides *what a principal is* and they must never hold
        // different opinions.
        //
        // It used to test the FULL namespaced identity. That let
        // `agg:<key-id>:` with an EMPTY operator through — non-empty as a whole
        // string, so it survived the drop — and `dedupe_by_identity` then filed it
        // under the bare key `""`, so an UNNAMED principal filled a recipe slot.
        // That is a direct obligation-X (non-substitution) violation. No shipped
        // entry point produces the shape (`web/api.rs` substitutes
        // `NO_OPERATOR_SENTINEL`, the panel uses the session user, the OOB link
        // filters non-empty, the CLI stamps `cli:<user>`), but `Signoff`
        // deserializes from the vault with no identity validation at all, so it is
        // reachable across the persistence boundary — and "unreachable by
        // convention in four places" is exactly the reasoning this codebase has
        // measured to be wrong.
        //
        // Strictly fail-closed: it can only drop MORE sign-offs than before, never
        // fewer, so it can never newly satisfy a recipe. See
        // `stage1_proofs::an_unnamed_principal_fills_no_slot` and
        // `the_drop_and_the_distinctness_key_agree_about_what_a_principal_is`.
        if bare_approver_identity(&so.approver_identity)
            .trim()
            .is_empty()
        {
            continue; // malformed / unnamed: fail-closed, drop
        }
        let Some(class) = so.resolved_class else {
            continue; // unresolved class: never counted (fail-closed)
        };
        // Kind/Class cross-check (defense in depth), mirrors govder's
        // classifySignOffs: a "human" Kind must resolve to senior/teammate and a
        // "delegate-agent" Kind must resolve to agent-reviewer; a mismatch is
        // malformed and dropped. An EXPLICIT, non-empty, unrecognized Kind is ALSO
        // dropped (Codex P2 review MINOR): the previous wildcard silently accepted
        // it, more permissive than govder — which only ever classifies
        // human/delegate-agent. A genuinely EMPTY/blank stored Kind is now ALSO
        // DROPPED (Codex P2 RE-REVIEW MINOR), matching govder's recipes.go which
        // drops an empty `approver_kind` during recipe evaluation — closing the
        // old/corrupt-record divergence. Normal new decisions default to "human"
        // via `default_approver_kind`, so this only affects malformed/legacy records.
        match so.approver_kind.trim() {
            "human" if !class.is_human() => continue,
            "delegate-agent" if class != ApproverClass::AgentReviewer => continue,
            "human" | "delegate-agent" => {}
            _ => continue, // empty/blank OR explicit unknown Kind: fail-closed, drop
        }
        match class {
            ApproverClass::Senior | ApproverClass::Teammate => humans.push(so),
            ApproverClass::AgentReviewer => {
                let has_grant_ref = so
                    .delegation_grant_ref
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !has_grant_ref {
                    continue; // agent-reviewer sign-off with no grant ref: malformed, drop
                }
                agent_reviewers.push(so);
            }
            ApproverClass::Unknown => continue,
        }
    }

    // D4(b) distinct principals: dedupe by identity, first occurrence wins.
    let humans = dedupe_by_identity(humans);
    let agent_reviewers = dedupe_by_identity(agent_reviewers);

    // D4(f) controller-domain collapse (agent-reviewers only). NOTE: this does NOT
    // also fold in govder's D4(d) pairwise-lineage-unrelatedness (see this
    // function's doc) — that axis needs govder's agent-hierarchy store.
    let agent_reviewers = collapse_by_controller(agent_reviewers);

    let avail_senior = humans
        .iter()
        .filter(|s| s.resolved_class == Some(ApproverClass::Senior))
        .count() as u32;
    let avail_teammate = humans
        .iter()
        .filter(|s| s.resolved_class == Some(ApproverClass::Teammate))
        .count() as u32;
    let avail_agent_reviewer = agent_reviewers.len() as u32;

    rule.recipes
        .iter()
        .any(|r| recipe_satisfied(r, avail_senior, avail_teammate, avail_agent_reviewer))
}

/// Whether a govder-AUTHORITATIVE `risk_tier` wire value forces `deny-on-any-deny`
/// regardless of an org's `majority-with-dissent-recorded` opt-in (Codex P2 review
/// BLOCKER 5). `Low`/`Medium`/`High` do NOT force — majority mode is a legitimate
/// per-org relaxation below Extreme (approval-recipes.md §5 D4(a)), mirroring govder's
/// `forceDenyOnAnyDeny := irreversible || riskTier == Extreme`. `Extreme` forces; `""`
/// (govder could not resolve) or ANY unparseable value → treated as Extreme
/// (fail-closed).
fn risk_tier_forces_deny_on_any_deny(risk_tier: &str) -> bool {
    !matches!(risk_tier.trim(), "Low" | "Medium" | "High")
}

/// Cross-plane cap on any single [`RecipeTerm::count`] AND the summed total per recipe
/// (Codex P2 review BLOCKER 3; mirrors govder's `maxRecipeTermCount`). A stamped rule
/// with a huge or repeated `count` must never wrap the `u32` slot-need sum to a small
/// value and clear with fewer approvers — a recipe breaching this cap is treated as
/// permanently UNSATISFIABLE (fail-closed). 64 is far above any legitimate recipe (the
/// realistic ceiling is single digits) and leaves no path to `u32` overflow, since
/// [`recipe_well_formed`] rejects the recipe the moment a running sum would exceed it.
const MAX_RECIPE_TERM_COUNT: u32 = 64;

/// Injective senior-first slot matching (mirrors govder's `recipeSatisfied` exactly).
/// Senior slots are filled by senior sign-offs first; any senior LEFT OVER after that
/// may fill a teammate slot (a senior is a fortiori a teammate); agent-reviewer slots
/// are filled only by agent-reviewer sign-offs (disjoint from both human classes).
/// Greedy senior-first assignment is provably sufficient for this two-human-class
/// system — see approval-recipes.md §2 for the swap argument (a senior placed in a
/// teammate slot while a senior slot goes unfilled can always be swapped with a plain
/// teammate, so greedy never fails where a matching exists). A structurally malformed
/// recipe (see [`recipe_well_formed`]) can never be satisfied.
fn recipe_satisfied(
    r: &Recipe,
    avail_senior: u32,
    avail_teammate: u32,
    avail_agent_reviewer: u32,
) -> bool {
    // Shared need computation (recipe_needs) so this and class_fills_a_slot — the
    // hard-SoD same-key contribution check — can NEVER diverge on well-formedness or
    // the senior⊇teammate hierarchy (that drift is what let Codex RE-REVIEW-5's
    // senior-fills-teammate fabrication through when the guard hand-rolled its own,
    // exact-match contribution rule).
    let Some((need_senior, need_teammate, need_agent_reviewer)) = recipe_needs(r) else {
        return false; // malformed / unknown class: never satisfiable
    };
    // Agent-reviewer recipe terms are disabled system-wide (Codex P2 review finding 6;
    // mirrors govder's `recipeSatisfied` hard guard). govder rejects agent-reviewer
    // terms at WRITE time, so a fetched rule should only ever contain {senior,
    // teammate} — but if a hand-crafted or stale rule somehow arrives, a recipe
    // REQUIRING an agent-reviewer term is UNSATISFIABLE here too (never clears via
    // agents), regardless of how many agent-reviewer sign-offs were collected.
    if need_agent_reviewer > 0 {
        return false;
    }
    if avail_senior < need_senior {
        return false; // senior slots can ONLY be filled by seniors
    }
    let leftover_senior = avail_senior - need_senior;
    if leftover_senior.saturating_add(avail_teammate) < need_teammate {
        return false;
    }
    // Moot past the hard guard above (`need_agent_reviewer == 0`), kept for signature
    // parity with govder's `recipeSatisfied` and the collect machinery.
    avail_agent_reviewer >= need_agent_reviewer
}

/// The `(senior, teammate, agent-reviewer)` slot counts a WELL-FORMED recipe requires,
/// or `None` if the recipe is structurally malformed (per [`recipe_well_formed`], incl.
/// an unknown class) and thus never satisfiable. Extracted so [`recipe_satisfied`] and
/// [`class_fills_a_slot`] share ONE source of truth for well-formedness + the need
/// totals — they must never disagree about which recipes/slots are real (Codex
/// RE-REVIEW-5). Saturating arithmetic mirrors the BLOCKER-3 overflow guard.
fn recipe_needs(r: &Recipe) -> Option<(u32, u32, u32)> {
    if !recipe_well_formed(r) {
        return None;
    }
    let (mut need_senior, mut need_teammate, mut need_agent_reviewer) = (0u32, 0u32, 0u32);
    for t in &r.terms {
        match t.class {
            ApproverClass::Senior => need_senior = need_senior.saturating_add(t.count),
            ApproverClass::Teammate => need_teammate = need_teammate.saturating_add(t.count),
            ApproverClass::AgentReviewer => {
                need_agent_reviewer = need_agent_reviewer.saturating_add(t.count)
            }
            ApproverClass::Unknown => return None, // recipe_well_formed already excludes this
        }
    }
    Some((need_senior, need_teammate, need_agent_reviewer))
}

/// Whether a POSITIVE sign-off of `class` can fill a slot in recipe `r`, using the
/// EXACT rules [`recipe_satisfied`] counts by (Codex RE-REVIEW-5). This is the unit the
/// hard-SoD same-aggregator-key guard protects, so it MUST agree with satisfaction:
///   * the recipe must be satisfiable-in-principle — well-formed AND requiring no
///     agent-reviewer term (those are disabled, so such a branch clears via NO one and
///     fills no VIABLE slot — a positive toward it must not poison the key, RE-REVIEW-5
///     Blocker 2);
///   * a Senior may fill a senior OR a teammate slot (senior ⊇ teammate — the hierarchy
///     recipe_satisfied's leftover-senior rule encodes; missing this let a Senior look
///     "non-contributing" on `{teammate:N}` and slip the guard, RE-REVIEW-5 Blocker 1);
///   * a Teammate fills only a teammate slot; agent-reviewer / unknown fill none.
fn class_fills_a_slot(r: &Recipe, class: ApproverClass) -> bool {
    let Some((need_senior, need_teammate, need_agent_reviewer)) = recipe_needs(r) else {
        return false;
    };
    if need_agent_reviewer > 0 {
        return false; // unsatisfiable branch (agent-reviewers disabled): no viable slot
    }
    match class {
        ApproverClass::Senior => need_senior > 0 || need_teammate > 0,
        ApproverClass::Teammate => need_teammate > 0,
        ApproverClass::AgentReviewer | ApproverClass::Unknown => false,
    }
}

/// Structural well-formedness (mirrors govder's `recipeComposition`'s `ok` return): a
/// recipe with no terms, any non-positive OR over-cap count, a summed total exceeding
/// [`MAX_RECIPE_TERM_COUNT`], or any unknown class can never be satisfied — permanently
/// disqualified rather than erroring the whole rule. The per-term AND running-total
/// caps are the BLOCKER-3 overflow guard: they reject a malformed rule long before any
/// `u32` slot-need sum could wrap (agent-reviewer terms remain structurally valid here,
/// exactly as in govder — [`recipe_satisfied`]'s hard guard is what makes them
/// unsatisfiable at eval time).
fn recipe_well_formed(r: &Recipe) -> bool {
    if r.terms.is_empty() {
        return false;
    }
    let mut total: u32 = 0;
    for t in &r.terms {
        // Per-term cap (BLOCKER 3): a count outside [1, MAX_RECIPE_TERM_COUNT] is
        // rejected outright — this is how a huge (or negative-after-wrap on the wire)
        // count would otherwise let a small sign-off set clear a recipe reading as
        // enormous on paper.
        if t.count == 0 || t.count > MAX_RECIPE_TERM_COUNT {
            return false;
        }
        // Running total, capped after every addition (BLOCKER 3): catches both a
        // single huge term and many small terms whose cumulative sum would exceed any
        // sane recipe, long before the sum could approach an overflow boundary.
        total = total.saturating_add(t.count);
        if total > MAX_RECIPE_TERM_COUNT {
            return false;
        }
        if !matches!(
            t.class,
            ApproverClass::Senior | ApproverClass::Teammate | ApproverClass::AgentReviewer
        ) {
            return false;
        }
    }
    true
}

/// Bounded model checks for the approval predicate itself.
///
/// These harnesses intentionally live beside the private production functions:
/// Kani therefore verifies the code that ships rather than a public test model.
/// Except for P3's explicitly bounded matching oracle, all counts and
/// availabilities are symbolic over the complete `u32` domain. The recipe has
/// three terms because Kani requires a concrete allocation shape; P5 separately
/// covers the empty shape, while the production predicate reduces every
/// non-empty shape to the same three need totals in `recipe_needs`.
#[cfg(kani)]
mod kani_recipe_proofs {
    use super::*;

    fn any_class() -> ApproverClass {
        match kani::any::<u8>() & 3 {
            0 => ApproverClass::Senior,
            1 => ApproverClass::Teammate,
            2 => ApproverClass::AgentReviewer,
            _ => ApproverClass::Unknown,
        }
    }

    fn any_recipe() -> Recipe {
        Recipe {
            terms: vec![
                RecipeTerm {
                    class: any_class(),
                    count: kani::any(),
                },
                RecipeTerm {
                    class: any_class(),
                    count: kani::any(),
                },
                RecipeTerm {
                    class: any_class(),
                    count: kani::any(),
                },
            ],
        }
    }

    /// P1: no non-empty recipe can clear without an approver.
    #[kani::proof]
    #[kani::unwind(4)]
    fn zero_approvers_never_satisfy() {
        let recipe = any_recipe();
        assert!(!recipe_satisfied(&recipe, 0, 0, 0));
    }

    /// P2: success implies every required slot was actually filled. Saturating
    /// arithmetic makes the assertion itself total at `u32::MAX`.
    #[kani::proof]
    #[kani::unwind(4)]
    fn satisfaction_never_underfills_a_slot() {
        let recipe = any_recipe();
        let avail_senior: u32 = kani::any();
        let avail_teammate: u32 = kani::any();
        let avail_agent: u32 = kani::any();

        if recipe_satisfied(&recipe, avail_senior, avail_teammate, avail_agent) {
            let (need_senior, need_teammate, need_agent) =
                recipe_needs(&recipe).expect("a satisfied recipe is well formed");
            assert_eq!(need_agent, 0);
            assert!(avail_senior >= need_senior);
            assert!(
                avail_senior
                    .saturating_sub(need_senior)
                    .saturating_add(avail_teammate)
                    >= need_teammate
            );
            assert!(avail_agent >= need_agent);
        }
    }

    /// Independent injective-assignment search for P3. `senior_to_teammate`
    /// is the only non-trivial matching choice in the two-class hierarchy.
    fn injective_match_exists_bound_5(
        need_senior: u32,
        need_teammate: u32,
        avail_senior: u32,
        avail_teammate: u32,
    ) -> bool {
        for senior_to_teammate in 0..=5u32 {
            if senior_to_teammate <= avail_senior
                && senior_to_teammate <= need_teammate
                && avail_senior - senior_to_teammate >= need_senior
                && avail_teammate >= need_teammate - senior_to_teammate
            {
                return true;
            }
        }
        false
    }

    /// P3: the production senior-first shortcut is equivalent to an exhaustive
    /// injective matching search for three symbolic human terms at bound five.
    #[kani::proof]
    #[kani::unwind(7)]
    fn greedy_matches_exhaustive_assignment_at_bound_5() {
        let mut terms = Vec::with_capacity(3);
        for _ in 0..3 {
            let class = if kani::any::<bool>() {
                ApproverClass::Senior
            } else {
                ApproverClass::Teammate
            };
            let count: u32 = kani::any();
            kani::assume((1..=5).contains(&count));
            terms.push(RecipeTerm { class, count });
        }
        let recipe = Recipe { terms };
        let avail_senior: u32 = kani::any();
        let avail_teammate: u32 = kani::any();
        kani::assume(avail_senior <= 5 && avail_teammate <= 5);

        let (need_senior, need_teammate, need_agent) =
            recipe_needs(&recipe).expect("bounded human recipe is well formed");
        assert_eq!(need_agent, 0);
        assert_eq!(
            recipe_satisfied(&recipe, avail_senior, avail_teammate, 0),
            injective_match_exists_bound_5(
                need_senior,
                need_teammate,
                avail_senior,
                avail_teammate,
            )
        );
    }

    /// P4: increasing any availability cannot turn an approval into a denial,
    /// including at the integer boundary.
    #[kani::proof]
    #[kani::unwind(4)]
    fn satisfaction_is_monotone_in_availability() {
        let recipe = any_recipe();
        let senior: u32 = kani::any();
        let teammate: u32 = kani::any();
        let agent: u32 = kani::any();
        let more_senior: u32 = kani::any();
        let more_teammate: u32 = kani::any();
        let more_agent: u32 = kani::any();

        if recipe_satisfied(&recipe, senior, teammate, agent) {
            assert!(recipe_satisfied(
                &recipe,
                senior.saturating_add(more_senior),
                teammate.saturating_add(more_teammate),
                agent.saturating_add(more_agent),
            ));
        }
    }

    /// P5: each structural malformation is permanently unsatisfiable, even
    /// with maximum apparent availability.
    #[kani::proof]
    #[kani::unwind(7)]
    fn malformed_recipes_never_satisfy() {
        let class = any_class();
        let over_cap: u32 = kani::any();
        kani::assume(over_cap > MAX_RECIPE_TERM_COUNT);
        let first: u32 = kani::any();
        let second: u32 = kani::any();
        kani::assume(
            first > 0
                && first <= MAX_RECIPE_TERM_COUNT
                && second > 0
                && second <= MAX_RECIPE_TERM_COUNT
                && first.saturating_add(second) > MAX_RECIPE_TERM_COUNT,
        );

        let malformed = [
            Recipe { terms: vec![] },
            Recipe {
                terms: vec![RecipeTerm { class, count: 0 }],
            },
            Recipe {
                terms: vec![RecipeTerm {
                    class,
                    count: over_cap,
                }],
            },
            Recipe {
                terms: vec![
                    RecipeTerm {
                        class: ApproverClass::Senior,
                        count: first,
                    },
                    RecipeTerm {
                        class: ApproverClass::Teammate,
                        count: second,
                    },
                ],
            },
            Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Unknown,
                    count: 1,
                }],
            },
        ];

        for recipe in malformed {
            assert!(!recipe_well_formed(&recipe));
            assert!(!recipe_satisfied(&recipe, u32::MAX, u32::MAX, u32::MAX,));
        }
    }

    /// P6: well-formedness makes the need sum finite and all additions
    /// representable; this is the premise that makes the real-cap exhaustive
    /// sweep in `stage1_proofs` complete.
    #[kani::proof]
    #[kani::unwind(4)]
    fn recipe_cap_prevents_need_overflow() {
        let recipe = any_recipe();
        if recipe_well_formed(&recipe) {
            let (senior, teammate, agent) =
                recipe_needs(&recipe).expect("well-formed recipe has needs");
            let total = senior
                .checked_add(teammate)
                .and_then(|n| n.checked_add(agent));
            assert!(matches!(total, Some(n) if n <= MAX_RECIPE_TERM_COUNT));
        }
    }

    /// P7: the same production need decomposition drives both satisfaction and
    /// the same-controller contribution guard. Adding a class that cannot fill
    /// a viable slot must never be the step that clears a recipe.
    #[kani::proof]
    #[kani::unwind(4)]
    fn class_slot_contribution_agrees_with_satisfaction() {
        let recipe = any_recipe();
        let class = any_class();
        let senior: u32 = kani::any();
        let teammate: u32 = kani::any();
        let agent: u32 = kani::any();
        let before = recipe_satisfied(&recipe, senior, teammate, agent);
        let after = match class {
            ApproverClass::Senior => {
                recipe_satisfied(&recipe, senior.saturating_add(1), teammate, agent)
            }
            ApproverClass::Teammate => {
                recipe_satisfied(&recipe, senior, teammate.saturating_add(1), agent)
            }
            ApproverClass::AgentReviewer => {
                recipe_satisfied(&recipe, senior, teammate, agent.saturating_add(1))
            }
            ApproverClass::Unknown => before,
        };

        if !before && after {
            assert!(class_fills_a_slot(&recipe, class));
        }
        if !class_fills_a_slot(&recipe, class) {
            assert!(!after || before);
        }
    }
}

/// D4(b) distinct principals: keep the FIRST occurrence per distinct identity
/// (trimmed comparison — mirrors govder's `dedupeByIdentity`).
///
/// Recipe-slot distinctness keys on the BARE immutable subject, NOT the full
/// `agg:<key-id>:<subject>` wrapper vultrino stamps on aggregator-asserted identities
/// (Codex P2 RE-REVIEW RE-BLOCKER 1). vultrino rewrites the broker's immutable subject
/// into `agg:<api-key-id>:<subject>` at `web/api.rs`; comparing the FULL namespaced
/// value would let ONE OIDC subject fill TWO recipe slots when signed through two
/// different broker/admin keys (key rotation or an HA broker) — `agg:A:sub-alice` and
/// `agg:B:sub-alice` reading as distinct principals, so one person could clear a
/// `{teammate:2}` recipe. Stripping to the bare subject via `bare_approver_identity`
/// collapses those to ONE slot regardless of which key routed the sign-off. The
/// dedupe key is also ASCII-case-folded: the aggregator only `trim()`s the asserted
/// operator string before embedding it, never case-normalizes it, so
/// `agg:A:Alice@corp.com` and `agg:B:alice@corp.com` must still collapse to one
/// principal — matching the `eq_ignore_ascii_case` convention already used by the
/// sibling `DuplicateApprover` guard (`transition()`) and `sod_for`. `to_ascii_lowercase`
/// (not Unicode `to_lowercase`) is used deliberately, for parity with that same
/// `eq_ignore_ascii_case` semantics. This does NOT touch the aggregator-SoD `agg:`
/// scheme itself (the `SameAggregatorKey` / `DuplicateApprover` checks in
/// `transition`) — only the recipe-satisfaction dedupe.
fn dedupe_by_identity(signoffs: Vec<&Signoff>) -> Vec<&Signoff> {
    let mut seen = std::collections::HashSet::new();
    signoffs
        .into_iter()
        .filter(|s| {
            seen.insert(
                bare_approver_identity(&s.approver_identity)
                    .trim()
                    .to_ascii_lowercase(),
            )
        })
        .collect()
}

/// D4(f) controller-domain collapse ONLY — not the joint D4(d) lineage collapse
/// govder also performs (that needs govder's agent-hierarchy store; see
/// [`approval_rule_satisfied`]'s doc for why that axis stays govder's job). Agent-
/// reviewer sign-offs sharing a controller collapse to the FIRST representative; an
/// empty/unresolved controller joins a single sentinel domain, so unknowns collapse
/// together rather than each counting (fail-closed) — mirrors govder's
/// `collapseAgentReviewers`'s `controllerKey` helper.
fn collapse_by_controller(agent_reviewers: Vec<&Signoff>) -> Vec<&Signoff> {
    const UNKNOWN_CONTROLLER: &str = "\u{0}unknown-controller";
    let mut seen = std::collections::HashSet::new();
    agent_reviewers
        .into_iter()
        .filter(|s| {
            let key = s
                .controller
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .unwrap_or(UNKNOWN_CONTROLLER)
                .to_string();
            seen.insert(key)
        })
        .collect()
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
///
/// Public so the outbox/webhook payload builder (`storage/file.rs`) can emit each
/// sign-off's BARE subject — govder's terminal backstop must re-validate recipe
/// distinctness on the immutable subject, not vultrino's per-key `agg:` wrapper
/// (Codex P2 RE-REVIEW RE-BLOCKER 1 / payload item).
pub fn bare_approver_identity(identity: &str) -> &str {
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

    /// Clamp the two SLA windows so an approval's FINAL DEADLINE can never outlive
    /// the credential that would execute it (plan 103 §10h FINDING 4).
    ///
    /// The measured defect: `approvals.ttl_secs` defaults to 3600s while govder
    /// compiles an L3·High use token with a **900s** TTL, so vultrino offered an
    /// approval for four times as long as the credential could honour it. A human
    /// who decided inside the advertised window got `Approved` recorded and the
    /// action refused at resume with `use token has expired` — an approver signing
    /// an irreversible money action that then never ran.
    ///
    /// `credential_remaining` is the time left on the use token driving the request:
    /// * `None` — the request is not use-token-driven (a local/API-key caller), or
    ///   the token carries no expiry (`max_uses` alone bounds it). There is no
    ///   credential deadline to clamp against, so the configured SLA stands.
    /// * `Some(d)` — the deadline. The returned windows always sum to `min(total, d)`.
    ///
    /// Returns `None` when the credential is ALREADY dead (or dies inside the same
    /// second): the caller must then REFUSE to open the approval rather than create
    /// one no approver could ever make good on. That is fail-closed in both
    /// directions — nothing executes, and no human is invited to authorize something
    /// that cannot run.
    ///
    /// Both phases are scaled by `remaining / total` rather than truncating the
    /// second window, so a clamped request keeps its two-phase escalate-then-expire
    /// shape (a High request clamped from 900+900 to 900 total escalates at 450s)
    /// instead of degenerating into "escalates exactly when it expires".
    pub fn clamped_to_credential(
        &self,
        credential_remaining: Option<chrono::Duration>,
    ) -> Option<(chrono::Duration, chrono::Duration)> {
        let after = self.escalate_after();
        let window = self.escalate_window();
        let remaining = match credential_remaining {
            None => return Some((after, window)),
            Some(r) => r,
        };
        // Whole seconds only: `open()` stamps `expires_at` from these durations and
        // a sub-second remainder is not a window any human can decide inside, so it
        // is treated as "already dead" (refuse) rather than rounded up into one.
        let rem_secs = remaining.num_seconds();
        if rem_secs <= 0 {
            return None;
        }
        let total_secs = (after + window).num_seconds().max(1);
        if total_secs <= rem_secs {
            return Some((after, window));
        }
        // i128 so the product cannot overflow for any credential TTL an operator
        // can express.
        let scaled_after =
            (after.num_seconds() as i128 * rem_secs as i128 / total_secs as i128) as i64;
        let after_secs = scaled_after.clamp(0, rem_secs);
        Some((
            chrono::Duration::seconds(after_secs),
            chrono::Duration::seconds(rem_secs - after_secs),
        ))
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
    /// The startup warning to print when approvals are DISABLED, or `None` when they
    /// are on.
    ///
    /// Why a startup warning exists at all (feir-os plan 103 §10h FINDING 6a). `enabled =
    /// false` is fail-closed but it does NOT mean "hold for a human" — it means an action
    /// the compiled policy marks `require_approval` is **refused outright** at execute.
    /// Nothing upstream inspects the flag: measured on a live single-host stack, an org
    /// pack applied with exit 0, its status read IN SYNC across all 44 declared items, the
    /// product's approvals inbox rendered, and the first refund an agent requested came
    /// back `400 … approvals are not enabled on this Vultrino instance`. So the only place
    /// this is knowable before an agent acts is here, at startup.
    ///
    /// It is deliberately a WARNING and not a startup refusal: a deployment with no
    /// human-gated action is a legitimate configuration, and refusing to boot would break
    /// every such deployment to fix a documentation problem.
    pub fn startup_warning(&self) -> Option<String> {
        if self.enabled {
            return None;
        }
        Some(
            "[approvals] enabled is FALSE (the default). Actions whose policy requires human \
             approval will be REFUSED at execute, not held for a human: \
             `400 Request denied by policy: This action requires human approval, but approvals \
             are not enabled on this Vultrino instance`. Nothing upstream reports this, so an \
             org pack can apply cleanly and then fail on its first gated action. Set \
             `[approvals] enabled = true` if any agent on this deployment needs a human."
                .to_string(),
        )
    }

    /// Effective default TTL as a `chrono::Duration`. `ttl_secs == 0` is treated
    /// as the sentinel for "use the default of 1 hour" (a zero-TTL approval would
    /// expire before anyone could decide).
    pub fn ttl(&self) -> chrono::Duration {
        let secs = if self.ttl_secs == 0 {
            3600
        } else {
            self.ttl_secs
        };
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
                let total = if self.ttl_secs == 0 {
                    3600
                } else {
                    self.ttl_secs.max(2)
                };
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
        self.sla_overrides
            .get(&class)
            .copied()
            .unwrap_or_else(|| self.default_sla(class))
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
    async fn notify(
        &self,
        approval: &ApprovalRequest,
        links: &ApprovalLinks,
    ) -> Result<(), NotifyError>;
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
        // Bound both connect and total time: a stalled Telegram/webhook endpoint
        // must never hang an approval-decision notification. This client never
        // streams. (timeouts, ported from fix/agent-boundary-hardening.)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
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

    async fn notify(
        &self,
        approval: &ApprovalRequest,
        links: &ApprovalLinks,
    ) -> Result<(), NotifyError> {
        let api = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );

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

    async fn notify(
        &self,
        approval: &ApprovalRequest,
        links: &ApprovalLinks,
    ) -> Result<(), NotifyError> {
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
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Cross-plane conformance vectors for approval-recipe satisfaction, shared
/// byte-identically with `govder/internal/oversight` (see that file's header).
/// Test-only: this declaration compiles to nothing outside `cargo test`.
#[cfg(test)]
mod recipe_conformance;

#[cfg(test)]
mod stage1_proofs;

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
            preview: None,
            action_label: None,
            dual_control: false,
            criticality: CriticalityClass::Medium,
            trusted_irreversible: None,
            escalate_after: chrono::Duration::minutes(30),
            escalate_window: chrono::Duration::minutes(30),
            oob_identity: None,
            reauth_interval_secs: None,
            required_approvals: 1,
            approval_rule: None,
        })
    }

    /// Build a request with a stamped `ApprovalRule` (plan 100 P2 Phase D tests).
    fn new_approval_with_rule(rule: ApprovalRule) -> ApprovalRequest {
        let (mut a, _) = new_approval();
        a.approval_rule = Some(rule);
        a
    }

    /// A one-recipe rule requiring `1 senior + 2 agent-reviewer` sign-offs.
    fn senior_plus_two_reviewers_rule() -> ApprovalRule {
        ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![
                    RecipeTerm {
                        class: ApproverClass::Senior,
                        count: 1,
                    },
                    RecipeTerm {
                        class: ApproverClass::AgentReviewer,
                        count: 2,
                    },
                ],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        }
    }

    fn approve_as(
        a: &mut ApprovalRequest,
        identity: &str,
        class: ApproverClass,
        controller: Option<&str>,
        grant_ref: Option<&str>,
    ) -> Result<(), ApprovalError> {
        let kind = if class == ApproverClass::AgentReviewer {
            "delegate-agent"
        } else {
            "human"
        };
        let mut decision = Decision::new("admin panel", identity).with_resolved_class(class);
        decision.approver_kind = kind.to_string();
        if let Some(c) = controller {
            decision = decision.with_controller(c);
        }
        if let Some(g) = grant_ref {
            decision.delegation_grant_ref = Some(g.to_string());
        }
        a.approve(decision)
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
    fn delegate_veto_window_defers_execution_and_allows_human_veto() {
        let (mut approval, _) = new_approval();
        approval.delegate_veto_until = Some(Utc::now() + chrono::Duration::minutes(5));
        approval
            .approve(Decision::new("delegate-agent", "ep_delegate").as_delegate("dg_1"))
            .unwrap();
        assert!(approval.veto_pending());
        approval
            .deny(Decision::new("admin panel", "human@example.com"))
            .unwrap();
        assert_eq!(approval.status, ApprovalStatus::Denied);
        assert!(!approval.veto_pending());
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
        assert!(matches!(
            err,
            ApprovalError::AlreadyDecided(ApprovalStatus::Approved)
        ));
    }

    #[test]
    fn test_expired_cannot_be_approved() {
        let (mut a, _) = new_approval();
        a.expires_at = Utc::now() - chrono::Duration::minutes(1);
        let err = a
            .approve(Decision::new("admin panel", "alice"))
            .unwrap_err();
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
        let err = a
            .approve(Decision::new("admin panel", "ALICE"))
            .unwrap_err();
        assert!(matches!(err, ApprovalError::DuplicateApprover));
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "duplicate doesn't advance"
        );
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
        assert_eq!(
            restored.required_approvals, 1,
            "serde default for the absent field"
        );
        assert_eq!(
            restored.effective_required_approvals(),
            2,
            "dual_control forces >= 2"
        );

        // A single approval does NOT grant it.
        let mut r = restored;
        r.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(
            r.status,
            ApprovalStatus::Pending,
            "single approval must not grant dual control"
        );
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
        assert_eq!(
            a.sod_violation,
            Some(true),
            "deny SoD must be sticky-true over a prior false"
        );
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
        a.approve(Decision::new("admin panel", "alice").enforcing_sod(true))
            .unwrap();
        a.approve(Decision::new("admin panel", "bob").enforcing_sod(true))
            .unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_aggregator_identity_helpers() {
        // Bare identity passes through unchanged.
        assert_eq!(
            bare_approver_identity("alice@example.com"),
            "alice@example.com"
        );
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
        assert_eq!(
            bare_approver_identity("agg:no-second-colon"),
            "agg:no-second-colon"
        );
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
        assert_eq!(
            b.status,
            ApprovalStatus::Pending,
            "self-approval not recorded"
        );

        // A genuinely DIFFERENT operator on the aggregator surface is clean.
        let (mut c, _) = new_approval();
        c.requester.owner = Some("alice@example.com".to_string());
        c.approve(Decision::new("json-api", "agg:key-123:bob@example.com").enforcing_sod(true))
            .unwrap();
        assert_eq!(
            c.sod_violation,
            Some(false),
            "distinct operator satisfies SoD"
        );
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
        assert_eq!(
            a.signoffs.len(),
            1,
            "the same-key second sign-off was not recorded"
        );
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
        a.approve(Decision::new("admin panel", "ALICE@example.com"))
            .unwrap();
        assert_eq!(
            a.violates_sod(),
            Some(true),
            "approver == bound owner → SoD violation"
        );

        // SoD checks ALL the agent's identities: approving under the agent's own
        // name (not the owner) is still a self-approval.
        let (mut b, _) = new_approval(); // principal_name "agent"
        b.requester.owner = Some("alice@example.com".to_string());
        b.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(
            b.violates_sod(),
            Some(true),
            "self-approval under any identity is flagged"
        );

        // A genuinely distinct approver (neither the owner nor the agent) is clean.
        let (mut c, _) = new_approval();
        c.requester.owner = Some("alice@example.com".to_string());
        c.approve(Decision::new("admin panel", "secops-oncall"))
            .unwrap();
        assert_eq!(
            c.violates_sod(),
            Some(false),
            "distinct approver satisfies SoD"
        );

        // A blank owner must NOT poison the result to not-computable — SoD falls
        // through to the agent's other identities (the old `.or()` chain bug).
        let (mut d, _) = new_approval(); // principal_name "agent"
        d.requester.owner = Some("   ".to_string());
        d.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(
            d.violates_sod(),
            Some(true),
            "blank owner doesn't poison SoD to None"
        );
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
        b.deny(Decision::new("admin panel", "secops-oncall"))
            .unwrap();
        assert_eq!(b.violates_sod(), Some(false));
    }

    #[test]
    fn test_sod_recorded_always_and_enforced_when_configured() {
        // Recorded but allowed by default.
        let (mut a, _) = new_approval();
        a.approve(Decision::new("admin panel", "agent")).unwrap();
        assert_eq!(a.sod_violation, Some(true));
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "allowed when not enforcing"
        );

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
        b.approve(Decision::new("admin panel", "secops").enforcing_sod(true))
            .unwrap();
        assert_eq!(b.status, ApprovalStatus::Approved);
        assert_eq!(b.sod_violation, Some(false));

        // A self-*denial* is harmless and is never blocked, even when enforcing.
        let (mut c, _) = new_approval();
        c.deny(Decision::new("admin panel", "agent").enforcing_sod(true))
            .unwrap();
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
        assert_eq!(
            a.decided_by.as_deref(),
            Some("admin panel"),
            "channel preserved"
        );
        assert_eq!(
            a.approver_identity.as_deref(),
            Some("alice"),
            "approver preserved"
        );
        assert_eq!(a.decided_at, decided_at, "decision time preserved");
        let note = a.decision_note.as_deref().unwrap();
        assert!(note.contains("ok by me"), "original note kept: {note}");
        assert!(note.contains("re-authorization"), "lapse appended: {note}");

        // No prior note → just the lapse reason (the default arm).
        let (mut b, _) = new_approval();
        b.approve(Decision::new("admin panel", "bob")).unwrap();
        b.expire_reauth_lapsed();
        assert_eq!(
            b.decision_note.as_deref(),
            Some("re-authorization window lapsed before execution")
        );
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
    fn test_needs_reauth_bounds_unrun_grant_without_interval() {
        // With NO configured interval, an approved-but-unrun grant is still bounded
        // by the default execute-by window — otherwise it stays runnable forever
        // (Approved is not is_open(), so expires_at stops firing once approved).
        let (mut a, _) = new_approval();
        a.reauth_interval_secs = None;
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        // Fresh, well within the window → still runnable.
        assert!(!a.needs_reauth());
        // Just inside the default window → still runnable.
        a.decided_at = Some(
            Utc::now() - chrono::Duration::seconds(DEFAULT_UNRUN_GRANT_WINDOW_SECS as i64 - 60),
        );
        assert!(!a.needs_reauth());
        // Past the default window → lapsed (must be re-approved).
        a.decided_at = Some(
            Utc::now() - chrono::Duration::seconds(DEFAULT_UNRUN_GRANT_WINDOW_SECS as i64 + 60),
        );
        assert!(
            a.needs_reauth(),
            "an unrun grant past the default execute-by window must lapse even with no interval"
        );
    }

    #[test]
    fn test_needs_reauth_treats_zero_interval_as_disabled() {
        // A stored `Some(0)` (e.g. a pre-fix vault record) must NOT make the grant
        // stale ~1s after approval — it is treated as "disabled" and falls back to
        // the generous default window, not a 0-second one.
        let (mut a, _) = new_approval();
        a.reauth_interval_secs = Some(0);
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        a.decided_at = Some(Utc::now() - chrono::Duration::seconds(5));
        assert!(
            !a.needs_reauth(),
            "reauth_interval_secs = 0 must be disabled, not a 0-second window"
        );
        // But the default execute-by bound still applies.
        a.decided_at = Some(
            Utc::now() - chrono::Duration::seconds(DEFAULT_UNRUN_GRANT_WINDOW_SECS as i64 + 60),
        );
        assert!(a.needs_reauth());
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
        assert!(
            e["links"].get("approve_url").is_none(),
            "blank links omitted"
        );
        assert!(e["links"]["panel_url"].is_string());

        // A decided/closed status is not a live notify path → Config error.
        a.status = ApprovalStatus::Approved;
        assert!(matches!(
            webhook_payload(&a, &links),
            Err(NotifyError::Config(_))
        ));
    }

    #[test]
    fn webhook_payload_carries_tenant() {
        let (mut approval, token) = new_approval();
        let links = approval.links("https://vault.example.com", &token);

        // Untenanted (new_approval sets tenant: None) → nested approval.tenant is null.
        let p = webhook_payload(&approval, &links).expect("pending payload builds");
        assert!(
            p["approval"].get("tenant").is_some(),
            "nested tenant key present"
        );
        assert!(p["approval"]["tenant"].is_null(), "untenanted ⇒ null");

        // Tenanted → the nested key carries the tenant string.
        approval.tenant = Some("acme".to_string());
        let p2 = webhook_payload(&approval, &links).expect("pending payload builds");
        assert_eq!(p2["approval"]["tenant"], "acme");
    }

    #[test]
    fn test_sla_windows_per_class() {
        let mut cfg = ApprovalConfig {
            ttl_secs: 7200,
            ..Default::default()
        };
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
            CriticalitySla {
                escalate_after_secs: 1,
                escalate_window_secs: 2,
            },
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

    // ============ Plan 100 P2 Phase D: approval-recipe in-lock evaluator ========

    #[test]
    fn recipe_with_agent_reviewer_term_is_unsatisfiable_even_when_fully_signed() {
        // Finding 6 (agent-reviewer defense-in-depth): govder rejects agent-reviewer
        // terms at write, so a fetched rule should only ever contain {senior,
        // teammate}. If a hand-crafted / stale rule somehow arrives, a recipe REQUIRING
        // an agent-reviewer term is UNSATISFIABLE — it never clears via agents, no
        // matter how many distinct-controller agent-reviewers sign off.
        let mut a = new_approval_with_rule(senior_plus_two_reviewers_rule());

        approve_as(&mut a, "senior@corp", ApproverClass::Senior, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);

        approve_as(
            &mut a,
            "ep_reviewer_a",
            ApproverClass::AgentReviewer,
            Some("controller-a"),
            Some("dg_a"),
        )
        .unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);

        // A SECOND agent-reviewer under a DISTINCT controller would once have completed
        // the "1 senior + 2 agent-reviewer" recipe — now the recipe is categorically
        // unsatisfiable, so the request stays pending forever.
        approve_as(
            &mut a,
            "ep_reviewer_b",
            ApproverClass::AgentReviewer,
            Some("controller-b"),
            Some("dg_b"),
        )
        .unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "an agent-reviewer recipe term is disabled system-wide (never clears via agents)"
        );
        assert_eq!(a.signoffs.len(), 3, "the sign-offs are still recorded");
    }

    #[test]
    fn recipe_any_deny_denies_under_default_deny_on_any_deny_mode() {
        let mut a = new_approval_with_rule(senior_plus_two_reviewers_rule());
        approve_as(
            &mut a,
            "ep_reviewer_a",
            ApproverClass::AgentReviewer,
            Some("controller-a"),
            Some("dg_a"),
        )
        .unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
        a.deny(Decision::new("admin panel", "senior@corp")).unwrap();
        assert_eq!(a.status, ApprovalStatus::Denied);
    }

    #[test]
    fn recipe_present_but_unsatisfied_stays_pending_never_auto_approves() {
        // A rule that can never be satisfied (an agent-reviewer-only recipe with no
        // agent-reviewer sign-off ever recorded) must leave the request pending
        // forever — never auto-approve just because a stamped rule exists.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::AgentReviewer,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        // A human approval does NOT satisfy an agent-reviewer-only recipe, even
        // though a single approval would have sufficed under the numeric path.
        approve_as(&mut a, "senior@corp", ApproverClass::Senior, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
    }

    #[test]
    fn recipe_unresolved_class_never_counts_even_though_numeric_path_would_allow_it() {
        // No `approver_class` supplied (e.g. an admin-panel/OOB/CLI decision, or a
        // pre-Phase-D broker) must never count toward a stamped rule, even though
        // the SAME sign-off would have satisfied the plain numeric threshold.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.approve(Decision::new("admin panel", "alice")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "an unresolved class must never count toward a stamped rule"
        );
    }

    #[test]
    fn recipe_majority_with_dissent_recorded_lets_the_recipe_clear_despite_a_dissent() {
        // Opt-in majority mode: a single dissent is recorded but does not, by
        // itself, terminate the request — the recipe may still clear via the
        // remaining positive sign-offs (approval-recipes.md §3 P2 build decision #1).
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        // Majority mode is only honored below Extreme (approval-recipes.md §5 D4(a)):
        // stamp a RESOLVED, non-forcing authoritative tier so the deny-wins force does
        // not fire. Without this, the default "" authoritative_risk_tier would be
        // treated as Extreme (fail-closed) and the dissent WOULD terminate.
        a.authoritative_risk_tier = "Medium".to_string();
        approve_as(&mut a, "alice@corp", ApproverClass::Teammate, None, None).unwrap();
        // A dissent: recorded, but NOT terminal under majority mode.
        a.deny(Decision::new("admin panel", "carol@corp")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "a dissent under majority-with-dissent-recorded must not terminate the request"
        );
        assert_eq!(a.signoffs.len(), 2, "the dissent is recorded, never lost");
        // A second distinct teammate approval completes the recipe despite the dissent.
        approve_as(&mut a, "bob@corp", ApproverClass::Teammate, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert!(
            a.signoffs.iter().any(|s| !s.approve),
            "the dissent stays on the recorded sign-off set even once approved"
        );
    }

    #[test]
    fn recipe_extreme_authoritative_tier_forces_deny_on_any_deny_despite_majority_mode() {
        // BLOCKER 5: Extreme/irreversible actions ALWAYS behave as deny-on-any-deny,
        // regardless of the configured decision_mode (approval-recipes.md §3/§5 D4a).
        // The force uses govder's AUTHORITATIVE risk tier, NOT vultrino's local
        // criticality — here local criticality is deliberately left at its default
        // Medium to prove it no longer drives the force.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Extreme".to_string();
        assert_eq!(a.criticality, CriticalityClass::Medium, "local criticality is not the authority");
        approve_as(&mut a, "alice@corp", ApproverClass::Teammate, None, None).unwrap();
        a.deny(Decision::new("admin panel", "carol@corp")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Denied,
            "authoritative Extreme forces deny-on-any-deny even under majority mode"
        );
    }

    #[test]
    fn recipe_empty_authoritative_tier_forces_deny_on_any_deny_fail_closed() {
        // BLOCKER 5: risk_tier == "" (govder could not resolve) → treated as Extreme
        // (fail-closed). A stamped majority-mode rule with NO authoritative risk facts
        // must still force deny-on-any-deny — a dissent terminates.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        assert_eq!(a.authoritative_risk_tier, "", "default is the unresolved worst case");
        approve_as(&mut a, "alice@corp", ApproverClass::Teammate, None, None).unwrap();
        a.deny(Decision::new("admin panel", "carol@corp")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Denied,
            "an empty authoritative risk_tier is Extreme (fail-closed) and forces deny-wins"
        );
    }

    #[test]
    fn recipe_authoritative_irreversible_forces_deny_on_any_deny_despite_majority_mode() {
        // BLOCKER 5: an authoritatively-irreversible action forces deny-on-any-deny
        // even under majority mode, using the AUTHORITATIVE stamp (not local
        // trusted_irreversible). Risk tier is a resolved, non-forcing value to prove
        // irreversibility alone is sufficient.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Medium".to_string();
        a.authoritative_irreversible = true;
        approve_as(&mut a, "alice@corp", ApproverClass::Teammate, None, None).unwrap();
        a.deny(Decision::new("admin panel", "carol@corp")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Denied,
            "authoritative irreversibility forces deny-on-any-deny even under majority mode"
        );
    }

    #[test]
    fn recipe_high_authoritative_tier_honors_majority_mode() {
        // BLOCKER 5 boundary (approval-recipes.md §5 D4(a)): majority-with-dissent is a
        // legitimate per-org opt-in BELOW Extreme, so a RESOLVED High/Medium/Low tier
        // does NOT force deny-on-any-deny — the dissent stays non-terminal and the
        // recipe can still clear. This mirrors govder's
        // `forceDenyOnAnyDeny := irreversible || riskTier == Extreme` exactly (High is
        // NOT forced), keeping the two planes convergent rather than diverging.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "High".to_string();
        approve_as(&mut a, "alice@corp", ApproverClass::Teammate, None, None).unwrap();
        a.deny(Decision::new("admin panel", "carol@corp")).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "resolved High honors majority mode (deny non-terminal) — matches govder"
        );
        approve_as(&mut a, "bob@corp", ApproverClass::Teammate, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }

    #[test]
    fn recipe_same_bare_subject_across_aggregator_keys_is_rejected() {
        // RE-BLOCKER 1: vultrino stamps `agg:<key-id>:<subject>` on aggregator-asserted
        // identities. The SAME OIDC subject signed through TWO DIFFERENT broker/admin
        // keys (key rotation or an HA broker) — `agg:key-a:alice@corp` and
        // `agg:key-b:alice@corp` — must fill ONLY ONE recipe slot, never two; otherwise
        // one person alone could clear a {teammate:2} recipe. Recipe-slot distinctness
        // keys on the BARE subject via `bare_approver_identity`.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Medium".to_string();
        // Same bare subject `alice@corp` via two DIFFERENT aggregator keys. The
        // second is rejected at decision time: waiting until grant re-derivation
        // would leave a misleading stored Approved/Pending history.
        approve_as(&mut a, "agg:key-a:alice@corp", ApproverClass::Teammate, None, None).unwrap();
        let duplicate = approve_as(
            &mut a,
            "agg:key-b:alice@corp",
            ApproverClass::Teammate,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(duplicate, ApprovalError::DuplicateApprover));
        assert_eq!(
            a.signoffs.len(),
            1,
            "the duplicate bare subject must not be recorded"
        );
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "one bare subject via two aggregator keys fills only ONE of the two teammate slots"
        );
        // A GENUINELY distinct bare subject fills the second slot and clears the recipe.
        approve_as(&mut a, "agg:key-b:bob@corp", ApproverClass::Teammate, None, None).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "a second DISTINCT bare subject satisfies the two-teammate recipe"
        );
    }

    /// Minimal teammate Signoff for direct `dedupe_by_identity` / `approval_rule_satisfied`
    /// unit tests (bypasses `transition()` so case-varied full identities can be staged
    /// without hitting DuplicateApprover on the bare non-aggregator path).
    fn teammate_signoff(identity: &str) -> Signoff {
        Signoff {
            approver_identity: identity.to_string(),
            channel: "test".to_string(),
            decided_at: Utc::now(),
            note: None,
            approver_kind: "human".to_string(),
            delegation_grant_ref: None,
            resolved_class: Some(ApproverClass::Teammate),
            controller: None,
            approve: true,
        }
    }

    fn two_teammate_rule() -> ApprovalRule {
        ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        }
    }

    #[test]
    fn dedupe_collapses_case_varied_bare_subject_across_aggregator_keys() {
        // Case-varied spellings of ONE principal via two aggregator keys must fill
        // ONE recipe slot (parity with DuplicateApprover / sod_for ASCII case-fold).
        let a = teammate_signoff("agg:key-a:Alice@corp.com");
        let b = teammate_signoff("agg:key-b:alice@corp.com");
        let out = dedupe_by_identity(vec![&a, &b]);
        assert_eq!(
            out.len(),
            1,
            "Alice@corp.com and alice@corp.com via distinct keys are one principal"
        );
    }

    #[test]
    fn dedupe_case_varied_same_principal_does_not_satisfy_two_slot_recipe() {
        let a = teammate_signoff("agg:key-a:Alice@corp.com");
        let b = teammate_signoff("agg:key-b:alice@corp.com");
        assert!(
            !approval_rule_satisfied(&two_teammate_rule(), &[a, b]),
            "one principal with case-varied spellings must not clear {{teammate:2}}"
        );
    }

    #[test]
    fn dedupe_keeps_genuinely_distinct_principals() {
        let a = teammate_signoff("agg:key-a:alice@corp.com");
        let b = teammate_signoff("agg:key-b:bob@corp.com");
        let out = dedupe_by_identity(vec![&a, &b]);
        assert_eq!(out.len(), 2, "alice and bob remain two distinct principals");
        assert!(
            approval_rule_satisfied(&two_teammate_rule(), &[a, b]),
            "two distinct principals must still clear {{teammate:2}}"
        );
    }

    #[test]
    fn dedupe_collapses_case_varied_non_aggregator_identities() {
        let a = teammate_signoff("Alice@corp.com");
        let b = teammate_signoff("alice@corp.com");
        let out = dedupe_by_identity(vec![&a, &b]);
        assert_eq!(
            out.len(),
            1,
            "non-aggregator identities differing only by ASCII case collapse to one"
        );
    }

    #[test]
    fn recipe_hard_sod_rejects_second_signoff_from_same_aggregator_key() {
        // RE-REVIEW-3 BLOCKER 1: a stamped recipe REPLACES the numeric threshold,
        // which stays 1 for an ordinary require_approval token (dual_control=false,
        // required_approvals=1 — the EXACT shape the recipe e2e uses). Gating the
        // same-aggregator-key SoD guard on effective_required_approvals() > 1 alone
        // SKIPPED it under a recipe, letting ONE aggregator key invent two distinct
        // operator names to fill both {teammate:2} slots (one key fabricating M-of-N).
        // same_aggregator_key_guard_active now activates whenever a rule is stamped.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Medium".to_string();
        // Ordinary token: no dual_control, numeric threshold is 1 — the guard would be
        // skipped if it keyed on effective_required_approvals() alone.
        assert_eq!(a.effective_required_approvals(), 1);
        assert!(a.same_aggregator_key_guard_active(true), "recipe activates the guard");
        // First teammate via aggregator key A, under HARD SoD.
        let mut d1 = Decision::new("json-api", "agg:keyA:fake-alice@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        d1.approver_kind = "human".to_string();
        a.approve(d1).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
        // A SECOND, differently-named operator on the SAME aggregator key is rejected —
        // the aggregator's claim of a distinct human is unverifiable under hard SoD.
        let mut d2 = Decision::new("json-api", "agg:keyA:fake-bob@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        d2.approver_kind = "human".to_string();
        let err = a.approve(d2).unwrap_err();
        assert!(matches!(err, ApprovalError::SameAggregatorKey));
        assert_eq!(a.signoffs.len(), 1, "the same-key second sign-off was not recorded");
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "one aggregator key cannot clear a {{teammate:2}} recipe"
        );
        // A DISTINCT aggregator key supplies a genuinely different human → recipe clears.
        let mut d3 = Decision::new("json-api", "agg:keyB:carol@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        d3.approver_kind = "human".to_string();
        a.approve(d3).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert_eq!(a.signoffs.len(), 2);
    }

    #[test]
    fn recipe_hard_sod_majority_dissent_does_not_poison_aggregator_key() {
        // RE-REVIEW-4 BLOCKER (fail-closed-too-hard): a recorded majority-mode
        // DISSENT must NOT poison the aggregator key. Feir OS uses ONE vultrino key
        // per TENANT (not per human), so a dissent and a later DISTINCT approval
        // routinely share a key. The guard must key on POSITIVE, slot-CONTRIBUTING
        // sign-offs — never "one verdict per key" — or the dissent becomes a
        // permanent veto no distinct approver can overcome.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::MajorityWithDissentRecorded,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "High".to_string(); // majority honored: dissent non-terminal
        // Carol DISSENTS through tenant aggregator key K.
        let carol = Decision::new("json-api", "agg:keyK:carol@corp")
            .with_resolved_class(ApproverClass::Teammate);
        a.deny(carol).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "High-risk majority mode: the dissent is non-terminal"
        );
        // Alice — a DISTINCT real teammate — approves through the SAME tenant key K,
        // under hard SoD. Her single positive is all {teammate:1} requires; the
        // recorded dissent must not veto it.
        let mut alice = Decision::new("json-api", "agg:keyK:alice@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        alice.approver_kind = "human".to_string();
        a.approve(alice).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "a dissent on the per-tenant key must not veto a distinct approver on that key"
        );
    }

    #[test]
    fn recipe_hard_sod_offclass_positive_does_not_poison_aggregator_key() {
        // RE-REVIEW-4 BLOCKER (second form): a POSITIVE that fills no recipe slot
        // (wrong class) must not poison the key either. A teammate positive on a
        // {senior:1} rule contributes nothing, so a later SENIOR on the same tenant
        // key — the first CONTRIBUTING positive — must still clear the recipe.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Medium".to_string();
        // A teammate approves through tenant key K — recorded, but fills no {senior:1} slot.
        let mut bob = Decision::new("json-api", "agg:keyK:bob@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        bob.approver_kind = "human".to_string();
        a.approve(bob).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending, "a teammate does not satisfy {{senior:1}}");
        // A senior approves through the SAME key K — the first CONTRIBUTING positive.
        let mut alice = Decision::new("json-api", "agg:keyK:alice@corp")
            .with_resolved_class(ApproverClass::Senior)
            .enforcing_sod(true);
        alice.approver_kind = "human".to_string();
        a.approve(alice).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "an off-class positive on the key must not veto the required senior on that key"
        );
    }

    #[test]
    fn recipe_hard_sod_senior_cannot_fabricate_teammate_slots_via_one_key() {
        // RE-REVIEW-5 BLOCKER 1 (fail-OPEN): a Senior fills a Teammate slot
        // (senior ⊇ teammate), so a Senior positive DOES contribute to a {teammate:2}
        // recipe. An EXACT class-match contribution check wrongly called Seniors
        // non-contributing, so the guard skipped them and ONE aggregator key could
        // submit two Seniors (or senior+teammate) and clear {teammate:2} without two
        // distinct real humans. class_fills_a_slot now mirrors recipe_satisfied's
        // hierarchy, so both interleavings are rejected on the same key.
        let make_rule = || ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 2,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let signoff = |ident: &str, class| {
            let mut d = Decision::new("json-api", ident)
                .with_resolved_class(class)
                .enforcing_sod(true);
            d.approver_kind = "human".to_string();
            d
        };
        // Senior + Senior on ONE key K: the second must be rejected.
        let mut a = new_approval_with_rule(make_rule());
        a.authoritative_risk_tier = "High".to_string();
        a.approve(signoff("agg:keyK:fake-alice@corp", ApproverClass::Senior))
            .unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
        let err = a
            .approve(signoff("agg:keyK:fake-bob@corp", ApproverClass::Senior))
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::SameAggregatorKey),
            "two seniors on one key must not fabricate two teammate slots"
        );
        assert_eq!(a.status, ApprovalStatus::Pending);

        // Senior + Teammate on ONE key K: also rejected (the existing senior contributes).
        let mut b = new_approval_with_rule(make_rule());
        b.authoritative_risk_tier = "High".to_string();
        b.approve(signoff("agg:keyK:fake-carol@corp", ApproverClass::Senior))
            .unwrap();
        let err2 = b
            .approve(signoff("agg:keyK:fake-dave@corp", ApproverClass::Teammate))
            .unwrap_err();
        assert!(
            matches!(err2, ApprovalError::SameAggregatorKey),
            "senior-then-teammate on one key must not fabricate two teammate slots"
        );

        // Teammate + Senior on ONE key K (the REVERSE ordering): equally rejected —
        // the existing teammate contributes and the senior would too (senior fills a
        // teammate slot), so the guard is order-independent (Codex RE-REVIEW-6 minor).
        let mut d = new_approval_with_rule(make_rule());
        d.authoritative_risk_tier = "High".to_string();
        d.approve(signoff("agg:keyK:fake-erin@corp", ApproverClass::Teammate))
            .unwrap();
        let err3 = d
            .approve(signoff("agg:keyK:fake-frank@corp", ApproverClass::Senior))
            .unwrap_err();
        assert!(
            matches!(err3, ApprovalError::SameAggregatorKey),
            "teammate-then-senior on one key must not fabricate two teammate slots"
        );

        // Two DISTINCT keys still clear it — a senior is a valid teammate-slot filler.
        let mut c = new_approval_with_rule(make_rule());
        c.authoritative_risk_tier = "High".to_string();
        c.approve(signoff("agg:keyA:alice@corp", ApproverClass::Senior))
            .unwrap();
        c.approve(signoff("agg:keyB:bob@corp", ApproverClass::Teammate))
            .unwrap();
        assert_eq!(
            c.status,
            ApprovalStatus::Approved,
            "a senior + a teammate on DISTINCT keys legitimately fill {{teammate:2}}"
        );
    }

    #[test]
    fn recipe_hard_sod_unsatisfiable_branch_positive_does_not_poison_key() {
        // RE-REVIEW-5 BLOCKER 2 (fail-closed-too-hard): a positive toward an
        // UNSATISFIABLE branch (one requiring a disabled agent-reviewer term) fills no
        // VIABLE slot, so it must not poison the key. Rule: {teammate:1, agent-reviewer:1}
        // OR {senior:1}. A teammate positive (branch 1, never clears) on key K must not
        // block a later senior (branch 2) on key K.
        let rule = ApprovalRule {
            recipes: vec![
                Recipe {
                    terms: vec![
                        RecipeTerm {
                            class: ApproverClass::Teammate,
                            count: 1,
                        },
                        RecipeTerm {
                            class: ApproverClass::AgentReviewer,
                            count: 1,
                        },
                    ],
                },
                Recipe {
                    terms: vec![RecipeTerm {
                        class: ApproverClass::Senior,
                        count: 1,
                    }],
                },
            ],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "High".to_string();
        let mut tm = Decision::new("json-api", "agg:keyK:bob@corp")
            .with_resolved_class(ApproverClass::Teammate)
            .enforcing_sod(true);
        tm.approver_kind = "human".to_string();
        a.approve(tm).unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
        let mut sr = Decision::new("json-api", "agg:keyK:alice@corp")
            .with_resolved_class(ApproverClass::Senior)
            .enforcing_sod(true);
        sr.approver_kind = "human".to_string();
        a.approve(sr).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "a positive toward an unsatisfiable branch must not veto the senior on that key"
        );
    }

    #[test]
    fn recipe_empty_approver_kind_signoff_is_dropped() {
        // RE-REVIEW MINOR: a genuinely EMPTY/blank stored `approver_kind` is DROPPED
        // during recipe evaluation (matching govder's recipes.go), never counted.
        // Normal new decisions default to "human", so this only affects malformed/legacy
        // records.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        a.authoritative_risk_tier = "Medium".to_string();
        // A sign-off with a RESOLVED Teammate class but a BLANK Kind (corrupt/legacy).
        let mut decision = Decision::new("admin panel", "alice@corp")
            .with_resolved_class(ApproverClass::Teammate);
        decision.approver_kind = "  ".to_string(); // blank/whitespace
        a.approve(decision).unwrap();
        assert_eq!(a.signoffs.len(), 1, "the sign-off is still recorded");
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "a blank approver_kind sign-off is DROPPED from recipe matching (fail-closed, matches govder)"
        );
        // A well-formed human Teammate sign-off then satisfies the {teammate:1} recipe.
        approve_as(&mut a, "bob@corp", ApproverClass::Teammate, None, None).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Approved,
            "a well-formed human Teammate then clears the recipe"
        );
    }

    #[test]
    fn recipe_none_path_numeric_threshold_unchanged() {
        // Parity: with no ApprovalRule stamped, behavior is byte-identical to the
        // pre-Phase-D numeric threshold (already exercised by
        // test_dual_control_requires_distinct_approvers above; this test pins the
        // `approval_rule` field itself).
        let (a, _) = new_approval();
        assert!(a.approval_rule.is_none());
    }

    #[test]
    fn recipe_decision_mode_deserializes_fail_closed() {
        // A missing, empty, or unrecognized decision_mode must normalize to the
        // conservative default rather than erroring the whole ApprovalRule parse
        // (mirrors govder's RecipeDecisionMode.Valid() fallback).
        let rule: ApprovalRule =
            serde_json::from_str(r#"{"recipes":[{"terms":[{"class":"senior","count":1}]}]}"#)
                .expect("missing decision_mode must not error");
        assert_eq!(rule.decision_mode, RecipeDecisionMode::DenyOnAnyDeny);

        let rule: ApprovalRule = serde_json::from_str(
            r#"{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":""}"#,
        )
        .expect("empty decision_mode must not error");
        assert_eq!(rule.decision_mode, RecipeDecisionMode::DenyOnAnyDeny);

        let rule: ApprovalRule = serde_json::from_str(
            r#"{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"bogus"}"#,
        )
        .expect("unrecognized decision_mode must not error");
        assert_eq!(rule.decision_mode, RecipeDecisionMode::DenyOnAnyDeny);

        let rule: ApprovalRule = serde_json::from_str(
            r#"{"recipes":[{"terms":[{"class":"senior","count":1}]}],"decision_mode":"majority-with-dissent-recorded"}"#,
        )
        .unwrap();
        assert_eq!(
            rule.decision_mode,
            RecipeDecisionMode::MajorityWithDissentRecorded
        );
    }

    #[test]
    fn recipe_unknown_class_disqualifies_only_that_recipe() {
        // An unrecognized class value on a fetched RecipeTerm must disqualify only
        // THAT recipe, never fail the whole ApprovalRule deserialization/fetch.
        let rule: ApprovalRule = serde_json::from_str(
            r#"{"recipes":[
                {"terms":[{"class":"galactic-overlord","count":1}]},
                {"terms":[{"class":"teammate","count":1}]}
            ],"decision_mode":"deny-on-any-deny"}"#,
        )
        .expect("an unknown class must not error the whole rule");
        let mut a = new_approval_with_rule(rule);
        // The malformed recipe (bad class) is unsatisfiable; the second, well-formed
        // recipe (1 teammate) still lets the approval clear.
        approve_as(&mut a, "bob@corp", ApproverClass::Teammate, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }

    #[test]
    fn recipe_over_cap_or_overflow_count_is_unsatisfiable() {
        // BLOCKER 3: per-term AND summed-total caps prevent a u32 wrap from letting a
        // small sign-off set clear a recipe reading as enormous on paper.
        //
        // (a) The concrete overflow exploit: senior:u32::MAX + senior:2. Unchecked
        // summation would wrap need_senior to 1, so ONE senior would clear a rule
        // reading as 4,294,967,297 seniors. The cap disqualifies the recipe outright —
        // no available pool, however large, can satisfy it.
        let overflow = Recipe {
            terms: vec![
                RecipeTerm {
                    class: ApproverClass::Senior,
                    count: u32::MAX,
                },
                RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 2,
                },
            ],
        };
        assert!(!recipe_well_formed(&overflow));
        assert!(
            !recipe_satisfied(&overflow, 1, 0, 0),
            "one senior must never clear a wrapped requirement"
        );
        assert!(
            !recipe_satisfied(&overflow, u32::MAX, u32::MAX, u32::MAX),
            "even a maxed-out available pool cannot satisfy a capped-out recipe"
        );

        // (b) A single over-cap term (65 > 64) is unsatisfiable.
        let over = Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 65,
            }],
        };
        assert!(!recipe_well_formed(&over));
        assert!(!recipe_satisfied(&over, 0, 100, 0));

        // (c) Per-term counts are each <= 64 but the SUMMED total exceeds 64.
        let summed = Recipe {
            terms: vec![
                RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 40,
                },
                RecipeTerm {
                    class: ApproverClass::Teammate,
                    count: 40,
                },
            ],
        };
        assert!(!recipe_well_formed(&summed));
        assert!(!recipe_satisfied(&summed, 100, 100, 0));

        // (d) A recipe exactly AT the cap (total 64) still clears with enough approvers
        // — the cap disqualifies only rules that BREACH it, never a legitimate one.
        let at_cap = Recipe {
            terms: vec![RecipeTerm {
                class: ApproverClass::Teammate,
                count: 64,
            }],
        };
        assert!(recipe_well_formed(&at_cap));
        assert!(recipe_satisfied(&at_cap, 0, 64, 0));
        assert!(!recipe_satisfied(&at_cap, 0, 63, 0));
    }

    #[test]
    fn recipe_over_cap_rule_never_auto_approves_via_transition() {
        // BLOCKER 3 end-to-end: a stamped rule whose only recipe breaches the cap is
        // unsatisfiable through the real approve path — it never auto-approves.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![
                    RecipeTerm {
                        class: ApproverClass::Senior,
                        count: u32::MAX,
                    },
                    RecipeTerm {
                        class: ApproverClass::Senior,
                        count: 2,
                    },
                ],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        approve_as(&mut a, "senior@corp", ApproverClass::Senior, None, None).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "a capped-out recipe is unsatisfiable and must never clear with fewer approvers"
        );
    }

    #[test]
    fn recipe_explicit_unknown_kind_is_dropped_fail_closed() {
        // MINOR: an EXPLICIT, non-empty, unrecognized approver_kind must be dropped from
        // recipe matching (fail-closed) — govder only ever classifies
        // human/delegate-agent. The previous wildcard silently accepted it.
        let rule = ApprovalRule {
            recipes: vec![Recipe {
                terms: vec![RecipeTerm {
                    class: ApproverClass::Senior,
                    count: 1,
                }],
            }],
            decision_mode: RecipeDecisionMode::DenyOnAnyDeny,
        };
        let mut a = new_approval_with_rule(rule);
        // Explicit unknown Kind with an otherwise-valid senior class: dropped.
        let mut d =
            Decision::new("admin panel", "mystery").with_resolved_class(ApproverClass::Senior);
        d.approver_kind = "robot".to_string();
        a.approve(d).unwrap();
        assert_eq!(
            a.status,
            ApprovalStatus::Pending,
            "an explicit unknown Kind must not satisfy a senior recipe"
        );

        // Positive control: a well-formed human senior sign-off DOES satisfy it.
        approve_as(&mut a, "senior@corp", ApproverClass::Senior, None, None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
    }
}

#[cfg(test)]
mod finding_6a_startup_warning_tests {
    use super::*;

    /// feir-os plan 103 §10h FINDING 6a. `[approvals] enabled` absent from a shipped runbook's
    /// config yields a stack that applies clean and then refuses every money verb, and nothing
    /// upstream of the agent's first action reports it. The startup warning is the only place it
    /// is knowable in time, so it must exist, must name the CONSEQUENCE (not just the flag), and
    /// must be silent when approvals are on.
    #[test]
    fn disabled_approvals_warn_and_name_the_consequence() {
        let cfg = ApprovalConfig::default();
        assert!(
            !cfg.enabled,
            "the default must stay DISABLED (this test's premise); if this ever flips, the \
             warning becomes dead code and the docs change too"
        );
        let w = cfg
            .startup_warning()
            .expect("disabled approvals must produce a startup warning");
        for needle in [
            "REFUSED at execute",
            "not held for a human",
            "approvals are not enabled on this Vultrino instance",
            "enabled = true",
        ] {
            assert!(
                w.contains(needle),
                "the startup warning does not mention {needle:?}; an operator reading it cannot \
                 tell what breaks or how to fix it.\nwarning: {w}"
            );
        }
    }

    #[test]
    fn enabled_approvals_warn_about_nothing() {
        let cfg = ApprovalConfig {
            enabled: true,
            ..ApprovalConfig::default()
        };
        assert!(
            cfg.startup_warning().is_none(),
            "a correctly configured deployment must not be warned; a warning that always fires \
             is one nobody reads"
        );
    }
}

// MERGE NOTE (2026-07-27): FIX A's FINDING 6a startup-warning tests above and FIX B's FINDING 4
// TTL/clamp tests below were appended at the SAME point in this file by two concurrent streams,
// and this was the only textual conflict in the whole vultrino merge. Both are kept in full: they
// assert different properties of the same subsystem (whether a DISABLED approval subsystem
// announces itself at startup, vs whether an approval can outlive the use token that would
// execute it) and neither is a superset of the other.
#[cfg(test)]
mod finding4_tests {
    use super::*;

    fn sla(after: u64, window: u64) -> CriticalitySla {
        CriticalitySla {
            escalate_after_secs: after,
            escalate_window_secs: window,
        }
    }

    /// FINDING 4 (plan 103 §10h): the SHIPPED divergence, in numbers. govder's
    /// scope table compiles an L3·High use token at **900s**
    /// (`internal/enforce/scope.go`), while the High criticality SLA is 15+15
    /// minutes (**1800s**) and the legacy `approvals.ttl_secs` default is 3600s. An
    /// approval offered for 1800s (or 3600s) against a 900s credential is an
    /// approval a human can sign and nothing can execute.
    #[test]
    fn clamp_binds_the_approval_window_to_an_l3_high_use_token() {
        let high = sla(15 * 60, 15 * 60);
        let (after, window) = high
            .clamped_to_credential(Some(chrono::Duration::seconds(900)))
            .expect("a 900s credential is alive, so the approval must open");
        assert_eq!(
            (after + window).num_seconds(),
            900,
            "the final deadline must equal the credential's remaining life, not 1800s"
        );
        // Both phases survive proportionally: escalate at the halfway point, so a
        // clamped request still escalates BEFORE it expires.
        assert_eq!(after.num_seconds(), 450);
        assert_eq!(window.num_seconds(), 450);
    }

    /// The clamp only ever SHRINKS the window. A credential with more life left than
    /// the configured SLA must not extend the approval — the SLA is still a real
    /// policy bound, and widening it here would be fail-open.
    #[test]
    fn clamp_never_extends_the_window_past_the_configured_sla() {
        let high = sla(15 * 60, 15 * 60);
        let (after, window) = high
            .clamped_to_credential(Some(chrono::Duration::seconds(86_400)))
            .unwrap();
        assert_eq!(after.num_seconds(), 900);
        assert_eq!(window.num_seconds(), 900);
    }

    /// No credential deadline to clamp against (a local/API-key caller, or a token
    /// bounded only by `max_uses`): the configured SLA stands, byte-identical to the
    /// pre-fix behavior.
    #[test]
    fn clamp_is_a_no_op_without_a_credential_deadline() {
        let medium = sla(1800, 1800);
        let (after, window) = medium.clamped_to_credential(None).unwrap();
        assert_eq!(after.num_seconds(), 1800);
        assert_eq!(window.num_seconds(), 1800);
    }

    /// A dead (or sub-second) credential yields `None` — the caller must REFUSE to
    /// open. Opening a 0-second approval would invite a human to authorize an action
    /// that is already impossible; refusing executes nothing and says so.
    #[test]
    fn clamp_refuses_when_the_credential_is_already_dead() {
        let high = sla(900, 900);
        assert!(high
            .clamped_to_credential(Some(chrono::Duration::seconds(0)))
            .is_none());
        assert!(high
            .clamped_to_credential(Some(chrono::Duration::seconds(-30)))
            .is_none());
        assert!(
            high.clamped_to_credential(Some(chrono::Duration::milliseconds(800)))
                .is_none(),
            "a sub-second remainder is not a decidable window"
        );
    }

    /// A very short but real window still opens, with both phases inside it.
    #[test]
    fn clamp_keeps_a_short_window_inside_the_credential() {
        let high = sla(900, 900);
        let (after, window) = high
            .clamped_to_credential(Some(chrono::Duration::seconds(30)))
            .unwrap();
        assert_eq!((after + window).num_seconds(), 30);
        assert!(after.num_seconds() >= 0 && window.num_seconds() >= 0);
    }

    fn approved_request() -> ApprovalRequest {
        let (mut a, _t) = tests_support::open_minimal();
        a.status = ApprovalStatus::Approved;
        a
    }

    /// FINDING 4 layer 3: the measured misreport. The approval is granted, the
    /// credential that would execute it is dead, and the decision response must say
    /// BLOCKED — never a state a UI can paint as a completed action.
    #[test]
    fn execution_state_is_blocked_when_the_credential_cannot_execute() {
        let a = approved_request();
        assert!(!a.executed);
        let (state, reason) = execution_state_at_decision(
            &a,
            &CredentialCheck::Unusable("use token has expired".to_string()),
        );
        assert_eq!(state, ExecutionState::Blocked);
        assert_eq!(state.as_wire(), "blocked");
        assert_eq!(reason.as_deref(), Some("use token has expired"));
    }

    /// The discriminating control: the SAME granted, unexecuted approval with a
    /// LIVE credential is `awaiting_execution`. If the classifier answered "blocked"
    /// here, the state would be worthless (it would flag every healthy grant).
    #[test]
    fn execution_state_is_awaiting_when_the_credential_is_alive() {
        let a = approved_request();
        let (state, reason) = execution_state_at_decision(&a, &CredentialCheck::Usable);
        assert_eq!(state, ExecutionState::AwaitingExecution);
        assert_eq!(state.as_wire(), "awaiting_execution");
        assert!(reason.is_none());
    }

    /// An unreadable credential lookup is `awaiting_execution` with no invented
    /// reason — never `Usable`-by-default and never a "will run" claim.
    #[test]
    fn execution_state_never_claims_a_dead_credential_is_fine_on_an_unknown_lookup() {
        let a = approved_request();
        let (state, _) = execution_state_at_decision(&a, &CredentialCheck::Unknown);
        assert_eq!(state, ExecutionState::AwaitingExecution);
    }

    /// A terminal failure is `failed`, carrying vultrino's own recorded reason —
    /// this is the state the product UI painted as "Approved. Recorded just now."
    #[test]
    fn execution_state_separates_a_failed_run_from_a_completed_one() {
        let mut failed = approved_request();
        failed.executed = true;
        failed.result_error = Some("use token has expired".to_string());
        let (state, reason) = execution_state_at_decision(&failed, &CredentialCheck::NotApplicable);
        assert_eq!(state, ExecutionState::Failed);
        assert_eq!(state.as_wire(), "failed");
        assert_eq!(reason.as_deref(), Some("use token has expired"));

        let mut ok = approved_request();
        ok.executed = true;
        ok.result_status = Some(200);
        let (state, reason) = execution_state_at_decision(&ok, &CredentialCheck::NotApplicable);
        assert_eq!(state, ExecutionState::Executed);
        assert_eq!(state.as_wire(), "executed");
        assert!(reason.is_none());
    }

    /// A still-open or denied request implies nothing about execution.
    #[test]
    fn execution_state_is_not_applicable_for_a_non_approved_request() {
        let (mut pending, _t) = tests_support::open_minimal();
        assert_eq!(pending.status, ApprovalStatus::Pending);
        let (state, _) = execution_state_at_decision(&pending, &CredentialCheck::Usable);
        assert_eq!(state, ExecutionState::NotApplicable);
        assert_eq!(state.as_wire(), "not_applicable");

        pending.status = ApprovalStatus::Denied;
        let (state, _) = execution_state_at_decision(&pending, &CredentialCheck::Usable);
        assert_eq!(state, ExecutionState::NotApplicable);
    }

    mod tests_support {
        use super::*;

        pub fn open_minimal() -> (ApprovalRequest, String) {
            ApprovalRequest::open(NewApproval {
                credential: "stripe-prod".to_string(),
                action: "http.request".to_string(),
                params: serde_json::json!({"method": "post"}),
                requester: RequesterInfo::local(),
                use_token_id: Some("ut_1".to_string()),
                principal_id: None,
                agent_label: None,
                tenant: None,
                workload_id: None,
                preview: None,
                action_label: Some("payments.refund".to_string()),
                dual_control: false,
                criticality: CriticalityClass::Medium,
                trusted_irreversible: None,
                escalate_after: chrono::Duration::minutes(15),
                escalate_window: chrono::Duration::minutes(15),
                oob_identity: None,
                reauth_interval_secs: None,
                required_approvals: 1,
                approval_rule: None,
            })
        }
    }
}
