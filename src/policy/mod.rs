//! Policy engine for Vultrino
//!
//! Evaluates access policies to determine whether credential use is allowed.
//! Policies can restrict by:
//! - URL patterns
//! - HTTP methods
//! - Time windows
//! - Rate limits

mod types;

pub use types::*;

use crate::RequestContext;
use glob::Pattern;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Policy-related errors
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy denied: {0}")]
    Denied(String),

    #[error("Invalid policy: {0}")]
    Invalid(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// Policy evaluation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed
    Allow,
    /// Request is denied with reason
    Deny(String),
    /// Request requires user prompt (future feature)
    Prompt,
}

/// The resolved principal making a request (V4): the presenting key/token id
/// and an optional agent label. Used to match [`Policy::principal_pattern`] so a
/// policy (e.g. a per-agent Deny) can target one agent without affecting others
/// sharing the same credential.
#[derive(Debug, Clone, Default)]
pub struct Principal {
    /// Stable id of the presenting principal (`vk_`/`vut_` id).
    pub id: String,
    /// Optional agent label carried on the token, bound by the control plane.
    pub agent_label: Option<String>,
    /// Optional human/directory owner of this non-human identity (V10): the
    /// IdP-resolvable owner binding (OIDC `sub` / SCIM id).
    pub owner: Option<String>,
}

/// An extracted spend attempt for a request (V3): an amount in minor units
/// (cents/micros) and its asset. Produced by a [`SpendExtractor`] from the
/// request body before evaluation.
#[derive(Debug, Clone)]
pub struct SpendAttempt {
    pub asset: String,
    pub amount: u64,
}

/// Inputs to a policy evaluation. Bundled into one struct so the `evaluate`
/// surface stays stable as new dimensions (principal, spend) are threaded
/// through (V3/V4) — one pass over the evaluator.
#[derive(Debug, Clone, Default)]
pub struct EvalInput<'a> {
    pub credential_alias: &'a str,
    pub url: Option<&'a str>,
    pub method: Option<&'a str>,
    /// Resolved principal, for `principal_pattern` matching (V4).
    pub principal: Option<&'a Principal>,
    /// Extracted spend attempt, for `SpendCap` evaluation (V3).
    pub spend: Option<&'a SpendAttempt>,
}

/// Rate limiter state for a credential
struct RateLimitState {
    /// Requests in current window
    count: u32,
    /// Window start time
    window_start: Instant,
}

/// Policy engine that evaluates access decisions
pub struct PolicyEngine {
    /// Registered policies
    policies: RwLock<Vec<Policy>>,
    /// Rate limit states per credential
    rate_limits: RwLock<HashMap<String, RateLimitState>>,
    /// Engine-level decision when a credential matches **no** policy.
    /// `true` = fail-closed (deny), `false` = fail-open (allow, legacy).
    /// Read on the hot path, so it's a plain atomic rather than a lock.
    default_deny: AtomicBool,
}

impl PolicyEngine {
    /// Create a new policy engine.
    ///
    /// The engine starts **fail-closed** (a credential matching no policy is
    /// denied) — the secure default, so a constructor that forgets to wire
    /// `[enforcement] default_action` cannot silently fail open. The server
    /// still sets the mode explicitly from config via [`Self::set_default_deny`];
    /// callers that want the legacy fail-open behavior opt in with
    /// `set_default_deny(false)`.
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            rate_limits: RwLock::new(HashMap::new()),
            default_deny: AtomicBool::new(true),
        }
    }

    /// Set the engine's behavior when a credential matches **no** policy.
    ///
    /// `true` = **fail-closed**: the credential is denied with a distinct
    /// `no_policy` reason (the govder enforcement posture, V2). `false` = legacy
    /// fail-open: the credential is allowed. Wired from `[enforcement]
    /// default_action` at server start. It is stored as an atomic so a runtime
    /// toggle (e.g. a future admin-API flip) needs no engine rebuild — though no
    /// such runtime caller exists yet.
    pub fn set_default_deny(&self, deny: bool) {
        self.default_deny.store(deny, Ordering::SeqCst);
    }

    /// Whether the engine denies credentials that match no policy.
    pub fn default_deny(&self) -> bool {
        self.default_deny.load(Ordering::SeqCst)
    }

    /// Add a policy
    pub fn add_policy(&self, policy: Policy) {
        let mut policies = self.policies.write();
        policies.push(policy);
    }

    /// Remove a policy by ID
    pub fn remove_policy(&self, id: &str) -> bool {
        let mut policies = self.policies.write();
        let len_before = policies.len();
        policies.retain(|p| p.id != id);
        policies.len() < len_before
    }

    /// List all policies
    pub fn list_policies(&self) -> Vec<Policy> {
        let policies = self.policies.read();
        policies.clone()
    }

    /// Load policies from configuration
    pub fn load_policies(&self, policies: Vec<Policy>) {
        let mut p = self.policies.write();
        *p = policies;
    }

    /// Evaluate a request against all applicable policies (legacy 4-arg form,
    /// kept for existing callers/tests). Derives the principal id from `context`;
    /// the server uses [`Self::evaluate_full`] to also pass the agent label and
    /// the extracted spend attempt.
    pub fn evaluate(
        &self,
        credential_alias: &str,
        url: Option<&str>,
        method: Option<&str>,
        context: &RequestContext,
    ) -> PolicyDecision {
        let principal = context.api_key_id.as_ref().map(|id| Principal {
            id: id.clone(),
            agent_label: context.agent_label.clone(),
            owner: None, // legacy path: owner is used for SoD, not policy matching
        });
        let input = EvalInput {
            credential_alias,
            url,
            method,
            principal: principal.as_ref(),
            spend: None,
        };
        self.evaluate_inner(&input, true)
    }

    /// Side-effecting evaluation against the full [`EvalInput`] (principal +
    /// spend). Used by the live execute path (V3/V4).
    pub fn evaluate_full(&self, input: &EvalInput) -> PolicyDecision {
        self.evaluate_inner(input, true)
    }

    /// Whether an authoritative **kill switch** (V6) matches this input — i.e. the
    /// `Deny` came from a halt, not an ordinary policy. Read-only / no side
    /// effects. Used so a halt is never downgraded by V11 observe mode (a halt is
    /// a security override, not a per-tenant policy that observe can wave away).
    pub fn is_halted(&self, input: &EvalInput) -> bool {
        let policies = self.policies.read();
        policies.iter().any(|p| {
            p.kill
                && credential_matches(&p.credential_pattern, input.credential_alias)
                && principal_matches(p.principal_pattern.as_deref(), input.principal)
        })
    }

    /// Whether a matching policy carries a **resource guard** — a `SpendCap` or
    /// `RateLimit` rule (V11). Read-only / no side effects. Used so V11 observe
    /// mode does NOT downgrade a denial for a credential/principal under a spend
    /// or rate cap: those are financial/abuse boundaries, not authorization
    /// posture, so they must hold even in observe mode (a downgraded over-cap call
    /// would run uncharged — the cumulative ledger only advances on an admitting
    /// rule — and a downgraded over-limit call would defeat the rate limiter).
    pub fn has_resource_guard(&self, input: &EvalInput) -> bool {
        fn rule_guards(c: &PolicyCondition) -> bool {
            match c {
                PolicyCondition::SpendCap { .. } | PolicyCondition::RateLimit { .. } => true,
                PolicyCondition::And(v) | PolicyCondition::Or(v) => v.iter().any(rule_guards),
                PolicyCondition::Not(b) => rule_guards(b),
                _ => false,
            }
        }
        let policies = self.policies.read();
        policies
            .iter()
            .filter(|p| {
                credential_matches(&p.credential_pattern, input.credential_alias)
                    && principal_matches(p.principal_pattern.as_deref(), input.principal)
            })
            .any(|p| p.rules.iter().any(|r| rule_guards(&r.condition)))
    }

    /// Like [`Self::evaluate`] but with **no side effects**: `RateLimit` and
    /// `SpendCap` are treated as already-admitted (within limit/charge) instead
    /// of being counted/charged. Used by the deferred post-approval path
    /// ([`crate::server::VultrinoServer::resume_approved`]) to re-enforce hard
    /// deny gates (url/method/time/principal/explicit deny) at execution time
    /// without re-charging the rate limiter or spend ledger that the original
    /// request already accounted for when it opened the approval.
    pub fn evaluate_readonly(
        &self,
        credential_alias: &str,
        url: Option<&str>,
        method: Option<&str>,
    ) -> PolicyDecision {
        let input = EvalInput { credential_alias, url, method, principal: None, spend: None };
        self.evaluate_inner(&input, false)
    }

    /// No-side-effect evaluation against the full [`EvalInput`], for the deferred
    /// post-approval resume (same semantics as [`Self::evaluate_readonly`]).
    pub fn evaluate_readonly_full(&self, input: &EvalInput) -> PolicyDecision {
        self.evaluate_inner(input, false)
    }

    fn evaluate_inner(&self, input: &EvalInput, record: bool) -> PolicyDecision {
        let policies = self.policies.read();

        // Find policies matching BOTH the credential and (V4) the principal.
        let matching_policies: Vec<_> = policies
            .iter()
            .filter(|p| {
                credential_matches(&p.credential_pattern, input.credential_alias)
                    && principal_matches(p.principal_pattern.as_deref(), input.principal)
            })
            .collect();

        // V6 kill switch: an authoritative per-principal halt overrides everything
        // — evaluated before any normal policy so an allow rule ordered first can
        // never let a halted agent through. (A kill policy matches a credential +
        // principal like any other, but its `kill` flag makes it unconditional.)
        if matching_policies.iter().any(|p| p.kill) {
            // Generic reason to the caller — don't leak the kill-policy name or
            // label scheme to a (possibly compromised) agent. The specifics live
            // in the halt audit log.
            return PolicyDecision::Deny("denied: this principal has been halted".to_string());
        }

        // If no policies match, fall back to the configured engine default.
        if matching_policies.is_empty() {
            if self.default_deny.load(Ordering::SeqCst) {
                return PolicyDecision::Deny(
                    "no_policy: no policy matches this credential (default-deny enforcement)"
                        .to_string(),
                );
            }
            return PolicyDecision::Allow;
        }

        for policy in matching_policies {
            for rule in &policy.rules {
                // A top-level SpendCap is evaluated here (per-action, stateless) —
                // NOT as a side effect of the recursive boolean walk. Nested
                // SpendCap is rejected by Policy::validate at config/admin load.
                let matched = match &rule.condition {
                    PolicyCondition::SpendCap { asset, per_action_max } => {
                        self.spend_within_cap(
                            input.spend,
                            asset,
                            *per_action_max,
                            record, // check the cap on the live path; skip on resume
                        )
                    }
                    other => self.evaluate_condition(other, input, record),
                };
                if matched {
                    match rule.action {
                        PolicyAction::Allow => return PolicyDecision::Allow,
                        PolicyAction::Deny => {
                            return PolicyDecision::Deny(format!(
                                "Denied by policy '{}': rule matched",
                                policy.name
                            ))
                        }
                        PolicyAction::Prompt => return PolicyDecision::Prompt,
                    }
                }
            }

            match policy.default_action {
                PolicyAction::Allow => continue,
                PolicyAction::Deny => {
                    return PolicyDecision::Deny(format!(
                        "Denied by policy '{}': default action",
                        policy.name
                    ))
                }
                PolicyAction::Prompt => return PolicyDecision::Prompt,
            }
        }

        PolicyDecision::Allow
    }

    /// Evaluate a single condition against the request input.
    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        input: &EvalInput,
        record: bool,
    ) -> bool {
        match condition {
            PolicyCondition::UrlMatch(pattern) => {
                input.url.map(|u| url_matches(u, pattern)).unwrap_or(false)
            }

            PolicyCondition::MethodMatch(methods) => input
                .method
                .map(|m| methods.iter().any(|x| x.eq_ignore_ascii_case(m)))
                .unwrap_or(false),

            PolicyCondition::TimeWindow { start, end } => {
                let now = chrono::Local::now().time();
                now >= *start && now <= *end
            }

            PolicyCondition::RateLimit { max, window_secs } => {
                if record {
                    self.check_rate_limit(input.credential_alias, *max, *window_secs)
                } else {
                    // Deferred (post-approval) evaluation: the slot was taken when
                    // the request first opened the approval; re-applying the limit
                    // would wrongly deny an already-approved action.
                    true
                }
            }

            PolicyCondition::SpendCap { asset, per_action_max } => {
                // Reached only if a SpendCap is (mis)nested inside and/or/not,
                // which Policy::validate rejects at load. Evaluate it purely as a
                // safety net — the authoritative check is a top-level SpendCap rule
                // in evaluate_inner.
                self.spend_within_cap(input.spend, asset, *per_action_max, record)
            }

            PolicyCondition::And(conditions) => conditions
                .iter()
                .all(|c| self.evaluate_condition(c, input, record)),

            PolicyCondition::Or(conditions) => conditions
                .iter()
                .any(|c| self.evaluate_condition(c, input, record)),

            PolicyCondition::Not(inner) => !self.evaluate_condition(inner, input, record),

            PolicyCondition::Always => true,
        }
    }

    /// Whether a spend attempt is within a `SpendCap` (per-action, stateless).
    ///
    /// - `check=false` (the deferred resume path): the attempt was already checked
    ///   when the approval opened, so return `true` (within) without re-checking.
    /// - A missing/unparseable amount or a mismatched asset fails **closed**
    ///   (false → leads to deny).
    ///
    /// There is no cumulative ledger: cumulative/windowed spend is the
    /// book-of-record's plane, pushed back as a `Deny` policy via the write API.
    fn spend_within_cap(
        &self,
        spend: Option<&SpendAttempt>,
        asset: &str,
        per_action_max: u64,
        check: bool,
    ) -> bool {
        if !check {
            return true;
        }
        let Some(spend) = spend else {
            tracing::warn!(
                asset = %asset,
                "spend_unparseable: a SpendCap applies but no spend amount was extracted from \
                 the request — failing closed (deny)"
            );
            return false;
        };
        // This cap governs a specific asset; a different asset isn't covered.
        if spend.asset != asset {
            return false;
        }
        // Per-call cap.
        spend.amount <= per_action_max
    }

    /// Check and update rate limit
    fn check_rate_limit(&self, credential_alias: &str, max: u32, window_secs: u64) -> bool {
        let mut limits = self.rate_limits.write();
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);

        let state = limits
            .entry(credential_alias.to_string())
            .or_insert_with(|| RateLimitState {
                count: 0,
                window_start: now,
            });

        // Check if we're in a new window
        if now.duration_since(state.window_start) >= window {
            state.count = 1;
            state.window_start = now;
            true
        } else if state.count < max {
            state.count += 1;
            true
        } else {
            false // Rate limit exceeded
        }
    }

    /// Record a request for rate limiting
    pub fn record_request(&self, credential_alias: &str) {
        let policies = self.policies.read();

        // Find rate limit conditions for this credential
        for policy in policies.iter() {
            if !credential_matches(&policy.credential_pattern, credential_alias) {
                continue;
            }

            for rule in &policy.rules {
                if let PolicyCondition::RateLimit { max, window_secs } = &rule.condition {
                    // Touch the rate limiter to record the request
                    self.check_rate_limit(credential_alias, *max, *window_secs);
                }
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a credential alias matches a pattern (glob-style)
fn credential_matches(pattern: &str, alias: &str) -> bool {
    glob_matches(pattern, alias)
}

/// Generic glob match: `*` matches anything; otherwise compile as a glob and
/// fall back to exact comparison if the pattern doesn't compile.
fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Ok(glob) = Pattern::new(pattern) {
        glob.matches(value)
    } else {
        pattern == value
    }
}

/// Whether a principal matches a policy's `principal_pattern` (V4). `None`
/// pattern applies to every principal; a `Some` pattern requires a present
/// principal whose id **or** agent label matches the glob (so a policy that
/// targets a principal never applies to a request that carries no principal).
fn principal_matches(pattern: Option<&str>, principal: Option<&Principal>) -> bool {
    match pattern {
        None => true,
        Some(pat) => match principal {
            None => false,
            Some(p) => {
                glob_matches(pat, &p.id)
                    || p.agent_label.as_deref().is_some_and(|l| glob_matches(pat, l))
            }
        },
    }
}

/// Extracts a [`SpendAttempt`] from a request's params for `SpendCap` evaluation
/// (V3). Matched by action + credential globs; reads the amount from a JSON
/// pointer (an integer in minor units) and the asset from a literal or a second
/// JSON pointer.
#[derive(Debug, Clone)]
pub struct SpendExtractor {
    pub action_pattern: String,
    pub credential_pattern: String,
    /// JSON pointer (RFC 6901) into the request params to the amount integer.
    pub amount_pointer: String,
    /// Literal asset, used when `asset_pointer` is not set.
    pub asset: Option<String>,
    /// JSON pointer to the asset string (takes precedence over `asset`).
    pub asset_pointer: Option<String>,
}

impl SpendExtractor {
    /// Whether this extractor applies to the given action + credential.
    pub fn matches(&self, action: &str, credential_alias: &str) -> bool {
        glob_matches(&self.action_pattern, action)
            && glob_matches(&self.credential_pattern, credential_alias)
    }

    /// Extract a [`SpendAttempt`] from params, or `None` if the amount/asset
    /// can't be read (which the caller treats as fail-closed for SpendCap).
    pub fn extract(&self, params: &serde_json::Value) -> Option<SpendAttempt> {
        let amount = params.pointer(&self.amount_pointer).and_then(|v| v.as_u64())?;
        let asset = match (&self.asset_pointer, &self.asset) {
            (Some(ptr), _) => params.pointer(ptr).and_then(|v| v.as_str())?.to_string(),
            (None, Some(lit)) => lit.clone(),
            (None, None) => return None,
        };
        Some(SpendAttempt { asset, amount })
    }
}

/// Run the first matching extractor over `params`. Returns the extracted
/// attempt, or `None` when **no** extractor applies OR a matching extractor
/// could not parse the amount/asset — both of which a `SpendCap` policy treats
/// as fail-closed (deny). The two cases are collapsed deliberately: if a
/// credential is governed by a spend cap, a missing extractor is as much a
/// misconfiguration as an unparseable body, and both must deny.
pub fn extract_spend(
    extractors: &[SpendExtractor],
    action: &str,
    credential_alias: &str,
    params: &serde_json::Value,
) -> Option<SpendAttempt> {
    extractors
        .iter()
        .find(|e| e.matches(action, credential_alias))
        .and_then(|e| e.extract(params))
}

/// Check if a URL matches a pattern
fn url_matches(url: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        url.starts_with(prefix)
    } else if let Ok(glob) = Pattern::new(pattern) {
        glob.matches(url)
    } else {
        url == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> RequestContext {
        RequestContext::new()
    }

    #[test]
    fn test_allow_when_no_policies_in_fail_open_mode() {
        // new() is fail-closed by default now; opt into legacy fail-open here.
        let engine = PolicyEngine::new();
        engine.set_default_deny(false);
        let decision = engine.evaluate("github-api", Some("https://api.github.com"), Some("GET"), &make_context());
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_new_engine_is_fail_closed_by_default() {
        // The secure default: a bare engine denies an un-policied credential.
        let engine = PolicyEngine::new();
        assert!(engine.default_deny());
        match engine.evaluate("x", Some("https://x"), Some("GET"), &make_context()) {
            PolicyDecision::Deny(r) => assert!(r.starts_with("no_policy:")),
            other => panic!("expected fail-closed Deny, got {other:?}"),
        }
    }

    #[test]
    fn test_default_deny_denies_unpolicied_credential() {
        let engine = PolicyEngine::new();
        engine.set_default_deny(true);
        assert!(engine.default_deny());

        // A credential with no matching policy is denied, with the distinct
        // machine-greppable `no_policy` reason.
        let decision =
            engine.evaluate("unpolicied", Some("https://api.example.com"), Some("GET"), &make_context());
        match decision {
            PolicyDecision::Deny(reason) => assert!(
                reason.starts_with("no_policy:"),
                "expected a no_policy deny reason, got: {reason}"
            ),
            other => panic!("expected Deny, got {other:?}"),
        }

        // An explicit allow policy still admits the request even in deny mode.
        engine.add_policy(Policy::allow_all("allow-it", "unpolicied"));
        assert_eq!(
            engine.evaluate("unpolicied", Some("https://api.example.com"), Some("GET"), &make_context()),
            PolicyDecision::Allow
        );

        // A credential matched by an explicit deny policy reports that policy's
        // reason, not the no_policy fallback.
        engine.add_policy(Policy::deny_all("block", "blocked-cred"));
        match engine.evaluate("blocked-cred", Some("https://x"), Some("GET"), &make_context()) {
            PolicyDecision::Deny(reason) => assert!(
                !reason.starts_with("no_policy:"),
                "an explicitly-denied credential should not use the no_policy reason: {reason}"
            ),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn test_readonly_evaluation_respects_default_deny() {
        // The deferred (post-approval) read-only path must also honor
        // fail-closed: an un-policied credential is denied there too.
        let engine = PolicyEngine::new();
        engine.set_default_deny(true);
        match engine.evaluate_readonly("unpolicied", Some("https://x"), Some("GET")) {
            PolicyDecision::Deny(reason) => assert!(reason.starts_with("no_policy:")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn test_has_resource_guard_detects_spend_rate_and_nested() {
        let input = EvalInput {
            credential_alias: "c",
            url: None,
            method: None,
            principal: None,
            spend: None,
        };
        // No policies → no guard.
        let engine = PolicyEngine::new();
        assert!(!engine.has_resource_guard(&input));

        // A RateLimit rule (action Allow — the common admit-within-limit pattern)
        // is still detected as a guard.
        let e_rl = PolicyEngine::new();
        e_rl.add_policy(
            Policy::deny_all("rl", "*")
                .with_rule(PolicyCondition::RateLimit { max: 1, window_secs: 60 }, PolicyAction::Allow),
        );
        assert!(e_rl.has_resource_guard(&input));

        // A SpendCap nested inside And[...] is detected (recursion).
        let e_sc = PolicyEngine::new();
        e_sc.add_policy(Policy::deny_all("sc", "*").with_rule(
            PolicyCondition::And(vec![
                PolicyCondition::UrlMatch("*".to_string()),
                PolicyCondition::SpendCap {
                    asset: "usd".to_string(),
                    per_action_max: 100,
                },
            ]),
            PolicyAction::Allow,
        ));
        assert!(e_sc.has_resource_guard(&input));

        // A non-guard policy (URL only) is NOT a resource guard.
        let e_url = PolicyEngine::new();
        e_url.add_policy(
            Policy::allow_all("u", "*")
                .with_rule(PolicyCondition::UrlMatch("*".to_string()), PolicyAction::Allow),
        );
        assert!(!e_url.has_resource_guard(&input));

        // A guard scoped to a different credential does NOT match this input.
        let e_other = PolicyEngine::new();
        e_other.add_policy(
            Policy::deny_all("rl", "other-*")
                .with_rule(PolicyCondition::RateLimit { max: 1, window_secs: 60 }, PolicyAction::Allow),
        );
        assert!(!e_other.has_resource_guard(&input));
    }

    #[test]
    fn test_kill_policy_overrides_allow_rule() {
        // V6: a kill policy is authoritative — it denies a matching principal even
        // when an allow policy with a matching allow RULE is ordered first (which
        // would otherwise short-circuit to Allow).
        let engine = PolicyEngine::new();
        engine.set_default_deny(false);
        // Ordered FIRST: a broad allow with an explicit allow rule.
        engine.add_policy(
            Policy::allow_all("allow-all", "*")
                .with_rule(PolicyCondition::UrlMatch("*".to_string()), PolicyAction::Allow),
        );
        // Then a kill policy scoped to agent "bot-7".
        engine.add_policy(Policy::kill_switch("halt:bot-7", "bot-7"));

        let halted = Principal { id: "k1".to_string(), agent_label: Some("bot-7".to_string()), owner: None };
        let decision = engine.evaluate_full(&EvalInput {
            credential_alias: "github-prod",
            url: Some("https://api.github.com/x"),
            method: Some("GET"),
            principal: Some(&halted),
            spend: None,
        });
        match decision {
            PolicyDecision::Deny(r) => assert!(r.contains("halted"), "reason: {r}"),
            other => panic!("kill must override the allow rule, got {other:?}"),
        }

        // A different agent is unaffected → the allow rule applies.
        let other = Principal { id: "k2".to_string(), agent_label: Some("bot-9".to_string()), owner: None };
        let decision = engine.evaluate_full(&EvalInput {
            credential_alias: "github-prod",
            url: Some("https://api.github.com/x"),
            method: Some("GET"),
            principal: Some(&other),
            spend: None,
        });
        assert_eq!(decision, PolicyDecision::Allow, "non-halted agent still allowed");

        // The kill is also authoritative on the read-only resume path.
        let resume = engine.evaluate_readonly_full(&EvalInput {
            credential_alias: "github-prod",
            url: Some("https://api.github.com/x"),
            method: Some("GET"),
            principal: Some(&halted),
            spend: None,
        });
        assert!(matches!(resume, PolicyDecision::Deny(_)), "kill applies on resume too");
    }

    #[test]
    fn test_url_pattern_matching() {
        let engine = PolicyEngine::new();
        engine.add_policy(Policy {
            id: "1".to_string(),
            name: "github-readonly".to_string(),
            credential_pattern: "github-*".to_string(),
            principal_pattern: None,
            rules: vec![
                PolicyRule {
                    condition: PolicyCondition::UrlMatch("https://api.github.com/*".to_string()),
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
            kill: false,
        });

        // Should allow GitHub API
        let decision = engine.evaluate(
            "github-api",
            Some("https://api.github.com/user"),
            Some("GET"),
            &make_context(),
        );
        assert_eq!(decision, PolicyDecision::Allow);

        // Should deny other URLs
        let decision = engine.evaluate(
            "github-api",
            Some("https://api.example.com/user"),
            Some("GET"),
            &make_context(),
        );
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_method_restriction() {
        let engine = PolicyEngine::new();
        engine.add_policy(Policy {
            id: "1".to_string(),
            name: "readonly".to_string(),
            credential_pattern: "*".to_string(),
            principal_pattern: None,
            rules: vec![
                PolicyRule {
                    condition: PolicyCondition::MethodMatch(vec!["GET".to_string(), "HEAD".to_string()]),
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
            kill: false,
        });

        let decision = engine.evaluate("any", Some("https://api.example.com"), Some("GET"), &make_context());
        assert_eq!(decision, PolicyDecision::Allow);

        let decision = engine.evaluate("any", Some("https://api.example.com"), Some("POST"), &make_context());
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_credential_pattern_matching() {
        assert!(credential_matches("*", "anything"));
        assert!(credential_matches("github-*", "github-api"));
        assert!(credential_matches("github-*", "github-token"));
        assert!(!credential_matches("github-*", "gitlab-api"));
        assert!(credential_matches("exact", "exact"));
        assert!(!credential_matches("exact", "not-exact"));
    }

    #[test]
    fn test_rate_limiting() {
        let engine = PolicyEngine::new();
        engine.add_policy(Policy {
            id: "1".to_string(),
            name: "rate-limit".to_string(),
            credential_pattern: "*".to_string(),
            principal_pattern: None,
            rules: vec![
                PolicyRule {
                    condition: PolicyCondition::RateLimit {
                        max: 3,
                        window_secs: 60,
                    },
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
            kill: false,
        });

        // First 3 requests should succeed
        for _ in 0..3 {
            let decision = engine.evaluate("test", Some("https://api.example.com"), Some("GET"), &make_context());
            assert_eq!(decision, PolicyDecision::Allow);
        }

        // 4th request should be denied (rate limit exceeded)
        let decision = engine.evaluate("test", Some("https://api.example.com"), Some("GET"), &make_context());
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_evaluate_readonly_does_not_charge_rate_limit() {
        let engine = PolicyEngine::new();
        engine.add_policy(Policy {
            id: "1".to_string(),
            name: "rate-limit".to_string(),
            credential_pattern: "*".to_string(),
            principal_pattern: None,
            rules: vec![PolicyRule {
                condition: PolicyCondition::RateLimit {
                    max: 1,
                    window_secs: 60,
                },
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Deny,
            kill: false,
        });

        // Read-only evaluation must neither consume the single unit of budget nor
        // fail against it — it is the deferred post-approval check, and the
        // request that opened the approval already holds the slot.
        for _ in 0..5 {
            assert_eq!(
                engine.evaluate_readonly("test", Some("https://api.example.com"), Some("GET")),
                PolicyDecision::Allow
            );
        }

        // The one *real* request still goes through (budget was untouched)...
        assert_eq!(
            engine.evaluate("test", Some("https://api.example.com"), Some("GET"), &make_context()),
            PolicyDecision::Allow
        );
        // ...and a read-only check after the budget is spent still passes,
        // because the deferred path never re-applies the rate limit.
        assert_eq!(
            engine.evaluate_readonly("test", Some("https://api.example.com"), Some("GET")),
            PolicyDecision::Allow
        );
    }

    // ==================== V4: principal dimension ====================

    fn input_spend<'a>(alias: &'a str, spend: &'a SpendAttempt) -> EvalInput<'a> {
        EvalInput { credential_alias: alias, url: None, method: None, principal: None, spend: Some(spend) }
    }

    fn spend_policy(asset: &str, per_action_max: u64) -> Policy {
        let mut p = Policy::deny_all("spend", "pay-*");
        p.rules = vec![PolicyRule {
            condition: PolicyCondition::SpendCap { asset: asset.to_string(), per_action_max },
            action: PolicyAction::Allow,
        }];
        p
    }

    #[test]
    fn test_principal_pattern_scopes_policy() {
        let engine = PolicyEngine::new();
        engine.set_default_deny(false); // isolate: unmatched → allow
        // Per-agent Deny for "refund-bot" only (kill-leg W3).
        engine.add_policy(Policy::deny_all("kill-refund-bot", "pay-*").with_principal("refund-bot"));

        let bot = Principal { id: "tok1".to_string(), agent_label: Some("refund-bot".to_string()), owner: None };
        let other = Principal { id: "tok2".to_string(), agent_label: Some("other-bot".to_string()), owner: None };
        let bot_in = EvalInput { credential_alias: "pay-1", url: None, method: None, principal: Some(&bot), spend: None };
        let other_in = EvalInput { credential_alias: "pay-1", url: None, method: None, principal: Some(&other), spend: None };
        let none_in = EvalInput { credential_alias: "pay-1", url: None, method: None, principal: None, spend: None };
        // refund-bot is denied; other agents and principal-less requests are not.
        assert!(matches!(engine.evaluate_full(&bot_in), PolicyDecision::Deny(_)));
        assert_eq!(engine.evaluate_full(&other_in), PolicyDecision::Allow);
        assert_eq!(engine.evaluate_full(&none_in), PolicyDecision::Allow);
    }

    #[test]
    fn test_legacy_evaluate_matches_per_agent_via_context() {
        // The legacy 4-arg evaluate derives the full principal (id + agent_label)
        // from RequestContext, so per-agent policies match through it too.
        let engine = PolicyEngine::new();
        engine.set_default_deny(false);
        engine.add_policy(Policy::deny_all("kill", "api-*").with_principal("bot"));
        let mut ctx = make_context();
        ctx.api_key_id = Some("tok1".to_string());
        ctx.agent_label = Some("bot".to_string());
        assert!(matches!(
            engine.evaluate("api-1", Some("https://x"), Some("GET"), &ctx),
            PolicyDecision::Deny(_)
        ));
        // Without the label the per-agent deny doesn't match (fail-open allow).
        ctx.agent_label = None;
        assert_eq!(
            engine.evaluate("api-1", Some("https://x"), Some("GET"), &ctx),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn test_principal_pattern_matches_id_too() {
        let engine = PolicyEngine::new();
        engine.set_default_deny(false);
        engine.add_policy(Policy::deny_all("kill-by-id", "*").with_principal("tok-*"));
        let p = Principal { id: "tok-abc".to_string(), agent_label: None, owner: None };
        assert!(matches!(
            engine.evaluate_full(&EvalInput { credential_alias: "any", url: None, method: None, principal: Some(&p), spend: None }),
            PolicyDecision::Deny(_)
        ));
    }

    // ==================== V3: spend caps ====================

    #[test]
    fn test_spend_cap_per_action() {
        let engine = PolicyEngine::new();
        engine.add_policy(spend_policy("usd", 5000));
        let within = SpendAttempt { asset: "usd".to_string(), amount: 5000 };
        let over = SpendAttempt { asset: "usd".to_string(), amount: 5001 };
        assert_eq!(engine.evaluate_full(&input_spend("pay-1", &within)), PolicyDecision::Allow);
        assert!(matches!(engine.evaluate_full(&input_spend("pay-1", &over)), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_spend_cap_unparseable_fails_closed() {
        let engine = PolicyEngine::new();
        engine.add_policy(spend_policy("usd", 100));
        // No spend attempt extracted → SpendCap false → default Deny.
        let no_spend = EvalInput { credential_alias: "pay-1", url: None, method: None, principal: None, spend: None };
        assert!(matches!(engine.evaluate_full(&no_spend), PolicyDecision::Deny(_)));
        // Wrong asset also doesn't satisfy the cap → deny.
        let eur = SpendAttempt { asset: "eur".to_string(), amount: 1 };
        assert!(matches!(engine.evaluate_full(&input_spend("pay-1", &eur)), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_spend_check_is_stateless() {
        // Per-action only: the check has no ledger, so an in-cap amount passes
        // every time, on both the recording and read-only paths, and a prior
        // over-cap denial leaves no residue that affects a later in-cap call.
        let engine = PolicyEngine::new();
        engine.add_policy(spend_policy("usd", 100));
        let eighty = SpendAttempt { asset: "usd".to_string(), amount: 80 };
        let over = SpendAttempt { asset: "usd".to_string(), amount: 101 };
        for _ in 0..5 {
            assert_eq!(engine.evaluate_full(&input_spend("pay-1", &eighty)), PolicyDecision::Allow);
            assert_eq!(engine.evaluate_readonly_full(&input_spend("pay-1", &eighty)), PolicyDecision::Allow);
        }
        assert!(matches!(engine.evaluate_full(&input_spend("pay-1", &over)), PolicyDecision::Deny(_)));
        assert_eq!(engine.evaluate_full(&input_spend("pay-1", &eighty)), PolicyDecision::Allow);
    }

    #[test]
    fn test_spend_extractor() {
        let ext = SpendExtractor {
            action_pattern: "http.request".to_string(),
            credential_pattern: "stripe-*".to_string(),
            amount_pointer: "/body/amount".to_string(),
            asset: Some("usd".to_string()),
            asset_pointer: None,
        };
        let got = ext.extract(&serde_json::json!({"body": {"amount": 4200}})).unwrap();
        assert_eq!(got.amount, 4200);
        assert_eq!(got.asset, "usd");
        // Missing amount → None (fail-closed upstream).
        assert!(ext.extract(&serde_json::json!({"body": {}})).is_none());

        // extract_spend matches by action + credential globs; asset via pointer.
        let by_ptr = SpendExtractor {
            asset: None,
            asset_pointer: Some("/currency".to_string()),
            ..ext
        };
        let attempt = extract_spend(
            std::slice::from_ref(&by_ptr),
            "http.request",
            "stripe-prod",
            &serde_json::json!({"body": {"amount": 7}, "currency": "eur"}),
        )
        .unwrap();
        assert_eq!(attempt.amount, 7);
        assert_eq!(attempt.asset, "eur");
        // A non-matching action yields no extractor → None.
        assert!(extract_spend(std::slice::from_ref(&by_ptr), "postgres.run_sql", "stripe-prod", &serde_json::json!({})).is_none());
    }

    #[test]
    fn test_spend_cap_validation() {
        // Valid: top-level SpendCap, default_action deny.
        assert!(spend_policy("usd", 100).validate().is_ok());

        // A cap but default action allow → rejected (not fail-closed).
        let mut not_closed = spend_policy("usd", 1);
        not_closed.default_action = PolicyAction::Allow;
        assert!(not_closed.validate().is_err());

        // Nested SpendCap (inside And) → rejected.
        let mut nested = Policy::deny_all("nested", "pay-*");
        nested.rules = vec![PolicyRule {
            condition: PolicyCondition::And(vec![
                PolicyCondition::url("https://x/*"),
                PolicyCondition::SpendCap { asset: "usd".into(), per_action_max: 1 },
            ]),
            action: PolicyAction::Allow,
        }];
        assert!(nested.validate().is_err());

        // Empty asset → rejected.
        assert!(spend_policy("", 1).validate().is_err());
    }
}
