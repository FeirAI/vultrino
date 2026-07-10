//! Policy data structures

use chrono::NaiveTime;
use serde::{Deserialize, Serialize};

/// A security policy for credential access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Pattern for matching credential aliases (glob-style: "github-*", "*")
    pub credential_pattern: String,
    /// Optional glob over the presenting **principal** (V4): the `vk_`/`vut_`
    /// id or an `agent_label` carried on the token. `None` applies to any
    /// principal; `Some(pattern)` applies only to principals matching the glob
    /// (so a per-agent Deny — kill-leg W3 — is expressible). A request with no
    /// principal never matches a policy that has a `principal_pattern`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_pattern: Option<String>,
    /// Rules to evaluate in order
    pub rules: Vec<PolicyRule>,
    /// Action when no rules match
    pub default_action: PolicyAction,
    /// **Kill switch** (V6): when true, this policy is an *authoritative*
    /// unconditional Deny for every principal+credential it matches, evaluated
    /// **before** all non-kill policies — so a halt can't be overridden by an
    /// allow rule that happens to be ordered first. Used by the per-agent halt
    /// (`POST /api/v1/agents/{label}/halt`), which installs one with
    /// `principal_pattern` = the agent label.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kill: bool,
}

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Condition to evaluate
    pub condition: PolicyCondition,
    /// Action to take if condition matches
    pub action: PolicyAction,
}

/// Conditions for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Match URL pattern (glob-style)
    UrlMatch(String),

    /// Match HTTP methods
    MethodMatch(Vec<String>),

    /// Match the request's business ACTION label (V8) against a glob. The govder
    /// connector compiler AND-clamps this onto each per-capability rule so the
    /// GRANTED action is enforced in-path — not merely via the use-token's
    /// (collapsible) action_scope. A request whose action does not match (e.g. an
    /// ungranted action issued against a granted URL/method envelope, or the
    /// generic `http.request` against a `web.read` grant) fails this condition and
    /// falls through to default-deny.
    ActionMatch(String),

    /// Allow only during specific time window
    TimeWindow { start: NaiveTime, end: NaiveTime },

    /// Rate limit (requests per window)
    RateLimit { max: u32, window_secs: u64 },

    /// Spend cap (V3): the request's extracted amount (in minor units, e.g.
    /// cents/micros) must be within `per_action_max` for this single call, for the
    /// matching `asset`. Matches (true) only when the request carries a spend
    /// attempt for this asset within the cap; a missing/unparseable amount or
    /// mismatched asset fails **closed** (false → leads to deny).
    ///
    /// **Per-action only — vultrino's spend check is stateless.** There is no
    /// cumulative/windowed ledger here: cumulative/budget enforcement is the
    /// book-of-record's plane (govder decision D4), and arrives as a `Deny` policy
    /// pushed through the V1/V4 write API when a budget is exhausted.
    SpendCap {
        /// Asset this cap governs (e.g. "usd"). Must equal the attempt's asset.
        asset: String,
        /// Max for a single call (minor units). Must be `> 0` (enforced by
        /// [`Policy::validate`] on create). `#[serde(default)]` is purely for
        /// forward-compatible *vault loads*: a policy persisted under the pre-R1
        /// schema as a cumulative-only cap (no `per_action_max`) deserializes to `0`
        /// — fail-closed against every positive spend, surfacing the stale policy
        /// for the operator to fix — rather than failing the whole encrypted-vault
        /// load. validate does not run on stored policies, so the 0 is tolerated
        /// only there; a freshly-created cap (config/admin API) with `0` or a
        /// missing value is rejected. Extra legacy keys (`cumulative_max`/
        /// `window_secs`) are ignored on load.
        #[serde(default)]
        per_action_max: u64,
    },

    /// All conditions must match
    And(Vec<PolicyCondition>),

    /// Any condition must match
    Or(Vec<PolicyCondition>),

    /// Negate a condition
    Not(Box<PolicyCondition>),

    /// Always matches (for default rules)
    Always,
}

/// Action to take based on policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow the request
    Allow,
    /// Deny the request
    Deny,
    /// Prompt user for approval (future feature)
    Prompt,
}

impl Policy {
    /// Create a new policy that allows all requests
    pub fn allow_all(name: impl Into<String>, credential_pattern: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            credential_pattern: credential_pattern.into(),
            principal_pattern: None,
            rules: vec![],
            default_action: PolicyAction::Allow,
            kill: false,
        }
    }

    /// Create a new policy that denies all requests by default
    pub fn deny_all(name: impl Into<String>, credential_pattern: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            credential_pattern: credential_pattern.into(),
            principal_pattern: None,
            rules: vec![],
            default_action: PolicyAction::Deny,
            kill: false,
        }
    }

    /// Create an authoritative per-principal **kill** policy (V6): denies every
    /// request from principals matching `principal_pattern`, on any credential,
    /// ahead of all non-kill policies. `id` is fixed so re-halting is idempotent.
    pub fn kill_switch(id: impl Into<String>, principal_pattern: impl Into<String>) -> Self {
        let pattern = principal_pattern.into();
        Self {
            id: id.into(),
            name: format!("halt {}", pattern),
            credential_pattern: "*".to_string(),
            principal_pattern: Some(pattern),
            rules: vec![],
            default_action: PolicyAction::Deny,
            kill: true,
        }
    }

    /// Add a rule to the policy
    pub fn with_rule(mut self, condition: PolicyCondition, action: PolicyAction) -> Self {
        self.rules.push(PolicyRule { condition, action });
        self
    }

    /// Scope this policy to principals matching the given glob (V4).
    pub fn with_principal(mut self, pattern: impl Into<String>) -> Self {
        self.principal_pattern = Some(pattern.into());
        self
    }

    /// Validate structural invariants for the spend-cap feature (V3), so a
    /// misconfigured cap can't silently fail open. Enforced at config load and
    /// by the admin API:
    /// - a `SpendCap` must be a rule's **top-level** condition (not nested in
    ///   and/or/not) — the engine evaluates exactly the firing cap, and a nested
    ///   cap would gate ambiguously;
    /// - a `SpendCap`'s `asset` must be non-empty;
    /// - a `SpendCap`'s `per_action_max` must be `> 0` — a 0 cap admits only a
    ///   zero-amount spend (express "no spend" as a `Deny` instead). This also
    ///   closes the admin-API edge where a missing `per_action_max` would
    ///   `#[serde(default)]` to 0 (validate runs on create, so a fresh cap can't be
    ///   0; only a pre-R1 cumulative-only policy *loaded from the vault* — where
    ///   validate does not run — defaults to a fail-closed 0 cap, by design);
    /// - a policy that uses a `SpendCap` rule must be fail-closed
    ///   (`default_action = deny`), so an over-cap or unparseable request falls
    ///   through to deny rather than being allowed.
    pub fn validate(&self) -> Result<(), String> {
        let mut uses_spend_cap = false;
        for rule in &self.rules {
            if let PolicyCondition::SpendCap {
                asset,
                per_action_max,
            } = &rule.condition
            {
                uses_spend_cap = true;
                if asset.trim().is_empty() {
                    return Err(format!(
                        "policy '{}': SpendCap asset must not be empty",
                        self.name
                    ));
                }
                if *per_action_max == 0 {
                    return Err(format!(
                        "policy '{}': SpendCap per_action_max must be > 0 (use a Deny rule to forbid spend)",
                        self.name
                    ));
                }
            } else if condition_nests_spend_cap(&rule.condition) {
                return Err(format!(
                    "policy '{}': SpendCap must be a rule's top-level condition, not nested in and/or/not",
                    self.name
                ));
            }
            // Reject an ambiguous `start == end` TimeWindow (top-level or nested):
            // it can't be told apart from an empty window vs. an all-day one, and the
            // wrap-around evaluator would treat it as a single instant. Fail loudly at
            // load rather than silently mis-gating. (For "always" use `Always`; for a
            // near-instant window use a 1-minute span.)
            if let Some((start, end)) = condition_degenerate_time_window(&rule.condition) {
                return Err(format!(
                    "policy '{}': TimeWindow start ({}) must not equal end ({}) — \
                     use a real span, or `Always` for all-day",
                    self.name, start, end
                ));
            }
        }
        if uses_spend_cap && self.default_action != PolicyAction::Deny {
            return Err(format!(
                "policy '{}': a policy with a SpendCap rule must use default_action = \"deny\" (fail-closed)",
                self.name
            ));
        }
        Ok(())
    }
}

/// Whether a condition tree nests a `SpendCap` inside and/or/not (which is
/// rejected — SpendCap must be a rule's top-level condition).
fn condition_nests_spend_cap(c: &PolicyCondition) -> bool {
    match c {
        PolicyCondition::And(cs) | PolicyCondition::Or(cs) => cs.iter().any(contains_spend_cap),
        PolicyCondition::Not(inner) => contains_spend_cap(inner),
        _ => false,
    }
}

fn contains_spend_cap(c: &PolicyCondition) -> bool {
    match c {
        PolicyCondition::SpendCap { .. } => true,
        PolicyCondition::And(cs) | PolicyCondition::Or(cs) => cs.iter().any(contains_spend_cap),
        PolicyCondition::Not(inner) => contains_spend_cap(inner),
        _ => false,
    }
}

/// Find a degenerate (`start == end`) `TimeWindow` anywhere in a condition tree,
/// returning its `(start, end)` for the error message. Recurses through and/or/not
/// so a nested window is caught too.
fn condition_degenerate_time_window(c: &PolicyCondition) -> Option<(NaiveTime, NaiveTime)> {
    match c {
        PolicyCondition::TimeWindow { start, end } if start == end => Some((*start, *end)),
        PolicyCondition::And(cs) | PolicyCondition::Or(cs) => {
            cs.iter().find_map(condition_degenerate_time_window)
        }
        PolicyCondition::Not(inner) => condition_degenerate_time_window(inner),
        _ => None,
    }
}

impl PolicyCondition {
    /// Create a URL match condition
    pub fn url(pattern: impl Into<String>) -> Self {
        Self::UrlMatch(pattern.into())
    }

    /// Create a method match condition for read-only operations
    pub fn read_only() -> Self {
        Self::MethodMatch(vec![
            "GET".to_string(),
            "HEAD".to_string(),
            "OPTIONS".to_string(),
        ])
    }

    /// Create a method match condition for write operations
    pub fn write_methods() -> Self {
        Self::MethodMatch(vec![
            "POST".to_string(),
            "PUT".to_string(),
            "PATCH".to_string(),
            "DELETE".to_string(),
        ])
    }

    /// Create a rate limit condition
    pub fn rate_limit(max: u32, window_secs: u64) -> Self {
        Self::RateLimit { max, window_secs }
    }

    /// Combine conditions with AND
    pub fn and(conditions: Vec<PolicyCondition>) -> Self {
        Self::And(conditions)
    }

    /// Combine conditions with OR
    pub fn or(conditions: Vec<PolicyCondition>) -> Self {
        Self::Or(conditions)
    }

    /// Negate a condition
    pub fn negate(condition: PolicyCondition) -> Self {
        Self::Not(Box::new(condition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_builder() {
        let policy = Policy::deny_all("github-readonly", "github-*").with_rule(
            PolicyCondition::and(vec![
                PolicyCondition::url("https://api.github.com/*"),
                PolicyCondition::read_only(),
            ]),
            PolicyAction::Allow,
        );

        assert_eq!(policy.name, "github-readonly");
        assert_eq!(policy.credential_pattern, "github-*");
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.default_action, PolicyAction::Deny);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: "test-id".to_string(),
            name: "test".to_string(),
            credential_pattern: "*".to_string(),
            principal_pattern: None,
            rules: vec![PolicyRule {
                condition: PolicyCondition::UrlMatch("https://*".to_string()),
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Deny,
            kill: false,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, policy.id);
        assert_eq!(parsed.name, policy.name);
    }
}
