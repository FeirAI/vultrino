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

    /// Allow only during specific time window
    TimeWindow {
        start: NaiveTime,
        end: NaiveTime,
    },

    /// Rate limit (requests per window)
    RateLimit {
        max: u32,
        window_secs: u64,
    },

    /// Spend cap (V3): the request's extracted amount (in minor units, e.g.
    /// cents/micros) must be within `per_action_max` for this single call and
    /// within `cumulative_max` summed over the rolling `window_secs`, for the
    /// matching `asset`. Matches (true) only when the request carries a spend
    /// attempt for this asset within the caps; a missing/unparseable amount or
    /// mismatched asset fails **closed** (false → leads to deny).
    SpendCap {
        /// Asset this cap governs (e.g. "usd"). Must equal the attempt's asset.
        asset: String,
        /// Max for a single call (minor units). `None` = no per-call limit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        per_action_max: Option<u64>,
        /// Max summed over `window_secs` (minor units). `None` = no cumulative limit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cumulative_max: Option<u64>,
        /// Rolling window (seconds) for the cumulative cap.
        window_secs: u64,
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
    ///   and/or/not) — the engine charges exactly the firing cap, and a nested
    ///   cap would gate without charging (fail-open for the cumulative window);
    /// - a `SpendCap` must set at least one of `per_action_max`/`cumulative_max`;
    /// - a policy that uses a `SpendCap` rule must be fail-closed
    ///   (`default_action = deny`), so an over-cap or unparseable request falls
    ///   through to deny rather than being allowed.
    pub fn validate(&self) -> Result<(), String> {
        let mut uses_spend_cap = false;
        for rule in &self.rules {
            if let PolicyCondition::SpendCap {
                asset,
                per_action_max,
                cumulative_max,
                window_secs,
            } = &rule.condition
            {
                uses_spend_cap = true;
                if per_action_max.is_none() && cumulative_max.is_none() {
                    return Err(format!(
                        "policy '{}': SpendCap must set per_action_max and/or cumulative_max",
                        self.name
                    ));
                }
                if asset.trim().is_empty() {
                    return Err(format!("policy '{}': SpendCap asset must not be empty", self.name));
                }
                // A zero window makes the cumulative cap a no-op (every charge is
                // immediately pruned), silently failing open.
                if cumulative_max.is_some() && *window_secs == 0 {
                    return Err(format!(
                        "policy '{}': SpendCap window_secs must be > 0 when cumulative_max is set",
                        self.name
                    ));
                }
            } else if condition_nests_spend_cap(&rule.condition) {
                return Err(format!(
                    "policy '{}': SpendCap must be a rule's top-level condition, not nested in and/or/not",
                    self.name
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
        let policy = Policy::deny_all("github-readonly", "github-*")
            .with_rule(
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
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, policy.id);
        assert_eq!(parsed.name, policy.name);
    }
}
