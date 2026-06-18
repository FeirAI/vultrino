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
    /// The engine starts **fail-open** (an un-policied credential is allowed) to
    /// preserve the historical default for direct constructors and tests. The
    /// server flips this to fail-closed from `[enforcement] default_action`
    /// (which itself defaults to `deny`) via [`Self::set_default_deny`].
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            rate_limits: RwLock::new(HashMap::new()),
            default_deny: AtomicBool::new(false),
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
        self.default_deny.store(deny, Ordering::Relaxed);
    }

    /// Whether the engine denies credentials that match no policy.
    pub fn default_deny(&self) -> bool {
        self.default_deny.load(Ordering::Relaxed)
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

    /// Evaluate a request against all applicable policies
    pub fn evaluate(
        &self,
        credential_alias: &str,
        url: Option<&str>,
        method: Option<&str>,
        _context: &RequestContext,
    ) -> PolicyDecision {
        self.evaluate_inner(credential_alias, url, method, true)
    }

    /// Like [`Self::evaluate`] but with **no side effects**: a `RateLimit`
    /// condition is treated as already-admitted (within limit) instead of being
    /// counted. Used by the deferred post-approval path
    /// ([`crate::server::VultrinoServer::resume_approved`]) to re-enforce hard
    /// deny gates (url/method/time/explicit deny) at execution time without
    /// re-charging — or re-failing against — the rate limiter that the original
    /// request already accounted for.
    pub fn evaluate_readonly(
        &self,
        credential_alias: &str,
        url: Option<&str>,
        method: Option<&str>,
    ) -> PolicyDecision {
        self.evaluate_inner(credential_alias, url, method, false)
    }

    fn evaluate_inner(
        &self,
        credential_alias: &str,
        url: Option<&str>,
        method: Option<&str>,
        record_rate: bool,
    ) -> PolicyDecision {
        let policies = self.policies.read();

        // Find policies that match this credential
        let matching_policies: Vec<_> = policies
            .iter()
            .filter(|p| credential_matches(&p.credential_pattern, credential_alias))
            .collect();

        // If no policies match, fall back to the configured engine default.
        // Fail-closed (default-deny) denies an un-policied credential with a
        // distinct `no_policy` reason so callers (e.g. govder) can tell
        // "denied by an explicit policy" from "denied: no policy covers this
        // credential at all". Fail-open keeps the legacy allow behavior.
        if matching_policies.is_empty() {
            if self.default_deny.load(Ordering::Relaxed) {
                return PolicyDecision::Deny(format!(
                    "no_policy: no policy matches credential '{}' (default-deny enforcement)",
                    credential_alias
                ));
            }
            return PolicyDecision::Allow;
        }

        // Evaluate each matching policy
        for policy in matching_policies {
            // Check each rule in order
            for rule in &policy.rules {
                if self.evaluate_condition(&rule.condition, url, method, credential_alias, record_rate) {
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

            // No rules matched, use default action
            match policy.default_action {
                PolicyAction::Allow => continue, // Check next policy
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

    /// Evaluate a single condition
    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        url: Option<&str>,
        method: Option<&str>,
        credential_alias: &str,
        record_rate: bool,
    ) -> bool {
        match condition {
            PolicyCondition::UrlMatch(pattern) => {
                if let Some(url) = url {
                    url_matches(url, pattern)
                } else {
                    false
                }
            }

            PolicyCondition::MethodMatch(methods) => {
                if let Some(method) = method {
                    methods.iter().any(|m| m.eq_ignore_ascii_case(method))
                } else {
                    false
                }
            }

            PolicyCondition::TimeWindow { start, end } => {
                let now = chrono::Local::now().time();
                now >= *start && now <= *end
            }

            PolicyCondition::RateLimit { max, window_secs } => {
                if record_rate {
                    self.check_rate_limit(credential_alias, *max, *window_secs)
                } else {
                    // Deferred (post-approval) evaluation: this request was
                    // already admitted by the rate limiter when it first opened
                    // the approval, so its slot is taken. Re-applying the limit
                    // here would wrongly deny an already-approved action (and a
                    // small `max` would deny it every time). Treat it as
                    // within-limit; only hard rules (url/method/time/deny) gate.
                    true
                }
            }

            PolicyCondition::And(conditions) => conditions
                .iter()
                .all(|c| self.evaluate_condition(c, url, method, credential_alias, record_rate)),

            PolicyCondition::Or(conditions) => conditions
                .iter()
                .any(|c| self.evaluate_condition(c, url, method, credential_alias, record_rate)),

            PolicyCondition::Not(inner) => {
                !self.evaluate_condition(inner, url, method, credential_alias, record_rate)
            }

            PolicyCondition::Always => true,
        }
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
    if pattern == "*" {
        return true;
    }

    if let Ok(glob) = Pattern::new(pattern) {
        glob.matches(alias)
    } else {
        pattern == alias
    }
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
    fn test_allow_when_no_policies() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate("github-api", Some("https://api.github.com"), Some("GET"), &make_context());
        assert_eq!(decision, PolicyDecision::Allow);
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
    fn test_url_pattern_matching() {
        let engine = PolicyEngine::new();
        engine.add_policy(Policy {
            id: "1".to_string(),
            name: "github-readonly".to_string(),
            credential_pattern: "github-*".to_string(),
            rules: vec![
                PolicyRule {
                    condition: PolicyCondition::UrlMatch("https://api.github.com/*".to_string()),
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
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
            rules: vec![
                PolicyRule {
                    condition: PolicyCondition::MethodMatch(vec!["GET".to_string(), "HEAD".to_string()]),
                    action: PolicyAction::Allow,
                },
            ],
            default_action: PolicyAction::Deny,
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
            rules: vec![PolicyRule {
                condition: PolicyCondition::RateLimit {
                    max: 1,
                    window_secs: 60,
                },
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Deny,
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
}
