//! VUL-32: the broadening of a url_match never turns a request that the engine without it
//! would DENY into a Prompt. The shape under test is the one govder compiles for a gated money
//! action and feir-os ships in `deploy/connectors/capabilities.yaml` and the packs: a policy
//! whose default is Deny, holding a Prompt rule `and(url_match <exact glob>, method POST)`.
//! Only the exact URL reaches an approver; a query or a trailing slash on it stays Denied.

use vultrino::policy::{
    Policy, PolicyAction, PolicyCondition, PolicyDecision, PolicyEngine, PolicyRule,
};

const GLOBS: &[&str] = &[
    "https://api.payments.example/v1/refunds",
    "https://api.payments.example/v1/payouts",
    "https://api.payments.example/v1/kyc/check",
    "https://api.payments.example/v1/filings",
    "https://api.payments.example/v1/messages",
    "/v1/refunds",
    "/v1/payouts",
    "/v1/kyc/check",
    "/v1/filings",
    "/v1/messages",
];

fn prompt_policy(glob: &str) -> Policy {
    let mut p = Policy::allow_all("govder-gated", "*");
    p.default_action = PolicyAction::Deny;
    p.rules = vec![PolicyRule {
        condition: PolicyCondition::And(vec![
            PolicyCondition::UrlMatch(glob.to_string()),
            PolicyCondition::MethodMatch(vec!["POST".to_string()]),
        ]),
        action: PolicyAction::Prompt,
    }];
    p
}

fn decide(e: &PolicyEngine, url: &str) -> &'static str {
    match e.evaluate_readonly("cred", Some(url), Some("POST")) {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Prompt => "prompt",
        PolicyDecision::Deny(_) => "deny",
    }
}

#[test]
fn query_and_slash_variants_of_a_govder_exact_prompt_stay_denied() {
    for glob in GLOBS {
        let e = PolicyEngine::new();
        e.add_policy(prompt_policy(glob));
        assert_eq!(
            decide(&e, glob),
            "prompt",
            "the exact URL is the one that prompts: {glob}"
        );
        for suffix in [
            "?to=acct_evil",
            "/",
            "/?amount=999999",
            "?a=1&b=2",
            "X",
            "?confirm=true&dest=evil",
        ] {
            let url = format!("{glob}{suffix}");
            assert_eq!(
                decide(&e, &url),
                "deny",
                "{url} must stay denied under {glob}"
            );
        }
    }
}

#[test]
fn a_second_policys_allow_cannot_skip_the_exact_prompt_but_never_makes_a_deny_a_prompt() {
    for glob in GLOBS {
        let e = PolicyEngine::new();
        e.add_policy(prompt_policy(glob));
        // A broader policy for the same credential that allows everything under the host.
        let mut allow = Policy::allow_all("allow-all", "*");
        allow.rules = vec![PolicyRule {
            condition: PolicyCondition::Always,
            action: PolicyAction::Allow,
        }];
        e.add_policy(allow);
        // Allow outcome with a broadened Prompt match: the upgrade to Prompt is the strict way.
        assert_eq!(decide(&e, glob), "prompt", "{glob}");
        let q = format!("{glob}?to=acct_evil");
        assert_eq!(
            decide(&e, &q),
            "prompt",
            "a query on the gated URL is not allowed past: {q}"
        );
        let s = format!("{glob}/");
        assert_eq!(decide(&e, &s), "prompt", "{s}");
        // A URL the rule does not concern is allowed by the second policy, as before.
        assert_eq!(decide(&e, "https://api.payments.example/v1/other"), "allow");
    }
}
