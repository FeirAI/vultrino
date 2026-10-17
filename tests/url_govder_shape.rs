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

/// govder compiles a rate-limited gated action as `and(action_match, url_match, method,
/// rate_limit)` Prompt under a Deny default. A request that ends Denied through a URL variant
/// must never charge the rule's rate limit, or probing locks the agent out of its own gated
/// action for the window.
#[test]
fn denied_url_variants_do_not_charge_a_prompt_rules_rate_limit() {
    use vultrino::policy::EvalInput;
    let url = "https://api.payments.example/v1/refunds";
    let mut p = Policy::allow_all("govder-gated", "*");
    p.default_action = PolicyAction::Deny;
    p.rules = vec![PolicyRule {
        condition: PolicyCondition::And(vec![
            PolicyCondition::ActionMatch("payments.refund".to_string()),
            PolicyCondition::UrlMatch(url.to_string()),
            PolicyCondition::MethodMatch(vec!["POST".to_string()]),
            PolicyCondition::RateLimit {
                max: 2,
                window_secs: 3600,
            },
        ]),
        action: PolicyAction::Prompt,
    }];
    let e = PolicyEngine::new();
    e.add_policy(p);
    let eval = |u: &str| {
        let input = EvalInput {
            credential_alias: "cred",
            url: Some(u),
            method: Some("POST"),
            action: Some("payments.refund"),
            principal: None,
            spend: None,
        };
        match e.evaluate_full(&input) {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Prompt => "prompt",
            PolicyDecision::Deny(_) => "deny",
        }
    };
    for _ in 0..5 {
        assert_eq!(eval(&format!("{url}?to=evil")), "deny");
        assert_eq!(eval(&format!("{url}/")), "deny");
    }
    assert_eq!(eval(url), "prompt", "variants must not have used the slot");
    assert_eq!(eval(url), "prompt");
    assert_eq!(eval(url), "deny", "the real limit still applies");
}

/// Reverse proxies merge repeated slashes and some servers decode `%2F`: a Deny written for
/// the plain path covers those spellings too (VUL-32).
#[test]
fn empty_segments_and_encoded_slashes_stay_denied() {
    for (pat, urls) in [
        (
            "https://api.example.com/v1/refunds*",
            &[
                "https://api.example.com//v1/refunds",
                "https://api.example.com/v1//refunds",
                "https://api.example.com/v1%2Frefunds",
                "https://api.example.com/v1%2frefunds?x=1",
            ][..],
        ),
        (
            "https://api.example.com/admin*",
            &[
                "https://api.example.com//admin",
                "https://api.example.com/%2Fadmin",
                "https://api.example.com/;x=1/admin",
                "https://api.example.com/x/..%2Fadmin",
            ][..],
        ),
    ] {
        for u in urls {
            let e = PolicyEngine::new();
            let mut p = Policy::allow_all("p", "*");
            p.rules = vec![PolicyRule {
                condition: PolicyCondition::UrlMatch(pat.to_string()),
                action: PolicyAction::Deny,
            }];
            e.add_policy(p);
            assert_eq!(decide(&e, u), "deny", "{pat} vs {u}");
        }
    }
}
