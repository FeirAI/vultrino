//! The typed cause of a policy Deny (feir-ops#1). The refusal record's reason class comes from
//! these facts, never from the message text, so each cause is pinned here against the engine.

use super::*;
use crate::refusal::RefusalClass;

const CRED: &str = "cred";

fn eval(
    engine: &PolicyEngine,
    params: &serde_json::Value,
    spend: Option<&SpendAttempt>,
    principal: Option<&Principal>,
) -> Evaluation {
    engine.evaluate_for_admission(
        &AdmissionQuery {
            credential_alias: CRED,
            action: "mock.echo",
            params,
            principal,
            spend,
        },
        false,
    )
}

fn principal(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        agent_label: None,
        owner: None,
        workload_id: None,
    }
}

fn class_of(e: &Evaluation) -> RefusalClass {
    e.deny_cause()
        .expect("a Deny carries a typed cause")
        .refusal_class()
}

#[test]
fn a_kill_switch_is_a_halt_and_a_kill_fence_refusal() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::kill_switch("halt:p1", "p1"));
    let p = principal("p1");
    let e = eval(&engine, &serde_json::json!({}), None, Some(&p));
    assert!(matches!(e.decision(), PolicyDecision::Deny(_)));
    assert_eq!(e.deny_cause(), Some(DenyCause::Halt));
    assert_eq!(class_of(&e), RefusalClass::KillFence);
}

#[test]
fn a_matching_deny_rule_is_a_rule_cause_and_a_policy_deny() {
    let engine = PolicyEngine::new();
    engine.add_policy(
        Policy::allow_all("p", CRED).with_rule(PolicyCondition::Always, PolicyAction::Deny),
    );
    let e = eval(&engine, &serde_json::json!({}), None, None);
    assert_eq!(e.deny_cause(), Some(DenyCause::Rule));
    assert_eq!(class_of(&e), RefusalClass::PolicyDeny);
}

#[test]
fn no_matching_rule_under_a_deny_default_is_the_default_cause() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::deny_all("p", CRED));
    let e = eval(&engine, &serde_json::json!({}), None, None);
    assert_eq!(e.deny_cause(), Some(DenyCause::Default));
    assert_eq!(class_of(&e), RefusalClass::PolicyDeny);
    // And with no policy at all under the engine's default-deny.
    let bare = PolicyEngine::new();
    let e = eval(&bare, &serde_json::json!({}), None, None);
    assert!(matches!(e.decision(), PolicyDecision::Deny(_)));
    assert_eq!(e.deny_cause(), Some(DenyCause::Default));
}

#[test]
fn an_exhausted_rate_limit_is_a_rate_limit_refusal_not_a_policy_deny() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::deny_all("p", CRED).with_rule(
        PolicyCondition::RateLimit {
            max: 1,
            window_secs: 3600,
        },
        PolicyAction::Allow,
    ));
    let p = principal("p1");
    let first = eval(&engine, &serde_json::json!({}), None, Some(&p));
    assert!(matches!(first.decision(), PolicyDecision::Allow));
    assert_eq!(first.deny_cause(), None, "an Allow has no cause");
    let second = eval(&engine, &serde_json::json!({}), None, Some(&p));
    assert!(matches!(second.decision(), PolicyDecision::Deny(_)));
    assert_eq!(second.deny_cause(), Some(DenyCause::RateLimit));
    assert_eq!(class_of(&second), RefusalClass::RateLimit);
}

#[test]
fn an_over_cap_spend_is_a_spend_cap_refusal_and_a_within_cap_one_is_allowed() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::deny_all("p", CRED).with_rule(
        PolicyCondition::SpendCap {
            asset: "usd".to_string(),
            per_action_max: 100,
        },
        PolicyAction::Allow,
    ));
    let within = SpendAttempt {
        asset: "usd".to_string(),
        amount: 50,
    };
    let e = eval(&engine, &serde_json::json!({}), Some(&within), None);
    assert!(matches!(e.decision(), PolicyDecision::Allow));
    let over = SpendAttempt {
        asset: "usd".to_string(),
        amount: 500,
    };
    let e = eval(&engine, &serde_json::json!({}), Some(&over), None);
    assert!(matches!(e.decision(), PolicyDecision::Deny(_)));
    assert_eq!(e.deny_cause(), Some(DenyCause::SpendCap));
    assert_eq!(class_of(&e), RefusalClass::SpendCap);
}

#[test]
fn a_url_that_cannot_be_canonicalised_under_a_url_deny_rule_is_its_own_cause() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::allow_all("p", CRED).with_rule(
        PolicyCondition::UrlMatch("https://example.com/admin/*".to_string()),
        PolicyAction::Deny,
    ));
    let params = serde_json::json!({"url": "http://[::1"});
    let e = eval(&engine, &params, None, None);
    assert!(matches!(e.decision(), PolicyDecision::Deny(_)));
    assert_eq!(e.deny_cause(), Some(DenyCause::UrlUncanonical));
    assert_eq!(class_of(&e), RefusalClass::PolicyDeny);
}

#[test]
fn allow_and_prompt_carry_no_cause() {
    let engine = PolicyEngine::new();
    engine.add_policy(Policy::allow_all("p", CRED));
    let e = eval(&engine, &serde_json::json!({}), None, None);
    assert!(matches!(e.decision(), PolicyDecision::Allow));
    assert_eq!(e.deny_cause(), None);
    let prompt = PolicyEngine::new();
    prompt.add_policy(
        Policy::allow_all("p", CRED).with_rule(PolicyCondition::Always, PolicyAction::Prompt),
    );
    let e = eval(&prompt, &serde_json::json!({}), None, None);
    assert!(matches!(e.decision(), PolicyDecision::Prompt));
    assert_eq!(e.deny_cause(), None);
}
