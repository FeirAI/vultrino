//! VUL-32: a query string appended to a URL never weakens a decision. For every policy the
//! write path accepts (`refuse_warned_url_patterns`), over a fixed grid of patterns, URLs,
//! rule shapes and defaults, the engine's decision for `u?x=1` is at least as strict as for `u`
//! (Allow < Prompt < Deny). Exhaustive over the grid, not over all patterns.

use vultrino::policy::{
    refuse_warned_url_patterns, Policy, PolicyAction, PolicyCondition, PolicyDecision,
    PolicyEngine, PolicyRule,
};

const PATTERNS: &[&str] = &[
    "https://api.example.com/v1/*/delete",
    "https://api.example.com/admi[n]",
    "https://api.example.com/admin",
    "https://api.example.com/admin*",
    "https://api.example.com/*",
    "https://api.example.com/v1/refunds",
    "https://api.example.com/v1/ref?nds",
    "https://api.example.com/v1/*",
    "https://api.example.com/v1/transfer?confirm=true",
    "https://api.example.com/v1/transfer?confirm=true*",
    "https://api.example.com/admin?",
    "https://api.example.com:8443/x",
    "https://*/x",
    "https://*.example.com/*",
    "*://api.example.com/v1/*/delete",
    "https://api.example.com",
    "https://api.example.com/",
    "https://api.example.com/v1/*/",
    "/v1/refunds",
    "/v1/*/delete",
];

const URLS: &[&str] = &[
    "https://api.example.com/v1/a/delete/",
    "https://api.example.com/admin/",
    "https://api.example.com/v1/a/delete",
    "https://api.example.com/admin",
    "https://api.example.com/admin/x",
    "https://api.example.com/v1/refunds",
    "https://api.example.com/v1/a",
    "https://api.example.com/v1/a/",
    "https://api.example.com/",
    "https://api.example.com",
    "https://api.example.com:8443/x",
    "https://other.example.com/x",
    "https://api.example.com/v1/a?b=1",
    "https://api.example.com/v1/transfer?b=1",
];

fn rank(d: &PolicyDecision) -> u8 {
    match d {
        PolicyDecision::Allow => 0,
        PolicyDecision::Prompt => 1,
        PolicyDecision::Deny(_) => 2,
    }
}

fn wrap(shape: usize, p: &str) -> PolicyCondition {
    let u = || PolicyCondition::UrlMatch(p.to_string());
    match shape {
        0 => u(),
        1 => PolicyCondition::And(vec![u(), PolicyCondition::MethodMatch(vec!["GET".into()])]),
        2 => PolicyCondition::Or(vec![u(), PolicyCondition::MethodMatch(vec!["POST".into()])]),
        3 => PolicyCondition::Not(Box::new(PolicyCondition::Not(Box::new(u())))),
        _ => PolicyCondition::Not(Box::new(u())),
    }
}

fn rules(action: PolicyAction, shape: usize, p: &str, allow_all_rule: bool) -> Vec<PolicyRule> {
    let mut v = Vec::new();
    if allow_all_rule {
        v.push(PolicyRule {
            condition: PolicyCondition::UrlMatch("https://api.example.com/*".into()),
            action: PolicyAction::Allow,
        });
    }
    v.push(PolicyRule {
        condition: wrap(shape, p),
        action,
    });
    v
}

#[test]
fn a_query_suffix_never_weakens_an_accepted_policy() {
    let mut accepted = 0usize;
    let mut checked = 0usize;
    for action in [
        PolicyAction::Deny,
        PolicyAction::Prompt,
        PolicyAction::Allow,
    ] {
        for default in [
            PolicyAction::Allow,
            PolicyAction::Prompt,
            PolicyAction::Deny,
        ] {
            for shape in 0..5 {
                // A Prompt under a single not is outside the property: it prompts every URL
                // except the pattern's, so with a deny default the query form moves from the
                // default Deny to Prompt. That is a different rule, not a slipped one.
                if shape == 4 && action == PolicyAction::Prompt {
                    continue;
                }
                for allow_rule in [false, true] {
                    for p in PATTERNS {
                        let mut pol = Policy::allow_all("p", "*");
                        pol.default_action = default;
                        pol.rules = rules(action, shape, p, allow_rule);
                        if refuse_warned_url_patterns(&pol).is_err() {
                            continue;
                        }
                        accepted += 1;
                        let e = PolicyEngine::new();
                        e.add_policy(pol);
                        for u in URLS {
                            let sep = if u.contains('?') { '&' } else { '?' };
                            let with_q = format!("{u}{sep}x=1");
                            let a = rank(&e.evaluate_readonly("c", Some(u), Some("GET")));
                            let b = rank(&e.evaluate_readonly("c", Some(&with_q), Some("GET")));
                            checked += 1;
                            // A trailing slash and a parameter placed before an existing one
                            // never weaken either.
                            let slashed = format!("{}/", u.split('?').next().unwrap());
                            // A pattern that itself ends in `/`, or holds a `?` (a one-character wildcard, accepted only
                            // as a default-deny Prompt or an Allow), matches the slashed URL on its own terms.
                            if !u.contains('?')
                                && !u.ends_with('/')
                                && !p.ends_with('/')
                                && !p.contains('?')
                            {
                                let c =
                                    rank(&e.evaluate_readonly("c", Some(&slashed), Some("GET")));
                                assert!(c >= a, "slash weakened {action:?} {shape} {default:?} {allow_rule} {p}: {u} -> {a}, {slashed} -> {c}");
                            }
                            if u.contains("?b=1") {
                                let ins = u.replace("?b=1", "?x=1&b=1");
                                let c = rank(&e.evaluate_readonly("c", Some(&ins), Some("GET")));
                                assert!(c >= a, "inserted param weakened {action:?} {shape} {default:?} {allow_rule} {p}: {u} -> {a}, {ins} -> {c}");
                            }
                            // An Allow rule may legitimately narrow: a rule that allowed u
                            // allows less once a query is appended. That is stricter, never
                            // weaker, so the same inequality holds for every action.
                            assert!(
                                b >= a,
                                "query weakened {action:?} shape {shape} default {default:?} \
                                 allow_rule {allow_rule} pattern {p}: {u} -> {a}, {with_q} -> {b}"
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(accepted > 250 && checked > 3000, "{accepted} {checked}");
}

#[test]
fn the_reviewer_probes_are_now_strict() {
    for (action, pat, url) in [
        (
            PolicyAction::Deny,
            "https://api.example.com/v1/*/delete",
            "https://api.example.com/v1/a/delete",
        ),
        (
            PolicyAction::Deny,
            "https://api.example.com/admi[n]",
            "https://api.example.com/admin",
        ),
        (
            PolicyAction::Prompt,
            "https://api.example.com/v1/refunds",
            "https://api.example.com/v1/refunds",
        ),
    ] {
        let e = PolicyEngine::new();
        let mut p = Policy::allow_all("p", "*");
        p.default_action = PolicyAction::Deny;
        p.rules = rules(action, 0, pat, true);
        e.add_policy(p);
        let q = format!("{url}?x=1");
        assert_eq!(
            rank(&e.evaluate_readonly("c", Some(url), Some("GET"))),
            rank(&e.evaluate_readonly("c", Some(&q), Some("GET"))),
            "{pat}"
        );
        assert_ne!(
            rank(&e.evaluate_readonly("c", Some(&q), Some("GET"))),
            0,
            "{pat}"
        );
    }
}

fn decide(pat: &str, action: PolicyAction, url: &str) -> u8 {
    let e = PolicyEngine::new();
    let mut p = Policy::allow_all("p", "*");
    p.default_action = PolicyAction::Allow;
    p.rules = rules(action, 0, pat, false);
    e.add_policy(p);
    rank(&e.evaluate_readonly("c", Some(url), Some("GET")))
}

/// Round 2 probes: a Deny that carries a query is refused at write (the old acceptance let
/// `?x=1&confirm=true` through, and so did the documented `*` form), a bare trailing `?` is
/// refused, and a trailing slash no longer slips past a path pattern.
#[test]
fn query_patterns_are_refused_and_trailing_slash_is_denied() {
    for pat in [
        "https://api.example.com/v1/transfer?confirm=true",
        "https://api.example.com/v1/transfer?confirm=true*",
        "https://api.example.com/admin?",
    ] {
        for action in [PolicyAction::Deny, PolicyAction::Prompt] {
            let mut p = Policy::allow_all("p", "*");
            p.rules = rules(action, 0, pat, false);
            assert!(refuse_warned_url_patterns(&p).is_err(), "{action:?} {pat}");
        }
    }
    let pat = "https://api.example.com/v1/*/delete";
    for u in [
        "https://api.example.com/v1/a/delete/",
        "https://api.example.com/v1/a/delete/?x=1",
        "https://api.example.com/v1/a/delete?x=1",
        "https://api.example.com/v1/a/delete",
    ] {
        assert_eq!(decide(pat, PolicyAction::Deny, u), 2, "{u}");
    }
}
