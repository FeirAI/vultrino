//! SB-03: `UrlMatch` is evaluated on a canonical form of the URL.
//!
//! These tests go through the public engine API only, so they run unchanged
//! against the pre-fix tree (red-first).

use proptest::prelude::*;
use vultrino::policy::{
    policy_url, Policy, PolicyAction, PolicyCondition, PolicyDecision, PolicyEngine, PolicyRule,
};

fn engine(rules: Vec<(PolicyCondition, PolicyAction)>, default: PolicyAction) -> PolicyEngine {
    let e = PolicyEngine::new();
    let mut p = Policy::allow_all("p", "*");
    p.default_action = default;
    p.rules = rules
        .into_iter()
        .map(|(condition, action)| PolicyRule { condition, action })
        .collect();
    e.add_policy(p);
    e
}

fn decide(e: &PolicyEngine, url: &str) -> PolicyDecision {
    e.evaluate_readonly("cred", Some(url), Some("GET"))
}

fn is_deny(d: &PolicyDecision) -> bool {
    matches!(d, PolicyDecision::Deny(_))
}

const SPELLINGS: &[&str] = &[
    "https://api.example.com/admin/x",
    "HTTPS://API.EXAMPLE.COM/admin/x",
    "https://Api.Example.Com:443/admin/x",
    "https://api.example.com/v1/../admin/x",
    "https://api.example.com/./admin/x",
    "https://api.example.com/%61dmin/x",
    "https://api.example.com/admin/%78",
    "https://api.example.com/%41dmin/x", // uppercase A: a different path, see below
    "https://api.example.com/admin/x#frag",
    "https://api.example.com\\admin\\x",
    "https://api.example.com/%2e%2e/admin/x",
    "  https://api.example.com/admin/x",
    "https://api.example.com/admin/%78%",
];

#[test]
fn deny_rule_catches_equivalent_spellings() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com/admin/*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    // Every spelling of the same URL is denied. `%41dmin` is the path `Admin`
    // (case-sensitive path, a different resource) and is the one that must stay
    // allowed: percent decoding applies to unreserved characters only, it does
    // not fold case.
    for s in SPELLINGS {
        let d = decide(&e, s);
        if s.contains("%41dmin") {
            assert!(!is_deny(&d), "case-distinct path must not be folded: {s}");
        } else {
            assert!(
                is_deny(&d),
                "equivalent spelling evaded the deny rule: {s} -> {d:?}"
            );
        }
    }
}

#[test]
fn prefix_without_trailing_slash_stops_at_the_host_boundary() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com*".into()),
            PolicyAction::Allow,
        )],
        PolicyAction::Deny,
    );
    assert!(!is_deny(&decide(&e, "https://api.example.com/v1")));
    assert!(!is_deny(&decide(&e, "HTTPS://API.EXAMPLE.COM:443/v1")));
    assert!(is_deny(&decide(&e, "https://api.example.com.evil.net/v1")));
    assert!(is_deny(&decide(&e, "https://api.example.comevil.net/")));
    assert!(is_deny(&decide(&e, "https://api.example.com@evil.net/")));
}

#[test]
fn unparseable_url_never_matches_allow_and_is_denied_under_a_url_deny() {
    // Deny rule present, engine default allow: an unparseable URL is denied.
    let with_deny = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com/admin/*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    for bad in [
        "https://[::1",
        "http://",
        "https://exa mple.com/",
        "not a url",
        "",
    ] {
        assert!(
            is_deny(&decide(&with_deny, bad)),
            "unparseable allowed: {bad:?}"
        );
    }
    // Negated URL match in an Allow rule must not admit an unparseable URL.
    let negated = engine(
        vec![(
            PolicyCondition::Not(Box::new(PolicyCondition::UrlMatch(
                "https://bad.example/*".into(),
            ))),
            PolicyAction::Allow,
        )],
        PolicyAction::Deny,
    );
    assert!(is_deny(&decide(&negated, "https://[::1")));
    assert!(!is_deny(&decide(&negated, "https://good.example/")));
    // An Allow-only UrlMatch never matches an unparseable URL.
    let allow_only = engine(
        vec![(PolicyCondition::UrlMatch("*".into()), PolicyAction::Allow)],
        PolicyAction::Deny,
    );
    assert!(is_deny(&decide(&allow_only, "https://[::1")));
}

#[test]
fn relative_paths_keep_working() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("/v1/refunds/*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    assert!(is_deny(&decide(&e, "/v1/refunds/9")));
    assert!(is_deny(&decide(&e, "/v1/x/../refunds/9")));
    assert!(!is_deny(&decide(&e, "/v1/orders/9")));
}

#[test]
fn host_prefix_still_matches_the_same_host_on_other_ports_and_trailing_dot() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    for same_host in [
        "https://api.example.com/x",
        "https://api.example.com:8443/x",
        "https://api.example.com./x",
        "https://API.EXAMPLE.COM.:8443/x",
        "https://api.example.com",
    ] {
        assert!(
            is_deny(&decide(&e, same_host)),
            "same host escaped: {same_host}"
        );
    }
    for other in [
        "https://api.example.com.evil.net/x",
        "https://api.example.com0/x",
        "https://api.example.coma/x",
    ] {
        assert!(!is_deny(&decide(&e, other)), "look-alike denied: {other}");
    }
}

#[test]
fn stray_percent_never_skips_a_prompt_rule() {
    // A URL the parser accepts but that used to fail the fixed-point check.
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com/v1/refunds*".into()),
            PolicyAction::Prompt,
        )],
        PolicyAction::Allow,
    );
    for u in [
        "https://api.example.com/v1/refunds/%%%33%32%%36%35",
        "https://api.example.com/v1/refunds/%",
        "https://api.example.com/v1/refunds/%2",
    ] {
        assert!(
            matches!(decide(&e, u), PolicyDecision::Prompt),
            "prompt skipped for {u}: {:?}",
            decide(&e, u)
        );
    }
    // A URL that really cannot be parsed is not allowed past a Prompt rule.
    assert!(!matches!(decide(&e, "https://[::1"), PolicyDecision::Allow));
}

#[test]
fn userinfo_cannot_sidestep_a_deny_rule() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com/admin/*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    for u in [
        "https://u@api.example.com/admin/x",
        "https://u:p@API.example.com:443/admin/x",
        "https://:p@api.example.com/admin/x",
    ] {
        assert!(
            is_deny(&decide(&e, u)),
            "userinfo evaded the deny rule: {u}"
        );
    }
}

#[test]
fn query_map_is_judged_with_the_url() {
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api.example.com/v1/search?q=secret*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    let params = serde_json::json!({
        "url": "https://api.example.com/v1/search",
        "query": {"q": "secret"}
    });
    let judged = policy_url(&params).expect("url present");
    assert_eq!(judged, "https://api.example.com/v1/search?q=secret");
    assert!(is_deny(&decide(&e, &judged)));
    // Sorted by key, so the string is independent of map order.
    let two = serde_json::json!({"url": "https://h.example/p", "query": {"b": "2", "a": "1 x"}});
    assert_eq!(policy_url(&two).unwrap(), "https://h.example/p?a=1%20x&b=2");
    // No url: nothing to judge. Unparseable url: the empty string, which no
    // rule can match.
    assert_eq!(policy_url(&serde_json::json!({"query": {"a": "1"}})), None);
    assert_eq!(
        policy_url(&serde_json::json!({"url": "https://[::1"})).unwrap(),
        ""
    );
}

#[test]
fn glob_pattern_and_scheme_only_pattern_keep_biting() {
    // `?` in a glob host is a glob character, not a query delimiter.
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("https://api?.example.com/v1/*/x".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    assert!(is_deny(&decide(&e, "https://api1.example.com/v1/a/x")));
    // An upper-case scheme-only pattern still matches every https URL.
    let e = engine(
        vec![(
            PolicyCondition::UrlMatch("HTTPS://*".into()),
            PolicyAction::Deny,
        )],
        PolicyAction::Allow,
    );
    assert!(is_deny(&decide(&e, "https://api.example.com/x")));
    assert!(is_deny(&decide(&e, "HTTPS://API.EXAMPLE.COM/x")));
}

fn spell_host(host: &str, bits: &[bool]) -> String {
    host.chars()
        .enumerate()
        .map(|(i, c)| {
            if bits[i % bits.len()] {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

fn spell_path(seg: &str, bits: &[bool]) -> String {
    // Percent-encode some unreserved characters.
    seg.chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphanumeric() && bits[i % bits.len()] {
                format!("%{:02x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every equivalent spelling of a URL gets the same decision as the plain
    /// spelling, for Deny prefix and Allow prefix rules.
    #[test]
    fn equivalent_spellings_decide_identically(
        host_bits in proptest::collection::vec(any::<bool>(), 1..8),
        path_bits in proptest::collection::vec(any::<bool>(), 1..8),
        port in prop_oneof![Just(""), Just(":443")],
        dots in 0usize..3,
        frag in prop_oneof![Just(""), Just("#f")],
        which in 0usize..3,
        seg in prop_oneof![Just("admin"), Just("v1"), Just("public")],
    ) {
        let rules = vec![
            (PolicyCondition::UrlMatch("https://api.example.com/admin/*".into()), PolicyAction::Deny),
            (PolicyCondition::UrlMatch("https://api.example.com/v1/*".into()), PolicyAction::Allow),
            (PolicyCondition::UrlMatch("https://api.example.com/public*".into()), PolicyAction::Allow),
        ];
        let e = engine(rules, PolicyAction::Deny);
        let plain = format!("https://api.example.com/{seg}/x");
        let host = spell_host("api.example.com", &host_bits);
        let dotprefix = "./".repeat(dots);
        let detour = if which == 0 { "zz/../" } else { "" };
        let spelled = format!(
            "HTTPS://{host}{port}/{detour}{dotprefix}{}/{}{frag}",
            spell_path(seg, &path_bits),
            spell_path("x", &path_bits)
        );
        prop_assert_eq!(
            is_deny(&decide(&e, &plain)),
            is_deny(&decide(&e, &spelled)),
            "plain {} vs spelled {}", plain, spelled
        );
    }

    /// Whatever the host suffix, the boundary rule never lets a look-alike host
    /// through a `https://api.example.com*` Allow.
    #[test]
    fn lookalike_hosts_never_match_the_host_prefix(suffix in "[a-z0-9.\\-]{1,12}") {
        let e = engine(
            vec![(PolicyCondition::UrlMatch("https://api.example.com*".into()), PolicyAction::Allow)],
            PolicyAction::Deny,
        );
        let url = format!("https://api.example.com{suffix}/x");
        // A suffix that starts a new label or continues the name changes the host.
        let parsed = url::Url::parse(&url);
        if let Ok(u) = parsed {
            if u.host_str().map(|h| h.trim_end_matches('.')) != Some("api.example.com") {
                prop_assert!(is_deny(&decide(&e, &url)), "look-alike admitted: {}", url);
            }
        }
    }

    /// Glob and host-boundary rules decide identically for equivalent spellings.
    #[test]
    fn glob_and_host_boundary_rules_decide_identically(
        host_bits in proptest::collection::vec(any::<bool>(), 1..8),
        path_bits in proptest::collection::vec(any::<bool>(), 1..8),
        port in prop_oneof![Just(""), Just(":443")],
        dot in prop_oneof![Just(""), Just(".")],
        seg in prop_oneof![Just("a"), Just("b1"), Just("zz")],
        tail in prop_oneof![Just("secret"), Just("other")],
        frag in prop_oneof![Just(""), Just("#f")],
    ) {
        let rules = vec![
            (PolicyCondition::UrlMatch("https://api.example.com/*/secret".into()), PolicyAction::Deny),
            (PolicyCondition::UrlMatch("https://api.example.com*".into()), PolicyAction::Allow),
        ];
        let e = engine(rules, PolicyAction::Deny);
        let plain = format!("https://api.example.com/{seg}/{tail}");
        let host = spell_host("api.example.com", &host_bits);
        let spelled = format!(
            "HTTPS://{host}{dot}{port}/{}/{}{frag}",
            spell_path(seg, &path_bits),
            spell_path(tail, &path_bits)
        );
        prop_assert_eq!(
            is_deny(&decide(&e, &plain)),
            is_deny(&decide(&e, &spelled)),
            "plain {} vs spelled {}", plain, spelled
        );
        // The glob Deny really fires on the secret tail (the test is not vacuous).
        prop_assert_eq!(is_deny(&decide(&e, &plain)), tail == "secret");
    }
}
