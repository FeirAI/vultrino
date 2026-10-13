//! VUL-32: URL Deny and Prompt rules must match what they read. A pattern that matches less
//! than it reads is refused at write (admin API, covered in web_smoke), at config-file load,
//! and when a stored policy is loaded; `fix_stored_policy_url_patterns` repairs it offline.

use secrecy::SecretString;
use tempfile::tempdir;
use vultrino::config::Config;
use vultrino::policy::{
    fix_stored_policy_url_patterns, refuse_unloadable_stored_policies, Policy, PolicyAction,
    PolicyCondition,
};
use vultrino::storage::{FileStorage, StorageBackend};

fn policy(action: PolicyAction, pattern: &str) -> Policy {
    Policy::deny_all("p", "cred-*")
        .with_rule(PolicyCondition::UrlMatch(pattern.to_string()), action)
}

#[test]
fn config_file_load_refuses_the_footgun_deny_and_prompt_patterns() {
    for (action, pattern, default) in [
        ("deny", "https://api.example.com/admin", "deny"),
        // A prompt on an exact URL is refused unless the policy default is deny (see below).
        ("prompt", "https://api.example.com/admin", "allow"),
        ("deny", "/v1/refunds", "deny"),
        ("deny", "https://api.example.com/{admin,root}/*", "deny"),
        ("prompt", "https://api.example.com/{admin,root}/*", "deny"),
        ("prompt", "https://*.example.com/x", "deny"),
    ] {
        let toml = format!(
            r#"
[[policies]]
name = "p"
credential_pattern = "cred-*"
default_action = "{default}"
[[policies.rules]]
action = "{action}"
condition = {{ url_match = "{pattern}" }}
"#
        );
        let err = Config::parse(&toml).expect_err(&format!("{action} {pattern} must be refused"));
        assert!(err.to_string().contains("url_match"), "{err}");
    }
    // The prefix form, and an exact URL on an Allow rule, still load.
    for (action, pattern) in [
        ("deny", "https://api.example.com/admin*"),
        ("deny", "https://api.example.com/admin?x=1"),
        ("allow", "https://api.example.com/admin"),
        // govder's compiled shape: a prompt on an exact URL in a default-deny policy.
        ("prompt", "https://api.example.com/admin"),
    ] {
        let toml = format!(
            r#"
[[policies]]
name = "p"
credential_pattern = "cred-*"
default_action = "deny"
[[policies.rules]]
action = "{action}"
condition = {{ url_match = "{pattern}" }}
"#
        );
        Config::parse(&toml).unwrap_or_else(|e| panic!("{action} {pattern}: {e}"));
    }
}

#[tokio::test]
async fn stored_policy_is_refused_on_load_and_the_fix_path_repairs_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let storage = FileStorage::new(&path, &SecretString::from("pw"))
        .await
        .unwrap();

    let mut exact = policy(PolicyAction::Deny, "https://api.example.com/admin");
    exact.id = "exact-id".into();
    let mut braces = policy(PolicyAction::Prompt, "https://api.example.com/{a,b}/x");
    braces.id = "braces-id".into();
    let mut star = policy(PolicyAction::Deny, "https://*.example.com/x");
    star.id = "star-id".into();
    for p in [&exact, &braces, &star] {
        storage.store_policy(p).await.unwrap();
    }
    let stored = storage.list_stored_policies().await.unwrap();
    let refusal = refuse_unloadable_stored_policies(&stored).expect_err("must refuse");
    for id in ["exact-id", "braces-id", "star-id"] {
        assert!(refusal.contains(id), "{refusal}");
    }
    assert!(refusal.contains("vultrino policy check"), "{refusal}");

    // The automatic fix repairs the exact URL and the alternation, and says it cannot fix a star.
    assert_eq!(
        fix_stored_policy_url_patterns(&storage, "exact-id")
            .await
            .unwrap(),
        1
    );
    // The alternation expands (1). Each alternative is an exact URL on a prompt rule in a
    // default-deny policy, which is allowed (govder's compiled shape), so it stays exact.
    assert_eq!(
        fix_stored_policy_url_patterns(&storage, "braces-id")
            .await
            .unwrap(),
        1
    );
    let err = fix_stored_policy_url_patterns(&storage, "star-id")
        .await
        .expect_err("a star in the host needs a human");
    assert!(err.to_string().contains("still refused"), "{err}");
    storage.delete_policy("star-id").await.unwrap();
    let stored = storage.list_stored_policies().await.unwrap();
    refuse_unloadable_stored_policies(&stored).expect("fixed policies load");

    // What was stored now does what the old pattern read: the exact Deny covers a query.
    let fixed = storage.get_policy("exact-id").await.unwrap().unwrap();
    let PolicyCondition::UrlMatch(p) = &fixed.rules[0].condition else {
        panic!("shape");
    };
    assert_eq!(p, "https://api.example.com/admin*");
    let fixed = storage.get_policy("braces-id").await.unwrap().unwrap();
    let PolicyCondition::Or(alts) = &fixed.rules[0].condition else {
        panic!("shape");
    };
    let got: Vec<&str> = alts
        .iter()
        .map(|c| match c {
            PolicyCondition::UrlMatch(p) => p.as_str(),
            _ => panic!("shape"),
        })
        .collect();
    assert_eq!(
        got,
        ["https://api.example.com/a/x", "https://api.example.com/b/x"]
    );
}

#[test]
fn exact_prompt_is_refused_only_when_the_policy_default_is_not_deny() {
    use vultrino::policy::refuse_warned_url_patterns;
    let mut p = policy(PolicyAction::Prompt, "https://api.example.com/admin");
    refuse_warned_url_patterns(&p).expect("default deny: a query form falls to deny");
    p.default_action = PolicyAction::Allow;
    assert!(refuse_warned_url_patterns(&p).is_err());
    p.default_action = PolicyAction::Prompt;
    assert!(refuse_warned_url_patterns(&p).is_err());
    // A deny rule is refused whatever the default.
    let d = policy(PolicyAction::Deny, "https://api.example.com/admin");
    assert!(refuse_warned_url_patterns(&d).is_err());
}

#[tokio::test]
async fn url_token_secret_with_structure_characters_is_refused_at_store() {
    use vultrino::{Credential, CredentialData, Secret};
    let dir = tempdir().unwrap();
    let storage = FileStorage::new(&dir.path().join("v.enc"), &SecretString::from("pw"))
        .await
        .unwrap();
    for bad in ["a/b", "a?b", "a#b", "a\\b", "a%2Fb", "a b", "a\nb", ""] {
        let c = Credential::new(
            "tg".to_string(),
            CredentialData::UrlToken {
                token: Secret::new(bad),
            },
        );
        assert!(storage.store(&c).await.is_err(), "{bad:?} must be refused");
    }
    let ok = Credential::new(
        "tg".to_string(),
        CredentialData::UrlToken {
            token: Secret::new("123456:ABC-def_GHI"),
        },
    );
    storage.store(&ok).await.expect("a plain token is stored");
}
