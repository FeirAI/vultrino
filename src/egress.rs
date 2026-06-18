//! Egress controls (V7): keep a proxied response from carrying secrets back to
//! the agent.
//!
//! Two layers, applied at the execution seam ([`crate::server`]):
//! 1. **Always-on secret-material redaction.** If an endpoint reflects the
//!    credential's own injected secret in its response (a header-echoing
//!    reflector, an open redirect to an attacker host, etc.), the server scrubs
//!    the secret — and its common re-encoded forms — from the body and headers
//!    before returning them. Closes the read-back vector (REVIEW H2/F2) at one
//!    place, for every plugin. Defense-in-depth, not absolute: an endpoint that
//!    *transforms* the secret (base64/gzip/hashing) or returns it compressed can
//!    still leak it — use a `block` rule for endpoints you don't trust.
//! 2. **Egress classification.** Operator `[[egress]]` rules mark a
//!    `(credential, action)` whose response may carry a *secondary* secret —
//!    `block`ing the body+headers entirely or redacting extra `redact_patterns`.

use crate::ExecuteResponse;
use regex::Regex;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Secrets shorter than this are not byte-scrubbed from responses: a very short
/// secret would over-redact common substrings, and such "secrets" carry little
/// entropy anyway. High-risk short secrets should use an egress `block` rule.
pub const MIN_REDACT_LEN: usize = 5;

/// Whether any of these secrets is non-empty but below the redaction floor (so
/// the always-on scrubbing would NOT catch a reflection of it). Used to warn
/// operators at credential-store time.
pub fn has_unredactable_secret(secrets: &[Zeroizing<String>]) -> bool {
    secrets.iter().any(|s| !s.is_empty() && s.len() < MIN_REDACT_LEN)
}

/// Scrub the credential's own secret material (and its percent-encoded /
/// JSON-escaped forms) from a response body and headers (layer 1). Returns
/// whether anything was changed.
pub fn redact_secret_material(
    resp: &mut ExecuteResponse,
    secrets: &[Zeroizing<String>],
    alias: &str,
) -> bool {
    let marker = format!("[REDACTED:{}]", alias);
    // Build the forms to scrub, deduped and longest-first so a longer encoded
    // form is replaced before a shorter form it may contain.
    let mut forms: Vec<String> = Vec::new();
    for secret in secrets {
        let raw: &str = secret;
        if raw.len() < MIN_REDACT_LEN {
            continue;
        }
        forms.push(raw.to_string());
        let pct = urlencoding::encode(raw).into_owned();
        if pct != raw {
            forms.push(pct);
        }
        if let Some(escaped) = json_escaped_inner(raw) {
            if escaped != raw && escaped.len() >= MIN_REDACT_LEN {
                forms.push(escaped);
            }
        }
    }
    forms.sort();
    forms.dedup();
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));

    let mut modified = false;
    for form in &forms {
        let (new_body, hit) = replace_bytes(&resp.body, form.as_bytes(), marker.as_bytes());
        if hit {
            resp.body = new_body;
            modified = true;
        }
        for v in resp.headers.values_mut() {
            if v.contains(form.as_str()) {
                *v = v.replace(form.as_str(), &marker);
                modified = true;
            }
        }
    }
    // Wipe the derived plaintext forms.
    forms.iter_mut().for_each(|f| f.zeroize());
    modified
}

/// The inner (escape sequences intact) of a JSON-string encoding of `s`, i.e.
/// `serde_json::to_string(s)` with exactly one surrounding quote removed each
/// side — so secrets that themselves contain `"` aren't mangled by a naive trim.
fn json_escaped_inner(s: &str) -> Option<String> {
    let json = serde_json::to_string(s).ok()?;
    // `to_string` of a string is always `"..."`, so slice off one quote each end.
    json.get(1..json.len().checked_sub(1)?).map(|s| s.to_string())
}

/// Drop response framing headers that a redacted body invalidates. Redaction
/// changes the body length, so a forwarded `Content-Length`/`Transfer-Encoding`
/// would be wrong (and would leak the original length); the transport sets
/// framing from the actual bytes. Only call when the body was modified.
pub fn strip_content_framing_headers(resp: &mut ExecuteResponse) {
    resp.headers.retain(|k, _| {
        !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")
    });
}

/// A compiled egress classification rule (layer 2). Patterns are compiled at
/// config load, so an invalid glob fails fast (rather than silently degrading
/// to exact-match and never blocking — a fail-open hazard).
#[derive(Debug, Clone)]
pub struct EgressRule {
    pub credential_pattern: glob::Pattern,
    pub action_pattern: glob::Pattern,
    /// Withhold the response body (and headers) entirely — for endpoints whose
    /// response is itself a secret (STS/login/secret-read).
    pub block: bool,
    /// Extra patterns (compiled regexes) to redact from body AND headers.
    pub redact_patterns: Vec<Regex>,
}

impl EgressRule {
    fn matches(&self, alias: &str, action: &str) -> bool {
        self.credential_pattern.matches(alias) && self.action_pattern.matches(action)
    }
}

/// Apply the first matching egress classification rule to a response (layer 2).
/// Returns whether the response was changed.
pub fn apply_egress(
    resp: &mut ExecuteResponse,
    rules: &[EgressRule],
    alias: &str,
    action: &str,
) -> bool {
    let Some(rule) = rules.iter().find(|r| r.matches(alias, action)) else {
        return false;
    };
    if rule.block {
        resp.body =
            b"[vultrino: response body withheld by egress policy (secret-bearing endpoint)]".to_vec();
        // Headers can also carry secrets (Set-Cookie, tokens) — drop them too.
        resp.headers.clear();
        return true;
    }
    if rule.redact_patterns.is_empty() {
        return false;
    }
    let mut modified = false;
    // Regex redaction is text-oriented; skip a non-UTF-8 (binary/compressed) body
    // rather than corrupt it via lossy conversion. Such endpoints need a `block`.
    if let Ok(text) = std::str::from_utf8(&resp.body) {
        let mut out = text.to_string();
        for re in &rule.redact_patterns {
            out = re.replace_all(&out, "[REDACTED:egress]").into_owned();
        }
        if out.as_bytes() != resp.body.as_slice() {
            resp.body = out.into_bytes();
            modified = true;
        }
    } else {
        tracing::warn!(
            credential = %alias,
            action = %action,
            "egress redact_patterns skipped: response body is not UTF-8 (use a block rule)"
        );
    }
    // Secondary secrets routinely sit in response headers (Set-Cookie,
    // Authorization, X-Amz-*), so apply the patterns to header values too.
    for v in resp.headers.values_mut() {
        for re in &rule.redact_patterns {
            let replaced = re.replace_all(v, "[REDACTED:egress]").into_owned();
            if replaced != *v {
                *v = replaced;
                modified = true;
            }
        }
    }
    modified
}

/// Replace every non-overlapping occurrence of `needle`; returns the new bytes
/// and whether any replacement happened.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, bool) {
    if needle.is_empty() || haystack.len() < needle.len() {
        return (haystack.to_vec(), false);
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut hit = false;
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
            hit = true;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, hit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resp(body: &str) -> ExecuteResponse {
        ExecuteResponse {
            status: 200,
            headers: HashMap::new(),
            body: body.as_bytes().to_vec(),
            updated_credential: None,
        }
    }

    fn secrets(items: &[&str]) -> Vec<Zeroizing<String>> {
        items.iter().map(|s| Zeroizing::new(s.to_string())).collect()
    }

    fn rule(cred: &str, action: &str, block: bool, patterns: &[&str]) -> EgressRule {
        EgressRule {
            credential_pattern: glob::Pattern::new(cred).unwrap(),
            action_pattern: glob::Pattern::new(action).unwrap(),
            block,
            redact_patterns: patterns.iter().map(|p| Regex::new(p).unwrap()).collect(),
        }
    }

    #[test]
    fn test_redact_secret_material_body_and_headers() {
        let mut r = resp("token is sk-supersecret-123 here");
        r.headers.insert("X-Echo".to_string(), "Bearer sk-supersecret-123".to_string());
        assert!(redact_secret_material(&mut r, &secrets(&["sk-supersecret-123"]), "stripe"));
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains("sk-supersecret-123"));
        assert!(body.contains("[REDACTED:stripe]"));
        assert_eq!(r.headers.get("X-Echo").unwrap(), "Bearer [REDACTED:stripe]");
    }

    #[test]
    fn test_redact_returns_false_when_no_secret_present() {
        let mut r = resp("nothing sensitive here");
        assert!(!redact_secret_material(&mut r, &secrets(&["sk-supersecret-123"]), "x"));
        assert_eq!(String::from_utf8_lossy(&r.body), "nothing sensitive here");
    }

    #[test]
    fn test_redact_skips_short_secrets() {
        let mut r = resp("the cat sat");
        assert!(!redact_secret_material(&mut r, &secrets(&["cat"]), "x"));
        assert_eq!(String::from_utf8_lossy(&r.body), "the cat sat");
    }

    #[test]
    fn test_redact_catches_percent_encoded_form() {
        let secret = "a b/c+d=secret";
        let encoded = urlencoding::encode(secret).into_owned();
        let mut r = resp(&format!("echo {}", encoded));
        assert!(redact_secret_material(&mut r, &secrets(&[secret]), "x"));
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains(&encoded), "percent-encoded secret survived: {body}");
        assert!(body.contains("[REDACTED:x]"));
    }

    #[test]
    fn test_redact_catches_json_escaped_form() {
        // A secret containing a quote and backslash, reflected JSON-escaped.
        let secret = r#"ab"cd\ef"#;
        let escaped = json_escaped_inner(secret).unwrap();
        assert_ne!(escaped, secret);
        let mut r = resp(&format!("{{\"echo\":\"{}\"}}", escaped));
        assert!(redact_secret_material(&mut r, &secrets(&[secret]), "x"));
        assert!(!String::from_utf8_lossy(&r.body).contains(&escaped));
    }

    #[test]
    fn test_unredactable_secret_detection() {
        assert!(has_unredactable_secret(&secrets(&["pin"])));
        assert!(!has_unredactable_secret(&secrets(&["longenough"])));
        assert!(!has_unredactable_secret(&secrets(&[""])));
    }

    #[test]
    fn test_strip_content_framing_headers() {
        let mut r = resp("x");
        r.headers.insert("Content-Length".to_string(), "999".to_string());
        r.headers.insert("transfer-encoding".to_string(), "chunked".to_string());
        r.headers.insert("Content-Type".to_string(), "application/json".to_string());
        strip_content_framing_headers(&mut r);
        assert!(!r.headers.keys().any(|k| k.eq_ignore_ascii_case("content-length")));
        assert!(!r.headers.keys().any(|k| k.eq_ignore_ascii_case("transfer-encoding")));
        assert!(r.headers.contains_key("Content-Type"));
    }

    #[test]
    fn test_egress_block_withholds_body_and_headers() {
        let mut r = resp("{\"downstream_token\":\"abc\"}");
        r.headers.insert("Set-Cookie".to_string(), "session=zzz".to_string());
        assert!(apply_egress(&mut r, &[rule("sts-*", "*", true, &[])], "sts-prod", "http.request"));
        assert!(String::from_utf8_lossy(&r.body).contains("withheld by egress policy"));
        assert!(r.headers.is_empty());
    }

    #[test]
    fn test_egress_redact_patterns_body_and_headers() {
        let mut r = resp("id=42 secret=DEADBEEFCAFE rest");
        r.headers.insert("Set-Cookie".to_string(), "session=DEADBEEFCAFE".to_string());
        let modified = apply_egress(&mut r, &[rule("*", "*", false, &["[A-F0-9]{8,}"])], "any", "http.request");
        assert!(modified);
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains("DEADBEEFCAFE"));
        assert!(body.contains("[REDACTED:egress]"));
        assert!(!r.headers.get("Set-Cookie").unwrap().contains("DEADBEEFCAFE"));
    }

    #[test]
    fn test_egress_redact_skips_binary_body() {
        // A non-UTF-8 body must be left intact (not corrupted via lossy convert).
        let mut r = ExecuteResponse {
            status: 200,
            headers: HashMap::new(),
            body: vec![0xff, 0xfe, 0x00, 0x01, 0x80],
            updated_credential: None,
        };
        let before = r.body.clone();
        apply_egress(&mut r, &[rule("*", "*", false, &["[A-F0-9]{8,}"])], "any", "http.request");
        assert_eq!(r.body, before, "binary body must be untouched");
    }

    #[test]
    fn test_egress_first_matching_rule_wins() {
        let rules = vec![
            rule("pay-*", "*", true, &[]),                 // block
            rule("*", "*", false, &["should-not-apply"]),  // would redact
        ];
        let mut r = resp("should-not-apply body");
        apply_egress(&mut r, &rules, "pay-1", "http.request");
        // The first (block) rule wins, not the second (redact).
        assert!(String::from_utf8_lossy(&r.body).contains("withheld by egress policy"));
    }

    #[test]
    fn test_egress_no_matching_rule_is_noop() {
        let mut r = resp("hello");
        assert!(!apply_egress(&mut r, &[rule("other-*", "*", true, &[])], "pay-1", "http.request"));
        assert_eq!(String::from_utf8_lossy(&r.body), "hello");
    }
}
