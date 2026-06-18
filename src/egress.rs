//! Egress controls (V7): keep a proxied response from carrying secrets back to
//! the agent.
//!
//! Two layers, applied at the execution seam ([`crate::server`]):
//! 1. **Always-on secret-material redaction.** If an endpoint reflects the
//!    credential's own injected secret in its response (a header-echoing
//!    reflector, an open redirect to an attacker host, etc.), the server scrubs
//!    the secret from the body and headers before returning them. This closes
//!    the read-back vector (REVIEW H2/F2) at one place, for every plugin.
//! 2. **Egress classification.** Operator-configured `[[egress]]` rules mark a
//!    `(credential, action)` whose response may carry a *secondary* secret (an
//!    STS token, a login response, a secret-reading API) — either `block`ing the
//!    body entirely or redacting extra `redact_patterns` (regexes) from it.

use crate::ExecuteResponse;
use regex::Regex;

/// Secrets shorter than this are not byte-scrubbed from responses: a very short
/// secret would over-redact common substrings, and such "secrets" carry little
/// entropy anyway. High-risk short secrets should use an egress `block` rule.
pub const MIN_REDACT_LEN: usize = 5;

/// Whether any of these secrets is non-empty but below the redaction floor (so
/// the always-on scrubbing would NOT catch a reflection of it). Used to warn
/// operators at credential-store time.
pub fn has_unredactable_secret(secrets: &[String]) -> bool {
    secrets.iter().any(|s| !s.is_empty() && s.len() < MIN_REDACT_LEN)
}

/// Scrub the credential's own secret material from a response (layer 1).
///
/// Scrubs the raw secret plus its common re-encoded forms (percent-encoded and
/// JSON-string-escaped) from the body and headers, so a reflector that returns
/// the secret in an encoded form is still caught. This is defense-in-depth, not
/// a guarantee against *arbitrary* re-encoding (e.g. base64/gzip of the secret
/// is not detectable here) — pair it with an egress `block` rule for endpoints
/// that may transform a secret.
pub fn redact_secret_material(resp: &mut ExecuteResponse, secrets: &[String], alias: &str) {
    let marker = format!("[REDACTED:{}]", alias);
    // Build the set of forms to scrub, deduped and longest-first so a longer
    // encoded form is replaced before a shorter form it may contain.
    let mut forms: Vec<String> = Vec::new();
    for secret in secrets {
        if secret.len() < MIN_REDACT_LEN {
            continue;
        }
        forms.push(secret.clone());
        let pct = urlencoding::encode(secret).into_owned();
        if pct != *secret {
            forms.push(pct);
        }
        if let Ok(json) = serde_json::to_string(secret) {
            let escaped = json.trim_matches('"').to_string();
            if escaped != *secret && escaped.len() >= MIN_REDACT_LEN {
                forms.push(escaped);
            }
        }
    }
    forms.sort();
    forms.dedup();
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));

    for form in &forms {
        resp.body = replace_bytes(&resp.body, form.as_bytes(), marker.as_bytes());
        for v in resp.headers.values_mut() {
            if v.contains(form.as_str()) {
                *v = v.replace(form.as_str(), &marker);
            }
        }
    }
}

/// Drop response framing headers that a buffered (and possibly redacted) body
/// invalidates. Redaction changes the body length, so a forwarded
/// `Content-Length`/`Transfer-Encoding` would be wrong (and would leak the
/// original length); the transport sets framing from the actual bytes.
pub fn strip_content_framing_headers(resp: &mut ExecuteResponse) {
    resp.headers.retain(|k, _| {
        !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding")
    });
}

/// A compiled egress classification rule (layer 2).
#[derive(Debug, Clone)]
pub struct EgressRule {
    pub credential_pattern: String,
    pub action_pattern: String,
    /// Withhold the response body (and headers) entirely — for endpoints whose
    /// response is itself a secret (STS/login/secret-read).
    pub block: bool,
    /// Extra patterns (compiled regexes) to redact from the body when not blocked.
    pub redact_patterns: Vec<Regex>,
}

impl EgressRule {
    fn matches(&self, alias: &str, action: &str) -> bool {
        glob_match(&self.credential_pattern, alias) && glob_match(&self.action_pattern, action)
    }
}

/// Apply the first matching egress classification rule to a response (layer 2).
pub fn apply_egress(resp: &mut ExecuteResponse, rules: &[EgressRule], alias: &str, action: &str) {
    let Some(rule) = rules.iter().find(|r| r.matches(alias, action)) else {
        return;
    };
    if rule.block {
        resp.body =
            b"[vultrino: response body withheld by egress policy (secret-bearing endpoint)]".to_vec();
        // Headers can also carry secrets (Set-Cookie, tokens) — drop them too.
        resp.headers.clear();
        return;
    }
    if !rule.redact_patterns.is_empty() {
        let mut text = String::from_utf8_lossy(&resp.body).into_owned();
        for re in &rule.redact_patterns {
            text = re.replace_all(&text, "[REDACTED:egress]").into_owned();
        }
        resp.body = text.into_bytes();
        // Secondary secrets routinely sit in response headers (Set-Cookie,
        // Authorization, X-Amz-*), so apply the patterns to header values too.
        for v in resp.headers.values_mut() {
            for re in &rule.redact_patterns {
                *v = re.replace_all(v, "[REDACTED:egress]").into_owned();
            }
        }
    }
}

/// Glob match: `*` matches anything; otherwise compile, falling back to exact.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    glob::Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or(pattern == value)
}

/// Replace every non-overlapping occurrence of `needle` in `haystack`.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + needle.len() <= haystack.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
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

    #[test]
    fn test_redact_secret_material_body_and_headers() {
        let mut r = resp("token is sk-supersecret-123 here");
        r.headers.insert("X-Echo".to_string(), "Bearer sk-supersecret-123".to_string());
        redact_secret_material(&mut r, &["sk-supersecret-123".to_string()], "stripe");
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains("sk-supersecret-123"));
        assert!(body.contains("[REDACTED:stripe]"));
        assert_eq!(r.headers.get("X-Echo").unwrap(), "Bearer [REDACTED:stripe]");
    }

    #[test]
    fn test_redact_skips_short_secrets() {
        // A 3-char "secret" must not over-redact arbitrary substrings.
        let mut r = resp("the cat sat");
        redact_secret_material(&mut r, &["cat".to_string()], "x");
        assert_eq!(String::from_utf8_lossy(&r.body), "the cat sat");
    }

    #[test]
    fn test_egress_block_withholds_body_and_headers() {
        let mut r = resp("{\"downstream_token\":\"abc\"}");
        r.headers.insert("Set-Cookie".to_string(), "session=zzz".to_string());
        let rules = vec![EgressRule {
            credential_pattern: "sts-*".to_string(),
            action_pattern: "*".to_string(),
            block: true,
            redact_patterns: vec![],
        }];
        apply_egress(&mut r, &rules, "sts-prod", "http.request");
        assert!(String::from_utf8_lossy(&r.body).contains("withheld by egress policy"));
        assert!(r.headers.is_empty());
    }

    #[test]
    fn test_egress_redact_patterns() {
        let mut r = resp("id=42 secret=DEADBEEFCAFE rest");
        let rules = vec![EgressRule {
            credential_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            block: false,
            redact_patterns: vec![Regex::new("[A-F0-9]{8,}").unwrap()],
        }];
        apply_egress(&mut r, &rules, "any", "http.request");
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains("DEADBEEFCAFE"));
        assert!(body.contains("[REDACTED:egress]"));
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
        assert!(r.headers.contains_key("Content-Type")); // unrelated header kept
    }

    #[test]
    fn test_egress_redact_patterns_also_scrub_headers() {
        let mut r = resp("body ok");
        r.headers.insert("Set-Cookie".to_string(), "session=DEADBEEFCAFE".to_string());
        let rules = vec![EgressRule {
            credential_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            block: false,
            redact_patterns: vec![Regex::new("[A-F0-9]{8,}").unwrap()],
        }];
        apply_egress(&mut r, &rules, "any", "http.request");
        let cookie = r.headers.get("Set-Cookie").unwrap();
        assert!(!cookie.contains("DEADBEEFCAFE"), "header secret survived: {cookie}");
        assert!(cookie.contains("[REDACTED:egress]"));
    }

    #[test]
    fn test_redact_catches_percent_encoded_form() {
        // A reflector that returns the secret percent-encoded is still scrubbed.
        let secret = "a b/c+d=secret"; // special chars → distinct encoded form
        let encoded = urlencoding::encode(secret).into_owned();
        let mut r = resp(&format!("echo {}", encoded));
        redact_secret_material(&mut r, &[secret.to_string()], "x");
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains(&encoded), "percent-encoded secret survived: {body}");
        assert!(body.contains("[REDACTED:x]"));
    }

    #[test]
    fn test_unredactable_secret_detection() {
        assert!(has_unredactable_secret(&["pin".to_string()])); // 3 < 5
        assert!(!has_unredactable_secret(&["longenough".to_string()]));
        assert!(!has_unredactable_secret(&["".to_string()])); // empty ignored
    }

    #[test]
    fn test_egress_no_matching_rule_is_noop() {
        let mut r = resp("hello");
        let rules = vec![EgressRule {
            credential_pattern: "other-*".to_string(),
            action_pattern: "*".to_string(),
            block: true,
            redact_patterns: vec![],
        }];
        apply_egress(&mut r, &rules, "pay-1", "http.request");
        assert_eq!(String::from_utf8_lossy(&r.body), "hello");
    }
}
