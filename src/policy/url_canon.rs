//! Canonical form for URL policy matching (SB-03).
//!
//! `UrlMatch` used to compare the raw agent-supplied string against a pattern by
//! case-sensitive prefix or glob. Equivalent spellings of one URL
//! (`HTTPS://API.EXAMPLE.COM:443/a/../v1`, `%61pi`, ...) therefore evaded Deny
//! rules, and a prefix such as `https://api.example.com*` also matched
//! `https://api.example.com.evil.net`.
//!
//! The URL is now matched in canonical form: parsed with the `url` crate (scheme
//! and host lowercased, IDNA to ASCII, default port dropped, dot segments
//! resolved, tabs/newlines/backslashes handled the way a client does), the
//! fragment dropped (it is never sent), and percent-encoding normalised
//! (unreserved characters decoded, remaining escapes upper-cased). The HTTP
//! plugins send exactly this string, so the URL that was judged is the URL that
//! is sent.
//!
//! A path-only reference (`/v1/refunds`, the `internal_http` shape) is
//! canonicalised against a dummy base and kept path-only.

use url::Url;

const DUMMY_BASE: &str = "http://relative.invalid";
/// Stands in for `*` while a glob pattern is parsed as a URL. Lowercase ASCII
/// letters and digits survive every normalisation step unchanged.
const STAR: &str = "zzstarzz0";

fn is_relative(raw: &str) -> bool {
    raw.starts_with('/') && !raw.starts_with("//") && !raw.starts_with("/\\")
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Decode percent-escapes of unreserved characters and upper-case the rest.
fn normalize_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                let b = (h * 16 + l) as u8;
                if is_unreserved(b) {
                    out.push(b as char);
                } else {
                    out.push_str(&format!("%{:02X}", b));
                }
                i += 3;
                continue;
            }
        }
        // Non-escape bytes: copy the whole char (input is valid UTF-8).
        let ch = s[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn one_pass(raw: &str) -> Option<String> {
    if is_relative(raw) {
        let base = Url::parse(DUMMY_BASE).ok()?;
        let u = Url::options().base_url(Some(&base)).parse(raw).ok()?;
        let mut s = u.path().to_string();
        if let Some(q) = u.query() {
            s.push('?');
            s.push_str(q);
        }
        return Some(normalize_percent(&s));
    }
    let mut u = Url::parse(raw).ok()?;
    u.set_fragment(None);
    Some(normalize_percent(u.as_str()))
}

/// Canonical form of a request URL, or `None` when it cannot be parsed.
///
/// Idempotent: a second pass is applied so that a decoded escape cannot reveal a
/// dot segment or a different structure that the first pass did not see.
pub fn canonical_url(raw: &str) -> Option<String> {
    let first = one_pass(raw)?;
    let second = one_pass(&first)?;
    if first == second {
        Some(second)
    } else {
        // Not a fixed point after two passes: refuse rather than guess.
        let third = one_pass(&second)?;
        (third == second).then_some(second)
    }
}

/// Why a pattern deserves a load-time warning. Refused in a future release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternWarning {
    /// The pattern ends in `*` right after a host (no `/`): it used to match
    /// look-alike hosts such as `api.example.com.evil.net`. It now stops at the
    /// host boundary.
    StarAfterHost,
    /// `*` inside the host part. A glob `*` also matches `/`, so such a pattern
    /// can match a different host.
    StarInHost,
    /// Canonicalisation changed what the pattern means (dot segments resolved, a
    /// path appended, ...). Pure case, default-port and percent-encoding
    /// rewrites are not reported.
    MeaningChanged,
    /// The pattern is not a parseable URL or path; it is compared literally.
    Unparseable,
}

/// A pattern in canonical form plus load-time warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonPattern {
    pub text: String,
    pub warnings: Vec<PatternWarning>,
}

fn host_part(s: &str) -> Option<&str> {
    let rest = s.split_once("://")?.1;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    Some(auth.rsplit_once('@').map(|x| x.1).unwrap_or(auth))
}

/// Canonicalise a policy pattern. Same two shapes as before: a trailing `*`
/// makes a literal prefix, anything else is a glob (or an exact match).
pub fn canonical_pattern(pattern: &str) -> CanonPattern {
    let mut warnings = Vec::new();
    let keep = |text: &str, warnings: Vec<PatternWarning>| CanonPattern {
        text: text.to_string(),
        warnings,
    };
    if pattern.contains(STAR) {
        return keep(pattern, vec![PatternWarning::Unparseable]);
    }
    let (body, prefix_mode) = match pattern.strip_suffix('*') {
        Some(b) => (b, true),
        None => (pattern, false),
    };
    // `*`, `https://*`, `http*` and similar: nothing to canonicalise.
    if body.is_empty() || body.ends_with("://") || !(body.contains("://") || is_relative(body)) {
        return keep(pattern, warnings);
    }
    let src = if prefix_mode {
        body.to_string()
    } else {
        body.replace('*', STAR)
    };
    let Some(mut canon) = canonical_url(&src) else {
        return keep(pattern, vec![PatternWarning::Unparseable]);
    };
    if !prefix_mode {
        canon = canon.replace(STAR, "*");
    }
    if let Some(h) = host_part(body) {
        if h.contains('*') {
            warnings.push(PatternWarning::StarInHost);
        }
        if prefix_mode {
            // `https://host*`: no `/` after the authority.
            let rest = body.split_once("://").map(|x| x.1).unwrap_or("");
            if !rest.contains('/') {
                warnings.push(PatternWarning::StarAfterHost);
            }
        }
    }
    // Meaning change: ignore case/port/percent rewrites by comparing the
    // structure after resolving only those. A dot segment or an appended path
    // shows up as a different segment list.
    let segs = |s: &str| -> Vec<String> {
        let after = s.split_once("://").map(|x| x.1).unwrap_or(s);
        let path = after.find('/').map(|i| &after[i..]).unwrap_or("");
        path.split(['?', '#'])
            .next()
            .unwrap_or("")
            .split('/')
            .map(|x| x.to_string())
            .collect()
    };
    let before = segs(body);
    let after = segs(&canon);
    let host_only_prefix = prefix_mode && warnings.contains(&PatternWarning::StarAfterHost);
    if !host_only_prefix && before.iter().any(|s| s == "." || s == "..") && before != after {
        warnings.push(PatternWarning::MeaningChanged);
    }
    CanonPattern {
        text: if prefix_mode {
            format!("{canon}*")
        } else {
            canon
        },
        warnings,
    }
}

/// Match an already-canonical URL against an already-canonical pattern.
pub fn canonical_matches(url: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        url.starts_with(prefix)
    } else if let Ok(glob) = glob::Pattern::new(pattern) {
        glob.matches(url)
    } else {
        url == pattern
    }
}

/// `UrlMatch` semantics: canonicalise both sides, then match. A URL that cannot
/// be canonicalised never matches.
pub fn url_matches(raw_url: &str, raw_pattern: &str) -> bool {
    match canonical_url(raw_url) {
        Some(u) => canonical_matches(&u, &canonical_pattern(raw_pattern).text),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_examples() {
        for (raw, want) in [
            (
                "HTTPS://API.Example.COM:443/a/../v1/%61?q=%7e#f",
                "https://api.example.com/v1/a?q=~",
            ),
            ("http://example.com:80", "http://example.com/"),
            ("https://example.com:8443/x", "https://example.com:8443/x"),
            ("https://example.com/%2f%2F", "https://example.com/%2F%2F"),
            ("https://example.com/./b/%2e%2e/c", "https://example.com/c"),
            ("/v1/./x/../refunds?a=%41", "/v1/refunds?a=A"),
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ] {
            assert_eq!(canonical_url(raw).as_deref(), Some(want), "{raw}");
        }
        for bad in ["", "https://[::1", "http://", "nonsense"] {
            assert_eq!(canonical_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn canonicalisation_is_idempotent() {
        for raw in [
            "https://a.example/%2e%2e/%2E/x%2",
            "https://a.example/.%2e/x",
            "HTTP://A.example:80/%7Euser/%e4%bd%a0",
            "/a/%2e%2e/b",
        ] {
            if let Some(c) = canonical_url(raw) {
                assert_eq!(canonical_url(&c).as_deref(), Some(c.as_str()), "{raw}");
            }
        }
    }

    #[test]
    fn pattern_warnings() {
        let w = |p: &str| canonical_pattern(p).warnings;
        assert!(w("https://api.example.com*").contains(&PatternWarning::StarAfterHost));
        assert!(w("https://*.example.com/x").contains(&PatternWarning::StarInHost));
        assert!(w("https://*.example.com/*").contains(&PatternWarning::StarInHost));
        assert!(w("https://api.example.com/a/../b/*").contains(&PatternWarning::MeaningChanged));
        assert!(w("https://[::1/*").contains(&PatternWarning::Unparseable));
        // Quiet cases: case, default port, percent rewrites, plain prefixes.
        for quiet in [
            "https://api.example.com/*",
            "HTTPS://API.example.com:443/v1/%61*",
            "https://api.github.com/x",
            "*",
            "https://*",
            "/v1/refunds/*",
        ] {
            assert!(w(quiet).is_empty(), "{quiet}: {:?}", w(quiet));
        }
    }

    #[test]
    fn pattern_canonical_text() {
        assert_eq!(
            canonical_pattern("HTTPS://API.example.com:443/v1/%61*").text,
            "https://api.example.com/v1/a*"
        );
        assert_eq!(
            canonical_pattern("https://api.example.com*").text,
            "https://api.example.com/*"
        );
        assert_eq!(
            canonical_pattern("https://api.example.com").text,
            "https://api.example.com/"
        );
        assert_eq!(
            canonical_pattern("https://*.example.com/x").text,
            "https://*.example.com/x"
        );
    }
}
