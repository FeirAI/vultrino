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
        // A '%' that does not start a valid escape is encoded, so a URL the parser
        // accepts always reaches a fixed point (a decoded unreserved character
        // can never complete a new escape).
        if bytes[i] == b'%' {
            out.push_str("%25");
            i += 1;
            continue;
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
        // A value such as "/\t/evil.com/x" becomes the scheme-relative
        // "//evil.com/x" once the tab is stripped: policy must never judge a
        // URL whose host it has discarded.
        if u.host_str() != Some("relative.invalid")
            || u.port().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return None;
        }
        let mut s = u.path().to_string();
        if let Some(q) = u.query() {
            s.push('?');
            s.push_str(q);
        }
        return Some(normalize_percent(&s));
    }
    let mut u = Url::parse(raw).ok()?;
    // Userinfo is not part of the destination but reqwest turns it into a
    // Basic header on the same host and path, so `https://u@host/admin` would
    // sidestep a rule on `https://host/admin/*`. Refuse it.
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    u.set_fragment(None);
    // `host.` and `host` are the same destination (client-side DNS): drop the
    // trailing dot so one spelling remains.
    let trimmed = match u.host() {
        Some(url::Host::Domain(h)) if h.ends_with('.') => Some(h.trim_end_matches('.').to_string()),
        _ => None,
    };
    if let Some(h) = trimmed {
        if h.is_empty() {
            return None;
        }
        u.set_host(Some(&h)).ok()?;
    }
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

/// Comparison form used only to decide whether canonicalisation changed what a
/// pattern means: percent escapes decoded (the parser encodes `{`, `}`, a space
/// and the like in the URL the same way, so such an escape is not a change),
/// case folded, default ports and a trailing slash ignored. Anything else that
/// differs (fragment, dot segments, backslashes, a moved `?`) is a meaning
/// change.
fn loose(s: &str) -> String {
    let mut t =
        String::from_utf8_lossy(&urlencoding::decode_binary(s.as_bytes())).to_ascii_lowercase();
    for port in [":443", ":80"] {
        t = t
            .replace(&format!("{port}/"), "/")
            .replace(&format!("{port}?"), "?");
        if let Some(x) = t.strip_suffix(port) {
            t = x.to_string();
        }
    }
    t.trim_end_matches('/').to_string()
}

/// Whether a `*` cuts a percent escape short (`/v1/%2*`, `a%*b`). That `%` is
/// re-encoded as `%25`, so the pattern no longer matches the escapes it used to
/// match. `loose` cannot see this: it decodes `%25` back to the same `%`.
fn star_cuts_an_escape(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    (0..b.len()).any(|i| b[i] == b'%' && b[i + 1..].iter().take(2).any(|&c| c == b'*'))
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
    if body.is_empty() {
        return keep(pattern, warnings);
    }
    // Scheme only (`https://*`): lower-case it, the URL side is lower-case.
    if let Some(scheme) = body.strip_suffix("://") {
        if scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            return keep(&pattern.to_ascii_lowercase(), warnings);
        }
    }
    // No scheme and not a path: `*.example.com/*`, `*example.com*`, `http*`.
    if !(body.contains("://") || is_relative(body)) {
        // A prefix of `http://` or `https://` (`http*`, `https*`) has no host
        // part: a canonical URL starts with its lower-case scheme, so such a
        // prefix can only match there and its `*` is not in a host. Any other
        // body keeps the warning: `internal*`, `evil*` or `HTTP*` match no
        // canonical http(s) URL at all, so a Deny or Prompt rule on one is dead,
        // and the warning is the only sign of that.
        let scheme_prefix =
            prefix_mode && ["http://", "https://"].iter().any(|s| s.starts_with(body));
        if pattern != "*" && !scheme_prefix && pattern.split('/').next().unwrap_or("").contains('*')
        {
            warnings.push(PatternWarning::StarInHost);
        }
        return keep(pattern, warnings);
    }
    let rest = body.split_once("://").map(|x| x.1);
    // A glob whose host part holds `?` would be reparsed as a query delimiter.
    // Keep the old literal glob meaning and say so.
    if let (false, Some(r)) = (prefix_mode, rest) {
        let auth_end = r.find('/').unwrap_or(r.len());
        if r[..auth_end].contains('?') {
            return keep(pattern, vec![PatternWarning::Unparseable]);
        }
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
    }
    // `https://host*`: nothing after the authority. Matched with a host
    // boundary (see `canonical_matches`).
    let host_only = prefix_mode && rest.is_some_and(|r| !r.contains(['/', '?', '#']));
    if host_only {
        warnings.push(PatternWarning::StarAfterHost);
    }
    if loose(body) != loose(&canon) || star_cuts_an_escape(pattern) {
        warnings.push(PatternWarning::MeaningChanged);
    }
    let text = if host_only {
        format!("{}*", canon.trim_end_matches('/'))
    } else if prefix_mode {
        format!("{canon}*")
    } else {
        canon
    };
    CanonPattern { text, warnings }
}

/// Match an already-canonical URL against an already-canonical pattern.
///
/// A prefix that stops right after a host (`https://api.example.com*`) is a
/// host match: the prefix must be followed by a port, a path, a query or the
/// end, never by more host characters (`api.example.com.evil.net`).
pub fn canonical_matches(url: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        if !url.starts_with(prefix) {
            return false;
        }
        let host_only = prefix
            .split_once("://")
            .is_some_and(|(_, r)| !r.is_empty() && !r.contains('/'));
        if host_only {
            let rest = &url[prefix.len()..];
            return rest.is_empty() || rest.starts_with(['/', ':', '?']);
        }
        true
    } else if let Ok(glob) = glob::Pattern::new(pattern) {
        glob.matches(url)
    } else {
        url == pattern
    }
}

/// The URL that policy judges and the HTTP plugins send: the canonical form of
/// `url` with the caller's `query` map merged in, sorted by key and encoded
/// with percent-escapes. `None` when the base URL cannot be canonicalised.
pub fn effective_url(
    url: &str,
    query: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let base = canonical_url(url)?;
    if query.is_empty() {
        return Some(base);
    }
    let mut pairs: Vec<_> = query.iter().collect();
    pairs.sort();
    let qs = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let sep = if base.contains('?') { '&' } else { '?' };
    canonical_url(&format!("{base}{sep}{qs}"))
}

/// The URL string policy evaluates for a request's params (`url` plus the
/// `query` map). `None` when there is no `url`. A URL that cannot be
/// canonicalised yields the empty string, which no rule can match and which the
/// engine's unparseable pre-check treats as a deny trigger.
pub fn policy_url(params: &serde_json::Value) -> Option<String> {
    let raw = params.get("url")?.as_str()?;
    let query = match params.get("query") {
        Some(serde_json::Value::Object(m)) => m
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect(),
        _ => std::collections::HashMap::new(),
    };
    Some(effective_url(raw, &query).unwrap_or_default())
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
            // The parser encodes `{` and `}` in a path; the URL side is encoded
            // the same way, so this is not a meaning change.
            "https://api.telegram.org/bot{credential}/sendMessage",
            "https://api.example.com/a b/*",
            "HTTPS://API.example.com:443/v1/%61*",
            "https://api.github.com/x",
            "*",
            "https://*",
            "/v1/refunds/*",
        ] {
            assert!(w(quiet).is_empty(), "{quiet}: {:?}", w(quiet));
        }
    }

    /// A trailing-star prefix of `http://` or `https://` (`http*`) has no host
    /// part, so it is not reported as a star in the host (which is planned to be
    /// refused). It matches by scheme only. Any other scheme-less prefix keeps
    /// the warning: it matches no canonical http(s) URL, so a Deny or Prompt
    /// rule on it is dead and the warning is the only sign of that.
    #[test]
    fn scheme_prefix_star_is_not_a_star_in_the_host() {
        let w = |p: &str| canonical_pattern(p).warnings;
        for quiet in ["h*", "http*", "https*", "https:*"] {
            assert!(w(quiet).is_empty(), "{quiet}: {:?}", w(quiet));
        }
        assert!(url_matches("https://api.example.com/x", "http*"));
        assert!(url_matches("http://api.example.com/x", "http*"));
        assert!(!url_matches("http://api.example.com/x", "https*"));
        // A prefix that is not the start of an http(s) scheme never matches a
        // canonical http(s) URL: it keeps its warning.
        for dead in ["internal*", "evil*", "localhost*", "api*", "ftp*"] {
            assert!(
                !url_matches("https://internal.example.com/x", dead),
                "{dead}"
            );
        }
        // Host characters before the star are still a star in the host.
        for warned in [
            "*.example.com/*",
            "*example.com*",
            "api.*",
            "http*.example.com/*",
            "HTTP*",
            "internal*",
            "evil*",
            "localhost*",
            "ftp*",
        ] {
            assert!(
                w(warned).contains(&PatternWarning::StarInHost),
                "{warned}: {:?}",
                w(warned)
            );
        }
    }

    /// docs/src/guides/policies.md: a `url_match` glob has no `{a,b}`
    /// alternation. The braces are literal (percent-encoded in canonical form),
    /// so such a pattern matches none of the paths it seems to list.
    #[test]
    fn brace_alternation_is_literal_not_a_glob_feature() {
        let pat = "https://api.github.com/{user,repos,gists}/*";
        for url in [
            "https://api.github.com/user/x",
            "https://api.github.com/repos/a/b",
            "https://api.github.com/gists/1",
        ] {
            assert!(!url_matches(url, pat), "{url}");
        }
        assert_eq!(
            canonical_pattern(pat).text,
            "https://api.github.com/%7Buser,repos,gists%7D/*"
        );
    }

    #[test]
    fn userinfo_and_hidden_hosts_are_not_canonicalisable() {
        for bad in [
            "https://u@api.example.com/x",
            "https://u:p@api.example.com/x",
            "/\t/evil.com/x",
            "//evil.com/x",
        ] {
            assert_eq!(canonical_url(bad), None, "{bad}");
        }
        assert_eq!(
            canonical_url("https://API.example.com.:8443/x").as_deref(),
            Some("https://api.example.com:8443/x")
        );
    }

    #[test]
    fn stray_percent_reaches_a_fixed_point() {
        let c = canonical_url("https://a.example/%%%33%32%%36%35").expect("parseable");
        assert_eq!(canonical_url(&c).as_deref(), Some(c.as_str()));
        assert_eq!(c, "https://a.example/%25%2532%2565");
    }

    #[test]
    fn more_pattern_warnings() {
        let w = |p: &str| canonical_pattern(p).warnings;
        assert!(w("https://api.example.com/x#*").contains(&PatternWarning::MeaningChanged));
        assert!(w("https://api.example.com/v1/%2e%2e/admin/*")
            .contains(&PatternWarning::MeaningChanged));
        assert!(w("https://api.example.com\\admin/*").contains(&PatternWarning::MeaningChanged));
        assert!(w("*.example.com/*").contains(&PatternWarning::StarInHost));
        assert!(w("*example.com*").contains(&PatternWarning::StarInHost));
        assert!(!w("https://api?.example.com/v1/*/x").is_empty());
        // A `*` that cuts an escape short: the stray `%` is re-encoded as %25.
        assert!(w("https://api.example.com/v1/%2*").contains(&PatternWarning::MeaningChanged));
        assert!(w("https://api.example.com/v1/a%*/x").contains(&PatternWarning::MeaningChanged));
        assert!(w("https://api.example.com/v1/%2F*").is_empty());
        assert_eq!(canonical_pattern("HTTPS://*").text, "https://*");
        assert_eq!(
            canonical_pattern("https://api?.example.com/v1/*/x").text,
            "https://api?.example.com/v1/*/x"
        );
    }

    #[test]
    fn host_boundary_matching() {
        let p = canonical_pattern("https://api.example.com*").text;
        assert_eq!(p, "https://api.example.com*");
        for yes in [
            "https://api.example.com/x",
            "https://api.example.com:8443/x",
            "https://api.example.com/?a=1",
        ] {
            assert!(canonical_matches(yes, &p), "{yes}");
        }
        for no in [
            "https://api.example.com.evil.net/",
            "https://api.example.coma/",
        ] {
            assert!(!canonical_matches(no, &p), "{no}");
        }
        assert!(!canonical_matches(
            "https://h:84430/",
            &canonical_pattern("https://h:8443*").text
        ));
    }

    #[test]
    fn pattern_canonical_text() {
        assert_eq!(
            canonical_pattern("HTTPS://API.example.com:443/v1/%61*").text,
            "https://api.example.com/v1/a*"
        );
        assert_eq!(
            canonical_pattern("https://api.example.com*").text,
            "https://api.example.com*"
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
