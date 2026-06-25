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

/// Build the set of forms to scrub for a credential's secret material: the raw
/// secret plus its percent-encoded and JSON-escaped representations, each at least
/// [`MIN_REDACT_LEN`] bytes, deduplicated and sorted **longest-first** (so a longer
/// encoded form is replaced before a shorter form it may contain).
///
/// This is the SINGLE source of truth for the scrub form-set: the buffered
/// [`redact_secret_material`], the streaming [`StreamScrubber`], and
/// [`scrub_headers`] all call it, so the two paths cannot disagree on what counts
/// as a secret (a divergence would be a silent secret-leak vector). Parity is thus
/// guaranteed by construction; the `streamed_scrub_equals_buffered` proptest also
/// checks output equivalence over many forms/chunkings.
pub fn derive_secret_forms(secrets: &[Zeroizing<String>]) -> Vec<String> {
    // Add `candidate` only if it is a distinct, long-enough reflection of `raw` (a form
    // equal to raw, or below the redaction floor, adds nothing).
    fn add(forms: &mut Vec<String>, candidate: String, raw: &str) {
        if candidate != raw && candidate.len() >= MIN_REDACT_LEN {
            forms.push(candidate);
        }
    }
    let mut forms: Vec<String> = Vec::new();
    for secret in secrets {
        let raw: &str = secret;
        if raw.len() < MIN_REDACT_LEN {
            continue;
        }
        forms.push(raw.to_string());
        // Percent-encoded (URL/query reflection). urlencoding emits UPPERCASE hex; also add
        // the lowercase-hex variant — percent-escape hex is case-insensitive on the wire, so
        // a client/upstream using `%2f` (vs `%2F`) would otherwise slip past byte-exact match.
        // And the application/x-www-form-urlencoded variant (space → `+`, not `%20`).
        let pct = urlencoding::encode(raw).into_owned();
        let pct_lower = percent_hex_lower(&pct);
        if pct.contains("%20") {
            add(&mut forms, pct.replace("%20", "+"), raw);
            add(&mut forms, pct_lower.replace("%20", "+"), raw);
        }
        if pct_lower != pct {
            add(&mut forms, pct_lower, raw);
        }
        add(&mut forms, pct, raw);
        // JSON-escaped inner (serde default: \", \\, \n, control \uXXXX). Also a
        // slash-escaped variant — HTML-safe JSON encoders emit `/` as `\/`, which the
        // default escaping does not, so a secret with `/` reflected by such an encoder
        // would otherwise slip past.
        if let Some(escaped) = json_escaped_inner(raw) {
            if escaped.contains('/') {
                add(&mut forms, escaped.replace('/', "\\/"), raw);
            }
            add(&mut forms, escaped, raw);
        }
        // Slash-escaped raw (an encoder that escapes only `/`, no other special chars).
        if raw.contains('/') {
            add(&mut forms, raw.replace('/', "\\/"), raw);
        }
        // JSON \uXXXX-escaped variants for the realistic single-pass encoder dialects:
        //   - ensure_ascii: ALL non-ASCII → \uXXXX (Python json.dumps default, etc.);
        //   - HTML-safe: `<` `>` `&` → </3e/26 (Go encoding/json default).
        // Generated in BOTH hex cases (\uXXXX hex is case-insensitive; a given encoder is
        // consistent-case), each also COMPOSED with `/` → `\/`. Bounded: a handful of
        // consistent-case dialects, NOT per-character combinatorics. See the egress note in
        // docs/dev/LIMITATIONS.md — this is best-effort defense-in-depth against ACCIDENTAL
        // reflection; an adversarially-encoding upstream is out of byte-exact-match scope.
        if !raw.is_ascii() || raw.contains(['<', '>', '&']) {
            for upper in [false, true] {
                for html_safe in [false, true] {
                    let esc = json_unicode_escaped(raw, upper, html_safe);
                    if esc.contains('/') {
                        add(&mut forms, esc.replace('/', "\\/"), raw);
                    }
                    add(&mut forms, esc, raw);
                }
            }
        }
    }
    forms.sort();
    forms.dedup();
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms
}

/// Lowercase the hex digits in every `%XX` percent-escape of an (ASCII) percent-encoded
/// string, leaving everything else untouched — percent-escape hex is case-insensitive, so
/// this complements urlencoding's uppercase output for byte-exact scrubbing.
fn percent_hex_lower(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push('%');
            out.push((b[i + 1] as char).to_ascii_lowercase());
            out.push((b[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// A JSON-string inner with `\uXXXX` escaping for the realistic encoder dialects:
/// - ALWAYS escapes EVERY non-ASCII char as `\uXXXX` (with surrogate pairs for astral code
///   points) — the "ensure_ascii" encoding (Python json.dumps default, many others); serde
///   emits raw UTF-8 for printable non-ASCII, so this catches an ensure_ascii upstream.
/// - when `html_safe`, ALSO escapes `<` `>` `&` as `</3e/26` — Go's encoding/json
///   default (HTML-safe), which the plain escaping leaves raw.
///
/// `upper` selects the hex-digit case. The caller generates all (upper × html_safe) combos.
fn json_unicode_escaped(s: &str, upper: bool, html_safe: bool) -> String {
    let u = |cp: u32| {
        if upper {
            format!("\\u{:04X}", cp)
        } else {
            format!("\\u{:04x}", cp)
        }
    };
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' if html_safe => out.push_str(&u(c as u32)),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c if (c as u32) <= 0xFFFF => out.push_str(&u(c as u32)),
            c => {
                let cp = c as u32 - 0x10000;
                let hi = 0xD800 + (cp >> 10);
                let lo = 0xDC00 + (cp & 0x3FF);
                out.push_str(&u(hi));
                out.push_str(&u(lo));
            }
        }
    }
    out
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
    // Forms to scrub, deduped and longest-first (shared with StreamScrubber so the
    // buffered and streaming paths can never disagree on what counts as a secret).
    let mut forms: Vec<String> = derive_secret_forms(secrets);

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

/// If a response is still compressed (a `Content-Encoding` the HTTP client did
/// not decompress, e.g. `zstd`), its body is opaque to the secret scrubber — so
/// **fail closed** by withholding it entirely. Returns whether it blocked. Call
/// before redaction so a compressed reflected secret can never slip through.
pub fn block_if_compressed(resp: &mut ExecuteResponse) -> bool {
    let still_compressed = resp.headers.iter().any(|(k, v)| {
        (k.eq_ignore_ascii_case("content-encoding") || k.eq_ignore_ascii_case("transfer-encoding"))
            && is_compression(v)
    });
    if still_compressed {
        resp.body =
            b"[vultrino: response withheld - a compressed body could not be scrubbed for secrets]"
                .to_vec();
        resp.headers.clear();
        resp.headers.insert("Content-Type".to_string(), "text/plain".to_string());
        return true;
    }
    false
}

/// Whether a `Content-Encoding`/`Transfer-Encoding` value names an actual
/// content compression the HTTP client did not strip (reqwest removes
/// `Content-Encoding` when it decompresses gzip/deflate/br). Any token other
/// than `identity` or the `chunked` framing is treated as compression, handling
/// multi-value lists (`gzip, br`) and case-insensitively — so unknown/legacy
/// codecs (`x-gzip`, `zstd`) are caught fail-closed rather than waved through.
fn is_compression(value: &str) -> bool {
    value.split(',').map(str::trim).any(|t| {
        !t.is_empty() && !t.eq_ignore_ascii_case("identity") && !t.eq_ignore_ascii_case("chunked")
    })
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
        // Headers can also carry secrets (Set-Cookie, tokens) — drop them too,
        // then label the placeholder body.
        resp.headers.clear();
        resp.headers.insert("Content-Type".to_string(), "text/plain".to_string());
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

/// Run the full V7 egress pipeline over a freshly-executed response, in one
/// place, before the body ever reaches the agent. Pure with respect to the
/// rest of the system: it only mutates `resp` (and emits warning logs) — no
/// audit / metrics / policy side effects live here, so the early return on a
/// withheld compressed body loses nothing.
///
/// Order matters and is fail-closed:
/// 1. If the body is still compressed (an encoding the client didn't decode) it
///    can't be scrubbed, so withhold it and stop — the body is now an opaque
///    placeholder and the headers have been replaced, so further scrub /
///    classify / framing-strip would be pointless.
/// 2. Otherwise scrub the credential's own reflected secret, then apply operator
///    egress classification (block / extra redaction).
/// 3. If either changed the body, drop framing headers a stale `Content-Length`
///    would otherwise leak or corrupt.
pub fn scrub_response(
    resp: &mut ExecuteResponse,
    secrets: &[Zeroizing<String>],
    alias: &str,
    rules: &[EgressRule],
    action: &str,
) {
    if block_if_compressed(resp) {
        // NOTE: this early return must stay side-effect-free. Any future audit /
        // metric emission about the response belongs in the caller, not here, or
        // the withheld-compressed path would silently skip it.
        return;
    }
    let redacted = redact_secret_material(resp, secrets, alias);
    let classified = apply_egress(resp, rules, alias, action);
    if redacted || classified {
        strip_content_framing_headers(resp);
    }
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

/// Scrub the credential's secret forms out of header VALUES in place (the
/// streaming-path analogue of the header half of [`redact_secret_material`]). The
/// streaming response head commits to the wire before any body byte, so a secret
/// reflected in a provider response header must be redacted here, before the head
/// is flushed. `forms` is the shared [`derive_secret_forms`] set. Returns whether
/// any header was changed.
pub fn scrub_headers(
    headers: &mut std::collections::HashMap<String, String>,
    forms: &[String],
    alias: &str,
) -> bool {
    let marker = format!("[REDACTED:{}]", alias);
    let mut modified = false;
    for v in headers.values_mut() {
        for form in forms {
            if v.contains(form.as_str()) {
                *v = v.replace(form.as_str(), &marker);
                modified = true;
            }
        }
    }
    modified
}

/// Whether a `(credential, action)` is safe to serve on the INCREMENTAL streaming
/// path (connector M1). The always-on literal credential-secret scrub
/// ([`StreamScrubber`]) runs incrementally, but the two operator [`EgressRule`]
/// classifications cannot:
/// - a `block` rule withholds the WHOLE body (any streamed byte is a leak), and
/// - `redact_patterns` are arbitrary regexes that can match across an unbounded
///   span, so no finite carry buffer can apply them correctly at a chunk seam.
///
/// When a matching rule carries either, the caller must fall back to the BUFFERED
/// path (where `apply_egress` runs whole-body) rather than stream — an honest,
/// fail-closed trade. Returns `true` only when no matching rule has `block` or a
/// non-empty `redact_patterns`.
pub fn stream_is_egress_safe(rules: &[EgressRule], alias: &str, action: &str) -> bool {
    !rules
        .iter()
        .any(|r| r.matches(alias, action) && (r.block || !r.redact_patterns.is_empty()))
}

/// Whether response headers indicate a body the HTTP client did NOT decompress
/// (an exotic `Content-Encoding`/`Transfer-Encoding` like `zstd`). Such a streamed
/// body is opaque to the secret scrubber, so the streaming path must withhold it
/// fail-closed — the streaming analogue of [`block_if_compressed`], decided from
/// the head before any body byte is forwarded.
pub fn headers_indicate_compression(headers: &std::collections::HashMap<String, String>) -> bool {
    headers.iter().any(|(k, v)| {
        (k.eq_ignore_ascii_case("content-encoding") || k.eq_ignore_ascii_case("transfer-encoding"))
            && is_compression(v)
    })
}

/// A fatal condition on the streaming scrub path. Surfaced so the adaptor can
/// terminate the stream fail-closed rather than forward un-scrubbable bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    /// The working buffer (retained carry + a single chunk) exceeded the configured
    /// hard cap — a delimiter-less giant payload that could OOM. Fail closed.
    BufferOverflow,
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrubError::BufferOverflow => {
                write!(f, "stream scrub buffer exceeded the configured cap")
            }
        }
    }
}

impl std::error::Error for ScrubError {}

/// Incremental secret scrubber for a **streamed** response body (connector M1).
///
/// The whole-body [`redact_secret_material`] can't run on a stream, so this scrubs
/// chunk-by-chunk while keeping the SAME guarantee: the credential's own secret
/// (and its [`derive_secret_forms`] encoded variants) never reaches the agent —
/// even when a secret straddles a chunk boundary.
///
/// ## Algorithm (carry-buffer)
/// It holds back the trailing `keep = max_form_len - 1` bytes of the working buffer
/// (`carry` + new chunk) each round, because a secret could *begin* within those
/// bytes and complete in the next chunk. Bytes before that danger zone are final:
/// a longest-first scan replaces every fully-present form occurrence with the
/// marker and emits the rest. A match that *starts* before the danger zone but
/// extends into it is fully present (forms are ≤ `max_form_len`), so it is replaced,
/// not split. [`Self::finish`] flushes the residual carry (a trailing partial form
/// is not a complete secret, so emitting it raw leaks nothing).
///
/// Security note: longest-first position scanning never leaves a complete form
/// intact — to skip a form occurrence the scan would have to pass its start
/// position without matching, but at that position the longest matching form (which
/// includes this one if nothing longer matched) *does* match; the only way an
/// occurrence is "missed" is if an earlier overlapping match already consumed its
/// start byte, which destroys the secret anyway.
pub struct StreamScrubber {
    /// Secret byte-forms, longest-first, each ≥ [`MIN_REDACT_LEN`]. Zeroized on drop.
    forms: Vec<Zeroizing<Vec<u8>>>,
    /// The `[REDACTED:alias]` replacement bytes.
    marker: Vec<u8>,
    /// Raw, not-yet-emittable trailing bytes carried to the next chunk. Zeroized.
    carry: Zeroizing<Vec<u8>>,
    /// `max_form_len - 1`: how many trailing bytes to hold back (0 when no forms).
    keep: usize,
    /// Hard cap on the working buffer (carry + chunk); over it, fail closed.
    max_buffer: usize,
}

impl StreamScrubber {
    /// Build a scrubber for a credential's secret material. `max_buffer` bounds the
    /// working buffer so a delimiter-less giant chunk fails closed instead of OOMing.
    pub fn new(secrets: &[Zeroizing<String>], alias: &str, max_buffer: usize) -> Self {
        let forms: Vec<Zeroizing<Vec<u8>>> = derive_secret_forms(secrets)
            .into_iter()
            .map(|s| Zeroizing::new(s.into_bytes()))
            .collect();
        let max_form_len = forms.iter().map(|f| f.len()).max().unwrap_or(0);
        Self {
            forms,
            marker: format!("[REDACTED:{}]", alias).into_bytes(),
            carry: Zeroizing::new(Vec::new()),
            keep: max_form_len.saturating_sub(1),
            max_buffer,
        }
    }

    /// Whether this scrubber will never modify bytes (no secret ≥ [`MIN_REDACT_LEN`]).
    /// Such a credential gets pure pass-through, matching the buffered path (which
    /// also can't redact a sub-`MIN_REDACT_LEN` secret); operators are warned at
    /// store time via [`has_unredactable_secret`].
    pub fn is_noop(&self) -> bool {
        self.forms.is_empty()
    }

    /// Feed one upstream chunk; returns the bytes safe to forward to the agent now
    /// (the rest is retained as carry until the next chunk or [`Self::finish`]).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, ScrubError> {
        if self.forms.is_empty() {
            return Ok(chunk.to_vec());
        }
        let mut working = std::mem::take(&mut *self.carry);
        working.extend_from_slice(chunk);
        if working.len() > self.max_buffer {
            // Fail closed — but first wipe the transient buffer (it holds raw,
            // pre-scrub secret-bearing bytes), symmetric with the normal push/finish
            // paths. The overflow early-return previously skipped this, leaving secret
            // material in freed heap until reuse.
            working.iter_mut().for_each(|b| *b = 0);
            return Err(ScrubError::BufferOverflow);
        }
        let safe_end = working.len().saturating_sub(self.keep);
        let (out, consumed) = self.scrub_prefix(&working, safe_end);
        *self.carry = working[consumed..].to_vec();
        // Wipe the transient working buffer (it held raw, pre-scrub bytes).
        working.iter_mut().for_each(|b| *b = 0);
        Ok(out)
    }

    /// Flush the residual carry at end-of-stream (everything is now final).
    pub fn finish(&mut self) -> Result<Vec<u8>, ScrubError> {
        if self.forms.is_empty() || self.carry.is_empty() {
            return Ok(Vec::new());
        }
        let mut working = std::mem::take(&mut *self.carry);
        let (out, _consumed) = self.scrub_prefix(&working, working.len());
        // Wipe the transient buffer (it held raw, pre-scrub secret-bearing bytes),
        // symmetric with `push`.
        working.iter_mut().for_each(|b| *b = 0);
        Ok(out)
    }

    /// Scrub `buf`, emitting final output and returning `(output, consumed)`. Bytes
    /// `buf[consumed..]` are retained as carry. `safe_end` is the input index beyond
    /// which an as-yet-incomplete match could still be completed by a future chunk:
    /// at or past it, a non-matching position stops the scan (retain from there).
    fn scrub_prefix(&self, buf: &[u8], safe_end: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            let matched = self.forms.iter().find_map(|form| {
                let f: &[u8] = form;
                if i + f.len() <= buf.len() && &buf[i..i + f.len()] == f {
                    Some(f.len())
                } else {
                    None
                }
            });
            match matched {
                Some(len) => {
                    out.extend_from_slice(&self.marker);
                    i += len;
                }
                None => {
                    // No complete form at i. In the danger zone a future chunk could
                    // still complete a match starting here, so stop and retain.
                    if i >= safe_end {
                        break;
                    }
                    out.push(buf[i]);
                    i += 1;
                }
            }
        }
        (out, i)
    }
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
    fn test_redact_catches_composed_ascii_escaped_slash_form() {
        // A secret with BOTH non-ASCII and '/', reflected by an ensure_ascii + HTML-safe
        // JSON encoder (e.g. Python json.dumps escaping slashes): é → é AND / → \/.
        // Neither the plain ensure_ascii form nor the plain slash-escaped form matches this
        // composed reflection — the COMPOSED derived form must.
        let secret = "café/key-1234567";
        // ensure_ascii renders the non-ASCII 'é' (U+00E9) as the 6 literal chars
        // backslash-u-0-0-e-9, and an HTML-safe pass renders '/' as backslash-slash. The
        // composed reflection is therefore "caf" + "é" + "\/" + "key-1234567".
        let composed = format!("caf{}{}key-1234567", "\\u00e9", "\\/");
        let mut r = resp(&format!("{{\"echo\":\"{composed}\"}}"));
        assert!(
            redact_secret_material(&mut r, &secrets(&[secret]), "x"),
            "composed ensure_ascii+slash secret must be detected"
        );
        let body = String::from_utf8_lossy(&r.body);
        assert!(!body.contains(composed.as_str()), "composed secret form survived: {body}");
        assert!(body.contains("[REDACTED:x]"));
    }

    #[test]
    fn test_redact_catches_alternate_hex_case_forms() {
        // \uXXXX and %XX hex are case-insensitive on the wire; the derived forms cover both
        // cases so an alternate-case reflection can't slip past byte-exact scrubbing.
        // (a) UPPERCASE ensure_ascii: é → é.
        let secret = "café-key-1234567";
        let upper_ascii = format!("caf{}-key-1234567", "\\u00E9");
        let mut r = resp(&format!("{{\"echo\":\"{upper_ascii}\"}}"));
        assert!(
            redact_secret_material(&mut r, &secrets(&[secret]), "x"),
            "uppercase \\u ensure_ascii form must be scrubbed"
        );
        assert!(!String::from_utf8_lossy(&r.body).contains(upper_ascii.as_str()));
        // (b) lowercase percent-escapes (urlencoding emits uppercase): %2f vs %2F. The secret
        // has only lowercase letters, so to_lowercase only re-cases the %-hex.
        let secret2 = "a/b/c-key-1234567";
        let lower_pct = urlencoding::encode(secret2).into_owned().to_lowercase();
        let mut r2 = resp(&format!("echo {lower_pct}"));
        assert!(
            redact_secret_material(&mut r2, &secrets(&[secret2]), "x"),
            "lowercase percent-escape form must be scrubbed"
        );
        assert!(!String::from_utf8_lossy(&r2.body).contains(lower_pct.as_str()));
    }

    #[test]
    fn test_redact_catches_form_url_plus_and_html_safe_forms() {
        // (a) application/x-www-form-urlencoded reflects space as `+` (not %20).
        let secret = "a b/c+d=secret";
        let form_url = urlencoding::encode(secret).into_owned().replace("%20", "+");
        let mut r = resp(&format!("echo {form_url}"));
        assert!(
            redact_secret_material(&mut r, &secrets(&[secret]), "x"),
            "form-url (+ for space) secret form must be scrubbed"
        );
        assert!(!String::from_utf8_lossy(&r.body).contains(form_url.as_str()));
        // (b) HTML-safe JSON (Go encoding/json) escapes < > & as </3e/26.
        let secret2 = "tok<a>&b-1234567";
        let html_safe = format!("tok{}a{}{}b-1234567", "\\u003c", "\\u003e", "\\u0026");
        let mut r2 = resp(&format!("{{\"echo\":\"{html_safe}\"}}"));
        assert!(
            redact_secret_material(&mut r2, &secrets(&[secret2]), "x"),
            "HTML-safe JSON (\\u003c/3e/26) secret form must be scrubbed"
        );
        assert!(!String::from_utf8_lossy(&r2.body).contains(html_safe.as_str()));
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
        // The secret header is dropped; only a labelling Content-Type remains.
        assert!(!r.headers.contains_key("Set-Cookie"));
        assert_eq!(r.headers.get("Content-Type").map(String::as_str), Some("text/plain"));
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
    fn test_egress_redact_binary_body_still_scrubs_headers() {
        // Body is binary (skipped), but a matching header is still redacted.
        let mut r = ExecuteResponse {
            status: 200,
            headers: HashMap::new(),
            body: vec![0xff, 0xfe, 0x00],
            updated_credential: None,
        };
        r.headers.insert("Set-Cookie".to_string(), "t=DEADBEEFCAFE".to_string());
        let before = r.body.clone();
        let modified = apply_egress(&mut r, &[rule("*", "*", false, &["[A-F0-9]{8,}"])], "a", "http.request");
        assert_eq!(r.body, before, "binary body must be untouched");
        assert!(!r.headers.get("Set-Cookie").unwrap().contains("DEADBEEFCAFE"));
        assert!(modified);
    }

    #[test]
    fn test_redact_header_only_secret_reports_modified() {
        // Secret only in a header (clean body) → still reports modified=true.
        let mut r = resp("clean body");
        r.headers.insert("X-Echo".to_string(), "Bearer sk-supersecret-123".to_string());
        assert!(redact_secret_material(&mut r, &secrets(&["sk-supersecret-123"]), "x"));
        assert!(r.headers.get("X-Echo").unwrap().contains("[REDACTED:x]"));
        assert_eq!(String::from_utf8_lossy(&r.body), "clean body");
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
    fn test_block_if_compressed() {
        // A residual non-identity Content-Encoding → body withheld; headers
        // cleared except a labelling Content-Type.
        let mut r = resp("compressed-bytes-with-secret");
        r.headers.insert("Content-Encoding".to_string(), "zstd".to_string());
        assert!(block_if_compressed(&mut r));
        assert!(String::from_utf8_lossy(&r.body).contains("withheld"));
        assert_eq!(r.headers.get("Content-Type").map(String::as_str), Some("text/plain"));
        assert!(!r.headers.keys().any(|k| k.eq_ignore_ascii_case("content-encoding")));

        // Case-insensitive, multi-value, and Transfer-Encoding compression block.
        for (hdr, val) in [
            ("content-encoding", "GZIP"),
            ("Content-Encoding", "gzip, br"),
            ("transfer-encoding", "gzip"),
            ("Transfer-Encoding", "chunked, gzip"),
        ] {
            let mut rr = resp("x");
            rr.headers.insert(hdr.to_string(), val.to_string());
            assert!(block_if_compressed(&mut rr), "expected block for {hdr}: {val}");
        }

        // identity / chunked-only / absent → not blocked.
        for (hdr, val) in [("content-encoding", "identity"), ("transfer-encoding", "chunked")] {
            let mut rr = resp("plain");
            rr.headers.insert(hdr.to_string(), val.to_string());
            assert!(!block_if_compressed(&mut rr), "must not block {hdr}: {val}");
            assert_eq!(String::from_utf8_lossy(&rr.body), "plain");
        }
        let mut r3 = resp("plain");
        assert!(!block_if_compressed(&mut r3));
        assert_eq!(String::from_utf8_lossy(&r3.body), "plain");

        // A pre-existing Content-Type is replaced (not duplicated) by the label.
        let mut r4 = resp("x");
        r4.headers.insert("content-type".to_string(), "application/json".to_string());
        r4.headers.insert("Content-Encoding".to_string(), "br".to_string());
        assert!(block_if_compressed(&mut r4));
        let cts: Vec<_> =
            r4.headers.keys().filter(|k| k.eq_ignore_ascii_case("content-type")).collect();
        assert_eq!(cts.len(), 1, "exactly one Content-Type after block");
        assert_eq!(r4.headers.get("Content-Type").map(String::as_str), Some("text/plain"));
    }

    #[test]
    fn test_is_compression_edge_tokens() {
        // Real / legacy / unknown codecs are compression (fail-closed).
        for v in ["gzip", "GZIP", "x-gzip", "zstd", "gzip, br", "identity, gzip", "deflate"] {
            assert!(is_compression(v), "{v:?} should count as compression");
        }
        // Framing-only / empty values are not compression.
        for v in ["", " ", "identity", "chunked", "IDENTITY", "chunked, identity", " , "] {
            assert!(!is_compression(v), "{v:?} should NOT count as compression");
        }
    }

    #[test]
    fn test_scrub_response_orchestration() {
        let secret = "supersecret-token-value";
        let rules = vec![rule("sts-*", "*", true, &[])];

        // (a) Compressed body → withheld, and the scrub/classify/strip steps are
        //     skipped: a matching block rule does NOT overwrite the compression
        //     placeholder, framing headers are gone, only the label remains.
        let mut r = resp(secret);
        r.headers.insert("Content-Encoding".to_string(), "gzip".to_string());
        r.headers.insert("Content-Length".to_string(), "999".to_string());
        scrub_response(&mut r, &secrets(&[secret]), "sts-prod", &rules, "http.request");
        assert!(String::from_utf8_lossy(&r.body).contains("compressed body could not be scrubbed"));
        assert!(!r.headers.keys().any(|k| k.eq_ignore_ascii_case("content-length")));
        assert_eq!(r.headers.get("Content-Type").map(String::as_str), Some("text/plain"));

        // (b) Reflected secret in an uncompressed body → scrubbed, and the stale
        //     Content-Length (set before redaction) is stripped.
        let mut r = resp(&format!("echo {secret} back"));
        r.headers.insert("Content-Length".to_string(), "99".to_string());
        scrub_response(&mut r, &secrets(&[secret]), "github-1", &[], "http.request");
        assert!(!String::from_utf8_lossy(&r.body).contains(secret));
        assert!(String::from_utf8_lossy(&r.body).contains("[REDACTED:github-1]"));
        assert!(!r.headers.keys().any(|k| k.eq_ignore_ascii_case("content-length")));

        // (c) Operator block rule on an uncompressed body → body+headers withheld.
        let mut r = resp("downstream secret payload");
        r.headers.insert("Set-Cookie".to_string(), "session=zzz".to_string());
        scrub_response(&mut r, &[], "sts-prod", &rules, "http.request");
        assert!(String::from_utf8_lossy(&r.body).contains("withheld by egress policy"));
        assert!(!r.headers.contains_key("Set-Cookie"));

        // (d) Clean body, no rules → untouched, framing preserved.
        let mut r = resp("nothing to see");
        r.headers.insert("Content-Length".to_string(), "14".to_string());
        scrub_response(&mut r, &secrets(&["unrelated"]), "github-1", &[], "http.request");
        assert_eq!(String::from_utf8_lossy(&r.body), "nothing to see");
        assert_eq!(r.headers.get("Content-Length").map(String::as_str), Some("14"));
    }

    #[test]
    fn test_egress_no_matching_rule_is_noop() {
        let mut r = resp("hello");
        assert!(!apply_egress(&mut r, &[rule("other-*", "*", true, &[])], "pay-1", "http.request"));
        assert_eq!(String::from_utf8_lossy(&r.body), "hello");
    }

    // --- StreamScrubber (incremental egress scrub) -------------------------

    /// Run the incremental scrubber over `body`, chunked at `splits`, and return
    /// the concatenated output (mirrors how the server adaptor drives it).
    fn run_stream(secrets_in: &[&str], alias: &str, body: &[u8], splits: &[usize]) -> Vec<u8> {
        let secs = secrets(secrets_in);
        let mut sc = StreamScrubber::new(&secs, alias, 1 << 20);
        let mut out = Vec::new();
        let mut points: Vec<usize> = splits.iter().copied().filter(|&p| p <= body.len()).collect();
        points.sort_unstable();
        points.dedup();
        if points.last() != Some(&body.len()) {
            points.push(body.len());
        }
        let mut start = 0;
        for p in points {
            if p < start {
                continue;
            }
            out.extend(sc.push(&body[start..p]).unwrap());
            start = p;
        }
        out.extend(sc.finish().unwrap());
        out
    }

    /// Buffered redaction of `body` (the oracle the streamed output must match).
    fn run_buffered(secrets_in: &[&str], alias: &str, body: &[u8]) -> Vec<u8> {
        let mut r = ExecuteResponse {
            status: 200,
            headers: HashMap::new(),
            body: body.to_vec(),
            updated_credential: None,
        };
        redact_secret_material(&mut r, &secrets(secrets_in), alias);
        r.body
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn derive_secret_forms_is_longest_first_and_shared() {
        // A secret with chars that differ under percent / JSON encoding yields ≥ 2
        // forms, sorted longest-first. This is the single set both paths use.
        let forms = derive_secret_forms(&secrets(&["a b\"c/d"]));
        assert!(forms.len() >= 2, "expected raw + encoded forms: {forms:?}");
        for w in forms.windows(2) {
            assert!(w[0].len() >= w[1].len(), "forms must be longest-first: {forms:?}");
        }
        // A sub-MIN_REDACT_LEN secret contributes no form (matches buffered behavior).
        assert!(derive_secret_forms(&secrets(&["pin"])).is_empty());
    }

    #[test]
    fn stream_scrubber_no_split() {
        let out = run_stream(&["sk-supersecret-123"], "x", b"echo sk-supersecret-123 end", &[]);
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("sk-supersecret-123"));
        assert!(s.contains("[REDACTED:x]"));
    }

    #[test]
    fn stream_scrubber_catches_boundary_split_secret() {
        let secret = "supersecret-token-value";
        let body = format!("before {secret} after");
        let at = body.find(secret).unwrap() + 5; // split INSIDE the secret
        let out = run_stream(&[secret], "x", body.as_bytes(), &[at]);
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains(secret), "boundary-split secret leaked: {s}");
        assert!(s.contains("[REDACTED:x]"));
    }

    #[test]
    fn stream_scrubber_single_byte_chunks_match_buffered() {
        let secret = "supersecret-token-value";
        let body = format!("aa {secret} bb {secret}").into_bytes();
        let by_byte = run_stream(&[secret], "x", &body, &(1..body.len()).collect::<Vec<_>>());
        let buffered = run_buffered(&[secret], "x", &body);
        assert_eq!(by_byte, buffered, "single-byte chunking must equal buffered redaction");
    }

    #[test]
    fn stream_scrubber_partial_secret_at_end_is_flushed_not_leaked() {
        // The stream ends mid-secret: the partial prefix is emitted raw (it is not a
        // complete secret), and nothing is left stuck in the carry.
        let secret = "supersecret-token-value";
        let truncated = &secret.as_bytes()[..10]; // first 10 bytes only
        let mut body = b"x ".to_vec();
        body.extend_from_slice(truncated);
        let out = run_stream(&[secret], "x", &body, &[]);
        assert_eq!(out, body, "a partial (incomplete) secret must pass through unchanged");
    }

    #[test]
    fn stream_scrubber_noop_when_no_redactable_secret() {
        // All secrets below MIN_REDACT_LEN → pure pass-through.
        let secs = secrets(&["pin", "abc"]);
        let mut sc = StreamScrubber::new(&secs, "x", 1 << 20);
        assert!(sc.is_noop());
        let out = sc.push(b"the pin is abc here").unwrap();
        assert_eq!(out, b"the pin is abc here");
        assert!(sc.finish().unwrap().is_empty());
    }

    #[test]
    fn stream_scrubber_buffer_cap_fails_closed() {
        let secs = secrets(&["supersecret-token-value"]);
        // Tiny cap: a chunk bigger than the cap trips BufferOverflow (fail closed),
        // rather than buffering unbounded.
        let mut sc = StreamScrubber::new(&secs, "x", 8);
        let err = sc.push(b"way more than eight bytes").unwrap_err();
        assert_eq!(err, ScrubError::BufferOverflow);
    }

    #[test]
    fn stream_is_egress_safe_flags_block_and_regex() {
        // A matching block rule OR a non-empty redact_patterns ⇒ NOT stream-safe.
        assert!(!stream_is_egress_safe(&[rule("pay-*", "*", true, &[])], "pay-1", "http.request"));
        assert!(!stream_is_egress_safe(
            &[rule("*", "*", false, &["[0-9]+"])],
            "any",
            "http.request"
        ));
        // A rule that doesn't match, or no rules, is safe to stream.
        assert!(stream_is_egress_safe(&[rule("other-*", "*", true, &[])], "pay-1", "http.request"));
        assert!(stream_is_egress_safe(&[], "any", "http.request"));
    }

    #[test]
    fn headers_indicate_compression_detects_residual_codecs() {
        let mut compressed = HashMap::new();
        compressed.insert("Content-Encoding".to_string(), "zstd".to_string());
        assert!(headers_indicate_compression(&compressed));

        let mut identity = HashMap::new();
        identity.insert("content-type".to_string(), "text/event-stream".to_string());
        identity.insert("content-encoding".to_string(), "identity".to_string());
        assert!(!headers_indicate_compression(&identity));
    }

    #[test]
    fn derive_secret_forms_yields_multiple_forms_for_special_chars() {
        // A secret with a space + slash percent-encodes to a LONGER form than the raw
        // bytes, so StreamScrubber's carry (sized off the longest form) must hold back
        // more than the raw length — the case the proptest below exercises.
        let forms = derive_secret_forms(&secrets(&["SECRET abcdef/1234567890"]));
        assert!(forms.len() >= 2, "expected raw + percent-encoded forms: {forms:?}");
        let longest = forms.iter().map(|f| f.len()).max().unwrap();
        assert!(longest > "SECRET abcdef/1234567890".len(), "encoded form is longer than raw");
    }

    proptest::proptest! {
        /// For ANY surrounding bytes and ANY chunk split, the streamed scrub equals
        /// the buffered redaction, and no secret survives. The secret contains a space
        /// and a slash, so it has TWO forms (raw + a longer percent-encoded form);
        /// only the raw form is planted, so the paths stay byte-identical while the
        /// carry buffer is still sized off the longer encoded form.
        #[test]
        fn streamed_scrub_equals_buffered(
            prefix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..48),
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..48),
            split in 0usize..256,
        ) {
            let secret = "SECRET abcdef/1234567890"; // space + slash → raw + longer pct form
            let mut body = prefix;
            body.extend_from_slice(secret.as_bytes());
            body.extend_from_slice(&suffix);

            let buffered = run_buffered(&[secret], "x", &body);
            let at = split % (body.len() + 1);
            let streamed = run_stream(&[secret], "x", &body, &[at]);
            proptest::prop_assert_eq!(&streamed, &buffered, "split at {} diverged", at);

            // Chunking invariance: single-byte splits also equal the oracle.
            let by_byte = run_stream(&[secret], "x", &body, &(1..body.len()).collect::<Vec<_>>());
            proptest::prop_assert_eq!(&by_byte, &buffered);

            // No occurrence of the planted secret survives.
            proptest::prop_assert!(!contains_subslice(&streamed, secret.as_bytes()));
        }
    }
}
