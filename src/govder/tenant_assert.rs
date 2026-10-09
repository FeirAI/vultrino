//! Tenant assertion signing — wire-compatible with `govder/pkg/tenantassert`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Why an inbound request-bound assertion was rejected. Callers deliberately
/// collapse these variants to one generic HTTP error so no MAC/expiry oracle is
/// exposed; the variants make the verifier's fail-closed contract testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TenantAssertionError {
    #[error("malformed tenant assertion")]
    Malformed,
    #[error("tenant assertion does not match the request")]
    BadMac,
    #[error("tenant assertion expired")]
    Expired,
    #[error("tenant assertion exceeds the verifier TTL bound")]
    ExcessiveTtl,
    #[error("tenant assertion names a different tenant")]
    WrongTenant,
}

/// The one jti grammar shared with govder's `pkg/tenantassert` (`JTIPattern`): exactly 16
/// lowercase hex characters. Every signer emits it and every verifier enforces it; before
/// 2026-10 this verifier also accepted uppercase hex digits and govder accepted any jti.
pub fn valid_jti(jti: &str) -> bool {
    jti.len() == 16 && jti.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The TTL ceiling applied when the configured maximum is zero. A zero maximum is a
/// configuration error and must not mean "no ceiling" (SB-21).
pub const DEFAULT_MAX_TTL: Duration = Duration::from_secs(5 * 60);

/// Mint `X-Govder-Tenant-Assertion` binding tenant + whole request + a one-time jti.
///
/// Wire format: `seg0.seg1.seg2.mac` where seg0 = base64url(tenant), seg1 = exp
/// unix seconds, seg2 = a random 16-hex-char jti (nonce), and the MAC covers
/// `seg0.seg1.seg2\nMETHOD\npath\nquery\nhost\nbody_digest`. The jti is bound
/// into the MAC so a tampered jti invalidates it; two identical requests produce
/// distinct assertions. Govder atomically consumes each `(tenant, jti)` through
/// expiry, so an exact captured request cannot be replayed.
///
/// `path` and `query` must be the path and query EXACTLY as transmitted (percent-encoding
/// kept): the verifier binds the raw request-target it receives. The golden vectors are
/// `vectors/tenant-assertion.v1.json` (owned by govder, copied byte for byte).
#[allow(clippy::too_many_arguments)] // the signed wire tuple is deliberately explicit and order-sensitive
pub fn sign_tenant_assertion(
    secret: &str,
    tenant: &str,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    exp: DateTime<Utc>,
) -> String {
    sign_tenant_assertion_with_jti(secret, tenant, &new_jti(), method, path, query, host, body, exp)
}

/// [`sign_tenant_assertion`] with a caller-chosen jti, so the golden vectors can pin the
/// exact output. Production callers use [`sign_tenant_assertion`] (a fresh CSPRNG jti).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_tenant_assertion_with_jti(
    secret: &str,
    tenant: &str,
    jti: &str,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    exp: DateTime<Utc>,
) -> String {
    let seg0 = URL_SAFE_NO_PAD.encode(tenant.as_bytes());
    let seg1 = exp.timestamp().to_string();
    let payload = assertion_payload(&seg0, &seg1, jti, method, path, query, host, body);
    let mac = mac_base64(secret.as_bytes(), &payload);
    format!("{seg0}.{seg1}.{jti}.{mac}")
}

/// The MAC input. Case mapping is ASCII only (`to_ascii_uppercase` / `to_ascii_lowercase`),
/// as in govder's `tenantassert.Payload`.
#[allow(clippy::too_many_arguments)]
fn assertion_payload(
    seg0: &str,
    seg1: &str,
    seg2: &str,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
) -> String {
    format!(
        "{seg0}.{seg1}.{seg2}\n{}\n{path}\n{query}\n{}\n{}",
        method.to_ascii_uppercase(),
        host.to_ascii_lowercase(),
        body_digest(body),
    )
}

/// seg1 grammar: canonical decimal `^[1-9][0-9]{0,18}$` that fits an i64 (no sign, no
/// leading zero), as in govder.
fn parse_exp(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 19 || !(b'1'..=b'9').contains(&b[0]) {
        return None;
    }
    if !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// Verify an assertion against the exact request Vultrino received.
///
/// This is the inbound half of the same wire contract used for Vultrino's
/// outbound Govder calls. A successful result establishes that the holder of the
/// configured broker/Govder assertion key signed this tenant, method, path,
/// query, host, and exact body before the bounded expiry. In particular, the
/// `approver`, `approver_class`, and approval id in a decision request cannot be
/// changed after signing because the whole JSON body and route are MAC-bound.
/// `path` and `query` must be the raw request-target as received (`OriginalUri`).
///
/// Checks run in the same order as govder's `tenantassert.Verify`: segment grammar
/// (canonical base64url, canonical decimal exp, jti grammar), MAC, expiry, TTL ceiling
/// (a zero `max_ttl` applies [`DEFAULT_MAX_TTL`]), then the expected tenant.
///
/// Replay storage is intentionally not duplicated here: the bound approval
/// transition is itself idempotent/one-way under the storage lock. Replaying the
/// exact assertion cannot change identity, class, outcome, tenant, or target and
/// therefore cannot create a second recipe slot.
#[allow(clippy::too_many_arguments)] // the verified wire tuple is deliberately explicit
pub fn verify_tenant_assertion(
    assertion: &str,
    secret: &str,
    expected_tenant: &str,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    body: &[u8],
    now: DateTime<Utc>,
    max_ttl: Duration,
) -> Result<(), TenantAssertionError> {
    if secret.is_empty() || expected_tenant.is_empty() {
        return Err(TenantAssertionError::Malformed);
    }
    let parts: Vec<_> = assertion.split('.').collect();
    if parts.len() != 4 {
        return Err(TenantAssertionError::Malformed);
    }
    let tenant = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| TenantAssertionError::Malformed)?;
    if tenant.is_empty()
        || std::str::from_utf8(&tenant).is_err()
        || tenant.iter().any(|b| *b < 0x20 || *b == 0x7f)
    {
        return Err(TenantAssertionError::Malformed);
    }
    let exp = parse_exp(parts[1]).ok_or(TenantAssertionError::Malformed)?;
    if !valid_jti(parts[2]) {
        return Err(TenantAssertionError::Malformed);
    }
    let supplied_mac = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| TenantAssertionError::Malformed)?;
    if supplied_mac.len() != 32 {
        return Err(TenantAssertionError::Malformed);
    }

    let payload = assertion_payload(parts[0], parts[1], parts[2], method, path, query, host, body);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| TenantAssertionError::Malformed)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&supplied_mac)
        .map_err(|_| TenantAssertionError::BadMac)?;

    let remaining = exp
        .checked_sub(now.timestamp())
        .ok_or(TenantAssertionError::Malformed)?;
    if remaining < 0 {
        return Err(TenantAssertionError::Expired);
    }
    let ceiling = if max_ttl.as_secs() == 0 {
        DEFAULT_MAX_TTL
    } else {
        max_ttl
    };
    if u64::try_from(remaining).map_err(|_| TenantAssertionError::Malformed)? > ceiling.as_secs() {
        return Err(TenantAssertionError::ExcessiveTtl);
    }
    if tenant.as_slice() != expected_tenant.as_bytes() {
        return Err(TenantAssertionError::WrongTenant);
    }
    Ok(())
}

fn new_jti() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn body_digest(body: &[u8]) -> String {
    let sum = Sha256::digest(body);
    URL_SAFE_NO_PAD.encode(sum)
}

fn mac_base64(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn sign_produces_stable_segment_shape() {
        let exp = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let assertion = sign_tenant_assertion(
            "s3cr3t",
            "acme",
            "POST",
            "/v1/delegation/evaluate-decision",
            "",
            "example.com",
            br#"{"grant_id":"g1","approve":true}"#,
            exp,
        );
        let parts: Vec<_> = assertion.split('.').collect();
        assert_eq!(parts.len(), 4, "assertion must be seg0.seg1.seg2.jti_mac");
        assert_eq!(parts[0], URL_SAFE_NO_PAD.encode(b"acme"));
        assert_eq!(parts[1], exp.timestamp().to_string());
        assert_eq!(parts[2].len(), 16, "jti seg2 must be 16 hex chars");
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!parts[3].is_empty());
    }

    #[test]
    fn jti_makes_identical_requests_distinct() {
        let exp = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let a = sign_tenant_assertion(
            "s3cr3t",
            "acme",
            "GET",
            "/v1/delegation/grants",
            "",
            "example.com",
            b"",
            exp,
        );
        let b = sign_tenant_assertion(
            "s3cr3t",
            "acme",
            "GET",
            "/v1/delegation/grants",
            "",
            "example.com",
            b"",
            exp,
        );
        assert_ne!(
            a, b,
            "random jti must make identical requests sign distinctly"
        );
        assert_ne!(a.split('.').nth(2), b.split('.').nth(2));
    }

    #[test]
    fn empty_body_digests_empty_string() {
        let d1 = body_digest(b"");
        let d2 = body_digest(&[]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn verify_accepts_exact_request_and_rejects_every_bound_axis() {
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let exp = now + chrono::Duration::seconds(60);
        let body = br#"{"approve":true,"approver":"sub-alice","approver_class":"senior"}"#;
        let assertion = sign_tenant_assertion(
            "s3cr3t",
            "acme",
            "POST",
            "/api/v1/approvals/appr_1/decision",
            "",
            "vultrino.internal:8080",
            body,
            exp,
        );
        let verify = |tenant: &str, method: &str, path: &str, host: &str, body: &[u8]| {
            verify_tenant_assertion(
                &assertion,
                "s3cr3t",
                tenant,
                method,
                path,
                "",
                host,
                body,
                now,
                Duration::from_secs(90),
            )
        };
        assert_eq!(
            verify(
                "acme",
                "POST",
                "/api/v1/approvals/appr_1/decision",
                "vultrino.internal:8080",
                body,
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                "other",
                "POST",
                "/api/v1/approvals/appr_1/decision",
                "vultrino.internal:8080",
                body,
            ),
            Err(TenantAssertionError::WrongTenant)
        );
        for bad in [
            verify(
                "acme",
                "DELETE",
                "/api/v1/approvals/appr_1/decision",
                "vultrino.internal:8080",
                body,
            ),
            verify(
                "acme",
                "POST",
                "/api/v1/approvals/appr_2/decision",
                "vultrino.internal:8080",
                body,
            ),
            verify(
                "acme",
                "POST",
                "/api/v1/approvals/appr_1/decision",
                "elsewhere.internal:8080",
                body,
            ),
            verify(
                "acme",
                "POST",
                "/api/v1/approvals/appr_1/decision",
                "vultrino.internal:8080",
                br#"{"approve":true,"approver":"sub-mallory","approver_class":"senior"}"#,
            ),
        ] {
            assert_eq!(bad, Err(TenantAssertionError::BadMac));
        }
    }

    #[test]
    fn verify_rejects_expired_far_future_malformed_and_bad_mac() {
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let sign = |exp| sign_tenant_assertion("s", "acme", "POST", "/p", "", "host", b"{}", exp);
        let verify = |assertion: &str| {
            verify_tenant_assertion(
                assertion,
                "s",
                "acme",
                "POST",
                "/p",
                "",
                "host",
                b"{}",
                now,
                Duration::from_secs(90),
            )
        };
        assert_eq!(
            verify(&sign(now - chrono::Duration::seconds(1))),
            Err(TenantAssertionError::Expired)
        );
        assert_eq!(
            verify(&sign(now + chrono::Duration::seconds(91))),
            Err(TenantAssertionError::ExcessiveTtl)
        );
        assert_eq!(
            verify("not-an-assertion"),
            Err(TenantAssertionError::Malformed)
        );

        let mut bad = sign(now + chrono::Duration::seconds(60));
        let original_last = bad.pop().expect("signed assertion has a MAC");
        bad.push(if original_last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verify(&bad),
            Err(TenantAssertionError::BadMac | TenantAssertionError::Malformed)
        ));
    }
    // ===== golden vectors (vectors/tenant-assertion.v1.json, owned by govder) =====

    fn load_tenant_assertion_vectors() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vectors")
            .join("tenant-assertion.v1.json");
        let raw = std::fs::read(&path).expect("read vectors/tenant-assertion.v1.json");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("decode vectors");
        assert_eq!(v["format"], "feir.tenant-assertion");
        assert_eq!(v["version"], 1);
        v
    }

    fn vb64(s: &serde_json::Value) -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD;
        STANDARD
            .decode(s.as_str().expect("body_b64 is a string"))
            .expect("body_b64 decodes")
    }

    /// The shipped verifier gives the reference verdict (and reason) on every vector.
    #[test]
    fn verify_agrees_with_golden_vectors() {
        let file = load_tenant_assertion_vectors();
        let vectors = file["vectors"].as_array().expect("vectors array");
        assert!(vectors.len() >= 100, "vector file too small");
        let mut failures = Vec::new();
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let ver = &v["verify"];
            let req = &ver["request"];
            let now = DateTime::<Utc>::from_timestamp(ver["now"].as_i64().unwrap(), 0).unwrap();
            let got = verify_tenant_assertion(
                v["assertion"].as_str().unwrap(),
                ver["key"].as_str().unwrap(),
                ver["expected_tenant"].as_str().unwrap(),
                req["method"].as_str().unwrap(),
                req["path"].as_str().unwrap(),
                req["query"].as_str().unwrap(),
                req["host"].as_str().unwrap(),
                &vb64(&req["body_b64"]),
                now,
                Duration::from_secs(ver["max_ttl_s"].as_u64().unwrap()),
            );
            let want_reason = match v["reason"].as_str() {
                Some("malformed") => Some(TenantAssertionError::Malformed),
                Some("bad_mac") => Some(TenantAssertionError::BadMac),
                Some("expired") => Some(TenantAssertionError::Expired),
                Some("ttl") => Some(TenantAssertionError::ExcessiveTtl),
                _ => None,
            };
            match (v["expect"].as_str().unwrap(), got) {
                ("accept", Ok(())) => {}
                ("reject", Err(e)) => {
                    if let Some(want) = want_reason {
                        if e != want {
                            failures.push(format!("{id}: want {want:?}, got {e:?}"));
                        }
                    }
                }
                (want, got) => failures.push(format!("{id}: want {want}, got {got:?}")),
            }
        }
        assert!(failures.is_empty(), "vector mismatches:\n{}", failures.join("\n"));
    }
    /// vectors/approval-assertion.v1.json is owned by feir-os (the broker signs the approval
    /// decision with M) and copied here byte for byte. vultrino's verifier on
    /// POST /api/v1/approvals/{id}/decision gives the reference verdict on every vector: the
    /// request-target it receives, the admin key's tenant and the exact body are all bound, and
    /// an assertion signed with F instead of M is refused.
    #[test]
    fn verify_agrees_with_approval_assertion_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vectors")
            .join("approval-assertion.v1.json");
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("read vectors")).expect("decode");
        assert_eq!(file["format"], "feir.approval-assertion");
        let vectors = file["vectors"].as_array().expect("vectors array");
        assert!(vectors.len() >= 10, "vector file too small");
        let mut failures = Vec::new();
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let ver = &v["verify"];
            let req = &ver["request"];
            let now = DateTime::<Utc>::from_timestamp(ver["now"].as_i64().unwrap(), 0).unwrap();
            let got = verify_tenant_assertion(
                v["assertion"].as_str().unwrap(),
                ver["key"].as_str().unwrap(),
                ver["expected_tenant"].as_str().unwrap(),
                req["method"].as_str().unwrap(),
                req["path"].as_str().unwrap(),
                req["query"].as_str().unwrap(),
                req["host"].as_str().unwrap(),
                &vb64(&req["body_b64"]),
                now,
                Duration::from_secs(ver["max_ttl_s"].as_u64().unwrap()),
            );
            match (v["expect"].as_str().unwrap(), got) {
                ("accept", Ok(())) | ("reject", Err(_)) => {}
                (want, got) => failures.push(format!("{id}: want {want}, got {got:?}")),
            }
        }
        assert!(failures.is_empty(), "vector mismatches:\n{}", failures.join("\n"));
    }

    /// The shipped Rust signer reproduces the reference payload and header value for every
    /// vector that carries sign inputs (the same bytes govder's Go signer must produce).
    #[test]
    fn sign_agrees_with_golden_vectors() {
        let file = load_tenant_assertion_vectors();
        let mut n = 0;
        let mut failures = Vec::new();
        for v in file["vectors"].as_array().unwrap() {
            let Some(s) = v.get("sign") else { continue };
            n += 1;
            let id = v["id"].as_str().unwrap();
            let body = vb64(&s["body_b64"]);
            let exp = DateTime::<Utc>::from_timestamp(s["exp"].as_i64().unwrap(), 0).unwrap();
            let seg0 = URL_SAFE_NO_PAD.encode(s["tenant"].as_str().unwrap().as_bytes());
            let payload = assertion_payload(
                &seg0,
                &exp.timestamp().to_string(),
                s["jti"].as_str().unwrap(),
                s["method"].as_str().unwrap(),
                s["path"].as_str().unwrap(),
                s["query"].as_str().unwrap(),
                s["host"].as_str().unwrap(),
                &body,
            );
            if payload != v["payload"].as_str().unwrap() {
                failures.push(format!("{id}: payload {payload:?}"));
            }
            let got = sign_tenant_assertion_with_jti(
                s["key"].as_str().unwrap(),
                s["tenant"].as_str().unwrap(),
                s["jti"].as_str().unwrap(),
                s["method"].as_str().unwrap(),
                s["path"].as_str().unwrap(),
                s["query"].as_str().unwrap(),
                s["host"].as_str().unwrap(),
                &body,
                exp,
            );
            if got != v["assertion"].as_str().unwrap() {
                failures.push(format!("{id}: assertion {got:?}"));
            }
        }
        assert!(n >= 40, "only {n} sign vectors ran");
        assert!(failures.is_empty(), "sign mismatches:\n{}", failures.join("\n"));
    }

    #[test]
    fn production_jti_matches_the_grammar() {
        for _ in 0..64 {
            assert!(valid_jti(&new_jti()));
        }
    }

    #[test]
    fn zero_max_ttl_still_has_a_ceiling() {
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let ceiling = chrono::Duration::from_std(DEFAULT_MAX_TTL).unwrap();
        let far = sign_tenant_assertion("k", "acme", "GET", "/x", "", "h", b"", now + ceiling + chrono::Duration::seconds(1));
        let near = sign_tenant_assertion("k", "acme", "GET", "/x", "", "h", b"", now + ceiling);
        let v = |a: &str| verify_tenant_assertion(a, "k", "acme", "GET", "/x", "", "h", b"", now, Duration::ZERO);
        assert_eq!(v(&far), Err(TenantAssertionError::ExcessiveTtl));
        assert_eq!(v(&near), Ok(()));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]
        /// In-repo differential between the Rust signer and the Rust verifier: whatever the
        /// signer emits for grammar-valid inputs verifies on the same request, and any one-byte
        /// change of the assertion, or of the raw path, is refused.
        #[test]
        fn sign_verify_agree(
            tenant in "[a-z\\-]{1,12}(\u{e9}|\u{4e2d})?",
            jti in "[0-9a-f]{16}",
            method in "(GET|POST|put|Delete)",
            path in "/([a-z0-9._~-]|%2F|%2f|%20|%25){0,24}",
            query in "([a-z0-9=&]|%20){0,16}",
            host in "[A-Za-z0-9.:-]{1,24}",
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            ttl in 0i64..=300,
            pos in proptest::prelude::any::<usize>(),
            byte in proptest::prelude::any::<u8>(),
        ) {
            let now = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
            let exp = now + chrono::Duration::seconds(ttl);
            let a = sign_tenant_assertion_with_jti("prop-key", &tenant, &jti, &method, &path, &query, &host, &body, exp);
            let max = Duration::from_secs(300);
            proptest::prop_assert_eq!(
                verify_tenant_assertion(&a, "prop-key", &tenant, &method, &path, &query, &host, &body, now, max),
                Ok(())
            );
            let i = pos % a.len();
            if a.as_bytes()[i] != byte && byte.is_ascii() {
                let mut m = a.clone().into_bytes();
                m[i] = byte;
                let m = String::from_utf8(m).unwrap();
                proptest::prop_assert!(
                    verify_tenant_assertion(&m, "prop-key", &tenant, &method, &path, &query, &host, &body, now, max).is_err(),
                    "one-byte change at {} verified: {}", i, m
                );
            }
            let j = pos % path.len();
            if path.as_bytes()[j] != byte && byte.is_ascii() {
                let mut p2 = path.clone().into_bytes();
                p2[j] = byte;
                let p2 = String::from_utf8(p2).unwrap();
                proptest::prop_assert!(
                    verify_tenant_assertion(&a, "prop-key", &tenant, &method, &p2, &query, &host, &body, now, max).is_err(),
                    "a different raw path {:?} verified an assertion signed over {:?}", p2, path
                );
            }
        }
    }
}


