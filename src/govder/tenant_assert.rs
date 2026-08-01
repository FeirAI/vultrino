//! Tenant assertion signing — wire-compatible with `govder/pkg/tenantassert`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
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

/// Mint `X-Govder-Tenant-Assertion` binding tenant + whole request + a one-time jti.
///
/// Wire format: `seg0.seg1.seg2.mac` where seg0 = base64url(tenant), seg1 = exp
/// unix seconds, seg2 = a random 16-hex-char jti (nonce), and the MAC covers
/// `seg0.seg1.seg2\nMETHOD\npath\nquery\nhost\nbody_digest`. The jti is bound
/// into the MAC so a tampered jti invalidates it; two identical requests produce
/// distinct assertions. Govder atomically consumes each `(tenant, jti)` through
/// expiry, so an exact captured request cannot be replayed.
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
    let seg0 = URL_SAFE_NO_PAD.encode(tenant.as_bytes());
    let seg1 = exp.timestamp().to_string();
    let seg2 = new_jti();
    let body_hash = body_digest(body);
    let payload = format!(
        "{seg0}.{seg1}.{seg2}\n{}\n{path}\n{query}\n{}\n{body_hash}",
        method.to_ascii_uppercase(),
        host.to_ascii_lowercase(),
    );
    let mac = mac_base64(secret.as_bytes(), &payload);
    format!("{seg0}.{seg1}.{seg2}.{mac}")
}

/// Verify an assertion against the exact request Vultrino received.
///
/// This is the inbound half of the same wire contract used for Vultrino's
/// outbound Govder calls. A successful result establishes that the holder of the
/// configured broker/Govder assertion key signed this tenant, method, path,
/// query, host, and exact body before the bounded expiry. In particular, the
/// `approver`, `approver_class`, and approval id in a decision request cannot be
/// changed after signing because the whole JSON body and route are MAC-bound.
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
    if parts.len() != 4
        || parts[2].len() != 16
        || !parts[2].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(TenantAssertionError::Malformed);
    }

    let tenant = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| TenantAssertionError::Malformed)?;
    if tenant.is_empty() || tenant.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return Err(TenantAssertionError::Malformed);
    }
    if tenant.as_slice() != expected_tenant.as_bytes() {
        return Err(TenantAssertionError::WrongTenant);
    }

    let exp = parts[1]
        .parse::<i64>()
        .map_err(|_| TenantAssertionError::Malformed)?;
    let remaining = exp
        .checked_sub(now.timestamp())
        .ok_or(TenantAssertionError::Malformed)?;
    if remaining < 0 {
        return Err(TenantAssertionError::Expired);
    }
    if max_ttl.as_secs() > 0
        && u64::try_from(remaining).map_err(|_| TenantAssertionError::Malformed)?
            > max_ttl.as_secs()
    {
        return Err(TenantAssertionError::ExcessiveTtl);
    }

    let body_hash = body_digest(body);
    let payload = format!(
        "{}.{}.{}\n{}\n{path}\n{query}\n{}\n{body_hash}",
        parts[0],
        parts[1],
        parts[2],
        method.to_ascii_uppercase(),
        host.to_ascii_lowercase(),
    );
    let supplied_mac = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| TenantAssertionError::Malformed)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| TenantAssertionError::Malformed)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&supplied_mac)
        .map_err(|_| TenantAssertionError::BadMac)
}

fn new_jti() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
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
        let sign = |exp| {
            sign_tenant_assertion("s", "acme", "POST", "/p", "", "host", b"{}", exp)
        };
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
        assert_eq!(verify("not-an-assertion"), Err(TenantAssertionError::Malformed));

        let mut bad = sign(now + chrono::Duration::seconds(60));
        let original_last = bad.pop().expect("signed assertion has a MAC");
        bad.push(if original_last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verify(&bad),
            Err(TenantAssertionError::BadMac | TenantAssertionError::Malformed)
        ));
    }
}
