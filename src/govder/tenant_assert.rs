//! Tenant assertion signing — wire-compatible with `govder/pkg/tenantassert`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

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
}
