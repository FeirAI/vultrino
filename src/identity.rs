//! Workload-identity resolution (V10): make the principal vultrino scopes
//! against a **workload identity** rather than only a static `vk_`/`vut_` secret.
//!
//! An [`IdentityResolver`] turns an inbound identity document — a SPIFFE/SPIRE
//! SVID, a cloud-IAM token (AWS IAM Roles Anywhere / GCP workload identity / Entra
//! workload identity), or a generic OIDC token — into a [`WorkloadIdentity`]
//! whose `subject` is the principal id a policy's `principal_pattern` matches and
//! whose `trust_domain` scopes it.
//!
//! **Wiring (R6).** The SPIFFE and OIDC resolvers are wired into the request path:
//! configure `[identity]` with a `kind` (`spiffe`/`oidc`) and a `header`, and an
//! inbound request carrying that header has its principal resolved from the
//! document before policy evaluation. The resolved `subject` becomes
//! `Principal.workload_id` — an **additional** `principal_pattern` match dimension,
//! never replacing `Principal.id` (the credential id stays the halt/ownership
//! anchor) — and `owner` becomes `Principal.owner`. See
//! [`crate::server::VultrinoServer::resolve_identity`].
//!
//! **Trust boundary (VUL-20).** The resolvers parse + validate a document whose
//! *token* the edge has already verified (mTLS / JWT / SVID). Vultrino no longer
//! believes the header on the edge's say-so: the edge must also sign it. The
//! request carries `<header>-signature`, a MAC under the shared key
//! `VULTRINO_IDENTITY_SECRET` over the document, an expiry and the exact bearer
//! secret the request authenticates with (see [`sign_identity`]). A missing, wrong,
//! expired or foreign-bearer signature makes the document ignored (the static
//! principal stays), and a deployment with `[identity]` and no key refuses to
//! start. The cloud-IAM resolvers are
//! *claim adapters*: they map verified claims to a principal but do **not** do the
//! cloud-specific cryptographic verification (cloud SDK / JWKS), so they stay
//! integration-time and are not auto-wired inbound.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Env var holding the key the edge signs the identity header with (`_FILE` form preferred).
pub const IDENTITY_SECRET_ENV: &str = "VULTRINO_IDENTITY_SECRET";
/// The longest an identity signature may be valid for, in seconds.
pub const IDENTITY_MAX_TTL_SECS: i64 = 300;

/// Name of the signature header that accompanies the identity `header`.
pub fn signature_header_name(header: &str) -> String {
    format!("{header}-signature")
}

/// Read the identity signing key: `VULTRINO_IDENTITY_SECRET_FILE` first, then the env var.
/// Blank or unreadable is unset.
pub fn verification_key_from_env() -> Option<String> {
    if let Ok(path) = std::env::var(format!("{IDENTITY_SECRET_ENV}_FILE")) {
        if !path.trim().is_empty() {
            return std::fs::read_to_string(&path)
                .ok()
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty());
        }
    }
    std::env::var(IDENTITY_SECRET_ENV)
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

fn identity_mac(key: &str, document: &str, exp: i64, bearer: &str) -> Vec<u8> {
    let bearer_digest = hex::encode(Sha256::digest(bearer.as_bytes()));
    let payload = format!("vultrino-identity-v1\n{document}\n{exp}\n{bearer_digest}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Sign an identity document for one request: `v1.<exp>.<base64url MAC>`. The MAC covers the
/// document, the expiry (unix seconds) and the SHA-256 of the bearer secret the request will
/// authenticate with, so a captured header is useless with any other token and expires.
/// This is the contract the edge implements (the same HMAC-SHA-256 and base64url as the
/// tenant assertion).
pub fn sign_identity(key: &str, document: &str, bearer: &str, exp: i64) -> String {
    let mac = identity_mac(key, document, exp, bearer);
    format!("v1.{exp}.{}", URL_SAFE_NO_PAD.encode(mac))
}

/// Verify a signature from [`sign_identity`] for this document and bearer at `now`.
pub fn verify_identity_signature(
    key: &str,
    document: &str,
    bearer: &str,
    signature: &str,
    now: i64,
) -> Result<(), IdentityError> {
    let bad = |d: &str| IdentityError::BadSignature(d.to_string());
    let mut parts = signature.split('.');
    let (Some("v1"), Some(exp), Some(mac), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("malformed"));
    };
    if exp.is_empty() || !exp.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("malformed expiry"));
    }
    let exp: i64 = exp.parse().map_err(|_| bad("malformed expiry"))?;
    let supplied = URL_SAFE_NO_PAD
        .decode(mac)
        .map_err(|_| bad("malformed mac"))?;
    let mut m = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    let bearer_digest = hex::encode(Sha256::digest(bearer.as_bytes()));
    m.update(format!("vultrino-identity-v1\n{document}\n{exp}\n{bearer_digest}").as_bytes());
    m.verify_slice(&supplied).map_err(|_| bad("mac mismatch"))?;
    if exp < now {
        return Err(bad("expired"));
    }
    if exp - now > IDENTITY_MAX_TTL_SECS {
        return Err(bad("expiry beyond the maximum lifetime"));
    }
    Ok(())
}

/// The kind of workload-identity document a [`WorkloadIdentity`] was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// SPIFFE/SPIRE SVID (`spiffe://<trust-domain>/<path>`).
    Spiffe,
    /// AWS IAM (Roles Anywhere) — principal is the assumed-role ARN.
    AwsIam,
    /// GCP workload identity — principal is the service-account email.
    GcpWorkload,
    /// Microsoft Entra workload identity — principal is the `oid`/`sub`.
    EntraWorkload,
    /// Generic OIDC — principal is the `sub`, trust domain the `iss`.
    Oidc,
}

/// A resolved workload identity (V10): the principal a request authenticated as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub kind: IdentityKind,
    /// The principal identifier — matched by a policy `principal_pattern`.
    pub subject: String,
    /// Trust domain / issuer that vouches for the subject, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// The bound human/directory owner (OIDC `sub` / SCIM id), if resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Errors resolving a workload-identity document.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("malformed {kind:?} identity document: {detail}")]
    Malformed { kind: IdentityKind, detail: String },
    #[error("trust domain '{0}' is not allowed")]
    UntrustedDomain(String),
    #[error("missing required claim '{0}'")]
    MissingClaim(String),
    #[error("identity signature rejected: {0}")]
    BadSignature(String),
}

/// Resolves an inbound identity document into a [`WorkloadIdentity`] (V10).
pub trait IdentityResolver: Send + Sync {
    fn kind(&self) -> IdentityKind;
    /// Map an **already-verified** document/claims to a workload identity.
    fn resolve(&self, document: &str) -> Result<WorkloadIdentity, IdentityError>;
}

// ==================== SPIFFE / SPIRE ====================

/// SPIFFE/SPIRE adapter (V10): parses a SPIFFE ID `spiffe://<trust-domain>/<path>`
/// into a principal, optionally restricting to an allowlist of trust domains.
#[derive(Debug, Clone, Default)]
pub struct SpiffeResolver {
    /// Allowed trust domains; empty = accept any.
    pub allowed_trust_domains: Vec<String>,
}

impl SpiffeResolver {
    pub fn new(allowed_trust_domains: Vec<String>) -> Self {
        Self {
            allowed_trust_domains,
        }
    }

    /// Parse a SPIFFE ID into `(trust_domain, workload_path)`. Validates the
    /// `spiffe://` scheme, a non-empty trust domain, and a non-empty path.
    pub fn parse_spiffe_id(id: &str) -> Result<(String, String), IdentityError> {
        let malformed = |detail: &str| IdentityError::Malformed {
            kind: IdentityKind::Spiffe,
            detail: detail.to_string(),
        };
        let rest = id
            .strip_prefix("spiffe://")
            .ok_or_else(|| malformed("must start with spiffe://"))?;
        let (trust_domain, path) = rest
            .split_once('/')
            .ok_or_else(|| malformed("missing workload path after the trust domain"))?;
        if trust_domain.is_empty() {
            return Err(malformed("empty trust domain"));
        }
        if path.is_empty() {
            return Err(malformed("empty workload path"));
        }
        Ok((trust_domain.to_string(), format!("/{}", path)))
    }
}

impl IdentityResolver for SpiffeResolver {
    fn kind(&self) -> IdentityKind {
        IdentityKind::Spiffe
    }

    fn resolve(&self, document: &str) -> Result<WorkloadIdentity, IdentityError> {
        let (trust_domain, _path) = Self::parse_spiffe_id(document.trim())?;
        // Trust domains are DNS names — compare case-insensitively so a
        // case-variant can't slip past the allowlist.
        if !self.allowed_trust_domains.is_empty()
            && !self
                .allowed_trust_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&trust_domain))
        {
            return Err(IdentityError::UntrustedDomain(trust_domain));
        }
        Ok(WorkloadIdentity {
            kind: IdentityKind::Spiffe,
            // The full SPIFFE ID is the stable principal subject.
            subject: document.trim().to_string(),
            trust_domain: Some(trust_domain),
            owner: None,
        })
    }
}

// ==================== Generic OIDC ====================

/// Generic OIDC adapter (V10): maps **already-verified** OIDC claims (JSON) to a
/// principal — `sub` as the subject, `iss` as the trust domain. The owner binding
/// is taken from a **human** claim (`email`/`preferred_username`) only — there is
/// **no `sub` fallback**, since a machine token's `sub` is the workload itself and
/// would give false human accountability.
#[derive(Debug, Clone, Default)]
pub struct OidcResolver {
    /// Allowed issuers; empty = accept any.
    pub allowed_issuers: Vec<String>,
}

impl OidcResolver {
    pub fn new(allowed_issuers: Vec<String>) -> Self {
        Self { allowed_issuers }
    }
}

impl IdentityResolver for OidcResolver {
    fn kind(&self) -> IdentityKind {
        IdentityKind::Oidc
    }

    fn resolve(&self, claims_json: &str) -> Result<WorkloadIdentity, IdentityError> {
        let claims: serde_json::Value =
            serde_json::from_str(claims_json).map_err(|e| IdentityError::Malformed {
                kind: IdentityKind::Oidc,
                detail: format!("claims are not valid JSON: {e}"),
            })?;
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| IdentityError::MissingClaim("sub".to_string()))?;
        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // Enforce the issuer allowlist unconditionally: a token with NO `iss` must
        // NOT bypass the allowlist (fail-closed — the allowlist is the resolver's
        // only trust boundary).
        if !self.allowed_issuers.is_empty() {
            let issuer = iss
                .as_deref()
                .ok_or_else(|| IdentityError::MissingClaim("iss".to_string()))?;
            if !self.allowed_issuers.iter().any(|i| i == issuer) {
                return Err(IdentityError::UntrustedDomain(issuer.to_string()));
            }
        }
        // The owner is a HUMAN/directory identity — only set it from a human claim
        // (email / preferred_username). Do NOT fall back to `sub` (which for a
        // machine token is the workload itself, giving no human accountability).
        let owner = claims
            .get("email")
            .or_else(|| claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok(WorkloadIdentity {
            kind: IdentityKind::Oidc,
            subject: sub.to_string(),
            trust_domain: iss,
            owner,
        })
    }
}

// ==================== Cloud IAM adapters (claim scaffolding) ====================

/// Extract a string claim, erroring with [`IdentityError::MissingClaim`] if absent.
fn require_str_claim(claims: &serde_json::Value, key: &str) -> Result<String, IdentityError> {
    claims
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| IdentityError::MissingClaim(key.to_string()))
}

/// Map an already-verified cloud-IAM token's claims to a principal (V10
/// scaffolding). `kind` selects the claim layout:
/// - `AwsIam`: subject = the assumed-role ARN (`arn` claim), trust domain = `aws`.
/// - `GcpWorkload`: subject = service-account `email`, trust domain = `iss`.
/// - `EntraWorkload`: subject = `oid` (object id), trust domain = `tid` (tenant).
///
/// Cryptographic verification of the token is the deployment's responsibility
/// (cloud SDK / JWKS); this adapter trusts the claims it is handed.
pub fn resolve_cloud_iam(
    kind: IdentityKind,
    claims_json: &str,
) -> Result<WorkloadIdentity, IdentityError> {
    let claims: serde_json::Value =
        serde_json::from_str(claims_json).map_err(|e| IdentityError::Malformed {
            kind,
            detail: format!("claims are not valid JSON: {e}"),
        })?;
    let (subject, trust_domain) = match kind {
        IdentityKind::AwsIam => (require_str_claim(&claims, "arn")?, Some("aws".to_string())),
        IdentityKind::GcpWorkload => (
            require_str_claim(&claims, "email")?,
            claims
                .get("iss")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        ),
        IdentityKind::EntraWorkload => (
            require_str_claim(&claims, "oid")?,
            claims
                .get("tid")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        ),
        other => {
            return Err(IdentityError::Malformed {
                kind: other,
                detail: "resolve_cloud_iam supports aws_iam/gcp_workload/entra_workload only"
                    .to_string(),
            })
        }
    };
    Ok(WorkloadIdentity {
        kind,
        subject,
        trust_domain,
        // Cloud-IAM tokens identify a *workload*, not a human — there is no human
        // owner claim to bind here (owner binding is set out-of-band on the
        // vk_/vut_). Leave it None rather than aliasing the machine as its owner.
        owner: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_parse_and_resolve() {
        let (td, path) =
            SpiffeResolver::parse_spiffe_id("spiffe://example.org/ns/prod/sa/api").unwrap();
        assert_eq!(td, "example.org");
        assert_eq!(path, "/ns/prod/sa/api");

        // Malformed forms are rejected.
        assert!(SpiffeResolver::parse_spiffe_id("https://example.org/x").is_err());
        assert!(SpiffeResolver::parse_spiffe_id("spiffe://example.org").is_err()); // no path
        assert!(SpiffeResolver::parse_spiffe_id("spiffe:///ns/x").is_err()); // empty domain

        // Resolve sets the full ID as subject + the trust domain.
        let r = SpiffeResolver::default();
        let id = r.resolve("spiffe://example.org/ns/prod/sa/api").unwrap();
        assert_eq!(id.kind, IdentityKind::Spiffe);
        assert_eq!(id.subject, "spiffe://example.org/ns/prod/sa/api");
        assert_eq!(id.trust_domain.as_deref(), Some("example.org"));
    }

    #[test]
    fn test_spiffe_trust_domain_allowlist() {
        let r = SpiffeResolver::new(vec!["trusted.org".to_string()]);
        assert!(r.resolve("spiffe://trusted.org/sa/x").is_ok());
        let err = r.resolve("spiffe://evil.org/sa/x").unwrap_err();
        assert_eq!(err, IdentityError::UntrustedDomain("evil.org".to_string()));
        // Trust domains are DNS names → case-insensitive allowlist match.
        assert!(
            r.resolve("spiffe://TRUSTED.ORG/sa/x").is_ok(),
            "case variant of a trusted domain"
        );
        assert!(
            r.resolve("spiffe://Evil.org/sa/x").is_err(),
            "case variant of an untrusted domain"
        );
    }

    #[test]
    fn test_oidc_resolve_subject_issuer_owner() {
        let r = OidcResolver::default();
        let id = r
            .resolve(
                r#"{"sub":"user-123","iss":"https://idp.example.com","email":"alice@example.com"}"#,
            )
            .unwrap();
        assert_eq!(id.subject, "user-123");
        assert_eq!(id.trust_domain.as_deref(), Some("https://idp.example.com"));
        assert_eq!(id.owner.as_deref(), Some("alice@example.com"));

        // Missing sub → error; a machine token (no human claim) has NO owner.
        assert!(r.resolve(r#"{"iss":"x"}"#).is_err());
        let id = r.resolve(r#"{"sub":"svc-1"}"#).unwrap();
        assert_eq!(
            id.owner, None,
            "no email/preferred_username → no human owner"
        );

        // Issuer allowlist enforced — and a token with NO iss must NOT bypass it.
        let r = OidcResolver::new(vec!["https://good".to_string()]);
        assert!(r.resolve(r#"{"sub":"a","iss":"https://bad"}"#).is_err());
        assert_eq!(
            r.resolve(r#"{"sub":"a"}"#),
            Err(IdentityError::MissingClaim("iss".to_string())),
            "an iss-less token cannot bypass a non-empty issuer allowlist"
        );
        // With no allowlist, an iss-less token is accepted (owner falls through).
        assert!(OidcResolver::default().resolve(r#"{"sub":"a"}"#).is_ok());
        // An empty email claim is not a valid owner.
        let id = OidcResolver::default()
            .resolve(r#"{"sub":"x","email":""}"#)
            .unwrap();
        assert_eq!(id.owner, None, "empty email is not an owner");
    }

    /// VUL-20: the edge signature binds document, expiry and bearer; any change is refused.
    #[test]
    fn identity_signature_roundtrip_and_tamper() {
        let key = "identity-key-0123456789abcdef";
        let doc = "spiffe://example.org/ns/prod/sa/agent";
        let now = 1_800_000_000;
        let sig = sign_identity(key, doc, "vut_abc", now + 60);
        verify_identity_signature(key, doc, "vut_abc", &sig, now).expect("valid");
        let bad = |k: &str, d: &str, b: &str, s: &str, n: i64| {
            matches!(
                verify_identity_signature(k, d, b, s, n),
                Err(IdentityError::BadSignature(_))
            )
        };
        assert!(
            bad("other-key-0123456789abcdef", doc, "vut_abc", &sig, now),
            "wrong key"
        );
        assert!(
            bad(key, "spiffe://example.org/other", "vut_abc", &sig, now),
            "other doc"
        );
        assert!(bad(key, doc, "vut_other", &sig, now), "other bearer");
        assert!(bad(key, doc, "vut_abc", &sig, now + 61), "expired");
        let far = sign_identity(key, doc, "vut_abc", now + IDENTITY_MAX_TTL_SECS + 1);
        assert!(
            bad(key, doc, "vut_abc", &far, now),
            "lifetime beyond the ceiling"
        );
        let at_ceiling = sign_identity(key, doc, "vut_abc", now + IDENTITY_MAX_TTL_SECS);
        verify_identity_signature(key, doc, "vut_abc", &at_ceiling, now).expect("at the ceiling");
        // Tampered expiry with the old MAC.
        let mac = sig.rsplit('.').next().unwrap();
        assert!(bad(
            key,
            doc,
            "vut_abc",
            &format!("v1.{}.{mac}", now + 120),
            now
        ));
        for malformed in [
            "",
            "v1",
            "v1.1.2.3",
            "v2.1.AAAA",
            "v1.-5.AAAA",
            "v1..AAAA",
            "v1.1800000060.!!",
            "v1.99999999999999999999.AAAA",
        ] {
            assert!(bad(key, doc, "vut_abc", malformed, now), "{malformed}");
        }
    }

    #[test]
    fn test_cloud_iam_claim_adapters() {
        let aws = resolve_cloud_iam(
            IdentityKind::AwsIam,
            r#"{"arn":"arn:aws:sts::123:assumed-role/agent/sess"}"#,
        )
        .unwrap();
        assert_eq!(aws.subject, "arn:aws:sts::123:assumed-role/agent/sess");
        assert_eq!(aws.trust_domain.as_deref(), Some("aws"));

        let gcp = resolve_cloud_iam(
            IdentityKind::GcpWorkload,
            r#"{"email":"agent@proj.iam.gserviceaccount.com","iss":"https://accounts.google.com"}"#,
        )
        .unwrap();
        assert_eq!(gcp.subject, "agent@proj.iam.gserviceaccount.com");
        // A cloud workload is NOT its own human owner — even with an email claim,
        // owner stays None (no false human accountability / trivial self-approval).
        assert_eq!(gcp.owner, None, "cloud-IAM workload has no human owner");

        let entra = resolve_cloud_iam(
            IdentityKind::EntraWorkload,
            r#"{"oid":"00000000-aaaa","tid":"tenant-1"}"#,
        )
        .unwrap();
        assert_eq!(entra.subject, "00000000-aaaa");
        assert_eq!(entra.trust_domain.as_deref(), Some("tenant-1"));

        // A missing required claim errors.
        assert!(resolve_cloud_iam(IdentityKind::AwsIam, r#"{}"#).is_err());
        // Unsupported kind via this fn errors.
        assert!(resolve_cloud_iam(IdentityKind::Spiffe, r#"{}"#).is_err());
    }
}
