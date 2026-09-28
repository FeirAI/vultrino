//! Google service-account access tokens (RFC 7523 JWT-bearer grant).
//!
//! A service-account key does not expire the way an installed-app refresh token
//! does, so this is the credential shape a long-running governed deployment can
//! actually keep. The trade is that the vault now holds an RSA private key, so
//! every rule here is written to fail closed:
//!
//! - The token endpoint is **pinned** to [`GOOGLE_TOKEN_URI`] byte-for-byte.
//!   Not "an https host", not "a googleapis.com host": that exact string. The
//!   assertion is signed for that audience and the private key is only ever
//!   exercised against it, so a tampered `token_uri` cannot walk the key to
//!   another origin. Redirects are refused by the shared guarded client
//!   (`build_guarded_client` sets `redirect::Policy::none()`), and a 3xx from
//!   the token endpoint surfaces as a failure rather than a second hop.
//! - Scopes must be a non-empty subset of [`ALLOWED_SCOPES`]: the Sheets and
//!   Calendar scopes the solo connector actually calls, and nothing else. A key
//!   that a project granted more broadly still cannot mint a broader token here.
//! - **No domain-wide delegation.** A `sub` claim is never set, so the minted
//!   token is the service account acting as itself. An operator grants it access
//!   by sharing the specific spreadsheet or calendar with the service account's
//!   own address; it cannot impersonate a human in the workspace.
//! - The assertion lives at most [`ASSERTION_LIFETIME_SECS`], and no caller can
//!   widen that.
//!
//! Nothing in this module returns key material, the assertion, or the token to a
//! caller-visible error. Google's own `error` / `error_description` strings are
//! the only upstream text that reaches the operator log, and they reach no
//! further than the log.

use super::PluginError;
use crate::{Credential, CredentialData, Secret};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

/// The one token endpoint a service-account credential may be used against.
/// Compared byte-for-byte; see the module note on why this is not a host check.
pub(crate) const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Every service-account address Google issues ends in this. A credential whose
/// `client_email` does not is not a service account, and is refused rather than
/// tried.
pub(crate) const SERVICE_ACCOUNT_EMAIL_SUFFIX: &str = ".iam.gserviceaccount.com";

/// The complete set of scopes a service-account credential may request. This is
/// what the solo connector calls, and only that: Sheets values read/append
/// (`v4/spreadsheets/{id}/values/...`) and Calendar events plus freebusy
/// (`calendars/{id}/events`, `freeBusy`). Read-only variants are permitted so an
/// operator can seed a narrower key for a read-only deployment.
pub(crate) const ALLOWED_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.readonly",
];

/// Google rejects an assertion longer-lived than an hour; we never ask for one.
const ASSERTION_LIFETIME_SECS: i64 = 3600;

/// RSA keys below this are refused before `ring` ever sees them, so the refusal
/// is ours and says why.
const MIN_RSA_MODULUS_BITS: usize = 2048;

const PKCS8_PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_PEM_END: &str = "-----END PRIVATE KEY-----";

/// Framings an operator plausibly pastes instead of PKCS#8. Each is refused, but
/// by a message that names what they actually have; see [`pem_framing_reason`].
const PKCS1_PEM_BEGIN: &str = "-----BEGIN RSA PRIVATE KEY-----";
const ENCRYPTED_PKCS8_PEM_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const SEC1_EC_PEM_BEGIN: &str = "-----BEGIN EC PRIVATE KEY-----";

/// Google's own clock is the one that judges `iat`, so the assertion is backdated
/// by this much: a vultrino host running even slightly fast would otherwise mint
/// an assertion issued in the future, which Google rejects as `invalid_grant` on
/// every single call.
const ASSERTION_BACKDATE_SECS: i64 = 30;

const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// A cached Google access token this close to its `expires_at` is replaced
/// rather than served. Shared with the solo oauth2 refresh path so both Google
/// credential shapes roll over at the same point.
const REFRESH_MARGIN_SECS: i64 = 300;

/// The subset of Google's token response this path uses.
#[derive(Debug, Deserialize)]
pub(crate) struct MintedToken {
    pub(crate) access_token: String,
    #[serde(default)]
    pub(crate) expires_in: Option<u64>,
}

/// Google's RFC 6749 §5.2 error body. Parsed only so the operator log can say
/// *why* a mint failed (`invalid_grant` when a key is disabled, `invalid_scope`
/// when the project has not enabled an API). Never returned to the agent.
#[derive(Debug, Deserialize)]
struct TokenErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Admission check for a `google_service_account` credential. Runs at credential
/// create (seed time) and again immediately before the key is used, so a record
/// that reached the vault by some other route still cannot mint.
///
/// Every message is a fixed string: none of them quotes the key, the email, or
/// the offending scope back to the caller.
pub(crate) fn validate(
    client_email: &str,
    private_key: &str,
    private_key_id: &str,
    token_uri: &str,
    scopes: &[String],
) -> Result<(), &'static str> {
    validate_fields(client_email, private_key_id, token_uri, scopes)?;
    // Proving the key parses is part of admission: a credential that cannot sign
    // must be refused at seed, not at the first governed call.
    signing_key(private_key).map(|_| ())
}

/// The half of [`validate`] that touches no key material. Split out so the use
/// path can re-check the pinned endpoint, the service-account address and the
/// scope allowlist on EVERY governed call while a cached access token is served,
/// and only pay for the PKCS#8 parse when it is actually about to mint (the mint
/// path parses the key itself, so nothing is unchecked).
pub(crate) fn validate_fields(
    client_email: &str,
    private_key_id: &str,
    token_uri: &str,
    scopes: &[String],
) -> Result<(), &'static str> {
    if token_uri != GOOGLE_TOKEN_URI {
        return Err(
            "google_service_account token_uri must be exactly https://oauth2.googleapis.com/token",
        );
    }
    let email = client_email.trim();
    if email.is_empty() || !email.ends_with(SERVICE_ACCOUNT_EMAIL_SUFFIX) {
        return Err("google_service_account client_email must end with .iam.gserviceaccount.com");
    }
    if private_key_id.trim().is_empty() {
        return Err("google_service_account private_key_id must not be empty");
    }
    if scopes.is_empty() {
        return Err("google_service_account requires at least one scope");
    }
    if !scopes
        .iter()
        .all(|scope| ALLOWED_SCOPES.contains(&scope.as_str()))
    {
        return Err(
            "google_service_account scopes must be a subset of the Sheets/Calendar allowlist",
        );
    }
    Ok(())
}

/// Decode a PKCS#8 PEM private key and hand back a `ring` RSA key pair.
///
/// The PKCS#8 label is required. A PKCS#1 (`BEGIN RSA PRIVATE KEY`) or SEC1
/// (`BEGIN EC PRIVATE KEY`) body is refused here rather than being coerced:
/// Google emits PKCS#8, so anything else means the operator pasted something
/// this path was not designed to sign with.
fn signing_key(private_key: &str) -> Result<ring::signature::RsaKeyPair, &'static str> {
    let der = decode_pkcs8_pem(private_key)?;
    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|_| "google_service_account private_key is not a usable PKCS#8 RSA key")?;
    if key_pair.public().modulus_len() * 8 < MIN_RSA_MODULUS_BITS {
        return Err("google_service_account private_key must be an RSA key of at least 2048 bits");
    }
    Ok(key_pair)
}

fn decode_pkcs8_pem(private_key: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    // An operator pasting Google's JSON key into an env var, a .env file or a
    // compose file very often lands the PEM with its newlines still escaped as
    // the two characters backslash-n, because nothing in that chain interprets
    // JSON escapes. It is the same key, so normalize it rather than refuse: the
    // trailing literal `\n` is what used to survive `trim()`, defeat
    // `strip_suffix` and produce a "must be a PKCS#8 PEM block" message that
    // reads as "wrong key type". Applies to both callers, validate and mint,
    // because both reach the key through here.
    let normalized: Zeroizing<String> = Zeroizing::new(if private_key.contains("\\n") {
        private_key.replace("\\n", "\n")
    } else {
        private_key.to_string()
    });
    let trimmed = normalized.trim();
    let body = match trimmed
        .strip_prefix(PKCS8_PEM_BEGIN)
        .and_then(|rest| rest.strip_suffix(PKCS8_PEM_END))
    {
        Some(body) => body,
        None => return Err(pem_framing_reason(trimmed)),
    };
    let base64_body: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    STANDARD
        .decode(base64_body.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| "google_service_account private_key PEM body is not valid base64")
}

/// Name the framing the operator actually pasted, so the refusal points at the
/// remedy instead of restating the requirement. Every arm is a fixed string and
/// none of them quotes any part of the key.
fn pem_framing_reason(trimmed: &str) -> &'static str {
    if trimmed.starts_with(PKCS1_PEM_BEGIN) {
        "google_service_account private_key is a PKCS#1 RSA key; convert it to PKCS#8 with \
         'openssl pkcs8 -topk8 -nocrypt' and store that block"
    } else if trimmed.starts_with(ENCRYPTED_PKCS8_PEM_BEGIN) {
        "google_service_account private_key is an encrypted PKCS#8 key; this path cannot \
         hold a passphrase, so store the decrypted key (Google's JSON key is not encrypted)"
    } else if trimmed.starts_with(SEC1_EC_PEM_BEGIN) {
        "google_service_account private_key is an EC key; a Google service-account key is \
         RSA in PKCS#8 form"
    } else {
        "google_service_account private_key must be a PKCS#8 PEM block"
    }
}

/// Build and sign the RS256 assertion. Public inputs only in the output; the
/// key never leaves this function.
fn signed_assertion(
    client_email: &str,
    private_key: &str,
    private_key_id: &str,
    token_uri: &str,
    scopes: &[String],
) -> Result<Zeroizing<String>, &'static str> {
    let key_pair = signing_key(private_key)?;
    // Backdated; `exp` stays exactly one hour after `iat`, which is Google's
    // ceiling. See ASSERTION_BACKDATE_SECS.
    let issued_at = Utc::now().timestamp() - ASSERTION_BACKDATE_SECS;

    // No `sub`: this is the service account acting as itself. Adding one would
    // be domain-wide delegation, which this deployment does not do.
    let header = json!({"alg": "RS256", "typ": "JWT", "kid": private_key_id});
    let claims = json!({
        "iss": client_email,
        "scope": scopes.join(" "),
        "aud": token_uri,
        "iat": issued_at,
        "exp": issued_at + ASSERTION_LIFETIME_SECS,
    });

    let encode = |value: &serde_json::Value| -> Result<String, &'static str> {
        serde_json::to_vec(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|_| "google_service_account assertion could not be encoded")
    };
    let signing_input = format!("{}.{}", encode(&header)?, encode(&claims)?);

    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| "google_service_account assertion could not be signed")?;

    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    )))
}

/// Mint an access token from the service-account key.
///
/// `token_uri` is taken as a parsed [`Url`] so the caller has already had to
/// pin it; [`validate`] is what enforces that it is [`GOOGLE_TOKEN_URI`], and
/// every production caller runs that first. The `aud` claim is signed over the
/// string form of this same URL, so the assertion is worthless anywhere else.
pub(crate) async fn mint_access_token(
    client: &Client,
    token_uri: &Url,
    client_email: &str,
    private_key: &str,
    private_key_id: &str,
    scopes: &[String],
) -> Result<MintedToken, PluginError> {
    let assertion = signed_assertion(
        client_email,
        private_key,
        private_key_id,
        token_uri.as_str(),
        scopes,
    )
    .map_err(|reason| PluginError::Validation(reason.to_string()))?;

    let response = client
        .post(token_uri.clone())
        .timeout(crate::plugins::REQUEST_TIMEOUT)
        .form(&[
            ("grant_type", JWT_BEARER_GRANT),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        // `without_url()` keeps the query-free endpoint out of the message; the
        // assertion was in the body, never the URL, so nothing secret is here.
        .map_err(|error| PluginError::Http(error.without_url().to_string()))?;

    let status = response.status();
    let body = crate::plugins::read_body_capped(response).await?;
    if !status.is_success() {
        // A 3xx lands here too: the guarded client does not follow redirects, so
        // a token endpoint that tries to move us is a failure, not a second hop.
        log_upstream_failure(status.as_u16(), &body);
        return Err(PluginError::ExecutionFailed(format!(
            "Google service-account token mint returned HTTP {}",
            status.as_u16()
        )));
    }

    let token: MintedToken = serde_json::from_slice(&body).map_err(|_| {
        PluginError::ExecutionFailed("Google service-account token response was invalid".into())
    })?;
    if token.access_token.is_empty() {
        return Err(PluginError::ExecutionFailed(
            "Google service-account token response did not contain an access token".into(),
        ));
    }
    Ok(token)
}

/// Whether a cached Google access token must be replaced before use: absent, or
/// inside [`REFRESH_MARGIN_SECS`] of its `expires_at`.
pub(crate) fn token_is_stale(
    access_token: Option<&Secret>,
    expires_at: Option<DateTime<Utc>>,
) -> bool {
    match access_token {
        None => true,
        Some(_) => expires_at
            .is_some_and(|expires| Utc::now() + Duration::seconds(REFRESH_MARGIN_SECS) >= expires),
    }
}

/// Resolve a `google_service_account` credential to a bearer token: the cached
/// access token while it is outside [`token_is_stale`]'s margin, otherwise a
/// freshly minted one plus the updated credential data for the caller to
/// persist. Every connector that accepts this credential shape goes through
/// here, so re-validation, caching and minting live in exactly one place.
///
/// The credential is re-validated even though the create path already did:
/// use time is the last gate before the private key is exercised, and the
/// vault is not the only way a record can arrive.
///
/// `required_scopes` is the calling connector's own need: the credential must
/// carry at least one of them or the call is refused before any token is
/// served or minted. An empty slice relies on the allowlist alone. The mint
/// still requests the credential's full scope set, because the minted token is
/// persisted on the shared credential and served to every connector using it.
///
/// `token_endpoint` must be [`GOOGLE_TOKEN_URI`]; outside unit tests anything
/// else is refused. It is a parameter only so tests can mint against a
/// loopback endpoint while the credential still carries the pinned `token_uri`.
pub(crate) async fn service_account_token(
    client: &Client,
    credential: &Credential,
    token_endpoint: &Url,
    required_scopes: &[&str],
) -> Result<(Credential, Option<CredentialData>, String), PluginError> {
    let CredentialData::GoogleServiceAccount {
        client_email,
        private_key,
        private_key_id,
        token_uri,
        scopes,
        access_token,
        expires_at,
    } = &credential.data
    else {
        return Err(PluginError::UnsupportedCredentialType(
            "service-account path requires google_service_account".into(),
        ));
    };
    if !cfg!(test) && token_endpoint.as_str() != GOOGLE_TOKEN_URI {
        return Err(PluginError::InvalidParams(
            "google_service_account token endpoint must be exactly https://oauth2.googleapis.com/token"
                .into(),
        ));
    }
    // Use-time re-validation, cheap half first. The pinned endpoint, the
    // service-account address, the key id and the scope allowlist are re-checked
    // on EVERY governed call, including the ones served from the cached token.
    // The PKCS#8 parse is not: it is the expensive part and it is unavoidable on
    // the mint path anyway (`signed_assertion` parses the key it signs with, and
    // refuses with the same messages), so a cache hit does not pay for it.
    credential
        .data
        .validate_admission_fields()
        .map_err(|reason| PluginError::InvalidParams(reason.to_string()))?;
    if !required_scopes.is_empty()
        && !scopes
            .iter()
            .any(|scope| required_scopes.contains(&scope.as_str()))
    {
        return Err(PluginError::InvalidParams(
            "google_service_account scopes do not cover this connector".into(),
        ));
    }
    if let Some(token) = access_token {
        if !token_is_stale(Some(token), *expires_at) {
            return Ok((credential.clone(), None, token.expose().into()));
        }
    }
    let token = mint_access_token(
        client,
        token_endpoint,
        client_email,
        private_key.expose(),
        private_key_id,
        scopes,
    )
    .await?;
    let expires_at = token.expires_in.and_then(|seconds| {
        i64::try_from(seconds)
            .ok()
            .and_then(Duration::try_seconds)
            .and_then(|duration| Utc::now().checked_add_signed(duration))
    });
    let updated_data = CredentialData::GoogleServiceAccount {
        client_email: client_email.clone(),
        private_key: private_key.clone(),
        private_key_id: private_key_id.clone(),
        token_uri: token_uri.clone(),
        scopes: scopes.clone(),
        access_token: Some(Secret::new(token.access_token.clone())),
        expires_at,
    };
    let mut effective = credential.clone();
    effective.data = updated_data.clone();
    effective.updated_at = Utc::now();
    Ok((effective, Some(updated_data), token.access_token))
}

/// Operator-log only. Google's `error` / `error_description` are the two strings
/// that make a failed mint diagnosable (`invalid_grant`, `invalid_scope`,
/// "Invalid JWT Signature."); nothing else from the body is logged, and the
/// agent-visible error carries only the status code.
fn log_upstream_failure(status: u16, body: &[u8]) {
    let parsed: Option<TokenErrorBody> = serde_json::from_slice(body).ok();
    let (error, description) = parsed
        .map(|b| (b.error, b.error_description))
        .unwrap_or((None, None));
    tracing::warn!(
        status,
        error = error.as_deref().unwrap_or("unknown"),
        error_description = description.as_deref().unwrap_or(""),
        "Google service-account token mint failed"
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{routing::any, Json, Router};
    use std::process::Command;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::net::TcpListener;

    /// A 2048-bit RSA key generated locally, once, for this test run. It is
    /// never a real key and never leaves the process image.
    pub(crate) fn test_key_pem() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| generate_rsa_pem(2048))
    }

    fn generate_rsa_pem(bits: usize) -> String {
        let output = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                &format!("rsa_keygen_bits:{bits}"),
                "-outform",
                "PEM",
            ])
            .output()
            .expect("openssl is required to generate the RSA test key");
        assert!(output.status.success(), "openssl genpkey failed");
        String::from_utf8(output.stdout).expect("openssl emits utf-8 PEM")
    }

    fn scopes() -> Vec<String> {
        vec!["https://www.googleapis.com/auth/spreadsheets".to_string()]
    }

    const EMAIL: &str = "solo@feir-demo.iam.gserviceaccount.com";
    const KID: &str = "0123456789abcdef0123456789abcdef01234567";

    fn decode_segment(segment: &str) -> serde_json::Value {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segment)
                .expect("segment is base64url"),
        )
        .expect("segment is JSON")
    }

    #[test]
    fn assertion_header_and_claims_are_exact_and_carry_no_sub() {
        let before = Utc::now().timestamp();
        let jwt = signed_assertion(
            EMAIL,
            test_key_pem(),
            KID,
            GOOGLE_TOKEN_URI,
            &[
                "https://www.googleapis.com/auth/spreadsheets".to_string(),
                "https://www.googleapis.com/auth/calendar".to_string(),
            ],
        )
        .expect("a valid service-account key signs");
        let after = Utc::now().timestamp();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "a JWS compact serialization has three parts"
        );

        let header = decode_segment(parts[0]);
        assert_eq!(
            header,
            json!({"alg": "RS256", "typ": "JWT", "kid": KID}),
            "the header is exactly alg/typ/kid"
        );

        let claims = decode_segment(parts[1]);
        assert_eq!(claims["iss"], json!(EMAIL));
        assert_eq!(
            claims["scope"],
            json!("https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/calendar"),
            "scopes are space-joined in order"
        );
        assert_eq!(claims["aud"], json!(GOOGLE_TOKEN_URI));
        assert!(
            claims.get("sub").is_none(),
            "no domain-wide delegation: a sub claim must never be set"
        );

        let iat = claims["iat"].as_i64().expect("iat is a number");
        let exp = claims["exp"].as_i64().expect("exp is a number");
        assert_eq!(exp - iat, 3600, "the assertion lives exactly one hour");
        // Backdated by ASSERTION_BACKDATE_SECS so a host whose clock runs fast
        // does not issue an assertion Google reads as being from the future.
        assert!(
            (before - ASSERTION_BACKDATE_SECS..=after - ASSERTION_BACKDATE_SECS).contains(&iat),
            "iat is minted now, backdated 30s"
        );
        assert!(
            exp <= after + 3600,
            "exp is never more than an hour past the real clock"
        );

        // Exactly the five claims above, and nothing the brief did not ask for.
        let claim_names: Vec<&String> = claims
            .as_object()
            .expect("claims are an object")
            .keys()
            .collect();
        assert_eq!(
            claim_names.len(),
            5,
            "claims are iss/scope/aud/iat/exp only"
        );
    }

    #[test]
    fn assertion_signature_verifies_against_the_public_key() {
        let pem = test_key_pem();
        let jwt = signed_assertion(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &scopes()).unwrap();
        let (signing_input, signature_b64) = jwt.rsplit_once('.').expect("jwt has a signature");
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .expect("the signature is base64url");

        let key_pair = signing_key(pem).unwrap();
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key_pair.public().as_ref(),
        );
        public_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("RS256 signature verifies against the service-account public key");

        // Tampering with the signed input must break it.
        let tampered = format!("{signing_input}x");
        assert!(public_key.verify(tampered.as_bytes(), &signature).is_err());
    }

    #[test]
    fn validation_pins_the_token_uri() {
        let pem = test_key_pem();
        assert!(validate(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &scopes()).is_ok());
        for other in [
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com/token/",
            "https://oauth2.googleapis.com:443/token",
            "https://accounts.google.com/o/oauth2/token",
            "https://evil.example/token",
            "",
        ] {
            assert!(
                validate(EMAIL, pem, KID, other, &scopes()).is_err(),
                "token_uri {other:?} must be refused"
            );
        }
    }

    #[test]
    fn validation_enforces_the_service_account_email_suffix() {
        let pem = test_key_pem();
        for bad in [
            "owner@feir.ai",
            "solo@iam.gserviceaccount.com.evil.example",
            "solo@feir-demo.iam.gserviceaccount.com.evil",
            "",
        ] {
            assert!(
                validate(bad, pem, KID, GOOGLE_TOKEN_URI, &scopes()).is_err(),
                "client_email {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn validation_enforces_the_scope_allowlist() {
        let pem = test_key_pem();
        assert!(
            validate(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &[]).is_err(),
            "an empty scope set is refused"
        );
        for bad in [
            "https://www.googleapis.com/auth/drive",
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/spreadsheets ",
            "spreadsheets",
        ] {
            assert!(
                validate(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &[bad.to_string()]).is_err(),
                "scope {bad:?} must be refused"
            );
        }
        // One allowed scope plus one disallowed scope is still refused.
        let mixed = vec![
            "https://www.googleapis.com/auth/spreadsheets".to_string(),
            "https://www.googleapis.com/auth/drive".to_string(),
        ];
        assert!(validate(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &mixed).is_err());
        // Every allowlisted scope is individually accepted.
        for allowed in ALLOWED_SCOPES {
            assert!(validate(EMAIL, pem, KID, GOOGLE_TOKEN_URI, &[allowed.to_string()]).is_ok());
        }
    }

    #[test]
    fn validation_requires_a_private_key_id() {
        assert!(validate(EMAIL, test_key_pem(), "   ", GOOGLE_TOKEN_URI, &scopes()).is_err());
    }

    #[test]
    fn validation_rejects_short_non_rsa_and_malformed_keys() {
        let short = generate_rsa_pem(1024);
        assert!(
            validate(EMAIL, &short, KID, GOOGLE_TOKEN_URI, &scopes()).is_err(),
            "a 1024-bit RSA key is below the floor"
        );

        let ec = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-outform",
                "PEM",
            ])
            .output()
            .expect("openssl generates the EC test key");
        assert!(ec.status.success());
        let ec_pem = String::from_utf8(ec.stdout).unwrap();
        assert!(
            validate(EMAIL, &ec_pem, KID, GOOGLE_TOKEN_URI, &scopes()).is_err(),
            "a P-256 key is not an RSA signing key"
        );

        for malformed in [
            "",
            "not a pem at all",
            "-----BEGIN PRIVATE KEY-----\nnot base64!!!\n-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
        ] {
            assert!(
                validate(EMAIL, malformed, KID, GOOGLE_TOKEN_URI, &scopes()).is_err(),
                "malformed key {malformed:?} must be refused"
            );
        }
    }

    #[test]
    fn a_pem_whose_newlines_arrived_escaped_is_accepted() {
        // Google's JSON key holds the PEM with `\n` escapes. Paste that value into
        // an env var, a .env file or a compose file and the two characters
        // backslash-n are what reaches us. Same key, so it is accepted, on both
        // the validate and the mint path.
        let escaped = test_key_pem().replace('\n', "\\n");
        assert!(
            escaped.contains("\\n") && !escaped.contains('\n'),
            "the fixture really is the escaped form"
        );
        validate(EMAIL, &escaped, KID, GOOGLE_TOKEN_URI, &scopes())
            .expect("an escaped-newline PEM is the same key");

        let jwt = signed_assertion(EMAIL, &escaped, KID, GOOGLE_TOKEN_URI, &scopes())
            .expect("the mint path accepts it too");
        let (signing_input, signature_b64) = jwt.rsplit_once('.').expect("jwt has a signature");
        let signature = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        let key_pair = signing_key(test_key_pem()).unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key_pair.public().as_ref(),
        )
        .verify(signing_input.as_bytes(), &signature)
        .expect("it signed with the very same key");

        // A trailing escaped newline, the exact shape that used to defeat
        // strip_suffix and report "must be a PKCS#8 PEM block".
        let trailing = format!("{}\\n", test_key_pem().trim_end());
        validate(EMAIL, &trailing, KID, GOOGLE_TOKEN_URI, &scopes())
            .expect("a trailing escaped newline is not a different key");
    }

    #[test]
    fn the_wrong_pem_framing_is_named_in_the_refusal() {
        // Each of these is refused either way; what is tested is that the message
        // tells the operator which mistake they made.
        let pkcs1 = validate(
            EMAIL,
            "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
            KID,
            GOOGLE_TOKEN_URI,
            &scopes(),
        )
        .unwrap_err();
        assert!(pkcs1.contains("PKCS#1"), "names what they pasted: {pkcs1}");
        assert!(pkcs1.contains("PKCS#8"), "names what is needed: {pkcs1}");
        assert!(
            pkcs1.contains("openssl pkcs8 -topk8"),
            "names the remedy: {pkcs1}"
        );

        let encrypted = validate(
            EMAIL,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----",
            KID,
            GOOGLE_TOKEN_URI,
            &scopes(),
        )
        .unwrap_err();
        assert!(
            encrypted.contains("encrypted"),
            "names the encryption: {encrypted}"
        );

        let sec1_ec = validate(
            EMAIL,
            "-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE KEY-----",
            KID,
            GOOGLE_TOKEN_URI,
            &scopes(),
        )
        .unwrap_err();
        assert!(sec1_ec.contains("EC key"), "names the curve key: {sec1_ec}");
        assert!(sec1_ec.contains("RSA"), "names what is needed: {sec1_ec}");

        // A PKCS#8-framed key that is simply not RSA still gets the generic
        // not-a-usable-RSA-key message from `ring`'s parse.
        let ec_pkcs8 = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-outform",
                "PEM",
            ])
            .output()
            .expect("openssl generates the EC test key");
        let ec_pem = String::from_utf8(ec_pkcs8.stdout).unwrap();
        let message = validate(EMAIL, &ec_pem, KID, GOOGLE_TOKEN_URI, &scopes()).unwrap_err();
        assert!(
            message.contains("PKCS#8 RSA key"),
            "a PKCS#8-framed non-RSA key: {message}"
        );
    }

    #[test]
    fn validate_fields_runs_every_rule_but_the_key_parse() {
        // The use path calls this on every governed call; it must still refuse an
        // unpinned endpoint, a non-service-account address, a blank key id and an
        // off-allowlist scope, and must NOT care about the key (the mint path
        // parses it).
        assert!(validate_fields(EMAIL, KID, GOOGLE_TOKEN_URI, &scopes()).is_ok());
        assert!(validate_fields(EMAIL, KID, "https://evil.example/token", &scopes()).is_err());
        assert!(validate_fields("owner@feir.ai", KID, GOOGLE_TOKEN_URI, &scopes()).is_err());
        assert!(validate_fields(EMAIL, "  ", GOOGLE_TOKEN_URI, &scopes()).is_err());
        assert!(validate_fields(EMAIL, KID, GOOGLE_TOKEN_URI, &[]).is_err());
        assert!(validate_fields(
            EMAIL,
            KID,
            GOOGLE_TOKEN_URI,
            &["https://www.googleapis.com/auth/drive".to_string()]
        )
        .is_err());
        // The full `validate` is the one that also proves the key parses.
        assert!(validate(EMAIL, "garbage", KID, GOOGLE_TOKEN_URI, &scopes()).is_err());
    }

    #[test]
    fn no_validation_error_ever_quotes_key_material() {
        let pem = test_key_pem();
        let body = pem.lines().nth(1).expect("the PEM has a body line");
        let cases: Vec<Result<(), &'static str>> = vec![
            validate(EMAIL, pem, KID, "https://evil.example/token", &scopes()),
            validate("owner@feir.ai", pem, KID, GOOGLE_TOKEN_URI, &scopes()),
            validate(EMAIL, pem, "", GOOGLE_TOKEN_URI, &scopes()),
            validate(
                EMAIL,
                pem,
                KID,
                GOOGLE_TOKEN_URI,
                &["https://www.googleapis.com/auth/drive".to_string()],
            ),
            validate(EMAIL, "garbage", KID, GOOGLE_TOKEN_URI, &scopes()),
        ];
        for case in cases {
            let message = case.unwrap_err();
            assert!(!message.contains(body), "no key body in a refusal");
            assert!(
                !message.contains("BEGIN PRIVATE KEY"),
                "no PEM framing in a refusal"
            );
        }
    }

    // ---- service_account_token ------------------------------------------
    //
    // The mock token endpoint lives on 127.0.0.1, which `build_guarded_client`
    // deliberately cannot reach (its connect-time resolver keeps public IPs
    // only). These tests therefore use a client that keeps the one property
    // under test here (`redirect::Policy::none()`) and drops only the DNS
    // guard. Production still goes through `build_guarded_client`.
    pub(crate) fn loopback_client() -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client builds")
    }

    pub(crate) type TokenHits = Arc<Mutex<Vec<(String, String)>>>;

    /// A token endpoint that records every request it receives and answers with
    /// `reply`. Returns its URL and the recording.
    pub(crate) async fn recording_token_server(
        status: u16,
        reply: serde_json::Value,
    ) -> (String, TokenHits) {
        let hits: TokenHits = Arc::new(Mutex::new(Vec::new()));
        let recorder = hits.clone();
        let app = Router::new().route(
            "/{*path}",
            any(move |request: axum::extract::Request| {
                let recorder = recorder.clone();
                let reply = reply.clone();
                async move {
                    let uri = request.uri().to_string();
                    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
                        .await
                        .unwrap_or_default();
                    recorder
                        .lock()
                        .unwrap()
                        .push((uri, String::from_utf8_lossy(&body).to_string()));
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        Json(reply),
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/token"), hits)
    }

    /// A `google_service_account` credential carrying the pinned `token_uri`,
    /// the test key and `scopes`, with an optional cached access token.
    pub(crate) fn service_account_credential(
        scopes: &[&str],
        access_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Credential {
        Credential::new(
            "cred-google-sheets".into(),
            CredentialData::GoogleServiceAccount {
                client_email: EMAIL.into(),
                private_key: Secret::new(test_key_pem()),
                private_key_id: KID.into(),
                token_uri: GOOGLE_TOKEN_URI.into(),
                scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
                access_token: access_token.map(Secret::new),
                expires_at,
            },
        )
    }

    const SHEETS: &str = "https://www.googleapis.com/auth/spreadsheets";
    const SHEETS_READONLY: &str = "https://www.googleapis.com/auth/spreadsheets.readonly";
    const CALENDAR: &str = "https://www.googleapis.com/auth/calendar";

    async fn minting_endpoint() -> (Url, TokenHits) {
        let (url, hits) = recording_token_server(
            200,
            json!({"access_token": "minted-token", "expires_in": 3599, "token_type": "Bearer"}),
        )
        .await;
        (Url::parse(&url).unwrap(), hits)
    }

    /// A credential with no cached token mints once, returns the update to
    /// persist, and the persisted form is then served from cache with no
    /// second mint and nothing new to persist.
    #[tokio::test]
    async fn service_account_token_mints_once_then_serves_the_persisted_token() {
        let (endpoint, hits) = minting_endpoint().await;
        let client = loopback_client();
        let credential = service_account_credential(&[SHEETS], None, None);

        let (effective, updated, token) =
            service_account_token(&client, &credential, &endpoint, &[SHEETS])
                .await
                .expect("a pinned credential mints");
        assert_eq!(token, "minted-token");
        let Some(CredentialData::GoogleServiceAccount {
            access_token: Some(persisted),
            expires_at: Some(expires_at),
            scopes,
            ..
        }) = &updated
        else {
            panic!("the minted token is handed back for persistence: {updated:?}");
        };
        assert_eq!(persisted.expose(), "minted-token");
        assert!(*expires_at > Utc::now() + Duration::seconds(3500));
        assert_eq!(scopes, &[SHEETS.to_string()], "scopes carried unchanged");
        assert_eq!(hits.lock().unwrap().len(), 1, "exactly one mint");

        let (_again, updated, token) =
            service_account_token(&client, &effective, &endpoint, &[SHEETS])
                .await
                .expect("the persisted token is served");
        assert_eq!(token, "minted-token");
        assert!(updated.is_none(), "nothing to persist on a cache hit");
        assert_eq!(hits.lock().unwrap().len(), 1, "no second mint");
    }

    /// A cached token inside the refresh margin is replaced, not served.
    #[tokio::test]
    async fn service_account_token_replaces_a_token_inside_the_refresh_margin() {
        let (endpoint, hits) = minting_endpoint().await;
        let credential = service_account_credential(
            &[SHEETS],
            Some("nearly-expired"),
            Some(Utc::now() + Duration::seconds(REFRESH_MARGIN_SECS - 1)),
        );
        let (_effective, updated, token) =
            service_account_token(&loopback_client(), &credential, &endpoint, &[])
                .await
                .expect("a stale token is replaced");
        assert_eq!(token, "minted-token");
        assert!(updated.is_some());
        assert_eq!(hits.lock().unwrap().len(), 1);
    }

    /// A credential whose scopes do not cover the caller's need is refused
    /// before any token is served or minted, including a fresh cached one.
    #[tokio::test]
    async fn service_account_token_refuses_a_scope_the_caller_needs_but_the_credential_lacks() {
        let (endpoint, hits) = minting_endpoint().await;
        let client = loopback_client();
        for credential in [
            service_account_credential(&[CALENDAR], None, None),
            service_account_credential(
                &[CALENDAR],
                Some("cached-calendar-token"),
                Some(Utc::now() + Duration::seconds(3000)),
            ),
            service_account_credential(&[SHEETS_READONLY], None, None),
        ] {
            let error = service_account_token(&client, &credential, &endpoint, &[SHEETS])
                .await
                .expect_err("a scope mismatch fails closed");
            assert!(
                matches!(&error, PluginError::InvalidParams(m) if m.contains("do not cover")),
                "{error}"
            );
            assert!(!error.to_string().contains("cached-calendar-token"));
        }
        assert!(
            hits.lock().unwrap().is_empty(),
            "no mint on a scope refusal"
        );

        // Any one of the accepted scopes suffices.
        let readonly = service_account_credential(&[SHEETS_READONLY], None, None);
        service_account_token(&client, &readonly, &endpoint, &[SHEETS, SHEETS_READONLY])
            .await
            .expect("a read-only credential covers a read");
    }

    /// Use-time re-validation runs before the scope check and the cache, so a
    /// widened vault record is refused even with a fresh cached token.
    #[tokio::test]
    async fn service_account_token_revalidates_before_serving_the_cache() {
        let (endpoint, hits) = minting_endpoint().await;
        let mut credential = service_account_credential(
            &[SHEETS],
            Some("cached"),
            Some(Utc::now() + Duration::seconds(3000)),
        );
        if let CredentialData::GoogleServiceAccount { scopes, .. } = &mut credential.data {
            scopes.push("https://www.googleapis.com/auth/drive".into());
        }
        let error = service_account_token(&loopback_client(), &credential, &endpoint, &[SHEETS])
            .await
            .expect_err("a scope outside the allowlist is refused");
        assert!(error.to_string().contains("allowlist"), "{error}");
        assert!(hits.lock().unwrap().is_empty());
    }

    /// A refused mint surfaces only the status to the caller.
    #[tokio::test]
    async fn service_account_token_surfaces_a_refused_mint_as_status_only() {
        let (url, _hits) = recording_token_server(400, json!({"error": "invalid_grant"})).await;
        let credential = service_account_credential(&[SHEETS], None, None);
        let error = service_account_token(
            &loopback_client(),
            &credential,
            &Url::parse(&url).unwrap(),
            &[SHEETS],
        )
        .await
        .expect_err("a 400 fails the call");
        assert!(error.to_string().contains("HTTP 400"), "{error}");
    }

    #[tokio::test]
    async fn service_account_token_refuses_other_credential_types() {
        let credential = Credential::new(
            "k".into(),
            CredentialData::ApiKey {
                key: Secret::new("k"),
                header_name: "Authorization".into(),
                header_prefix: "Bearer ".into(),
            },
        );
        let error = service_account_token(
            &loopback_client(),
            &credential,
            &Url::parse(GOOGLE_TOKEN_URI).unwrap(),
            &[],
        )
        .await
        .expect_err("not a service account");
        assert!(matches!(error, PluginError::UnsupportedCredentialType(_)));
    }
}
