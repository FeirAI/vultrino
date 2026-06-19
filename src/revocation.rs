//! Downstream credential **revoke-propagation** (R5 / V7 AC criterion 3).
//!
//! Blocking/redacting an egress response stops an agent reading a downstream
//! secret, but a credential revoke historically did **not** revoke a secret the
//! downstream provider already issued — it was left to expire. This module closes
//! that: for a credential type that exposes a resource-side revocation endpoint
//! (OAuth2 / STS, RFC 7009), deleting the credential actively revokes its issued
//! access/refresh token at the provider.
//!
//! The revocation HTTP call goes through a [`RevocationClient`] trait so it is
//! testable past the http plugin's SSRF guard (the default [`HttpRevocationClient`]
//! still requires an HTTPS endpoint).

use crate::storage::StorageBackend;
use crate::{Credential, CredentialData};
use async_trait::async_trait;

/// Calls a resource-side token revocation endpoint (RFC 7009). Abstracted so the
/// propagation path is unit-testable without real network / SSRF constraints.
#[async_trait]
pub trait RevocationClient: Send + Sync {
    /// Revoke a single token. `token_type_hint` is `access_token` or
    /// `refresh_token`. Best-effort: returns `Err` on any failure (the caller
    /// logs and continues — a failed propagation must not block the local delete).
    async fn revoke(
        &self,
        revocation_url: &str,
        token: &str,
        token_type_hint: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), String>;
}

/// Default [`RevocationClient`]: POSTs an RFC 7009 revocation request over HTTPS.
pub struct HttpRevocationClient {
    client: reqwest::Client,
}

impl HttpRevocationClient {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

impl Default for HttpRevocationClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RevocationClient for HttpRevocationClient {
    async fn revoke(
        &self,
        revocation_url: &str,
        token: &str,
        token_type_hint: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(), String> {
        // The revocation endpoint is operator-configured (credential metadata),
        // not agent-controlled, but require HTTPS so the token isn't sent in clear.
        let url = url::Url::parse(revocation_url).map_err(|e| format!("invalid revocation_url: {e}"))?;
        if url.scheme() != "https" {
            return Err("revocation_url must be https".to_string());
        }
        let resp = self
            .client
            .post(url)
            .form(&[
                ("token", token),
                ("token_type_hint", token_type_hint),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .map_err(|e| format!("revocation request failed: {e}"))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("revocation endpoint returned {}", resp.status()))
        }
    }
}

/// Metadata key holding a credential's resource-side token revocation endpoint.
pub const REVOCATION_URL_META: &str = "revocation_url";

/// Propagate a credential revoke to the resource side (R5/V7). For an OAuth2
/// credential carrying a non-empty `revocation_url` metadata key, call the
/// revocation endpoint for each issued token (access then refresh), then emit a
/// `credential.revoked` event recording what was propagated. Best-effort and
/// non-fatal: a failed revoke is logged and never blocks the local delete.
pub async fn propagate_revoke(
    client: &dyn RevocationClient,
    storage: &dyn StorageBackend,
    cred: &Credential,
) {
    let Some(url) = cred
        .metadata
        .get(REVOCATION_URL_META)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let CredentialData::OAuth2 {
        client_id,
        client_secret,
        access_token,
        refresh_token,
        ..
    } = &cred.data
    else {
        return;
    };

    let mut revoked: Vec<&str> = Vec::new();
    for (token, hint) in [
        (access_token.as_ref(), "access_token"),
        (refresh_token.as_ref(), "refresh_token"),
    ] {
        let Some(token) = token else { continue };
        match client
            .revoke(url, token.expose(), hint, client_id, client_secret.expose())
            .await
        {
            Ok(()) => revoked.push(hint),
            Err(e) => tracing::warn!(
                credential = %cred.alias,
                token_type = hint,
                error = %e,
                "downstream credential revoke-propagation failed (token left to expire)"
            ),
        }
    }

    if !revoked.is_empty() {
        if let Err(e) = storage
            .append_event(
                &cred.alias,
                crate::outbox::EVENT_CREDENTIAL_REVOKED,
                serde_json::json!({ "credential": cred.alias, "revoked_tokens": revoked }),
            )
            .await
        {
            tracing::warn!(error = %e, "failed to append credential.revoked event");
        }
    }
}
