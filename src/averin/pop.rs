//! Byte-exact reproduction of averin's broker/resource proof-of-possession (PoP)
//! preimages, so vultrino's seal-client can present a valid `agent_sig` (grant)
//! and `use_sig` (use) to a real averin `/v2/grants` + `/v2/use`.
//!
//! This is a cross-language binding. averin keeps the canonical vectors in
//! `averin/spec/golden-vectors/broker-preimages.json`; the `use_pop_challenge`
//! cases are reproduced verbatim in the tests below so a byte drift on the LP4
//! digest fails here (fast) before it fails as an averin 400 in the e2e.
//!
//! The seal-client holds the ONLY non-averin key in the flow: an ephemeral agent
//! Ed25519 keypair (the capability's `cnf`). averin's three recording keys stay
//! disjoint and never leave averin (see `docs/dev/averin-sealing.md` §1).

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// averin domain tags (RCP §9.2 / ADR 0003/0004). Must match averin verbatim:
/// `server/internal/broker/broker.go` and `server/internal/resourceshim/resourceshim.go`.
pub const GRANT_POP_TAG: &str = "averin.broker.pop.v1";
pub const USE_POP_TAG: &str = "averin.broker.use.pop.v1";
pub const COMMIT_TAG: &str = "averin.commit.v1";
pub const COMMIT_DOMAIN_INPUT: &str = "input";

/// An ephemeral agent PoP keypair. vultrino generates one per grant, proves
/// possession of it in the grant (`agent_sig`), and re-proves it at each use
/// (`use_sig`). This is the sender constraint — averin binds the pubkey's kid as
/// the capability's `cnf`. The private half never leaves vultrino; it is not an
/// averin key.
pub struct PopKeypair {
    signing: SigningKey,
}

impl PopKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        // rand 0.8 OsRng implements the rand_core 0.6 traits ed25519-dalek v2 uses.
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        Self { signing }
    }

    /// base64url-no-pad of the raw 32-byte public key — the wire `agent_pubkey`.
    pub fn agent_pubkey_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    /// Sign an arbitrary message, returning base64url-no-pad of the raw 64-byte
    /// signature (the wire encoding averin decodes for `agent_sig` / `use_sig`).
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.signing.sign(msg).to_bytes())
    }

    /// Reconstruct a keypair from its 32-byte Ed25519 seed (`SigningKey::from_bytes`) — the
    /// durable PoP-key store round-trip (plan 088 D2): the store persists ONLY this seed (never
    /// derived nonce/scalar state), and this reconstructs a fully-usable signing keypair from it
    /// after a restart.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte Ed25519 seed (`SigningKey::to_bytes`) — the ONLY bytes the durable PoP-key
    /// store persists (plan 088 D2's `pop_seed` field). Round-trips through
    /// [`Self::from_seed_bytes`] byte-for-byte.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }
}

/// Append `LP(b) = uint32_be(len(b)) ‖ b` (RCP §9 length-prefix).
fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// The grant PoP challenge bytes `agent_sig` signs. Byte-identical to Go's
/// sorted-key `json.Marshal(map[string]any{...})` in `broker.Request.Challenge`:
/// the six keys emit in alphabetical order with no whitespace. We use a struct
/// whose fields are DECLARED alphabetically so serde emits the same order; every
/// value here is ASCII (dotted action/scope, base64url pubkey), so serde's
/// non-HTML-escaping output matches Go's byte-for-byte.
pub fn grant_challenge(
    action: &str,
    agent_id: &str,
    agent_pubkey_b64: &str,
    resource: &str,
    scope: &str,
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Challenge<'a> {
        action: &'a str,
        agent_id: &'a str,
        agent_pubkey: &'a str,
        resource: &'a str,
        scope: &'a str,
        tag: &'a str,
    }
    serde_json::to_vec(&Challenge {
        action,
        agent_id,
        agent_pubkey: agent_pubkey_b64,
        resource,
        scope,
        tag: GRANT_POP_TAG,
    })
    .expect("challenge serialization is infallible for &str fields")
}

/// The 32-byte use PoP digest `use_sig` signs (`resourceshim.usePoPChallenge`):
/// `SHA256( LP(tag) ‖ LP(grant_id) ‖ LP(resource_id) ‖ LP(action) ‖
/// LP(params_commitment) ‖ LP(credential_binding) ‖ LP(nonce) )`.
pub fn use_pop_challenge(
    grant_id: &str,
    resource_id: &str,
    action: &str,
    params_commitment: &str,
    credential_binding: &str,
    nonce: &str,
) -> [u8; 32] {
    let mut pre = Vec::new();
    for part in [
        USE_POP_TAG,
        grant_id,
        resource_id,
        action,
        params_commitment,
        credential_binding,
        nonce,
    ] {
        lp(&mut pre, part.as_bytes());
    }
    Sha256::digest(&pre).into()
}

/// The params hiding commitment (`core/src/commit.rs`):
/// `"sha256:" + hex( SHA256( LP("averin.commit.v1") ‖ LP("input") ‖ LP(nonce32) ‖ LP(value) ) )`,
/// where `nonce32` is the hex-decoded `params_nonce` (64 lowercase hex chars =
/// 32 bytes) and `value` is the raw `params` bytes.
pub fn params_commitment(params: &[u8], params_nonce_hex: &str) -> Result<String, PopError> {
    let nonce = hex::decode(params_nonce_hex).map_err(|_| PopError::BadParamsNonce)?;
    if nonce.len() != 32 {
        return Err(PopError::BadParamsNonce);
    }
    let mut pre = Vec::new();
    lp(&mut pre, COMMIT_TAG.as_bytes());
    lp(&mut pre, COMMIT_DOMAIN_INPUT.as_bytes());
    lp(&mut pre, &nonce);
    lp(&mut pre, params);
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&pre))))
}

/// The credential binding (`resourceshim.credentialBinding`):
/// `"sha256:" + hex( SHA256( base64url_decode(payload) ) )`, where `payload` is
/// the part of the capability token before the first `.`.
pub fn credential_binding(capability: &str) -> Result<String, PopError> {
    let payload_enc = capability
        .split_once('.')
        .map(|(p, _)| p)
        .ok_or(PopError::MalformedCapability)?;
    let payload = B64
        .decode(payload_enc)
        .map_err(|_| PopError::MalformedCapability)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&payload))))
}

/// A 64-lowercase-hex random `params_nonce` for the hiding commitment.
pub fn random_params_nonce_hex() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PopError {
    #[error("params_nonce must be 64 lowercase hex chars (32 bytes)")]
    BadParamsNonce,
    #[error("malformed capability token (want <payload>.<sig>)")]
    MalformedCapability,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors copied verbatim from
    // averin/spec/golden-vectors/broker-preimages.json ("use_pop_challenge").
    // A byte drift in the LP4 digest breaks this test.
    #[test]
    fn use_pop_challenge_ascii_matches_golden() {
        let d = use_pop_challenge("g", "r", "a", "pc", "cb", "n");
        assert_eq!(
            hex::encode(d),
            "ea55b822189110918d850f1b64582311c844fd75b8e3ee6cbe9ff509b4c40a1d"
        );
    }

    #[test]
    fn use_pop_challenge_multibyte_matches_golden() {
        let d = use_pop_challenge("café", "資源", "🔑", "pc", "cb", "n");
        assert_eq!(
            hex::encode(d),
            "3f274a9c975514017ea1e324db94dc1fc018ded8bd733e26eddd113250672889"
        );
    }

    #[test]
    fn grant_challenge_is_sorted_key_compact_json() {
        // Exactly what Go's sorted-map json.Marshal emits: alphabetical keys, no spaces.
        let c = grant_challenge("db.query:orders-ro", "agent-1", "AAAA", "orders-db", "read:orders");
        assert_eq!(
            String::from_utf8(c).unwrap(),
            r#"{"action":"db.query:orders-ro","agent_id":"agent-1","agent_pubkey":"AAAA","resource":"orders-db","scope":"read:orders","tag":"averin.broker.pop.v1"}"#
        );
    }

    #[test]
    fn params_commitment_is_prefixed_and_stable() {
        let nonce = "ab".repeat(32); // 64 hex chars
        let c = params_commitment(b"{\"q\":1}", &nonce).unwrap();
        assert!(c.starts_with("sha256:"));
        assert_eq!(c.len(), "sha256:".len() + 64);
        // deterministic
        assert_eq!(c, params_commitment(b"{\"q\":1}", &nonce).unwrap());
    }

    #[test]
    fn params_commitment_rejects_bad_nonce() {
        assert_eq!(
            params_commitment(b"x", "notlongenough"),
            Err(PopError::BadParamsNonce)
        );
    }

    #[test]
    fn credential_binding_splits_and_hashes_payload() {
        // payload "AAAA" (base64url) -> bytes 0x00 0x00 0x00; binding is sha256 of those.
        let b = credential_binding("AAAA.SIGNATURE").unwrap();
        assert_eq!(
            b,
            format!("sha256:{}", hex::encode(Sha256::digest([0u8, 0, 0])))
        );
        assert_eq!(
            credential_binding("nodothere"),
            Err(PopError::MalformedCapability)
        );
    }

    #[test]
    fn keypair_signs_and_pubkey_is_32_bytes_b64() {
        let kp = PopKeypair::generate();
        let pk = kp.agent_pubkey_b64();
        assert_eq!(B64.decode(&pk).unwrap().len(), 32);
        let sig = kp.sign_b64(b"hello");
        assert_eq!(B64.decode(&sig).unwrap().len(), 64);
    }

    #[test]
    fn from_seed_bytes_round_trips_and_signs_deterministically() {
        // plan 088 D2/Step 2: the durable PoP-key store persists ONLY `seed_bytes()`. This
        // asserts the round trip through `from_seed_bytes` reconstructs a keypair that (a) has
        // the SAME public key and (b) signs BYTE-IDENTICALLY to the original — RFC 8032 Ed25519
        // signing is deterministic (same seed + same message -> same signature), which is
        // load-bearing for D5's deterministic retry (a durable-worker retry after a restart must
        // reproduce the exact `use_sig` averin already recorded, or an honest retry would 409 as
        // a mismatched operation).
        let kp = PopKeypair::generate();
        let seed = kp.seed_bytes();
        let rebuilt = PopKeypair::from_seed_bytes(&seed);

        assert_eq!(
            kp.agent_pubkey_b64(),
            rebuilt.agent_pubkey_b64(),
            "the reconstructed keypair must have the SAME public key"
        );

        let msg = b"averin durable pop seed round-trip";
        let sig_original = kp.sign_b64(msg);
        let sig_rebuilt_1 = rebuilt.sign_b64(msg);
        let sig_rebuilt_2 = rebuilt.sign_b64(msg);

        assert_eq!(
            sig_original, sig_rebuilt_1,
            "a keypair rebuilt from the seed signs BYTE-IDENTICALLY to the original (RFC 8032)"
        );
        assert_eq!(
            sig_rebuilt_1, sig_rebuilt_2,
            "signing the same message twice with the same (rebuilt) key is deterministic"
        );

        // Round-trip the seed itself, twice removed, to be thorough: seed -> keypair -> seed.
        assert_eq!(
            rebuilt.seed_bytes(),
            seed,
            "seed_bytes(from_seed_bytes(seed)) must reproduce the original seed exactly"
        );
    }
}
