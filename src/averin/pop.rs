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
pub const GRANT_POP_TAG_V2: &str = "averin.broker.pop.v2";
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
        // ed25519-dalek v2 pins rand_core 0.6; fill via rand 0.10 SysRng then from_bytes.
        use rand::TryRng;
        let mut secret = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut secret)
            .expect("SysRng failure");
        let signing = SigningKey::from_bytes(&secret);
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

/// The `uint32_be` length prefix of `LP`, or `None` when `n` does not fit in 32 bits.
/// A truncating cast here would frame a 2^32 + k byte field as a k byte one, so two
/// different field sequences could share a preimage (VUL-15).
fn lp_len(n: usize) -> Option<u32> {
    u32::try_from(n).ok()
}

/// Append `LP(b) = uint32_be(len(b)) ‖ b` (RCP §9 length-prefix); a field of 2^32 bytes
/// or more is refused, never framed with a truncated length.
fn lp(out: &mut Vec<u8>, b: &[u8]) -> Result<(), PopError> {
    let len = lp_len(b.len()).ok_or(PopError::LpFieldTooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// Fully resolved brokered issuance subject. `issued_at`/`request_expires_at`
/// form a separate freshness envelope; a retry may refresh them only while all
/// semantic fields (including the idempotency key) remain identical.
pub struct GrantRequestV2<'a> {
    pub project_id: &'a str,
    pub idempotency_key: &'a str,
    pub session_id: &'a str,
    pub agent_id: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub scope: &'a str,
    pub scope_class: &'a str,
    pub agent_pubkey: &'a str,
    pub principal: &'a str,
    pub justification: &'a str,
    pub use_limit: i64,
    pub ttl_seconds: i64,
    pub delegation_chain: &'a [&'a str],
    pub issued_at: i64,
    pub request_expires_at: i64,
}

fn checked_lp4_len(n: u64) -> Result<u32, PopError> {
    u32::try_from(n).map_err(|_| PopError::GrantFieldTooLong)
}

fn lp_v2(out: &mut Vec<u8>, b: &[u8]) -> Result<(), PopError> {
    let len = checked_lp4_len(b.len() as u64)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

// This is the production framing path. The local Lean vector test compares the
// encoded bytes directly, so field and framing differences are easy to diagnose.
fn grant_preimage_v2(r: &GrantRequestV2<'_>) -> Result<Vec<u8>, PopError> {
    let mut b = Vec::new();
    for s in [
        GRANT_POP_TAG_V2,
        r.project_id,
        r.idempotency_key,
        r.session_id,
        r.agent_id,
        r.action,
        r.resource,
        r.scope,
        r.scope_class,
        r.agent_pubkey,
        r.principal,
        r.justification,
        "capability",
    ] {
        lp_v2(&mut b, s.as_bytes())?;
    }
    b.extend_from_slice(&r.use_limit.to_be_bytes());
    b.extend_from_slice(&r.ttl_seconds.to_be_bytes());
    let chain_len =
        i64::try_from(r.delegation_chain.len()).map_err(|_| PopError::GrantFieldTooLong)?;
    b.extend_from_slice(&chain_len.to_be_bytes());
    for s in r.delegation_chain {
        lp_v2(&mut b, s.as_bytes())?;
    }
    b.extend_from_slice(&r.issued_at.to_be_bytes());
    b.extend_from_slice(&r.request_expires_at.to_be_bytes());
    Ok(b)
}

pub fn grant_challenge_v2(r: &GrantRequestV2<'_>) -> Result<[u8; 32], PopError> {
    Ok(Sha256::digest(grant_preimage_v2(r)?).into())
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
) -> Result<[u8; 32], PopError> {
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
        lp(&mut pre, part.as_bytes())?;
    }
    Ok(Sha256::digest(&pre).into())
}

/// The params hiding commitment (`core/src/commit.rs`):
/// `"sha256:" + hex( SHA256( LP("averin.commit.v1") ‖ LP("input") ‖ LP(nonce32) ‖ LP(value) ) )`,
/// where `nonce32` is the hex-decoded `params_nonce` (64 lowercase hex chars =
/// 32 bytes) and `value` is the raw `params` bytes.
pub fn params_commitment(params: &[u8], params_nonce_hex: &str) -> Result<String, PopError> {
    // Exactly 64 LOWERCASE hex characters, as averin's FFI requires (hex::decode alone also
    // accepts uppercase, which averin would refuse after vultrino signed over it).
    if params_nonce_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(PopError::BadParamsNonce);
    }
    let nonce = hex::decode(params_nonce_hex).map_err(|_| PopError::BadParamsNonce)?;
    if nonce.len() != 32 {
        return Err(PopError::BadParamsNonce);
    }
    let mut pre = Vec::new();
    lp(&mut pre, COMMIT_TAG.as_bytes())?;
    lp(&mut pre, COMMIT_DOMAIN_INPUT.as_bytes())?;
    lp(&mut pre, &nonce)?;
    lp(&mut pre, params)?;
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
    use rand::TryRng;
    let mut b = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut b)
        .expect("SysRng failure");
    hex::encode(b)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PopError {
    #[error("params_nonce must be 64 lowercase hex chars (32 bytes)")]
    BadParamsNonce,
    #[error("malformed capability token (want <payload>.<sig>)")]
    MalformedCapability,
    #[error("grant PoP v2 field exceeds the 32-bit length framing limit")]
    GrantFieldTooLong,
    #[error("PoP field exceeds the 32-bit length framing limit")]
    LpFieldTooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors copied verbatim from
    // averin/spec/golden-vectors/broker-preimages.json ("use_pop_challenge").
    // A byte drift in the LP4 digest breaks this test.
    #[test]
    fn use_pop_challenge_ascii_matches_golden() {
        let d = use_pop_challenge("g", "r", "a", "pc", "cb", "n").unwrap();
        assert_eq!(
            hex::encode(d),
            "ea55b822189110918d850f1b64582311c844fd75b8e3ee6cbe9ff509b4c40a1d"
        );
    }

    #[test]
    fn use_pop_challenge_multibyte_matches_golden() {
        let d = use_pop_challenge("café", "資源", "🔑", "pc", "cb", "n").unwrap();
        assert_eq!(
            hex::encode(d),
            "3f274a9c975514017ea1e324db94dc1fc018ded8bd733e26eddd113250672889"
        );
    }

    #[test]
    fn grant_challenge_is_sorted_key_compact_json() {
        // Exactly what Go's sorted-map json.Marshal emits: alphabetical keys, no spaces.
        let c = grant_challenge(
            "db.query:orders-ro",
            "agent-1",
            "AAAA",
            "orders-db",
            "read:orders",
        );
        assert_eq!(
            String::from_utf8(c).unwrap(),
            r#"{"action":"db.query:orders-ro","agent_id":"agent-1","agent_pubkey":"AAAA","resource":"orders-db","scope":"read:orders","tag":"averin.broker.pop.v1"}"#
        );
    }

    #[test]
    fn grant_challenge_v2_matches_averin_shared_vector() {
        // averin/spec/golden-vectors/broker-preimages.json: grant_pop_v2[0].
        let request = GrantRequestV2 {
            project_id: "p1",
            idempotency_key: "idem-1",
            session_id: "s1",
            agent_id: "agent-1",
            action: "db.query:orders-ro",
            resource: "orders-db",
            scope: "read:orders",
            scope_class: "single_operation",
            agent_pubkey: "AAAA",
            principal: "",
            justification: "",
            use_limit: 0,
            ttl_seconds: 300,
            delegation_chain: &[],
            issued_at: 1718445000,
            request_expires_at: 1718445900,
        };
        // averin/formal/oracle/expected.json, family "grant PoP v2": the
        // framed bytes, not merely their digest, match the production signer.
        assert_eq!(
            hex::encode(grant_preimage_v2(&request).unwrap()),
            "0000001461766572696e2e62726f6b65722e706f702e7632000000027031000000066964656d2d31000000027331000000076167656e742d310000001264622e71756572793a6f72646572732d726f000000096f72646572732d64620000000b726561643a6f72646572730000001073696e676c655f6f7065726174696f6e000000044141414100000000000000000000000a6361706162696c6974790000000000000000000000000000012c000000000000000000000000666d63c800000000666d674c"
        );
        let c = grant_challenge_v2(&request).unwrap();
        assert_eq!(
            hex::encode(c),
            "20809965afd8dd263d5f02afb1461cdce5a8cb7adf1187ba0feb43a46b48fe94"
        );
    }

    #[test]
    fn grant_challenge_v2_multihop_unicode_matches_lean_vector() {
        // averin/formal/oracle/expected.json, second "grant PoP v2" row;
        // averin/spec/golden-vectors/broker-preimages.json, grant_pop_v2[1].
        let request = GrantRequestV2 {
            project_id: "p-équipe",
            idempotency_key: "idem-2",
            session_id: "s2",
            agent_id: "agent-2",
            action: "db.query:orders-ro",
            resource: "orders-db",
            scope: "read:café",
            scope_class: "bounded_reuse",
            agent_pubkey: "AAAA",
            principal: "acct:café",
            justification: "approved by Zoë",
            use_limit: 7,
            ttl_seconds: 120,
            delegation_chain: &["delegate:α", "delegate:東京"],
            issued_at: 1718445000,
            request_expires_at: 1718445900,
        };
        assert_eq!(
            hex::encode(grant_preimage_v2(&request).unwrap()),
            "0000001461766572696e2e62726f6b65722e706f702e763200000009702dc3a97175697065000000066964656d2d32000000027332000000076167656e742d320000001264622e71756572793a6f72646572732d726f000000096f72646572732d64620000000a726561643a636166c3a90000000d626f756e6465645f726575736500000004414141410000000a616363743a636166c3a900000010617070726f766564206279205a6fc3ab0000000a6361706162696c6974790000000000000007000000000000007800000000000000020000000b64656c65676174653aceb10000000f64656c65676174653ae69db1e4baac00000000666d63c800000000666d674c"
        );
        assert_eq!(
            hex::encode(grant_challenge_v2(&request).unwrap()),
            "4b134bc82d3d5bce854c3c63e4f6e85f50f5aad710e8fefded9ea303cf5f7ce1"
        );
    }

    #[test]
    fn grant_pop_v2_rejects_truncating_length_frame() {
        assert_eq!(checked_lp4_len(u32::MAX as u64), Ok(u32::MAX));
        assert_eq!(
            checked_lp4_len(u32::MAX as u64 + 1),
            Err(PopError::GrantFieldTooLong)
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

    /// VUL-15: the length prefix is exact or refused. Every length that fits in 32 bits
    /// frames as itself; every length that does not is refused, never wrapped to
    /// `n mod 2^32` (a 2^32 + k byte field would otherwise frame as a k byte one).
    #[test]
    fn lp_length_prefix_is_exact_or_refused() {
        let max = u32::MAX as u64;
        for n in [0u64, 1, 2, 255, 256, 65_535, 65_536, max - 1, max] {
            assert_eq!(lp_len(n as usize), Some(n as u32), "{n}");
        }
        #[cfg(target_pointer_width = "64")]
        for n in [
            max + 1,
            max + 2,
            2 * (max + 1),
            (max + 1) + 5,
            u64::MAX / 2,
            usize::MAX as u64,
        ] {
            assert_eq!(lp_len(n as usize), None, "{n} must be refused, not wrapped");
        }
        // The framing itself: prefix is the big-endian length, then the bytes.
        let mut out = Vec::new();
        lp(&mut out, b"abc").unwrap();
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    /// Cross-language golden vectors for `params_commitment`: vendored from averin
    /// (vectors/params-commitment.v1.json, pinned in vectors.lock, produced by an
    /// independent Python reference). Every `input` entry must reproduce; every
    /// rejected nonce string must be refused.
    #[test]
    fn params_commitment_matches_the_cross_language_golden_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("vectors")
            .join("params-commitment.v1.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut checked = 0;
        for c in v["vectors"].as_array().unwrap() {
            if c["domain"] != "input" {
                continue; // vultrino only ever commits under the input domain
            }
            let value = hex::decode(c["value_hex"].as_str().unwrap()).unwrap();
            let got = params_commitment(&value, c["nonce_hex"].as_str().unwrap()).unwrap();
            assert_eq!(got, c["expect"].as_str().unwrap(), "{}", c["id"]);
            checked += 1;
        }
        assert!(checked >= 8, "too few input vectors: {checked}");
        let rejects = v["reject_nonce_hex"].as_array().unwrap();
        assert!(rejects.len() >= 8);
        for r in rejects {
            assert_eq!(
                params_commitment(b"x", r["nonce_hex"].as_str().unwrap()),
                Err(PopError::BadParamsNonce),
                "{}",
                r["id"]
            );
        }
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
