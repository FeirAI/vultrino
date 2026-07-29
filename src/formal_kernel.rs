//! Pure enforcement kernel mirrored by `formal/lean/Vultrino`.
//!
//! This module contains no I/O, async, locks, globals, or unsafe code. It is the
//! small Rust surface intended for translation/refinement checking. The Tokio
//! adapter is responsible only for deriving these values from authenticated
//! state and linearizing the durable claim.

use sha2::{Digest, Sha256};

/// Every execution-relevant field an approval or direct decision authorizes.
/// Equality is the refinement obligation at the side-effect boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBinding {
    pub approval_id: String,
    pub epoch: u64,
    pub tenant: String,
    pub principal: String,
    pub credential: String,
    pub action: String,
    pub params_digest: String,
    pub rule_digest: String,
}

impl ExecutionBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        approval_id: impl Into<String>,
        epoch: u64,
        tenant: impl Into<String>,
        principal: impl Into<String>,
        credential: impl Into<String>,
        action: impl Into<String>,
        params_digest: impl Into<String>,
        rule_digest: impl Into<String>,
    ) -> Self {
        Self {
            approval_id: approval_id.into(),
            epoch,
            tenant: tenant.into(),
            principal: principal.into(),
            credential: credential.into(),
            action: action.into(),
            params_digest: params_digest.into(),
            rule_digest: rule_digest.into(),
        }
    }
}

/// Exact SHA-256 digest of the bytes the adapter presents to the kernel.
/// Canonicalization is deliberately outside this function and must be shared by
/// the producer/consumer adapter; collision resistance remains a TCB assumption.
pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Advance the durable one-shot fence without wraparound.
pub(crate) fn next_epoch(current: u64) -> Option<u64> {
    current.checked_add(1)
}

/// Why an execution permit exists. Private so possession, not inspection, is
/// the authority consumed at dispatch.
#[derive(Debug)]
#[allow(dead_code)] // carried as the consumed proof object, never a decision input
enum PermitBasis {
    Direct,
    Approved(Box<crate::approval::Granted>),
}

/// The only authority accepted by a side-effecting plugin dispatch.
///
/// It has no public constructor and is neither `Clone`, `Copy`, `Default`, nor
/// deserializable. An approved permit consumes the persisted grant witness.
#[derive(Debug)]
#[must_use = "dropping an ExecutionPermit discards the authority to execute"]
pub(crate) struct ExecutionPermit {
    binding: ExecutionBinding,
    #[allow(dead_code)] // possession/consumption is the invariant
    basis: PermitBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PermitError {
    PolicyDenied,
    ApprovalRequired,
    ApprovalNotRequired,
    BindingMismatch,
    GrantNotYetIssued,
    GrantExpired,
}

impl ExecutionPermit {
    /// Mint authority for the effective-policy allow path only.
    pub(crate) fn direct(
        binding: ExecutionBinding,
        policy_allows: bool,
        approval_required: bool,
    ) -> Result<Self, PermitError> {
        if !policy_allows {
            return Err(PermitError::PolicyDenied);
        }
        if approval_required {
            return Err(PermitError::ApprovalRequired);
        }
        Ok(Self {
            binding,
            basis: PermitBasis::Direct,
        })
    }

    /// Mint authority for an approval-required request by consuming evidence
    /// re-derived from the persisted record under the durable claim lock.
    pub(crate) fn approved(
        binding: ExecutionBinding,
        policy_allows: bool,
        approval_required: bool,
        grant: crate::approval::Granted,
        now_unix_seconds: i64,
    ) -> Result<Self, PermitError> {
        if !policy_allows {
            return Err(PermitError::PolicyDenied);
        }
        if !approval_required {
            return Err(PermitError::ApprovalNotRequired);
        }
        if grant.binding() != &binding {
            return Err(PermitError::BindingMismatch);
        }
        if now_unix_seconds < grant.issued_at_unix_seconds() {
            return Err(PermitError::GrantNotYetIssued);
        }
        if now_unix_seconds >= grant.expires_at_unix_seconds() {
            return Err(PermitError::GrantExpired);
        }
        Ok(Self {
            binding,
            basis: PermitBasis::Approved(Box::new(grant)),
        })
    }

    /// Bind the permit to the exact dispatch payload. The returned wrapper has
    /// no public constructor, preventing field substitution after authorization.
    pub(crate) fn authorize<T>(
        self,
        actual: &ExecutionBinding,
        payload: T,
    ) -> Result<Authorized<T>, PermitError> {
        if &self.binding != actual {
            return Err(PermitError::BindingMismatch);
        }
        Ok(Authorized {
            payload,
            _permit: self,
        })
    }
}

/// A payload paired with and protected by one non-cloneable permit.
#[derive(Debug)]
pub(crate) struct Authorized<T> {
    payload: T,
    _permit: ExecutionPermit,
}

impl<T> Authorized<T> {
    pub(crate) fn payload(&self) -> &T {
        &self.payload
    }

    /// Consumes the permit and payload together at the side-effect seam.
    pub(crate) fn into_payload(self) -> T {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(action: &str) -> ExecutionBinding {
        ExecutionBinding::new(
            "direct:req-1",
            0,
            "tenant-a",
            "agent-a",
            "credential-a",
            action,
            digest_bytes(b"{}"),
            digest_bytes(b"direct"),
        )
    }

    #[test]
    fn direct_permit_refuses_deny_and_approval_required() {
        assert_eq!(
            ExecutionPermit::direct(binding("http.get"), false, false).unwrap_err(),
            PermitError::PolicyDenied
        );
        assert_eq!(
            ExecutionPermit::direct(binding("http.get"), true, true).unwrap_err(),
            PermitError::ApprovalRequired
        );
    }

    #[test]
    fn exact_binding_prevents_action_substitution() {
        let expected = binding("payments.refund");
        let permit = ExecutionPermit::direct(expected.clone(), true, false).unwrap();
        let substituted = binding("payments.charge");
        assert_eq!(
            permit.authorize(&substituted, ()).unwrap_err(),
            PermitError::BindingMismatch
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn fixed_binding() -> ExecutionBinding {
        ExecutionBinding::new("direct:r", 0, "t", "p", "c", "a", "pd", "rd")
    }

    #[kani::proof]
    fn direct_permit_truth_table_is_exact() {
        let policy_allows: bool = kani::any();
        let approval_required: bool = kani::any();
        let admitted =
            ExecutionPermit::direct(fixed_binding(), policy_allows, approval_required).is_ok();
        assert_eq!(admitted, policy_allows && !approval_required);
    }

    #[kani::proof]
    fn execution_epoch_never_wraps() {
        let current: u64 = kani::any();
        match next_epoch(current) {
            Some(next) => assert!(next > current),
            None => assert_eq!(current, u64::MAX),
        }
    }
}
