//! Durable provider-neutral native-draft operation records.
//!
//! These records deliberately have stronger semantics than the admin API's
//! idempotency table: a reservation is never reclaimed or released.  Once a
//! remote create may have started, a crash must remain an ambiguous operation
//! that blocks blind recreation until a human/provider reconciliation resolves
//! it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const MAX_IDENTITY_LEN: usize = 256;
const MAX_PROJECT_LEN: usize = 512;
const MAX_HASH_LEN: usize = 128;
const MAX_TOKEN_LEN: usize = 128;
const MAX_URL_LEN: usize = 2048;
const MAX_ERROR_LEN: usize = 4096;

fn bounded(value: &str, max: usize, field: &'static str) -> Result<(), &'static str> {
    if value.trim().is_empty() {
        return Err(field);
    }
    if value.chars().count() > max {
        return Err(field);
    }
    Ok(())
}

/// Stable identity of one provider-native draft handoff.
///
/// The tenant and project are mandatory because a cross-project or untenant-ed
/// key would make a duplicate mapping an authority/collision boundary.  The
/// target is an operator-pinned alias, not a caller-selected provider ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NativeDraftKey {
    pub tenant: String,
    pub project_ref: String,
    pub provider: String,
    pub target_alias: String,
    pub credential_alias: String,
    pub campaign_id: String,
    pub variant_id: String,
    pub row_version: u64,
}

impl NativeDraftKey {
    /// A deterministic, collision-resistant map key. JSON is generated from a
    /// fixed field order and contains no secrets.
    pub fn storage_key(&self) -> String {
        serde_json::to_string(self).expect("NativeDraftKey is always serializable")
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        for (name, value) in [
            ("tenant", self.tenant.as_str()),
            ("project_ref", self.project_ref.as_str()),
            ("provider", self.provider.as_str()),
            ("target_alias", self.target_alias.as_str()),
            ("credential_alias", self.credential_alias.as_str()),
            ("campaign_id", self.campaign_id.as_str()),
            ("variant_id", self.variant_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(match name {
                    "tenant" => "native draft tenant is blank",
                    "project_ref" => "native draft project_ref is blank",
                    "provider" => "native draft provider is blank",
                    "target_alias" => "native draft target_alias is blank",
                    "credential_alias" => "native draft credential_alias is blank",
                    "campaign_id" => "native draft campaign_id is blank",
                    _ => "native draft variant_id is blank",
                });
            }
            let max = if name == "project_ref" {
                MAX_PROJECT_LEN
            } else {
                MAX_IDENTITY_LEN
            };
            if value.chars().count() > max {
                return Err(match name {
                    "tenant" => "native draft tenant is too long",
                    "project_ref" => "native draft project_ref is too long",
                    "provider" => "native draft provider is too long",
                    "target_alias" => "native draft target_alias is too long",
                    "credential_alias" => "native draft credential_alias is too long",
                    "campaign_id" => "native draft campaign_id is too long",
                    _ => "native draft variant_id is too long",
                });
            }
        }
        if self.row_version == 0 {
            return Err("native draft row_version must be positive");
        }
        Ok(())
    }
}

/// Trusted execution identity captured with the reservation for audit and CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeDraftMetadata {
    pub approval_id: String,
    pub execution_epoch: u64,
    pub principal_id: Option<String>,
    pub agent_label: Option<String>,
    /// Canonical source-row content hash. This is deliberately distinct from
    /// `NativeDraftRecord.payload_hash`, which binds the complete operation
    /// envelope (including pins and row version) for CAS/idempotency.
    pub content_hash: String,
    /// Audit metadata only; credential_alias is the stable key component.
    pub credential_id: String,
}

/// Provider-neutral receipt returned after a confirmed native draft create or
/// a later read/reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftReceipt {
    pub provider: String,
    pub campaign_id: String,
    pub variant_id: String,
    pub row_version: u64,
    pub content_hash: String,
    pub channel_ref: String,
    /// SHA-256 of the exact draft text returned by the provider. This is
    /// intentionally separate from `content_hash`, which is the canonical
    /// row payload hash used to reserve the operation; a provider read does
    /// not have all canonical row fields needed to recompute that hash.
    #[serde(default)]
    pub external_content_hash: Option<String>,
    pub external_id: Option<String>,
    pub external_status: Option<String>,
    pub review_url: Option<String>,
    pub sync_status: DraftSyncStatus,
}

/// Durable local knowledge of the remote operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftSyncStatus {
    /// Reservation exists; the outbound attempt may or may not have happened.
    /// This state is never automatically retried.
    Reserved,
    Succeeded,
    /// Provider rejection was observed. It remains terminal for this key.
    Failed,
    /// The provider outcome or local finalize is ambiguous.
    Unknown,
    /// A read observed native edits/drift; no write is implied.
    Drift,
}

/// One durable operation record. `reservation_token` is the finalize CAS
/// capability and is never accepted from caller parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeDraftRecord {
    pub key: NativeDraftKey,
    pub payload_hash: String,
    pub metadata: NativeDraftMetadata,
    pub reservation_token: String,
    pub status: DraftSyncStatus,
    pub receipt: Option<DraftReceipt>,
    /// Immutable first confirmed provider receipt. `receipt` may later carry
    /// an explicitly recorded observation such as `Drift`; this field keeps
    /// the original create identity for reconciliation/audit.
    #[serde(default)]
    pub original_receipt: Option<DraftReceipt>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl NativeDraftRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.key.validate()?;
        bounded(
            &self.payload_hash,
            MAX_HASH_LEN,
            "native draft payload_hash is invalid",
        )?;
        bounded(
            &self.metadata.approval_id,
            MAX_IDENTITY_LEN,
            "native draft approval identity is invalid",
        )?;
        if self.metadata.execution_epoch == 0 {
            return Err("native draft execution_epoch must be positive");
        }
        if self
            .metadata
            .principal_id
            .as_deref()
            .map(|value| bounded(value, MAX_IDENTITY_LEN, "native draft principal is invalid"))
            .transpose()?
            .is_none()
        {
            return Err("native draft principal identity is missing");
        }
        if let Some(agent) = self.metadata.agent_label.as_deref() {
            bounded(
                agent,
                MAX_IDENTITY_LEN,
                "native draft agent label is invalid",
            )?;
        }
        bounded(
            &self.metadata.credential_id,
            MAX_IDENTITY_LEN,
            "native draft credential identity is invalid",
        )?;
        if self.metadata.content_hash.len() != 64
            || !self
                .metadata
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("native draft canonical content hash is not SHA-256 hex");
        }
        bounded(
            &self.reservation_token,
            MAX_TOKEN_LEN,
            "native draft reservation token is invalid",
        )?;
        if let Some(error) = self.error.as_deref() {
            if error.chars().count() > MAX_ERROR_LEN {
                return Err("native draft error is too long");
            }
        }
        if self.status == DraftSyncStatus::Reserved && self.receipt.is_some() {
            return Err("reserved native draft cannot carry a receipt");
        }
        if let Some(receipt) = &self.receipt {
            validate_receipt(&self.key, &self.metadata.content_hash, self.status, receipt)?;
        }
        if let Some(receipt) = &self.original_receipt {
            validate_receipt(
                &self.key,
                &self.metadata.content_hash,
                receipt.sync_status,
                receipt,
            )?;
        }
        if matches!(
            self.status,
            DraftSyncStatus::Succeeded | DraftSyncStatus::Drift
        ) && self.receipt.is_none()
        {
            return Err("successful/drift native draft lacks a receipt");
        }
        if self.updated_at < self.created_at {
            return Err("native draft timestamps are out of order");
        }
        Ok(())
    }
}

fn validate_receipt(
    key: &NativeDraftKey,
    content_hash: &str,
    outcome: DraftSyncStatus,
    receipt: &DraftReceipt,
) -> Result<(), &'static str> {
    bounded(
        &receipt.provider,
        MAX_IDENTITY_LEN,
        "native draft receipt provider is invalid",
    )?;
    bounded(
        &receipt.campaign_id,
        MAX_IDENTITY_LEN,
        "native draft receipt campaign is invalid",
    )?;
    bounded(
        &receipt.variant_id,
        MAX_IDENTITY_LEN,
        "native draft receipt variant is invalid",
    )?;
    bounded(
        &receipt.channel_ref,
        MAX_IDENTITY_LEN,
        "native draft receipt target is invalid",
    )?;
    bounded(
        &receipt.content_hash,
        MAX_HASH_LEN,
        "native draft receipt content hash is invalid",
    )?;
    if receipt.provider != key.provider
        || receipt.campaign_id != key.campaign_id
        || receipt.variant_id != key.variant_id
        || receipt.row_version != key.row_version
        || receipt.channel_ref != key.target_alias
        || receipt.content_hash != content_hash
    {
        return Err("native draft receipt identity does not match its key");
    }
    if receipt.sync_status != outcome {
        return Err("native draft receipt status does not match record status");
    }
    if let Some(external_id) = receipt.external_id.as_deref() {
        bounded(
            external_id,
            MAX_IDENTITY_LEN,
            "native draft external id is invalid",
        )?;
    }
    if let Some(external_content_hash) = receipt.external_content_hash.as_deref() {
        bounded(
            external_content_hash,
            MAX_HASH_LEN,
            "native draft external content hash is invalid",
        )?;
        if external_content_hash.len() != 64
            || !external_content_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("native draft external content hash is not SHA-256 hex");
        }
    }
    if let Some(external_status) = receipt.external_status.as_deref() {
        bounded(
            external_status,
            MAX_IDENTITY_LEN,
            "native draft external status is invalid",
        )?;
    }
    if let Some(review_url) = receipt.review_url.as_deref() {
        bounded(
            review_url,
            MAX_URL_LEN,
            "native draft review URL is invalid",
        )?;
    }
    if matches!(outcome, DraftSyncStatus::Succeeded | DraftSyncStatus::Drift)
        && (receipt
            .external_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            || receipt
                .external_status
                .as_deref()
                .is_none_or(|value| value.trim().is_empty()))
    {
        return Err("successful/drift native draft receipt lacks provider identity/status");
    }
    if matches!(outcome, DraftSyncStatus::Succeeded | DraftSyncStatus::Drift)
        && receipt
            .external_content_hash
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err("successful/drift native draft receipt lacks provider content digest");
    }
    Ok(())
}

/// Result of the atomic reservation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeDraftReservation {
    /// Caller owns this one operation token and may make one outbound attempt.
    Fresh { record: NativeDraftRecord },
    /// A durable record already exists. The caller must not create remotely.
    Existing { record: NativeDraftRecord },
}

/// Terminal update written by the operation owner. The storage layer binds it
/// to the exact reservation token and payload hash before committing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDraftOutcome {
    pub status: DraftSyncStatus,
    pub receipt: Option<DraftReceipt>,
    pub error: Option<String>,
}
