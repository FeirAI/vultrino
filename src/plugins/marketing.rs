//! Typed marketing connectors.
//!
//! These adapters deliberately do not expose a generic HTTP or GraphQL
//! document tool.  The operator pins the upstream endpoint and identifiers in
//! `Capability.target.plugin_params`; the caller supplies only the typed
//! content fields for the selected business operation.
//!
//! The Sheets adapter additionally enforces its own spreadsheet and A1 range
//! pins from operator TOML (`[[sheets_pins]]`, plan 106 G1b). A capability
//! schema `const` is only one layer: any path that reaches this plugin with a
//! spreadsheet id or range outside the pins is refused before credential use
//! or network I/O, and no pins at all refuses every call.

use super::{Plugin, PluginError, PluginRequest};
use crate::config::{A1Range, SheetsPin};
use crate::{Credential, CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const SHEETS_BASE_URL: &str = "https://sheets.googleapis.com";
const SHEETS_SOURCES_RANGE: &str = "Sources!A1:F100";
const PIPELINE_COLUMN_COUNT: usize = 23;
const PIPELINE_VARIANT_ID: usize = 1;
const PIPELINE_DRAFT_COPY: usize = 6;
const PIPELINE_MEDIA_BRIEF: usize = 7;
const PIPELINE_STATE: usize = 10;
const PIPELINE_LUCAS_NOTES: usize = 11;
const PIPELINE_ROW_VERSION: usize = 13;
const PIPELINE_CONTENT_HASH: usize = 14;
const PIPELINE_UPDATED_AT: usize = 20;
const PIPELINE_UPDATED_BY: usize = 21;
const PIPELINE_SOURCE_IDS: usize = 22;
const PENDING_REVIEW_STATE: &str = "Pending Review";
const FEIR_APPROVAL_ACTOR: &str = "feir_approval";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SheetsReadParams {
    base_url: String,
    spreadsheet_id: String,
    range: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SheetsAppendParams {
    base_url: String,
    spreadsheet_id: String,
    range: String,
    campaign_id: String,
    variant_id: String,
    channel: String,
    account_id: String,
    audience: String,
    content_type: String,
    draft_copy: String,
    #[serde(default)]
    media_brief: String,
    #[serde(default)]
    asset_url: String,
    #[serde(default)]
    asset_hash: String,
    #[serde(default)]
    lucas_notes: String,
    #[serde(default)]
    publish_at: String,
    row_version: String,
    content_hash: String,
    source_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SheetsReviseParams {
    base_url: String,
    spreadsheet_id: String,
    range: String,
    variant_id: String,
    expected_row_version: String,
    draft_copy: String,
    #[serde(default)]
    media_brief: String,
    #[serde(default)]
    lucas_notes: String,
    content_hash: String,
}

fn validate_content_hash(value: &str, action: &str) -> Result<(), PluginError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PluginError::InvalidParams(format!(
            "{action} content_hash must be exactly 64 hexadecimal characters"
        )));
    }
    Ok(())
}

pub(crate) struct DraftHashPayload<'a> {
    pub(crate) campaign_id: &'a str,
    pub(crate) variant_id: &'a str,
    pub(crate) channel: &'a str,
    pub(crate) account_id: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) content_type: &'a str,
    pub(crate) draft_copy: &'a str,
    pub(crate) media_brief: &'a str,
    pub(crate) asset_url: &'a str,
    pub(crate) asset_hash: &'a str,
    pub(crate) publish_at: &'a str,
    pub(crate) source_ids: Vec<String>,
}

fn normalize_source_ids(source_ids: &[String]) -> Result<Vec<String>, PluginError> {
    if source_ids.is_empty() || source_ids.len() > 16 {
        return Err(PluginError::InvalidParams(
            "source_ids must contain between 1 and 16 pinned source ids".to_string(),
        ));
    }
    let mut normalized = source_ids.to_vec();
    if normalized
        .iter()
        .any(|id| id.is_empty() || id.chars().count() > 128)
    {
        return Err(PluginError::InvalidParams(
            "source_ids entries must be non-empty and at most 128 characters".to_string(),
        ));
    }
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PluginError::InvalidParams(
            "source_ids must not contain duplicates".to_string(),
        ));
    }
    Ok(normalized)
}

pub(crate) fn draft_content_hash(payload: DraftHashPayload<'_>) -> Result<String, PluginError> {
    let source_ids = normalize_source_ids(&payload.source_ids)?;
    let mut canonical = BTreeMap::new();
    canonical.insert("account_id", json!(payload.account_id));
    canonical.insert("asset_hash", json!(payload.asset_hash));
    canonical.insert("asset_url", json!(payload.asset_url));
    canonical.insert("audience", json!(payload.audience));
    canonical.insert("campaign_id", json!(payload.campaign_id));
    canonical.insert("channel", json!(payload.channel));
    canonical.insert("content_type", json!(payload.content_type));
    canonical.insert("draft_copy", json!(payload.draft_copy));
    canonical.insert("media_brief", json!(payload.media_brief));
    canonical.insert("publish_at", json!(payload.publish_at));
    canonical.insert("source_ids", json!(source_ids));
    canonical.insert("variant_id", json!(payload.variant_id));
    let bytes = serde_json::to_vec(&canonical).map_err(|error| {
        PluginError::InvalidParams(format!("could not canonicalize draft payload: {error}"))
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn append_payload(params: &SheetsAppendParams) -> DraftHashPayload<'_> {
    DraftHashPayload {
        campaign_id: &params.campaign_id,
        variant_id: &params.variant_id,
        channel: &params.channel,
        account_id: &params.account_id,
        audience: &params.audience,
        content_type: &params.content_type,
        draft_copy: &params.draft_copy,
        media_brief: &params.media_brief,
        asset_url: &params.asset_url,
        asset_hash: &params.asset_hash,
        publish_at: &params.publish_at,
        source_ids: params.source_ids.clone(),
    }
}

fn row_payload(row: &[Value]) -> Result<DraftHashPayload<'_>, PluginError> {
    if row.len() < PIPELINE_COLUMN_COUNT {
        return Err(PluginError::ExecutionFailed(format!(
            "Pipeline row has {} cells, expected at least {PIPELINE_COLUMN_COUNT}",
            row.len()
        )));
    }
    let cell = |index: usize, name: &str| {
        row[index].as_str().ok_or_else(|| {
            PluginError::ExecutionFailed(format!("Pipeline {name} cell is not a string"))
        })
    };
    let source_ids: Vec<String> = serde_json::from_str(cell(PIPELINE_SOURCE_IDS, "source_ids")?)
        .map_err(|error| {
            PluginError::ExecutionFailed(format!(
                "Pipeline source_ids cell is not a JSON string array: {error}"
            ))
        })?;
    Ok(DraftHashPayload {
        campaign_id: cell(0, "campaign_id")?,
        variant_id: cell(1, "variant_id")?,
        channel: cell(2, "channel")?,
        account_id: cell(3, "account_id")?,
        audience: cell(4, "audience")?,
        content_type: cell(5, "content_type")?,
        draft_copy: cell(6, "draft_copy")?,
        media_brief: cell(7, "media_brief")?,
        asset_url: cell(8, "asset_url")?,
        asset_hash: cell(9, "asset_hash")?,
        publish_at: cell(12, "publish_at")?,
        source_ids,
    })
}

fn validate_source_rows(
    document: &Value,
    requested: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<String>, PluginError> {
    let requested = normalize_source_ids(requested)?;
    let rows = document["values"].as_array().ok_or_else(|| {
        PluginError::ExecutionFailed(
            "Sheets Sources read did not contain a values array".to_string(),
        )
    })?;
    let header = rows.first().and_then(Value::as_array).ok_or_else(|| {
        PluginError::ExecutionFailed("Sheets Sources range has no header row".to_string())
    })?;
    let column = |name: &str| {
        header
            .iter()
            .position(|value| value.as_str() == Some(name))
            .ok_or_else(|| {
                PluginError::ExecutionFailed(format!(
                    "Sheets Sources range is missing required column {name}"
                ))
            })
    };
    let id_col = column("source_id")?;
    let fetched_col = column("fetched_at")?;
    let fresh_col = column("fresh_for_hours")?;
    for requested_id in &requested {
        let row = rows
            .iter()
            .skip(1)
            .filter_map(Value::as_array)
            .find(|row| row.get(id_col).and_then(Value::as_str) == Some(requested_id.as_str()))
            .ok_or_else(|| {
                PluginError::InvalidParams(format!(
                    "source_id '{requested_id}' is not present in the pinned Sources range"
                ))
            })?;
        let fetched_at = row
            .get(fetched_col)
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .ok_or_else(|| {
                PluginError::ExecutionFailed(format!(
                    "source_id '{requested_id}' has an invalid fetched_at"
                ))
            })?;
        let fresh_for_hours = row
            .get(fresh_col)
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|value| value.parse::<i64>().ok())
                    .or_else(|| value.as_i64())
            })
            .filter(|hours| *hours > 0 && *hours <= 24 * 365)
            .ok_or_else(|| {
                PluginError::ExecutionFailed(format!(
                    "source_id '{requested_id}' has an invalid fresh_for_hours"
                ))
            })?;
        let expires_at = fetched_at
            .checked_add_signed(chrono::Duration::hours(fresh_for_hours))
            .ok_or_else(|| PluginError::ExecutionFailed("source freshness overflow".to_string()))?;
        if expires_at < now {
            return Err(PluginError::InvalidParams(format!(
                "source_id '{requested_id}' is stale"
            )));
        }
    }
    Ok(requested)
}

fn validate_positive_row_version(value: &str) -> Result<u64, PluginError> {
    let version = value.parse::<u64>().map_err(|_| {
        PluginError::InvalidParams(
            "expected_row_version must be a positive decimal row version".to_string(),
        )
    })?;
    if version == 0 {
        return Err(PluginError::InvalidParams(
            "expected_row_version must be a positive decimal row version".to_string(),
        ));
    }
    Ok(version)
}

fn validate_base_url(raw: &str, expected: &str) -> Result<reqwest::Url, PluginError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| PluginError::InvalidParams(format!("invalid connector base_url: {e}")))?;
    let expected_url = reqwest::Url::parse(expected).expect("connector constant is valid");
    let test_loopback = cfg!(test) && matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    if !test_loopback
        && (url.scheme() != expected_url.scheme() || url.host_str() != expected_url.host_str())
    {
        return Err(PluginError::InvalidParams(format!(
            "connector base_url host is operator-pinned to {}",
            expected_url.host_str().unwrap_or(expected)
        )));
    }
    Ok(url)
}

fn credential_headers(credential: &Credential) -> Result<reqwest::header::HeaderMap, PluginError> {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
    let mut headers = HeaderMap::new();
    let token = match &credential.data {
        CredentialData::ApiKey { key, .. } => key.expose().to_string(),
        CredentialData::OAuth2 {
            access_token: Some(token),
            ..
        } => token.expose().to_string(),
        CredentialData::OAuth2 { .. } => {
            return Err(PluginError::UnsupportedCredentialType(
                "marketing connector requires a live OAuth2 access token".to_string(),
            ))
        }
        other => {
            return Err(PluginError::UnsupportedCredentialType(format!(
                "marketing connector does not support {:?}",
                other.credential_type()
            )))
        }
    };
    let auth = HeaderValue::try_from(format!("Bearer {token}")).map_err(|e| {
        PluginError::InvalidParams(format!("credential cannot form Authorization header: {e}"))
    })?;
    headers.insert(AUTHORIZATION, auth);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(headers)
}

async fn effective_marketing_credential(
    credential: &Credential,
) -> Result<(Credential, Option<CredentialData>), PluginError> {
    if !matches!(credential.data, CredentialData::OAuth2 { .. }) {
        return Ok((credential.clone(), None));
    }

    let oauth = crate::plugins::HttpPlugin::new();
    let (_, updated) = oauth.ensure_valid_token(&credential.data).await?;
    let mut effective = credential.clone();
    if let Some(data) = updated.clone() {
        effective.data = data;
        effective.updated_at = Utc::now();
    }
    Ok((effective, updated))
}

fn attach_credential_update(
    response: ExecuteResponse,
    updated: Option<CredentialData>,
) -> ExecuteResponse {
    match updated {
        Some(data) => response.with_updated_credential(data),
        None => response,
    }
}

async fn send_json(
    client: &Client,
    url: reqwest::Url,
    credential: &Credential,
    body: Value,
) -> Result<ExecuteResponse, PluginError> {
    let response = client
        .post(url)
        .headers(credential_headers(credential)?)
        .json(&body)
        .send()
        .await
        .map_err(|e| PluginError::Http(e.to_string()))?;
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = crate::plugins::read_body_capped(response).await?;
    if !status.is_success() {
        return Err(PluginError::ExecutionFailed(format!(
            "marketing upstream returned {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        )));
    }
    Ok(ExecuteResponse {
        status: status.as_u16(),
        headers,
        body,
        updated_credential: None,
    })
}

async fn send_json_method(
    client: &Client,
    method: reqwest::Method,
    url: reqwest::Url,
    credential: &Credential,
    body: Value,
) -> Result<ExecuteResponse, PluginError> {
    let headers = credential_headers(credential)?;
    let request = client.request(method.clone(), url).headers(headers);
    let request = if matches!(method, reqwest::Method::GET | reqwest::Method::HEAD) {
        request
    } else {
        request.json(&body)
    };
    let response = request
        .send()
        .await
        .map_err(|e| PluginError::Http(e.to_string()))?;
    let status = response.status();
    let response_headers = response
        .headers()
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = crate::plugins::read_body_capped(response).await?;
    if !status.is_success() {
        return Err(PluginError::ExecutionFailed(format!(
            "marketing upstream returned {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        )));
    }
    Ok(ExecuteResponse {
        status: status.as_u16(),
        headers: response_headers,
        body,
        updated_credential: None,
    })
}

pub struct SheetsPlugin {
    client: Client,
    revise_lock: Arc<tokio::sync::Mutex<()>>,
    /// Operator pins from `[[sheets_pins]]`. Empty = every call is refused.
    pins: Arc<Vec<SheetsPin>>,
}

fn pin_refusal(message: &str) -> PluginError {
    PluginError::InvalidParams(format!("sheets pin: {message}"))
}

impl SheetsPlugin {
    /// Build the adapter over the operator's pins. An empty list is legal and
    /// means every Sheets call is refused (fail closed, never "allow all").
    pub fn new(pins: Vec<SheetsPin>) -> Self {
        Self::with_client(crate::plugins::build_guarded_client(), pins)
    }

    fn with_client(client: Client, pins: Vec<SheetsPin>) -> Self {
        Self {
            client,
            revise_lock: Arc::new(tokio::sync::Mutex::new(())),
            pins: Arc::new(pins),
        }
    }

    /// The pin for an exact (byte-for-byte) spreadsheet id.
    fn pinned_spreadsheet(&self, spreadsheet_id: &str) -> Result<&SheetsPin, PluginError> {
        if self.pins.is_empty() {
            return Err(pin_refusal(
                "no spreadsheet is operator-pinned ([[sheets_pins]] is empty); every Sheets call is refused",
            ));
        }
        self.pins
            .iter()
            .find(|pin| pin.spreadsheet_id == spreadsheet_id)
            .ok_or_else(|| pin_refusal("spreadsheet_id is not operator-pinned"))
    }

    /// A caller range that EXACTLY equals one of the pinned ranges of `kind`.
    fn pinned_range(
        &self,
        spreadsheet_id: &str,
        range: &str,
        write: bool,
    ) -> Result<(&SheetsPin, A1Range), PluginError> {
        let pin = self.pinned_spreadsheet(spreadsheet_id)?;
        let parsed = A1Range::parse_strict(range)
            .map_err(|error| pin_refusal(&format!("range refused: {error}")))?;
        let (allowed, kind) = if write {
            (&pin.write_ranges, "write")
        } else {
            (&pin.read_ranges, "read")
        };
        if !allowed.contains(&parsed) {
            return Err(pin_refusal(&format!(
                "range is not an operator-pinned {kind} range for this spreadsheet"
            )));
        }
        Ok((pin, parsed))
    }

    /// Append names a pinned write range and also performs the adapter-internal
    /// Sources lineage read, which must sit inside a pinned read range.
    fn pinned_append_range(&self, p: &SheetsAppendParams) -> Result<A1Range, PluginError> {
        let (pin, range) = self.pinned_range(&p.spreadsheet_id, &p.range, true)?;
        let sources = A1Range::parse_strict(SHEETS_SOURCES_RANGE)
            .map_err(|error| pin_refusal(&format!("Sources range constant: {error}")))?;
        if !pin.read_ranges.iter().any(|read| read.contains(&sources)) {
            return Err(pin_refusal(
                "append_draft reads Sources lineage, which is outside every operator-pinned read range",
            ));
        }
        Ok(range)
    }

    fn validate_typed(&self, action: &str, params: &Value) -> Result<(), PluginError> {
        match action {
            "read" => {
                let p = serde_json::from_value::<SheetsReadParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                self.pinned_range(&p.spreadsheet_id, &p.range, false)
                    .map(|_| ())
            }
            "append_draft" => {
                let p = serde_json::from_value::<SheetsAppendParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                self.pinned_append_range(&p)?;
                if p.row_version != "1" {
                    return Err(PluginError::InvalidParams(
                        "append_draft only creates rows at row_version 1".to_string(),
                    ));
                }
                validate_content_hash(&p.content_hash, "append_draft")?;
                let expected_hash = draft_content_hash(append_payload(&p))?;
                if p.content_hash != expected_hash {
                    return Err(PluginError::InvalidParams(
                        "append_draft content_hash does not match the canonical draft payload"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            "revise_draft" => {
                let p = serde_json::from_value::<SheetsReviseParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                self.pinned_range(&p.spreadsheet_id, &p.range, true)?;
                validate_positive_row_version(&p.expected_row_version)?;
                validate_content_hash(&p.content_hash, "revise_draft")
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    async fn execute_typed(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        match request.action.as_str() {
            "read" => {
                let p: SheetsReadParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                // Pin check first: before credential refresh or any request.
                let (_, range) = self.pinned_range(&p.spreadsheet_id, &p.range, false)?;
                let (credential, updated) =
                    effective_marketing_credential(&request.credential).await?;
                let base = validate_base_url(&p.base_url, SHEETS_BASE_URL)?;
                let url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(&range.to_string())
                    ))
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                let response = send_json_method(
                    &self.client,
                    reqwest::Method::GET,
                    url,
                    &credential,
                    json!({}),
                )
                .await?;
                Ok(attach_credential_update(response, updated))
            }
            "append_draft" => {
                let p: SheetsAppendParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                // Pin check first: before credential refresh or any request.
                let append_range = self.pinned_append_range(&p)?;
                if p.row_version != "1" {
                    return Err(PluginError::InvalidParams(
                        "append_draft only creates rows at row_version 1".to_string(),
                    ));
                }
                validate_content_hash(&p.content_hash, "append_draft")?;
                let expected_hash = draft_content_hash(append_payload(&p))?;
                if p.content_hash != expected_hash {
                    return Err(PluginError::InvalidParams(
                        "append_draft content_hash does not match the canonical draft payload"
                            .to_string(),
                    ));
                }
                let (credential, updated) =
                    effective_marketing_credential(&request.credential).await?;
                let base = validate_base_url(&p.base_url, SHEETS_BASE_URL)?;
                let sources_url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(SHEETS_SOURCES_RANGE)
                    ))
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                let sources = send_json_method(
                    &self.client,
                    reqwest::Method::GET,
                    sources_url,
                    &credential,
                    json!({}),
                )
                .await?;
                let source_document: Value =
                    serde_json::from_slice(&sources.body).map_err(|e| {
                        PluginError::ExecutionFailed(format!(
                            "Sheets Sources read was not JSON: {e}"
                        ))
                    })?;
                let source_ids = validate_source_rows(&source_document, &p.source_ids, Utc::now())?;
                let url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(&append_range.to_string())
                    ))
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                let values = json!([[
                    p.campaign_id,
                    p.variant_id,
                    p.channel,
                    p.account_id,
                    p.audience,
                    p.content_type,
                    p.draft_copy,
                    p.media_brief,
                    p.asset_url,
                    p.asset_hash,
                    PENDING_REVIEW_STATE,
                    p.lucas_notes,
                    p.publish_at,
                    p.row_version,
                    p.content_hash,
                    "",
                    "",
                    "",
                    "0",
                    "",
                    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                    FEIR_APPROVAL_ACTOR,
                    serde_json::to_string(&source_ids)
                        .map_err(|error| PluginError::InvalidParams(error.to_string()))?
                ]]);
                let response =
                    send_json(&self.client, url, &credential, json!({"values": values})).await?;
                Ok(attach_credential_update(response, updated))
            }
            "revise_draft" => {
                let p: SheetsReviseParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                // Pin check first: before credential refresh or any request.
                let (_, write_range) = self.pinned_range(&p.spreadsheet_id, &p.range, true)?;
                let expected_row_version = p.expected_row_version.parse::<u64>().map_err(|_| {
                    PluginError::InvalidParams(
                        "expected_row_version must be a positive decimal row version".to_string(),
                    )
                })?;
                if expected_row_version == 0 {
                    return Err(PluginError::InvalidParams(
                        "expected_row_version must be a positive decimal row version".to_string(),
                    ));
                }
                validate_content_hash(&p.content_hash, "revise_draft")?;
                let (credential, updated) =
                    effective_marketing_credential(&request.credential).await?;
                // One Eve agent is the only writer in this pack. The mutex makes
                // the read/compare/update sequence a process-local CAS, while
                // the authoritative row_version check below protects a stale
                // or replayed request after a restart as well.
                let _revision_guard = self.revise_lock.lock().await;
                let base = validate_base_url(&p.base_url, SHEETS_BASE_URL)?;
                let read_url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(&write_range.to_string())
                    ))
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                let current = send_json_method(
                    &self.client,
                    reqwest::Method::GET,
                    read_url,
                    &credential,
                    json!({}),
                )
                .await?;
                let document: Value = serde_json::from_slice(&current.body).map_err(|e| {
                    PluginError::ExecutionFailed(format!("Sheets pipeline read was not JSON: {e}"))
                })?;
                let rows = document["values"].as_array().ok_or_else(|| {
                    PluginError::ExecutionFailed(
                        "Sheets pipeline read did not contain a values array".to_string(),
                    )
                })?;
                let (row_index, current_row) = rows
                    .iter()
                    .enumerate()
                    .find_map(|(index, row)| {
                        (row.get(PIPELINE_VARIANT_ID).and_then(Value::as_str)
                            == Some(p.variant_id.as_str()))
                        .then_some((index, row))
                    })
                    .ok_or_else(|| {
                        PluginError::InvalidParams(format!(
                            "variant_id '{}' is not present in the pinned Pipeline range",
                            p.variant_id
                        ))
                    })?;
                // The values array starts at the pinned range's first row and
                // column, so the row write is derived from the pin (never a
                // hardcoded sheet) and must stay inside the pinned write range.
                let write_target = u32::try_from(row_index)
                    .ok()
                    .and_then(|index| write_range.first_row().checked_add(index))
                    .zip(
                        write_range
                            .first_col()
                            .checked_add(PIPELINE_COLUMN_COUNT as u32 - 1),
                    )
                    .map(|(row, last_col)| {
                        A1Range::row_span(
                            write_range.sheet(),
                            write_range.first_col(),
                            last_col,
                            row,
                        )
                    })
                    .filter(|target| write_range.contains(target))
                    .ok_or_else(|| {
                        pin_refusal(
                            "the resolved Pipeline row write falls outside the operator-pinned write range",
                        )
                    })?;
                let current_cells = current_row.as_array().ok_or_else(|| {
                    PluginError::ExecutionFailed("Pipeline row was not an array".to_string())
                })?;
                if current_cells.len() < PIPELINE_COLUMN_COUNT {
                    return Err(PluginError::ExecutionFailed(format!(
                        "Pipeline row for '{}' has {} cells, expected at least {PIPELINE_COLUMN_COUNT}",
                        p.variant_id,
                        current_cells.len()
                    )));
                }
                let current_state = current_cells
                    .get(PIPELINE_STATE)
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !matches!(
                    current_state,
                    "Draft" | "Revision Requested" | "Pending Review"
                ) {
                    return Err(PluginError::InvalidParams(format!(
                        "variant_id '{}' is in state '{}' and cannot receive a governed draft revision",
                        p.variant_id, current_state
                    )));
                }
                let current_version = current_cells
                    .get(PIPELINE_ROW_VERSION)
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| {
                        PluginError::ExecutionFailed(
                            "Pipeline row has no valid numeric row_version".to_string(),
                        )
                    })?;
                if current_version != expected_row_version {
                    return Err(PluginError::InvalidParams(format!(
                        "stale row_version for '{}': expected {}, current {}",
                        p.variant_id, expected_row_version, current_version
                    )));
                }
                let mut next_row = current_cells.clone();
                next_row[PIPELINE_DRAFT_COPY] = Value::String(p.draft_copy);
                next_row[PIPELINE_MEDIA_BRIEF] = Value::String(p.media_brief);
                next_row[PIPELINE_LUCAS_NOTES] = Value::String(p.lucas_notes);
                next_row[PIPELINE_STATE] = Value::String(PENDING_REVIEW_STATE.to_string());
                let next_row_version = expected_row_version.checked_add(1).ok_or_else(|| {
                    PluginError::InvalidParams("row_version overflow".to_string())
                })?;
                next_row[PIPELINE_ROW_VERSION] = Value::String(next_row_version.to_string());
                let expected_hash = draft_content_hash(row_payload(&next_row)?)?;
                if p.content_hash != expected_hash {
                    return Err(PluginError::InvalidParams(
                        "revise_draft content_hash does not match the canonical revised payload"
                            .to_string(),
                    ));
                }
                next_row[PIPELINE_CONTENT_HASH] = Value::String(p.content_hash);
                next_row[PIPELINE_UPDATED_AT] =
                    Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
                next_row[PIPELINE_UPDATED_BY] = Value::String(FEIR_APPROVAL_ACTOR.to_string());
                let url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}?valueInputOption=RAW",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(&write_target.to_string())
                    ))
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                let response = send_json_method(
                    &self.client,
                    reqwest::Method::PUT,
                    url,
                    &credential,
                    json!({"values": [next_row]}),
                )
                .await?;
                Ok(attach_credential_update(response, updated))
            }
            action => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }
}

impl Default for SheetsPlugin {
    /// No pins: every call is refused.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[async_trait]
impl Plugin for SheetsPlugin {
    fn name(&self) -> &str {
        "sheets"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey, CredentialType::OAuth2]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["read", "append_draft", "revise_draft"]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.execute_typed(request).await
    }
    fn validate_params(&self, action: &str, params: &Value) -> Result<(), PluginError> {
        self.validate_typed(action, params)
    }
}
