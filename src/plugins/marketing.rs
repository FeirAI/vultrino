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
const BUFFER_BASE_URL: &str = "https://api.buffer.com";
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferReadParams {
    base_url: String,
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferDraftParams {
    base_url: String,
    channel_id: String,
    account_id: String,
    text: String,
    media_hash: String,
    content_hash: String,
    row_version: String,
    due_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferScheduleParams {
    base_url: String,
    post_id: String,
    channel_id: String,
    account_id: String,
    text: String,
    media_hash: String,
    content_hash: String,
    row_version: String,
    due_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferPostParams {
    base_url: String,
    post_id: String,
    channel_id: String,
    account_id: String,
    text: String,
    media_hash: String,
    content_hash: String,
    row_version: String,
    due_at: String,
}

fn validate_frozen_buffer_fields(
    channel_id: &str,
    account_id: &str,
    text: &str,
    media_hash: &str,
    content_hash: &str,
    row_version: &str,
    due_at: &str,
) -> Result<(), PluginError> {
    for (name, value) in [
        ("channel_id", channel_id),
        ("account_id", account_id),
        ("text", text),
        ("media_hash", media_hash),
        ("content_hash", content_hash),
        ("row_version", row_version),
        ("due_at", due_at),
    ] {
        if value.is_empty() {
            return Err(PluginError::InvalidParams(format!(
                "Buffer frozen payload field {name} must be non-empty"
            )));
        }
    }
    if content_hash.len() != 64 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PluginError::InvalidParams(
            "Buffer frozen payload content_hash must be 64 hexadecimal characters".to_string(),
        ));
    }
    if row_version
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .is_none()
    {
        return Err(PluginError::InvalidParams(
            "Buffer frozen payload row_version must be a positive decimal version".to_string(),
        ));
    }
    Ok(())
}

fn validate_content_hash(value: &str, action: &str) -> Result<(), PluginError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PluginError::InvalidParams(format!(
            "{action} content_hash must be exactly 64 hexadecimal characters"
        )));
    }
    Ok(())
}

struct DraftHashPayload<'a> {
    campaign_id: &'a str,
    variant_id: &'a str,
    channel: &'a str,
    account_id: &'a str,
    audience: &'a str,
    content_type: &'a str,
    draft_copy: &'a str,
    media_brief: &'a str,
    asset_url: &'a str,
    asset_hash: &'a str,
    publish_at: &'a str,
    source_ids: Vec<String>,
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

fn draft_content_hash(payload: DraftHashPayload<'_>) -> Result<String, PluginError> {
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

fn validate_post_id(value: &str) -> Result<(), PluginError> {
    if value.is_empty() {
        return Err(PluginError::InvalidParams(
            "Buffer mutation post_id must be non-empty".to_string(),
        ));
    }
    Ok(())
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

async fn send_buffer_json(
    client: &Client,
    url: reqwest::Url,
    credential: &Credential,
    query: &'static str,
    variables: Value,
) -> Result<ExecuteResponse, PluginError> {
    let response = send_json(
        client,
        url,
        credential,
        json!({"query": query, "variables": variables}),
    )
    .await?;
    let document: Value = serde_json::from_slice(&response.body).map_err(|e| {
        PluginError::ExecutionFailed(format!("Buffer upstream returned non-JSON: {e}"))
    })?;
    if document
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
        || contains_graphql_message(&document)
    {
        return Err(PluginError::ExecutionFailed(
            "Buffer upstream returned a GraphQL error".to_string(),
        ));
    }
    Ok(response)
}

fn contains_graphql_message(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "message" && value.is_string()) || contains_graphql_message(value)
        }),
        Value::Array(values) => values.iter().any(contains_graphql_message),
        _ => false,
    }
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

pub struct BufferPlugin {
    client: Client,
}

impl BufferPlugin {
    pub fn new() -> Self {
        Self {
            client: crate::plugins::build_guarded_client(),
        }
    }

    #[cfg(test)]
    fn with_client(client: Client) -> Self {
        Self { client }
    }

    fn validate_typed(action: &str, params: &Value) -> Result<(), PluginError> {
        match action {
            "accounts_read" | "channels_read" => {
                serde_json::from_value::<BufferReadParams>(params.clone())
                    .map(|_| ())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))
            }
            "draft" => {
                let p = serde_json::from_value::<BufferDraftParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )
            }
            "schedule" => {
                let p = serde_json::from_value::<BufferScheduleParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                validate_post_id(&p.post_id)?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )
            }
            "publish" | "cancel_delete" => {
                let p = serde_json::from_value::<BufferPostParams>(params.clone())
                    .map_err(|error| PluginError::InvalidParams(error.to_string()))?;
                validate_post_id(&p.post_id)?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )
            }
            _ => Err(PluginError::UnsupportedAction(action.to_string())),
        }
    }

    async fn execute_typed(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        const ACCOUNT_QUERY: &str = "query EveAccount { account { id organizations { id name } } }";
        const CHANNELS_QUERY: &str =
            "query EveChannels($input: ChannelsInput!) { channels(input: $input) { id name service organizationId } }";
        const DRAFT_QUERY: &str =
            "mutation EveDraft($input: CreatePostInput!) { createPost(input: $input) { ... on PostActionSuccess { post { id text status } } ... on MutationError { message } } }";
        const SCHEDULE_QUERY: &str =
            "mutation EveSchedule($input: EditPostInput!) { editPost(input: $input) { ... on PostActionSuccess { post { id text status dueAt } } ... on MutationError { message } } }";
        const PUBLISH_QUERY: &str =
            "mutation EvePublish($input: EditPostInput!) { editPost(input: $input) { ... on PostActionSuccess { post { id status } } ... on MutationError { message } } }";
        const DELETE_QUERY: &str =
            "mutation EveDelete($input: DeletePostInput!) { deletePost(input: $input) { ... on DeletePostSuccess { id } ... on MutationError { message } } }";

        let (base_url, query, variables) = match request.action.as_str() {
            "accounts_read" => {
                let p: BufferReadParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                (p.base_url, ACCOUNT_QUERY, json!({}))
            }
            "channels_read" => {
                let p: BufferReadParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                (
                    p.base_url,
                    CHANNELS_QUERY,
                    json!({"input": {"organizationId": p.organization_id}}),
                )
            }
            "draft" => {
                let p: BufferDraftParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )?;
                (
                    p.base_url,
                    DRAFT_QUERY,
                    json!({"input": {
                        "text": p.text,
                        "channelId": p.channel_id,
                        "dueAt": p.due_at,
                        "schedulingType": "automatic",
                        "mode": "addToQueue",
                        "saveToDraft": true
                    }}),
                )
            }
            "schedule" => {
                let p: BufferScheduleParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                validate_post_id(&p.post_id)?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )?;
                (
                    p.base_url,
                    SCHEDULE_QUERY,
                    json!({"input": {
                        "id": p.post_id,
                        "text": p.text,
                        "schedulingType": "automatic",
                        "mode": "customScheduled",
                        "dueAt": p.due_at
                    }}),
                )
            }
            "publish" => {
                let p: BufferPostParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                validate_post_id(&p.post_id)?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )?;
                (
                    p.base_url,
                    PUBLISH_QUERY,
                    json!({"input": {
                        "id": p.post_id,
                        "mode": "shareNow",
                        "schedulingType": "automatic"
                    }}),
                )
            }
            "cancel_delete" => {
                let p: BufferPostParams = serde_json::from_value(request.params)
                    .map_err(|e| PluginError::InvalidParams(e.to_string()))?;
                validate_post_id(&p.post_id)?;
                validate_frozen_buffer_fields(
                    &p.channel_id,
                    &p.account_id,
                    &p.text,
                    &p.media_hash,
                    &p.content_hash,
                    &p.row_version,
                    &p.due_at,
                )?;
                (
                    p.base_url,
                    DELETE_QUERY,
                    json!({"input": {"id": p.post_id}}),
                )
            }
            action => return Err(PluginError::UnsupportedAction(action.to_string())),
        };
        let base = validate_base_url(&base_url, BUFFER_BASE_URL)?;
        let (credential, updated) = effective_marketing_credential(&request.credential).await?;
        let response = send_buffer_json(&self.client, base, &credential, query, variables).await?;
        Ok(attach_credential_update(response, updated))
    }
}

impl Default for BufferPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for BufferPlugin {
    fn name(&self) -> &str {
        "buffer"
    }
    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey, CredentialType::OAuth2]
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec![
            "accounts_read",
            "channels_read",
            "draft",
            "schedule",
            "publish",
            "cancel_delete",
        ]
    }
    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.execute_typed(request).await
    }
    fn validate_params(&self, action: &str, params: &Value) -> Result<(), PluginError> {
        Self::validate_typed(action, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RequestContext, Secret};
    use axum::{
        extract::State,
        routing::{get, post},
        Router,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    async fn fake(
        State(seen): State<Arc<parking_lot::Mutex<Value>>>,
        body: axum::Json<Value>,
    ) -> axum::Json<Value> {
        *seen.lock() = body.0;
        axum::Json(json!({"data":{"ok":true}}))
    }

    async fn server() -> (String, Arc<parking_lot::Mutex<Value>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Value::Null));
        let app = Router::new()
            .route("/", post(fake))
            .with_state(seen.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), seen)
    }

    async fn sources_get() -> axum::Json<Value> {
        axum::Json(json!({"values": [
            ["source_id", "url", "title", "fetched_at", "fresh_for_hours", "content_hash"],
            ["source-1", "https://example.com/source", "Source", Utc::now().to_rfc3339(), "168", "source-hash"]
        ]}))
    }

    async fn sheets_server() -> (String, Arc<parking_lot::Mutex<Value>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Value::Null));
        let app = Router::new()
            .route("/{*path}", get(sources_get).post(fake))
            .with_state(seen.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), seen)
    }

    async fn pipeline_get() -> axum::Json<Value> {
        axum::Json(json!({"values": [
            ["campaign_id", "variant_id", "channel", "account_id", "audience", "content_type", "draft_copy", "media_brief", "asset_url", "asset_hash", "state", "lucas_notes", "publish_at", "row_version", "content_hash", "approval_id", "buffer_post_id", "published_url", "attempt_count", "last_error", "updated_at", "updated_by", "source_ids"],
            ["camp-1", "var-1", "linkedin", "lucas-linkedin", "builders", "text", "old", "", "", "", "Pending Review", "", "", "1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "", "", "0", "", "2026-08-18T00:00:00Z", "feir_approval", "[\"source-1\"]"]
        ]}))
    }

    async fn revision_server() -> (String, Arc<parking_lot::Mutex<Value>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Value::Null));
        let app = Router::new()
            .route("/{*path}", get(pipeline_get).put(fake))
            .with_state(seen.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), seen)
    }

    fn credential() -> Credential {
        Credential::new(
            "marketing-test".to_string(),
            CredentialData::ApiKey {
                key: Secret::new("not-logged"),
                header_name: "Authorization".into(),
                header_prefix: "Bearer ".into(),
            },
        )
    }

    fn test_draft_hash(draft_copy: &str, media_brief: &str) -> String {
        draft_content_hash(DraftHashPayload {
            campaign_id: "camp-1",
            variant_id: "var-1",
            channel: "linkedin",
            account_id: "lucas-linkedin",
            audience: "builders",
            content_type: "text",
            draft_copy,
            media_brief,
            asset_url: "",
            asset_hash: "",
            publish_at: "",
            source_ids: vec!["source-1".to_string()],
        })
        .unwrap()
    }

    #[test]
    fn sheets_source_lineage_requires_present_fresh_unique_sources() {
        let now = Utc::now();
        let document = json!({"values": [
            ["source_id", "url", "title", "fetched_at", "fresh_for_hours", "content_hash"],
            ["fresh", "https://example.com", "Fresh", now.to_rfc3339(), "24", "hash"],
            ["stale", "https://example.com/old", "Old", (now - chrono::Duration::hours(48)).to_rfc3339(), "1", "hash"]
        ]});
        assert_eq!(
            validate_source_rows(&document, &["fresh".to_string()], now).unwrap(),
            vec!["fresh".to_string()]
        );
        assert!(matches!(
            validate_source_rows(&document, &["missing".to_string()], now),
            Err(PluginError::InvalidParams(message)) if message.contains("not present")
        ));
        assert!(matches!(
            validate_source_rows(&document, &["stale".to_string()], now),
            Err(PluginError::InvalidParams(message)) if message.contains("stale")
        ));
        assert!(matches!(
            validate_source_rows(&document, &["fresh".to_string(), "fresh".to_string()], now),
            Err(PluginError::InvalidParams(message)) if message.contains("duplicates")
        ));
    }

    #[test]
    fn sheets_append_rejects_a_hash_not_bound_to_the_draft() {
        let params = json!({
            "base_url": SHEETS_BASE_URL,
            "spreadsheet_id": "solo-marketing-fixture",
            "range": "Pipeline!A:Z",
            "campaign_id": "camp-1",
            "variant_id": "var-1",
            "channel": "linkedin",
            "account_id": "lucas-linkedin",
            "audience": "builders",
            "content_type": "text",
            "draft_copy": "A sourced draft",
            "row_version": "1",
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "source_ids": ["source-1"]
        });
        assert!(matches!(
            pinned_plugin().validate_typed("append_draft", &params),
            Err(PluginError::InvalidParams(message)) if message.contains("canonical draft payload")
        ));
    }

    #[test]
    fn direct_graphql_document_and_channel_are_not_accepted_as_input() {
        let params = json!({"base_url": BUFFER_BASE_URL, "organization_id": "org", "query": "mutation publishNow", "channel_id": "attacker"});
        assert!(BufferPlugin::validate_typed("channels_read", &params).is_err());
    }

    #[tokio::test]
    async fn buffer_expired_oauth_requires_refresh_before_dispatch() {
        let (base_url, seen) = server().await;
        let credential = Credential::new(
            "buffer-oauth".to_string(),
            CredentialData::OAuth2 {
                client_id: "client".into(),
                client_secret: Secret::new("client-secret"),
                refresh_token: None,
                access_token: Some(Secret::new("expired-access")),
                expires_at: Some(Utc::now() - chrono::Duration::minutes(1)),
                token_url: "https://oauth2.googleapis.com/token".into(),
                scopes: vec![],
            },
        );
        let result = BufferPlugin::with_client(Client::new())
            .execute(PluginRequest {
                credential,
                action: "accounts_read".into(),
                params: json!({"base_url": base_url, "organization_id": "org"}),
                context: RequestContext::default(),
            })
            .await;
        assert!(
            result.is_err(),
            "an expired OAuth2 credential must fail refresh before Buffer dispatch"
        );
        assert!(
            seen.lock().is_null(),
            "Buffer must not receive an expired token"
        );
    }

    #[tokio::test]
    async fn draft_sends_fixed_mutation_to_fake_upstream() {
        let (base_url, seen) = server().await;
        let plugin = BufferPlugin::with_client(Client::new());
        let response = plugin.execute(PluginRequest { credential: credential(), action: "draft".into(), params: json!({
            "base_url": base_url,
            "channel_id":"pinned-channel",
            "account_id":"pinned-account",
            "text":"hello \"world\"",
            "media_hash":"media-1",
            "content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "row_version":"2",
            "due_at":"2026-08-20T09:00:00Z"
        }), context: RequestContext::default() }).await.unwrap();
        assert_eq!(response.status, 200);
        let query = seen.lock()["query"].as_str().unwrap().to_string();
        assert!(query.contains("mutation EveDraft"));
        assert!(query.contains("$input: CreatePostInput!"));
        assert!(!query.contains("pinned-channel"));
        assert!(!query.contains("hello"));
        assert!(!query.contains("saveToDraft"));
        assert!(!query.contains("publishNow"));
        assert_eq!(
            seen.lock()["variables"]["input"]["channelId"],
            "pinned-channel"
        );
        assert_eq!(seen.lock()["variables"]["input"]["text"], "hello \"world\"");
    }

    #[test]
    fn buffer_mutations_require_the_complete_frozen_payload() {
        let missing = json!({
            "base_url": BUFFER_BASE_URL,
            "channel_id": "channel",
            "text": "copy"
        });
        assert!(matches!(
            BufferPlugin::validate_typed("draft", &missing),
            Err(PluginError::InvalidParams(_))
        ));

        let invalid_hash = json!({
            "base_url": BUFFER_BASE_URL,
            "channel_id": "channel",
            "account_id": "account",
            "text": "copy",
            "media_hash": "media",
            "content_hash": "not-a-hash",
            "row_version": "1",
            "due_at": "2026-08-20T09:00:00Z"
        });
        assert!(matches!(
            BufferPlugin::validate_typed("draft", &invalid_hash),
            Err(PluginError::InvalidParams(_))
        ));

        let missing_post_id = json!({
            "base_url": BUFFER_BASE_URL,
            "post_id": "",
            "channel_id": "channel",
            "account_id": "account",
            "text": "copy",
            "media_hash": "media",
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "row_version": "1",
            "due_at": "2026-08-20T09:00:00Z"
        });
        assert!(matches!(
            BufferPlugin::validate_typed("publish", &missing_post_id),
            Err(PluginError::InvalidParams(message)) if message.contains("post_id")
        ));
    }

    #[tokio::test]
    async fn sheets_append_advances_only_to_pending_review_after_the_governed_write() {
        let (base_url, seen) = sheets_server().await;
        let plugin = pinned_plugin();
        let params = json!({
            "base_url": base_url,
            "spreadsheet_id": "solo-marketing-fixture",
            "range": "Pipeline!A:Z",
            "campaign_id": "camp-1",
            "variant_id": "var-1",
            "channel": "linkedin",
            "account_id": "lucas-linkedin",
            "audience": "builders",
            "content_type": "text",
            "draft_copy": "A sourced draft",
            "media_brief": "",
            "asset_url": "",
            "asset_hash": "",
            "lucas_notes": "review",
            "publish_at": "",
            "row_version": "1",
            "content_hash": test_draft_hash("A sourced draft", ""),
            "source_ids": ["source-1"]
        });
        plugin
            .execute(PluginRequest {
                credential: credential(),
                action: "append_draft".into(),
                params,
                context: RequestContext::default(),
            })
            .await
            .unwrap();
        let seen = seen.lock();
        let row = seen["values"][0].as_array().unwrap();
        assert_eq!(row[1], "var-1");
        assert_eq!(row[10], PENDING_REVIEW_STATE);
        assert_eq!(row[13], "1");
        assert_eq!(row.len(), PIPELINE_COLUMN_COUNT);
        assert_eq!(row[15], "");
        assert_eq!(row[18], "0");
        assert_eq!(row[PIPELINE_UPDATED_BY], FEIR_APPROVAL_ACTOR);
        assert_eq!(row[PIPELINE_SOURCE_IDS], "[\"source-1\"]");
    }

    #[tokio::test]
    async fn sheets_revision_rejects_zero_row_version_before_network() {
        let params = json!({
            "base_url": SHEETS_BASE_URL,
            "spreadsheet_id": "solo-marketing-fixture",
            "range": "Pipeline!A:Z",
            "variant_id": "var-1",
            "expected_row_version": "0",
            "draft_copy": "new",
            "media_brief": "",
            "lucas_notes": "",
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });
        let result = pinned_plugin()
            .execute(PluginRequest {
                credential: credential(),
                action: "revise_draft".into(),
                params,
                context: RequestContext::default(),
            })
            .await;
        assert!(
            matches!(result, Err(PluginError::InvalidParams(message)) if message.contains("positive decimal"))
        );
    }

    #[tokio::test]
    async fn sheets_revision_performs_row_version_cas_and_targets_the_resolved_row() {
        let (base_url, seen) = revision_server().await;
        let plugin = pinned_plugin();
        let result = plugin
            .execute(PluginRequest {
                credential: credential(),
                action: "revise_draft".into(),
                params: json!({
                    "base_url": base_url,
                    "spreadsheet_id": "solo-marketing-fixture",
                    "range": "Pipeline!A:Z",
                    "variant_id": "var-1",
                    "expected_row_version": "1",
                    "draft_copy": "revised",
                    "media_brief": "",
                    "lucas_notes": "reviewed",
                    "content_hash": test_draft_hash("revised", ""),
                }),
                context: RequestContext::default(),
            })
            .await
            .unwrap();
        assert_eq!(result.status, 200);
        let row = &seen.lock()["values"][0];
        assert_eq!(row[6], "revised");
        assert_eq!(row[10], PENDING_REVIEW_STATE);
        assert_eq!(row[13], "2");
        assert_eq!(row[14], test_draft_hash("revised", ""));
        assert_eq!(row[15], "");
        assert_eq!(row[PIPELINE_UPDATED_BY], FEIR_APPROVAL_ACTOR);
        assert_eq!(row[PIPELINE_SOURCE_IDS], "[\"source-1\"]");
    }

    // -----------------------------------------------------------------------
    // G1b: the adapter itself pins spreadsheet id and A1 ranges.
    // -----------------------------------------------------------------------

    const PINNED_SPREADSHEET: &str = "solo-marketing-fixture";

    type Hits = Arc<parking_lot::Mutex<Vec<(String, String)>>>;

    /// A loopback upstream that records EVERY request (method + path/query) and
    /// answers GETs with `get_body`. An empty `Hits` after a call proves that no
    /// outbound request was made.
    async fn recording_sheets_server(get_body: Value) -> (String, Hits) {
        let hits: Hits = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let recorded = hits.clone();
        let app =
            Router::new().fallback(move |method: axum::http::Method, uri: axum::http::Uri| {
                let recorded = recorded.clone();
                let get_body = get_body.clone();
                async move {
                    recorded.lock().push((method.to_string(), uri.to_string()));
                    if method == axum::http::Method::GET {
                        axum::Json(get_body)
                    } else {
                        axum::Json(json!({"ok": true}))
                    }
                }
            });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), hits)
    }

    fn fixture_pins() -> Vec<SheetsPin> {
        vec![SheetsPin::parse(
            PINNED_SPREADSHEET,
            &[
                "Brand!A1:Z100",
                "Sources!A1:Z100",
                "Campaigns!A1:Z100",
                "Pipeline!A1:Z100",
            ],
            &["Pipeline!A:Z"],
        )
        .unwrap()]
    }

    fn pinned_plugin() -> SheetsPlugin {
        SheetsPlugin::with_client(Client::new(), fixture_pins())
    }

    fn unpinned_plugin() -> SheetsPlugin {
        SheetsPlugin::with_client(Client::new(), Vec::new())
    }

    fn read_params(base_url: &str, spreadsheet_id: &str, range: &str) -> Value {
        json!({"base_url": base_url, "spreadsheet_id": spreadsheet_id, "range": range})
    }

    fn append_params(base_url: &str, spreadsheet_id: &str, range: &str) -> Value {
        json!({
            "base_url": base_url,
            "spreadsheet_id": spreadsheet_id,
            "range": range,
            "campaign_id": "camp-1",
            "variant_id": "var-1",
            "channel": "linkedin",
            "account_id": "lucas-linkedin",
            "audience": "builders",
            "content_type": "text",
            "draft_copy": "A sourced draft",
            "row_version": "1",
            "content_hash": test_draft_hash("A sourced draft", ""),
            "source_ids": ["source-1"]
        })
    }

    fn revise_params(base_url: &str, spreadsheet_id: &str, range: &str) -> Value {
        json!({
            "base_url": base_url,
            "spreadsheet_id": spreadsheet_id,
            "range": range,
            "variant_id": "var-1",
            "expected_row_version": "1",
            "draft_copy": "revised",
            "media_brief": "",
            "lucas_notes": "reviewed",
            "content_hash": test_draft_hash("revised", ""),
        })
    }

    async fn run_sheets(
        plugin: &SheetsPlugin,
        action: &str,
        params: Value,
    ) -> Result<ExecuteResponse, PluginError> {
        plugin
            .execute(PluginRequest {
                credential: credential(),
                action: action.into(),
                params,
                context: RequestContext::default(),
            })
            .await
    }

    /// Assert both the preflight (`validate_params`) and a DIRECT `execute`
    /// refuse, and that the upstream saw nothing.
    async fn assert_refused_without_network(
        plugin: &SheetsPlugin,
        hits: &Hits,
        action: &str,
        params: Value,
        why: &str,
    ) {
        assert!(
            plugin.validate_params(action, &params).is_err(),
            "{action} preflight must refuse {why}"
        );
        let result = run_sheets(plugin, action, params).await;
        assert!(
            matches!(result, Err(PluginError::InvalidParams(_))),
            "{action} execute must refuse {why}, got {result:?}"
        );
        assert!(
            hits.lock().is_empty(),
            "{action} must make no outbound request for {why}: {:?}",
            hits.lock()
        );
    }

    /// Range spellings that are NOT the pinned `Pipeline!A1:Z100` read range:
    /// case tricks, whitespace, absolute refs, quoting, `!` injection, R1C1,
    /// whole-sheet and widened ranges, and a different sheet.
    const SNEAKY_READ_RANGES: &[&str] = &[
        "Secrets!A1:Z100",
        "pipeline!A1:Z100",
        "PIPELINE!A1:Z100",
        "Pipeline!a1:z100",
        " Pipeline!A1:Z100",
        "Pipeline!A1:Z100 ",
        "Pipeline! A1:Z100",
        "Pipeline!A1 :Z100",
        "Pipeline!A1:Z100\n",
        "Pipeline!$A$1:$Z$100",
        "'Pipeline'!A1:Z100",
        "Pipeline!A1:Z100!Secrets",
        "Pipeline!Secrets!A1:Z100",
        "Secrets!A1:Z100,Pipeline!A1:Z100",
        "Pipeline!R1C1:R100C26",
        "Pipeline",
        "Pipeline!A:Z",
        "Pipeline!A:ZZ",
        "Pipeline!A1:Z1000",
        "Pipeline!A1:AA100",
        "Pipeline!A1",
        "Pipeline!1:100",
        "Pipeline!A01:Z100",
        "Pipeline!Z100:A1",
        "Pipeline!A1:Z100/../Secrets",
        "Pipeline%21A1%3AZ100",
        "",
    ];

    #[tokio::test]
    async fn sheets_pinned_read_is_the_positive_control() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = pinned_plugin();
        let params = read_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A1:Z100");
        plugin.validate_params("read", &params).unwrap();
        let response = run_sheets(&plugin, "read", params).await.unwrap();
        assert_eq!(response.status, 200);
        let hits = hits.lock();
        assert_eq!(hits.len(), 1, "exactly one upstream read: {hits:?}");
        assert_eq!(hits[0].0, "GET");
        assert!(
            hits[0]
                .1
                .starts_with("/v4/spreadsheets/solo-marketing-fixture/values/Pipeline"),
            "{hits:?}"
        );
    }

    #[tokio::test]
    async fn sheets_read_refuses_a_foreign_spreadsheet_before_network() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = pinned_plugin();
        for foreign in [
            "attacker-spreadsheet",
            "Solo-marketing-fixture",
            "solo-marketing-fixture ",
            "solo-marketing-fixture/values/Secrets!A1:Z9?x=",
            "solo-marketing-fixture%2F..",
            "",
        ] {
            assert_refused_without_network(
                &plugin,
                &hits,
                "read",
                read_params(&base_url, foreign, "Pipeline!A1:Z100"),
                &format!("foreign spreadsheet {foreign:?}"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn sheets_read_refuses_ranges_outside_the_pin_before_network() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = pinned_plugin();
        for range in SNEAKY_READ_RANGES {
            assert_refused_without_network(
                &plugin,
                &hits,
                "read",
                read_params(&base_url, PINNED_SPREADSHEET, range),
                &format!("range {range:?}"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn sheets_append_refuses_foreign_spreadsheet_and_ranges_before_network() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = pinned_plugin();
        assert_refused_without_network(
            &plugin,
            &hits,
            "append_draft",
            append_params(&base_url, "attacker-spreadsheet", "Pipeline!A:Z"),
            "a foreign spreadsheet",
        )
        .await;
        for range in [
            "Secrets!A:Z",
            "pipeline!A:Z",
            "Pipeline!a:z",
            "Pipeline!A:ZZ",
            " Pipeline!A:Z",
            "Pipeline!A:Z!Secrets",
            "Pipeline!C1:R9999",
            "Pipeline",
            // A READ pin is not a write pin.
            "Pipeline!A1:Z100",
        ] {
            assert_refused_without_network(
                &plugin,
                &hits,
                "append_draft",
                append_params(&base_url, PINNED_SPREADSHEET, range),
                &format!("write range {range:?}"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn sheets_revise_refuses_foreign_spreadsheet_and_ranges_before_network() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = pinned_plugin();
        assert_refused_without_network(
            &plugin,
            &hits,
            "revise_draft",
            revise_params(&base_url, "attacker-spreadsheet", "Pipeline!A:Z"),
            "a foreign spreadsheet",
        )
        .await;
        for range in [
            "Secrets!A:Z",
            "PIPELINE!A:Z",
            "Pipeline!A:AA",
            "Pipeline!A1:Z100",
        ] {
            assert_refused_without_network(
                &plugin,
                &hits,
                "revise_draft",
                revise_params(&base_url, PINNED_SPREADSHEET, range),
                &format!("write range {range:?}"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn sheets_with_no_pin_config_refuses_every_action_before_network() {
        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let plugin = unpinned_plugin();
        assert_refused_without_network(
            &plugin,
            &hits,
            "read",
            read_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A1:Z100"),
            "a call with no operator pin configured",
        )
        .await;
        assert_refused_without_network(
            &plugin,
            &hits,
            "append_draft",
            append_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A:Z"),
            "a call with no operator pin configured",
        )
        .await;
        assert_refused_without_network(
            &plugin,
            &hits,
            "revise_draft",
            revise_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A:Z"),
            "a call with no operator pin configured",
        )
        .await;
    }

    #[tokio::test]
    async fn sheets_revise_never_writes_a_row_outside_the_pinned_write_range() {
        // The pinned write range covers only row 1; the variant resolves to
        // row 2, so the adapter must refuse before the PUT.
        let (base_url, hits) = recording_sheets_server(pipeline_get().await.0).await;
        let plugin = SheetsPlugin::with_client(
            Client::new(),
            vec![SheetsPin::parse(PINNED_SPREADSHEET, &[], &["Pipeline!A1:Z2"]).unwrap()],
        );
        // Row 2 IS inside A1:Z2: positive control for the derived write range.
        run_sheets(
            &plugin,
            "revise_draft",
            revise_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A1:Z2"),
        )
        .await
        .unwrap();
        {
            let hits = hits.lock();
            assert_eq!(hits.len(), 2, "{hits:?}");
            assert_eq!(hits[1].0, "PUT");
            assert!(
                hits[1].1.starts_with(
                    "/v4/spreadsheets/solo-marketing-fixture/values/Pipeline%21A2%3AW2?"
                ),
                "{hits:?}"
            );
            drop(hits);
        }
        hits.lock().clear();

        let (base_url, hits) = recording_sheets_server(pipeline_get().await.0).await;
        let plugin = SheetsPlugin::with_client(
            Client::new(),
            vec![SheetsPin::parse(PINNED_SPREADSHEET, &[], &["Pipeline!A1:Z1"]).unwrap()],
        );
        let result = run_sheets(
            &plugin,
            "revise_draft",
            revise_params(&base_url, PINNED_SPREADSHEET, "Pipeline!A1:Z1"),
        )
        .await;
        assert!(result.is_err(), "row 2 is outside Pipeline!A1:Z1");
        assert!(
            hits.lock().iter().all(|(method, _)| method == "GET"),
            "no write may reach the upstream: {:?}",
            hits.lock()
        );
    }

    /// Through the server's enforced execute path (`VultrinoServer::execute_gated`,
    /// which `/api/v1/execute` and MCP `tools/call` both reach) under a policy that
    /// allows every `sheets.*` action: the refusal of a foreign spreadsheet is the
    /// adapter's own, from operator TOML, and happens before any upstream request.
    #[tokio::test]
    async fn server_execute_path_refuses_a_foreign_spreadsheet_from_operator_pins() {
        use crate::auth::{NewUseToken, UseToken};
        use crate::server::{ExecAuth, VultrinoServer};
        use crate::storage::{FileStorage, StorageBackend};
        use crate::{ExecuteRequest, ExecutionOutcome};

        let (base_url, hits) = recording_sheets_server(json!({"values": []})).await;
        let config = crate::config::Config::parse(
            r#"
[[sheets_pins]]
spreadsheet_id = "solo-marketing-fixture"
read_ranges = ["Pipeline!A1:Z100"]
write_ranges = ["Pipeline!A:Z"]

[[policies]]
name = "permissive-sheets"
credential_pattern = "sheets-*"
default_action = "deny"

[[policies.rules]]
action = "allow"
condition = { action_match = "sheets.*" }
"#,
        )
        .expect("operator config parses");

        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn StorageBackend> = Arc::new(
            FileStorage::new(
                &dir.path().join("store.enc"),
                &secrecy::SecretString::from("test-password"),
            )
            .await
            .unwrap(),
        );
        let mut cred = credential();
        cred.alias = "sheets-google".to_string();
        storage.store(&cred).await.unwrap();
        let (_full, token) = UseToken::create(NewUseToken {
            name: "sheets-token".to_string(),
            credential_scope: "sheets-google".to_string(),
            action_scope: Some("sheets.read".to_string()),
            max_uses: None,
            require_approval: false,
            expires_in: None,
        });
        storage.store_use_token(&token).await.unwrap();
        let resolver = crate::router::CredentialResolver::new(storage.clone());
        let server = VultrinoServer::new(config, storage, resolver);

        let run = |spreadsheet: &str| ExecuteRequest {
            credential: "sheets-google".to_string(),
            action: "sheets.read".to_string(),
            params: read_params(&base_url, spreadsheet, "Pipeline!A1:Z100"),
        };

        let refused = server
            .execute_gated(
                run("attacker-spreadsheet"),
                ExecAuth::from_use_token(token.clone()),
            )
            .await;
        assert!(
            refused.is_err(),
            "a foreign spreadsheet must be refused on the execute path"
        );
        assert!(
            hits.lock().is_empty(),
            "the foreign spreadsheet must never reach the upstream: {:?}",
            hits.lock()
        );

        // Positive control: the same token, policy and credential reach the
        // upstream for the operator-pinned spreadsheet, so the refusal above is
        // the pin and not an unrelated denial.
        let allowed = server
            .execute_gated(run(PINNED_SPREADSHEET), ExecAuth::from_use_token(token))
            .await;
        assert!(
            matches!(allowed, Ok(ExecutionOutcome::Completed(_))),
            "pinned spreadsheet must execute, got {allowed:?}"
        );
        assert_eq!(hits.lock().len(), 1);
    }
}
