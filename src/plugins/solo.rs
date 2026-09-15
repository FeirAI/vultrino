//! Typed connector for the Feir learner/session workflow.
//!
//! This module is intentionally self-contained.  Registration is kept outside
//! the file so the connector can be reviewed as one narrow, deny-by-default
//! capability surface.

use super::{Plugin, PluginError, PluginRequest};
use crate::config::SoloPins;
use crate::{Credential, CredentialData, CredentialType, ExecuteResponse, Secret};
use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

const SHEETS_BASE_URL: &str = "https://sheets.googleapis.com/";
const CALENDAR_BASE_URL: &str = "https://www.googleapis.com/calendar/v3/";
const TELEGRAM_BASE_URL: &str = "https://api.telegram.org";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

const COHORTS_RANGE: &str = "Cohorts!A1:K100";
const LEARNERS_RANGE: &str = "Learners!A1:L1000";
const ATTENDANCE_RANGE: &str = "Attendance!A1:K1000";
const KNOWLEDGE_RANGE: &str = "Knowledge!A1:H200";

const FEIR_APPROVAL_ACTOR: &str = "feir_approval";
const EVENT_ID_HEX_LEN: usize = 32;
const MAX_RESPONSE_HEADERS: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearnerReadParams {
    base_url: String,
    spreadsheet_id: String,
    range: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttendanceUpdateParams {
    base_url: String,
    spreadsheet_id: String,
    range: String,
    attendance_id: String,
    learner_id: String,
    session_id: String,
    cohort_id: String,
    expected_row_version: String,
    status: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionListParams {
    base_url: String,
    calendar_id: String,
    time_min: String,
    time_max: String,
    timezone: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailabilityCheckParams {
    base_url: String,
    calendar_id: String,
    time_min: String,
    time_max: String,
    timezone: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCreateParams {
    base_url: String,
    calendar_id: String,
    session_id: String,
    cohort_id: String,
    title: String,
    description: String,
    start_at: String,
    end_at: String,
    timezone: String,
    #[serde(default)]
    meeting_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionUpdateParams {
    base_url: String,
    calendar_id: String,
    event_id: String,
    expected_etag: String,
    session_id: String,
    cohort_id: String,
    title: String,
    description: String,
    start_at: String,
    end_at: String,
    timezone: String,
    #[serde(default)]
    meeting_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCancelParams {
    base_url: String,
    calendar_id: String,
    event_id: String,
    expected_etag: String,
    session_id: String,
    cohort_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LearnerMessageSendParams {
    recipient_ref: String,
    learner_id: String,
    session_id: String,
    message_body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelegramSecretDocument {
    bot_token: String,
    recipients: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

struct GoogleResponse {
    response: ExecuteResponse,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct AttendanceColumns {
    attendance_id: usize,
    learner_id: usize,
    session_id: usize,
    cohort_id: usize,
    status: usize,
    confirmed_at: usize,
    notes: usize,
    row_version: usize,
    updated_at: usize,
    updated_by: usize,
}

const FIXED_ATTENDANCE_COLUMNS: AttendanceColumns = AttendanceColumns {
    attendance_id: 0,
    learner_id: 1,
    session_id: 2,
    cohort_id: 3,
    status: 4,
    confirmed_at: 5,
    notes: 6,
    row_version: 7,
    updated_at: 8,
    updated_by: 9,
};

fn invalid(message: impl Into<String>) -> PluginError {
    PluginError::InvalidParams(message.into())
}

fn validate_text(name: &str, value: &str, max_chars: usize) -> Result<(), PluginError> {
    if value.is_empty() || value.chars().count() > max_chars {
        return Err(invalid(format!(
            "{name} must be non-empty and at most {max_chars} characters"
        )));
    }
    if value.chars().any(|ch| ch == '\0') {
        return Err(invalid(format!(
            "{name} contains a forbidden control character"
        )));
    }
    Ok(())
}

fn validate_optional_text(
    name: &str,
    value: Option<&str>,
    max_chars: usize,
) -> Result<(), PluginError> {
    if let Some(value) = value {
        if value.is_empty() {
            return Err(invalid(format!("{name} cannot be empty when provided")));
        }
        validate_text(name, value, max_chars)?;
    }
    Ok(())
}

fn validate_base_url(raw: &str, expected: &str) -> Result<Url, PluginError> {
    // Unit tests only: a loopback mock upstream stands in for Google so the
    // adapter can be exercised end to end without live calls.
    let test_loopback = cfg!(test)
        && Url::parse(raw)
            .is_ok_and(|url| url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
    if raw != expected && !test_loopback {
        return Err(invalid(format!("base_url must be exactly {expected}")));
    }
    Url::parse(raw).map_err(|_| invalid("base_url is not a valid HTTPS URL"))
}

fn validate_id(name: &str, value: &str) -> Result<(), PluginError> {
    validate_text(name, value, 256)
}

fn validate_sheet_params(base_url: &str, spreadsheet_id: &str) -> Result<(), PluginError> {
    validate_base_url(base_url, SHEETS_BASE_URL)?;
    validate_id("spreadsheet_id", spreadsheet_id)
}

fn validate_calendar_id(value: &str) -> Result<(), PluginError> {
    validate_text("calendar_id", value, 512)
}

fn validate_calendar_base(base_url: &str, calendar_id: &str) -> Result<(), PluginError> {
    validate_base_url(base_url, CALENDAR_BASE_URL)?;
    validate_calendar_id(calendar_id)
}

fn parse_rfc3339(name: &str, value: &str) -> Result<DateTime<Utc>, PluginError> {
    validate_text(name, value, 64)?;
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| invalid(format!("{name} must be RFC3339")))
}

fn validate_window(time_min: &str, time_max: &str) -> Result<(), PluginError> {
    let start = parse_rfc3339("time_min", time_min)?;
    let end = parse_rfc3339("time_max", time_max)?;
    validate_ordered_window(start, end)
}

fn validate_ordered_window(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<(), PluginError> {
    if start >= end {
        return Err(invalid("time_min/start must be before time_max/end"));
    }
    if end - start > Duration::days(31) {
        return Err(invalid("calendar windows may not exceed 31 days"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_session_fields(
    session_id: &str,
    cohort_id: &str,
    title: &str,
    description: &str,
    start: &str,
    end: &str,
    timezone: &str,
    meeting_url: Option<&str>,
) -> Result<(), PluginError> {
    validate_id("session_id", session_id)?;
    validate_id("cohort_id", cohort_id)?;
    validate_text("title", title, 200)?;
    validate_text("description", description, 4_000)?;
    let start = parse_rfc3339("start_at", start)?;
    let end = parse_rfc3339("end_at", end)?;
    validate_ordered_window(start, end)?;
    validate_text("timezone", timezone, 128)?;
    validate_optional_text("meeting_url", meeting_url, 2048)?;
    if let Some(meeting_url) = meeting_url {
        let parsed = Url::parse(meeting_url)
            .map_err(|_| invalid("meeting_url must be a valid HTTPS URL"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(invalid(
                "meeting_url must be an HTTPS URL without embedded credentials",
            ));
        }
    }
    Ok(())
}

fn validate_expected_row_version(value: &str) -> Result<u64, PluginError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| invalid("expected_row_version must be a positive decimal integer"))?;
    if parsed == 0 {
        return Err(invalid(
            "expected_row_version must be a positive decimal integer",
        ));
    }
    Ok(parsed)
}

fn validate_attendance_update(p: &AttendanceUpdateParams) -> Result<(), PluginError> {
    validate_sheet_params(&p.base_url, &p.spreadsheet_id)?;
    if p.range != ATTENDANCE_RANGE {
        return Err(invalid("range must be the pinned Attendance range"));
    }
    validate_id("attendance_id", &p.attendance_id)?;
    validate_id("learner_id", &p.learner_id)?;
    validate_id("session_id", &p.session_id)?;
    validate_id("cohort_id", &p.cohort_id)?;
    validate_expected_row_version(&p.expected_row_version)?;
    if !matches!(
        p.status.as_str(),
        "Confirmed" | "Declined" | "Attended" | "Absent"
    ) {
        return Err(invalid(
            "status must be Confirmed, Declined, Attended, or Absent",
        ));
    }
    validate_optional_text("notes", p.notes.as_deref(), 2_000)
}

fn validate_message_params(p: &LearnerMessageSendParams) -> Result<(), PluginError> {
    validate_id("recipient_ref", &p.recipient_ref)?;
    validate_id("learner_id", &p.learner_id)?;
    validate_id("session_id", &p.session_id)?;
    if p.message_body.is_empty() || p.message_body.chars().count() > 4096 {
        return Err(invalid(
            "message_body must be non-empty and at most 4096 characters",
        ));
    }
    if p.message_body.chars().any(|ch| ch == '\0') {
        return Err(invalid(
            "message_body contains a forbidden control character",
        ));
    }
    Ok(())
}

fn validate_telegram_document(raw: &str) -> Result<TelegramSecretDocument, PluginError> {
    if raw.chars().count() > 32_768 {
        return Err(invalid("UrlToken document is too large"));
    }
    let document: TelegramSecretDocument = serde_json::from_str(raw)
        .map_err(|_| invalid("UrlToken is not a valid Telegram document"))?;
    if document.bot_token.is_empty()
        || document.bot_token.chars().count() > 256
        || !document
            .bot_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
    {
        return Err(invalid("Telegram bot_token has an invalid shape"));
    }
    if document.recipients.is_empty() || document.recipients.len() > 256 {
        return Err(invalid("Telegram recipients must contain 1 to 256 entries"));
    }
    for (recipient_ref, chat_id) in &document.recipients {
        validate_id("recipient_ref", recipient_ref)?;
        validate_text("chat_id", chat_id, 128)?;
    }
    Ok(document)
}

fn lookup_recipient_chat_id<'a>(
    document: &'a TelegramSecretDocument,
    recipient_ref: &str,
) -> Result<&'a str, PluginError> {
    document
        .recipients
        .get(recipient_ref)
        .map(String::as_str)
        .ok_or_else(|| invalid("recipient_ref is not present in the UrlToken recipient map"))
}

fn deterministic_event_id(session_id: &str) -> String {
    let digest = Sha256::digest(session_id.as_bytes());
    hex::encode(digest)[..EVENT_ID_HEX_LEN].to_string()
}

fn normalized_header(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-' && *ch != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn column_from_headers(headers: &[Value], name: &str) -> Option<usize> {
    headers.iter().position(|value| {
        value
            .as_str()
            .map(normalized_header)
            .is_some_and(|header| header == normalized_header(name))
    })
}

fn attendance_columns(values: &[Value]) -> (usize, AttendanceColumns) {
    let Some(headers) = values.first().and_then(Value::as_array) else {
        return (0, FIXED_ATTENDANCE_COLUMNS);
    };
    let names = [
        "attendance_id",
        "learner_id",
        "session_id",
        "cohort_id",
        "status",
        "confirmed_at",
        "notes",
        "row_version",
        "updated_at",
        "updated_by",
    ];
    let columns: Vec<usize> = names
        .iter()
        .filter_map(|name| column_from_headers(headers, name))
        .collect();
    if columns.len() != names.len() {
        return (0, FIXED_ATTENDANCE_COLUMNS);
    }
    (
        1,
        AttendanceColumns {
            attendance_id: columns[0],
            learner_id: columns[1],
            session_id: columns[2],
            cohort_id: columns[3],
            status: columns[4],
            confirmed_at: columns[5],
            notes: columns[6],
            row_version: columns[7],
            updated_at: columns[8],
            updated_by: columns[9],
        },
    )
}

fn cell_text(row: &[Value], index: usize) -> Option<String> {
    row.get(index).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

fn next_row_version(current: &str, expected: u64) -> Result<String, PluginError> {
    let current = current.parse::<u64>().map_err(|_| {
        PluginError::ExecutionFailed("Attendance row has an invalid row_version".into())
    })?;
    if current != expected {
        return Err(invalid(format!(
            "stale attendance row_version: expected {expected}, current {current}"
        )));
    }
    expected
        .checked_add(1)
        .map(|version| version.to_string())
        .ok_or_else(|| invalid("attendance row_version overflow"))
}

fn set_cell(row: &mut [Value], index: usize, value: Value) -> Result<(), PluginError> {
    let cell = row.get_mut(index).ok_or_else(|| {
        PluginError::ExecutionFailed("Attendance row is missing a required column".into())
    })?;
    *cell = value;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn event_body(
    event_id: Option<&str>,
    session_id: &str,
    cohort_id: &str,
    title: &str,
    description: &str,
    start: &str,
    end: &str,
    timezone: &str,
    meeting_url: Option<&str>,
    include_status: bool,
    clear_missing_location: bool,
) -> Value {
    let mut body = Map::new();
    if let Some(event_id) = event_id {
        body.insert("id".into(), Value::String(event_id.to_string()));
    }
    body.insert("summary".into(), Value::String(title.to_string()));
    body.insert("description".into(), Value::String(description.to_string()));
    body.insert(
        "start".into(),
        json!({"dateTime": start, "timeZone": timezone}),
    );
    body.insert("end".into(), json!({"dateTime": end, "timeZone": timezone}));
    if let Some(meeting_url) = meeting_url {
        body.insert("location".into(), Value::String(meeting_url.to_string()));
    } else if clear_missing_location {
        body.insert("location".into(), Value::Null);
    }
    body.insert(
        "extendedProperties".into(),
        json!({"private": {
            "feir_session_id": session_id,
            "feir_cohort_id": cohort_id
        }}),
    );
    if include_status {
        body.insert("status".into(), Value::String("confirmed".into()));
    }
    Value::Object(body)
}

fn verify_calendar_event_binding(
    body: &[u8],
    expected_etag: &str,
    session_id: &str,
    cohort_id: &str,
) -> Result<(), PluginError> {
    let event: Value = serde_json::from_slice(body)
        .map_err(|_| PluginError::ExecutionFailed("Calendar event was not valid JSON".into()))?;
    let actual_etag = event.get("etag").and_then(Value::as_str).ok_or_else(|| {
        PluginError::ExecutionFailed("Calendar event did not contain an ETag".into())
    })?;
    if actual_etag != expected_etag {
        return Err(invalid(
            "Calendar event ETag does not match the approval's expected ETag",
        ));
    }
    let private = event
        .pointer("/extendedProperties/private")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid("Calendar event is missing Feir session metadata; refusing mutation")
        })?;
    if private.get("feir_session_id").and_then(Value::as_str) != Some(session_id) {
        return Err(invalid(
            "Calendar event session_id does not match the requested session",
        ));
    }
    if private.get("feir_cohort_id").and_then(Value::as_str) != Some(cohort_id) {
        return Err(invalid(
            "Calendar event cohort_id does not match the requested cohort",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verified_calendar_mutation(
    client: &Client,
    event_url: Url,
    token: &str,
    expected_etag: &str,
    session_id: &str,
    cohort_id: &str,
    method: Method,
    body: Option<Value>,
) -> Result<GoogleResponse, PluginError> {
    let current = send_google(client, Method::GET, event_url.clone(), token, None, None).await?;
    verify_calendar_event_binding(&current.body, expected_etag, session_id, cohort_id)?;
    let mut if_match = HeaderMap::new();
    if_match.insert(
        IF_MATCH,
        HeaderValue::try_from(expected_etag)
            .map_err(|_| invalid("expected_etag cannot form If-Match"))?,
    );
    send_google(client, method, event_url, token, body, Some(if_match)).await
}

fn safe_response_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.as_str(),
                "content-type" | "etag" | "location" | "retry-after"
            )
        })
        .take(MAX_RESPONSE_HEADERS)
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn bearer_headers(token: &str, content_type: bool) -> Result<HeaderMap, PluginError> {
    let mut headers = HeaderMap::new();
    let auth = HeaderValue::try_from(format!("Bearer {token}"))
        .map_err(|_| invalid("OAuth access token cannot form an Authorization header"))?;
    headers.insert(AUTHORIZATION, auth);
    if content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    Ok(headers)
}

async fn send_google(
    client: &Client,
    method: Method,
    url: Url,
    token: &str,
    body: Option<Value>,
    extra_headers: Option<HeaderMap>,
) -> Result<GoogleResponse, PluginError> {
    let mut headers = bearer_headers(token, body.is_some())?;
    if let Some(extra_headers) = extra_headers {
        headers.extend(extra_headers);
    }
    let mut request = client
        .request(method, url)
        .timeout(crate::plugins::REQUEST_TIMEOUT)
        .headers(headers);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| PluginError::Http(error.without_url().to_string()))?;
    let status = response.status();
    let response_headers = safe_response_headers(response.headers());
    let response_body = crate::plugins::read_body_capped(response).await?;
    if !status.is_success() {
        return Err(PluginError::ExecutionFailed(format!(
            "Google upstream returned HTTP {}",
            status.as_u16()
        )));
    }
    Ok(GoogleResponse {
        response: ExecuteResponse::new(status.as_u16(), response_headers, response_body.clone()),
        body: response_body,
    })
}

fn attach_credential_update(
    response: ExecuteResponse,
    updated: Option<CredentialData>,
) -> ExecuteResponse {
    updated.map_or(response.clone(), |credential| {
        response.with_updated_credential(credential)
    })
}

fn token_is_stale(access_token: Option<&Secret>, expires_at: Option<DateTime<Utc>>) -> bool {
    match access_token {
        None => true,
        Some(_) => expires_at.is_some_and(|expires| Utc::now() + Duration::seconds(300) >= expires),
    }
}

async fn refresh_google_token(
    client: &Client,
    client_id: &str,
    client_secret: &Secret,
    refresh_token: &Secret,
    scopes: &[String],
) -> Result<OAuthTokenResponse, PluginError> {
    let token_url = Url::parse(GOOGLE_TOKEN_URL).expect("Google token URL is valid");
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.expose().to_string()),
        ("client_id", client_id.to_string()),
        ("client_secret", client_secret.expose().to_string()),
    ];
    if !scopes.is_empty() {
        form.push(("scope", scopes.join(" ")));
    }
    let response = client
        .post(token_url)
        .timeout(crate::plugins::REQUEST_TIMEOUT)
        .form(&form)
        .send()
        .await
        .map_err(|error| PluginError::Http(error.without_url().to_string()))?;
    let status = response.status();
    let body = crate::plugins::read_body_capped(response).await?;
    if !status.is_success() {
        return Err(PluginError::ExecutionFailed(format!(
            "Google OAuth token refresh returned HTTP {}",
            status.as_u16()
        )));
    }
    let token: OAuthTokenResponse = serde_json::from_slice(&body).map_err(|_| {
        PluginError::ExecutionFailed("Google OAuth token response was invalid".into())
    })?;
    if token.access_token.is_empty() {
        return Err(PluginError::ExecutionFailed(
            "Google OAuth token response did not contain an access token".into(),
        ));
    }
    Ok(token)
}

async fn effective_google_credential(
    client: &Client,
    credential: &Credential,
) -> Result<(Credential, Option<CredentialData>, String), PluginError> {
    let CredentialData::OAuth2 {
        client_id,
        client_secret,
        refresh_token,
        access_token,
        expires_at,
        token_url,
        scopes,
    } = &credential.data
    else {
        return Err(PluginError::UnsupportedCredentialType(
            "solo Sheets/Calendar actions require OAuth2".into(),
        ));
    };
    if token_url != GOOGLE_TOKEN_URL {
        return Err(invalid(format!(
            "OAuth token_url must be exactly {GOOGLE_TOKEN_URL}"
        )));
    }
    if !token_is_stale(access_token.as_ref(), *expires_at) {
        return Ok((
            credential.clone(),
            None,
            access_token.as_ref().unwrap().expose().into(),
        ));
    }
    let refresh_token = refresh_token.as_ref().ok_or_else(|| {
        invalid("refresh_token is required when the OAuth access token is missing or expired")
    })?;
    let token =
        refresh_google_token(client, client_id, client_secret, refresh_token, scopes).await?;
    let expires_at = token.expires_in.and_then(|seconds| {
        i64::try_from(seconds)
            .ok()
            .and_then(Duration::try_seconds)
            .and_then(|duration| Utc::now().checked_add_signed(duration))
    });
    let updated_data = CredentialData::OAuth2 {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
        refresh_token: token
            .refresh_token
            .map(Secret::new)
            .or_else(|| Some(refresh_token.clone())),
        access_token: Some(Secret::new(token.access_token.clone())),
        expires_at,
        token_url: token_url.clone(),
        scopes: scopes.clone(),
    };
    let mut effective = credential.clone();
    effective.data = updated_data.clone();
    effective.updated_at = Utc::now();
    Ok((effective, Some(updated_data), token.access_token))
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: &Value) -> Result<T, PluginError> {
    serde_json::from_value(params.clone()).map_err(|error| invalid(error.to_string()))
}

fn pin_refusal(message: &str) -> PluginError {
    PluginError::InvalidParams(format!("solo pin: {message}"))
}

/// The spreadsheet id must byte-exactly equal an operator `[solo_pins]`
/// learner spreadsheet id. Runs before format checks, credential use, or I/O.
fn require_pinned_spreadsheet(pins: &SoloPins, spreadsheet_id: &str) -> Result<(), PluginError> {
    if pins.learner_spreadsheet_ids.is_empty() {
        return Err(pin_refusal(
            "no learner spreadsheet is operator-pinned ([solo_pins] learner_spreadsheet_ids is empty); every solo Sheets call is refused",
        ));
    }
    if !pins.allows_learner_spreadsheet(spreadsheet_id) {
        return Err(pin_refusal("spreadsheet_id is not operator-pinned"));
    }
    Ok(())
}

/// The Calendar id must byte-exactly equal an operator `[solo_pins]` Calendar
/// id. Runs before format checks, credential use, or I/O.
fn require_pinned_calendar(pins: &SoloPins, calendar_id: &str) -> Result<(), PluginError> {
    if pins.calendar_ids.is_empty() {
        return Err(pin_refusal(
            "no calendar is operator-pinned ([solo_pins] calendar_ids is empty); every solo Calendar call is refused",
        ));
    }
    if !pins.allows_calendar(calendar_id) {
        return Err(pin_refusal("calendar_id is not operator-pinned"));
    }
    Ok(())
}

fn validate_typed(pins: &SoloPins, action: &str, params: &Value) -> Result<(), PluginError> {
    match action {
        "learner_read" => {
            let p: LearnerReadParams = parse_params(params)?;
            require_pinned_spreadsheet(pins, &p.spreadsheet_id)?;
            validate_sheet_params(&p.base_url, &p.spreadsheet_id)?;
            if !matches!(
                p.range.as_str(),
                COHORTS_RANGE | LEARNERS_RANGE | ATTENDANCE_RANGE | KNOWLEDGE_RANGE
            ) {
                return Err(invalid(
                    "range is not one of the four pinned learner ranges",
                ));
            }
            Ok(())
        }
        "attendance_update" => {
            let p: AttendanceUpdateParams = parse_params(params)?;
            require_pinned_spreadsheet(pins, &p.spreadsheet_id)?;
            validate_attendance_update(&p)
        }
        "session_list" => {
            let p: SessionListParams = parse_params(params)?;
            require_pinned_calendar(pins, &p.calendar_id)?;
            validate_calendar_base(&p.base_url, &p.calendar_id)?;
            validate_text("timezone", &p.timezone, 128)?;
            validate_window(&p.time_min, &p.time_max)
        }
        "availability_check" => {
            let p: AvailabilityCheckParams = parse_params(params)?;
            require_pinned_calendar(pins, &p.calendar_id)?;
            validate_calendar_base(&p.base_url, &p.calendar_id)?;
            validate_text("timezone", &p.timezone, 128)?;
            validate_window(&p.time_min, &p.time_max)
        }
        "session_create" => {
            let p: SessionCreateParams = parse_params(params)?;
            require_pinned_calendar(pins, &p.calendar_id)?;
            validate_calendar_base(&p.base_url, &p.calendar_id)?;
            validate_session_fields(
                &p.session_id,
                &p.cohort_id,
                &p.title,
                &p.description,
                &p.start_at,
                &p.end_at,
                &p.timezone,
                p.meeting_url.as_deref(),
            )
        }
        "session_update" => {
            let p: SessionUpdateParams = parse_params(params)?;
            require_pinned_calendar(pins, &p.calendar_id)?;
            validate_calendar_base(&p.base_url, &p.calendar_id)?;
            validate_id("event_id", &p.event_id)?;
            validate_text("expected_etag", &p.expected_etag, 1024)?;
            validate_session_fields(
                &p.session_id,
                &p.cohort_id,
                &p.title,
                &p.description,
                &p.start_at,
                &p.end_at,
                &p.timezone,
                p.meeting_url.as_deref(),
            )
        }
        "session_cancel" => {
            let p: SessionCancelParams = parse_params(params)?;
            require_pinned_calendar(pins, &p.calendar_id)?;
            validate_calendar_base(&p.base_url, &p.calendar_id)?;
            validate_id("event_id", &p.event_id)?;
            validate_text("expected_etag", &p.expected_etag, 1024)?;
            validate_id("session_id", &p.session_id)?;
            validate_id("cohort_id", &p.cohort_id)
        }
        "learner_message_send" => {
            let p: LearnerMessageSendParams = parse_params(params)?;
            validate_message_params(&p)
        }
        other => Err(PluginError::UnsupportedAction(other.to_string())),
    }
}

pub struct SoloPlugin {
    client: Client,
    /// Operator pins from `[solo_pins]`. Empty = every Sheets/Calendar call is refused.
    pins: Arc<SoloPins>,
}

impl SoloPlugin {
    /// Build the adapter over the operator's pins. Empty pins are legal and
    /// mean every Sheets and Calendar call is refused (fail closed).
    pub fn new(pins: SoloPins) -> Self {
        Self::with_client(crate::plugins::build_guarded_client(), pins)
    }

    fn with_client(client: Client, pins: SoloPins) -> Self {
        Self {
            client,
            pins: Arc::new(pins),
        }
    }

    async fn execute_typed(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        validate_typed(&self.pins, &request.action, &request.params)?;
        // Every Sheets/Calendar arm re-checks its operator pin immediately
        // after parsing: before credential refresh and before any request.
        match request.action.as_str() {
            "learner_read" => {
                let p: LearnerReadParams = parse_params(&request.params)?;
                require_pinned_spreadsheet(&self.pins, &p.spreadsheet_id)?;
                let base = validate_base_url(&p.base_url, SHEETS_BASE_URL)?;
                let (_credential, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(&p.range)
                    ))
                    .map_err(|_| invalid("could not construct Sheets URL"))?;
                let response =
                    send_google(&self.client, Method::GET, url, &token, None, None).await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "attendance_update" => {
                let p: AttendanceUpdateParams = parse_params(&request.params)?;
                require_pinned_spreadsheet(&self.pins, &p.spreadsheet_id)?;
                let base = validate_base_url(&p.base_url, SHEETS_BASE_URL)?;
                let expected = validate_expected_row_version(&p.expected_row_version)?;
                let (_credential, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let read_url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/{}",
                        urlencoding::encode(&p.spreadsheet_id),
                        urlencoding::encode(ATTENDANCE_RANGE)
                    ))
                    .map_err(|_| invalid("could not construct Attendance read URL"))?;
                let read =
                    send_google(&self.client, Method::GET, read_url, &token, None, None).await?;
                let document: Value = serde_json::from_slice(&read.body).map_err(|_| {
                    PluginError::ExecutionFailed("Attendance read was not valid JSON".into())
                })?;
                let values = document
                    .get("values")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        PluginError::ExecutionFailed("Attendance read had no values".into())
                    })?;
                let (first_data_row, columns) = attendance_columns(values);
                let (row_number, mut row) = values
                    .iter()
                    .enumerate()
                    .skip(first_data_row)
                    .find_map(|(index, value)| {
                        let row = value.as_array()?;
                        (cell_text(row, columns.attendance_id).as_deref()
                            == Some(p.attendance_id.as_str()))
                        .then(|| (index + 1, row.clone()))
                    })
                    .ok_or_else(|| invalid("attendance_id was not found in the pinned range"))?;
                for (name, index, expected_value) in [
                    ("learner_id", columns.learner_id, p.learner_id.as_str()),
                    ("session_id", columns.session_id, p.session_id.as_str()),
                    ("cohort_id", columns.cohort_id, p.cohort_id.as_str()),
                ] {
                    if cell_text(&row, index).as_deref() != Some(expected_value) {
                        return Err(invalid(format!(
                            "attendance row {name} does not match request"
                        )));
                    }
                }
                let current_version = cell_text(&row, columns.row_version).ok_or_else(|| {
                    PluginError::ExecutionFailed("Attendance row has no row_version".into())
                })?;
                let next_version = next_row_version(&current_version, expected)?;
                let next_confirmed_at = if p.status == "Confirmed" {
                    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
                } else {
                    cell_text(&row, columns.confirmed_at).unwrap_or_default()
                };
                set_cell(&mut row, columns.status, Value::String(p.status))?;
                set_cell(
                    &mut row,
                    columns.confirmed_at,
                    Value::String(next_confirmed_at),
                )?;
                set_cell(
                    &mut row,
                    columns.notes,
                    Value::String(p.notes.unwrap_or_default()),
                )?;
                set_cell(&mut row, columns.row_version, Value::String(next_version))?;
                set_cell(
                    &mut row,
                    columns.updated_at,
                    Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
                )?;
                set_cell(
                    &mut row,
                    columns.updated_by,
                    Value::String(FEIR_APPROVAL_ACTOR.into()),
                )?;
                let write_url = base
                    .join(&format!(
                        "v4/spreadsheets/{}/values/Attendance!A{}:K{}?valueInputOption=RAW",
                        urlencoding::encode(&p.spreadsheet_id),
                        row_number,
                        row_number
                    ))
                    .map_err(|_| invalid("could not construct Attendance write URL"))?;
                let write = send_google(
                    &self.client,
                    Method::PUT,
                    write_url,
                    &token,
                    Some(json!({"values": [row]})),
                    None,
                )
                .await?;
                Ok(attach_credential_update(write.response, updated))
            }
            "session_list" => {
                let p: SessionListParams = parse_params(&request.params)?;
                require_pinned_calendar(&self.pins, &p.calendar_id)?;
                let base = validate_base_url(&p.base_url, CALENDAR_BASE_URL)?;
                let (_, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let mut url = base
                    .join(&format!(
                        "calendars/{}/events",
                        urlencoding::encode(&p.calendar_id)
                    ))
                    .map_err(|_| invalid("could not construct Calendar events URL"))?;
                url.set_query(Some(
                    &url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("timeMin", &p.time_min)
                        .append_pair("timeMax", &p.time_max)
                        .append_pair("timeZone", &p.timezone)
                        .append_pair("singleEvents", "true")
                        .append_pair("orderBy", "startTime")
                        .finish(),
                ));
                let response =
                    send_google(&self.client, Method::GET, url, &token, None, None).await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "availability_check" => {
                let p: AvailabilityCheckParams = parse_params(&request.params)?;
                require_pinned_calendar(&self.pins, &p.calendar_id)?;
                let base = validate_base_url(&p.base_url, CALENDAR_BASE_URL)?;
                let (_, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let url = base
                    .join("freeBusy")
                    .map_err(|_| invalid("could not construct freeBusy URL"))?;
                let response = send_google(
                    &self.client,
                    Method::POST,
                    url,
                    &token,
                    Some(json!({
                        "timeMin": p.time_min,
                        "timeMax": p.time_max,
                        "timeZone": p.timezone,
                        "items": [{"id": p.calendar_id}]
                    })),
                    None,
                )
                .await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "session_create" => {
                let p: SessionCreateParams = parse_params(&request.params)?;
                require_pinned_calendar(&self.pins, &p.calendar_id)?;
                let base = validate_base_url(&p.base_url, CALENDAR_BASE_URL)?;
                let (_, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let url = base
                    .join(&format!(
                        "calendars/{}/events",
                        urlencoding::encode(&p.calendar_id)
                    ))
                    .map_err(|_| invalid("could not construct Calendar events URL"))?;
                let body = event_body(
                    Some(&deterministic_event_id(&p.session_id)),
                    &p.session_id,
                    &p.cohort_id,
                    &p.title,
                    &p.description,
                    &p.start_at,
                    &p.end_at,
                    &p.timezone,
                    p.meeting_url.as_deref(),
                    true,
                    false,
                );
                let response =
                    send_google(&self.client, Method::POST, url, &token, Some(body), None).await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "session_update" => {
                let p: SessionUpdateParams = parse_params(&request.params)?;
                require_pinned_calendar(&self.pins, &p.calendar_id)?;
                let base = validate_base_url(&p.base_url, CALENDAR_BASE_URL)?;
                let (_, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let url = base
                    .join(&format!(
                        "calendars/{}/events/{}",
                        urlencoding::encode(&p.calendar_id),
                        urlencoding::encode(&p.event_id)
                    ))
                    .map_err(|_| invalid("could not construct Calendar event URL"))?;
                let body = event_body(
                    None,
                    &p.session_id,
                    &p.cohort_id,
                    &p.title,
                    &p.description,
                    &p.start_at,
                    &p.end_at,
                    &p.timezone,
                    p.meeting_url.as_deref(),
                    false,
                    true,
                );
                let response = verified_calendar_mutation(
                    &self.client,
                    url,
                    &token,
                    &p.expected_etag,
                    &p.session_id,
                    &p.cohort_id,
                    Method::PATCH,
                    Some(body),
                )
                .await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "session_cancel" => {
                let p: SessionCancelParams = parse_params(&request.params)?;
                require_pinned_calendar(&self.pins, &p.calendar_id)?;
                let base = validate_base_url(&p.base_url, CALENDAR_BASE_URL)?;
                let (_, updated, token) =
                    effective_google_credential(&self.client, &request.credential).await?;
                let url = base
                    .join(&format!(
                        "calendars/{}/events/{}",
                        urlencoding::encode(&p.calendar_id),
                        urlencoding::encode(&p.event_id)
                    ))
                    .map_err(|_| invalid("could not construct Calendar event URL"))?;
                let response = verified_calendar_mutation(
                    &self.client,
                    url,
                    &token,
                    &p.expected_etag,
                    &p.session_id,
                    &p.cohort_id,
                    Method::DELETE,
                    None,
                )
                .await?;
                Ok(attach_credential_update(response.response, updated))
            }
            "learner_message_send" => {
                let p: LearnerMessageSendParams = parse_params(&request.params)?;
                let CredentialData::UrlToken { token } = &request.credential.data else {
                    return Err(PluginError::UnsupportedCredentialType(
                        "learner_message_send requires a UrlToken credential".into(),
                    ));
                };
                let document = validate_telegram_document(token.expose())?;
                let chat_id = lookup_recipient_chat_id(&document, &p.recipient_ref)?;
                let url = Url::parse(&format!(
                    "{TELEGRAM_BASE_URL}/bot{}/sendMessage",
                    document.bot_token
                ))
                .map_err(|_| invalid("could not construct Telegram URL"))?;
                let response = self
                    .client
                    .post(url)
                    .timeout(crate::plugins::REQUEST_TIMEOUT)
                    .header(CONTENT_TYPE, "application/json")
                    .json(&json!({"chat_id": chat_id, "text": p.message_body}))
                    .send()
                    .await
                    .map_err(|error| PluginError::Http(error.without_url().to_string()))?;
                let status = response.status();
                let body = crate::plugins::read_body_capped(response).await?;
                if !status.is_success() {
                    return Err(PluginError::ExecutionFailed(format!(
                        "Telegram upstream returned HTTP {}",
                        status.as_u16()
                    )));
                }
                let telegram: Value = serde_json::from_slice(&body).map_err(|_| {
                    PluginError::ExecutionFailed("Telegram response was not valid JSON".into())
                })?;
                let ok = telegram.get("ok").and_then(Value::as_bool).unwrap_or(false);
                let message_id = telegram
                    .pointer("/result/message_id")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| {
                        PluginError::ExecutionFailed("Telegram response had no message_id".into())
                    })?;
                if !ok {
                    return Err(PluginError::ExecutionFailed(
                        "Telegram rejected the learner message".into(),
                    ));
                }
                let receipt = json!({
                    "ok": true,
                    "message_id": message_id,
                    "recipient_ref": p.recipient_ref,
                    "sent_at": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
                });
                let mut headers = HashMap::new();
                headers.insert("content-type".into(), "application/json".into());
                Ok(ExecuteResponse::new(
                    status.as_u16(),
                    headers,
                    serde_json::to_vec(&receipt).expect("receipt is serializable"),
                ))
            }
            other => Err(PluginError::UnsupportedAction(other.to_string())),
        }
    }
}

impl Default for SoloPlugin {
    /// No pins: every Sheets and Calendar call is refused.
    fn default() -> Self {
        Self::new(SoloPins::default())
    }
}

#[async_trait]
impl Plugin for SoloPlugin {
    fn name(&self) -> &str {
        "solo"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::OAuth2, CredentialType::UrlToken]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec![
            "learner_read",
            "attendance_update",
            "session_list",
            "availability_check",
            "session_create",
            "session_update",
            "session_cancel",
            "learner_message_send",
        ]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.execute_typed(request).await
    }

    fn validate_params(&self, action: &str, params: &Value) -> Result<(), PluginError> {
        validate_typed(&self.pins, action, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::any, Json, Router};
    use reqwest::Client;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// The pre-pin unit tests below target these ids; this shim keeps their
    /// field-validation meaning while the adapter now requires pins.
    fn validate_typed(action: &str, params: &Value) -> Result<(), PluginError> {
        let pins = SoloPins::parse(
            &["sheet-1".to_string()],
            &["calendar@example.com".to_string()],
        )
        .unwrap();
        super::validate_typed(&pins, action, params)
    }

    fn valid_session(action: &str) -> Value {
        let common = json!({
            "base_url": CALENDAR_BASE_URL,
            "calendar_id": "calendar@example.com",
            "session_id": "session-1",
            "cohort_id": "cohort-1",
            "title": "Office hours",
            "description": "A bounded description",
            "start_at": "2026-09-07T10:00:00Z",
            "end_at": "2026-09-07T11:00:00Z",
            "timezone": "Europe/Lisbon"
        });
        match action {
            "session_create" => common,
            "session_update" => {
                let mut object = common.as_object().unwrap().clone();
                object.insert("event_id".into(), json!("event-1"));
                object.insert("expected_etag".into(), json!("\"etag-1\""));
                Value::Object(object)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn supported_action_and_credential_sets_are_exact() {
        let plugin = SoloPlugin::default();
        assert_eq!(
            plugin.supported_actions(),
            vec![
                "learner_read",
                "attendance_update",
                "session_list",
                "availability_check",
                "session_create",
                "session_update",
                "session_cancel",
                "learner_message_send"
            ]
        );
        assert_eq!(plugin.name(), "solo");
        assert_eq!(
            plugin.supported_credential_types(),
            vec![CredentialType::OAuth2, CredentialType::UrlToken]
        );
    }

    #[test]
    fn strict_fields_and_unknown_actions_are_rejected() {
        let mut params = json!({
            "base_url": SHEETS_BASE_URL,
            "spreadsheet_id": "sheet-1",
            "range": LEARNERS_RANGE,
            "unexpected": true
        });
        assert!(validate_typed("learner_read", &params).is_err());
        params["range"] = json!(LEARNERS_RANGE);
        assert!(validate_typed("not_an_action", &params).is_err());
    }

    #[test]
    fn learner_ranges_are_pinned() {
        for range in [
            COHORTS_RANGE,
            LEARNERS_RANGE,
            ATTENDANCE_RANGE,
            KNOWLEDGE_RANGE,
        ] {
            let params = json!({
                "base_url": SHEETS_BASE_URL,
                "spreadsheet_id": "sheet-1",
                "range": range
            });
            assert!(validate_typed("learner_read", &params).is_ok());
        }
        let params = json!({
            "base_url": SHEETS_BASE_URL,
            "spreadsheet_id": "sheet-1",
            "range": "Learners!A1:M1000"
        });
        assert!(validate_typed("learner_read", &params).is_err());
    }

    #[test]
    fn time_windows_are_rfc3339_and_at_most_31_days() {
        assert!(validate_window("2026-09-01T00:00:00Z", "2026-10-02T00:00:00Z").is_ok());
        assert!(validate_window("2026-09-02T00:00:00Z", "2026-09-01T00:00:00Z").is_err());
        assert!(validate_window("2026-09-01T00:00:00Z", "2026-10-03T00:00:00Z").is_err());
        assert!(validate_window("not-a-time", "2026-09-02T00:00:00Z").is_err());
    }

    #[test]
    fn event_ids_are_lowercase_hex_and_deterministic() {
        let one = deterministic_event_id("session-1");
        assert_eq!(one, deterministic_event_id("session-1"));
        assert_eq!(one.len(), EVENT_ID_HEX_LEN);
        assert!(one
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(one, deterministic_event_id("session-2"));
    }

    #[test]
    fn attendance_cas_requires_positive_expected_version() {
        assert_eq!(next_row_version("4", 4).unwrap(), "5");
        assert!(next_row_version("5", 4).is_err());
        assert!(validate_expected_row_version("0").is_err());
        assert!(validate_expected_row_version("not-a-version").is_err());

        let params = json!({
            "base_url": SHEETS_BASE_URL,
            "spreadsheet_id": "sheet-1",
            "range": ATTENDANCE_RANGE,
            "attendance_id": "attendance-1",
            "learner_id": "learner-1",
            "session_id": "session-1",
            "cohort_id": "cohort-1",
            "expected_row_version": "1",
            "status": "Confirmed"
        });
        assert!(validate_typed("attendance_update", &params).is_ok());
    }

    #[test]
    fn calendar_reads_require_timezone_and_cancel_binds_business_ids() {
        let window = json!({
            "base_url": CALENDAR_BASE_URL,
            "calendar_id": "calendar@example.com",
            "time_min": "2026-09-07T10:00:00Z",
            "time_max": "2026-09-07T11:00:00Z",
            "timezone": "Europe/Lisbon"
        });
        assert!(validate_typed("session_list", &window).is_ok());
        assert!(validate_typed("availability_check", &window).is_ok());

        let cancel = json!({
            "base_url": CALENDAR_BASE_URL,
            "calendar_id": "calendar@example.com",
            "event_id": "event-1",
            "expected_etag": "\"etag-1\"",
            "session_id": "session-1",
            "cohort_id": "cohort-1"
        });
        assert!(validate_typed("session_cancel", &cancel).is_ok());
    }

    #[test]
    fn attendance_header_mapping_and_fixed_mapping_are_bounded() {
        let headers = vec![json!([
            "attendance_id",
            "learner_id",
            "session_id",
            "cohort_id",
            "status",
            "confirmed_at",
            "notes",
            "row_version",
            "updated_at",
            "updated_by",
            "formula_preserved"
        ])];
        let (start, columns) = attendance_columns(&headers);
        assert_eq!(start, 1);
        assert_eq!(columns.updated_by, 9);
        assert_eq!(attendance_columns(&[]).0, 0);
        assert_eq!(FIXED_ATTENDANCE_COLUMNS.updated_at, 8);
    }

    #[test]
    fn telegram_recipient_lookup_and_sanitized_receipt_shape() {
        let document = validate_telegram_document(
            r#"{"bot_token":"123:secret-token","recipients":{"parent-a":"42"}}"#,
        )
        .unwrap();
        assert_eq!(
            lookup_recipient_chat_id(&document, "parent-a").unwrap(),
            "42"
        );
        assert!(lookup_recipient_chat_id(&document, "unknown").is_err());
        let receipt = json!({
            "ok": true,
            "message_id": 7,
            "recipient_ref": "parent-a",
            "sent_at": "2026-09-07T00:00:00Z"
        });
        let text = serde_json::to_string(&receipt).unwrap();
        assert!(!text.contains("secret-token"));
        assert!(!text.contains("42"));
        assert!(!text.contains("result"));
    }

    #[test]
    fn typed_validation_bounds_message_and_session_fields() {
        let mut message = json!({
            "recipient_ref": "parent-a",
            "learner_id": "learner-1",
            "session_id": "session-1",
            "message_body": "hello"
        });
        assert!(validate_typed("learner_message_send", &message).is_ok());
        message["message_body"] = json!("x".repeat(4097));
        assert!(validate_typed("learner_message_send", &message).is_err());
        assert!(validate_typed("session_create", &valid_session("session_create")).is_ok());
        let mut session = valid_session("session_create");
        session["title"] = json!("x".repeat(201));
        assert!(validate_typed("session_create", &session).is_err());
    }

    #[test]
    fn telegram_secret_document_rejects_unknown_fields_and_unknown_recipients() {
        assert!(validate_telegram_document(
            r#"{"bot_token":"123:x","recipients":{"a":"1"},"user":{}}"#
        )
        .is_err());
        let document =
            validate_telegram_document(r#"{"bot_token":"123:x","recipients":{"a":"1"}}"#).unwrap();
        assert!(lookup_recipient_chat_id(&document, "b").is_err());
    }

    #[tokio::test]
    async fn google_oauth_requires_pinned_token_url_and_refresh_on_stale_access() {
        let wrong_url = Credential::new(
            "google".into(),
            CredentialData::OAuth2 {
                client_id: "client".into(),
                client_secret: Secret::new("client-secret"),
                refresh_token: Some(Secret::new("refresh")),
                access_token: Some(Secret::new("access")),
                expires_at: None,
                token_url: "https://accounts.example/token".into(),
                scopes: vec![],
            },
        );
        let client = crate::plugins::build_guarded_client();
        assert!(effective_google_credential(&client, &wrong_url)
            .await
            .is_err());

        let stale_without_refresh = Credential::new(
            "google".into(),
            CredentialData::OAuth2 {
                client_id: "client".into(),
                client_secret: Secret::new("client-secret"),
                refresh_token: None,
                access_token: None,
                expires_at: None,
                token_url: GOOGLE_TOKEN_URL.into(),
                scopes: vec![],
            },
        );
        let error = effective_google_credential(&client, &stale_without_refresh)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refresh_token is required"));
        assert!(!error.to_string().contains("client-secret"));
    }

    async fn calendar_binding_server() -> (String, Arc<Mutex<Vec<String>>>) {
        let methods = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", any(calendar_binding_handler))
            .with_state(methods.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), methods)
    }

    async fn calendar_binding_handler(
        State(methods): State<Arc<Mutex<Vec<String>>>>,
        request: axum::extract::Request,
    ) -> Json<Value> {
        methods.lock().unwrap().push(request.method().to_string());
        Json(json!({
            "etag": "\"actual-etag\"",
            "extendedProperties": {"private": {
                "feir_session_id": "session-actual",
                "feir_cohort_id": "cohort-actual"
            }}
        }))
    }

    fn calendar_event_url(base_url: &str) -> Url {
        Url::parse(&format!(
            "{base_url}calendars/calendar%40example.com/events/event-1"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn calendar_mutations_read_and_refuse_mismatched_event_before_write() {
        let (base_url, methods) = calendar_binding_server().await;
        let result = verified_calendar_mutation(
            &Client::new(),
            calendar_event_url(&base_url),
            "access",
            "\"actual-etag\"",
            "session-wrong",
            "cohort-actual",
            Method::PATCH,
            Some(json!({})),
        )
        .await;
        assert!(matches!(
            result,
            Err(PluginError::InvalidParams(message)) if message.contains("session_id")
        ));
        assert_eq!(&*methods.lock().unwrap(), &["GET"]);

        let (base_url, methods) = calendar_binding_server().await;
        let result = verified_calendar_mutation(
            &Client::new(),
            calendar_event_url(&base_url),
            "access",
            "\"wrong-etag\"",
            "session-actual",
            "cohort-actual",
            Method::DELETE,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(PluginError::InvalidParams(message)) if message.contains("ETag")
        ));
        assert_eq!(&*methods.lock().unwrap(), &["GET"]);
    }

    #[tokio::test]
    async fn calendar_mutations_verify_then_dispatch_the_expected_method() {
        let (base_url, methods) = calendar_binding_server().await;
        let patch = verified_calendar_mutation(
            &Client::new(),
            calendar_event_url(&base_url),
            "access",
            "\"actual-etag\"",
            "session-actual",
            "cohort-actual",
            Method::PATCH,
            Some(json!({"summary": "Updated"})),
        )
        .await
        .unwrap();
        assert_eq!(patch.response.status, 200);
        assert_eq!(&*methods.lock().unwrap(), &["GET", "PATCH"]);

        let (base_url, methods) = calendar_binding_server().await;
        let delete = verified_calendar_mutation(
            &Client::new(),
            calendar_event_url(&base_url),
            "access",
            "\"actual-etag\"",
            "session-actual",
            "cohort-actual",
            Method::DELETE,
            None,
        )
        .await
        .unwrap();
        assert_eq!(delete.response.status, 200);
        assert_eq!(&*methods.lock().unwrap(), &["GET", "DELETE"]);
    }

    // -----------------------------------------------------------------------
    // The adapter itself pins spreadsheet and Calendar ids from `[solo_pins]`.
    // -----------------------------------------------------------------------

    const PINNED_SHEET: &str = "solo-learner-fixture";
    const PINNED_CALENDAR: &str = "solo-calendar-fixture";
    const SHEET_ACTIONS: &[&str] = &["learner_read", "attendance_update"];
    const CALENDAR_ACTIONS: &[&str] = &[
        "session_list",
        "availability_check",
        "session_create",
        "session_update",
        "session_cancel",
    ];

    type Hits = Arc<Mutex<Vec<(String, String)>>>;

    /// A loopback upstream that records EVERY request. GETs answer with a body
    /// that satisfies both the Attendance CAS read and the Calendar binding
    /// read. An empty `Hits` after a call proves no outbound request was made.
    async fn recording_solo_server() -> (String, Hits) {
        let hits: Hits = Arc::new(Mutex::new(Vec::new()));
        let recorded = hits.clone();
        let app =
            Router::new().fallback(move |method: axum::http::Method, uri: axum::http::Uri| {
                let recorded = recorded.clone();
                async move {
                    recorded
                        .lock()
                        .unwrap()
                        .push((method.to_string(), uri.to_string()));
                    if method == axum::http::Method::GET {
                        Json(json!({
                            "values": [
                                ["attendance_id", "learner_id", "session_id", "cohort_id",
                                 "status", "confirmed_at", "notes", "row_version",
                                 "updated_at", "updated_by"],
                                ["attendance-1", "learner-1", "session-1", "cohort-1",
                                 "Pending", "", "", "1", "", ""]
                            ],
                            "etag": "\"etag-1\"",
                            "extendedProperties": {"private": {
                                "feir_session_id": "session-1",
                                "feir_cohort_id": "cohort-1"
                            }}
                        }))
                    } else {
                        Json(json!({"ok": true}))
                    }
                }
            });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), hits)
    }

    fn fixture_pins() -> SoloPins {
        SoloPins::parse(&[PINNED_SHEET.to_string()], &[PINNED_CALENDAR.to_string()]).unwrap()
    }

    fn pinned_plugin() -> SoloPlugin {
        SoloPlugin::with_client(Client::new(), fixture_pins())
    }

    fn unpinned_plugin() -> SoloPlugin {
        SoloPlugin::with_client(Client::new(), SoloPins::default())
    }

    /// Fresh access token: no OAuth refresh request is ever needed.
    fn fresh_google_credential() -> Credential {
        Credential::new(
            "google".into(),
            CredentialData::OAuth2 {
                client_id: "client".into(),
                client_secret: Secret::new("client-secret"),
                refresh_token: None,
                access_token: Some(Secret::new("access")),
                expires_at: None,
                token_url: GOOGLE_TOKEN_URL.into(),
                scopes: vec![],
            },
        )
    }

    /// Valid params for `action` against the mock upstream, targeting `id`
    /// (a spreadsheet id for Sheets actions, a Calendar id otherwise).
    fn action_params(action: &str, base_url: &str, id: &str) -> Value {
        let window = json!({
            "base_url": base_url,
            "calendar_id": id,
            "time_min": "2026-09-07T10:00:00Z",
            "time_max": "2026-09-07T11:00:00Z",
            "timezone": "Europe/Lisbon"
        });
        match action {
            "learner_read" => json!({
                "base_url": base_url,
                "spreadsheet_id": id,
                "range": LEARNERS_RANGE
            }),
            "attendance_update" => json!({
                "base_url": base_url,
                "spreadsheet_id": id,
                "range": ATTENDANCE_RANGE,
                "attendance_id": "attendance-1",
                "learner_id": "learner-1",
                "session_id": "session-1",
                "cohort_id": "cohort-1",
                "expected_row_version": "1",
                "status": "Confirmed"
            }),
            "session_list" | "availability_check" => window,
            "session_create" | "session_update" => {
                let mut params = valid_session(action);
                params["base_url"] = json!(base_url);
                params["calendar_id"] = json!(id);
                params
            }
            "session_cancel" => json!({
                "base_url": base_url,
                "calendar_id": id,
                "event_id": "event-1",
                "expected_etag": "\"etag-1\"",
                "session_id": "session-1",
                "cohort_id": "cohort-1"
            }),
            other => panic!("no fixture params for {other}"),
        }
    }

    async fn run_solo(
        plugin: &SoloPlugin,
        action: &str,
        params: Value,
    ) -> Result<ExecuteResponse, PluginError> {
        plugin
            .execute(PluginRequest {
                credential: fresh_google_credential(),
                action: action.into(),
                params,
                context: crate::RequestContext::default(),
            })
            .await
    }

    /// Both the preflight (`validate_params`) and a DIRECT `execute` refuse,
    /// and the upstream saw nothing.
    async fn assert_refused_without_network(
        plugin: &SoloPlugin,
        hits: &Hits,
        action: &str,
        params: Value,
        why: &str,
    ) {
        let preflight = plugin.validate_params(action, &params);
        assert!(
            matches!(&preflight, Err(PluginError::InvalidParams(m)) if m.starts_with("solo pin:")),
            "{action} preflight must refuse {why} with a pin error, got {preflight:?}"
        );
        let result = run_solo(plugin, action, params).await;
        assert!(
            matches!(&result, Err(PluginError::InvalidParams(m)) if m.starts_with("solo pin:")),
            "{action} execute must refuse {why} with a pin error, got {result:?}"
        );
        assert!(
            hits.lock().unwrap().is_empty(),
            "{action} must make no outbound request for {why}: {:?}",
            hits.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn solo_sheet_actions_refuse_a_foreign_spreadsheet_before_network() {
        let (base_url, hits) = recording_solo_server().await;
        let plugin = pinned_plugin();
        for action in SHEET_ACTIONS {
            for foreign in [
                "attacker-spreadsheet",
                "Solo-learner-fixture",
                "solo-learner-fixture ",
                " solo-learner-fixture",
                "solo-learner-fixture/values/Secrets!A1:Z9?x=",
                "solo-learner-fixture%2F..",
                // A pinned CALENDAR id never authorizes a spreadsheet.
                PINNED_CALENDAR,
            ] {
                assert_refused_without_network(
                    &plugin,
                    &hits,
                    action,
                    action_params(action, &base_url, foreign),
                    &format!("foreign spreadsheet {foreign:?}"),
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn solo_calendar_actions_refuse_a_foreign_calendar_before_network() {
        let (base_url, hits) = recording_solo_server().await;
        let plugin = pinned_plugin();
        for action in CALENDAR_ACTIONS {
            for foreign in [
                "attacker@example.com",
                "primary",
                "Solo-calendar-fixture",
                "solo-calendar-fixture ",
                "solo-calendar-fixture/events",
                "solo-calendar-fixture%40x",
                // A pinned SPREADSHEET id never authorizes a Calendar.
                PINNED_SHEET,
            ] {
                assert_refused_without_network(
                    &plugin,
                    &hits,
                    action,
                    action_params(action, &base_url, foreign),
                    &format!("foreign calendar {foreign:?}"),
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn solo_with_no_pin_config_refuses_every_sheet_and_calendar_action_before_network() {
        let (base_url, hits) = recording_solo_server().await;
        let plugin = unpinned_plugin();
        for action in SHEET_ACTIONS {
            assert_refused_without_network(
                &plugin,
                &hits,
                action,
                action_params(action, &base_url, PINNED_SHEET),
                "a call with no operator pin configured",
            )
            .await;
        }
        for action in CALENDAR_ACTIONS {
            assert_refused_without_network(
                &plugin,
                &hits,
                action,
                action_params(action, &base_url, PINNED_CALENDAR),
                "a call with no operator pin configured",
            )
            .await;
        }
        // The server wiring default is the same fail-closed posture.
        let default_plugin = SoloPlugin::default();
        for action in SHEET_ACTIONS {
            assert!(default_plugin
                .validate_params(
                    action,
                    &action_params(action, SHEETS_BASE_URL, PINNED_SHEET)
                )
                .is_err());
        }
        for action in CALENDAR_ACTIONS {
            assert!(default_plugin
                .validate_params(
                    action,
                    &action_params(action, CALENDAR_BASE_URL, PINNED_CALENDAR)
                )
                .is_err());
        }
    }

    #[tokio::test]
    async fn solo_pinned_ids_still_work_for_every_action_family() {
        let expected: &[(&str, &str, &[&str], &str)] = &[
            (
                "learner_read",
                PINNED_SHEET,
                &["GET"],
                "/v4/spreadsheets/solo-learner-fixture/values/Learners",
            ),
            (
                "attendance_update",
                PINNED_SHEET,
                &["GET", "PUT"],
                "/v4/spreadsheets/solo-learner-fixture/values/Attendance",
            ),
            (
                "session_list",
                PINNED_CALENDAR,
                &["GET"],
                "/calendars/solo-calendar-fixture/events",
            ),
            (
                "availability_check",
                PINNED_CALENDAR,
                &["POST"],
                "/freeBusy",
            ),
            (
                "session_create",
                PINNED_CALENDAR,
                &["POST"],
                "/calendars/solo-calendar-fixture/events",
            ),
            (
                "session_update",
                PINNED_CALENDAR,
                &["GET", "PATCH"],
                "/calendars/solo-calendar-fixture/events/event-1",
            ),
            (
                "session_cancel",
                PINNED_CALENDAR,
                &["GET", "DELETE"],
                "/calendars/solo-calendar-fixture/events/event-1",
            ),
        ];
        for (action, id, methods, path_prefix) in expected {
            let (base_url, hits) = recording_solo_server().await;
            let plugin = pinned_plugin();
            let params = action_params(action, &base_url, id);
            plugin.validate_params(action, &params).unwrap();
            let response = run_solo(&plugin, action, params).await.unwrap();
            assert_eq!(response.status, 200, "{action}");
            let hits = hits.lock().unwrap();
            let seen: Vec<&str> = hits.iter().map(|(m, _)| m.as_str()).collect();
            assert_eq!(&seen, methods, "{action}: {hits:?}");
            assert!(
                hits.iter().all(|(_, uri)| uri.starts_with(path_prefix)),
                "{action}: {hits:?}"
            );
        }
    }
}
