//! Narrow, fail-closed Buffer connector for human-reviewed text drafts.
//!
//! The adapter deliberately exposes only target discovery and the native
//! draft handoff. It does not expose arbitrary GraphQL or the generic admin
//! idempotency table.

use super::{Plugin, PluginError, PluginRequest};
use crate::config::BufferPin;
use crate::storage::{
    DraftReceipt, DraftSyncStatus, NativeDraftKey, NativeDraftMetadata, NativeDraftOutcome,
    NativeDraftReservation, StorageBackend,
};
use crate::{Credential, CredentialData, CredentialType, ExecuteResponse};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

const BUFFER_URL: &str = "https://api.buffer.com";
const X_SERVICE: &str = "twitter";
const LINKEDIN_SERVICE: &str = "linkedin";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftCreateParams {
    target_alias: String,
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
    publish_at: String,
    source_ids: Vec<String>,
    row_version: u64,
    content_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftReadParams {
    target_alias: String,
    campaign_id: String,
    variant_id: String,
    row_version: u64,
}

fn invalid(message: impl Into<String>) -> PluginError {
    PluginError::InvalidParams(message.into())
}

fn safe_text(name: &str, value: &str, max: usize) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(invalid(format!(
            "Buffer {name} must be non-empty and at most {max} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "Buffer {name} contains a control character"
        )));
    }
    Ok(())
}

fn safe_copy(value: &str, max: usize, name: &str) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(invalid(format!(
            "Buffer {name} must be non-empty and at most {max} bytes"
        )));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(invalid(format!(
            "Buffer {name} contains an unsafe control character"
        )));
    }
    Ok(())
}

fn service(target: &str) -> Option<&'static str> {
    match target {
        "x" => Some(X_SERVICE),
        "linkedin" => Some(LINKEDIN_SERVICE),
        _ => None,
    }
}

fn validate_source_ids(ids: &[String]) -> Result<(), PluginError> {
    if !(1..=16).contains(&ids.len()) {
        return Err(invalid("Buffer source_ids must contain 1 to 16 ids"));
    }
    for id in ids {
        safe_text("source_id", id, 128)?;
    }
    let mut sorted = ids.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("Buffer source_ids must not contain duplicates"));
    }
    Ok(())
}

fn validate_content_hash(value: &str) -> Result<(), PluginError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "Buffer content_hash must be exactly 64 hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_x_text(text: &str) -> Result<(), PluginError> {
    // A UTF-8-byte upper bound intentionally over-counts Unicode whitespace,
    // including U+3000. URLs (including uppercase schemes, www links, and
    // bare dotted domains) receive Buffer/X's conservative transformed-link
    // minimum. This may refuse borderline valid posts, but never undercounts
    // text that the provider could transform into a longer URL.
    let mut total = text.len();
    let url_re = regex::Regex::new(
        r"(?i:(?:https?://|www\.)|(?:[\p{L}\p{N}-]+[.\x{3002}\x{FF0E}\x{FF61}])+\p{L}+)",
    )
    .expect("the Buffer URL expression is static and valid");
    for _matched in url_re.find_iter(text) {
        total = total.saturating_add(23usize.saturating_sub(_matched.as_str().chars().count()));
    }
    if total > 280 {
        return Err(invalid(
            "Buffer x draft_copy exceeds the conservative 280-character limit",
        ));
    }
    Ok(())
}

fn validate_linkedin_text(text: &str) -> Result<(), PluginError> {
    let mut total = text.encode_utf16().count();
    let url_re = regex::Regex::new(
        r"(?i:(?:https?://|www\.)|(?:[\p{L}\p{N}-]+[.\x{3002}\x{FF0E}\x{FF61}])+\p{L}+)",
    )
    .expect("the Buffer URL expression is static and valid");
    for _matched in url_re.find_iter(text) {
        total =
            total.saturating_add(24usize.saturating_sub(_matched.as_str().encode_utf16().count()));
    }
    if total > 3_000 {
        return Err(invalid(
            "Buffer LinkedIn draft_copy exceeds the conservative 3000 UTF-16-unit limit",
        ));
    }
    Ok(())
}

fn validate_draft(p: &DraftCreateParams) -> Result<(), PluginError> {
    let expected_service = service(&p.target_alias)
        .ok_or_else(|| invalid("Buffer target_alias must be x or linkedin"))?;
    if p.channel != p.target_alias {
        return Err(invalid("Buffer channel must equal target_alias"));
    }
    safe_text("campaign_id", &p.campaign_id, 128)?;
    safe_text("variant_id", &p.variant_id, 128)?;
    safe_text("account_id", &p.account_id, 128)?;
    safe_text("audience", &p.audience, 512)?;
    safe_text("content_type", &p.content_type, 128)?;
    safe_copy(&p.draft_copy, 20_000, "draft_copy")?;
    if !p.media_brief.is_empty() {
        safe_copy(&p.media_brief, 2_000, "media_brief")?;
    }
    if !p.asset_url.is_empty() || !p.asset_hash.is_empty() || !p.publish_at.is_empty() {
        return Err(invalid(
            "Buffer text drafts cannot carry assets or publish_at",
        ));
    }
    validate_source_ids(&p.source_ids)?;
    if p.row_version == 0 {
        return Err(invalid("Buffer row_version must be positive"));
    }
    validate_content_hash(&p.content_hash)?;
    if expected_service == X_SERVICE {
        validate_x_text(&p.draft_copy)?;
    } else {
        validate_linkedin_text(&p.draft_copy)?;
    }
    Ok(())
}

fn canonical_content_hash(p: &DraftCreateParams) -> Result<String, PluginError> {
    crate::plugins::marketing::draft_content_hash(crate::plugins::marketing::DraftHashPayload {
        campaign_id: &p.campaign_id,
        variant_id: &p.variant_id,
        channel: &p.channel,
        account_id: &p.account_id,
        audience: &p.audience,
        content_type: &p.content_type,
        draft_copy: &p.draft_copy,
        media_brief: &p.media_brief,
        asset_url: &p.asset_url,
        asset_hash: &p.asset_hash,
        publish_at: &p.publish_at,
        source_ids: p.source_ids.clone(),
    })
}

fn canonical_payload_hash(p: &DraftCreateParams, pin: &BufferPin) -> Result<String, PluginError> {
    let mut payload = BTreeMap::<String, Value>::new();
    for (name, value) in [
        ("account_id", json!(p.account_id)),
        ("asset_hash", json!(p.asset_hash)),
        ("asset_url", json!(p.asset_url)),
        ("audience", json!(p.audience)),
        ("campaign_id", json!(p.campaign_id)),
        ("channel", json!(p.channel)),
        ("content_hash", json!(p.content_hash)),
        ("content_type", json!(p.content_type)),
        ("draft_copy", json!(p.draft_copy)),
        ("media_brief", json!(p.media_brief)),
        ("publish_at", json!(p.publish_at)),
        ("row_version", json!(p.row_version)),
        ("variant_id", json!(p.variant_id)),
    ] {
        payload.insert(name.to_string(), value);
    }
    let mut source_ids = p.source_ids.clone();
    source_ids.sort();
    payload.insert("source_ids".into(), json!(source_ids));
    let mut pin_value = BTreeMap::<String, Value>::new();
    for (name, value) in [
        ("account_id", json!(pin.account_id)),
        ("channel_id", json!(pin.channel_id)),
        ("credential_alias", json!(pin.credential_alias)),
        ("organization_id", json!(pin.organization_id)),
        ("project_id", json!(pin.project_id)),
        ("service_id", json!(pin.service_id)),
        ("target_alias", json!(pin.target_alias)),
        ("tenant_id", json!(pin.tenant_id)),
    ] {
        pin_value.insert(name.to_string(), value);
    }
    payload.insert(
        "pin".into(),
        serde_json::to_value(pin_value).expect("pin is serializable"),
    );
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| invalid(format!("could not canonicalize Buffer payload: {error}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn require_context(
    context: &crate::RequestContext,
) -> Result<(String, String, u64, String), PluginError> {
    let tenant = context
        .tenant
        .clone()
        .ok_or_else(|| invalid("Buffer requires a trusted tenant context"))?;
    let approval_id = context
        .approval_id
        .clone()
        .ok_or_else(|| invalid("Buffer requires a trusted approval_id"))?;
    let epoch = context
        .approval_execution_epoch
        .filter(|epoch| *epoch > 0)
        .ok_or_else(|| invalid("Buffer requires a trusted approval execution epoch"))?;
    let principal = context
        .api_key_id
        .clone()
        .or_else(|| context.agent_label.clone())
        .ok_or_else(|| invalid("Buffer requires a trusted agent principal"))?;
    safe_text("tenant", &tenant, 512)?;
    safe_text("approval_id", &approval_id, 512)?;
    safe_text("principal", &principal, 512)?;
    Ok((tenant, approval_id, epoch, principal))
}

fn require_tenant(context: &crate::RequestContext) -> Result<String, PluginError> {
    let tenant = context
        .tenant
        .clone()
        .ok_or_else(|| invalid("Buffer requires a trusted tenant context"))?;
    safe_text("tenant", &tenant, 512)?;
    Ok(tenant)
}

fn credential_headers(credential: &Credential) -> Result<reqwest::header::HeaderMap, PluginError> {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
    let token = match &credential.data {
        CredentialData::ApiKey { key, .. } => key.expose(),
        _ => {
            return Err(PluginError::UnsupportedCredentialType(
                "Buffer requires an API key credential".into(),
            ))
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::try_from(format!("Bearer {token}"))
            .map_err(|_| invalid("invalid Buffer credential"))?,
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(headers)
}

#[derive(Debug)]
struct UpstreamError {
    unknown: bool,
    message: String,
    external_id: Option<String>,
    external_content_hash: Option<String>,
    external_status: Option<String>,
}

fn external_id(value: &Value) -> Option<String> {
    let value = value.as_str()?;
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > 256
        || value.chars().any(char::is_control)
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn bounded_status(value: &Value) -> Option<String> {
    let status = value.as_str()?;
    if status.is_empty()
        || status.trim() != status
        || status.chars().count() > 128
        || status.chars().any(char::is_control)
    {
        None
    } else {
        Some(status.to_string())
    }
}

fn partial_post(document: &Value) -> Option<&Value> {
    document.get("data")?.get("createPost")?.get("post")
}

fn partial_error(document: &Value, unknown: bool, message: impl Into<String>) -> UpstreamError {
    let post = partial_post(document);
    let id = post.and_then(|post| post.get("id")).and_then(external_id);
    let text_hash = post
        .and_then(|post| post.get("text"))
        .and_then(Value::as_str)
        .map(|text| hex::encode(Sha256::digest(text.as_bytes())));
    let status = post
        .and_then(|post| post.get("status"))
        .and_then(bounded_status);
    UpstreamError {
        unknown,
        message: message.into(),
        external_id: id,
        external_content_hash: text_hash,
        external_status: status,
    }
}

async fn graphql(
    client: &Client,
    url: &Url,
    credential: &Credential,
    query: &str,
    vars: Value,
) -> Result<Value, UpstreamError> {
    let response = client
        .post(url.clone())
        .headers(
            credential_headers(credential).map_err(|error| UpstreamError {
                unknown: false,
                message: error.to_string(),
                external_id: None,
                external_content_hash: None,
                external_status: None,
            })?,
        )
        .json(&json!({ "query": query, "variables": vars }))
        .send()
        .await
        .map_err(|_| UpstreamError {
            unknown: true,
            message: "Buffer request outcome is unknown; reconcile before retrying".into(),
            external_id: None,
            external_content_hash: None,
            external_status: None,
        })?;
    let status = response.status();
    let body = crate::plugins::read_body_capped(response)
        .await
        .map_err(|_| UpstreamError {
            unknown: true,
            message: "Buffer response outcome is unknown; reconcile before retrying".into(),
            external_id: None,
            external_content_hash: None,
            external_status: None,
        })?;
    let document: Value = serde_json::from_slice(&body).map_err(|_| UpstreamError {
        unknown: true,
        message: "Buffer response outcome is unknown; reconcile before retrying".into(),
        external_id: None,
        external_content_hash: None,
        external_status: None,
    })?;
    if !status.is_success() {
        return Err(partial_error(
            &document,
            true,
            "Buffer upstream HTTP outcome is unknown; reconcile before retrying",
        ));
    }
    match document.get("errors") {
        None | Some(Value::Null) => Ok(document),
        Some(Value::Array(errors)) if errors.is_empty() => Ok(document),
        Some(Value::Array(_)) => Err(partial_error(
            &document,
            true,
            "Buffer GraphQL response contains errors; reconcile before retrying",
        )),
        Some(_) => Err(partial_error(
            &document,
            true,
            "Buffer GraphQL response has a malformed errors field; reconcile before retrying",
        )),
    }
}

pub struct BufferPlugin {
    client: Client,
    pins: Arc<Vec<BufferPin>>,
    storage: Arc<dyn StorageBackend>,
    #[cfg(test)]
    endpoint: Url,
}

impl BufferPlugin {
    pub fn new(pins: Vec<BufferPin>, storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            client: crate::plugins::build_guarded_client(),
            pins: Arc::new(pins),
            storage,
            #[cfg(test)]
            endpoint: Url::parse(BUFFER_URL).expect("static Buffer URL"),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_client_endpoint(
        client: Client,
        endpoint: Url,
        pins: Vec<BufferPin>,
        storage: Arc<dyn StorageBackend>,
    ) -> Self {
        Self {
            client,
            pins: Arc::new(pins),
            storage,
            endpoint,
        }
    }

    fn endpoint(&self) -> Url {
        #[cfg(test)]
        {
            self.endpoint.clone()
        }
        #[cfg(not(test))]
        {
            Url::parse(BUFFER_URL).expect("static Buffer URL")
        }
    }

    fn pin(
        &self,
        credential: &Credential,
        target: &str,
        tenant: &str,
    ) -> Result<BufferPin, PluginError> {
        self.pins
            .iter()
            .find(|pin| {
                pin.credential_alias == credential.alias
                    && pin.target_alias == target
                    && pin.tenant_id == tenant
            })
            .cloned()
            .ok_or_else(|| invalid("Buffer target is not operator-pinned"))
    }

    fn native_key(
        tenant: &str,
        pin: &BufferPin,
        credential: &Credential,
        campaign: &str,
        variant: &str,
        row_version: u64,
    ) -> NativeDraftKey {
        NativeDraftKey {
            tenant: tenant.to_string(),
            project_ref: pin.project_id.clone(),
            provider: "buffer".into(),
            target_alias: pin.target_alias.clone(),
            credential_alias: credential.alias.clone(),
            campaign_id: campaign.to_string(),
            variant_id: variant.to_string(),
            row_version,
        }
    }

    fn validate_typed(action: &str, params: &Value) -> Result<(), PluginError> {
        match action {
            "targets_read" => {
                if !params.is_object()
                    || params.as_object().is_some_and(|object| !object.is_empty())
                {
                    return Err(invalid("buffer.targets_read takes no parameters"));
                }
                Ok(())
            }
            "draft_create" => {
                let p: DraftCreateParams = serde_json::from_value(params.clone())
                    .map_err(|error| invalid(error.to_string()))?;
                validate_draft(&p)?;
                if canonical_content_hash(&p)? != p.content_hash {
                    return Err(invalid(
                        "Buffer content_hash does not match the canonical draft payload",
                    ));
                }
                Ok(())
            }
            "draft_read" => {
                let p: DraftReadParams = serde_json::from_value(params.clone())
                    .map_err(|error| invalid(error.to_string()))?;
                if p.row_version == 0 {
                    return Err(invalid("Buffer row_version must be positive"));
                }
                service(&p.target_alias)
                    .ok_or_else(|| invalid("Buffer target_alias must be x or linkedin"))?;
                safe_text("campaign_id", &p.campaign_id, 128)?;
                safe_text("variant_id", &p.variant_id, 128)
            }
            other => Err(PluginError::UnsupportedAction(other.to_string())),
        }
    }

    fn response_json(
        receipt: &DraftReceipt,
        key: &NativeDraftKey,
        approval_id: &str,
    ) -> Result<ExecuteResponse, PluginError> {
        let mut value = serde_json::to_value(receipt)
            .map_err(|error| PluginError::ExecutionFailed(error.to_string()))?;
        value["operation_key"] =
            Value::String(hex::encode(Sha256::digest(key.storage_key().as_bytes())));
        value["approval_id"] = Value::String(approval_id.to_string());
        Ok(ExecuteResponse::success(
            serde_json::to_vec(&value).expect("receipt is serializable"),
        ))
    }

    async fn preflight(
        &self,
        credential: &Credential,
        pin: &BufferPin,
    ) -> Result<Value, PluginError> {
        let query = "query BufferChannel($input: ChannelInput!) { channel(input: $input) { id organizationId service serviceId isDisconnected isLocked } }";
        let document = graphql(
            &self.client,
            &self.endpoint(),
            credential,
            query,
            json!({ "input": { "id": pin.channel_id } }),
        )
        .await
        .map_err(|error| PluginError::ExecutionFailed(error.message))?;
        let channel = document
            .get("data")
            .and_then(|data| data.get("channel"))
            .filter(|value| !value.is_null())
            .ok_or_else(|| {
                PluginError::ExecutionFailed("Buffer channel preflight returned no channel".into())
            })?;
        let fields_ok = channel.get("id").and_then(Value::as_str) == Some(pin.channel_id.as_str())
            && channel.get("organizationId").and_then(Value::as_str)
                == Some(pin.organization_id.as_str())
            && channel.get("service").and_then(Value::as_str) == Some(pin.service())
            && channel.get("serviceId").and_then(Value::as_str) == Some(pin.service_id.as_str())
            && channel.get("isDisconnected").and_then(Value::as_bool) == Some(false)
            && channel.get("isLocked").and_then(Value::as_bool) == Some(false);
        if !fields_ok {
            return Err(PluginError::ExecutionFailed(
                "Buffer channel preflight does not match the operator pin".into(),
            ));
        }
        Ok(channel.clone())
    }

    async fn create_remote(
        &self,
        credential: &Credential,
        pin: &BufferPin,
        p: &DraftCreateParams,
    ) -> Result<String, UpstreamError> {
        let query = "mutation BufferCreateDraft($input: CreatePostInput!) { createPost(input: $input) { __typename ... on PostActionSuccess { post { id text status channelId channelService dueAt assets { __typename } } } ... on MutationError { message } } }";
        let document = graphql(
            &self.client,
            &self.endpoint(),
            credential,
            query,
            json!({ "input": { "text": p.draft_copy, "channelId": pin.channel_id, "schedulingType": "automatic", "mode": "addToQueue", "saveToDraft": true, "assets": [], "needsApproval": false, "aiAssisted": true } }),
        )
        .await?;
        let action = match document.get("data").and_then(|data| data.get("createPost")) {
            Some(action) if action.is_object() => action,
            _ => {
                return Err(partial_error(
                    &document,
                    true,
                    "Buffer create response is incomplete; reconcile before retrying",
                ))
            }
        };
        let known_rejection = matches!(
            action.get("__typename").and_then(Value::as_str),
            Some("MutationError")
                | Some("InvalidInputError")
                | Some("LimitReachedError")
                | Some("VoidMutationError")
        );
        if known_rejection {
            let has_post = action.get("post").is_some_and(|post| !post.is_null());
            let has_message = action
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| !message.is_empty());
            if !has_post && has_message {
                return Err(UpstreamError {
                    unknown: false,
                    // Do not persist provider-controlled error text. These
                    // concrete Buffer error variants are confirmed rejections;
                    // every other malformed/partial response remains Unknown.
                    message: "Buffer create was rejected by upstream".into(),
                    external_id: None,
                    external_content_hash: None,
                    external_status: None,
                });
            }
            return Err(partial_error(
                &document,
                true,
                "Buffer create returned a malformed rejection; reconcile before retrying",
            ));
        }
        if action.get("__typename").and_then(Value::as_str) != Some("PostActionSuccess") {
            return Err(partial_error(
                &document,
                true,
                "Buffer create response had an unknown action type; reconcile before retrying",
            ));
        }
        let post = match action.get("post") {
            Some(post) if post.is_object() => post,
            _ => {
                return Err(partial_error(
                    &document,
                    true,
                    "Buffer create response had no draft post; reconcile before retrying",
                ))
            }
        };
        let id = post.get("id").and_then(external_id);
        let valid = post.get("text").and_then(Value::as_str) == Some(p.draft_copy.as_str())
            && post.get("status").and_then(Value::as_str) == Some("draft")
            && post.get("channelId").and_then(Value::as_str) == Some(pin.channel_id.as_str())
            && post.get("channelService").and_then(Value::as_str) == Some(pin.service())
            && post.get("dueAt").is_some_and(Value::is_null)
            && post
                .get("assets")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty);
        if !valid {
            return Err(partial_error(
                &document,
                true,
                "Buffer create response failed frozen-field validation; reconcile before retrying",
            ));
        }
        id.ok_or_else(|| {
            partial_error(
                &document,
                true,
                "Buffer create response had no draft id; reconcile before retrying",
            )
        })
    }

    async fn read_remote(&self, credential: &Credential, id: &str) -> Result<Value, UpstreamError> {
        let query = "query BufferPost($input: PostInput!) { post(input: $input) { id text status channelId channelService dueAt assets { __typename } } }";
        let document = graphql(
            &self.client,
            &self.endpoint(),
            credential,
            query,
            json!({ "input": { "id": id } }),
        )
        .await?;
        let post = document
            .get("data")
            .and_then(|data| data.get("post"))
            .filter(|post| !post.is_null())
            .ok_or_else(|| UpstreamError {
                unknown: false,
                message: "Buffer owned draft was not found or returned no post".into(),
                external_id: None,
                external_content_hash: None,
                external_status: None,
            })?;
        let typed = post.get("id").and_then(Value::as_str).is_some()
            && post.get("text").and_then(Value::as_str).is_some()
            && post.get("status").and_then(bounded_status).is_some()
            && post.get("channelId").and_then(Value::as_str).is_some()
            && post.get("channelService").and_then(Value::as_str).is_some()
            && post
                .get("dueAt")
                .is_some_and(|value| value.is_null() || value.as_str().is_some())
            && post.get("assets").and_then(Value::as_array).is_some();
        if !typed {
            return Err(UpstreamError {
                unknown: true,
                message: "Buffer read response was incomplete; reconcile before retrying".into(),
                external_id: post.get("id").and_then(external_id),
                external_content_hash: None,
                external_status: None,
            });
        }
        Ok(post.clone())
    }

    async fn native_create(
        &self,
        request: &PluginRequest,
        tenant: &str,
        p: DraftCreateParams,
        pin: BufferPin,
    ) -> Result<ExecuteResponse, PluginError> {
        validate_draft(&p)?;
        if canonical_content_hash(&p)? != p.content_hash {
            return Err(invalid(
                "Buffer content_hash does not match the canonical draft payload",
            ));
        }
        if pin.tenant_id != tenant
            || pin.target_alias != p.target_alias
            || pin.account_id != p.account_id
        {
            return Err(invalid("Buffer draft does not match the operator pin"));
        }
        let key = Self::native_key(
            tenant,
            &pin,
            &request.credential,
            &p.campaign_id,
            &p.variant_id,
            p.row_version,
        );
        let payload_hash = canonical_payload_hash(&p, &pin)?;
        let (_, approval_id, epoch, principal) = require_context(&request.context)?;
        // Exact terminal replay is served before preflight, so an upstream
        // outage cannot break a confirmed handoff or create a duplicate.
        if let Some(record) = self.storage.get_native_draft(&key).await.map_err(|error| {
            PluginError::ExecutionFailed(format!("Buffer durable operation unavailable: {error}"))
        })? {
            if record.payload_hash != payload_hash || record.metadata.content_hash != p.content_hash
            {
                return Err(invalid(
                    "Buffer native draft key conflicts with a different frozen payload",
                ));
            }
            match record.status {
                DraftSyncStatus::Succeeded | DraftSyncStatus::Drift => {
                    return Self::response_json(
                        &record.receipt.ok_or_else(|| {
                            PluginError::ExecutionFailed("Buffer durable receipt is incomplete".into())
                        })?,
                        &key,
                        &record.metadata.approval_id,
                    )
                }
                status => {
                    return Err(PluginError::ExecutionFailed(format!(
                        "Buffer operation is terminal or ambiguous ({status:?}); reconcile before retrying"
                    )))
                }
            }
        }
        let _channel = self.preflight(&request.credential, &pin).await?;
        let metadata = NativeDraftMetadata {
            approval_id: approval_id.clone(),
            execution_epoch: epoch,
            principal_id: Some(principal),
            agent_label: request.context.agent_label.clone(),
            content_hash: p.content_hash.clone(),
            credential_id: request.credential.id.clone(),
        };
        let reservation = self
            .storage
            .reserve_native_draft(&key, &payload_hash, metadata)
            .await
            .map_err(|error| {
                PluginError::ExecutionFailed(format!(
                    "Buffer durable operation unavailable: {error}"
                ))
            })?;
        let record = match reservation {
            NativeDraftReservation::Fresh { record } => record,
            NativeDraftReservation::Existing { record } => {
                if record.payload_hash != payload_hash
                    || record.metadata.content_hash != p.content_hash
                {
                    return Err(invalid(
                        "Buffer native draft key conflicts with a different frozen payload",
                    ));
                }
                return match record.status {
                    DraftSyncStatus::Succeeded | DraftSyncStatus::Drift => Self::response_json(
                        &record.receipt.ok_or_else(|| {
                            PluginError::ExecutionFailed("Buffer durable receipt is incomplete".into())
                        })?,
                        &key,
                        &record.metadata.approval_id,
                    ),
                    status => Err(PluginError::ExecutionFailed(format!(
                        "Buffer operation is terminal or ambiguous ({status:?}); reconcile before retrying"
                    ))),
                };
            }
        };
        let outcome = match self.create_remote(&request.credential, &pin, &p).await {
            Ok(external_id) => {
                let receipt = DraftReceipt {
                    provider: "buffer".into(),
                    campaign_id: p.campaign_id.clone(),
                    variant_id: p.variant_id.clone(),
                    row_version: p.row_version,
                    content_hash: p.content_hash.clone(),
                    channel_ref: pin.target_alias.clone(),
                    external_content_hash: Some(hex::encode(Sha256::digest(
                        p.draft_copy.as_bytes(),
                    ))),
                    external_id: Some(external_id),
                    external_status: Some("draft".into()),
                    review_url: Some("https://publish.buffer.com".into()),
                    sync_status: DraftSyncStatus::Succeeded,
                };
                NativeDraftOutcome {
                    status: DraftSyncStatus::Succeeded,
                    receipt: Some(receipt),
                    error: None,
                }
            }
            Err(error) => {
                let status = if error.unknown {
                    DraftSyncStatus::Unknown
                } else {
                    DraftSyncStatus::Failed
                };
                let receipt = error.external_id.map(|external_id| DraftReceipt {
                    provider: "buffer".into(),
                    campaign_id: p.campaign_id.clone(),
                    variant_id: p.variant_id.clone(),
                    row_version: p.row_version,
                    content_hash: p.content_hash.clone(),
                    channel_ref: pin.target_alias.clone(),
                    external_content_hash: error.external_content_hash,
                    external_id: Some(external_id),
                    external_status: error.external_status,
                    review_url: Some("https://publish.buffer.com".into()),
                    sync_status: status,
                });
                NativeDraftOutcome {
                    status,
                    receipt,
                    error: Some(error.message),
                }
            }
        };
        let final_record = self
            .storage
            .finalize_native_draft(&key, &record.reservation_token, &payload_hash, outcome)
            .await
            .map_err(|error| {
                PluginError::ExecutionFailed(format!("Buffer durable finalize failed: {error}"))
            })?;
        if final_record.status != DraftSyncStatus::Succeeded {
            return Err(PluginError::ExecutionFailed(
                final_record
                    .error
                    .unwrap_or_else(|| "Buffer draft outcome is not confirmed".into()),
            ));
        }
        Self::response_json(
            &final_record.receipt.ok_or_else(|| {
                PluginError::ExecutionFailed("Buffer durable receipt is incomplete".into())
            })?,
            &key,
            &final_record.metadata.approval_id,
        )
    }

    async fn native_read(
        &self,
        request: &PluginRequest,
        tenant: &str,
        p: DraftReadParams,
        pin: BufferPin,
    ) -> Result<ExecuteResponse, PluginError> {
        let key = Self::native_key(
            tenant,
            &pin,
            &request.credential,
            &p.campaign_id,
            &p.variant_id,
            p.row_version,
        );
        let record = self
            .storage
            .get_native_draft(&key)
            .await
            .map_err(|error| {
                PluginError::ExecutionFailed(format!(
                    "Buffer durable operation unavailable: {error}"
                ))
            })?
            .ok_or_else(|| {
                PluginError::ExecutionFailed(
                    "Buffer draft operation is not owned by this context".into(),
                )
            })?;
        let mut receipt = record.receipt.ok_or_else(|| {
            PluginError::ExecutionFailed(
                "Buffer draft has no provider id; manual reconciliation required".into(),
            )
        })?;
        let external_id = receipt
            .external_id
            .clone()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                PluginError::ExecutionFailed(
                    "Buffer draft has no provider id; manual reconciliation required".into(),
                )
            })?;
        let channel = self.preflight(&request.credential, &pin).await?;
        let remote = self
            .read_remote(&request.credential, &external_id)
            .await
            .map_err(|error| PluginError::ExecutionFailed(error.message))?;
        if remote.get("id").and_then(Value::as_str) != Some(external_id.as_str())
            || remote.get("channelId").and_then(Value::as_str)
                != channel.get("id").and_then(Value::as_str)
            || remote.get("channelService").and_then(Value::as_str) != Some(pin.service())
        {
            return Err(PluginError::ExecutionFailed(
                "Buffer owned draft id or channel ownership drifted".into(),
            ));
        }
        let remote_text = remote
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| PluginError::ExecutionFailed("Buffer read returned no text".into()))?;
        let remote_status = remote
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| PluginError::ExecutionFailed("Buffer read returned no status".into()))?;
        let drift = Some(hex::encode(Sha256::digest(remote_text.as_bytes())))
            != receipt.external_content_hash
            || remote_status != "draft"
            || (!remote["dueAt"].is_null() && remote["dueAt"] != "")
            || remote["assets"]
                .as_array()
                .is_none_or(|assets| !assets.is_empty());
        receipt.external_status = Some(remote_status.to_string());
        receipt.sync_status = if drift {
            DraftSyncStatus::Drift
        } else {
            match record.status {
                DraftSyncStatus::Unknown => DraftSyncStatus::Unknown,
                DraftSyncStatus::Failed => DraftSyncStatus::Failed,
                _ => DraftSyncStatus::Succeeded,
            }
        };
        // Read is an observation only; it never overwrites durable terminal
        // knowledge (including an Unknown operation) with a guessed outcome.
        Self::response_json(&receipt, &key, &record.metadata.approval_id)
    }

    async fn execute_typed(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        if request.credential.credential_type != CredentialType::ApiKey {
            return Err(PluginError::UnsupportedCredentialType(
                "Buffer requires an API key credential".into(),
            ));
        }
        let tenant = require_tenant(&request.context)?;
        Self::validate_typed(&request.action, &request.params)?;
        match request.action.as_str() {
            "targets_read" => {
                let mut targets = Vec::new();
                for pin in self.pins.iter().filter(|pin| {
                    pin.credential_alias == request.credential.alias && pin.tenant_id == tenant
                }) {
                    let channel = self.preflight(&request.credential, pin).await?;
                    targets.push(json!({
                        "target_alias": pin.target_alias,
                        "channel_id": channel["id"],
                        "account_id": pin.account_id
                    }));
                }
                if targets.is_empty() {
                    return Err(invalid(
                        "Buffer has no pinned targets for this credential/context",
                    ));
                }
                Ok(ExecuteResponse::success(
                    serde_json::to_vec(&json!({ "provider": "buffer", "targets": targets }))
                        .expect("targets are serializable"),
                ))
            }
            "draft_create" => {
                let p = serde_json::from_value::<DraftCreateParams>(request.params.clone())
                    .map_err(|error| invalid(error.to_string()))?;
                let pin = self.pin(&request.credential, &p.target_alias, &tenant)?;
                self.native_create(&request, &tenant, p, pin).await
            }
            "draft_read" => {
                let p = serde_json::from_value::<DraftReadParams>(request.params.clone())
                    .map_err(|error| invalid(error.to_string()))?;
                let pin = self.pin(&request.credential, &p.target_alias, &tenant)?;
                self.native_read(&request, &tenant, p, pin).await
            }
            _ => unreachable!("validate_typed rejects unsupported actions"),
        }
    }
}

#[async_trait]
impl Plugin for BufferPlugin {
    fn name(&self) -> &str {
        "buffer"
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::ApiKey]
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec!["targets_read", "draft_create", "draft_read"]
    }

    async fn execute(&self, request: PluginRequest) -> Result<ExecuteResponse, PluginError> {
        self.execute_typed(request).await
    }

    fn validate_params(&self, action: &str, params: &Value) -> Result<(), PluginError> {
        Self::validate_typed(action, params)
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::{bounded_status, external_id, validate_linkedin_text, validate_x_text};
    use serde_json::json;

    #[test]
    fn provider_identity_and_status_are_not_normalized() {
        assert_eq!(external_id(&json!("post-1")), Some("post-1".into()));
        assert!(external_id(&json!(" post-1")).is_none());
        assert!(external_id(&json!("post-1 ")).is_none());
        assert!(external_id(&json!("post\n1")).is_none());
        assert!(bounded_status(&json!("draft")).is_some());
        assert!(bounded_status(&json!("")).is_none());
        assert!(bounded_status(&json!(" draft")).is_none());
        assert!(bounded_status(&json!("draft ")).is_none());
    }

    #[test]
    fn url_candidates_are_case_insensitive_and_conservative_near_x_limit() {
        let base = "x".repeat(258);
        for suffix in [" HTTP://T.CO", " www.t.co", " t.co"] {
            assert!(
                validate_x_text(&format!("{base}{suffix}")).is_err(),
                "candidate {suffix:?} must include transformed-link allowance"
            );
        }
    }

    #[test]
    fn ordinary_period_prose_is_not_charged_as_a_url() {
        let prose = format!("{}End.", "word ".repeat(54));
        assert_eq!(prose.len(), 274);
        assert!(validate_x_text(&prose).is_ok());
        assert!(validate_linkedin_text(&prose).is_ok());
    }

    #[test]
    fn unicode_idn_candidates_are_conservative_near_both_limits() {
        let x_text = format!("{} 例.中国", "x".repeat(265));
        assert!(validate_x_text(&x_text).is_err());
        let linkedin_text = format!("{} 例。中国", "x".repeat(2_980));
        assert!(validate_linkedin_text(&linkedin_text).is_err());
    }
}

#[cfg(test)]
#[path = "buffer_tests.rs"]
mod tests;
