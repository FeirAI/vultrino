//! Human-in-the-loop action approvals.
//!
//! Some authenticated actions are too consequential to let an agent run
//! unsupervised. When an action requires approval, Vultrino does **not** execute
//! it. Instead it records an [`ApprovalRequest`], hands the agent an
//! `approval_id`, and waits. A human approves or denies it — in the admin panel,
//! via a Telegram button, or via a link delivered by webhook/email — and only
//! then does the action run, with the result delivered back to the agent the
//! next time it polls.
//!
//! ## The flow, from the agent's side
//! 1. Agent calls a tool (e.g. `http_request`). The response is **not** the API
//!    result — it's a clearly-labelled "approval required" message with an
//!    `approval_id` and instructions to poll `check_approval`.
//! 2. Agent polls `check_approval` with that id. While `pending`, it keeps
//!    waiting. If `denied`, it stops. If `approved`, the action executes
//!    (lazily, in the serving process) and the real result is returned.
//!
//! ## Out-of-band approval (Telegram / webhook / email)
//! Each request carries a single-**decision** capability token (only its hash is
//! stored): it authorizes one approve/deny while the request is pending and is
//! moot once a decision is recorded (the request is no longer pending) or the
//! TTL elapses. Approve/deny links embedding that token point at the web
//! server's `/approvals/{id}/decide` endpoint, so a Telegram inline button or an
//! email link can authorize a decision without a logged-in session. Because the
//! token travels in the link, set `public_base_url` to an HTTPS address and
//! avoid logging request URIs at DEBUG.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

/// Lifecycle state of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting a human decision.
    Pending,
    /// A human approved it; the action may run.
    Approved,
    /// A human rejected it; the action will never run.
    Denied,
    /// No decision was made before the request's TTL elapsed.
    Expired,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Expired => "expired",
        };
        write!(f, "{}", s)
    }
}

/// Who/what requested the gated action (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequesterInfo {
    /// `api_key`, `use_token`, or `local`.
    pub principal_kind: String,
    /// Stable id of the principal (api key id / use token id), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Human label of the principal, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_name: Option<String>,
    /// Role name, if the principal was an API key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl Default for RequesterInfo {
    fn default() -> Self {
        Self::local()
    }
}

impl RequesterInfo {
    /// A local (CLI, no auth) requester.
    pub fn local() -> Self {
        Self {
            principal_kind: "local".to_string(),
            principal_id: None,
            principal_name: None,
            role: None,
        }
    }

    /// Short human description, e.g. `api key "deploy-agent"` or `local`.
    pub fn describe(&self) -> String {
        match self.principal_name.as_deref() {
            Some(name) => format!("{} \"{}\"", self.principal_kind.replace('_', " "), name),
            None => self.principal_kind.replace('_', " "),
        }
    }
}

/// Parameters for opening a new approval request.
#[derive(Debug, Clone)]
pub struct NewApproval {
    pub credential: String,
    pub action: String,
    pub params: serde_json::Value,
    pub requester: RequesterInfo,
    pub use_token_id: Option<String>,
    /// Time-to-live; after this the request auto-expires if undecided.
    pub ttl: chrono::Duration,
}

/// A request for a human to approve (or deny) a specific authenticated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique id, format `appr_<uuid>` — this is what the agent polls with.
    pub id: String,
    /// Current lifecycle state.
    pub status: ApprovalStatus,
    /// Credential alias the action would use.
    pub credential: String,
    /// Fully-qualified action (`http.request`, `postgres.run_sql`, ...).
    pub action: String,
    /// Action parameters (no credential secrets) — what the approver reviews.
    pub params: serde_json::Value,
    /// Human one-liner describing the action.
    pub summary: String,
    /// Who requested it.
    pub requester: RequesterInfo,
    /// Use token to consume on execution, if the request was token-authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_token_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    /// Channel/identity that decided it (`admin panel`, `telegram`, `webhook`...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_note: Option<String>,
    /// SHA-256 of the out-of-band decision token (plaintext is shown only in
    /// the notification links).
    pub decision_token_hash: String,
    /// Set while a serving process is executing the approved action, to keep two
    /// concurrent polls from running it twice.
    #[serde(default)]
    pub executing: bool,
    /// When the current execution claim was taken. Used to detect and recover a
    /// stale claim left behind by a crashed worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executing_since: Option<DateTime<Utc>>,
    /// Whether the approved action has run.
    #[serde(default)]
    pub executed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_error: Option<String>,
}

impl ApprovalRequest {
    /// Open a new pending request. Returns the request plus the **plaintext**
    /// decision token (only its hash is stored on the request).
    pub fn open(params: NewApproval) -> (ApprovalRequest, String) {
        let now = Utc::now();
        let (decision_token, decision_token_hash) = generate_decision_token();
        let summary = summarize(&params.credential, &params.action, &params.params);

        let request = ApprovalRequest {
            id: format!("appr_{}", uuid::Uuid::new_v4()),
            status: ApprovalStatus::Pending,
            credential: params.credential,
            action: params.action,
            params: params.params,
            summary,
            requester: params.requester,
            use_token_id: params.use_token_id,
            created_at: now,
            expires_at: now + params.ttl,
            decided_at: None,
            decided_by: None,
            decision_note: None,
            decision_token_hash,
            executing: false,
            executing_since: None,
            executed: false,
            result_status: None,
            result_body: None,
            result_error: None,
        };

        (request, decision_token)
    }

    /// Whether the TTL has elapsed (independent of stored status).
    pub fn is_past_ttl(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// If pending but past its TTL, flip to `Expired`. Returns true if changed.
    pub fn expire_if_due(&mut self) -> bool {
        if self.status == ApprovalStatus::Pending && self.is_past_ttl() {
            self.status = ApprovalStatus::Expired;
            self.decided_at = Some(Utc::now());
            self.decided_by = Some("system (expired)".to_string());
            true
        } else {
            false
        }
    }

    /// Mark approved. Errors if the request is no longer pending.
    pub fn approve(&mut self, by: impl Into<String>, note: Option<String>) -> Result<(), ApprovalError> {
        self.transition(ApprovalStatus::Approved, by, note)
    }

    /// Mark denied. Errors if the request is no longer pending.
    pub fn deny(&mut self, by: impl Into<String>, note: Option<String>) -> Result<(), ApprovalError> {
        self.transition(ApprovalStatus::Denied, by, note)
    }

    fn transition(
        &mut self,
        to: ApprovalStatus,
        by: impl Into<String>,
        note: Option<String>,
    ) -> Result<(), ApprovalError> {
        if self.is_past_ttl() {
            self.expire_if_due();
            return Err(ApprovalError::Expired);
        }
        if self.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyDecided(self.status));
        }
        self.status = to;
        self.decided_at = Some(Utc::now());
        self.decided_by = Some(by.into());
        self.decision_note = note;
        Ok(())
    }

    /// Constant-time check of a presented out-of-band decision token.
    pub fn verify_decision_token(&self, token: &str) -> bool {
        let presented = hash_decision_token(token);
        let a = presented.as_bytes();
        let b = self.decision_token_hash.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Build approve/deny/panel links for notifications, given the public base
    /// URL and the plaintext decision token from [`ApprovalRequest::open`].
    pub fn links(&self, base_url: &str, decision_token: &str) -> ApprovalLinks {
        let base = base_url.trim_end_matches('/');
        let enc = urlencoding::encode(decision_token);
        ApprovalLinks {
            approve_url: format!("{}/approvals/{}/decide?token={}&decision=approve", base, self.id, enc),
            deny_url: format!("{}/approvals/{}/decide?token={}&decision=deny", base, self.id, enc),
            panel_url: format!("{}/approvals", base),
        }
    }
}

/// Errors when transitioning an approval request.
#[derive(Debug, Clone, Error)]
pub enum ApprovalError {
    #[error("approval request has already been {0}")]
    AlreadyDecided(ApprovalStatus),
    #[error("approval request has expired")]
    Expired,
    #[error("approval request not found")]
    NotFound,
    #[error("invalid decision token")]
    InvalidToken,
}

/// Links embedded in out-of-band notifications.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalLinks {
    pub approve_url: String,
    pub deny_url: String,
    pub panel_url: String,
}

/// Build a human-readable one-line summary of a gated action.
pub fn summarize(credential: &str, action: &str, params: &serde_json::Value) -> String {
    // HTTP-style requests: surface method + URL.
    let method = params.get("method").and_then(|v| v.as_str());
    let url = params.get("url").and_then(|v| v.as_str());
    if let (Some(method), Some(url)) = (method, url) {
        return format!("{} {} (via {})", method.to_uppercase(), url, credential);
    }
    if let Some(url) = url {
        return format!("{} (via {})", url, credential);
    }
    format!("{} on {}", action, credential)
}

// ==================== Decision token helpers ====================

fn generate_decision_token() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_decision_token(&token);
    (token, hash)
}

fn hash_decision_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    STANDARD.encode(hasher.finalize())
}

// ==================== Configuration ====================

/// Runtime configuration for the approval subsystem.
#[derive(Debug, Clone, Default)]
pub struct ApprovalConfig {
    /// Whether approvals are enabled. When false, actions that would require
    /// approval are denied instead (fail-closed).
    pub enabled: bool,
    /// Default time-to-live for a pending request, in seconds.
    pub ttl_secs: u64,
    /// Public base URL of the web server (e.g. `https://vault.example.com`),
    /// used to build approve/deny links for Telegram/webhook/email.
    pub public_base_url: Option<String>,
    /// Telegram bot notifier configuration.
    pub telegram: Option<TelegramConfig>,
    /// Generic webhook notifier configuration.
    pub webhook: Option<WebhookConfig>,
}

impl ApprovalConfig {
    /// Effective TTL as a `chrono::Duration`. `ttl_secs == 0` is treated as the
    /// sentinel for "use the default of 1 hour" (an approval with a zero TTL
    /// would be useless — it would expire before anyone could decide).
    pub fn ttl(&self) -> chrono::Duration {
        let secs = if self.ttl_secs == 0 { 3600 } else { self.ttl_secs };
        chrono::Duration::seconds(secs as i64)
    }
}

/// Telegram bot notifier config.
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

/// Generic webhook notifier config.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    /// Optional `Authorization` header value to send with the webhook POST.
    pub auth_header: Option<String>,
}

// ==================== Notifiers ====================

/// Error delivering an approval notification.
#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("notification transport error: {0}")]
    Transport(String),
    #[error("notifier misconfigured: {0}")]
    Config(String),
}

/// A channel that can tell a human a new approval is waiting.
#[async_trait::async_trait]
pub trait ApprovalNotifier: Send + Sync {
    /// Channel name for logging (e.g. `telegram`).
    fn channel(&self) -> &'static str;
    /// Deliver a notification for `approval`, embedding `links`.
    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError>;
}

/// Build the set of notifiers configured in `cfg`.
pub fn build_notifiers(cfg: &ApprovalConfig) -> Vec<std::sync::Arc<dyn ApprovalNotifier>> {
    let mut notifiers: Vec<std::sync::Arc<dyn ApprovalNotifier>> = Vec::new();
    if let Some(tg) = &cfg.telegram {
        notifiers.push(std::sync::Arc::new(TelegramNotifier::new(tg.clone())));
    }
    if let Some(wh) = &cfg.webhook {
        notifiers.push(std::sync::Arc::new(WebhookNotifier::new(wh.clone())));
    }
    notifiers
}

/// Notifier HTTP client with tight timeouts: notification dispatch is awaited
/// inline on the execute path, so a stalled Telegram/webhook endpoint must
/// never hang an agent's request.
fn notifier_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default()
}

/// Telegram bot notifier: sends a message with inline Approve/Deny URL buttons.
pub struct TelegramNotifier {
    config: TelegramConfig,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            config,
            client: notifier_client(),
        }
    }
}

#[async_trait::async_trait]
impl ApprovalNotifier for TelegramNotifier {
    fn channel(&self) -> &'static str {
        "telegram"
    }

    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError> {
        let api = format!("https://api.telegram.org/bot{}/sendMessage", self.config.bot_token);

        let text = format!(
            "\u{1F510} <b>Vultrino approval needed</b>\n\n{}\n\nRequested by: {}\nApproval ID: <code>{}</code>\nExpires: {}",
            html_escape(&approval.summary),
            html_escape(&approval.requester.describe()),
            html_escape(&approval.id),
            approval.expires_at.format("%Y-%m-%d %H:%M UTC"),
        );

        // Telegram inline-keyboard `url` buttons require absolute http(s) URLs.
        // Only attach buttons when we have a real base URL to point at.
        let mut body = serde_json::json!({
            "chat_id": self.config.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        if links.approve_url.starts_with("http") {
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[
                    { "text": "\u{2705} Approve", "url": links.approve_url },
                    { "text": "\u{274C} Deny", "url": links.deny_url },
                ]]
            });
        }

        let resp = self
            .client
            .post(&api)
            .json(&body)
            .send()
            .await
            // The bot token is in the request URL path; strip the URL from the
            // error so a transport failure never logs the secret.
            .map_err(|e| NotifyError::Transport(e.without_url().to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(NotifyError::Transport(format!(
                "telegram returned {}: {}",
                status, detail
            )));
        }
        Ok(())
    }
}

/// Generic webhook notifier: POSTs the approval + links as JSON to a URL.
///
/// Point it at an email-sending service, Slack, Zapier, or your own endpoint to
/// turn an approval into an email confirmation link, a chat message, etc.
pub struct WebhookNotifier {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookNotifier {
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: notifier_client(),
        }
    }
}

#[async_trait::async_trait]
impl ApprovalNotifier for WebhookNotifier {
    fn channel(&self) -> &'static str {
        "webhook"
    }

    async fn notify(&self, approval: &ApprovalRequest, links: &ApprovalLinks) -> Result<(), NotifyError> {
        let payload = serde_json::json!({
            "event": "approval.requested",
            "approval": {
                "id": approval.id,
                "summary": approval.summary,
                "credential": approval.credential,
                "action": approval.action,
                "requested_by": approval.requester.describe(),
                "created_at": approval.created_at,
                "expires_at": approval.expires_at,
            },
            "links": links,
        });

        let mut req = self.client.post(&self.config.url).json(&payload);
        if let Some(auth) = &self.config.auth_header {
            req = req.header(reqwest::header::AUTHORIZATION, auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| NotifyError::Transport(e.without_url().to_string()))?;

        if !resp.status().is_success() {
            return Err(NotifyError::Transport(format!(
                "webhook returned {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Minimal HTML escaping for Telegram `parse_mode: HTML`.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_approval() -> (ApprovalRequest, String) {
        ApprovalRequest::open(NewApproval {
            credential: "stripe-prod".to_string(),
            action: "http.request".to_string(),
            params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
            requester: RequesterInfo {
                principal_kind: "api_key".to_string(),
                principal_id: Some("k1".to_string()),
                principal_name: Some("agent".to_string()),
                role: Some("executor".to_string()),
            },
            use_token_id: None,
            ttl: chrono::Duration::hours(1),
        })
    }

    #[test]
    fn test_summarize_http() {
        let s = summarize(
            "stripe-prod",
            "http.request",
            &serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
        );
        assert!(s.contains("POST"));
        assert!(s.contains("stripe-prod"));
        assert!(s.contains("api.stripe.com"));
    }

    #[test]
    fn test_summarize_generic() {
        let s = summarize("db-prod", "postgres.run_sql", &serde_json::json!({}));
        assert_eq!(s, "postgres.run_sql on db-prod");
    }

    #[test]
    fn test_open_is_pending_with_summary() {
        let (a, token) = new_approval();
        assert_eq!(a.status, ApprovalStatus::Pending);
        assert!(a.id.starts_with("appr_"));
        assert!(!a.executed);
        assert!(a.summary.contains("api.stripe.com"));
        assert!(!token.is_empty());
    }

    #[test]
    fn test_decision_token_roundtrip() {
        let (a, token) = new_approval();
        assert!(a.verify_decision_token(&token));
        assert!(!a.verify_decision_token("wrong-token"));
        // Hash is stored, not the plaintext.
        assert_ne!(a.decision_token_hash, token);
    }

    #[test]
    fn test_approve_then_cannot_redecide() {
        let (mut a, _) = new_approval();
        a.approve("admin panel", None).unwrap();
        assert_eq!(a.status, ApprovalStatus::Approved);
        assert!(a.decided_at.is_some());

        let err = a.deny("admin panel", None).unwrap_err();
        assert!(matches!(err, ApprovalError::AlreadyDecided(ApprovalStatus::Approved)));
    }

    #[test]
    fn test_expired_cannot_be_approved() {
        let (mut a, _) = new_approval();
        a.expires_at = Utc::now() - chrono::Duration::minutes(1);
        let err = a.approve("admin panel", None).unwrap_err();
        assert!(matches!(err, ApprovalError::Expired));
        assert_eq!(a.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_links_embed_token_and_id() {
        let (a, token) = new_approval();
        let links = a.links("https://vault.example.com/", &token);
        assert!(links.approve_url.contains(&a.id));
        assert!(links.approve_url.contains("decision=approve"));
        assert!(links.deny_url.contains("decision=deny"));
        assert!(links.panel_url.ends_with("/approvals"));
    }
}
