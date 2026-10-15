//! FEI-16: an INDIVIDUAL approver identity for Telegram decisions.
//!
//! A decision link carries no identity: whoever can read the chat can open it, so every link
//! verdict is recorded under the one configured `oob_approver_identity`, and a second link
//! click is refused as a duplicate approver (so two link clicks never complete a two-person
//! action; one link click plus one sign-off under another identity still does). Telegram does tell a bot WHO pressed a callback button: `callback_query.from.id` is
//! set by Telegram's servers and cannot be forged by a chat member. This module turns that into
//! an attributable decision:
//!
//! * the notifier sends `callback_data` buttons instead of URL buttons, so NO decision token is
//!   ever posted into the chat;
//! * [`run_callback_loop`] long-polls `getUpdates` (outbound only: nothing is exposed) and, for
//!   each button press, looks the Telegram user id up in the operator's `[approvals.telegram.
//!   approvers]` table. An unlisted user is told they may not decide and nothing is recorded;
//! * a listed user's verdict is recorded under THEIR named identity (channel `telegram:<id>`), so
//!   two different Telegram users are two different approvers: separation of duty, `exclude_owner`
//!   and the distinct-approver count of a two-person rule see the right person among Telegram
//!   users. Against a verified panel sign-off the strings are compared, so the mapped identity
//!   must BE the person's IdP subject for them to count once (see docs/dev/CONFIGURATION.md).
//!
//! What it does not do: it does not resolve an approver class (an approval gated by a govder
//! recipe that names classes still needs the broker's verified assertion), and a bot can have only
//! one `getUpdates` consumer, so the approvals bot must not be shared with another poller.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use tracing::{error, info, warn};

use crate::server::VultrinoServer;
use crate::storage::StorageBackend;

use super::TelegramConfig;

/// Prefix of `callback_data` ("vultrino telegram v1"). The whole value must fit Telegram's
/// 64-byte limit.
const CALLBACK_PREFIX: &str = "vtg1";
const MAX_CALLBACK_DATA_BYTES: usize = 64;

/// Telegram's public API host. Overridden only by tests (never by configuration).
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// Callback-decision settings, validated at config load.
#[derive(Debug, Clone)]
pub struct TelegramCallbackConfig {
    /// The numeric id of the one chat the buttons are posted in. A press from any other chat is
    /// ignored.
    pub chat_id: i64,
    approvers: HashMap<i64, String>,
}

impl TelegramCallbackConfig {
    /// Validate and build the settings. Fails closed on anything ambiguous.
    pub fn build(chat_id: &str, approvers: &[(String, String)]) -> Result<Self, String> {
        let chat_id: i64 = chat_id.trim().parse().map_err(|_| {
            "approvals.telegram: callback_decisions needs a NUMERIC chat_id (a group is negative, \
             for example -1001234567890); a @channel name cannot be matched against the chat a \
             button press came from"
                .to_string()
        })?;
        if approvers.is_empty() {
            return Err(
                "approvals.telegram: callback_decisions = true needs at least one entry in \
                 [approvals.telegram.approvers] (Telegram user id = approver identity); without \
                 one, nobody could decide"
                    .to_string(),
            );
        }
        let mut by_user: HashMap<i64, String> = HashMap::new();
        let mut seen_identities: HashMap<String, i64> = HashMap::new();
        for (user, identity) in approvers {
            let user_id: i64 = user.trim().parse().map_err(|_| {
                format!(
                    "approvals.telegram.approvers: key '{user}' is not a numeric Telegram user id"
                )
            })?;
            if user_id <= 0 {
                return Err(format!(
                    "approvals.telegram.approvers: '{user}' is not a user id (users are positive)"
                ));
            }
            let identity = identity.trim();
            if identity.is_empty() {
                return Err(format!(
                    "approvals.telegram.approvers: user {user_id} maps to a blank identity"
                ));
            }
            // A provenance prefix is how the approval engine tells a signed assertion
            // (`verified:`) or an aggregator's unverifiable claim (`agg:`) from a plain name.
            // A configured name must not be able to claim either.
            let lower = identity.to_ascii_lowercase();
            if lower.starts_with("verified:") || lower.starts_with("agg:") {
                return Err(format!(
                    "approvals.telegram.approvers: identity '{identity}' uses a reserved provenance prefix"
                ));
            }
            if by_user.insert(user_id, identity.to_string()).is_some() {
                return Err(format!(
                    "approvals.telegram.approvers: Telegram user {user_id} is listed twice"
                ));
            }
            if let Some(other) = seen_identities.insert(lower, user_id) {
                return Err(format!(
                    "approvals.telegram.approvers: Telegram users {other} and {user_id} map to the same identity '{identity}'; \
                     two people sharing one approver identity would collapse into one approver"
                ));
            }
        }
        Ok(Self {
            chat_id,
            approvers: by_user,
        })
    }

    /// The named approver identity for a Telegram user id, if the operator listed them.
    pub fn identity_for(&self, user_id: i64) -> Option<&str> {
        self.approvers.get(&user_id).map(String::as_str)
    }

    pub fn approver_count(&self) -> usize {
        self.approvers.len()
    }
}

/// `callback_data` for a button: `vtg1:a:<approval id>` or `vtg1:d:<approval id>`.
pub fn callback_data(approve: bool, approval_id: &str) -> Result<String, String> {
    let data = format!(
        "{CALLBACK_PREFIX}:{}:{approval_id}",
        if approve { "a" } else { "d" }
    );
    if data.len() > MAX_CALLBACK_DATA_BYTES {
        return Err(format!(
            "approval id is too long for a Telegram callback button ({} bytes, limit {})",
            data.len(),
            MAX_CALLBACK_DATA_BYTES
        ));
    }
    Ok(data)
}

/// Parse `callback_data` back to `(approve, approval id)`. Anything else is not ours.
pub fn parse_callback_data(data: &str) -> Option<(bool, &str)> {
    let rest = data.strip_prefix(CALLBACK_PREFIX)?.strip_prefix(':')?;
    let (verb, id) = rest.split_once(':')?;
    let approve = match verb {
        "a" => true,
        "d" => false,
        _ => return None,
    };
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some((approve, id))
}

#[derive(Debug, Deserialize)]
pub struct UpdatesResponse {
    pub ok: bool,
    #[serde(default)]
    pub result: Vec<Update>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: TgUser,
    #[serde(default)]
    pub message: Option<TgMessage>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TgUser {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct TgMessage {
    pub chat: TgChat,
}

#[derive(Debug, Deserialize)]
pub struct TgChat {
    pub id: i64,
}

/// What a button press resulted in; `text` is shown to the person who pressed it.
#[derive(Debug, PartialEq, Eq)]
pub struct CallbackOutcome {
    /// True when a verdict was recorded.
    pub recorded: bool,
    pub text: String,
}

fn refused(text: impl Into<String>) -> CallbackOutcome {
    CallbackOutcome {
        recorded: false,
        text: text.into(),
    }
}

/// Decide one callback press. Pure of Telegram I/O so it is testable; the loop answers the
/// press with the returned text.
pub async fn handle_callback_query(
    cb: &TelegramCallbackConfig,
    storage: &Arc<dyn StorageBackend>,
    server: &VultrinoServer,
    enforce_sod: bool,
    q: &CallbackQuery,
) -> CallbackOutcome {
    // 1. Only presses on a button in the configured chat.
    match q.message.as_ref().map(|m| m.chat.id) {
        Some(chat) if chat == cb.chat_id => {}
        _ => return refused("This button is not in the approvals chat; nothing was recorded."),
    }
    // 2. Only our own buttons.
    let Some((approve, approval_id)) = q.data.as_deref().and_then(parse_callback_data) else {
        return refused("Unrecognised button; nothing was recorded.");
    };
    // 3. Only a listed person. The identity comes from Telegram's `from.id`, not from anything
    //    the clicker typed.
    let Some(identity) = cb.identity_for(q.from.id) else {
        warn!(
            telegram_user = q.from.id,
            "telegram approval press from a user who is not in [approvals.telegram.approvers]; refused"
        );
        return refused(
            "You are not a registered approver for this deployment; nothing was recorded.",
        );
    };
    let channel = format!("telegram:{}", q.from.id);

    // 4. The approval must exist and still be open.
    let _ = storage.reload().await;
    match storage.get_approval(approval_id).await {
        Ok(Some(a)) if a.status().is_open() => {}
        Ok(Some(a)) => {
            return refused(format!("Already {}; nothing was recorded.", a.status()));
        }
        _ => return refused("No such approval request; nothing was recorded."),
    }

    // 5. Record the verdict as THIS person.
    let decided = match storage
        .decide_approval(
            approval_id,
            approve,
            &channel,
            identity,
            enforce_sod,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    {
        Ok(d) => d,
        Err(e) => return refused(format!("Not recorded: {e}")),
    };
    info!(
        approval_id,
        approver = identity,
        telegram_user = q.from.id,
        approve,
        "telegram approval decision recorded"
    );
    let status = decided.status();
    if approve && status == crate::approval::ApprovalStatus::Approved && !decided.executed {
        // The same resume the link and panel paths run once the threshold is met.
        if let Err(e) = server.check_and_resume_approval(approval_id, None).await {
            warn!(approval_id, error = %e, "approved via telegram; resume failed, durable recovery will claim it");
        }
    }
    let text = match (approve, status) {
        (true, crate::approval::ApprovalStatus::Approved) => {
            format!("Approved as {identity}. The action will run.")
        }
        (true, _) => {
            format!("Your approval is recorded as {identity}. More approvers are still needed.")
        }
        (false, crate::approval::ApprovalStatus::Denied) => {
            format!("Denied as {identity}. The action will not run.")
        }
        (false, _) => format!("Your denial is recorded as {identity}."),
    };
    CallbackOutcome {
        recorded: true,
        text,
    }
}

/// Long-poll `getUpdates` for button presses and decide them, forever. Outbound HTTPS only. The
/// bot token is in the request path, so transport errors are logged without the URL.
pub async fn run_callback_loop(
    tg: TelegramConfig,
    storage: Arc<dyn StorageBackend>,
    server: Arc<VultrinoServer>,
    enforce_sod: bool,
) {
    let Some(cb) = tg.callback.clone() else {
        return;
    };
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(40))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "telegram approval callbacks: cannot build the HTTP client; callbacks are OFF");
            return;
        }
    };
    info!(
        approvers = cb.approver_count(),
        "telegram approval callbacks: polling for button presses (each press is attributed to the person who pressed it)"
    );
    let get_updates = format!("{}/bot{}/getUpdates", tg.api_base, tg.bot_token);
    let answer = format!("{}/bot{}/answerCallbackQuery", tg.api_base, tg.bot_token);
    let mut offset: Option<i64> = None;
    let mut backoff = std::time::Duration::from_secs(2);
    loop {
        let mut body = serde_json::json!({
            "timeout": 25,
            "allowed_updates": ["callback_query"],
        });
        if let Some(o) = offset {
            body["offset"] = serde_json::json!(o);
        }
        let resp = match client.post(&get_updates).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e.without_url(), "telegram approval callbacks: getUpdates failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
                continue;
            }
        };
        let parsed: UpdatesResponse = match resp.json().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e.without_url(), "telegram approval callbacks: unreadable getUpdates answer; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
                continue;
            }
        };
        if !parsed.ok {
            error!(
                description = parsed.description.as_deref().unwrap_or("none"),
                "telegram approval callbacks: Telegram refused getUpdates (is a webhook set, or another process polling this bot? the approvals bot must have one consumer); retrying"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
            continue;
        }
        backoff = std::time::Duration::from_secs(2);
        for update in parsed.result {
            offset = Some(update.update_id + 1);
            let Some(q) = update.callback_query else {
                continue;
            };
            let outcome = handle_callback_query(&cb, &storage, &server, enforce_sod, &q).await;
            let reply = serde_json::json!({
                "callback_query_id": q.id,
                "text": outcome.text,
                "show_alert": true,
            });
            if let Err(e) = client.post(&answer).json(&reply).send().await {
                warn!(error = %e.without_url(), "telegram approval callbacks: answerCallbackQuery failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approvers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn callback_data_round_trips_and_fits_telegram_limit() {
        let id = "appr_0b9f3c6e-8a40-4f43-8b7e-5d4c1f2a9e11";
        let a = callback_data(true, id).unwrap();
        let d = callback_data(false, id).unwrap();
        assert!(a.len() <= 64 && d.len() <= 64);
        assert_eq!(parse_callback_data(&a), Some((true, id)));
        assert_eq!(parse_callback_data(&d), Some((false, id)));
        assert!(callback_data(true, &"x".repeat(80)).is_err());
    }

    #[test]
    fn foreign_or_malformed_callback_data_is_not_ours() {
        for bad in [
            "",
            "vtg1",
            "vtg1:",
            "vtg1:x:appr_1",
            "vtg2:a:appr_1",
            "vtg1:a:",
            "vtg1:a:ap pr",
            "vtg1:a:../x",
            "approve:appr_1",
        ] {
            assert_eq!(parse_callback_data(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn config_requires_a_numeric_chat_and_at_least_one_approver() {
        assert!(TelegramCallbackConfig::build("@channel", &approvers(&[("1", "a@x")])).is_err());
        assert!(TelegramCallbackConfig::build("-100123", &[]).is_err());
        let ok =
            TelegramCallbackConfig::build("-100123", &approvers(&[("11", "a@x"), ("22", "b@x")]))
                .unwrap();
        assert_eq!(ok.chat_id, -100123);
        assert_eq!(ok.identity_for(11), Some("a@x"));
        assert_eq!(ok.identity_for(22), Some("b@x"));
        assert_eq!(ok.identity_for(33), None);
    }

    #[test]
    fn config_never_collapses_two_people_into_one_approver() {
        // Same identity for two Telegram users, in any case.
        let err = TelegramCallbackConfig::build(
            "-1",
            &approvers(&[("11", "Ann@x.io"), ("22", "ann@X.io")]),
        )
        .unwrap_err();
        assert!(err.contains("collapse"), "{err}");
        // The same Telegram user twice.
        assert!(
            TelegramCallbackConfig::build("-1", &approvers(&[("11", "a@x"), ("11", "b@x")]))
                .is_err()
        );
    }

    #[test]
    fn config_rejects_bad_keys_blank_and_reserved_identities() {
        for (k, v) in [
            ("abc", "a@x"),
            ("0", "a@x"),
            ("-5", "a@x"),
            ("11", "  "),
            ("11", "verified:alice"),
            ("11", "AGG:key:alice"),
        ] {
            assert!(
                TelegramCallbackConfig::build("-1", &approvers(&[(k, v)])).is_err(),
                "({k:?}, {v:?}) must be refused"
            );
        }
    }

    // ---- decisions against a real vault -------------------------------------------------

    use crate::approval::{
        ApprovalRequest, ApprovalStatus, CriticalityClass, NewApproval, RequesterInfo,
    };
    use crate::config::Config;
    use crate::router::CredentialResolver;

    struct Rig {
        storage: Arc<dyn StorageBackend>,
        server: Arc<VultrinoServer>,
        cb: TelegramCallbackConfig,
        _dir: tempfile::TempDir,
    }

    async fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn StorageBackend> = Arc::new(
            crate::storage::FileStorage::new(
                dir.path().join("vault.enc"),
                &secrecy::SecretString::from("test-password"),
            )
            .await
            .unwrap(),
        );
        let server = Arc::new(VultrinoServer::new(
            Config::default(),
            storage.clone(),
            CredentialResolver::new(storage.clone()),
        ));
        let cb = TelegramCallbackConfig::build(
            "-1001",
            &approvers(&[("11", "alice@example.com"), ("22", "bob@example.com")]),
        )
        .unwrap();
        Rig {
            storage,
            server,
            cb,
            _dir: dir,
        }
    }

    async fn open_approval(rig: &Rig, dual_control: bool) -> String {
        let (approval, _token) = ApprovalRequest::open(NewApproval {
            credential: "stripe-prod".to_string(),
            action: "http.request".to_string(),
            params: serde_json::json!({"method": "post", "url": "https://api.stripe.com/v1/refunds"}),
            requester: RequesterInfo::local(),
            use_token_id: None,
            principal_id: None,
            agent_label: Some("refund-bot".to_string()),
            tenant: None,
            workload_id: None,
            preview: None,
            action_label: None,
            dual_control,
            criticality: CriticalityClass::Medium,
            trusted_irreversible: None,
            escalate_after: chrono::Duration::minutes(30),
            escalate_window: chrono::Duration::minutes(30),
            oob_identity: Some("oncall".to_string()),
            reauth_interval_secs: None,
            required_approvals: if dual_control { 2 } else { 1 },
            approval_rule: None,
        });
        rig.storage.store_approval(&approval).await.unwrap();
        approval.id
    }

    fn press(user: i64, chat: i64, approve: bool, id: &str) -> CallbackQuery {
        CallbackQuery {
            id: "cbq".to_string(),
            from: TgUser { id: user },
            message: Some(TgMessage {
                chat: TgChat { id: chat },
            }),
            data: Some(callback_data(approve, id).unwrap()),
        }
    }

    async fn decide(rig: &Rig, q: &CallbackQuery) -> CallbackOutcome {
        handle_callback_query(&rig.cb, &rig.storage, &rig.server, false, q).await
    }

    /// The point of FEI-16: two different people are two different approvers, so a two-person
    /// action completes only when BOTH have pressed, each recorded under their own identity and
    /// their own Telegram user id.
    #[tokio::test]
    async fn two_people_pressing_are_two_distinct_approvers() {
        let rig = rig().await;
        let id = open_approval(&rig, true).await;

        let first = decide(&rig, &press(11, -1001, true, &id)).await;
        assert!(first.recorded, "{first:?}");
        assert!(
            first.text.contains("alice@example.com") && first.text.contains("More approvers"),
            "{}",
            first.text
        );
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(
            a.status(),
            ApprovalStatus::Pending,
            "one person is not a two-person approval"
        );

        let second = decide(&rig, &press(22, -1001, true, &id)).await;
        assert!(second.recorded, "{second:?}");
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Approved);
        let who: Vec<(&str, &str)> = a
            .signoffs
            .iter()
            .map(|s| (s.approver_identity.as_str(), s.channel.as_str()))
            .collect();
        assert_eq!(
            who,
            vec![
                ("alice@example.com", "telegram:11"),
                ("bob@example.com", "telegram:22")
            ],
            "each sign-off carries the person's own identity and Telegram user id"
        );
    }

    /// One person cannot be two approvers by pressing twice.
    #[tokio::test]
    async fn the_same_person_pressing_twice_is_one_approver() {
        let rig = rig().await;
        let id = open_approval(&rig, true).await;
        assert!(decide(&rig, &press(11, -1001, true, &id)).await.recorded);
        let again = decide(&rig, &press(11, -1001, true, &id)).await;
        assert!(!again.recorded, "{again:?}");
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Pending);
        assert_eq!(a.signoffs.len(), 1);
    }

    /// A chat member who is not listed can press the button and nothing is recorded.
    #[tokio::test]
    async fn an_unlisted_chat_member_cannot_decide() {
        let rig = rig().await;
        let id = open_approval(&rig, false).await;
        let out = decide(&rig, &press(999, -1001, true, &id)).await;
        assert!(!out.recorded);
        assert!(
            out.text.contains("not a registered approver"),
            "{}",
            out.text
        );
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Pending);
        assert!(a.signoffs.is_empty());
    }

    /// A press that did not come from a button in the configured chat is ignored, even from a
    /// listed person (a forwarded or re-posted button).
    #[tokio::test]
    async fn a_press_outside_the_configured_chat_is_ignored() {
        let rig = rig().await;
        let id = open_approval(&rig, false).await;
        assert!(!decide(&rig, &press(11, -42, true, &id)).await.recorded);
        let mut no_msg = press(11, -1001, true, &id);
        no_msg.message = None;
        assert!(!decide(&rig, &no_msg).await.recorded);
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Pending);
    }

    #[tokio::test]
    async fn foreign_data_unknown_and_decided_approvals_record_nothing() {
        let rig = rig().await;
        let id = open_approval(&rig, false).await;
        let mut foreign = press(11, -1001, true, &id);
        foreign.data = Some("something-else".to_string());
        assert!(!decide(&rig, &foreign).await.recorded);
        assert!(
            !decide(&rig, &press(11, -1001, true, "appr_does-not-exist"))
                .await
                .recorded
        );
        // Decide it, then a second press on the decided request records nothing.
        assert!(decide(&rig, &press(11, -1001, false, &id)).await.recorded);
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Denied);
        let late = decide(&rig, &press(22, -1001, true, &id)).await;
        assert!(!late.recorded && late.text.contains("Already"), "{late:?}");
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(
            a.status(),
            ApprovalStatus::Denied,
            "a late approve must not undo a denial"
        );
    }

    /// One denial by a listed person denies a single-approver request.
    #[tokio::test]
    async fn a_listed_person_can_deny() {
        let rig = rig().await;
        let id = open_approval(&rig, false).await;
        let out = decide(&rig, &press(22, -1001, false, &id)).await;
        assert!(
            out.recorded && out.text.contains("bob@example.com"),
            "{out:?}"
        );
        let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
        assert_eq!(a.status(), ApprovalStatus::Denied);
        assert_eq!(a.signoffs[0].channel, "telegram:22");
    }

    // ---- the loop against a stand-in Telegram -------------------------------------------

    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTelegram {
        polls: Mutex<u32>,
        updates: Mutex<Vec<serde_json::Value>>,
        answers: Mutex<Vec<serde_json::Value>>,
        offsets: Mutex<Vec<Option<i64>>>,
    }

    async fn fake_telegram(state: Arc<FakeTelegram>) -> String {
        use axum::{extract::State, routing::post, Json, Router};
        async fn get_updates(
            State(s): State<Arc<FakeTelegram>>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            s.offsets.lock().unwrap().push(body["offset"].as_i64());
            let first = {
                let mut n = s.polls.lock().unwrap();
                *n += 1;
                *n == 1
            };
            if first {
                let updates = s.updates.lock().unwrap().clone();
                return Json(serde_json::json!({"ok": true, "result": updates}));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Json(serde_json::json!({"ok": true, "result": []}))
        }
        async fn answer(
            State(s): State<Arc<FakeTelegram>>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            s.answers.lock().unwrap().push(body);
            Json(serde_json::json!({"ok": true, "result": true}))
        }
        let app = Router::new()
            .route("/botTOKEN/getUpdates", post(get_updates))
            .route("/botTOKEN/answerCallbackQuery", post(answer))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// End to end through the polling loop: two presses from two Telegram users complete a
    /// two-person approval, each press is answered to the person who made it, and the offset moves
    /// past the processed updates.
    #[tokio::test]
    async fn the_loop_attributes_each_press_and_answers_it() {
        let rig = rig().await;
        let id = open_approval(&rig, true).await;
        let fake = Arc::new(FakeTelegram::default());
        let mk = |update_id: i64, user: i64, qid: &str| {
            serde_json::json!({
                "update_id": update_id,
                "callback_query": {
                    "id": qid, "from": {"id": user},
                    "message": {"chat": {"id": -1001}},
                    "data": callback_data(true, &id).unwrap(),
                }
            })
        };
        *fake.updates.lock().unwrap() = vec![mk(100, 11, "q1"), mk(101, 22, "q2")];
        let base = fake_telegram(fake.clone()).await;
        let tg = TelegramConfig {
            bot_token: "TOKEN".to_string(),
            chat_id: "-1001".to_string(),
            api_base: base,
            callback: Some(rig.cb.clone()),
        };
        let handle = tokio::spawn(run_callback_loop(
            tg,
            rig.storage.clone(),
            rig.server.clone(),
            false,
        ));
        let mut approved = false;
        for _ in 0..100 {
            let a = rig.storage.get_approval(&id).await.unwrap().unwrap();
            if a.status() == ApprovalStatus::Approved && fake.answers.lock().unwrap().len() == 2 {
                approved = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        handle.abort();
        assert!(approved, "the two presses did not complete the approval");
        let answers = fake.answers.lock().unwrap().clone();
        let to = |qid: &str| {
            answers
                .iter()
                .find(|a| a["callback_query_id"] == qid)
                .unwrap_or_else(|| panic!("no answer for {qid}: {answers:?}"))["text"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert!(to("q1").contains("alice@example.com"), "{}", to("q1"));
        assert!(to("q2").contains("bob@example.com"), "{}", to("q2"));
        let offsets = fake.offsets.lock().unwrap().clone();
        assert_eq!(offsets[0], None);
        assert!(
            offsets.iter().skip(1).all(|o| *o == Some(102)),
            "{offsets:?}"
        );
    }

    // ---- the notifier's buttons ----------------------------------------------------------

    async fn sent_message_body(callback: bool) -> serde_json::Value {
        use axum::{extract::State, routing::post, Json, Router};
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        async fn send(
            State(c): State<Arc<Mutex<Option<serde_json::Value>>>>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            *c.lock().unwrap() = Some(body);
            Json(serde_json::json!({"ok": true}))
        }
        let app = Router::new()
            .route("/botTOKEN/sendMessage", post(send))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rig = rig().await;
        let id = open_approval(&rig, false).await;
        let approval = rig.storage.get_approval(&id).await.unwrap().unwrap();
        let tg = TelegramConfig {
            bot_token: "TOKEN".to_string(),
            chat_id: "-1001".to_string(),
            api_base: format!("http://{addr}"),
            callback: callback.then(|| rig.cb.clone()),
        };
        let notifier = crate::approval::TelegramNotifier::new(tg);
        let links = crate::approval::ApprovalLinks {
            approve_url:
                "https://vault.example.com/approvals/x/decide?token=SECRETTOKEN&decision=approve"
                    .to_string(),
            deny_url:
                "https://vault.example.com/approvals/x/decide?token=SECRETTOKEN&decision=deny"
                    .to_string(),
            panel_url: "https://vault.example.com/approvals".to_string(),
        };
        crate::approval::ApprovalNotifier::notify(&notifier, &approval, &links)
            .await
            .unwrap();
        let body = captured
            .lock()
            .unwrap()
            .clone()
            .expect("sendMessage called");
        let mut body = body;
        body["_approval_id"] = serde_json::json!(id);
        body
    }

    /// In callback mode the chat carries no bearer decision link at all.
    #[tokio::test]
    async fn callback_mode_posts_buttons_with_no_decision_token() {
        let body = sent_message_body(true).await;
        let rendered = body.to_string();
        assert!(
            !rendered.contains("SECRETTOKEN"),
            "a decision token reached the chat: {rendered}"
        );
        assert!(
            !rendered.contains("\"url\""),
            "no URL button in callback mode: {rendered}"
        );
        let id = body["_approval_id"].as_str().unwrap();
        let row = &body["reply_markup"]["inline_keyboard"][0];
        assert_eq!(row[0]["callback_data"], callback_data(true, id).unwrap());
        assert_eq!(row[1]["callback_data"], callback_data(false, id).unwrap());
    }

    /// The default (no callback table) is unchanged: URL buttons carrying the link.
    #[tokio::test]
    async fn url_mode_is_unchanged() {
        let body = sent_message_body(false).await;
        let row = &body["reply_markup"]["inline_keyboard"][0];
        assert!(row[0]["url"].as_str().unwrap().contains("decision=approve"));
        assert!(row[1]["url"].as_str().unwrap().contains("decision=deny"));
        assert!(row[0].get("callback_data").is_none());
    }
}
