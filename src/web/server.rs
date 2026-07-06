//! Web server implementation using Axum

use crate::auth::AuthManager;
use crate::config::Config;
use crate::config::ServerMode;
use crate::storage::StorageBackend;
use axum::{
    extract::{DefaultBodyLimit, FromRef},
    http::{header, HeaderValue},
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use super::api;
use super::auth::{AdminAuth, LoginRateLimiter};
use super::llm_proxy;
use super::mcp_http;
use super::routes;

/// Web server configuration
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Address to bind the web server
    pub bind: String,
    /// Whether to enable the web UI
    pub enabled: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7879".to_string(),
            enabled: true,
        }
    }
}

/// How often the background task reclaims expired login-throttle entries (once per rate-limit window).
const LOGIN_THROTTLE_CLEANUP_SECS: u64 = 300;

/// Body-size cap for /mcp + /llm (vs axum's 2MB default): generous enough for full chat prompts and
/// base64 vision images, but still a hard memory bound for the in-path PEP. 32 MiB.
const LLM_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub auth_manager: Arc<RwLock<AuthManager>>,
    pub admin_auth: Arc<AdminAuth>,
    pub config: Config,
    pub rate_limiter: LoginRateLimiter,
    /// Honor X-Forwarded-For / X-Real-IP for the login throttle ONLY when set (VULTRINO_TRUST_FORWARDED_FOR)
    /// — i.e. vultrino runs behind a trusted proxy. Default false: key on the real socket peer so a
    /// client can't spoof a fresh rate-limit bucket per request. See routes::get_client_ip.
    pub trust_forwarded_for: bool,
    /// Shared execution server, built once with plugins loaded — reused by the
    /// JSON API handlers instead of rebuilding + re-scanning plugins per request.
    pub server: Arc<crate::server::VultrinoServer>,
    /// Govder decide-plane client for delegation grant/evaluate (plan 031).
    pub govder: Option<Arc<crate::govder::GovderClient>>,
}

impl FromRef<AppState> for Arc<dyn StorageBackend> {
    fn from_ref(state: &AppState) -> Self {
        state.storage.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<AuthManager>> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_manager.clone()
    }
}

impl FromRef<AppState> for Arc<AdminAuth> {
    fn from_ref(state: &AppState) -> Self {
        state.admin_auth.clone()
    }
}

/// Web server for Vultrino admin UI
pub struct WebServer {
    config: WebConfig,
    app_state: AppState,
}

impl WebServer {
    /// Create a new web server.
    ///
    /// `server` is the shared execution server (built once, plugins loaded) the
    /// JSON API handlers reuse.
    pub fn new(
        config: WebConfig,
        vultrino_config: Config,
        storage: Arc<dyn StorageBackend>,
        auth_manager: AuthManager,
        admin_auth: AdminAuth,
        server: Arc<crate::server::VultrinoServer>,
    ) -> Self {
        // Trust X-Forwarded-For only when explicitly declared behind a trusted proxy.
        let trust_forwarded_for = std::env::var("VULTRINO_TRUST_FORWARDED_FOR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let govder = vultrino_config
            .govder
            .as_ref()
            .and_then(|cfg| match crate::govder::GovderClient::new(cfg.clone()) {
                Ok(c) => Some(Arc::new(c)),
                Err(e) => {
                    tracing::error!(error = %e, "govder client init failed — delegate paths fail-closed");
                    None
                }
            });
        let app_state = AppState {
            storage,
            auth_manager: Arc::new(RwLock::new(auth_manager)),
            admin_auth: Arc::new(admin_auth),
            config: vultrino_config,
            rate_limiter: LoginRateLimiter::new(),
            trust_forwarded_for,
            server,
            govder,
        };

        Self { config, app_state }
    }

    /// Build the router with all routes
    fn build_router(&self) -> Router {
        // Session store for login sessions
        let session_store = MemoryStore::default();

        // Determine if we should use secure cookies and HSTS:
        // - TLS is configured, OR
        // - Running in Server mode (likely behind a reverse proxy with TLS)
        let use_secure_mode = self.app_state.config.server.tls.is_some()
            || self.app_state.config.server.mode == ServerMode::Server;

        let session_layer = SessionManagerLayer::new(session_store)
            // Secure flag - only send cookies over HTTPS
            .with_secure(use_secure_mode)
            // HttpOnly - prevent JavaScript access to session cookie
            .with_http_only(true)
            // SameSite - prevent CSRF by not sending cookies on cross-site requests
            .with_same_site(tower_sessions::cookie::SameSite::Strict)
            // Session expiry - 24 hours for admin sessions
            .with_expiry(Expiry::OnInactivity(time::Duration::hours(24)));

        // Static files (CSS, JS, images)
        let static_dir = ServeDir::new("static");

        // Build base router with routes
        let mut router = Router::new()
            // Public routes
            .route("/login", get(routes::login_page))
            .route("/login", post(routes::login_submit))
            .route("/logout", post(routes::logout))
            // Protected routes (require auth)
            .route("/", get(routes::dashboard))
            .route("/dashboard", get(routes::dashboard))
            .route("/credentials", get(routes::credentials_list))
            .route("/credentials/new", get(routes::credential_new))
            .route("/credentials/new", post(routes::credential_create))
            .route("/credentials/{id}/delete", post(routes::credential_delete))
            .route("/roles", get(routes::roles_list))
            .route("/roles/new", get(routes::role_new))
            .route("/roles/new", post(routes::role_create))
            .route("/roles/{id}/delete", post(routes::role_delete))
            .route("/keys", get(routes::keys_list))
            .route("/keys/new", get(routes::key_new))
            .route("/keys/new", post(routes::key_create))
            .route("/keys/{id}/revoke", post(routes::key_revoke))
            // Use tokens (single-use / time-scoped grants)
            .route("/tokens", get(routes::tokens_list))
            .route("/tokens/new", get(routes::token_new))
            .route("/tokens/new", post(routes::token_create))
            .route("/tokens/{id}/revoke", post(routes::token_revoke))
            // Action approvals
            .route("/approvals", get(routes::approvals_list))
            .route("/approvals/{id}/approve", post(routes::approval_approve))
            .route("/approvals/{id}/deny", post(routes::approval_deny))
            // Out-of-band decision links (Telegram / webhook / email).
            // Capability-token authorized, no session required.
            .route(
                "/approvals/{id}/decide",
                get(routes::approval_decide_confirm),
            )
            .route(
                "/approvals/{id}/decide",
                post(routes::approval_decide_submit),
            )
            .route("/audit", get(routes::audit_log))
            // API endpoints for HTMX (web UI)
            .route("/api/stats", get(routes::api_stats))
            // JSON API endpoints (API key auth for CLI/external apps)
            .route("/api/v1/health", get(api::api_health))
            .route(
                "/api/v1/credentials",
                get(api::api_list_credentials).post(api::api_create_credential),
            )
            .route(
                "/api/v1/credentials/{id}",
                delete(api::api_delete_credential),
            )
            .route("/api/v1/execute", post(api::api_execute))
            // Approvals JSON API: agent poll-by-id; admin-key list + decision
            // (A3/A4) for a product aggregator (tenant-partitioned in the handlers).
            .route("/api/v1/approvals", get(api::api_list_approvals))
            .route("/api/v1/approvals/{id}", get(api::api_check_approval))
            .route(
                "/api/v1/approvals/{id}/decision",
                post(api::api_decide_approval),
            )
            .route(
                "/api/v1/approvals/{id}/delegate-decision",
                post(api::api_delegate_decide_approval),
            )
            // Admin API (V1): runtime config-write surface (Permission::Admin).
            .route(
                "/api/v1/policies",
                get(api::api_list_policies).post(api::api_create_policy),
            )
            .route(
                "/api/v1/policies/{id}",
                put(api::api_put_policy).delete(api::api_delete_policy),
            )
            // Capabilities (named MCP tools) — connector M1 admin surface.
            .route(
                "/api/v1/capabilities",
                get(api::api_list_capabilities).post(api::api_create_capability),
            )
            .route(
                "/api/v1/capabilities/{id}",
                put(api::api_put_capability).delete(api::api_delete_capability),
            )
            .route(
                "/api/v1/tokens",
                get(api::api_list_tokens).post(api::api_create_token),
            )
            .route("/api/v1/tokens/{id}/revoke", post(api::api_revoke_token))
            .route(
                "/api/v1/approval-tokens",
                post(api::api_create_approval_token),
            )
            .route("/api/v1/auth/agent", get(api::api_resolve_agent_token))
            .route(
                "/api/v1/auth/agent/consume",
                post(api::api_consume_agent_token),
            )
            .route(
                "/api/v1/approval-tokens/{id}/revoke",
                post(api::api_revoke_approval_token),
            )
            .route("/api/v1/roles", post(api::api_create_role))
            .route("/api/v1/roles/{id}", delete(api::api_delete_role))
            // Kill/halt + session registry (V6).
            .route(
                "/api/v1/agents/{label}/halt",
                post(api::api_halt_agent).delete(api::api_unhalt_agent),
            )
            .route("/api/v1/sessions", get(api::api_list_sessions))
            // Metrics read-back (V12).
            .route("/api/v1/metrics", get(api::api_metrics))
            // Signed event outbox replay + DLQ (V9).
            .route("/api/v1/events", get(api::api_list_events))
            .route("/api/v1/events/dead", get(api::api_list_dead_letters))
            .route(
                "/api/v1/events/{sequence}/replay",
                post(api::api_replay_dead_letter),
            )
            // Networked MCP transport (connector M1): a remote agent harness
            // reaches vultrino's MCP over JSON-RPC here, authed + scoped by a
            // Bearer use-token (vut_) / one-time secret. vultrino holds the
            // secrets and is network-isolated from the agent.
            // /mcp + /llm carry large payloads (tool args, full chat prompts, base64 vision images), so
            // they get an explicit GENEROUS-BUT-BOUNDED body limit instead of axum's 2MB default (which
            // would 413 legitimate vision/large-context requests). The cap is still a hard memory bound —
            // scoped to these routes only so the small admin-form routes keep the tight default.
            .route(
                "/mcp",
                post(mcp_http::mcp_jsonrpc).layer(DefaultBodyLimit::max(LLM_MAX_BODY_BYTES)),
            )
            // Metered LLM proxy (connector M1, decision 5): a harness points its
            // model `base_url` here; the request is forwarded to the provider with
            // the vault model key injected and token spend metered (V13). The
            // catch-all path captures the OpenAI route the client appends (e.g.
            // `/v1/chat/completions`); a bare `/llm` POST is also accepted.
            .route(
                "/llm",
                post(llm_proxy::llm_proxy_root).layer(DefaultBodyLimit::max(LLM_MAX_BODY_BYTES)),
            )
            .route(
                "/llm/{*path}",
                post(llm_proxy::llm_proxy).layer(DefaultBodyLimit::max(LLM_MAX_BODY_BYTES)),
            )
            // Static files
            .nest_service("/static", static_dir);

        // Add HSTS header only in secure mode (TLS or behind proxy)
        if use_secure_mode {
            router = router.layer(SetResponseHeaderLayer::if_not_present(
                header::STRICT_TRANSPORT_SECURITY,
                // max-age=1 year, includeSubDomains
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }

        // Add security headers
        router
            .layer(SetResponseHeaderLayer::if_not_present(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                header::X_XSS_PROTECTION,
                HeaderValue::from_static("1; mode=block"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                header::REFERRER_POLICY,
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
                ),
            ))
            // Session layer
            .layer(session_layer)
            .layer(TraceLayer::new_for_http())
            .with_state(self.app_state.clone())
    }

    /// Consume the server and return its configured Axum router.
    ///
    /// Useful for in-process testing (e.g. `tower::ServiceExt::oneshot`) without
    /// binding a socket.
    pub fn into_router(self) -> Router {
        self.build_router()
    }

    /// Run the web server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = self.build_router();
        let listener = tokio::net::TcpListener::bind(&self.config.bind).await?;

        tracing::info!(bind = %self.config.bind, "Starting Vultrino Web UI");

        // Periodically reclaim expired login-throttle entries so the attempts/lockouts maps don't grow
        // unbounded over the process lifetime (cleanup() drops entries past their window). Cheap; runs
        // once per rate-limit window.
        {
            let rl = self.app_state.rate_limiter.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                    LOGIN_THROTTLE_CLEANUP_SECS,
                ));
                loop {
                    tick.tick().await;
                    rl.cleanup().await;
                }
            });
        }

        // Use into_make_service_with_connect_info to enable IP address extraction for rate limiting
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;

        Ok(())
    }

    /// Get the bind address
    pub fn bind_address(&self) -> &str {
        &self.config.bind
    }

    /// The process-shared `AuthManager` handle. Exposed so `main` can drive a
    /// cross-process refresh loop that rebuilds it from the vault (picking up
    /// `vk_` key/role revocations pushed via the admin API on a sibling process).
    /// Every enforcement edge on this process — `/api/v1/execute`, `/llm`, and the
    /// networked MCP transport — reads this same `Arc<RwLock<AuthManager>>`.
    pub fn auth_manager(&self) -> Arc<RwLock<AuthManager>> {
        self.app_state.auth_manager.clone()
    }
}
