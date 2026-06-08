//! Web server implementation using Axum

use crate::auth::AuthManager;
use crate::config::Config;
use crate::storage::StorageBackend;
use axum::{
    extract::FromRef,
    http::{header, HeaderValue},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use crate::config::ServerMode;

use super::api;
use super::auth::{AdminAuth, LoginRateLimiter};
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

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub auth_manager: Arc<RwLock<AuthManager>>,
    pub admin_auth: Arc<AdminAuth>,
    pub config: Config,
    pub rate_limiter: LoginRateLimiter,
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
    /// Create a new web server
    pub fn new(
        config: WebConfig,
        vultrino_config: Config,
        storage: Arc<dyn StorageBackend>,
        auth_manager: AuthManager,
        admin_auth: AdminAuth,
    ) -> Self {
        let app_state = AppState {
            storage,
            auth_manager: Arc::new(RwLock::new(auth_manager)),
            admin_auth: Arc::new(admin_auth),
            config: vultrino_config,
            rate_limiter: LoginRateLimiter::new(),
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
            .route("/audit", get(routes::audit_log))
            // API endpoints for HTMX (web UI)
            .route("/api/stats", get(routes::api_stats))
            // JSON API endpoints (API key auth for CLI/external apps)
            .route("/api/v1/health", get(api::api_health))
            .route("/api/v1/credentials", get(api::api_list_credentials))
            .route("/api/v1/execute", post(api::api_execute))
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

    /// Run the web server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let router = self.build_router();
        let listener = tokio::net::TcpListener::bind(&self.config.bind).await?;

        tracing::info!(bind = %self.config.bind, "Starting Vultrino Web UI");

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
}
