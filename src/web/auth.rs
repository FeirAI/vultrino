//! Admin authentication for the web UI

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower_sessions::Session;

/// Session key for storing authentication state
const SESSION_KEY: &str = "vultrino_admin";
/// Session key for storing CSRF token
const CSRF_KEY: &str = "vultrino_csrf";
/// Maximum login attempts before rate limiting kicks in
const MAX_LOGIN_ATTEMPTS: u32 = 5;
/// Window duration for rate limiting (in seconds)
const RATE_LIMIT_WINDOW_SECS: u64 = 300; // 5 minutes
/// Lockout duration after too many failed attempts (in seconds)
const LOCKOUT_DURATION_SECS: u64 = 900; // 15 minutes
/// Hard cap on distinct IPs tracked, bounding the map even if the periodic cleanup falls behind. With
/// the socket-peer keying (X-Forwarded-For honored only behind a trusted proxy) this is unreachable in
/// practice, but it guarantees the in-path PEP can't be driven to OOM by login traffic.
const MAX_TRACKED_IPS: usize = 100_000;

/// Rate limiter for login attempts
///
/// Tracks login attempts by IP address and blocks IPs that exceed
/// the maximum number of attempts within the rate limit window.
#[derive(Debug, Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<RwLock<HashMap<IpAddr, Vec<Instant>>>>,
    lockouts: Arc<RwLock<HashMap<IpAddr, Instant>>>,
}

impl LoginRateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            lockouts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an IP is currently locked out
    pub async fn is_locked_out(&self, ip: &IpAddr) -> bool {
        let lockouts = self.lockouts.read().await;
        if let Some(lockout_start) = lockouts.get(ip) {
            let lockout_duration = Duration::from_secs(LOCKOUT_DURATION_SECS);
            if lockout_start.elapsed() < lockout_duration {
                return true;
            }
        }
        false
    }

    /// Check if a login attempt is allowed (not rate limited)
    /// Returns Ok(()) if allowed, Err with remaining seconds if blocked
    pub async fn check_rate_limit(&self, ip: &IpAddr) -> Result<(), u64> {
        // Check for lockout first
        let lockouts = self.lockouts.read().await;
        if let Some(lockout_start) = lockouts.get(ip) {
            let lockout_duration = Duration::from_secs(LOCKOUT_DURATION_SECS);
            let elapsed = lockout_start.elapsed();
            if elapsed < lockout_duration {
                let remaining = lockout_duration - elapsed;
                return Err(remaining.as_secs());
            }
        }
        drop(lockouts);

        // Check attempt count in current window
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        if let Some(ip_attempts) = attempts.get_mut(ip) {
            // Remove old attempts outside the window
            ip_attempts.retain(|t| now.duration_since(*t) < window);

            if ip_attempts.len() >= MAX_LOGIN_ATTEMPTS as usize {
                // Calculate remaining time in window
                if let Some(oldest) = ip_attempts.first() {
                    let remaining = window.saturating_sub(now.duration_since(*oldest));
                    return Err(remaining.as_secs());
                }
            }
        }

        Ok(())
    }

    /// Record a failed login attempt
    pub async fn record_failed_attempt(&self, ip: &IpAddr) {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Bound the map: at capacity for a NEW key, reclaim expired entries inline; if still full, skip
        // tracking this one (fail toward not-throttling a single new IP rather than unbounded growth).
        if attempts.len() >= MAX_TRACKED_IPS && !attempts.contains_key(ip) {
            attempts.retain(|_, ts| {
                ts.retain(|t| now.duration_since(*t) < window);
                !ts.is_empty()
            });
            if attempts.len() >= MAX_TRACKED_IPS {
                return;
            }
        }

        let ip_attempts = attempts.entry(*ip).or_insert_with(Vec::new);

        // Clean up old attempts
        ip_attempts.retain(|t| now.duration_since(*t) < window);

        // Add new attempt
        ip_attempts.push(now);

        // Check if we need to lock out this IP
        if ip_attempts.len() >= MAX_LOGIN_ATTEMPTS as usize {
            drop(attempts);
            let mut lockouts = self.lockouts.write().await;
            lockouts.insert(*ip, now);
        }
    }

    /// Clear attempts for an IP after successful login
    pub async fn clear_attempts(&self, ip: &IpAddr) {
        let mut attempts = self.attempts.write().await;
        attempts.remove(ip);

        let mut lockouts = self.lockouts.write().await;
        lockouts.remove(ip);
    }

    /// Clean up old entries (call periodically to prevent memory leaks)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        let lockout_duration = Duration::from_secs(LOCKOUT_DURATION_SECS);

        // Clean up old attempts
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < window);
            !timestamps.is_empty()
        });
        drop(attempts);

        // Clean up old lockouts
        let mut lockouts = self.lockouts.write().await;
        lockouts.retain(|_, lockout_start| {
            lockout_start.elapsed() < lockout_duration
        });
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Admin authentication manager
#[derive(Debug, Clone)]
pub struct AdminAuth {
    /// Bcrypt hash of the admin password
    password_hash: String,
    /// Admin username
    username: String,
}

impl AdminAuth {
    /// Create a new admin auth from username and password
    pub fn new(username: &str, password: &str) -> Result<Self, bcrypt::BcryptError> {
        let password_hash = hash(password, DEFAULT_COST)?;
        Ok(Self {
            password_hash,
            username: username.to_string(),
        })
    }

    /// Create from existing password hash (loaded from storage)
    pub fn from_hash(username: String, password_hash: String) -> Self {
        Self {
            password_hash,
            username,
        }
    }

    /// Verify a password against the stored hash
    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password hash (for storage)
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    /// Hash a password (utility function)
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }
}

/// Session data stored in the cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSession {
    pub username: String,
    pub authenticated: bool,
    pub authenticated_at: i64,
}

impl WebSession {
    /// Create a new authenticated session
    pub fn authenticated(username: &str) -> Self {
        Self {
            username: username.to_string(),
            authenticated: true,
            authenticated_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Check if the session is valid (not too old)
    pub fn is_valid(&self) -> bool {
        if !self.authenticated {
            return false;
        }

        // Sessions expire after 24 hours
        let now = chrono::Utc::now().timestamp();
        let max_age = 24 * 60 * 60; // 24 hours in seconds

        now - self.authenticated_at < max_age
    }
}

/// Extractor for requiring authentication
///
/// Use this in route handlers to require an authenticated admin session:
/// ```ignore
/// async fn protected_route(auth: RequireAuth, ...) -> impl IntoResponse {
///     // This handler only runs if the user is authenticated
/// }
/// ```
pub struct RequireAuth {
    pub session: WebSession,
}

impl<S> FromRequestParts<S> for RequireAuth
where
    Arc<AdminAuth>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Get the session
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| {
                Redirect::to("/login").into_response()
            })?;

        // Check for valid session data
        let web_session: Option<WebSession> = session
            .get(SESSION_KEY)
            .await
            .ok()
            .flatten();

        match web_session {
            Some(ws) if ws.is_valid() => Ok(RequireAuth { session: ws }),
            _ => {
                // Not authenticated or session expired
                Err(Redirect::to("/login").into_response())
            }
        }
    }
}

/// Helper to set the session after successful login
pub async fn set_authenticated_session(
    session: &Session,
    username: &str,
) -> Result<(), StatusCode> {
    let web_session = WebSession::authenticated(username);
    session
        .insert(SESSION_KEY, web_session)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

/// Helper to clear the session on logout
pub async fn clear_session(session: &Session) -> Result<(), StatusCode> {
    session.flush().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

/// Generate a new CSRF token and store it in the session
pub async fn generate_csrf_token(session: &Session) -> Result<String, StatusCode> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);

    session
        .insert(CSRF_KEY, token.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token)
}

/// Get the current CSRF token from the session, generating one if needed
pub async fn get_or_create_csrf_token(session: &Session) -> Result<String, StatusCode> {
    if let Ok(Some(token)) = session.get::<String>(CSRF_KEY).await {
        return Ok(token);
    }
    generate_csrf_token(session).await
}

/// Validate a CSRF token against the session using constant-time comparison
pub async fn validate_csrf_token(session: &Session, token: &str) -> bool {
    let stored: Option<String> = session.get(CSRF_KEY).await.ok().flatten();

    match stored {
        Some(stored_token) => {
            let stored_bytes = stored_token.as_bytes();
            let provided_bytes = token.as_bytes();

            // Use constant-time comparison
            if stored_bytes.len() != provided_bytes.len() {
                return false;
            }
            stored_bytes.ct_eq(provided_bytes).into()
        }
        None => false,
    }
}

/// Regenerate the CSRF token after a successful form submission
/// This prevents token reuse attacks
pub async fn regenerate_csrf_token(session: &Session) -> Result<String, StatusCode> {
    generate_csrf_token(session).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_auth_creation() {
        let auth = AdminAuth::new("admin", "secret123").unwrap();
        assert!(auth.verify_password("secret123"));
        assert!(!auth.verify_password("wrong"));
    }

    #[test]
    fn test_web_session_validity() {
        let session = WebSession::authenticated("admin");
        assert!(session.is_valid());

        // Test expired session
        let expired = WebSession {
            username: "admin".to_string(),
            authenticated: true,
            authenticated_at: chrono::Utc::now().timestamp() - (25 * 60 * 60), // 25 hours ago
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_csrf_token_generation() {
        // Test that generated tokens are the correct length and format
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);

        // Base64 URL-safe encoding of 32 bytes = 43 characters
        assert_eq!(token.len(), 43);
        // Should only contain URL-safe characters
        assert!(token.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_initial_attempts() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First few attempts should be allowed
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            assert!(limiter.check_rate_limit(&ip).await.is_ok());
            limiter.record_failed_attempt(&ip).await;
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_after_max_attempts() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.2".parse().unwrap();

        // Record max failed attempts
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            limiter.record_failed_attempt(&ip).await;
        }

        // Next check should be blocked
        let result = limiter.check_rate_limit(&ip).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_clear_on_success() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.3".parse().unwrap();

        // Record some failed attempts
        for _ in 0..3 {
            limiter.record_failed_attempt(&ip).await;
        }

        // Clear attempts (simulating successful login)
        limiter.clear_attempts(&ip).await;

        // Should be allowed again
        assert!(limiter.check_rate_limit(&ip).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_isolates_ips() {
        let limiter = LoginRateLimiter::new();
        let ip1: IpAddr = "192.168.1.10".parse().unwrap();
        let ip2: IpAddr = "192.168.1.11".parse().unwrap();

        // Block ip1
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            limiter.record_failed_attempt(&ip1).await;
        }

        // ip1 should be blocked
        assert!(limiter.check_rate_limit(&ip1).await.is_err());

        // ip2 should still be allowed
        assert!(limiter.check_rate_limit(&ip2).await.is_ok());
    }
}
