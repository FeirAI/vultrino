//! Web UI for Vultrino administration
//!
//! Provides a server-side rendered web interface for managing:
//! - Credentials
//! - Roles and API keys
//! - Audit logs and statistics
//!
//! Also provides a JSON API for CLI and external applications using API key auth.

mod api;
mod auth;
mod llm_proxy;
mod mcp_http;
mod routes;
mod server;
mod templates;

pub use auth::{AdminAuth, WebSession};
pub use server::{WebConfig, WebServer};
