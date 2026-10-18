//! The posture report a real router serves carries what feir-os's `averin_use_checks` reads from
//! vultrino: `averin.enabled` and `averin.api_key_configured`, beside the `averin-api-key`
//! fingerprint. Without `api_key_configured` that verifier rule fails every keyed averin whether or
//! not vultrino holds the key. The jq side is exercised by feir-os's own tests; this pins the
//! producer through the real `/api/v1/posture` route.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use secrecy::SecretString;
use tempfile::tempdir;
use tower::ServiceExt;

use vultrino::auth::AuthManager;
use vultrino::config::Config;
use vultrino::secret_fp::fingerprint;
use vultrino::storage::{FileStorage, StorageBackend};
use vultrino::web::{AdminAuth, WebConfig, WebServer};

async fn posture_for(config: Config) -> serde_json::Value {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    let password = SecretString::from("test-password");
    let storage: Arc<dyn StorageBackend> =
        Arc::new(FileStorage::new(&path, &password).await.unwrap());
    let auth_manager = AuthManager::new();
    let (admin_key, api_key) = auth_manager
        .create_api_key("admin-key", "admin", None)
        .unwrap();
    storage.store_api_key(&api_key).await.unwrap();
    let admin = AdminAuth::new("admin", "password123").unwrap();
    let resolver = vultrino::router::CredentialResolver::new(storage.clone());
    let exec_server = Arc::new(vultrino::server::VultrinoServer::new(
        config.clone(),
        storage.clone(),
        resolver,
    ));
    let router = WebServer::new(
        WebConfig {
            bind: "127.0.0.1:0".to_string(),
            enabled: true,
        },
        config,
        storage,
        auth_manager,
        admin,
        exec_server,
    )
    .into_router();
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/posture")
                .header("authorization", format!("Bearer {admin_key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn averin_config(enabled: bool, key: Option<&str>) -> Config {
    let mut cfg = Config::parse(&format!(
        "[averin]\nenabled = {enabled}\nbase_url = \"http://127.0.0.1:1\"\nresource_id = \"r\"\n"
    ))
    .unwrap();
    cfg.averin.api_key = key.map(str::to_string);
    cfg
}

#[tokio::test]
async fn keyed_seal_client_reports_enabled_and_api_key_configured_with_the_fingerprint() {
    let key = "averin-project-bearer-0123456789";
    let report = posture_for(averin_config(true, Some(key))).await;
    assert_eq!(report["averin"]["enabled"], true);
    assert_eq!(report["averin"]["api_key_configured"], true);
    assert_eq!(
        report["secret_fingerprints"]["averin-api-key"],
        serde_json::json!([fingerprint(key, "averin-api-key").unwrap()])
    );
    assert!(!report.to_string().contains(key));
}

#[tokio::test]
async fn seal_client_without_a_key_reports_api_key_configured_false_and_no_fingerprint() {
    let report = posture_for(averin_config(true, None)).await;
    assert_eq!(report["averin"]["enabled"], true);
    assert_eq!(report["averin"]["api_key_configured"], false);
    assert!(report["secret_fingerprints"]
        .get("averin-api-key")
        .is_none());
}
