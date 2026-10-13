//! VUL-29: the guarded outbound client ignores the ambient proxy environment, routes only
//! https targets through the explicit VULTRINO_UPSTREAM_PROXY opt-in, and refuses plain
//! http:// targets while that opt-in is set.
//!
//! Own test binary: it mutates process environment. A single test fn keeps ordering fixed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::any;
use axum::Router;
use vultrino::plugins::proxy_test_support::{admit_url, guarded_client};

async fn hit(State(n): State<Arc<AtomicUsize>>) -> &'static str {
    n.fetch_add(1, Ordering::SeqCst);
    "ok"
}

async fn server() -> (u16, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let app = Router::new().fallback(any(hit)).with_state(n.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (port, n)
}

#[tokio::test]
async fn ambient_proxy_is_ignored_and_opt_in_never_carries_plain_http() {
    let (target_port, target) = server().await;
    let (proxy_port, proxy) = server().await;
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");

    // 1. Ambient proxy variables must not capture the request.
    for k in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(k, &proxy_url);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    std::env::remove_var("VULTRINO_UPSTREAM_PROXY");
    let client = guarded_client();
    let r = client
        .get(format!("http://127.0.0.1:{target_port}/x"))
        .send()
        .await
        .expect("direct connection");
    assert!(r.status().is_success());
    assert_eq!(
        proxy.load(Ordering::SeqCst),
        0,
        "ambient proxy captured the request"
    );
    assert_eq!(
        target.load(Ordering::SeqCst),
        1,
        "the request must go direct"
    );
    assert!(!vultrino::plugins::upstream_proxy_configured());

    // 2. With the explicit opt-in set: plain http:// is refused at admission, and the
    //    client never hands an http:// request to the proxy.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", &proxy_url);
    assert!(vultrino::plugins::upstream_proxy_configured());
    let err = admit_url("http://93.184.216.34/api").expect_err("plain http must be refused");
    assert!(
        err.contains("plain http://") && err.contains("VULTRINO_UPSTREAM_PROXY"),
        "{err}"
    );
    admit_url("https://93.184.216.34/api").expect("https is still admitted");
    let client = guarded_client();
    let _ = client
        .get(format!("http://127.0.0.1:{target_port}/y"))
        .send()
        .await
        .expect("http target is not routed via the proxy");
    assert_eq!(
        proxy.load(Ordering::SeqCst),
        0,
        "http request reached the proxy"
    );

    // 3. A malformed opt-in fails closed at client construction.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "socks5://x");
    let r = std::panic::catch_unwind(guarded_client);
    assert!(r.is_err(), "invalid opt-in must not fall back to direct");
}
