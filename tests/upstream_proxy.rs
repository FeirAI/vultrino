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

    // 2. With the explicit opt-in set to a proxy that is NOT on this host: plain http:// is
    //    refused at admission, and the client never hands an http:// request to the proxy
    //    (it goes direct; the proxy address here is never contacted for it).
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "http://10.255.255.1:3128");
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
        .expect("an http target is not routed via a remote proxy");
    assert_eq!(target.load(Ordering::SeqCst), 2, "went direct");

    // A proxy named by a domain other than localhost is remote too.
    std::env::set_var(
        "VULTRINO_UPSTREAM_PROXY",
        "http://proxy.example.invalid:3128",
    );
    admit_url("http://93.184.216.34/api").expect_err("a domain proxy is not on this host");
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "http://[2001:db8::1]:3128");
    admit_url("http://93.184.216.34/api").expect_err("a public IPv6 proxy is remote");
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "http://localhost:3128");
    admit_url("http://93.184.216.34/api").expect("localhost is on this host");
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "http://[::1]:3128");
    admit_url("http://93.184.216.34/api").expect("::1 is on this host");

    // 2b. A proxy on this host (a loopback sidecar) may carry plain http: the hop never
    //     leaves the machine. The request reaches the proxy and not the target.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", &proxy_url);
    admit_url("http://93.184.216.34/api").expect("loopback proxy: plain http admitted");
    let client = guarded_client();
    let _ = client
        .get("http://93.184.216.34/z")
        .send()
        .await
        .expect("served by the loopback proxy");
    assert_eq!(
        proxy.load(Ordering::SeqCst),
        1,
        "routed via the loopback proxy"
    );
    assert_eq!(target.load(Ordering::SeqCst), 2);

    // 3. A malformed opt-in fails closed at client construction.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "socks5://x");
    let r = std::panic::catch_unwind(guarded_client);
    assert!(r.is_err(), "invalid opt-in must not fall back to direct");
}
