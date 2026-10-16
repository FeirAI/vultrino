//! VUL-29: the guarded outbound client ignores the ambient proxy environment, routes only
//! https targets through the explicit VULTRINO_UPSTREAM_PROXY opt-in, and plain http://
//! targets are refused at admission in every mode.
//!
//! Own test binary: it mutates process environment. A single test fn keeps ordering fixed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::any;
use axum::Router;
use vultrino::plugins::proxy_test_support::{admit_hmac_url, admit_url, guarded_client};

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

    // 2. Plain http:// to a public host is refused at admission in EVERY mode, because the
    //    plugin injects a credential and the request would carry it in clear text: with no
    //    proxy, with a remote proxy and with a loopback proxy. https is still admitted.
    for proxy_setting in [
        None,
        Some("http://10.255.255.1:3128".to_string()),
        Some("http://[2001:db8::1]:3128".to_string()),
        Some("http://proxy.example.invalid:3128".to_string()),
        Some("http://localhost:3128".to_string()),
        Some("http://[::1]:3128".to_string()),
        Some(proxy_url.clone()),
    ] {
        match &proxy_setting {
            Some(v) => std::env::set_var("VULTRINO_UPSTREAM_PROXY", v),
            None => std::env::remove_var("VULTRINO_UPSTREAM_PROXY"),
        }
        for url in ["http://93.184.216.34/api", "http://8.8.8.8/api"] {
            let err = admit_url(url).expect_err(&format!("{url} under {proxy_setting:?}"));
            assert!(err.contains("plain http://"), "{err}");
        }
        if proxy_setting.is_none() {
            admit_url("https://93.184.216.34/api").expect("https is admitted");
        }
    }

    // A proxy named by a host name is refused at client construction (only an IP literal
    // works, because a name is resolved through the target SSRF guard).
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "http://localhost:3128");
    assert!(
        std::panic::catch_unwind(guarded_client).is_err(),
        "a host-name proxy must stop client construction"
    );

    // 2b. Even with a loopback proxy configured, the client never hands an http:// request
    //     to it: the request is not proxied, so the proxy sees nothing.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", &proxy_url);
    let client = guarded_client();
    let _ = client
        .get(format!("http://127.0.0.1:{target_port}/y"))
        .send()
        .await
        .expect("an http target is not routed via the proxy");
    assert_eq!(
        proxy.load(Ordering::SeqCst),
        0,
        "the proxy saw an http:// request"
    );
    assert_eq!(target.load(Ordering::SeqCst), 2, "went direct");

    // 2b'. The proxy's private CA: set without a proxy it is refused (it would only widen the
    //      trust of direct connections); unreadable or not a certificate it stops construction.
    std::env::remove_var("VULTRINO_UPSTREAM_PROXY");
    std::env::set_var("VULTRINO_UPSTREAM_PROXY_CA_FILE", "/nonexistent/ca.pem");
    assert!(
        std::panic::catch_unwind(guarded_client).is_err(),
        "a CA with no proxy must stop client construction"
    );
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", &proxy_url);
    assert!(
        std::panic::catch_unwind(guarded_client).is_err(),
        "an unreadable CA must stop client construction"
    );
    let junk = std::env::temp_dir().join(format!("vultrino-junk-ca-{}.pem", std::process::id()));
    std::fs::write(&junk, b"not a certificate").unwrap();
    std::env::set_var("VULTRINO_UPSTREAM_PROXY_CA_FILE", &junk);
    assert!(
        std::panic::catch_unwind(guarded_client).is_err(),
        "a CA that is not PEM must stop client construction"
    );
    let _ = std::fs::remove_file(&junk);
    std::env::remove_var("VULTRINO_UPSTREAM_PROXY_CA_FILE");

    // 2c. With the proxy set, a host this machine cannot resolve is refused at admission: the
    //     proxy would resolve it in its own DNS view. Without the proxy it is not refused here
    //     (the connect fails on its own), so the behaviour is unchanged.
    for u in [
        "http://unresolvable-zz9q.invalid/x",
        "https://unresolvable-zz9q.invalid/x",
    ] {
        admit_url(u).expect_err(u);
    }
    admit_hmac_url("https://unresolvable-zz9q.invalid/x").expect_err("hmac plugin too");
    std::env::remove_var("VULTRINO_UPSTREAM_PROXY");
    admit_url("https://unresolvable-zz9q.invalid/x").expect("no proxy: connect-time failure");
    admit_hmac_url("https://unresolvable-zz9q.invalid/x").expect("no proxy: connect-time failure");
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", &proxy_url);

    // 3. A malformed opt-in fails closed at client construction.
    std::env::set_var("VULTRINO_UPSTREAM_PROXY", "socks5://x");
    let r = std::panic::catch_unwind(guarded_client);
    assert!(r.is_err(), "invalid opt-in must not fall back to direct");
}
