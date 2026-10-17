//! No secret over plain http:// to a public address (VUL-29).
//!
//! Every client that sends a secret or a decision-bearing payload to an operator-configured
//! endpoint (the averin and govder plane clients, the outbox pusher, the approval webhook, the
//! request CLI) accepts `https://` anywhere and `http://` only for a loopback or private
//! destination (`localhost`, a loopback or RFC 1918 literal, a compose or cluster service name
//! that resolves to such an address). The same rule the HTTP plugin applies to agent-chosen
//! URLs, so no secret-bearing path in vultrino can cross a public network in clear text.
//!
//! Two layers: [`check`] at construction or config load (scheme and IP literal, and a name that
//! already resolves to a public address), and [`guard`], which for an `http://` URL gives the
//! client a connect-time resolver that returns only loopback or private addresses, so a name
//! that later resolves to a public address fails the connection.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

fn internal(ip: &IpAddr) -> bool {
    crate::plugins::is_internal_destination_ip(ip)
}

/// Refuse a URL that would send a secret in clear text over a public network.
pub fn check(url: &str) -> Result<(), String> {
    let u = url::Url::parse(url.trim()).map_err(|e| format!("invalid URL: {e}"))?;
    match u.scheme() {
        "https" => return Ok(()),
        "http" => {}
        s => {
            return Err(format!(
                "URL scheme '{s}' is not allowed (https, or http to a private address)"
            ))
        }
    }
    let refuse = || {
        Err(
            "plain http:// to a public address is refused: this endpoint receives a secret or a \
             decision-bearing payload. Use https://, or name a loopback or private address."
                .to_string(),
        )
    };
    match u.host() {
        None => Err("URL must have a host".to_string()),
        Some(url::Host::Ipv4(ip)) => {
            if internal(&IpAddr::V4(ip)) {
                Ok(())
            } else {
                refuse()
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if internal(&IpAddr::V6(ip)) {
                Ok(())
            } else {
                refuse()
            }
        }
        Some(url::Host::Domain(name)) => {
            let port = u.port_or_known_default().unwrap_or(80);
            // An unresolvable name is not refused here: the connect-time resolver from
            // `guard` refuses it if it ever resolves to a public address.
            match (name, port).to_socket_addrs() {
                Ok(addrs) => {
                    if addrs.into_iter().any(|a| !internal(&a.ip())) {
                        refuse()
                    } else {
                        Ok(())
                    }
                }
                Err(_) => Ok(()),
            }
        }
    }
}

struct PrivateOnlyResolver;

impl Resolve for PrivateOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            let resolved: std::io::Result<Vec<SocketAddr>> =
                tokio::task::spawn_blocking(move || {
                    (host.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|it| it.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let addrs = resolved
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let private = private_only(addrs)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::from(e) })?;
            let it: Addrs = Box::new(private.into_iter());
            Ok(it)
        })
    }
}

/// Keep only loopback or private addresses; fail closed when none remain.
fn private_only(addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, &'static str> {
    let kept: Vec<SocketAddr> = addrs.into_iter().filter(|a| internal(&a.ip())).collect();
    if kept.is_empty() {
        Err("plain http:// refused: host does not resolve to a loopback or private address")
    } else {
        Ok(kept)
    }
}

/// Build-time half: for an `http://` URL, resolve at connect time to private addresses only.
/// Also never follows a redirect off the configured endpoint for such a client.
pub fn guard(builder: reqwest::ClientBuilder, url: &str) -> reqwest::ClientBuilder {
    let is_http = url::Url::parse(url.trim())
        .map(|u| u.scheme() == "http")
        .unwrap_or(false);
    if is_http {
        builder
            .dns_resolver(std::sync::Arc::new(PrivateOnlyResolver))
            .redirect(reqwest::redirect::Policy::none())
    } else {
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_plain_http_is_refused_everything_else_admitted() {
        for u in [
            "http://203.0.113.9/x",
            "http://8.8.8.8:8080/",
            "http://[2606:4700::1111]/",
            "http://[::ffff:8.8.8.8]/",
            "HTTP://1.1.1.1/",
            "http://169.254.169.254/",
        ] {
            assert!(check(u).is_err(), "{u}");
        }
        for u in [
            "https://example.com/x",
            "https://8.8.8.8/",
            "http://127.0.0.1:8080",
            "http://[::1]:9/",
            "http://10.1.2.3/",
            "http://192.168.1.5/",
            "http://localhost:7879",
            "http://no-such-host.invalid/",
        ] {
            assert!(check(u).is_ok(), "{u}");
        }
        assert!(check("ftp://127.0.0.1/").is_err());
        assert!(check("not a url").is_err());
    }

    #[test]
    fn the_connect_time_resolver_keeps_only_private_addresses() {
        let pub_ = "8.8.8.8:0".parse().unwrap();
        let lo = "127.0.0.1:0".parse().unwrap();
        assert_eq!(private_only(vec![pub_, lo]).unwrap(), vec![lo]);
        assert!(private_only(vec![pub_]).is_err());
        assert!(private_only(vec![]).is_err());
    }

    /// Each secret-bearing client refuses a public plain-http endpoint when it is built or its
    /// config is loaded, and admits https and a loopback http endpoint.
    #[test]
    fn every_secret_bearing_client_refuses_public_plain_http() {
        use crate::averin::{AverinClient, AverinConfig};
        use crate::govder::{GovderClient, GovderConfig};
        let averin = |url: &str| {
            AverinClient::new(AverinConfig {
                enabled: true,
                base_url: url.to_string(),
                resource_id: "r".to_string(),
                ..AverinConfig::default()
            })
        };
        assert!(averin("http://203.0.113.9:8080").is_err());
        assert!(averin("http://127.0.0.1:8080").is_ok());
        assert!(averin("https://averin.example.com").is_ok());
        let govder = |url: &str| {
            GovderClient::new(GovderConfig {
                base_url: url.to_string(),
                assertion_secret: "s".to_string(),
                approval_assertion_secret: None,
                allow_shared_approval_key: false,
                assertion_ttl: std::time::Duration::from_secs(60),
                http_timeout: std::time::Duration::from_secs(5),
            })
        };
        assert!(govder("http://198.51.100.7:8080").is_err());
        assert!(govder("http://127.0.0.1:8080").is_ok());
        assert!(govder("https://govder.example.com").is_ok());
    }

    /// The webhook and outbox destinations are refused at config load.
    #[test]
    fn webhook_and_outbox_urls_are_refused_at_config_load() {
        use crate::config::Config;
        let webhook = |url: &str| {
            Config::parse(&format!(
                "[approvals]\noob_approver_identity = \"ops\"\n[approvals.webhook]\nurl = \"{url}\"\n"
            ))
        };
        assert!(webhook("http://203.0.113.9/hook").is_err());
        assert!(webhook("http://10.0.0.5/hook").is_ok());
        assert!(webhook("https://hooks.example.com/x").is_ok());
        let outbox = |url: &str| {
            Config::parse(&format!(
                "[outbox]\nurl = \"{url}\"\nhmac_secret = \"0123456789abcdef0123456789abcdef\"\n"
            ))
        };
        assert!(outbox("http://203.0.113.9/in").is_err());
        assert!(outbox("http://127.0.0.1:9/in").is_ok());
        assert!(outbox("https://consumer.example.com/in").is_ok());
    }

    /// A new secret-bearing client builder must go through `plain_http::guard`. The scan covers
    /// non-test source; the HTTP plugin (its own SSRF guard refuses public plain http) and
    /// internal_http (pinned private destinations) are exempt.
    #[test]
    fn every_client_builder_goes_through_the_plain_http_guard() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out)
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p)
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let mut seen = 0;
        let mut missing = Vec::new();
        for f in files {
            let name = f.file_name().unwrap().to_string_lossy().to_string();
            if name == "plain_http.rs"
                || name == "http.rs"
                || name == "internal_http.rs"
                || name.ends_with("tests.rs")
                || name.ends_with("_test.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            let end = (0..lines.len())
                .find(|&i| {
                    lines[i].trim_start().starts_with("#[cfg(test)]")
                        && lines.get(i + 1).is_some_and(|n| n.contains("mod "))
                })
                .unwrap_or(lines.len());
            for (i, l) in lines[..end].iter().enumerate() {
                if l.contains("Client::builder()") && !l.trim_start().starts_with("//") {
                    seen += 1;
                    let from = i.saturating_sub(2);
                    let chain = lines[from..(i + 4).min(end)].join("\n");
                    if !chain.contains("plain_http::guard") {
                        missing.push(format!("{}:{}", f.display(), i + 1));
                    }
                }
            }
        }
        assert!(seen >= 4, "the scan found only {seen} builders");
        // The request CLI lives in the binary: its URL check is asserted textually.
        let main = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
        )
        .unwrap();
        assert!(
            main.contains("plain_http::check(&api_url)")
                && main.contains("plain_http::guard(reqwest::Client::builder(), &api_url)"),
            "the request CLI must check and guard VULTRINO_API_URL"
        );
        assert!(
            missing.is_empty(),
            "builders without plain_http::guard: {missing:?}"
        );
    }
}
