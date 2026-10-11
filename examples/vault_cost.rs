//! Vault cost benchmark (P3-VAULT). Reports deterministic work (bytes written, fsyncs, plaintext
//! bytes decrypted, AES-GCM decrypts, records written), not wall time, for:
//!
//! * one admin write (store a policy) and one use-token write,
//! * one dispatch fence read (`kill_fence_check`), and
//! * a 40-write provision burst,
//!
//! as a function of N stored use tokens (with N/10 policies) and K kill marks.
//!
//! Run: `cargo run --release --example vault_cost` (add `-- --json` for machine output).

use secrecy::SecretString;
use vultrino::auth::{NewUseToken, UseToken};
use vultrino::policy::{KillFenceQuery, Policy};
use vultrino::storage::{FileStorage, StorageBackend, VaultIoStats};

fn token(i: usize) -> UseToken {
    let (_plain, t) = UseToken::create(NewUseToken {
        name: format!("tok-{i}"),
        credential_scope: "*".into(),
        action_scope: None,
        max_uses: Some(100),
        require_approval: false,
        expires_in: None,
    });
    t
}

fn kill_policy(i: usize) -> Policy {
    let mut p = Policy::allow_all(&format!("kill-{i}"), &format!("agent-{i}-*"));
    p.id = format!("kill-pol-{i}");
    p.kill = true;
    p
}

struct Row {
    n: usize,
    k: usize,
    policy_write: VaultIoStats,
    token_write: VaultIoStats,
    dispatch_fence: VaultIoStats,
    provision_40: VaultIoStats,
    /// Total bytes written per write while building the vault up to N tokens (includes any
    /// compaction, so it shows the amortised cost).
    build_bytes_per_write: u64,
    /// A second handle on the same vault (standing in for a second process) running its fence
    /// check right after the first handle wrote one record.
    fence_after_foreign_write: VaultIoStats,
}

async fn measure(n: usize, k: usize) -> Row {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let s = FileStorage::new(&path, &SecretString::from("pw"))
        .await
        .unwrap();
    let build_start = s.io_stats();
    let mut build_writes = 0u64;
    for i in 0..n {
        s.store_use_token(&token(i)).await.unwrap();
        build_writes += 1;
        if i % 10 == 0 {
            s.store_policy(&Policy::allow_all(&format!("p{i}"), "gh-*"))
                .await
                .unwrap();
            build_writes += 1;
        }
    }
    let build_bytes_per_write = s
        .io_stats()
        .since(build_start)
        .bytes_written
        .checked_div(build_writes)
        .unwrap_or(0);
    for i in 0..k {
        // store then lift: the mark stays behind
        let p = kill_policy(i);
        s.store_policy(&p).await.unwrap();
        s.delete_policy(&p.id).await.unwrap();
    }
    let a = s.io_stats();
    s.store_policy(&Policy::allow_all("probe", "probe-*"))
        .await
        .unwrap();
    let b = s.io_stats();
    s.store_use_token(&token(n + 1)).await.unwrap();
    let c = s.io_stats();
    let _ = s
        .kill_fence_check(&KillFenceQuery {
            credential_alias: "gh-main",
            principal: None,
            admitted_epoch: s.kill_fence_epoch().await,
        })
        .await
        .unwrap();
    let d = s.io_stats();
    for i in 0..40 {
        s.store_use_token(&token(n + 10 + i)).await.unwrap();
    }
    let e = s.io_stats();
    // Second handle: open (full load), then watch what one foreign write costs it.
    let s2 = FileStorage::new(&path, &SecretString::from("pw"))
        .await
        .unwrap();
    s.store_policy(&Policy::allow_all("foreign", "foreign-*"))
        .await
        .unwrap();
    let f0 = s2.io_stats();
    let _ = s2
        .kill_fence_check(&KillFenceQuery {
            credential_alias: "gh-main",
            principal: None,
            admitted_epoch: 0,
        })
        .await
        .unwrap();
    let f1 = s2.io_stats();
    Row {
        build_bytes_per_write,
        fence_after_foreign_write: f1.since(f0),
        n,
        k,
        policy_write: b.since(a),
        token_write: c.since(b),
        dispatch_fence: d.since(c),
        provision_40: e.since(d),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let json = std::env::args().any(|a| a == "--json");
    let ns = [0usize, 100, 1_000, 5_000];
    let ks = [0usize, 100, 500];
    let mut rows = Vec::new();
    for &n in &ns {
        for &k in &ks {
            if n == 5_000 && k == 500 {
                continue;
            }
            rows.push(measure(n, k).await);
        }
    }
    if json {
        let v: Vec<_> = rows
            .iter()
            .map(|r| {
                let f = |s: VaultIoStats| {
                    serde_json::json!({"bytes_written": s.bytes_written, "fsyncs": s.fsyncs,
                    "bytes_decrypted": s.bytes_decrypted, "decrypts": s.decrypts,
                    "records_written": s.records_written})
                };
                serde_json::json!({"tokens": r.n, "kill_marks": r.k,
                    "policy_write": f(r.policy_write), "token_write": f(r.token_write),
                    "dispatch_fence": f(r.dispatch_fence), "provision_40": f(r.provision_40),
                    "build_bytes_per_write": r.build_bytes_per_write,
                    "fence_after_foreign_write": f(r.fence_after_foreign_write)})
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return;
    }
    println!(
        "{:>6} {:>5} | {:>10} {:>8} {:>10} {:>5} | {:>10} {:>10} {:>5} | {:>12} {:>12}",
        "tokens", "marks", "wr_bytes", "wr_recs", "wr_decrypt", "fsync", "fence_dec", "fence_dcnt", "", "prov40_bytes", "prov40_dec"
    );
    println!("build_B/write = average bytes written per write while building the vault (incl. compaction); foreign_dec = plaintext bytes a second handle decrypts for one fence check right after another handle wrote one record");
    for r in &rows {
        println!(
            "{:>6} {:>5} | {:>10} {:>8} {:>10} {:>5} | {:>10} {:>10} {:>5} | {:>12} {:>12}",
            r.n,
            r.k,
            r.policy_write.bytes_written,
            r.policy_write.records_written,
            r.policy_write.bytes_decrypted,
            r.policy_write.fsyncs,
            r.dispatch_fence.bytes_decrypted,
            r.dispatch_fence.decrypts,
            "",
            r.provision_40.bytes_written,
            r.provision_40.bytes_decrypted
        );
        println!(
            "         build_B/write={:>8}  foreign_dec={:>8} ({} decrypts)",
            r.build_bytes_per_write,
            r.fence_after_foreign_write.bytes_decrypted,
            r.fence_after_foreign_write.decrypts
        );
    }
}
