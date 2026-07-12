//! Plan 086 spike proof + latency measurement — the "fourth contract"
//! (vultrino → averin per-use grant/use sealing).
//!
//! Harness choice: a **vultrino-side integration test against a REAL averin-server
//! binary** (not the four-plane e2e, not a stub). Rationale: the plan explicitly
//! permits this ("a vultrino-side integration test against a stub/real averin is
//! acceptable — say which you did and why"), and only a REAL averin can (a)
//! byte-validate the grant/use PoP (averin 400s a wrong preimage), (b) produce a
//! genuinely sealed `use` record that `GET /v2/export` / `GET /v2/verify` show,
//! and (c) yield a MEANINGFUL added-latency number (real crypto + real
//! consume-before-act ledger write). A stub would echo, not seal, and its latency
//! would be noise. Extending `govder/e2e/` would drag in three unrelated planes
//! for a flag-off spike — heavier than warranted here.
//!
//! This exercises the seal-client (`vultrino::averin::AverinClient`) directly —
//! which is exactly the code `run_action`/`api_create_token` call at the hook
//! sites (`av.on_mint` → `seal_grant`, `av.on_execute` → `seal_use`). The hook
//! wiring itself is covered by the default-off unit tests + the compiler.
//!
//! `#[ignore]` because it spawns an external binary. Run it with:
//!   AVERIN_SERVER_BIN=/Users/dzcodes/Projects/feir-ai/averin/server/averin-server \
//!   cargo test --test averin_spike -- --ignored --nocapture

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vultrino::averin::{AverinClient, AverinConfig, AverinMode};

const DEFAULT_AVERIN_BIN: &str = "/Users/dzcodes/Projects/feir-ai/averin/server/averin-server";
const RESOURCE_ID: &str = "orders-db";
const PROJECT: &str = "vultrino";
const SESSION: &str = "s1";
// Spike-safe grant scope/action (pass averin's forbidden-scope classifier).
const SCOPE: &str = "read:orders";
const ACTION: &str = "db.query:orders-ro";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A spawned averin-server, killed on drop.
struct Averin {
    child: Child,
    base_url: String,
}

impl Drop for Averin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_averin() -> Averin {
    let bin = std::env::var("AVERIN_SERVER_BIN").unwrap_or_else(|_| DEFAULT_AVERIN_BIN.to_string());
    let port = free_port();
    // Three pairwise-distinct 32-byte seeds (R2: signing ≠ broker ≠ resource).
    let child = Command::new(&bin)
        .env("AVERIN_SIGNING_SEED", "11".repeat(32))
        .env("AVERIN_BROKER_ISSUING_SEED", "22".repeat(32))
        .env("AVERIN_RESOURCE_SEED", "33".repeat(32))
        .env("AVERIN_RESOURCE_ID", RESOURCE_ID)
        .env("AVERIN_ADDR", format!(":{port}"))
        // no AVERIN_DATABASE_URL => in-memory store + in-memory ledger, both
        // broker (/v2/grants) and resource (/v2/use) enabled.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!("failed to spawn averin-server at {bin} ({e}); set AVERIN_SERVER_BIN or build it: (cd averin && cargo build -p averin-decision-core && cd server && go build -o averin-server ./cmd/averin-server)")
        });
    Averin {
        child,
        base_url: format!("http://127.0.0.1:{port}"),
    }
}

async fn wait_healthz(base_url: &str) {
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{base_url}/healthz")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("averin-server did not become healthy at {base_url}");
}

fn client(base_url: &str, mode: AverinMode) -> AverinClient {
    AverinClient::new(AverinConfig {
        enabled: true,
        base_url: base_url.to_string(),
        project_id: PROJECT.to_string(),
        session_id: SESSION.to_string(),
        resource_id: RESOURCE_ID.to_string(),
        api_key: None,
        mode,
        timeout: Duration::from_secs(5),
        grant_ttl_secs: 300,
        max_inflight_seals: 256,
    })
    .expect("client builds")
    .expect("client is Some when enabled")
}

/// Deliverable 3: a `vut_`-driven mint+execute produces a REAL sealed `use` record
/// that averin's export/verify show, with `resource_trust: assumed_truthful` and
/// the grant↔use join. If the PoP preimages were off by a byte, averin would 400
/// the grant or use and these `unwrap()`s would fail.
#[tokio::test]
#[ignore = "spawns a real averin-server binary; run with --ignored"]
async fn sealed_use_record_appears_in_averin_export() {
    let av = spawn_averin();
    wait_healthz(&av.base_url).await;
    let client = client(&av.base_url, AverinMode::Observe);
    let http = reqwest::Client::new();

    let token_id = "vut_spike_0001";
    // mint -> POST /v2/grants (record-before-issue)
    client
        .seal_grant(token_id, SCOPE, ACTION, Some(1))
        .await
        .expect("grant seals (byte-exact grant PoP accepted by real averin)");
    // execute -> POST /v2/use (consume-before-act one-phase receipt)
    let use_record_id = client
        .seal_use(token_id, br#"{"q":"select 1"}"#)
        .await
        .expect("use seals (byte-exact use PoP + params commitment accepted by real averin)");
    eprintln!("[086] sealed use record_id = {use_record_id}");
    assert!(
        use_record_id.starts_with("use-"),
        "averin returns a use-<uuid> record id, got {use_record_id}"
    );

    // GET /v2/export — the raw sealed bundle must contain this use record.
    let export = http
        .get(format!("{}/v2/export?project={PROJECT}", av.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        export.contains(&use_record_id),
        "export bundle must contain the sealed use record {use_record_id}"
    );

    // GET /v2/verify — the offline verifier RE-RUNS the use PoP and emits the
    // trust labels. resource_trust:assumed_truthful is unconditional on any
    // bundle with a resource gateway.
    let verify = http
        .get(format!("{}/v2/verify?project={PROJECT}", av.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    eprintln!("[086] verify report = {verify}");
    assert!(
        verify.contains("\"resource_trust\":\"assumed_truthful\""),
        "verify report must carry resource_trust:assumed_truthful; got: {verify}"
    );
    // Honest capstone note (see docs/dev/averin-sealing.md §6): a THIN single-
    // phase /v2/use provably cannot reach `attested_complete_over_brokered_surface`
    // (that needs two-phase + coverage_manifest + attestation + taxonomy). We do
    // NOT assert the capstone here — asserting it would be dishonest to the bound.
    // We print action_completeness so the go/no-go can record what it actually is.
    if let Some(i) = verify.find("action_completeness") {
        eprintln!("[086] {}", &verify[i..(i + 60).min(verify.len())]);
    }
}

/// Deliverable 4: measure the added `/execute` latency with the seal ON vs OFF.
/// The seal is the ONLY added work on `/execute`, so `seal_use`'s round-trip IS
/// the added latency. OFF ≈ 0 (the call is skipped when `self.averin == None`).
/// Numbers are a LOCALHOST + in-memory-averin FLOOR — production adds real network
/// RTT and averin's Postgres consume on top (see the go/no-go in the design doc).
#[tokio::test]
#[ignore = "spawns a real averin-server binary; run with --ignored"]
async fn measure_added_execute_latency() {
    let av = spawn_averin();
    wait_healthz(&av.base_url).await;
    let client = client(&av.base_url, AverinMode::Observe);

    const N: usize = 50;
    // warm up (first request pays connection setup)
    client.seal_grant("vut_warm", SCOPE, ACTION, Some(1)).await.unwrap();
    let _ = client.seal_use("vut_warm", b"{}").await;

    let mut samples: Vec<Duration> = Vec::with_capacity(N);
    for i in 0..N {
        let tid = format!("vut_lat_{i:04}");
        // single_operation is single-use, so each measured execute needs a fresh
        // grant (the grant seal is the mint-path cost, excluded from the measure).
        client.seal_grant(&tid, SCOPE, ACTION, Some(1)).await.unwrap();
        let t0 = Instant::now();
        client.seal_use(&tid, br#"{"q":"select 1"}"#).await.unwrap();
        samples.push(t0.elapsed());
    }
    samples.sort();
    let p = |q: f64| samples[((N as f64 * q) as usize).min(N - 1)];
    let sum: Duration = samples.iter().sum();
    let mean = sum / N as u32;

    eprintln!("[086] ADDED /execute latency with seal ON (sync POST /v2/use), N={N}, localhost+in-memory averin:");
    eprintln!("[086]   min    = {:?}", samples[0]);
    eprintln!("[086]   p50    = {:?}", p(0.50));
    eprintln!("[086]   mean   = {mean:?}");
    eprintln!("[086]   p90    = {:?}", p(0.90));
    eprintln!("[086]   p99    = {:?}", p(0.99));
    eprintln!("[086]   max    = {:?}", samples[N - 1]);
    eprintln!("[086] ADDED /execute latency with seal OFF = ~0 (seal call skipped when [averin].enabled=false)");

    // A generous sanity ceiling so a pathological regression fails the run; the
    // real go/no-go is the recorded numbers + the ingestMu argument, not this bound.
    assert!(p(0.99) < Duration::from_millis(500), "p99 seal latency unexpectedly high: {:?}", p(0.99));
}
