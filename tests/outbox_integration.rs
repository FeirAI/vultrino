//! V9 integration tests: the ordered, replayable, signed event outbox.

use std::sync::{Arc, Mutex};

use axum::{body::Bytes, extract::State, http::HeaderMap, http::StatusCode, routing::post, Router};
use secrecy::SecretString;
use tempfile::tempdir;

use vultrino::outbox::{sign_body, DeliveryState, OutboxConfig, EVENT_APPROVAL_REQUESTED};
use vultrino::storage::{FileStorage, StorageBackend};

async fn storage() -> Arc<dyn StorageBackend> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.enc");
    std::mem::forget(dir);
    let password = SecretString::from("pw");
    Arc::new(FileStorage::new(&path, &password).await.unwrap())
}

#[tokio::test]
async fn test_monotonic_append_and_gapfree_replay() {
    let storage = storage().await;
    // Append a mix of subjects.
    let s1 = storage.append_event("appr_1", EVENT_APPROVAL_REQUESTED, serde_json::json!({"n":1})).await.unwrap();
    let s2 = storage.append_event("appr_2", EVENT_APPROVAL_REQUESTED, serde_json::json!({"n":2})).await.unwrap();
    let s3 = storage.append_event("appr_1", "approval.approved", serde_json::json!({"n":3})).await.unwrap();
    // Sequences are monotonic and contiguous.
    assert_eq!((s1, s2, s3), (1, 2, 3));

    // Replay from the start → every event once, in order, no gaps.
    let all = storage.list_events_after(0, 100).await.unwrap();
    assert_eq!(all.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![1, 2, 3]);

    // Replay from a cursor → strictly after it (a consumer resuming after seq 2).
    let after2 = storage.list_events_after(2, 100).await.unwrap();
    assert_eq!(after2.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![3]);

    // Limit is honored.
    let first = storage.list_events_after(0, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].sequence, 1);
}

#[tokio::test]
async fn test_deliverable_events_preserve_per_subject_order() {
    let storage = storage().await;
    let a1 = storage.append_event("A", "e", serde_json::json!({})).await.unwrap();
    let _b2 = storage.append_event("B", "e", serde_json::json!({})).await.unwrap();
    let a3 = storage.append_event("A", "e", serde_json::json!({})).await.unwrap();

    // Earliest pending per subject: A's first (a1) and B's (b2) — A's later event
    // (a3) is withheld until a1 is delivered.
    let deliverable = storage.deliverable_events(100).await.unwrap();
    let seqs: Vec<u64> = deliverable.iter().map(|e| e.sequence).collect();
    assert_eq!(seqs, vec![a1, _b2], "earliest pending per subject");
    assert!(!seqs.contains(&a3), "A's later event withheld until its earlier one delivers");

    // Deliver a1 → a3 becomes the next deliverable for subject A.
    storage.record_event_delivery(a1, true, None, 5).await.unwrap();
    let deliverable = storage.deliverable_events(100).await.unwrap();
    assert!(deliverable.iter().any(|e| e.sequence == a3), "A advances to its next event");
}

#[tokio::test]
async fn test_dead_letter_after_max_attempts_then_replay() {
    let storage = storage().await;
    let seq = storage.append_event("A", "e", serde_json::json!({})).await.unwrap();
    let max = 3;
    // Fail it `max` times → dead-lettered.
    for _ in 0..max {
        storage.record_event_delivery(seq, false, Some("boom".to_string()), max).await.unwrap();
    }
    let dead = storage.list_dead_letter_events(100).await.unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].sequence, seq);
    assert_eq!(dead[0].delivery, DeliveryState::DeadLettered);
    assert_eq!(dead[0].attempts, max);
    // A dead-lettered event is not deliverable (doesn't block its subject).
    assert!(storage.deliverable_events(100).await.unwrap().is_empty());

    // Replay requeues it as pending.
    assert!(storage.replay_dead_letter_event(seq).await.unwrap());
    assert!(storage.list_dead_letter_events(100).await.unwrap().is_empty());
    let deliverable = storage.deliverable_events(100).await.unwrap();
    assert_eq!(deliverable.len(), 1);
    assert_eq!(deliverable[0].attempts, 0, "attempts reset on replay");
    // Replaying a non-dead-lettered sequence is a no-op.
    assert!(!storage.replay_dead_letter_event(999).await.unwrap());
}

#[tokio::test]
async fn test_gc_prunes_old_events() {
    let storage = storage().await;
    storage.append_event("A", "e", serde_json::json!({})).await.unwrap();
    storage.append_event("A", "e", serde_json::json!({})).await.unwrap();
    // retention 0 → cutoff is "now", and these were created strictly before → pruned.
    let pruned = storage.gc_outbox(0).await.unwrap();
    assert_eq!(pruned, 2);
    assert!(storage.list_events_after(0, 100).await.unwrap().is_empty());
}

// ---- end-to-end HMAC-signed delivery against a mock consumer ----

/// Captured deliveries: (Govder-Signature header, raw body bytes).
type Deliveries = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

#[derive(Clone, Default)]
struct Captured(Deliveries);

async fn capture_handler(State(cap): State<Captured>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let sig = headers
        .get("Govder-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    cap.0.lock().unwrap().push((sig, body.to_vec()));
    StatusCode::OK
}

#[tokio::test]
async fn test_signed_delivery_end_to_end_and_marks_delivered() {
    let storage = storage().await;
    let secret = "shared-hmac-secret";

    // Spin a mock consumer on an ephemeral port.
    let captured = Captured::default();
    let app = Router::new().route("/hook", post(capture_handler)).with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = OutboxConfig {
        enabled: true,
        url: Some(format!("http://{addr}/hook")),
        hmac_secret: Some(secret.to_string()),
        max_attempts: 3,
        retention_secs: 3600,
    };

    let seq = storage
        .append_event("appr_1", EVENT_APPROVAL_REQUESTED, serde_json::json!({"summary": "POST /refund"}))
        .await
        .unwrap();

    // One delivery pass.
    let client = reqwest::Client::new();
    vultrino::server::deliver_outbox_once(&storage, &config, &client).await.unwrap();

    // The consumer received exactly one delivery; the signature verifies under the
    // shared secret over the exact body bytes.
    let hits = captured.0.lock().unwrap().clone();
    assert_eq!(hits.len(), 1, "exactly one delivery");
    let (sig, body) = &hits[0];
    assert_eq!(*sig, sign_body(secret, body), "Govder-Signature verifies under the shared secret");
    // The body is the event envelope.
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(parsed["sequence"], seq);
    assert_eq!(parsed["event"], "approval.requested");
    assert_eq!(parsed["subject"], "appr_1");

    // The event is now Delivered → no longer deliverable, and not dead-lettered.
    assert!(storage.deliverable_events(100).await.unwrap().is_empty());
    let all = storage.list_events_after(0, 100).await.unwrap();
    assert_eq!(all[0].delivery, DeliveryState::Delivered);
    assert!(storage.list_dead_letter_events(100).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_failed_delivery_is_recorded_and_backed_off() {
    let storage = storage().await;
    // Mock consumer that always 500s.
    let app = Router::new().route("/hook", post(|| async { StatusCode::INTERNAL_SERVER_ERROR }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = OutboxConfig {
        enabled: true,
        url: Some(format!("http://{addr}/hook")),
        hmac_secret: Some("s".to_string()),
        max_attempts: 3,
        retention_secs: 3600,
    };
    let seq = storage.append_event("A", "e", serde_json::json!({})).await.unwrap();

    let client = reqwest::Client::new();
    // One pass: claims + POSTs once → a 500 records a failed attempt and a backoff
    // lease, so it is NOT re-attempted on the next immediate pass (no hammering).
    vultrino::server::deliver_outbox_once(&storage, &config, &client).await.unwrap();
    let after = storage.list_events_after(0, 10).await.unwrap();
    assert_eq!(after[0].sequence, seq);
    assert_eq!(after[0].attempts, 1, "one failed attempt recorded");
    assert_eq!(after[0].delivery, DeliveryState::Pending, "not yet dead-lettered");
    assert!(after[0].last_error.is_some(), "failure recorded");
    // The backoff lease withholds it from the next immediate claim.
    assert!(storage.claim_deliverable_events(10, 30).await.unwrap().is_empty(), "backed off");
}

#[tokio::test]
async fn test_dead_letters_after_max_via_record() {
    // The DLQ transition is timing-independent at the storage layer (the e2e
    // backoff makes a rapid-retry e2e nondeterministic).
    let storage = storage().await;
    let seq = storage.append_event("A", "e", serde_json::json!({})).await.unwrap();
    for _ in 0..3 {
        storage.record_event_delivery(seq, false, Some("500".to_string()), 3).await.unwrap();
    }
    let dead = storage.list_dead_letter_events(100).await.unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].sequence, seq);
}

#[tokio::test]
async fn test_claim_is_exclusive_across_callers() {
    // V9: claiming leases the event, so a second concurrent caller (the other
    // process's delivery pass) gets nothing — no double-delivery.
    let storage = storage().await;
    storage.append_event("A", "e", serde_json::json!({})).await.unwrap();

    let first = storage.claim_deliverable_events(10, 30).await.unwrap();
    assert_eq!(first.len(), 1, "first claimer takes it");
    let second = storage.claim_deliverable_events(10, 30).await.unwrap();
    assert!(second.is_empty(), "leased → second claimer gets nothing");

    // After delivery succeeds it's terminal; a stale-lease reclaim won't resurrect it.
    storage.record_event_delivery(first[0].sequence, true, None, 5).await.unwrap();
    let all = storage.list_events_after(0, 10).await.unwrap();
    assert_eq!(all[0].delivery, DeliveryState::Delivered);
    // A late duplicate failure can't corrupt a Delivered event.
    storage.record_event_delivery(first[0].sequence, false, Some("late".to_string()), 1).await.unwrap();
    let all = storage.list_events_after(0, 10).await.unwrap();
    assert_eq!(all[0].delivery, DeliveryState::Delivered, "Delivered is terminal");
}

#[tokio::test]
async fn test_stale_lease_is_reclaimable() {
    // V9: a crashed deliverer's lease expires and the event is re-claimable — the
    // other half of the lease contract (no event stuck-leased forever).
    let storage = storage().await;
    storage.append_event("A", "e", serde_json::json!({})).await.unwrap();

    // Claim with a 1s lease, then don't deliver (simulate a crash).
    let first = storage.claim_deliverable_events(10, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    // Immediately, the lease is still active → not re-claimable.
    assert!(storage.claim_deliverable_events(10, 1).await.unwrap().is_empty());
    // After the lease expires, a second deliverer reclaims it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let reclaimed = storage.claim_deliverable_events(10, 30).await.unwrap();
    assert_eq!(reclaimed.len(), 1, "stale lease reclaimed");
}
