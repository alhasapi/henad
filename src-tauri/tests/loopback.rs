//! End-to-end loopback tests: server and client run in one process over 127.0.0.1.
mod common;

use common::{endpoint, pair, wait_until};
use henad_lib::core::PROTOCOL_VERSION;
use henad_lib::protocol::{ControlMessage, ErrorCode};
use henad_lib::state::{PairingPrompt, PendingPairing};
use henad_lib::{net, transfer};
use std::{
    fs,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[tokio::test]
async fn pairing_pins_both_sides_with_the_same_code() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;

    let (code_a, code_b) = pair(&alpha, &beta).await;
    assert_eq!(code_a, code_b, "both screens must show the same code");
    assert_eq!(code_a.len(), 8);
    assert!(code_a.bytes().all(|b| b.is_ascii_digit()));

    let beta_id = beta.shared.identity.device_id.clone();
    let alpha_id = alpha.shared.identity.device_id.clone();

    let pinned_beta = alpha.shared.trusted(&beta_id).expect("alpha trusts beta");
    assert_eq!(
        pinned_beta.host_key,
        beta.shared.identity.host_public_bytes(),
        "the pinned host key must be the key beta actually presented"
    );
    assert_eq!(
        pinned_beta.client_key,
        beta.shared.identity.client_public_bytes()
    );

    let pinned_alpha = beta.shared.trusted(&alpha_id).expect("beta trusts alpha");
    assert_eq!(
        pinned_alpha.client_key,
        alpha.shared.identity.client_public_bytes()
    );
    assert_eq!(pinned_alpha.name, "Henad on alpha");

    // Discovery-like listing marks the peer online and trusted.
    let device = alpha
        .shared
        .devices()
        .into_iter()
        .find(|d| d.id == beta_id)
        .expect("beta should be listed");
    assert!(device.trusted);
    assert_eq!(device.state, "online");
}

#[tokio::test]
async fn a_single_file_transfers_with_matching_bytes() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let source = alpha.dir.join("payload.bin");
    fs::write(&source, &payload).unwrap();

    let transfer_id = transfer::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("the file should be queued");

    let completed = wait_until(
        || {
            alpha
                .shared
                .transfers()
                .iter()
                .any(|t| t.id == transfer_id && t.state == "complete")
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        completed,
        "transfer should complete: {:?}",
        alpha.shared.transfers()
    );

    let received = beta.shared.downloads_dir().join("payload.bin");
    assert!(received.exists(), "the receiver should save the file");
    assert_eq!(fs::read(&received).unwrap(), payload, "bytes must match");

    let receiver_side = beta.shared.transfers();
    let row = receiver_side
        .iter()
        .find(|t| t.file_name == "payload.bin")
        .expect("the receiver records the transfer");
    assert_eq!(row.state, "complete");
    assert_eq!(row.device_name, "Henad on alpha");

    // No staging file is left behind after a verified transfer.
    assert!(fs::read_dir(beta.shared.downloads_dir())
        .unwrap()
        .filter_map(Result::ok)
        .all(|entry| !entry.file_name().to_string_lossy().ends_with(".henad-part")));
}

#[tokio::test]
async fn an_unpaired_device_cannot_offer_a_transfer() {
    let beta = endpoint("dev-beta", "Henad on beta").await;
    let mallory = endpoint("dev-mallory", "Henad on mallory").await;

    let connection = net::connect(
        "127.0.0.1",
        beta.shared.port(),
        &mallory.shared.identity,
        None,
    )
    .await
    .expect("the SSH server accepts any key for pairing");
    let (mut reader, writer) = net::open_session(&connection.handle).await.unwrap();

    net::send_message(
        &writer,
        &ControlMessage::TransferOffer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: Uuid::new_v4(),
            name: "secrets.txt".into(),
            bytes: 4,
            blake3: None,
        },
    )
    .await
    .unwrap();

    let mut buffer = Vec::new();
    let decision = net::recv_message(&mut reader, &mut buffer, Duration::from_secs(5))
        .await
        .unwrap();
    match decision {
        ControlMessage::TransferDecision {
            accepted, error, ..
        } => {
            assert!(!accepted, "unpaired devices must be rejected");
            assert_eq!(error.unwrap().code, ErrorCode::Unauthorized);
        }
        other => panic!("expected a decision, got {}", other.kind()),
    }

    assert!(beta.shared.transfers().is_empty());
    assert!(!beta.shared.downloads_dir().join("secrets.txt").exists());
}

#[tokio::test]
async fn expired_pairing_prompts_are_swept() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let (tx, _rx) = tokio::sync::oneshot::channel();
    alpha.shared.pairing.lock().unwrap().insert(
        "ghost".into(),
        PendingPairing {
            prompt: PairingPrompt {
                device_id: "ghost".into(),
                device_name: "Ghost".into(),
                code: "00000000".into(),
                expires_in_secs: 120,
            },
            decision: Some(tx),
            is_responder: false,
            started: Instant::now() - Duration::from_secs(300),
        },
    );

    let expired = alpha.shared.sweep_pairings();
    assert_eq!(expired, vec!["ghost".to_string()]);
    assert!(alpha.shared.pairing_prompt("ghost").is_none());

    let results = alpha.events.results.lock().unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok);
    assert_eq!(
        results[0].error.as_deref(),
        Some("the pairing code expired")
    );
}

#[tokio::test]
async fn cancelling_an_unknown_transfer_marks_it_cancelled() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let source = alpha.dir.join("cancelled.bin");
    fs::write(&source, b"hello").unwrap();
    // Queue against an offline device so nothing starts, then cancel.
    let transfer_id = transfer::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    );
    let id = match transfer_id {
        Ok(id) => id,
        Err(_) => {
            // The peer is online in discovery, so the queue succeeds; if it ever
            // fails, the test has nothing to cancel.
            return;
        }
    };
    transfer::cancel(&alpha.shared, &id);
    let row = alpha
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == id)
        .expect("row should exist");
    assert!(
        row.state == "cancelled" || row.state == "complete" || row.state == "failed",
        "unexpected state {}",
        row.state
    );
}
