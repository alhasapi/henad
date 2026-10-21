//! Resume of an interrupted transfer: abort mid-stream in debug builds, then continue.
mod common;

use common::{endpoint, pair, wait_until};
use henad_lib::transfer;
use std::{fs, time::Duration};

const ABORT_AFTER: u64 = 1_000_000;

#[tokio::test]
async fn an_interrupted_transfer_resumes_from_the_partial_file() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let payload: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 241) as u8).collect();
    let source = alpha.dir.join("resume.bin");
    fs::write(&source, &payload).unwrap();

    // Abort the sender once it has pushed 1 MB over the wire.
    std::env::set_var("HENAD_TEST_ABORT_AFTER", ABORT_AFTER.to_string());
    let transfer_id = transfer::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("the file should be queued");

    let failed = wait_until(
        || {
            alpha
                .shared
                .transfers()
                .iter()
                .any(|t| t.id == transfer_id && t.state == "failed")
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        failed,
        "the aborted transfer should fail: {:?}",
        alpha.shared.transfers()
    );

    let part = beta.shared.downloads_dir().join("resume.bin.henad-part");
    // Wait until the receiver records the interruption before inspecting the staging file.
    let receiver_settled = wait_until(
        || {
            beta.shared.transfers().iter().any(|t| {
                t.file_name == "resume.bin"
                    && matches!(t.state.as_str(), "failed" | "cancelled" | "complete")
            })
        },
        Duration::from_secs(15),
    )
    .await;
    assert!(receiver_settled, "receiver should record the interruption");
    let partial = fs::metadata(&part)
        .expect("the receiver keeps the partial file")
        .len();
    assert!(
        partial > 0 && partial < 3 * 1024 * 1024,
        "unexpected partial size {partial}"
    );
    assert!(!beta.shared.downloads_dir().join("resume.bin").exists());

    // The UI marks the failed row as resumable.
    let row = alpha
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == transfer_id)
        .expect("sender row");
    assert!(
        row.can_resume,
        "a failed outgoing transfer should be resumable"
    );

    std::env::remove_var("HENAD_TEST_ABORT_AFTER");
    transfer::resume(&alpha.shared, &transfer_id).expect("resume should start");

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
        "resumed transfer should complete: {:?}",
        alpha.shared.transfers()
    );

    let received = beta.shared.downloads_dir().join("resume.bin");
    assert_eq!(
        fs::read(&received).unwrap(),
        payload,
        "resumed bytes must match"
    );
    assert!(!part.exists(), "the staging file is renamed on success");

    let receiver_row = beta
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.file_name == "resume.bin")
        .expect("receiver row");
    assert_eq!(receiver_row.state, "complete");
}

#[tokio::test]
async fn resuming_without_a_partial_file_explains_the_restart() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let source = alpha.dir.join("gone.bin");
    fs::write(&source, b"some bytes").unwrap();

    let transfer_id = transfer::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("the file should be queued");
    let settled = wait_until(
        || {
            alpha.shared.transfers().iter().any(|t| {
                t.id == transfer_id
                    && matches!(t.state.as_str(), "complete" | "failed" | "cancelled")
            })
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        settled,
        "the transfer never settled: {:?}",
        alpha.shared.transfers()
    );

    let row = alpha
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == transfer_id)
        .expect("sender row");
    assert_eq!(
        row.state, "complete",
        "expected a clean transfer before probing resume, got {:?}",
        row.error
    );

    // A completed transfer is not resumable, and the receiver has already renamed the file.
    let error = transfer::resume(&alpha.shared, &transfer_id).unwrap_err();
    assert!(error.contains("interrupted"), "unexpected error: {error}");
}
