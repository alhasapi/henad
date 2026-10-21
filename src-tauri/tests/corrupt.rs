//! Checksum enforcement: corrupt the wire bytes in debug builds and assert both
//! sides reject the transfer and no finalized file appears.
mod common;

use common::{endpoint, pair, wait_until};
use henad_lib::transfer;
use std::{fs, time::Duration};

#[tokio::test]
async fn a_corrupted_transfer_is_rejected_on_both_sides() {
    // Fault injection is compiled in for debug builds only (see transfer::send).
    std::env::set_var("HENAD_TEST_CORRUPT", "1");

    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 199) as u8).collect();
    let source = alpha.dir.join("corrupt.bin");
    fs::write(&source, &payload).unwrap();

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
                .any(|t| t.id == transfer_id && (t.state == "failed" || t.state == "complete"))
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(failed, "the transfer should reach a terminal state");

    let sender_row = alpha
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == transfer_id)
        .expect("sender row");
    assert_eq!(sender_row.state, "failed");
    assert!(
        sender_row
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("checksum"),
        "sender should learn about the checksum mismatch, got {:?}",
        sender_row.error
    );

    let receiver_row = beta
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.file_name == "corrupt.bin")
        .expect("receiver row");
    assert_eq!(receiver_row.state, "failed");
    assert!(
        !beta.shared.downloads_dir().join("corrupt.bin").exists(),
        "a corrupt file must never be finalized"
    );
    let leftovers: Vec<String> = fs::read_dir(beta.shared.downloads_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.iter().any(|name| name.ends_with(".henad-part")),
        "the partial file is kept for inspection: {leftovers:?}"
    );

    std::env::remove_var("HENAD_TEST_CORRUPT");
}
