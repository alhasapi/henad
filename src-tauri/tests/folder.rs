//! Folder transfers: manifest exchange, nested paths, per-file verification, consent.
mod common;

use common::{endpoint, pair, wait_until};
use henad_lib::{db, folder, transfer};
use std::{fs, path::Path, time::Duration};

fn make_tree(root: &Path) {
    fs::create_dir_all(root.join("photos/2026")).unwrap();
    fs::create_dir_all(root.join("docs")).unwrap();
    fs::write(root.join("readme.txt"), b"top level").unwrap();
    fs::write(root.join("docs/notes.md"), b"nested notes").unwrap();
    fs::write(root.join("photos/2026/a.jpg"), vec![7u8; 4096]).unwrap();
}

#[tokio::test]
async fn a_folder_transfers_with_nested_paths_intact() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let source = alpha.dir.join("trip");
    make_tree(&source);

    let session_id = folder::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("the folder should be queued");

    let completed = wait_until(
        || {
            alpha
                .shared
                .transfers()
                .iter()
                .any(|t| t.id == session_id && t.state == "complete")
        },
        Duration::from_secs(30),
    )
    .await;
    assert!(
        completed,
        "folder transfer should complete: {:?}",
        alpha.shared.transfers()
    );

    let destination = beta.shared.downloads_dir().join("trip");
    assert_eq!(
        fs::read(destination.join("readme.txt")).unwrap(),
        b"top level"
    );
    assert_eq!(
        fs::read(destination.join("docs/notes.md")).unwrap(),
        b"nested notes"
    );
    assert_eq!(
        fs::read(destination.join("photos/2026/a.jpg")).unwrap(),
        vec![7u8; 4096]
    );

    let receiver_row = beta
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == session_id)
        .expect("receiver records the folder session");
    assert_eq!(receiver_row.state, "complete");
    assert!(receiver_row.file_name.contains("3 files"));
    assert_eq!(receiver_row.bytes_total, 9 + 12 + 4096);
}

#[tokio::test]
async fn folder_offers_wait_for_consent_and_can_be_declined() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;
    beta.shared
        .with_db(|db| db::set_auto_accept(db, &alpha.shared.identity.device_id, false))
        .expect("database")
        .expect("auto accept");

    let source = alpha.dir.join("private");
    fs::create_dir_all(source.join("sub")).unwrap();
    fs::write(source.join("sub/secret.txt"), b"nope").unwrap();
    fs::write(source.join("other.txt"), b"also nope").unwrap();

    let session_id = folder::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("the folder should be queued");

    let prompted = wait_until(
        || !beta.events.offers.lock().unwrap().is_empty(),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        prompted,
        "the receiver should be asked before accepting a folder"
    );
    let prompt = beta.events.offers.lock().unwrap()[0].clone();
    assert_eq!(prompt.kind, "folder");
    assert_eq!(prompt.file_count, 2);
    assert!(prompt.file_name.contains("2 files"));

    assert!(beta
        .shared
        .decide_incoming(&prompt.transfer_id, false, false));

    let failed = wait_until(
        || {
            alpha
                .shared
                .transfers()
                .iter()
                .any(|t| t.id == session_id && t.state == "failed")
        },
        Duration::from_secs(10),
    )
    .await;
    assert!(failed, "the sender should learn about the decline");
    let receiver_row = beta
        .shared
        .transfers()
        .into_iter()
        .find(|t| t.id == session_id)
        .expect("decline is recorded");
    assert_eq!(receiver_row.state, "declined");
    assert!(
        !beta.shared.downloads_dir().join("private").exists(),
        "a declined folder must not create directories"
    );
}

#[tokio::test]
async fn an_empty_folder_is_refused_before_connecting() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let source = alpha.dir.join("empty");
    fs::create_dir_all(&source).unwrap();
    let error = folder::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("no files"), "unexpected error: {error}");
    assert!(alpha.shared.transfers().is_empty());
}

#[tokio::test]
async fn a_file_path_is_not_accepted_as_a_folder() {
    let alpha = endpoint("dev-alpha", "Henad on alpha").await;
    let beta = endpoint("dev-beta", "Henad on beta").await;
    pair(&alpha, &beta).await;

    let source = alpha.dir.join("one.txt");
    fs::write(&source, b"file").unwrap();
    let error = folder::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("folder"), "unexpected error: {error}");

    // Single-file transfers still work unchanged.
    let single = transfer::queue(
        &alpha.shared,
        &beta.shared.identity.device_id,
        source.to_str().unwrap(),
    )
    .expect("single file queue");
    let delivered = wait_until(
        || {
            alpha
                .shared
                .transfers()
                .iter()
                .any(|t| t.id == single && t.state == "complete")
        },
        Duration::from_secs(20),
    )
    .await;
    assert!(delivered, "single-file path still works");
}
