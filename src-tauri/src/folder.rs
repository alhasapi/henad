//! Folder transfer: one manifest session, one data channel, one file at a time.
//!
//! ```text
//! control: FolderOffer -> FolderManifest* -> FolderManifestEnd -> FolderDecision
//!          -> (sender: CancelTransfer on abort) -> FolderStatus
//! data:    FolderData frame, then per file: FileStart, raw bytes, FileEnd
//! ```
//!
//! Every path is validated per component on arrival and created below
//! `Downloads/Henad/<root>`, refusing to traverse pre-existing symlinks.
use crate::{
    core::{collision_name, manifest_hash, safe_relative_path, MANIFEST_CHUNK, MAX_FOLDER_FILES},
    db::{self, TransferRow, TrustedPeer},
    net::{self, NetError},
    protocol::{ControlMessage, ErrorCode, ManifestEntry, ProtocolError},
    state::{FolderSlot, IncomingTransfer, Shared},
    transfer::{ask_consent, connect_with_retry, trusted_for, CONSENT_WINDOW},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use uuid::Uuid;

const CHUNK: usize = 64 * 1024;
const DECISION_TIMEOUT: Duration = Duration::from_secs(30);
const STATUS_TIMEOUT: Duration = Duration::from_secs(120);
const DATA_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_IDLE: Duration = Duration::from_secs(60 * 60);

/// Validate and queue a folder. The transfer itself runs in the background.
pub fn queue(shared: &Arc<Shared>, device_id: &str, path: &str) -> Result<String, String> {
    let root = PathBuf::from(path);
    if !root.is_dir() {
        return Err("Choose a folder to send.".into());
    }
    let root_name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("That folder name cannot be sent.")?
        .to_owned();
    if safe_relative_path(&root_name).is_err() {
        return Err("That folder name cannot be sent.".into());
    }
    let files = walk(&root)?;
    if files.is_empty() {
        return Err("That folder has no files to send.".into());
    }
    let total: u64 = files.iter().map(|(_, bytes)| *bytes).sum();
    let peer = shared
        .trusted(device_id)
        .ok_or("Pair with this device before sending files.")?;
    if shared.discovered_peer(device_id).is_none() {
        return Err("This device is offline. Retry when it appears in the list again.".into());
    }

    let session_id = Uuid::new_v4().to_string();
    let display = format!("{root_name} ({} files)", files.len());
    shared.upsert_transfer(&TransferRow {
        id: session_id.clone(),
        device_id: peer.id.clone(),
        device_name: peer.name.clone(),
        file_name: display.clone(),
        source_path: root.to_string_lossy().into_owned(),
        bytes_done: 0,
        bytes_total: total,
        state: "queued".into(),
        error: None,
        created_at: String::new(),
    });
    shared.emit_transfers();

    let shared = shared.clone();
    let id = session_id.clone();
    tokio::spawn(async move {
        if let Err(error) = send(
            shared.clone(),
            peer,
            root,
            root_name,
            files,
            total,
            id.clone(),
            display,
        )
        .await
        {
            shared.finish_transfer(&id, "failed", Some(&error.to_string()));
        }
    });
    Ok(session_id)
}

#[allow(clippy::too_many_arguments)]
async fn send(
    shared: Arc<Shared>,
    peer: TrustedPeer,
    root: PathBuf,
    root_name: String,
    files: Vec<(String, u64)>,
    total: u64,
    session_id: String,
    _display: String,
) -> Result<(), NetError> {
    let discovered = shared
        .discovered_peer(&peer.id)
        .ok_or(NetError::Unreachable)?;
    let connection =
        connect_with_retry(&discovered.address, discovered.port, &shared, &peer).await?;
    let (mut control_reader, control_writer) = net::open_session(&connection.handle).await?;
    let session_uuid = Uuid::parse_str(&session_id).unwrap_or_default();
    let count = files.len() as u32;

    net::send_message(
        &control_writer,
        &ControlMessage::FolderOffer {
            protocol_version: crate::core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id: session_uuid,
            root_name: root_name.clone(),
            file_count: count,
            total_bytes: total,
        },
    )
    .await?;

    for (start, chunk) in files.chunks(MANIFEST_CHUNK).enumerate() {
        let entries = chunk
            .iter()
            .map(|(path, bytes)| ManifestEntry {
                path: path.clone(),
                bytes: *bytes,
            })
            .collect();
        net::send_message(
            &control_writer,
            &ControlMessage::FolderManifest {
                protocol_version: crate::core::PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                session_id: session_uuid,
                start: (start * MANIFEST_CHUNK) as u32,
                entries,
            },
        )
        .await?;
    }
    net::send_message(
        &control_writer,
        &ControlMessage::FolderManifestEnd {
            protocol_version: crate::core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id: session_uuid,
            manifest_hash: manifest_hash(&files),
        },
    )
    .await?;

    let mut buffer = Vec::new();
    match net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await? {
        ControlMessage::FolderDecision {
            accepted, error, ..
        } => {
            if !accepted {
                return Err(NetError::Protocol(
                    error
                        .map(|e| e.message)
                        .unwrap_or_else(|| "the other device declined the folder".into()),
                ));
            }
        }
        other => {
            return Err(NetError::Protocol(format!(
                "expected folder_decision, received {}",
                other.kind()
            )))
        }
    }

    let cancel = shared.start_live(&session_id, total);
    let _ = shared.with_db(|db| db::update_transfer(db, &session_id, 0, "active", None));

    let (_data_reader, data_writer) = net::open_session(&connection.handle).await?;
    net::send_message(
        &data_writer,
        &ControlMessage::FolderData {
            protocol_version: crate::core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id: session_uuid,
        },
    )
    .await?;

    let mut sink = data_writer.make_writer();
    let mut chunk = vec![0u8; CHUNK];
    let mut sent_total = 0u64;
    for (index, (relative, bytes)) in files.iter().enumerate() {
        net::send_message(
            &data_writer,
            &ControlMessage::FileStart {
                protocol_version: crate::core::PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                session_id: session_uuid,
                index: index as u32,
            },
        )
        .await?;

        let mut file = File::open(root.join(relative)).await?;
        let mut hasher = blake3::Hasher::new();
        let mut sent = 0u64;
        while sent < *bytes {
            if cancel.load(Ordering::SeqCst) {
                let _ = net::send_message(
                    &control_writer,
                    &ControlMessage::CancelTransfer {
                        protocol_version: crate::core::PROTOCOL_VERSION,
                        request_id: Uuid::new_v4(),
                        transfer_id: session_uuid,
                    },
                )
                .await;
                shared.finish_transfer(&session_id, "cancelled", Some("cancelled by you"));
                return Ok(());
            }
            let want = ((*bytes - sent) as usize).min(CHUNK);
            file.read_exact(&mut chunk[..want]).await.map_err(|_| {
                NetError::Protocol(format!("{relative} changed while it was being sent"))
            })?;
            hasher.update(&chunk[..want]);
            sink.write_all(&chunk[..want]).await?;
            sent += want as u64;
            sent_total += want as u64;
            shared.record_progress(&session_id, sent_total);
        }
        net::send_message(
            &data_writer,
            &ControlMessage::FileEnd {
                protocol_version: crate::core::PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                session_id: session_uuid,
                index: index as u32,
                blake3: *hasher.finalize().as_bytes(),
            },
        )
        .await?;
    }
    sink.flush().await?;
    drop(sink);

    match net::recv_message(&mut control_reader, &mut buffer, STATUS_TIMEOUT).await? {
        ControlMessage::FolderStatus {
            error,
            completed_files,
            ..
        } => {
            if let Some(error) = error {
                shared.finish_transfer(&session_id, "failed", Some(&error.message));
                return Err(NetError::Protocol(error.message));
            }
            if completed_files != count {
                let message =
                    format!("the receiver confirmed only {completed_files} of {count} files");
                shared.finish_transfer(&session_id, "failed", Some(&message));
                return Err(NetError::Protocol(message));
            }
        }
        other => {
            return Err(NetError::Protocol(format!(
                "expected folder_status, received {}",
                other.kind()
            )))
        }
    }
    shared.finish_transfer(&session_id, "complete", None);
    Ok(())
}

/// Handle an inbound folder offer: collect the manifest, ask the user, then receive files.
pub async fn receive_offer(
    shared: Arc<Shared>,
    mut control_reader: russh::ChannelReadHalf,
    control_writer: russh::ChannelWriteHalf<russh::server::Msg>,
    mut buffer: Vec<u8>,
    offer: ControlMessage,
    authenticated_key: Option<Vec<u8>>,
) -> Result<(), NetError> {
    let (session_id, root_name, file_count, total_bytes) = match offer {
        ControlMessage::FolderOffer {
            session_id,
            root_name,
            file_count,
            total_bytes,
            ..
        } => (session_id.to_string(), root_name, file_count, total_bytes),
        _ => return Err(NetError::Protocol("expected folder_offer".into())),
    };
    let session_uuid = Uuid::parse_str(&session_id).unwrap_or_default();

    let Some(trusted) = trusted_for(&shared, authenticated_key.as_deref()) else {
        reject_folder(
            &control_writer,
            session_uuid,
            ErrorCode::Unauthorized,
            "this device is not paired",
        )
        .await;
        return Err(NetError::Unauthorized);
    };

    if safe_relative_path(&root_name).is_err()
        || safe_relative_path(&root_name)
            .map(|path| path.components().count() != 1)
            .unwrap_or(true)
    {
        reject_folder(
            &control_writer,
            session_uuid,
            ErrorCode::InvalidPath,
            "the folder name is not allowed",
        )
        .await;
        return Err(NetError::Protocol("rejected an unsafe folder name".into()));
    }
    if file_count == 0 || file_count as usize > MAX_FOLDER_FILES {
        reject_folder(
            &control_writer,
            session_uuid,
            ErrorCode::TransferRejected,
            "the folder has an unsupported number of files",
        )
        .await;
        return Err(NetError::Protocol("bad file count".into()));
    }

    // Collect the manifest in order, verifying offsets, limits, and the digest.
    let mut entries: Vec<ManifestEntry> = Vec::new();
    loop {
        match net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await? {
            ControlMessage::FolderManifest {
                start,
                entries: chunk,
                ..
            } => {
                if start as usize != entries.len() {
                    reject_folder(
                        &control_writer,
                        session_uuid,
                        ErrorCode::TransferRejected,
                        "the manifest arrived out of order",
                    )
                    .await;
                    return Err(NetError::Protocol("manifest out of order".into()));
                }
                entries.extend(chunk);
                if entries.len() > file_count as usize || entries.len() > MAX_FOLDER_FILES {
                    reject_folder(
                        &control_writer,
                        session_uuid,
                        ErrorCode::TransferRejected,
                        "the manifest is larger than announced",
                    )
                    .await;
                    return Err(NetError::Protocol("manifest too large".into()));
                }
            }
            ControlMessage::FolderManifestEnd {
                manifest_hash: hash,
                ..
            } => {
                let flattened: Vec<(String, u64)> = entries
                    .iter()
                    .map(|entry| (entry.path.clone(), entry.bytes))
                    .collect();
                let expected = manifest_hash(&flattened);
                let sum: u64 = entries.iter().map(|entry| entry.bytes).sum();
                if entries.len() != file_count as usize
                    || sum != total_bytes
                    || hash != expected
                    || entries
                        .iter()
                        .any(|entry| safe_relative_path(&entry.path).is_err())
                {
                    reject_folder(
                        &control_writer,
                        session_uuid,
                        ErrorCode::InvalidPath,
                        "the folder manifest is not valid",
                    )
                    .await;
                    return Err(NetError::Protocol("invalid manifest".into()));
                }
                break;
            }
            other => {
                return Err(NetError::Protocol(format!(
                    "expected folder_manifest, received {}",
                    other.kind()
                )))
            }
        }
    }

    let auto = shared
        .with_db(|db| db::auto_accept(db, &trusted.id))
        .unwrap_or(false);
    let display = format!("{root_name} ({file_count} files)");
    let prompt = IncomingTransfer {
        transfer_id: session_id.clone(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: display.clone(),
        kind: "folder".into(),
        file_count,
        bytes: total_bytes,
        expires_in_secs: CONSENT_WINDOW.as_secs(),
    };
    if !auto && !ask_consent(&shared, prompt).await {
        record_declined(&shared, &trusted, &session_id, &display, total_bytes);
        reject_folder(
            &control_writer,
            session_uuid,
            ErrorCode::TransferRejected,
            "the receiving device declined the folder",
        )
        .await;
        return Ok(());
    }

    let downloads = shared.downloads_dir();
    tokio::fs::create_dir_all(&downloads).await?;
    let root_dir = downloads.join(collision_name(&root_name, |candidate| {
        downloads.join(candidate).exists()
    }));
    if let Err(error) = tokio::fs::create_dir_all(&root_dir).await {
        let message = format!("could not create the destination folder: {error}");
        shared.finish_transfer(&session_id, "failed", Some(&message));
        return Err(NetError::Protocol(message));
    }

    shared.upsert_transfer(&TransferRow {
        id: session_id.clone(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: display,
        source_path: String::new(),
        bytes_done: 0,
        bytes_total: total_bytes,
        state: "active".into(),
        error: None,
        created_at: String::new(),
    });
    shared.emit_transfers();

    net::send_message(
        &control_writer,
        &ControlMessage::FolderDecision {
            protocol_version: crate::core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id: session_uuid,
            accepted: true,
            error: None,
        },
    )
    .await?;

    let cancel = Arc::new(AtomicBool::new(false));
    let (data_tx, data_rx) = oneshot::channel();
    if let Ok(mut folders) = shared.incoming_folders.lock() {
        folders.insert(
            session_id.clone(),
            FolderSlot {
                cancel: cancel.clone(),
                data_ready: Some(data_tx),
            },
        );
    }

    {
        let cancel = cancel.clone();
        let mut reader = control_reader;
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            while let Ok(message) = net::recv_message(&mut reader, &mut buffer, CONTROL_IDLE).await
            {
                if matches!(message, ControlMessage::CancelTransfer { .. }) {
                    cancel.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });
    }

    let (mut data_reader, data_writer, mut pending) =
        match tokio::time::timeout(DATA_TIMEOUT, data_rx).await {
            Ok(Ok(pair)) => pair,
            _ => {
                let _ = tokio::fs::remove_dir_all(&root_dir).await;
                shared.finish_transfer(
                    &session_id,
                    "failed",
                    Some("the sender never opened a data channel"),
                );
                return Err(NetError::Protocol("no folder data channel".into()));
            }
        };
    drop(data_writer);
    shared.start_live_with(&session_id, total_bytes, cancel.clone(), 0);

    let outcome = receive_files(
        &shared,
        &session_id,
        &root_dir,
        &entries,
        &mut data_reader,
        &mut pending,
        &cancel,
    )
    .await;

    match outcome {
        Ok(completed) => {
            let _ = net::send_message(
                &control_writer,
                &ControlMessage::FolderStatus {
                    protocol_version: crate::core::PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    session_id: session_uuid,
                    completed_files: completed,
                    error: None,
                },
            )
            .await;
            shared.finish_transfer(&session_id, "complete", None);
        }
        Err(error) => {
            let cancelled = cancel.load(Ordering::SeqCst);
            let _ = tokio::fs::remove_dir_all(&root_dir).await;
            let message = error.to_string();
            shared.finish_transfer(
                &session_id,
                if cancelled { "cancelled" } else { "failed" },
                Some(&message),
            );
            let _ = net::send_message(
                &control_writer,
                &ControlMessage::FolderStatus {
                    protocol_version: crate::core::PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    session_id: session_uuid,
                    completed_files: 0,
                    error: Some(ProtocolError::new(
                        if cancelled {
                            ErrorCode::Cancelled
                        } else {
                            ErrorCode::HashMismatch
                        },
                        message,
                    )),
                },
            )
            .await;
            return Err(error);
        }
    }

    if let Ok(mut folders) = shared.incoming_folders.lock() {
        folders.remove(&session_id);
    }
    Ok(())
}

/// Hand the folder data channel to the session that is waiting for it.
pub async fn receive_data(
    shared: Arc<Shared>,
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<russh::server::Msg>,
    buffer: Vec<u8>,
    message: ControlMessage,
) -> Result<(), NetError> {
    let session_id = match message {
        ControlMessage::FolderData { session_id, .. } => session_id.to_string(),
        _ => return Err(NetError::Protocol("expected folder_data".into())),
    };
    let slot = shared
        .incoming_folders
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&session_id));
    let Some(mut slot) = slot else {
        return Err(NetError::Protocol(
            "no accepted folder for this channel".into(),
        ));
    };
    match slot.data_ready.take() {
        Some(tx) => tx
            .send((reader, writer, buffer))
            .map_err(|_| NetError::Protocol("the folder transfer was abandoned".into())),
        None => Err(NetError::Protocol(
            "the folder channel was already used".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_files(
    shared: &Arc<Shared>,
    session_id: &str,
    root: &Path,
    entries: &[ManifestEntry],
    reader: &mut russh::ChannelReadHalf,
    pending: &mut Vec<u8>,
    cancel: &AtomicBool,
) -> Result<u32, NetError> {
    let mut chunk = vec![0u8; CHUNK];
    let mut received_total = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return Err(NetError::Protocol("cancelled by the sender".into()));
        }
        match net::recv_message(reader, pending, DECISION_TIMEOUT).await? {
            ControlMessage::FileStart { index: started, .. } if started as usize == index => {}
            other => {
                return Err(NetError::Protocol(format!(
                    "expected file_start {index}, received {}",
                    other.kind()
                )))
            }
        }

        let safe = safe_relative_path(&entry.path)
            .map_err(|_| NetError::Protocol(format!("unsafe path in manifest: {}", entry.path)))?;
        let destination = root.join(&safe);
        if let Some(parent) = destination.parent() {
            ensure_directories(root, parent).await?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .await
            .map_err(|_| NetError::Protocol(format!("could not create {}", entry.path)))?;
        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;
        while written < entry.bytes {
            if cancel.load(Ordering::SeqCst) {
                return Err(NetError::Protocol("cancelled by the sender".into()));
            }
            let want = ((entry.bytes - written) as usize).min(CHUNK);
            net::read_exact(reader, pending, &mut chunk[..want], cancel).await?;
            file.write_all(&chunk[..want]).await?;
            hasher.update(&chunk[..want]);
            written += want as u64;
            received_total += want as u64;
            shared.record_progress(session_id, received_total);
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        match net::recv_message(reader, pending, DECISION_TIMEOUT).await? {
            ControlMessage::FileEnd {
                index: ended,
                blake3,
                ..
            } if ended as usize == index => {
                if *hasher.finalize().as_bytes() != blake3 {
                    return Err(NetError::Protocol(format!(
                        "{} did not match the sender's checksum",
                        entry.path
                    )));
                }
            }
            other => {
                return Err(NetError::Protocol(format!(
                    "expected file_end {index}, received {}",
                    other.kind()
                )))
            }
        }
    }
    Ok(entries.len() as u32)
}

/// Create each missing directory below `root`, refusing to follow symlinks.
async fn ensure_directories(root: &Path, parent: &Path) -> Result<(), NetError> {
    let relative = parent.strip_prefix(root).unwrap_or(Path::new(""));
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match tokio::fs::symlink_metadata(&current).await {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(NetError::Protocol(
                    "refusing to write through a symlink".into(),
                ))
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(NetError::Protocol(
                    "a path component is not a directory".into(),
                ))
            }
            Err(_) => tokio::fs::create_dir(&current).await?,
        }
    }
    Ok(())
}

async fn reject_folder(
    writer: &russh::ChannelWriteHalf<russh::server::Msg>,
    session_id: Uuid,
    code: ErrorCode,
    message: &str,
) {
    let _ = net::send_message(
        writer,
        &ControlMessage::FolderDecision {
            protocol_version: crate::core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            session_id,
            accepted: false,
            error: Some(ProtocolError::new(code, message)),
        },
    )
    .await;
}

fn record_declined(
    shared: &Arc<Shared>,
    trusted: &TrustedPeer,
    session_id: &str,
    display: &str,
    total: u64,
) {
    shared.upsert_transfer(&TransferRow {
        id: session_id.to_owned(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: display.to_owned(),
        source_path: String::new(),
        bytes_done: 0,
        bytes_total: total,
        state: "declined".into(),
        error: Some("declined on this device".into()),
        created_at: String::new(),
    });
    shared.emit_transfers();
}

/// Collect regular files under `root` as `/`-separated relative paths, skipping symlinks.
fn walk(root: &Path) -> Result<Vec<(String, u64)>, String> {
    fn visit(base: &Path, dir: &Path, out: &mut Vec<(String, u64)>) -> Result<(), String> {
        let mut children: Vec<_> = std::fs::read_dir(dir)
            .map_err(|error| format!("could not read {}: {error}", dir.display()))?
            .filter_map(Result::ok)
            .collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let path = child.path();
            let file_type = child
                .file_type()
                .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                visit(base, &path, out)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .map_err(|_| "could not build a relative path".to_string())?;
                let joined = relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let bytes = child
                    .metadata()
                    .map_err(|error| format!("could not stat {}: {error}", path.display()))?
                    .len();
                out.push((joined, bytes));
                if out.len() > MAX_FOLDER_FILES {
                    return Err(format!(
                        "That folder has more than {MAX_FOLDER_FILES} files."
                    ));
                }
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("henad-folder-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walk_lists_regular_files_in_order_and_skips_symlinks() {
        let root = temp_dir("walk");
        std::fs::create_dir_all(root.join("nested/deeper")).unwrap();
        std::fs::write(root.join("b.txt"), b"b").unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("nested/deeper/c.bin"), [0u8; 5]).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("link.txt")).unwrap();

        let files = walk(&root).unwrap();
        assert_eq!(
            files,
            vec![
                ("a.txt".to_string(), 1),
                ("b.txt".to_string(), 1),
                ("nested/deeper/c.bin".to_string(), 5),
            ]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn walk_rejects_missing_folders() {
        assert!(walk(Path::new("/definitely/not/here")).is_err());
    }

    #[test]
    fn manifest_paths_are_validated() {
        for bad in ["../escape", "/absolute", "a/../../b", "C:/x"] {
            assert!(safe_relative_path(bad).is_err(), "{bad}");
        }
        assert!(safe_relative_path("photos/2026/a.jpg").is_ok());
    }
}
