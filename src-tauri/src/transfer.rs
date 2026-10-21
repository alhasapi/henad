//! Single-file transfer over dedicated SSH channels.
//!
//! Flow (all channels belong to one authenticated SSH session):
//!
//! ```text
//! control: TransferOffer -> TransferDecision (accepted) -> TransferComplete -> TransferStatus
//! data:    TransferData frame, then exactly `bytes` raw octets
//! ```
//!
//! Cancellation travels on the control channel, so it can never be confused with file bytes.
use crate::{
    core::{collision_name, safe_relative_path, PROTOCOL_VERSION},
    db::{self, TransferRow, TrustedPeer},
    net::{self, NetError},
    protocol::{ControlMessage, ErrorCode, ProtocolError},
    state::{IncomingSlot, Shared},
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
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
};
use uuid::Uuid;

const CHUNK: usize = 64 * 1024;
const DECISION_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(60);
const DATA_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_IDLE: Duration = Duration::from_secs(60 * 60);

/// Validate an outgoing file and queue it. The actual transfer runs in the background.
pub fn queue(shared: &Arc<Shared>, device_id: &str, path: &str) -> Result<String, String> {
    let path = PathBuf::from(path);
    let meta = std::fs::metadata(&path)
        .map_err(|_| "The selected file is no longer available".to_string())?;
    if !meta.is_file() {
        return Err("Henad sends one regular file at a time.".into());
    }
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("Invalid filename")?
        .to_owned();
    let peer = shared
        .trusted(device_id)
        .ok_or("Pair with this device before sending files.")?;
    if shared.discovered_peer(device_id).is_none() {
        return Err("This device is offline. Retry when it appears in the list again.".into());
    }

    let transfer_id = Uuid::new_v4().to_string();
    shared.upsert_transfer(&TransferRow {
        id: transfer_id.clone(),
        device_id: peer.id.clone(),
        device_name: peer.name.clone(),
        file_name: name.clone(),
        source_path: path.to_string_lossy().into_owned(),
        bytes_done: 0,
        bytes_total: meta.len(),
        state: "queued".into(),
        error: None,
        created_at: String::new(),
    });
    shared.emit_transfers();

    let shared = shared.clone();
    let id = transfer_id.clone();
    tokio::spawn(async move {
        let total = meta.len();
        if let Err(error) = send(shared.clone(), peer, path, id.clone(), name, total).await {
            shared.finish_transfer(&id, "failed", Some(&error.to_string()));
        }
    });
    Ok(transfer_id)
}

/// A single retry absorbs transient LAN and firewall hiccups without hiding real failures:
/// pinning errors (`key_changed`) and authentication failures are never retried.
async fn connect_with_retry(
    address: &str,
    port: u16,
    shared: &Shared,
    peer: &TrustedPeer,
) -> Result<net::Peer, NetError> {
    let attempt = net::connect(address, port, &shared.identity, Some(peer.host_key.clone())).await;
    match attempt {
        Err(NetError::Protocol(_)) | Err(NetError::Unreachable) => {
            tokio::time::sleep(Duration::from_millis(400)).await;
            net::connect(address, port, &shared.identity, Some(peer.host_key.clone())).await
        }
        other => other,
    }
}

async fn send(
    shared: Arc<Shared>,
    peer: TrustedPeer,
    path: PathBuf,
    transfer_id: String,
    name: String,
    total: u64,
) -> Result<(), NetError> {
    let discovered = shared
        .discovered_peer(&peer.id)
        .ok_or(NetError::Unreachable)?;
    let connection =
        connect_with_retry(&discovered.address, discovered.port, &shared, &peer).await?;
    let (mut control_reader, control_writer) = net::open_session(&connection.handle).await?;
    let transfer_uuid = Uuid::parse_str(&transfer_id).unwrap_or_default();

    net::send_message(
        &control_writer,
        &ControlMessage::TransferOffer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            name: name.clone(),
            bytes: total,
            blake3: None,
        },
    )
    .await?;

    let mut buffer = Vec::new();
    let decision = net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await?;
    match decision {
        ControlMessage::TransferDecision {
            accepted, error, ..
        } => {
            if !accepted {
                let message = error
                    .map(|e| e.message)
                    .unwrap_or_else(|| "the other device declined the transfer".into());
                return Err(NetError::Protocol(message));
            }
        }
        other => {
            return Err(NetError::Protocol(format!(
                "expected transfer_decision, received {}",
                other.kind()
            )))
        }
    }

    let cancel = shared.start_live(&transfer_id, total);
    let _ = shared.with_db(|db| db::update_transfer(db, &transfer_id, 0, "active", None));

    let (_data_reader, data_writer) = net::open_session(&connection.handle).await?;
    net::send_message(
        &data_writer,
        &ControlMessage::TransferData {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
        },
    )
    .await?;

    let mut file = File::open(&path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut sink = data_writer.make_writer();
    let mut chunk = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = net::send_message(
                &control_writer,
                &ControlMessage::CancelTransfer {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    transfer_id: transfer_uuid,
                },
            )
            .await;
            shared.finish_transfer(&transfer_id, "cancelled", Some("cancelled by you"));
            return Ok(());
        }
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        // Test-only fault injection: corrupt the wire bytes so the receiver's
        // checksum verification can be exercised end to end.
        #[cfg(debug_assertions)]
        if std::env::var_os("HENAD_TEST_CORRUPT").is_some() {
            chunk[0] ^= 0xFF;
        }
        sink.write_all(&chunk[..read]).await?;
        sent += read as u64;
        shared.record_progress(&transfer_id, sent);
    }
    sink.flush().await?;
    drop(sink);

    net::send_message(
        &control_writer,
        &ControlMessage::TransferComplete {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            completed_bytes: sent,
            blake3: *hasher.finalize().as_bytes(),
        },
    )
    .await?;

    let status = net::recv_message(&mut control_reader, &mut buffer, COMPLETE_TIMEOUT).await?;
    match status {
        ControlMessage::TransferStatus { error, .. } => {
            if let Some(error) = error {
                shared.finish_transfer(&transfer_id, "failed", Some(&error.message));
                return Err(NetError::Protocol(error.message));
            }
        }
        other => {
            return Err(NetError::Protocol(format!(
                "expected transfer_status, received {}",
                other.kind()
            )))
        }
    }
    shared.finish_transfer(&transfer_id, "complete", None);
    Ok(())
}

/// Handle an inbound `TransferOffer` on a control channel.
pub async fn receive_offer(
    shared: Arc<Shared>,
    control_reader: russh::ChannelReadHalf,
    control_writer: russh::ChannelWriteHalf<russh::server::Msg>,
    offer: ControlMessage,
    authenticated_key: Option<Vec<u8>>,
) -> Result<(), NetError> {
    let (transfer_id, name, bytes) = match offer {
        ControlMessage::TransferOffer {
            transfer_id,
            name,
            bytes,
            ..
        } => (transfer_id.to_string(), name, bytes),
        other => {
            return Err(NetError::Protocol(format!(
                "expected transfer_offer, received {}",
                other.kind()
            )))
        }
    };
    let transfer_uuid = Uuid::parse_str(&transfer_id).unwrap_or_default();

    let trusted = authenticated_key.as_deref().and_then(|key| {
        shared
            .with_db(|db| db::trusted_peer_by_client_key(db, key))
            .ok()
            .flatten()
    });
    let Some(trusted) = trusted else {
        let _ = net::send_message(
            &control_writer,
            &ControlMessage::TransferDecision {
                protocol_version: PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                transfer_id: transfer_uuid,
                accepted: false,
                error: Some(ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "this device is not paired",
                )),
            },
        )
        .await;
        return Err(NetError::Unauthorized);
    };

    // One normal component only: no traversal, no absolute paths, no Windows-hostile names.
    let safe = match safe_relative_path(&name) {
        Ok(path) if path.components().count() == 1 => path,
        _ => {
            let _ = net::send_message(
                &control_writer,
                &ControlMessage::TransferDecision {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    transfer_id: transfer_uuid,
                    accepted: false,
                    error: Some(ProtocolError::new(
                        ErrorCode::InvalidPath,
                        "the filename is not allowed",
                    )),
                },
            )
            .await;
            return Err(NetError::Protocol("rejected an unsafe filename".into()));
        }
    };
    let file_name = safe.to_string_lossy().into_owned();
    let dir = shared.downloads_dir();
    tokio::fs::create_dir_all(&dir).await?;
    let final_name = collision_name(&file_name, |candidate| dir.join(candidate).exists());
    let final_path = dir.join(&final_name);
    let part_path = dir.join(format!("{final_name}.henad-part"));

    File::create(&part_path).await?;
    shared.upsert_transfer(&TransferRow {
        id: transfer_id.clone(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: final_name.clone(),
        source_path: String::new(),
        bytes_done: 0,
        bytes_total: bytes,
        state: "active".into(),
        error: None,
        created_at: String::new(),
    });
    shared.emit_transfers();

    net::send_message(
        &control_writer,
        &ControlMessage::TransferDecision {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            accepted: true,
            error: None,
        },
    )
    .await?;

    let cancel = Arc::new(AtomicBool::new(false));
    let (data_tx, data_rx) = oneshot::channel();
    let (control_tx, mut control_rx) = mpsc::channel(8);
    match shared.incoming.lock() {
        Ok(mut incoming) => {
            incoming.insert(
                transfer_id.clone(),
                IncomingSlot {
                    device_name: trusted.name.clone(),
                    file_name: final_name.clone(),
                    total: bytes,
                    cancel: cancel.clone(),
                    data_ready: Some(data_tx),
                },
            );
        }
        Err(_) => return Err(NetError::Protocol("internal state unavailable".into())),
    }

    // Watch the control channel: cancellation flips the flag, completion is forwarded.
    {
        let cancel = cancel.clone();
        let mut reader = control_reader;
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            loop {
                match net::recv_message(&mut reader, &mut buffer, CONTROL_IDLE).await {
                    Ok(ControlMessage::CancelTransfer { .. }) => {
                        cancel.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(message @ ControlMessage::TransferComplete { .. }) => {
                        let _ = control_tx.send(message).await;
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    let (data_reader, data_writer, mut pending) =
        match tokio::time::timeout(DATA_TIMEOUT, data_rx).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(_)) => {
                cleanup(&part_path).await;
                shared.finish_transfer(&transfer_id, "failed", Some("the sender disconnected"));
                return Err(NetError::Protocol("the sender disconnected".into()));
            }
            Err(_) => {
                cleanup(&part_path).await;
                shared.finish_transfer(
                    &transfer_id,
                    "failed",
                    Some("the sender never opened a data channel"),
                );
                return Err(NetError::Protocol("no data channel".into()));
            }
        };
    drop(data_writer);
    shared.start_live_with(&transfer_id, bytes, cancel.clone());

    let mut file = File::create(&part_path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut received = 0u64;
    let mut chunk = vec![0u8; CHUNK];
    let mut data_reader = data_reader;
    while received < bytes {
        if cancel.load(Ordering::SeqCst) {
            drop(file);
            cleanup(&part_path).await;
            shared.finish_transfer(&transfer_id, "cancelled", Some("cancelled by the sender"));
            return Ok(());
        }
        let want = ((bytes - received) as usize).min(CHUNK);
        if let Err(error) =
            net::read_exact(&mut data_reader, &mut pending, &mut chunk[..want], &cancel).await
        {
            drop(file);
            if cancel.load(Ordering::SeqCst) {
                cleanup(&part_path).await;
                shared.finish_transfer(&transfer_id, "cancelled", Some("cancelled by the sender"));
                return Ok(());
            }
            shared.finish_transfer(&transfer_id, "failed", Some(&error.to_string()));
            return Err(error);
        }
        file.write_all(&chunk[..want]).await?;
        hasher.update(&chunk[..want]);
        received += want as u64;
        shared.record_progress(&transfer_id, received);
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);

    let complete = match tokio::time::timeout(COMPLETE_TIMEOUT, control_rx.recv()).await {
        Ok(Some(message)) => message,
        _ => {
            shared.finish_transfer(
                &transfer_id,
                "failed",
                Some("the transfer ended unexpectedly"),
            );
            return Err(NetError::Protocol("missing transfer completion".into()));
        }
    };
    let ControlMessage::TransferComplete { blake3, .. } = complete else {
        return Err(NetError::Protocol("missing transfer completion".into()));
    };

    let verified = *hasher.finalize().as_bytes() == blake3;
    if verified {
        tokio::fs::rename(&part_path, &final_path).await?;
        shared.finish_transfer(&transfer_id, "complete", None);
    } else {
        shared.finish_transfer(
            &transfer_id,
            "failed",
            Some("the file did not match the sender's checksum"),
        );
    }

    let _ = net::send_message(
        &control_writer,
        &ControlMessage::TransferStatus {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            completed_bytes: received,
            error: if verified {
                None
            } else {
                Some(ProtocolError::new(
                    ErrorCode::HashMismatch,
                    "the received file did not match the checksum",
                ))
            },
        },
    )
    .await;

    if let Ok(mut incoming) = shared.incoming.lock() {
        incoming.remove(&transfer_id);
    }
    Ok(())
}

/// Handle the dedicated data channel: find the accepted slot and hand the channel over.
pub async fn receive_data(
    shared: Arc<Shared>,
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<russh::server::Msg>,
    buffer: Vec<u8>,
    message: ControlMessage,
) -> Result<(), NetError> {
    let transfer_id = match message {
        ControlMessage::TransferData { transfer_id, .. } => transfer_id.to_string(),
        _ => return Err(NetError::Protocol("expected transfer_data".into())),
    };
    let slot = shared
        .incoming
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&transfer_id));
    let Some(mut slot) = slot else {
        return Err(NetError::Protocol(
            "no accepted transfer for this channel".into(),
        ));
    };
    match slot.data_ready.take() {
        Some(tx) => tx
            .send((reader, writer, buffer))
            .map_err(|_| NetError::Protocol("the transfer was abandoned".into())),
        None => Err(NetError::Protocol(
            "the data channel was already used".into(),
        )),
    }
}

pub fn cancel(shared: &Shared, transfer_id: &str) -> bool {
    let found = shared
        .live
        .lock()
        .map(|live| {
            live.get(transfer_id)
                .map(|entry| entry.cancel.store(true, Ordering::SeqCst))
                .is_some()
        })
        .unwrap_or(false);
    if !found {
        shared.finish_transfer(transfer_id, "cancelled", Some("cancelled by you"));
    }
    found
}

async fn cleanup(part_path: &Path) {
    let _ = tokio::fs::remove_file(part_path).await;
}
