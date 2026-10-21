//! Single-file transfer over dedicated SSH channels, including resume of interrupted files.
//!
//! Fresh transfer:
//!
//! ```text
//! control: TransferOffer -> TransferDecision (accepted) -> TransferComplete -> TransferStatus
//! data:    TransferData frame, then exactly `bytes` raw octets
//! ```
//!
//! Resume of a previous failed attempt on the same transfer id:
//!
//! ```text
//! control: ResumeQuery -> ResumeState{offset} -> ResumeTransfer{offset}
//!          -> TransferDecision -> TransferComplete -> TransferStatus
//! data:    TransferData frame, then the remaining `bytes - offset` octets
//! ```
//!
//! Cancellation travels on the control channel, so it can never be confused with file bytes.
use crate::{
    core::{collision_name, safe_relative_path, PROTOCOL_VERSION},
    db::{self, TransferRow, TrustedPeer},
    net::{self, NetError},
    protocol::{ControlMessage, ErrorCode, ProtocolError},
    state::{IncomingResult, IncomingSlot, IncomingTransfer, PendingIncoming, Shared},
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
    sync::{mpsc, oneshot},
};
use uuid::Uuid;

const CHUNK: usize = 64 * 1024;
const DECISION_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(60);
const DATA_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROL_IDLE: Duration = Duration::from_secs(60 * 60);
pub(crate) const CONSENT_WINDOW: Duration = Duration::from_secs(60);

/// Reject links rather than silently following them: the user picks what gets sent.
pub(crate) fn reject_link(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| "The selected item is no longer available".to_string())?;
    if meta.file_type().is_symlink() {
        return Err("That is a link. Choose the file or folder it points to instead.".to_string());
    }
    Ok(())
}

/// What a dropped path turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Folder,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Folder => "folder",
        }
    }
}

/// Dispatch a user-selected path to the file or folder pipeline.
pub fn queue_path(
    shared: &Arc<Shared>,
    device_id: &str,
    path: &str,
) -> Result<(String, Kind), String> {
    let meta = std::fs::metadata(path).map_err(|_| "That item is no longer available.")?;
    if meta.is_dir() {
        Ok((crate::folder::queue(shared, device_id, path)?, Kind::Folder))
    } else {
        Ok((queue(shared, device_id, path)?, Kind::File))
    }
}

/// Validate an outgoing file and queue it. The actual transfer runs in the background.
pub fn queue(shared: &Arc<Shared>, device_id: &str, path: &str) -> Result<String, String> {
    let path = PathBuf::from(path);
    reject_link(&path)?;
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

/// Ask the receiver how much it already has and continue from there.
pub fn resume(shared: &Arc<Shared>, transfer_id: &str) -> Result<(), String> {
    let row = shared
        .with_db(|db| db::transfer(db, transfer_id))
        .map_err(|e| e.to_string())?
        .ok_or("That transfer is no longer in your history.")?;
    if row.source_path.is_empty() {
        return Err("Only files you sent can be resumed from this device.".into());
    }
    if !matches!(row.state.as_str(), "failed" | "cancelled") {
        return Err("Only interrupted transfers can be resumed.".into());
    }
    let path = PathBuf::from(&row.source_path);
    reject_link(&path)?;
    let meta = std::fs::metadata(&path).map_err(|_| "The original file is no longer available.")?;
    if !meta.is_file() || meta.len() != row.bytes_total {
        return Err("The file changed since the transfer started. Send it again.".into());
    }
    let peer = shared
        .trusted(&row.device_id)
        .ok_or("Pair with this device again before resuming.")?;
    if shared.discovered_peer(&row.device_id).is_none() {
        return Err("This device is offline. Retry when it appears in the list again.".into());
    }

    shared.upsert_transfer(&TransferRow {
        id: row.id.clone(),
        device_id: row.device_id.clone(),
        device_name: row.device_name.clone(),
        file_name: row.file_name.clone(),
        source_path: row.source_path.clone(),
        bytes_done: 0,
        bytes_total: row.bytes_total,
        state: "queued".into(),
        error: None,
        created_at: row.created_at.clone(),
    });
    shared.emit_transfers();

    let shared = shared.clone();
    let id = row.id.clone();
    tokio::spawn(async move {
        if let Err(error) = send_resume(
            shared.clone(),
            peer,
            path,
            id.clone(),
            row.file_name,
            row.bytes_total,
        )
        .await
        {
            shared.finish_transfer(&id, "failed", Some(&error.to_string()));
        }
    });
    Ok(())
}

async fn send(
    shared: Arc<Shared>,
    peer: TrustedPeer,
    path: PathBuf,
    transfer_id: String,
    name: String,
    total: u64,
) -> Result<(), NetError> {
    reject_link(&path).map_err(NetError::Protocol)?;
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
            name,
            bytes: total,
            blake3: None,
        },
    )
    .await?;

    let mut buffer = Vec::new();
    expect_decision(net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await?)?;

    let cancel = shared.start_live(&transfer_id, total);
    let _ = shared.with_db(|db| db::update_transfer(db, &transfer_id, 0, "active", None));

    stream_file(
        &shared,
        &connection,
        &transfer_id,
        transfer_uuid,
        &path,
        0,
        total,
        cancel,
        &mut control_reader,
        &control_writer,
        &mut buffer,
    )
    .await
}

async fn send_resume(
    shared: Arc<Shared>,
    peer: TrustedPeer,
    path: PathBuf,
    transfer_id: String,
    _name: String,
    total: u64,
) -> Result<(), NetError> {
    let discovered = shared
        .discovered_peer(&peer.id)
        .ok_or(NetError::Unreachable)?;
    let connection =
        connect_with_retry(&discovered.address, discovered.port, &shared, &peer).await?;
    let (mut control_reader, control_writer) = net::open_session(&connection.handle).await?;
    let transfer_uuid = Uuid::parse_str(&transfer_id).unwrap_or_default();
    let mut buffer = Vec::new();

    net::send_message(
        &control_writer,
        &ControlMessage::ResumeQuery {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
        },
    )
    .await?;

    let offset = match net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await?
    {
        ControlMessage::ResumeState {
            ok,
            offset,
            total: remote_total,
            ..
        } => {
            if !ok {
                return Err(NetError::Protocol(
                    "The other device no longer has the partial file. Send it again.".into(),
                ));
            }
            if remote_total != total || offset == 0 || offset >= total {
                return Err(NetError::Protocol(
                    "The other device's partial file does not match this transfer.".into(),
                ));
            }
            offset
        }
        other => {
            return Err(NetError::Protocol(format!(
                "expected resume_state, received {}",
                other.kind()
            )))
        }
    };

    net::send_message(
        &control_writer,
        &ControlMessage::ResumeTransfer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            completed_bytes: offset,
        },
    )
    .await?;

    expect_decision(net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await?)?;

    let cancel = shared.start_live_with(
        &transfer_id,
        total,
        Arc::new(AtomicBool::new(false)),
        offset,
    );
    let _ = shared.with_db(|db| db::update_transfer(db, &transfer_id, offset, "active", None));

    stream_file(
        &shared,
        &connection,
        &transfer_id,
        transfer_uuid,
        &path,
        offset,
        total,
        cancel,
        &mut control_reader,
        &control_writer,
        &mut buffer,
    )
    .await
}

pub(crate) fn expect_decision(message: ControlMessage) -> Result<(), NetError> {
    match message {
        ControlMessage::TransferDecision {
            accepted, error, ..
        } => {
            if accepted {
                Ok(())
            } else {
                Err(NetError::Protocol(error.map(|e| e.message).unwrap_or_else(
                    || "the other device declined the transfer".into(),
                )))
            }
        }
        other => Err(NetError::Protocol(format!(
            "expected transfer_decision, received {}",
            other.kind()
        ))),
    }
}

/// Stream `offset..total` from `path` on a fresh data channel, then report the whole-file hash.
#[allow(clippy::too_many_arguments)]
async fn stream_file(
    shared: &Arc<Shared>,
    connection: &net::Peer,
    transfer_id: &str,
    transfer_uuid: Uuid,
    path: &Path,
    offset: u64,
    total: u64,
    cancel: Arc<AtomicBool>,
    control_reader: &mut russh::ChannelReadHalf,
    control_writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    control_buffer: &mut Vec<u8>,
) -> Result<(), NetError> {
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

    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut chunk = vec![0u8; CHUNK];
    let mut consumed = 0u64;

    // Resume requires the full-file hash, so the already transferred prefix is re-read locally.
    while consumed < offset {
        let want = ((offset - consumed) as usize).min(CHUNK);
        file.read_exact(&mut chunk[..want]).await.map_err(|_| {
            NetError::Protocol("the original file shrank since the transfer started".into())
        })?;
        hasher.update(&chunk[..want]);
        consumed += want as u64;
    }

    let mut sink = data_writer.make_writer();
    let mut sent = offset;
    loop {
        if cancel.load(Ordering::SeqCst) {
            let _ = net::send_message(
                control_writer,
                &ControlMessage::CancelTransfer {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    transfer_id: transfer_uuid,
                },
            )
            .await;
            shared.finish_transfer(transfer_id, "cancelled", Some("cancelled by you"));
            return Ok(());
        }
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        // Test-only fault injection (debug builds): corrupt the wire bytes.
        #[cfg(debug_assertions)]
        if std::env::var_os("HENAD_TEST_CORRUPT").is_some() {
            chunk[0] ^= 0xFF;
        }
        sink.write_all(&chunk[..read]).await?;
        sent += read as u64;
        shared.record_progress(transfer_id, sent);

        #[cfg(debug_assertions)]
        if abort_after().is_some_and(|limit| sent >= limit) {
            // Give the receiver a moment to drain what is already buffered before the
            // connection drops, so the interrupted state is deterministic in tests.
            tokio::time::sleep(Duration::from_millis(1000)).await;
            return Err(NetError::Protocol("test abort".into()));
        }
    }
    sink.flush().await?;
    drop(sink);

    if sent != total {
        return Err(NetError::Protocol(
            "the file changed while it was being sent".into(),
        ));
    }

    net::send_message(
        control_writer,
        &ControlMessage::TransferComplete {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            completed_bytes: sent,
            blake3: *hasher.finalize().as_bytes(),
        },
    )
    .await?;

    match net::recv_message(control_reader, control_buffer, COMPLETE_TIMEOUT).await? {
        ControlMessage::TransferStatus { error, .. } => {
            if let Some(error) = error {
                shared.finish_transfer(transfer_id, "failed", Some(&error.message));
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
    shared.finish_transfer(transfer_id, "complete", None);
    Ok(())
}

/// A single retry absorbs transient LAN and firewall hiccups without hiding real failures:
/// pinning errors (`key_changed`) and authentication failures are never retried.
pub(crate) async fn connect_with_retry(
    address: &str,
    port: u16,
    shared: &Shared,
    peer: &TrustedPeer,
) -> Result<net::Peer, NetError> {
    let attempt = net::connect(address, port, &shared.identity, Some(peer.host_key.clone())).await;
    match attempt {
        Err(NetError::Protocol(_)) | Err(NetError::Unreachable) | Err(NetError::Timeout) => {
            tokio::time::sleep(Duration::from_millis(400)).await;
            net::connect(address, port, &shared.identity, Some(peer.host_key.clone())).await
        }
        other => other,
    }
}

#[cfg(debug_assertions)]
fn abort_after() -> Option<u64> {
    std::env::var("HENAD_TEST_ABORT_AFTER")
        .ok()
        .and_then(|value| value.parse().ok())
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

    let trusted = trusted_for(&shared, authenticated_key.as_deref());
    let Some(trusted) = trusted else {
        reject(
            &control_writer,
            transfer_uuid,
            ErrorCode::Unauthorized,
            "this device is not paired",
        )
        .await;
        return Err(NetError::Unauthorized);
    };

    // One normal component only: no traversal, no absolute paths, no Windows-hostile names.
    let safe = match safe_relative_path(&name) {
        Ok(path) if path.components().count() == 1 => path,
        _ => {
            reject(
                &control_writer,
                transfer_uuid,
                ErrorCode::InvalidPath,
                "the filename is not allowed",
            )
            .await;
            return Err(NetError::Protocol("rejected an unsafe filename".into()));
        }
    };
    let file_name = safe.to_string_lossy().into_owned();

    // Ask the human unless this device was explicitly trusted to send without prompting.
    let auto = shared
        .with_db(|db| db::auto_accept(db, &trusted.id))
        .unwrap_or(false);
    let prompt = IncomingTransfer {
        transfer_id: transfer_id.clone(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: file_name.clone(),
        kind: "file".into(),
        file_count: 1,
        bytes,
        expires_in_secs: 60,
    };
    if !auto && !ask_consent(&shared, prompt).await {
        record_declined(&shared, &trusted, &transfer_id, &file_name, bytes);
        let _ = net::send_message(
            &control_writer,
            &ControlMessage::TransferDecision {
                protocol_version: PROTOCOL_VERSION,
                request_id: Uuid::new_v4(),
                transfer_id: transfer_uuid,
                accepted: false,
                error: Some(ProtocolError::new(
                    ErrorCode::TransferRejected,
                    "the receiving device declined the transfer",
                )),
            },
        )
        .await;
        return Ok(());
    }

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

    run_receive(
        shared,
        control_reader,
        control_writer,
        transfer_id,
        trusted.name,
        final_name,
        part_path,
        final_path,
        bytes,
        0,
    )
    .await
}

/// Show an incoming-file prompt and wait for the local decision.
pub(crate) async fn ask_consent(shared: &Arc<Shared>, prompt: IncomingTransfer) -> bool {
    let transfer_id = prompt.transfer_id.clone();
    let (tx, rx) = oneshot::channel();
    if !shared.register_incoming(PendingIncoming {
        prompt: prompt.clone(),
        decision: Some(tx),
        started: std::time::Instant::now(),
    }) {
        return false;
    }
    shared.events.transfer_incoming(prompt);

    match tokio::time::timeout(CONSENT_WINDOW, rx).await {
        Ok(Ok((accepted, _remember))) => accepted,
        _ => {
            // Timed out or the channel dropped: make sure nothing is left pending.
            shared.decide_incoming(&transfer_id, false, false);
            shared.events.transfer_incoming_closed(IncomingResult {
                transfer_id,
                accepted: false,
                error: Some("the incoming file request expired".into()),
            });
            false
        }
    }
}

/// Keep a history row for declined offers so the sender's attempt is not invisible.
fn record_declined(
    shared: &Arc<Shared>,
    trusted: &TrustedPeer,
    transfer_id: &str,
    file_name: &str,
    bytes: u64,
) {
    shared.upsert_transfer(&TransferRow {
        id: transfer_id.to_owned(),
        device_id: trusted.id.clone(),
        device_name: trusted.name.clone(),
        file_name: file_name.to_owned(),
        source_path: String::new(),
        bytes_done: 0,
        bytes_total: bytes,
        state: "declined".into(),
        error: Some("declined on this device".into()),
        created_at: String::new(),
    });
    shared.emit_transfers();
}

/// Answer `ResumeQuery`, then handle the `ResumeTransfer` that follows on the same channel.
#[allow(clippy::too_many_arguments)]
pub async fn receive_resume_session(
    shared: Arc<Shared>,
    mut control_reader: russh::ChannelReadHalf,
    control_writer: russh::ChannelWriteHalf<russh::server::Msg>,
    mut buffer: Vec<u8>,
    message: ControlMessage,
    authenticated_key: Option<Vec<u8>>,
) -> Result<(), NetError> {
    let transfer_id = match message {
        ControlMessage::ResumeQuery { transfer_id, .. } => transfer_id.to_string(),
        _ => return Err(NetError::Protocol("expected resume_query".into())),
    };
    let transfer_uuid = Uuid::parse_str(&transfer_id).unwrap_or_default();
    let trusted = trusted_for(&shared, authenticated_key.as_deref());
    let Some(trusted) = trusted else {
        return Err(NetError::Unauthorized);
    };

    let row = shared
        .with_db(|db| db::transfer(db, &transfer_id))
        .ok()
        .flatten()
        .filter(|row| row.device_id == trusted.id && row.bytes_total > 0);
    let (ok, offset, total) = match row {
        Some(row) => {
            let part = shared
                .downloads_dir()
                .join(format!("{}.henad-part", row.file_name));
            let offset = tokio::fs::metadata(&part)
                .await
                .map(|meta| meta.len())
                .unwrap_or(0);
            (
                offset > 0 && offset < row.bytes_total,
                offset,
                row.bytes_total,
            )
        }
        None => (false, 0, 0),
    };

    net::send_message(
        &control_writer,
        &ControlMessage::ResumeState {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id: transfer_uuid,
            ok,
            offset,
            total,
        },
    )
    .await?;

    if !ok {
        return Ok(());
    }

    // The sender continues on this channel with the actual resume offer.
    match net::recv_message(&mut control_reader, &mut buffer, DECISION_TIMEOUT).await? {
        message @ ControlMessage::ResumeTransfer { .. } => {
            receive_resume(
                shared,
                control_reader,
                control_writer,
                message,
                authenticated_key,
            )
            .await
        }
        other => Err(NetError::Protocol(format!(
            "expected resume_transfer, received {}",
            other.kind()
        ))),
    }
}

/// Handle an inbound `ResumeTransfer` offer: validate the partial file and append the rest.
pub async fn receive_resume(
    shared: Arc<Shared>,
    control_reader: russh::ChannelReadHalf,
    control_writer: russh::ChannelWriteHalf<russh::server::Msg>,
    message: ControlMessage,
    authenticated_key: Option<Vec<u8>>,
) -> Result<(), NetError> {
    let (transfer_id, offset) = match message {
        ControlMessage::ResumeTransfer {
            transfer_id,
            completed_bytes,
            ..
        } => (transfer_id.to_string(), completed_bytes),
        _ => return Err(NetError::Protocol("expected resume_transfer".into())),
    };
    let transfer_uuid = Uuid::parse_str(&transfer_id).unwrap_or_default();
    let trusted = trusted_for(&shared, authenticated_key.as_deref());
    let Some(trusted) = trusted else {
        reject(
            &control_writer,
            transfer_uuid,
            ErrorCode::Unauthorized,
            "this device is not paired",
        )
        .await;
        return Err(NetError::Unauthorized);
    };

    let row = shared
        .with_db(|db| db::transfer(db, &transfer_id))
        .ok()
        .flatten()
        .filter(|row| row.device_id == trusted.id);
    let Some(row) = row else {
        reject(
            &control_writer,
            transfer_uuid,
            ErrorCode::TransferNotFound,
            "that transfer is not in the history on this device",
        )
        .await;
        return Err(NetError::Protocol("unknown transfer".into()));
    };

    let dir = shared.downloads_dir();
    let final_path = dir.join(&row.file_name);
    let part_path = dir.join(format!("{}.henad-part", row.file_name));
    let on_disk = tokio::fs::metadata(&part_path)
        .await
        .map(|meta| meta.len())
        .unwrap_or(0);
    if on_disk == 0 || on_disk != offset || on_disk >= row.bytes_total {
        reject(
            &control_writer,
            transfer_uuid,
            ErrorCode::TransferRejected,
            "the partial file no longer matches this transfer",
        )
        .await;
        return Err(NetError::Protocol(
            "the partial file does not match the sender's offset".into(),
        ));
    }

    shared.upsert_transfer(&TransferRow {
        id: row.id.clone(),
        device_id: row.device_id.clone(),
        device_name: trusted.name.clone(),
        file_name: row.file_name.clone(),
        source_path: String::new(),
        bytes_done: offset,
        bytes_total: row.bytes_total,
        state: "active".into(),
        error: None,
        created_at: row.created_at.clone(),
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

    run_receive(
        shared,
        control_reader,
        control_writer,
        transfer_id,
        trusted.name,
        row.file_name,
        part_path,
        final_path,
        row.bytes_total,
        offset,
    )
    .await
}

/// Register the accepted transfer, wait for its data channel, and receive the payload.
#[allow(clippy::too_many_arguments)]
async fn run_receive(
    shared: Arc<Shared>,
    control_reader: russh::ChannelReadHalf,
    control_writer: russh::ChannelWriteHalf<russh::server::Msg>,
    transfer_id: String,
    device_name: String,
    file_name: String,
    part_path: PathBuf,
    final_path: PathBuf,
    total: u64,
    offset: u64,
) -> Result<(), NetError> {
    let cancel = Arc::new(AtomicBool::new(false));
    let (data_tx, data_rx) = oneshot::channel();
    let (control_tx, mut control_rx) = mpsc::channel(8);
    match shared.incoming.lock() {
        Ok(mut incoming) => {
            incoming.insert(
                transfer_id.clone(),
                IncomingSlot {
                    device_name,
                    file_name,
                    total,
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

    let (mut data_reader, data_writer, mut pending) =
        match tokio::time::timeout(DATA_TIMEOUT, data_rx).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(_)) => {
                cleanup(&part_path).await;
                shared.finish_transfer(&transfer_id, "failed", Some("the sender disconnected"));
                return Err(NetError::Protocol("the sender disconnected".into()));
            }
            Err(_) => {
                shared.finish_transfer(
                    &transfer_id,
                    "failed",
                    Some("the sender never opened a data channel"),
                );
                return Err(NetError::Protocol("no data channel".into()));
            }
        };
    drop(data_writer);
    shared.start_live_with(&transfer_id, total, cancel.clone(), offset);

    // Hash whatever the previous attempt already delivered so the final check covers the whole file.
    let mut hasher = blake3::Hasher::new();
    if offset > 0 {
        match hash_existing(&part_path, offset, &mut hasher).await {
            Ok(()) => {}
            Err(error) => {
                shared.finish_transfer(&transfer_id, "failed", Some(&error.to_string()));
                return Err(error);
            }
        }
    }
    let mut file = if offset > 0 {
        OpenOptions::new().append(true).open(&part_path).await?
    } else {
        File::create(&part_path).await?
    };

    let mut received = offset;
    let mut chunk = vec![0u8; CHUNK];
    while received < total {
        if cancel.load(Ordering::SeqCst) {
            drop(file);
            cleanup(&part_path).await;
            shared.finish_transfer(&transfer_id, "cancelled", Some("cancelled by the sender"));
            return Ok(());
        }
        let want = ((total - received) as usize).min(CHUNK);
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
            transfer_id: Uuid::parse_str(&transfer_id).unwrap_or_default(),
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

pub(crate) fn trusted_for(
    shared: &Shared,
    authenticated_key: Option<&[u8]>,
) -> Option<TrustedPeer> {
    authenticated_key.and_then(|key| {
        shared
            .with_db(|db| db::trusted_peer_by_client_key(db, key))
            .ok()
            .flatten()
    })
}

pub(crate) async fn reject(
    writer: &russh::ChannelWriteHalf<russh::server::Msg>,
    transfer_id: Uuid,
    code: ErrorCode,
    message: &str,
) {
    let _ = net::send_message(
        writer,
        &ControlMessage::TransferDecision {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            transfer_id,
            accepted: false,
            error: Some(ProtocolError::new(code, message)),
        },
    )
    .await;
}

async fn hash_existing(
    path: &Path,
    length: u64,
    hasher: &mut blake3::Hasher,
) -> Result<(), NetError> {
    let mut file = File::open(path).await?;
    let mut chunk = vec![0u8; CHUNK];
    let mut hashed = 0u64;
    while hashed < length {
        let want = ((length - hashed) as usize).min(CHUNK);
        file.read_exact(&mut chunk[..want]).await?;
        hasher.update(&chunk[..want]);
        hashed += want as u64;
    }
    Ok(())
}

async fn cleanup(part_path: &Path) {
    let _ = tokio::fs::remove_file(part_path).await;
}
