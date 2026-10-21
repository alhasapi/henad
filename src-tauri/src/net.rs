//! SSH transport plumbing shared by pairing and transfer.
//!
//! Control messages are length-prefixed JSON frames ([`crate::core::encode_frame`]);
//! file payloads follow a `TransferOffer` as raw bytes for exactly `bytes` octets,
//! after which framing resumes.
use crate::{
    core::{decode_frame, encode_frame, FrameError, MAX_FRAME},
    identity::Identity,
    protocol::{self, ControlMessage, ProtocolError},
};
use russh::{
    client,
    keys::{ssh_key, PublicKeyBase64},
    ChannelMsg, ChannelReadHalf, ChannelWriteHalf,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    time::{timeout, Instant},
};

pub const SERVICE_TYPE: &str = "_henad._tcp.local.";
pub const DEFAULT_PORT: u16 = 47831;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const PAIRING_WINDOW: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum NetError {
    #[error("the device is unreachable")]
    Unreachable,
    #[error("the other device's identity changed since pairing")]
    KeyChanged,
    #[error("the other device does not trust this device")]
    Unauthorized,
    #[error("{0}")]
    Protocol(String),
    #[error("the connection timed out")]
    Timeout,
    #[error("the connection closed unexpectedly")]
    Closed,
    #[error("the device advertised a different identity than it presented")]
    DiscoveryMismatch,
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<ProtocolError> for NetError {
    fn from(value: ProtocolError) -> Self {
        NetError::Protocol(value.message)
    }
}

#[derive(Default)]
pub struct HostKeyRecord {
    pub observed: Mutex<Option<Vec<u8>>>,
    pub mismatch: std::sync::atomic::AtomicBool,
}

/// Client handler that pins the SSH host key: TOFU during pairing, exact match afterwards.
pub struct PinnedHostKey {
    expected: Option<Vec<u8>>,
    record: Arc<HostKeyRecord>,
}

impl PinnedHostKey {
    pub fn new(expected: Option<Vec<u8>>) -> (Self, Arc<HostKeyRecord>) {
        let record = Arc::new(HostKeyRecord::default());
        (
            Self {
                expected,
                record: record.clone(),
            },
            record,
        )
    }
}

impl client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let bytes = server_public_key.public_key_bytes();
        if let Ok(mut observed) = self.record.observed.lock() {
            *observed = Some(bytes.clone());
        }
        if let Some(expected) = &self.expected {
            if expected != &bytes {
                self.record
                    .mismatch
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub struct Peer {
    pub handle: client::Handle<PinnedHostKey>,
    pub host_key: Vec<u8>,
}

/// Connect and authenticate to a peer.
///
/// `expected_host_key` is `None` only while pairing (the code confirms the key);
/// for every other connection it must be the pinned key.
pub async fn connect(
    address: &str,
    port: u16,
    identity: &Identity,
    expected_host_key: Option<Vec<u8>>,
) -> Result<Peer, NetError> {
    let (handler, record) = PinnedHostKey::new(expected_host_key);
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(120)),
        nodelay: true,
        ..Default::default()
    });
    let mut handle = timeout(
        CONNECT_TIMEOUT,
        client::connect(config, (address, port), handler),
    )
    .await
    .map_err(|_| NetError::Unreachable)?
    .map_err(|_| NetError::Unreachable)?;

    if record.mismatch.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(NetError::KeyChanged);
    }
    let host_key = record
        .observed
        .lock()
        .ok()
        .and_then(|k| k.clone())
        .ok_or(NetError::Closed)?;

    let auth = timeout(
        HANDSHAKE_TIMEOUT,
        handle.authenticate_publickey(
            "henad",
            russh::keys::PrivateKeyWithHashAlg::new(Arc::clone(&identity.client), None),
        ),
    )
    .await
    .map_err(|_| NetError::Timeout)??;

    if !matches!(auth, client::AuthResult::Success) {
        return Err(NetError::Unauthorized);
    }
    Ok(Peer { handle, host_key })
}

pub async fn open_session(
    handle: &client::Handle<PinnedHostKey>,
) -> Result<(ChannelReadHalf, ChannelWriteHalf<client::Msg>), NetError> {
    let channel = timeout(HANDSHAKE_TIMEOUT, handle.channel_open_session())
        .await
        .map_err(|_| NetError::Timeout)??;
    Ok(channel.split())
}

pub async fn send_message<S>(
    writer: &ChannelWriteHalf<S>,
    message: &ControlMessage,
) -> Result<(), NetError>
where
    S: From<(russh::ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let payload = serde_json::to_vec(message)?;
    let frame = encode_frame(&payload)?;
    let mut sink = writer.make_writer();
    sink.write_all(&frame).await?;
    sink.flush().await?;
    Ok(())
}

/// Read one framed control message, honouring an overall deadline.
pub async fn recv_message(
    reader: &mut ChannelReadHalf,
    buffer: &mut Vec<u8>,
    deadline: Duration,
) -> Result<ControlMessage, NetError> {
    let started = Instant::now();
    loop {
        if let Some(payload) = decode_frame(buffer)? {
            return Ok(protocol::decode(&payload)?);
        }
        let remaining = deadline
            .checked_sub(started.elapsed())
            .ok_or(NetError::Timeout)?;
        match timeout(remaining, reader.wait())
            .await
            .map_err(|_| NetError::Timeout)?
        {
            Some(ChannelMsg::Data { data }) => {
                if buffer.len() + data.len() > MAX_FRAME * 4 {
                    return Err(NetError::Protocol("control flood".into()));
                }
                buffer.extend_from_slice(&data);
            }
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return Err(NetError::Closed),
            Some(_) => {}
        }
    }
}

/// Read exactly `out.len()` payload bytes, using `buffer` for anything already received.
pub async fn read_exact(
    reader: &mut ChannelReadHalf,
    buffer: &mut Vec<u8>,
    out: &mut [u8],
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(), NetError> {
    let mut filled = 0;
    while filled < out.len() {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(NetError::Protocol("cancelled".into()));
        }
        if !buffer.is_empty() {
            let take = buffer.len().min(out.len() - filled);
            out[filled..filled + take].copy_from_slice(&buffer[..take]);
            buffer.drain(..take);
            filled += take;
            continue;
        }
        match reader.wait().await {
            Some(ChannelMsg::Data { data }) => buffer.extend_from_slice(&data),
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return Err(NetError::Closed),
            Some(_) => {}
        }
    }
    Ok(())
}

/// Best-effort primary IPv4 address for mDNS advertisement; no packets are sent.
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        SocketAddr::V6(_) => None,
    }
}
