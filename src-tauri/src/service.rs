//! The inbound SSH service: authenticated, pairing-only for unknown peers, no shell.
use crate::{
    folder,
    net::{self, NetError},
    pairing,
    protocol::ControlMessage,
    state::Shared,
    transfer,
};
use russh::{keys::ssh_key, server, Channel};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Accept loop. Each connection gets its own handler; `Shared::open_connection` enforces the
/// global and per-address caps.
pub async fn serve(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if !shared.open_connection(Some(peer)) {
            drop(socket);
            continue;
        }

        let shared = shared.clone();
        let config = shared.server_config.clone();
        tokio::spawn(async move {
            let handler = Session {
                shared: shared.clone(),
                client_key: None,
                peer: Some(peer),
            };
            if let Ok(session) = server::run_stream(config, socket, handler).await {
                let _ = session.await;
            }
            shared.close_connection(Some(peer));
        });
    }
}

struct Session {
    shared: Arc<Shared>,
    client_key: Option<Vec<u8>>,
    peer: Option<std::net::SocketAddr>,
}

impl server::Handler for Session {
    type Error = russh::Error;

    /// Any key may connect: unknown peers are limited to the pairing exchange, and
    /// transfer channels require a key that matches a pinned device.
    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        use russh::keys::PublicKeyBase64;
        self.client_key = Some(public_key.public_key_bytes());
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let shared = self.shared.clone();
        let key = self.client_key.clone();
        let peer = self.peer;
        tokio::spawn(async move {
            if let Err(error) = dispatch(shared, channel, key).await {
                eprintln!("henad: session with {peer:?} ended: {error}");
            }
        });
        Ok(true)
    }
}

async fn dispatch(
    shared: Arc<Shared>,
    channel: Channel<server::Msg>,
    authenticated_key: Option<Vec<u8>>,
) -> Result<(), NetError> {
    let (mut reader, writer) = channel.split();
    let mut buffer = Vec::new();
    let first = net::recv_message(&mut reader, &mut buffer, net::HANDSHAKE_TIMEOUT).await?;
    match first {
        message @ ControlMessage::PairOffer { .. } => {
            pairing::respond(shared, reader, writer, buffer, authenticated_key, message).await
        }
        message @ ControlMessage::TransferOffer { .. } => {
            transfer::receive_offer(shared, reader, writer, message, authenticated_key).await
        }
        message @ ControlMessage::TransferData { .. } => {
            transfer::receive_data(shared, reader, writer, buffer, message).await
        }
        message @ ControlMessage::FolderOffer { .. } => {
            folder::receive_offer(shared, reader, writer, buffer, message, authenticated_key).await
        }
        message @ ControlMessage::FolderData { .. } => {
            folder::receive_data(shared, reader, writer, buffer, message).await
        }
        message @ ControlMessage::ResumeQuery { .. } => {
            transfer::receive_resume_session(
                shared,
                reader,
                writer,
                buffer,
                message,
                authenticated_key,
            )
            .await
        }
        message @ ControlMessage::ResumeTransfer { .. } => {
            transfer::receive_resume(shared, reader, writer, message, authenticated_key).await
        }
        other => Err(NetError::Protocol(format!(
            "unexpected first message: {}",
            other.kind()
        ))),
    }
}
