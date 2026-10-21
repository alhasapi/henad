//! First-contact pairing over SSH with a human-compared confirmation code.
//!
//! The code is derived from a transcript binding both identities, both host keys, both
//! client keys, and a nonce from each side. Accepting the peer's host key at this point
//! is trust-on-first-use: the human comparison is what pins it.
use crate::{
    core::{
        confirmation_code, fingerprint, fresh_nonce, pairing_transcript, transcript_hash,
        PROTOCOL_VERSION,
    },
    db::{self, TrustedPeer},
    identity,
    net::{self, NetError},
    protocol::ControlMessage,
    state::{PairingPrompt, PairingResult, PendingPairing, Shared},
};
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;
use uuid::Uuid;

pub async fn initiate(shared: Arc<Shared>, device_id: &str) -> Result<PairingPrompt, NetError> {
    if shared.trusted(device_id).is_some() {
        return Err(NetError::Protocol(
            "this device is already paired; unpair it first".into(),
        ));
    }
    let peer = shared
        .discovered_peer(device_id)
        .ok_or(NetError::Unreachable)?;

    let connection = net::connect(&peer.address, peer.port, &shared.identity, None).await?;
    if !peer.fingerprint.is_empty() && fingerprint(&connection.host_key) != peer.fingerprint {
        return Err(NetError::DiscoveryMismatch);
    }

    let (mut reader, writer) = net::open_session(&connection.handle).await?;
    let connection_handle = connection.handle;
    let nonce = fresh_nonce();
    net::send_message(
        &writer,
        &ControlMessage::PairOffer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            initiator_id: shared.identity.device_id.clone(),
            initiator_name: shared.identity.name.clone(),
            host_public_key: shared.identity.host_public_bytes(),
            client_public_key: shared.identity.client_public_bytes(),
            nonce,
        },
    )
    .await?;

    let mut buffer = Vec::new();
    let accept = net::recv_message(&mut reader, &mut buffer, net::HANDSHAKE_TIMEOUT).await?;
    let (responder_host, responder_client, responder_nonce) = match accept {
        ControlMessage::PairAccept {
            host_public_key,
            client_public_key,
            nonce,
            ..
        } => (host_public_key, client_public_key, nonce),
        other => {
            return Err(NetError::Protocol(format!(
                "expected pair_accept, received {}",
                other.kind()
            )))
        }
    };
    if responder_host != connection.host_key {
        return Err(NetError::Protocol(
            "the peer claimed a host key different from its SSH session key".into(),
        ));
    }

    let transcript = pairing_transcript(
        &shared.identity.device_id,
        &peer.id,
        &shared.identity.host_public_bytes(),
        &responder_host,
        &shared.identity.client_public_bytes(),
        &responder_client,
        &nonce,
        &responder_nonce,
    );
    let hash = transcript_hash(&transcript);
    let code = confirmation_code(&transcript);

    let prompt = PairingPrompt {
        device_id: peer.id.clone(),
        device_name: peer.name.clone(),
        code,
        expires_in_secs: net::PAIRING_WINDOW.as_secs(),
    };
    let (tx, rx) = oneshot::channel();
    if !shared.register_pairing(
        peer.id.clone(),
        PendingPairing {
            prompt: prompt.clone(),
            decision: Some(tx),
            is_responder: false,
            started: std::time::Instant::now(),
        },
    ) {
        return Err(NetError::Protocol(
            "a pairing with this device is already in progress".into(),
        ));
    }
    shared.events.pairing_code(prompt.clone());

    let trusted = TrustedPeer {
        id: peer.id.clone(),
        name: peer.name.clone(),
        host_key: responder_host,
        client_key: responder_client,
        fingerprint: fingerprint(&connection.host_key),
        last_seen: None,
    };
    let device_id = peer.id.clone();
    tokio::spawn(async move {
        let outcome = confirm(
            shared.clone(),
            reader,
            writer,
            trusted,
            hash,
            rx,
            false,
            &device_id,
            &mut buffer,
            Some(connection_handle),
        )
        .await;
        shared.clear_pairing(&device_id);
        shared.events.pairing_result(PairingResult {
            device_id,
            ok: outcome.is_ok(),
            error: outcome.err(),
        });
        shared.emit_devices();
    });

    Ok(prompt)
}

pub async fn respond(
    shared: Arc<Shared>,
    reader: russh::ChannelReadHalf,
    writer: russh::ChannelWriteHalf<russh::server::Msg>,
    mut buffer: Vec<u8>,
    authenticated_key: Option<Vec<u8>>,
    offer: ControlMessage,
) -> Result<(), NetError> {
    let (initiator_id, initiator_name, host_public_key, client_public_key, nonce) = match offer {
        ControlMessage::PairOffer {
            initiator_id,
            initiator_name,
            host_public_key,
            client_public_key,
            nonce,
            ..
        } => (
            initiator_id,
            initiator_name,
            host_public_key,
            client_public_key,
            nonce,
        ),
        other => {
            return Err(NetError::Protocol(format!(
                "expected pair_offer, received {}",
                other.kind()
            )))
        }
    };

    if authenticated_key.as_deref() != Some(client_public_key.as_slice()) {
        reject(
            &writer,
            "the offered key does not match the authenticated session",
        )
        .await?;
        return Err(NetError::Unauthorized);
    }
    if shared.trusted(&initiator_id).is_some() {
        reject(&writer, "this device is already paired").await?;
        return Err(NetError::Protocol("already paired".into()));
    }
    // Bound unsolicited prompts: at most three pairings may wait for a human at once.
    if shared.pairing.lock().map(|p| p.len()).unwrap_or(0) >= 3 {
        reject(&writer, "too many pairing requests are pending").await?;
        return Err(NetError::Protocol("too many pending pairings".into()));
    }

    let local_nonce = fresh_nonce();
    let transcript = pairing_transcript(
        &initiator_id,
        &shared.identity.device_id,
        &host_public_key,
        &shared.identity.host_public_bytes(),
        &client_public_key,
        &shared.identity.client_public_bytes(),
        &nonce,
        &local_nonce,
    );
    let hash = transcript_hash(&transcript);
    let code = confirmation_code(&transcript);

    let (tx, rx) = oneshot::channel();
    if !shared.register_pairing(
        initiator_id.clone(),
        PendingPairing {
            prompt: PairingPrompt {
                device_id: initiator_id.clone(),
                device_name: initiator_name.clone(),
                code: code.clone(),
                expires_in_secs: net::PAIRING_WINDOW.as_secs(),
            },
            decision: Some(tx),
            is_responder: true,
            started: std::time::Instant::now(),
        },
    ) {
        reject(&writer, "a pairing is already in progress").await?;
        return Err(NetError::Protocol("pairing already in progress".into()));
    }

    net::send_message(
        &writer,
        &ControlMessage::PairAccept {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            host_public_key: shared.identity.host_public_bytes(),
            client_public_key: shared.identity.client_public_bytes(),
            nonce: local_nonce,
        },
    )
    .await?;

    let prompt = PairingPrompt {
        device_id: initiator_id.clone(),
        device_name: initiator_name.clone(),
        code,
        expires_in_secs: net::PAIRING_WINDOW.as_secs(),
    };
    shared.events.pairing_incoming(prompt);

    let trusted = TrustedPeer {
        id: initiator_id.clone(),
        name: initiator_name,
        host_key: host_public_key,
        client_key: client_public_key,
        fingerprint: String::new(),
        last_seen: None,
    };
    let device_id = initiator_id.clone();
    tokio::spawn(async move {
        let outcome = confirm(
            shared.clone(),
            reader,
            writer,
            trusted,
            hash,
            rx,
            true,
            &device_id,
            &mut buffer,
            None,
        )
        .await;
        shared.clear_pairing(&device_id);
        shared.events.pairing_result(PairingResult {
            device_id,
            ok: outcome.is_ok(),
            error: outcome.err(),
        });
        shared.emit_devices();
    });

    Ok(())
}

async fn reject<S>(writer: &ChannelWriteHalf<S>, message: &str) -> Result<(), NetError>
where
    S: From<(russh::ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    net::send_message(
        writer,
        &ControlMessage::PairConfirm {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            accepted: false,
            transcript_hash: [0; 32],
            signature: String::new(),
        },
    )
    .await?;
    let _ = message;
    Ok(())
}

/// Wait for the local decision, exchange signed confirmations, and pin the peer on success.
#[allow(clippy::too_many_arguments)]
async fn confirm<S>(
    shared: Arc<Shared>,
    mut reader: ChannelReadHalf,
    writer: ChannelWriteHalf<S>,
    peer: TrustedPeer,
    hash: [u8; 32],
    decision: oneshot::Receiver<bool>,
    is_responder: bool,
    device_id: &str,
    buffer: &mut Vec<u8>,
    _connection: Option<russh::client::Handle<crate::net::PinnedHostKey>>,
) -> Result<(), String>
where
    S: From<(russh::ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    let accepted = tokio::time::timeout(net::PAIRING_WINDOW, decision)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);

    let signature = if accepted {
        shared
            .identity
            .sign(&hash)
            .map_err(|_| "could not sign the pairing transcript".to_owned())?
    } else {
        String::new()
    };
    net::send_message(
        &writer,
        &ControlMessage::PairConfirm {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            accepted,
            transcript_hash: hash,
            signature,
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    if !accepted {
        return Err(if is_responder {
            "pairing was declined on this device".into()
        } else {
            "pairing was cancelled".into()
        });
    }

    let remote = tokio::time::timeout(
        Duration::from_secs(net::PAIRING_WINDOW.as_secs()),
        net::recv_message(&mut reader, buffer, net::PAIRING_WINDOW),
    )
    .await
    .map_err(|_| "the other device did not confirm the pairing".to_owned())?
    .map_err(|e| e.to_string())?;

    let (accepted_remote, remote_hash, remote_signature) = match remote {
        ControlMessage::PairConfirm {
            accepted,
            transcript_hash,
            signature,
            ..
        } => (accepted, transcript_hash, signature),
        other => return Err(format!("expected pair_confirm, received {}", other.kind())),
    };
    if !accepted_remote {
        return Err("pairing was declined on the other device".to_owned());
    }
    if remote_hash != hash {
        return Err("the two devices derived different pairing codes".to_owned());
    }
    if !identity::verify(&peer.client_key, &hash, &remote_signature) {
        return Err("the other device sent an invalid pairing signature".to_owned());
    }

    let mut trusted = peer;
    trusted.fingerprint = fingerprint(&trusted.host_key);
    shared
        .with_db_write(|db| db::trust_peer(db, &trusted))
        .map_err(|_| "could not save the paired device".to_owned())?;
    let _ = device_id;
    Ok(())
}
