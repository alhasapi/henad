//! Versioned messages exchanged only over the authenticated Henad SSH channel.
//!
//! Discovery records are intentionally not represented here: they are hints, not authority.
//! Every message carries an explicit protocol version and request identity so that a peer
//! speaking a different dialect fails closed instead of being misinterpreted.
use crate::core::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedVersion,
    Unauthorized,
    KeyChanged,
    PairingExpired,
    PairingRejected,
    InvalidPath,
    TransferRejected,
    TransferNotFound,
    HashMismatch,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Every control payload carries an explicit version and request identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    /// Initiator -> responder. The responder answers with [`ControlMessage::PairAccept`].
    PairOffer {
        protocol_version: u16,
        request_id: Uuid,
        initiator_id: String,
        initiator_name: String,
        host_public_key: Vec<u8>,
        client_public_key: Vec<u8>,
        nonce: [u8; 32],
    },
    /// Responder -> initiator: the responder's half of the transcript.
    PairAccept {
        protocol_version: u16,
        request_id: Uuid,
        host_public_key: Vec<u8>,
        client_public_key: Vec<u8>,
        nonce: [u8; 32],
    },
    /// Both directions: the human decision, bound to the transcript.
    PairConfirm {
        protocol_version: u16,
        request_id: Uuid,
        accepted: bool,
        transcript_hash: [u8; 32],
        /// `sshsig` PEM signature over `transcript_hash` with the sender's client key.
        signature: String,
    },
    TransferOffer {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        name: String,
        bytes: u64,
        /// Known only when the sender pre-hashed the file (not used in v2).
        blake3: Option<[u8; 32]>,
    },
    /// First frame on the dedicated data channel; raw file bytes follow immediately.
    TransferData {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
    },
    TransferDecision {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        accepted: bool,
        error: Option<ProtocolError>,
    },
    /// Sent by the sender after the last data byte; the receiver answers with a
    /// final [`ControlMessage::TransferStatus`] carrying the verification result.
    TransferComplete {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        completed_bytes: u64,
        blake3: [u8; 32],
    },
    TransferStatus {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        completed_bytes: u64,
        error: Option<ProtocolError>,
    },
    CancelTransfer {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
    },
    /// Reserved for a later milestone; peers answer with `TransferRejected`.
    ResumeTransfer {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        completed_bytes: u64,
        blake3: [u8; 32],
    },
}

impl ControlMessage {
    pub fn version(&self) -> u16 {
        match self {
            Self::PairOffer {
                protocol_version, ..
            }
            | Self::PairAccept {
                protocol_version, ..
            }
            | Self::PairConfirm {
                protocol_version, ..
            }
            | Self::TransferOffer {
                protocol_version, ..
            }
            | Self::TransferData {
                protocol_version, ..
            }
            | Self::TransferDecision {
                protocol_version, ..
            }
            | Self::TransferComplete {
                protocol_version, ..
            }
            | Self::TransferStatus {
                protocol_version, ..
            }
            | Self::CancelTransfer {
                protocol_version, ..
            }
            | Self::ResumeTransfer {
                protocol_version, ..
            } => *protocol_version,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::PairOffer { .. } => "pair_offer",
            Self::PairAccept { .. } => "pair_accept",
            Self::PairConfirm { .. } => "pair_confirm",
            Self::TransferOffer { .. } => "transfer_offer",
            Self::TransferData { .. } => "transfer_data",
            Self::TransferDecision { .. } => "transfer_decision",
            Self::TransferComplete { .. } => "transfer_complete",
            Self::TransferStatus { .. } => "transfer_status",
            Self::CancelTransfer { .. } => "cancel_transfer",
            Self::ResumeTransfer { .. } => "resume_transfer",
        }
    }

    pub fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.version() == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError {
                code: ErrorCode::UnsupportedVersion,
                message: format!("Henad protocol {} is not supported", self.version()),
            })
        }
    }

    pub fn request_id(&self) -> Uuid {
        match self {
            Self::PairOffer { request_id, .. }
            | Self::PairAccept { request_id, .. }
            | Self::PairConfirm { request_id, .. }
            | Self::TransferOffer { request_id, .. }
            | Self::TransferData { request_id, .. }
            | Self::TransferDecision { request_id, .. }
            | Self::TransferComplete { request_id, .. }
            | Self::TransferStatus { request_id, .. }
            | Self::CancelTransfer { request_id, .. }
            | Self::ResumeTransfer { request_id, .. } => *request_id,
        }
    }
}

/// Version check applied before any payload is trusted.
pub fn decode(bytes: &[u8]) -> Result<ControlMessage, ProtocolError> {
    let message = serde_json::from_slice::<ControlMessage>(bytes)
        .map_err(|_| ProtocolError::new(ErrorCode::Internal, "malformed Henad control message"))?;
    message.validate_version()?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(version: u16) -> ControlMessage {
        ControlMessage::TransferOffer {
            protocol_version: version,
            request_id: Uuid::nil(),
            transfer_id: Uuid::nil(),
            name: "report.pdf".into(),
            bytes: 42,
            blake3: None,
        }
    }

    #[test]
    fn messages_round_trip_with_a_type_and_version() {
        let message = offer(PROTOCOL_VERSION);
        let encoded = serde_json::to_string(&message).unwrap();
        assert!(encoded.contains("transfer_offer"));
        assert_eq!(
            serde_json::from_str::<ControlMessage>(&encoded).unwrap(),
            message
        );
        assert!(message.validate_version().is_ok());
        assert_eq!(
            decode(encoded.as_bytes()).unwrap().request_id(),
            Uuid::nil()
        );
    }

    #[test]
    fn rejects_unknown_protocol_versions() {
        for version in [1, PROTOCOL_VERSION + 1] {
            let message = ControlMessage::CancelTransfer {
                protocol_version: version,
                request_id: Uuid::nil(),
                transfer_id: Uuid::nil(),
            };
            assert_eq!(
                message.validate_version().unwrap_err().code,
                ErrorCode::UnsupportedVersion
            );
        }
        let encoded = serde_json::to_vec(&offer(1)).unwrap();
        assert_eq!(
            decode(&encoded).unwrap_err().code,
            ErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn rejects_malformed_payloads() {
        assert_eq!(
            decode(b"{\"type\":\"nope\"}").unwrap_err().code,
            ErrorCode::Internal
        );
    }

    #[test]
    fn pairing_messages_are_distinct_kinds() {
        let message = ControlMessage::PairOffer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            initiator_id: "a".into(),
            initiator_name: "A".into(),
            host_public_key: vec![1],
            client_public_key: vec![2],
            nonce: [3; 32],
        };
        assert_eq!(message.kind(), "pair_offer");
        assert_eq!(message.version(), PROTOCOL_VERSION);
    }
}
