//! Versioned messages exchanged only over the authenticated Henad control channel.
//!
//! Discovery records are intentionally not represented here: they are hints, not authority.
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

/// Every control payload carries an explicit version and request identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    PairOffer {
        protocol_version: u16,
        request_id: Uuid,
        initiator_id: String,
        host_public_key: Vec<u8>,
        client_public_key: Vec<u8>,
        nonce: [u8; 32],
    },
    PairConfirm {
        protocol_version: u16,
        request_id: Uuid,
        accepted: bool,
        transcript_hash: [u8; 32],
        signature: Vec<u8>,
    },
    TransferOffer {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        name: String,
        bytes: u64,
        blake3: [u8; 32],
    },
    TransferDecision {
        protocol_version: u16,
        request_id: Uuid,
        transfer_id: Uuid,
        accepted: bool,
        error: Option<ProtocolError>,
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
            | Self::PairConfirm {
                protocol_version, ..
            }
            | Self::TransferOffer {
                protocol_version, ..
            }
            | Self::TransferDecision {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_with_a_type_and_version() {
        let message = ControlMessage::TransferOffer {
            protocol_version: PROTOCOL_VERSION,
            request_id: Uuid::nil(),
            transfer_id: Uuid::nil(),
            name: "report.pdf".into(),
            bytes: 42,
            blake3: [7; 32],
        };
        let encoded = serde_json::to_string(&message).unwrap();
        assert!(encoded.contains("transfer_offer"));
        assert_eq!(
            serde_json::from_str::<ControlMessage>(&encoded).unwrap(),
            message
        );
        assert!(message.validate_version().is_ok());
    }

    #[test]
    fn rejects_an_unknown_protocol_version() {
        let message = ControlMessage::CancelTransfer {
            protocol_version: PROTOCOL_VERSION + 1,
            request_id: Uuid::nil(),
            transfer_id: Uuid::nil(),
        };
        assert_eq!(
            message.validate_version().unwrap_err().code,
            ErrorCode::UnsupportedVersion
        );
    }
}
