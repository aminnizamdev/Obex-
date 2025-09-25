use thiserror::Error;

#[derive(Debug, Error)]
pub enum Step1Error {
    #[error("invalid length: expected {expected} got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("index out of range: {index} not in [0, {max})")]
    OutOfRangeIndex { index: u32, max: u32 },

    #[error("invalid VRF proof")]
    InvalidProof,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("merkle path mismatch")]
    MerklePathMismatch,

    #[error("challenge derivation error")]
    ChallengeDerivationError,

    #[error("decode error: {0}")]
    DecodeError(&'static str),

    #[error("encode error: {0}")]
    EncodeError(&'static str),

    #[error("challenge derivation failed after maximum attempts")]
    ChallengeDerivationFailed,

    #[error("challenge indices mismatch")]
    ChallengeIndicesMismatch,

    #[error("ticket expired: timestamp {timestamp}, current {current_time}, window {window}s")]
    TicketExpired { timestamp: u64, current_time: u64, window: u64 },
}