//! Error types for arxia-keri

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("KERI core error: {0}")]
    KeriCore(String),

    #[error("Invalid key configuration: {0}")]
    InvalidKeyConfig(String),

    #[error("Inception failed: {0}")]
    InceptionFailed(String),

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("Signature threshold error: {0}")]
    ThresholdError(String),

    #[error("Witness error: {0}")]
    WitnessError(String),

    #[error("Query/Reply error: {0}")]
    QueryReplyError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Seed error: {0}")]
    SeedError(String),

    #[error("Recovery error: {0}")]
    RecoveryError(String),

    #[error("Delegation error: {0}")]
    DelegationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Event not found: sn={0}")]
    EventNotFound(u64),

    #[error("Invalid event chain")]
    InvalidEventChain,

    #[error("SAID verification failed")]
    SaidVerificationFailed,

    #[error("Signature threshold not met: need {needed}, got {actual}")]
    ThresholdNotMet { needed: u64, actual: u64 },
}