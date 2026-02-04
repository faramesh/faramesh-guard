//! Error types for Guard security kernel

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardError {
    #[error("Invalid CAR format: {0}")]
    InvalidCar(String),

    #[error("Invalid permit: {0}")]
    InvalidPermit(String),

    #[error("Permit expired at {0}")]
    PermitExpired(i64),

    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("Replay detected: {0}")]
    ReplayDetected(String),

    #[error("Cache miss for hash: {0}")]
    CacheMiss(String),

    #[error("IPC error: {0}")]
    IpcError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for GuardError {
    fn from(e: serde_json::Error) -> Self {
        GuardError::SerializationError(e.to_string())
    }
}

impl From<std::io::Error> for GuardError {
    fn from(e: std::io::Error) -> Self {
        GuardError::IpcError(e.to_string())
    }
}
