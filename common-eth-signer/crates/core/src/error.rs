use thiserror::Error;

/// Errors that can occur anywhere in the signing flow.
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("CBOR decode error: {0}")]
    Decode(String),

    #[error("unsupported data-type: {0}")]
    UnsupportedDataType(u64),

    #[error("invalid transaction encoding: {0}")]
    InvalidTransaction(String),

    #[error("invalid EIP-712 typed data: {0}")]
    InvalidTypedData(String),

    #[error("key derivation error: {0}")]
    Derivation(String),

    #[error("signing key does not match the address in the request")]
    AddressMismatch,

    #[error("user rejected the signing request")]
    UserRejected,

    #[error("signing error: {0}")]
    Signing(String),

    #[error("UI error: {0}")]
    Ui(String),
}

/// Convenience result alias used throughout the workspace.
pub type Result<T> = core::result::Result<T, SignerError>;
