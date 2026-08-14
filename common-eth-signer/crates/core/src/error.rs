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

    /// A legacy transaction without an EIP-155 chain id. Its signature would
    /// be valid on every EVM chain, so it is refused outright.
    #[error("pre-EIP-155 legacy transaction (no chain id) is not supported")]
    PreEip155Unsupported,

    /// The request-level `chain-id` (ERC-4527 key 4) contradicts the chain id
    /// inside the transaction that would actually be signed.
    #[error("chain-id mismatch: request says {request}, transaction says {transaction}")]
    ChainIdMismatch { request: u64, transaction: u64 },

    /// An EIP-8141 frame transaction violated a structural or static
    /// constraint (see [`crate::frame_tx::FrameTxError`]).
    #[error("invalid frame transaction: {0}")]
    InvalidFrameTx(#[from] crate::frame_tx::FrameTxError),

    /// A frame transaction with no `SECP256K1` canonical-hash signature entry
    /// resolving to the device key: the signature the device would produce
    /// could never be inserted into this transaction, so it is refused.
    #[error("frame transaction has no canonical-hash SECP256K1 signature entry for the device key")]
    FrameNoSignatureSlot,

    /// A frame transaction asked the device to sign an explicit 32-byte
    /// digest. Refused: per EIP-8141's security considerations an
    /// explicit-digest approval is not bound to this transaction's frames and
    /// amounts to an open-ended authorization.
    #[error("refusing to sign an explicit digest for a frame transaction (open-ended authorization)")]
    FrameExplicitDigestRefused,

    /// A filled SECP256K1 co-signature in a frame transaction does not verify
    /// against its resolved signer; the transaction could never be valid
    /// on-chain, so the device refuses to co-sign it.
    #[error("frame transaction carries an invalid co-signature at index {0}")]
    FrameInvalidCoSignature(usize),

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
