//! Shared types, ERC-8213 digests, and errors for the Ethereum signer.
//!
//! This crate is the dependency-cycle breaker: `decoding`, `signing`, and
//! `displaying` all depend on it, but never on each other.

pub mod digest;
pub mod error;
pub mod request;

pub use digest::{calldata_digest, eip191_digest, eip712_digests};
pub use error::{Result, SignerError};
pub use request::{
    ChildNumber, DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest, TxDisplay,
    TypedData712,
};

// Re-export the alloy types that appear in our public API so downstream crates
// use exactly the same versions.
pub use alloy_consensus;
pub use alloy_dyn_abi;
pub use alloy_primitives;
