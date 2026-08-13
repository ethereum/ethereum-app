//! Key derivation from BIP-39 entropy and signing of decoded eth-sign-requests.

mod hashing;
mod seed;
mod sign;

pub use hashing::signing_hash;
pub use seed::{address_of, key_from_entropy};
pub use sign::sign_request;

/// The secp256k1 signing key type used across the workspace.
pub use k256::ecdsa::SigningKey;
