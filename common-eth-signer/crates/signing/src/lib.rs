//! Key derivation from BIP-39 entropy and signing of decoded eth-sign-requests.

mod hashing;
mod seed;
mod sign;

pub use hashing::signing_hash;
pub use seed::{
    address_of, address_of_public, key_from_entropy, key_from_seed, seed_from_entropy, AccountKey,
    AccountXpub,
};
pub use sign::sign_request;

/// The secp256k1 signing key type used across the workspace.
pub use k256::ecdsa::SigningKey;
