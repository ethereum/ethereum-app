//! ERC-4527 `eth-sign-request` (CBOR) decoding and `eth-signature` encoding.
//!
//! Scope: the binary CBOR payload only. The UR bytewords / fountain-code /
//! animated-QR transport layer is intentionally out of scope (handled by the
//! host/QR scanner, not the signer logic).

mod encode;
mod hdkey;
mod keypath;
mod request;
mod tx;
mod value;

pub use encode::encode_eth_signature;
pub use hdkey::encode_crypto_hdkey;
pub use request::decode_sign_request;
