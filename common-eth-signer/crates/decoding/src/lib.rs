//! ERC-4527 `eth-sign-request` (CBOR) decoding and `eth-signature` encoding.
//!
//! Scope: the binary CBOR payload only. The UR bytewords / fountain-code /
//! animated-QR transport layer is intentionally out of scope (handled by the
//! host/QR scanner, not the signer logic).
//!
//! [`tx`] is public because the transaction encoding it reads is ERC-4527's
//! `sign-data`, not ERC-4527 itself: a transport that carries the same bytes
//! without the CBOR envelope needs the decoders without [`decode_sign_request`].

mod encode;
mod hdkey;
mod keypath;
mod request;
pub mod tx;
mod value;

pub use encode::encode_eth_signature;
pub use hdkey::encode_crypto_hdkey;
pub use request::decode_sign_request;
pub use tx::{decode_eip1559, decode_eip7702, decode_legacy, decode_sign_data, decode_typed_tx};
