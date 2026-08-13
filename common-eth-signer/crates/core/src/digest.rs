//! ERC-8213 digest helpers.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{eip191_hash_message, keccak256, B256};

use crate::error::{Result, SignerError};

/// ERC-8213 EIP-191 Digest: the 32-byte result of the EIP-191 `signed_data`
/// for version 0x45 — `keccak256("\x19Ethereum Signed Message:\n" ||
/// len(message) || message)`. This is the value that is ultimately signed.
pub fn eip191_digest(message: &[u8]) -> B256 {
    eip191_hash_message(message)
}

/// ERC-8213 Calldata Digest: `keccak256( uint256(len(calldata)) || calldata )`.
///
/// The 32-byte big-endian length prefix prevents truncation/extension ambiguity,
/// and the chain id / envelope fields are intentionally excluded so the same
/// calldata yields the same digest on every chain.
pub fn calldata_digest(calldata: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(32 + calldata.len());
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(calldata.len() as u64).to_be_bytes());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(calldata);
    keccak256(buf)
}

/// The three ERC-8213 hashes for EIP-712 typed data:
/// `(EIP-712 Digest, Domain Hash, Message Hash)`.
pub fn eip712_digests(td: &TypedData) -> Result<(B256, B256, B256)> {
    let digest = td
        .eip712_signing_hash()
        .map_err(|e| SignerError::InvalidTypedData(e.to_string()))?;
    let domain_hash = td.domain.hash_struct();
    let message_hash = td
        .hash_struct()
        .map_err(|e| SignerError::InvalidTypedData(e.to_string()))?;
    Ok((digest, domain_hash, message_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip191_digest_matches_the_spec_formula() {
        let message = b"hello";
        let mut manual = Vec::new();
        manual.extend_from_slice(b"\x19Ethereum Signed Message:\n5");
        manual.extend_from_slice(message);
        assert_eq!(eip191_digest(message), keccak256(manual));
    }
}
