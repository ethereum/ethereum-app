//! The signing hash (keccak digest that is actually signed) per message kind.

use alloy_consensus::SignableTransaction;
use alloy_primitives::{eip191_hash_message, B256};
use signer_core::{DecodedTx, MessageKind, SignRequest};

/// Compute the 32-byte hash that must be signed for this request.
///
/// - EIP-191: `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`.
/// - EIP-712: the precomputed ERC-8213 "EIP-712 Digest".
/// - Transactions: alloy's `signature_hash` (legacy uses EIP-155 with chain id).
pub fn signing_hash(req: &SignRequest) -> B256 {
    match &req.message {
        MessageKind::Eip191(m) => eip191_hash_message(&m.raw),
        MessageKind::Eip712(td) => td.eip712_digest,
        MessageKind::Transaction(tx) => match tx {
            DecodedTx::Legacy(t) => t.signature_hash(),
            DecodedTx::Eip1559(t) => t.signature_hash(),
            DecodedTx::Eip7702(t) => t.signature_hash(),
        },
    }
}
