//! Producing the `r || s || v` signature.

use k256::ecdsa::{RecoveryId, SigningKey};
use signer_core::{DecodedTx, MessageKind, Result, SignRequest, SignerError};

use crate::hashing::signing_hash;

/// Sign a decoded request, returning `r (32) || s (32) || v` where `v` is the
/// minimal big-endian encoding of the value below. This matches the Keystone
/// reference `eth-signature` exactly (the consumer slices `[64..]` for `v` and
/// feeds it straight into the transaction, unmodified).
///
/// `v` convention:
/// - Legacy **EIP-155** transaction: `chain_id*2 + 35 + recovery_id` (the full
///   EIP-155 `v`; may be several bytes for large chain ids — e.g. 4 bytes on
///   Sepolia, making the signature 68 bytes).
/// - Legacy pre-EIP-155 transaction (no chain id): `27 + recovery_id`.
/// - EIP-2718 typed transactions (1559 / 7702): `recovery_id` (`y_parity`, 0/1).
/// - EIP-191 and EIP-712: `27 + recovery_id`.
pub fn sign_request(req: &SignRequest, key: &SigningKey) -> Result<Vec<u8>> {
    let hash = signing_hash(req);
    let (signature, recovery_id) = key
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|e| SignerError::Signing(e.to_string()))?;

    let v = v_value(&req.message, recovery_id);

    let mut out = Vec::with_capacity(64 + 8);
    out.extend_from_slice(&signature.r().to_bytes());
    out.extend_from_slice(&signature.s().to_bytes());
    out.extend_from_slice(&minimal_be(v));
    Ok(out)
}

fn v_value(message: &MessageKind, recovery_id: RecoveryId) -> u64 {
    let y = recovery_id.to_byte() as u64; // 0 or 1
    match message {
        MessageKind::Transaction(DecodedTx::Legacy(t)) => match t.chain_id {
            Some(chain_id) => chain_id * 2 + 35 + y, // EIP-155
            None => 27 + y,                          // pre-EIP-155
        },
        // Typed transactions carry the raw y-parity.
        MessageKind::Transaction(_) => y,
        // personal_sign / typed data use the classic 27/28.
        _ => 27 + y,
    }
}

/// Encode `v` as a minimal big-endian byte sequence (no leading zero bytes).
/// `v == 0` (a typed tx with `recovery_id == 0`) yields an empty slice, so the
/// signature is 64 bytes — matching the Keystone serializer.
fn minimal_be(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first_nonzero..].to_vec()
}
