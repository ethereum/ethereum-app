//! Producing the `r || s || v` signature (and the EIP-8141 `v || r || s`
//! signature-entry encoding for frame transactions).

use alloy_primitives::{keccak256, Address, B256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use signer_core::frame_tx::{FrameTx, SignatureScheme};
use signer_core::{DecodedTx, MessageKind, Result, SignRequest, SignerError};

use crate::hashing::signing_hash;
use crate::seed::address_of;

/// Sign a decoded request, returning `r (32) || s (32) || v` where `v` is the
/// minimal big-endian encoding of the value below. This matches the Keystone
/// reference `eth-signature` exactly (the consumer slices `[64..]` for `v` and
/// feeds it straight into the transaction, unmodified).
///
/// `v` convention:
/// - Legacy **EIP-155** transaction: `chain_id*2 + 35 + recovery_id` (the full
///   EIP-155 `v`; may be several bytes for large chain ids — e.g. 4 bytes on
///   Sepolia, making the signature 68 bytes).
/// - EIP-2718 typed transactions (1559 / 7702): `recovery_id` (`y_parity`, 0/1).
/// - EIP-191 and EIP-712: `27 + recovery_id`.
///
/// Legacy pre-EIP-155 transactions (no chain id) are refused: their signature
/// would be valid on every EVM chain. The decoder already rejects them; the
/// checks here are deliberate redundancy so no single skipped branch can
/// authorize a replayable or chain-mismatched signature.
pub fn sign_request(req: &SignRequest, key: &SigningKey) -> Result<Vec<u8>> {
    // Re-verify the envelope/transaction chain-id binding before any
    // signature exists (fail closed, no partial success).
    req.validate_chain_binding()?;

    // EIP-8141 frame transactions have their own signature encoding
    // (`v || r || s`, v ∈ {0, 1}) and signing policy; they never take the
    // `r || s || v` path below.
    if let MessageKind::Transaction(DecodedTx::Frame(tx)) = &req.message {
        return sign_frame_tx(tx, key);
    }

    let hash = signing_hash(req);
    let (signature, recovery_id) = key
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|e| SignerError::Signing(e.to_string()))?;

    let v = v_value(&req.message, recovery_id)?;

    let mut out = Vec::with_capacity(64 + 8);
    out.extend_from_slice(&signature.r().to_bytes());
    out.extend_from_slice(&signature.s().to_bytes());
    out.extend_from_slice(&minimal_be(v));
    Ok(out)
}

fn v_value(message: &MessageKind, recovery_id: RecoveryId) -> Result<u64> {
    let y = recovery_id.to_byte() as u64; // 0 or 1
    Ok(match message {
        MessageKind::Transaction(DecodedTx::Legacy(t)) => match t.chain_id {
            // EIP-155: chain_id * 2 + 35 + y, checked so a hostile chain id
            // near u64::MAX cannot overflow (debug panic / silent wrap).
            Some(chain_id) => chain_id
                .checked_mul(2)
                .and_then(|c| c.checked_add(35 + y))
                .ok_or_else(|| SignerError::Signing("chain id overflows EIP-155 v".into()))?,
            // Unreachable past `validate_chain_binding`; refuse rather than
            // emit the replayable pre-EIP-155 `27 + y`.
            None => return Err(SignerError::PreEip155Unsupported),
        },
        // Unreachable: `sign_request` routes frame transactions to
        // `sign_frame_tx` before this point. Refuse rather than emit an
        // `r || s || v` signature a consumer could misplace (fail closed
        // under fault).
        MessageKind::Transaction(DecodedTx::Frame(_)) => {
            return Err(SignerError::Signing(
                "frame transactions must use the frame signing path".into(),
            ))
        }
        // Typed transactions carry the raw y-parity.
        MessageKind::Transaction(_) => y,
        // personal_sign / typed data use the classic 27/28.
        _ => 27 + y,
    })
}

/// Encode `v` as a minimal big-endian byte sequence (no leading zero bytes).
/// `v == 0` (a typed tx with `recovery_id == 0`) yields an empty slice, so the
/// signature is 64 bytes — matching the Keystone serializer.
fn minimal_be(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first_nonzero..].to_vec()
}

/// Sign an EIP-8141 frame transaction, returning the 65-byte `SECP256K1`
/// signature-entry encoding `v (1) || r (32) || s (32)` with `v` the recovery
/// id (0 or 1 — never 27/28 or EIP-155) and canonical low-s `r`/`s`. The
/// wallet drops these bytes into the entry's `signature` field verbatim.
///
/// Fail-closed policy, each check independent of the decode boundary
/// (deliberate redundancy against fault injection):
///
/// 1. The transaction must re-validate ([`FrameTx::validate`]).
/// 2. The device key must own a canonical-hash `SECP256K1` signature slot
///    ([`FrameTx::signer_role`]); explicit-digest asks are refused — an
///    explicit digest is not bound to this transaction's frames and would be
///    an open-ended authorization (EIP-8141 security considerations).
/// 3. Every already-filled `SECP256K1` co-signature must verify against its
///    resolved signer; the device never co-signs a transaction that could not
///    be valid on-chain.
///
/// Only then is the canonical hash (`compute_sig_hash`) signed — never an
/// explicit digest.
fn sign_frame_tx(tx: &FrameTx, key: &SigningKey) -> Result<Vec<u8>> {
    tx.validate().map_err(SignerError::from)?;

    let device = address_of(key);
    tx.signer_role(device)?;

    let sig_hash = tx.sig_hash();
    verify_co_signatures(tx, sig_hash)?;

    let (mut signature, mut recovery_id) = key
        .sign_prehash_recoverable(sig_hash.as_slice())
        .map_err(|e| SignerError::Signing(e.to_string()))?;

    // k256 already emits low-s signatures; normalize defensively anyway and
    // flip the recovery parity if it ever fired, then enforce v ∈ {0, 1}.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recovery_id = RecoveryId::from_byte(recovery_id.to_byte() ^ 1)
            .ok_or_else(|| SignerError::Signing("recovery id normalization failed".into()))?;
    }
    let v = recovery_id.to_byte();
    if v > 1 {
        return Err(SignerError::Signing(
            "recovery id out of range for an EIP-8141 signature".into(),
        ));
    }

    let mut out = Vec::with_capacity(65);
    out.push(v);
    out.extend_from_slice(&signature.r().to_bytes());
    out.extend_from_slice(&signature.s().to_bytes());
    Ok(out)
}

/// Verify every already-filled `SECP256K1` signature entry: recover the
/// signer from the entry's message (the canonical hash for empty `msg`, the
/// explicit digest otherwise) and require it to equal the resolved signer.
///
/// `FrameTx::validate` has already enforced 65-byte length, `v ∈ {0, 1}`, and
/// canonical low-s bounds; any inconsistency found here anyway fails closed.
fn verify_co_signatures(tx: &FrameTx, sig_hash: B256) -> Result<()> {
    for (index, entry) in tx.signatures.iter().enumerate() {
        if entry.scheme != SignatureScheme::Secp256k1 || entry.signature.is_empty() {
            continue;
        }
        let invalid = || SignerError::FrameInvalidCoSignature(index);
        let v = *entry.signature.first().ok_or_else(invalid)?;
        let rs = entry.signature.get(1..65).ok_or_else(invalid)?;
        let signature = Signature::from_slice(rs).map_err(|_| invalid())?;
        let recovery_id = RecoveryId::from_byte(v).ok_or_else(invalid)?;
        let message = entry.msg.unwrap_or(sig_hash);
        let verifying_key =
            VerifyingKey::recover_from_prehash(message.as_slice(), &signature, recovery_id)
                .map_err(|_| invalid())?;
        let resolved = entry.resolved_signer(tx.sender).ok_or_else(invalid)?;
        if ethereum_address(&verifying_key) != resolved {
            return Err(invalid());
        }
    }
    Ok(())
}

/// The Ethereum address of a verifying key: last 20 bytes of
/// `keccak256(uncompressed_public_key[1..])` (same derivation as
/// [`crate::seed::address_of`]).
fn ethereum_address(vk: &VerifyingKey) -> Address {
    let encoded = vk.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}
