//! The canonical signing-flow orchestration, generic over the confirmation UI.

use signer_core::{DecodedTx, MessageKind, Result, SignerError};
use signer_decoding::{decode_sign_request, encode_eth_signature};
use signer_displaying::{build_view_model, ConfirmationUi, Decision};
use signer_signing::{address_of, key_from_entropy, sign_request};

/// Device info echoed in the `origin` field of the returned `eth-signature`.
const DEVICE_ORIGIN: &str = "Rust Eth Signer";

/// Run the full flow: decode → derive & verify → confirm → sign → encode.
///
/// Returns the CBOR bytes of the ERC-4527 `eth-signature` on approval, or an
/// error (`AddressMismatch`, `UserRejected`, decode/sign failures, ...).
pub fn run_signing_flow(
    sign_req_cbor: &[u8],
    entropy: &[u8],
    ui: &mut dyn ConfirmationUi,
) -> Result<Vec<u8>> {
    // 1. Decode the request (reject if it cannot be decoded).
    let req = decode_sign_request(sign_req_cbor)?;

    // 2. Derive the key; verify it matches the request address if present.
    let key = key_from_entropy(entropy, &req.derivation_path)?;
    let signer = address_of(&key);
    if let Some(expected) = req.address {
        if signer != expected {
            return Err(SignerError::AddressMismatch);
        }
    }

    // 2b. Frame transactions: the device key must own a canonical-hash
    // signature slot (explicit-digest asks are refused). Checked before the
    // UI — like AddressMismatch — and re-checked inside `sign_request`.
    if let MessageKind::Transaction(DecodedTx::Frame(tx)) = &req.message {
        tx.signer_role(signer)?;
    }

    // 3. Show the request and get the user's decision.
    let view_model = build_view_model(&req, signer);
    if ui.confirm(&view_model)? == Decision::Reject {
        return Err(SignerError::UserRejected);
    }

    // 4. Sign and 5. encode the eth-signature.
    let signature = sign_request(&req, &key)?;
    Ok(encode_eth_signature(
        req.request_id,
        &signature,
        Some(DEVICE_ORIGIN),
    ))
}
