//! Host test-scenario entry point: drive the flow from two hex strings.

use signer_core::{Result, SignerError};
use signer_displaying::ConfirmationUi;

use crate::flow::run_signing_flow;

fn unhex(label: &str, s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| SignerError::Decode(format!("{label} hex: {e}")))
}

/// Decode the two hex inputs (the CBOR `eth-sign-request` and the BIP-39
/// entropy) and run the signing flow.
pub fn run_scenario(
    sign_req_hex: &str,
    entropy_hex: &str,
    ui: &mut dyn ConfirmationUi,
) -> Result<Vec<u8>> {
    let cbor = unhex("eth-sign-request", sign_req_hex)?;
    let entropy = unhex("entropy", entropy_hex)?;
    run_signing_flow(&cbor, &entropy, ui)
}
