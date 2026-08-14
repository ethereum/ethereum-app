// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Transaction signing: an ERC-4527 `eth-sign-request` UR arrives from the
//! QR scanner, gets decoded (`signer_decoding`), confirmed on the sign page
//! and signed (`signer_signing`); the resulting `eth-signature` CBOR is shown
//! as a UR QR for the watch-only wallet to scan back.
//!
//! Only transaction requests (eth-transaction-data / eth-typed-transaction)
//! are handled today; typed-data (EIP-712) and raw-bytes (EIP-191) requests
//! decode fine but land on a "not supported yet" placeholder.

use {
    crate::{
        state::AppState, tr, EthMessageView, EthTxView, EthTypedDataView, Navigate, SignRequestKind,
        SignTx, SignTxState, TrId,
    },
    signer_core::{MessageKind, SignRequest},
    slint_keyos_platform::{
        gui_server_api::navigation::qrscanner::ScanQrResult,
        slint::{ComponentHandle, SharedString},
        spawn_local, spawn_worker, StoredValue,
    },
};

/// `origin` field of the returned eth-signature: identifies the signer.
const SIGNATURE_ORIGIN: &str = "Passport Prime";

/// A decoded, confirmed-pending request plus its derived signing key.
pub struct PendingSignTx {
    pub request: SignRequest,
    pub key: k256::ecdsa::SigningKey,
}

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<SignTx>();

    global.on_sign_tx(move || {
        sign_pending(state);
    });

    global.on_cancel_signing(move || {
        state.borrow_mut().pending_sign_tx = None;
        let s = state.borrow();
        let ui = s.ui();
        let global = ui.global::<SignTx>();
        global.set_state(SignTxState::Idle);
        global.set_signature_ur("".into());
        global.set_error_message("".into());
    });
}

/// Entry point from the home-page scan button.
pub fn handle_scan(state: StoredValue<AppState>, scan: ScanQrResult) {
    match scan {
        // Cancelled / navigation taps: nothing to do.
        ScanQrResult::LeftClicked | ScanQrResult::RightClicked | ScanQrResult::ButtonClicked => {}
        ScanQrResult::Ur2 { ur_type, data, .. } if ur_type == "eth-sign-request" => {
            match prepare_request(state, &data) {
                Ok(()) => {}
                Err(e) => {
                    log::error!("failed to prepare sign request: {e:?}");
                    show_error(state, e.to_string());
                }
            }
        }
        // A UR of another type, or a plain (non-UR) QR code.
        ScanQrResult::Ur2 { ur_type, .. } => {
            log::error!("unexpected UR type from scanner: {ur_type}");
            show_error(state, tr::lookup_id(TrId::SignTxInvalidQr).to_string());
        }
        ScanQrResult::Qr { .. } => {
            show_error(state, tr::lookup_id(TrId::SignTxInvalidQr).to_string());
        }
    }
}

fn show_error(state: StoredValue<AppState>, message: String) {
    let s = state.borrow();
    let ui = s.ui();
    let global = ui.global::<SignTx>();
    global.set_error_message(message.into());
    global.set_state(SignTxState::Error);
    ui.global::<Navigate>().invoke_sign_tx(Default::default());
}

fn prepare_request(state: StoredValue<AppState>, cbor: &[u8]) -> anyhow::Result<()> {
    let request = match signer_decoding::decode_sign_request(cbor) {
        Ok(request) => request,
        Err(e) => {
            log::error!("failed to decode eth-sign-request: {e}");
            anyhow::bail!("{}", tr::lookup_id(TrId::SignTxInvalidQr));
        }
    };

    let Some(keys) = state.borrow().keys() else {
        anyhow::bail!("{}", tr::lookup_id(TrId::SignTxWrongKey));
    };

    let key = keys
        .signing_key(&request.derivation_path)
        .map_err(|e| {
            log::error!("cannot serve request path: {e:?}");
            anyhow::anyhow!("{}", tr::lookup_id(TrId::SignTxWrongKey))
        })?;

    let signer = signer_signing::address_of(&key);
    // ERC-4527: when the request names an address, it must match the derived key.
    if let Some(expected) = request.address {
        if expected != signer {
            anyhow::bail!("{}", tr::lookup_id(TrId::SignTxWrongKey));
        }
    }

    // The signing key must belong to an account that actually exists on this
    // device (active or archived), i.e. the path is m/44'/60'/j'/0/i for an
    // account #j of the current wallet.
    {
        let s = state.borrow();
        let account_index = account_index_of(&request.derivation_path)
            .ok_or_else(|| anyhow::anyhow!("{}", tr::lookup_id(TrId::SignTxNoAccount)))?;
        let fingerprint = s.current_fingerprint();
        if !s.store.has_account_index(&fingerprint, account_index) {
            log::error!(
                "request path {} matches no account (wallet {fingerprint})",
                request.derivation_path
            );
            anyhow::bail!("{}", tr::lookup_id(TrId::SignTxNoAccount));
        }
    }

    let model = signer_displaying::build_view_model(&request, signer);
    let origin = model.origin.clone().unwrap_or_default();

    {
        let mut s = state.borrow_mut();
        let ui = s.ui();
        let global = ui.global::<SignTx>();
        match model.body {
            signer_displaying::ConfirmBody::Transaction(tx) => {
                global.set_kind(SignRequestKind::Transaction);
                global.set_pending_tx(build_tx_view(tx, &model.signer_address, &origin));
            }
            signer_displaying::ConfirmBody::TypedData {
                json_pretty,
                eip712_digest,
                domain_hash,
                message_hash,
            } => {
                global.set_kind(SignRequestKind::TypedData);
                global.set_pending_typed_data(EthTypedDataView {
                    json: json_pretty.into(),
                    eip712_digest: eip712_digest.into(),
                    domain_hash: domain_hash.into(),
                    message_hash: message_hash.into(),
                    origin: origin.into(),
                });
            }
            signer_displaying::ConfirmBody::Message { .. } => {
                global.set_kind(SignRequestKind::Message);
                global.set_pending_message(build_message_view(&request, origin.clone()));
            }
        }
        s.pending_sign_tx = Some(PendingSignTx { request, key });
        global.set_signature_ur("".into());
        global.set_error_message("".into());
        global.set_state(SignTxState::Sign);
        ui.global::<Navigate>().invoke_sign_tx(Default::default());
    }

    Ok(())
}

/// The BIP-44 account index of a standard m/44'/60'/j'/0/i request path;
/// None when the path has any other shape.
fn account_index_of(path: &signer_core::DerivationPath) -> Option<u32> {
    let c = &path.components;
    let expected_prefix =
        [(44u32, true), (60, true)].iter().zip(c).all(|(&(i, h), comp)| comp.index == i && comp.hardened == h);
    if c.len() == 5
        && expected_prefix
        && c[2].hardened
        && !c[3].hardened
        && c[3].index == 0
        && !c[4].hardened
    {
        Some(c[2].index)
    } else {
        None
    }
}

/// A message is displayable when it is valid UTF-8 containing no control
/// characters other than whitespace; anything else falls back to hex with a
/// warning on the sign page.
fn build_message_view(request: &SignRequest, origin: String) -> EthMessageView {
    let MessageKind::Eip191(message) = &request.message else {
        unreachable!("build_message_view on a non-message request");
    };

    let digest = signer_core::eip191_digest(&message.raw);

    let displayable_text = message.as_utf8.as_ref().filter(|text| {
        text.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    });
    let displayable = displayable_text.is_some();
    let text = displayable_text
        .cloned()
        .unwrap_or_else(|| format!("0x{}", hex::encode(&message.raw)));

    EthMessageView {
        text: text.into(),
        displayable,
        eip191_digest: format!("0x{}", hex::encode(digest)).into(),
        origin: origin.into(),
    }
}

fn build_tx_view(
    tx: signer_displaying::TxView,
    signer_address: &str,
    origin: &str,
) -> EthTxView {
    let to_is_address = tx.to.starts_with("0x");
    let to = if to_is_address {
        tx.to
    } else {
        tr::lookup_id(TrId::SignTxContractCreation).to_string()
    };

    EthTxView {
        from: signer_address.into(),
        to: to.into(),
        to_is_address,
        // The chain id from the RLP transaction body — the value the signature
        // commits to. Never the request-level (attacker-chosen) CBOR chain-id;
        // decoding rejects requests where the two disagree, and a pre-EIP-155
        // transaction shows the ALL CHAINS warning instead of a number.
        chain_id: tx.chain_id.into(),
        amount: tx.value.into(),
        max_fees: tx.max_fee.into(),
        tx_type: tx.tx_type.into(),
        origin: origin.into(),
        has_data: tx.calldata_digest.is_some(),
        data_digest: tx.calldata_digest.unwrap_or_default().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::account_index_of;
    use crate::eth_keys::KeyCache;
    use signer_core::{ChildNumber, DerivationPath};

    #[test]
    fn account_index_from_standard_paths() {
        assert_eq!(account_index_of(&KeyCache::path_for(0, 0)), Some(0));
        assert_eq!(account_index_of(&KeyCache::path_for(7, 42)), Some(7));

        // Wrong shapes are refused.
        assert_eq!(account_index_of(&KeyCache::account_origin(0)), None);
        let change = DerivationPath {
            components: vec![
                ChildNumber { index: 44, hardened: true },
                ChildNumber { index: 60, hardened: true },
                ChildNumber { index: 0, hardened: true },
                ChildNumber { index: 1, hardened: false },
                ChildNumber { index: 0, hardened: false },
            ],
        };
        assert_eq!(account_index_of(&change), None);
        let wrong_coin = DerivationPath {
            components: vec![
                ChildNumber { index: 44, hardened: true },
                ChildNumber { index: 0, hardened: true },
                ChildNumber { index: 0, hardened: true },
                ChildNumber { index: 0, hardened: false },
                ChildNumber { index: 0, hardened: false },
            ],
        };
        assert_eq!(account_index_of(&wrong_coin), None);
    }
}

fn sign_pending(state: StoredValue<AppState>) {
    let Some(pending) = state.borrow_mut().pending_sign_tx.take() else {
        log::error!("sign requested with no pending transaction");
        return;
    };

    state.borrow().ui().global::<SignTx>().set_state(SignTxState::Signing);

    spawn_local(async move {
        let result = spawn_worker(async move {
            let signature = signer_signing::sign_request(&pending.request, &pending.key)
                .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
            let cbor = signer_decoding::encode_eth_signature(
                pending.request.request_id,
                &signature,
                Some(SIGNATURE_ORIGIN),
            );
            // Single-part UR; uppercased so the QR encoder can use
            // alphanumeric mode.
            Ok::<String, anyhow::Error>(
                foundation_ur::UR::new("eth-signature", &cbor).to_string().to_uppercase(),
            )
        })
        .await;

        let s = state.borrow();
        let ui = s.ui();
        let global = ui.global::<SignTx>();
        match result {
            Ok(ur) => {
                global.set_signature_ur(SharedString::from(ur));
                global.set_state(SignTxState::Success);
            }
            Err(e) => {
                log::error!("{e:?}");
                global.set_error_message(tr::lookup_id(TrId::SignTxInvalidQr).into());
                global.set_state(SignTxState::Error);
            }
        }
    })
    .detach();
}
