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
    crate::{state::AppState, tr, EthTxView, Navigate, SignTx, SignTxState, TrId},
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

    // Placeholder until EIP-712 / EIP-191 support lands.
    if !matches!(request.message, MessageKind::Transaction(_)) {
        anyhow::bail!("{}", tr::lookup_id(TrId::SignTxUnsupportedType));
    }

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

    let view = build_tx_view(&request, signer);

    {
        let mut s = state.borrow_mut();
        s.pending_sign_tx = Some(PendingSignTx { request, key });
        let ui = s.ui();
        let global = ui.global::<SignTx>();
        global.set_pending_tx(view);
        global.set_signature_ur("".into());
        global.set_error_message("".into());
        global.set_state(SignTxState::Sign);
        ui.global::<Navigate>().invoke_sign_tx(Default::default());
    }

    Ok(())
}

fn build_tx_view(request: &SignRequest, signer: alloy_primitives::Address) -> EthTxView {
    let model = signer_displaying::build_view_model(request, signer);
    let tx = match model.body {
        signer_displaying::ConfirmBody::Transaction(tx) => tx,
        // prepare_request only lets transactions through.
        _ => unreachable!("non-transaction request on the sign page"),
    };

    let to = if tx.to == "(contract creation)" {
        tr::lookup_id(TrId::SignTxContractCreation).to_string()
    } else {
        tx.to
    };

    EthTxView {
        from: model.signer_address.into(),
        to: to.into(),
        // The request-level chain id (the tx's own field may be absent on a
        // pre-EIP-155 legacy transaction).
        chain_id: model.chain_id.to_string().into(),
        amount: tx.value.into(),
        max_fees: tx.max_fee.into(),
        tx_type: tx.tx_type.into(),
        origin: model.origin.unwrap_or_default().into(),
        has_data: tx.calldata_digest.is_some(),
        data_digest: tx.calldata_digest.unwrap_or_default().into(),
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
