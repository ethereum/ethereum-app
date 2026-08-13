// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Connect-wallet flow: exports the account's extended public key as an
//! ERC-4527 `crypto-hdkey` UR for a watch-only wallet to scan.

use {
    crate::{account_id::AccountId, eth_keys::KeyCache, state::AppState, ConnectAccount},
    slint_keyos_platform::{slint::ComponentHandle, StoredValue},
};

/// `source` field of the exported hdkey: identifies the signing device.
const HDKEY_SOURCE: &str = "Passport Prime";

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<ConnectAccount>();

    global.on_export_account_qr(move |id| {
        match export_account_ur(state, &id) {
            Ok(ur) => ur.into(),
            Err(e) => {
                log::error!("failed to export account {id}: {e:?}");
                "".into()
            }
        }
    });
}

fn export_account_ur(state: StoredValue<AppState>, id: &str) -> anyhow::Result<String> {
    let account_id = id.parse::<AccountId>()?;

    let state = state.borrow();
    let keys = state.keys.as_ref().ok_or_else(|| anyhow::anyhow!("keys not initialized yet"))?;
    let config = state
        .store
        .get(&account_id)
        .ok_or_else(|| anyhow::anyhow!("unknown account {account_id}"))?;

    let (key_data, chain_code) = keys.account_hdkey(account_id.index)?;
    let cbor = signer_decoding::encode_crypto_hdkey(
        &key_data,
        &chain_code,
        &KeyCache::account_origin(account_id.index),
        keys.master_fingerprint_u32(),
        Some(&config.name),
        Some(HDKEY_SOURCE),
    );

    // Single-part UR; uppercased so the QR encoder can use alphanumeric mode.
    Ok(foundation_ur::UR::new("crypto-hdkey", &cbor).to_string().to_uppercase())
}
