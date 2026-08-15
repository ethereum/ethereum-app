// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Verify-address flow: scan a QR of an Ethereum address and check whether it
//! is one of this wallet's derived addresses (m/44'/60'/0'/0/i).

use {
    crate::{
        account_id::AccountId, eth_keys::KeyCache, gui_permissions::GuiPermissions, state::AppState,
        tr, Animate, CheckedRanges, ExploreAddressParams, Navigate, NavigateOptions, TrId,
        VerifyAddress, VerifyAddressOptions, VerifyAddressState,
    },
    slint_keyos_platform::{
        gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
        navigation::open_qr_scanner,
        slint::{ComponentHandle, ToSharedString},
        spawn_local, spawn_worker, StoredValue,
    },
    std::sync::Arc,
};

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<VerifyAddress>();

    global.on_verify_address({
        move |opt| {
            let VerifyAddressOptions { account_id, show_skip_button, show_view_all } = opt;
            let Ok(Some(scan)) = open_qr_scanner::<GuiPermissions>(ScanQrOptions {
                header_title: tr::lookup_id(TrId::VerifyAddressTitle).to_string(),
                header_right_text: if show_skip_button {
                    tr::lookup_id(TrId::CommonButtonSkip).to_string()
                } else {
                    String::from("")
                },
                button_text: if show_view_all {
                    tr::lookup_id(TrId::VerifyAddressExploreAllAddresses).to_string()
                } else {
                    String::from("")
                },
                button_icon: String::from(if show_view_all { "list" } else { "" }),
                ..ScanQrOptions::default()
            })
            .inspect_err(|e| log::error!("failed to open qr scanner: {}", e)) else {
                return;
            };

            let ui = state.borrow().ui();
            let nav = ui.global::<Navigate>();
            let verify = ui.global::<VerifyAddress>();

            match scan {
                ScanQrResult::Qr { data, .. } => {
                    let Ok(address) = String::from_utf8(data)
                        .inspect_err(|e| log::error!("failed to decode qr scanner data: {}", e))
                    else {
                        return;
                    };
                    nav.invoke_verify_address(
                        crate::VerifyAddressParams { account_id: account_id.clone() },
                        NavigateOptions { animate: Animate::None, replace: false },
                    );
                    spawn_local(async move {
                        verify_address(state, address, 0, account_id.into())
                            .await
                            .inspect_err(|e| {
                                log::error!("Could not verify address: {:?}", e);
                            })
                            .ok();
                    })
                    .detach();
                }
                // cancelled
                ScanQrResult::LeftClicked => {}
                // skipped
                ScanQrResult::RightClicked => {
                    nav.invoke_verify_address(
                        crate::VerifyAddressParams { account_id: account_id.clone() },
                        NavigateOptions { animate: Animate::None, replace: false },
                    );
                    verify.set_state(VerifyAddressState::Skipped);
                }
                ScanQrResult::ButtonClicked => {
                    nav.invoke_explore_address(ExploreAddressParams { account_id }, Default::default());
                }
                action => {
                    log::error!("verify address failed: {:?}", action);
                    nav.invoke_verify_address(
                        crate::VerifyAddressParams { account_id: account_id.clone() },
                        NavigateOptions { animate: Animate::None, replace: false },
                    );
                    verify.set_state(VerifyAddressState::Invalid);
                }
            }
        }
    });

    global.on_continue_verify_address({
        move |opt, address, attempt_number| {
            let VerifyAddressOptions { account_id, .. } = opt;
            spawn_local(async move {
                verify_address(state, address.into(), attempt_number as u32, account_id.into())
                    .await
                    .inspect_err(|e| {
                        log::error!("Could not verify address: {:?}", e);
                    })
                    .ok();
            })
            .detach();
        }
    });
}

const VERIFY_ADDRESS_CHUNK_SIZE: u32 = 200;

/// Normalized lowercase hex form (without checksum casing), or None when the
/// input is not an Ethereum address.
fn normalize_address(address: &str) -> Option<String> {
    // EIP-681 style QR payloads prefix the address with "ethereum:" and may
    // append chain/params after '@' or '?'.
    let address = address.trim();
    let address = address.strip_prefix("ethereum:").unwrap_or(address);
    let address = address.split(['@', '?', '/']).next().unwrap_or(address);

    let hex_part = address.strip_prefix("0x").or_else(|| address.strip_prefix("0X"))?;
    if hex_part.len() != 40 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", hex_part.to_lowercase()))
}

async fn verify_address(
    state: StoredValue<AppState>,
    address: String,
    attempt_number: u32,
    account_id: String,
) -> anyhow::Result<()> {
    let account_id = account_id.parse::<AccountId>()?;

    let ui = state.borrow().ui();
    let global = ui.global::<VerifyAddress>();

    global.set_state(VerifyAddressState::Loading);
    global.set_address(address.to_shared_string());

    let Some(needle) = normalize_address(&address) else {
        global.set_state(VerifyAddressState::Invalid);
        return Ok(());
    };

    let Some(keys) = state.borrow().keys() else {
        log::error!("keys not initialized yet");
        global.set_state(VerifyAddressState::Invalid);
        return Ok(());
    };

    // Each attempt checks the next chunk of address indices off the UI thread.
    let start = attempt_number * VERIFY_ADDRESS_CHUNK_SIZE;
    let end = start + VERIFY_ADDRESS_CHUNK_SIZE;

    let found = spawn_worker({
        let keys: Arc<KeyCache> = keys;
        let needle = needle.clone();
        let account = account_id.index;
        async move {
            for i in start..end {
                match keys.address(account, i) {
                    Ok(candidate) => {
                        if candidate.to_lowercase() == needle {
                            return Ok(Some(i));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(None)
        }
    })
    .await;

    match found {
        Ok(Some(index)) => {
            global.set_state(VerifyAddressState::Success);
            global.set_index(index as i32);
        }
        Ok(None) => {
            global.set_state(VerifyAddressState::Error);
            global.set_checked_ranges(CheckedRanges {
                change_start: 0,
                change_end: 0,
                receive_start: 0,
                receive_end: (end - 1) as i32,
            });
            global.set_attempt_number(attempt_number as i32);
        }
        Err(e) => {
            log::error!("failed to verify address: {e:?}, address: {address:?}");
            global.set_state(VerifyAddressState::Invalid);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_address;

    #[test]
    fn normalizes_plain_and_eip681() {
        let addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        let lower = addr.to_lowercase();
        assert_eq!(normalize_address(addr).as_deref(), Some(lower.as_str()));
        assert_eq!(normalize_address(&format!("ethereum:{addr}")).as_deref(), Some(lower.as_str()));
        assert_eq!(normalize_address(&format!("ethereum:{addr}@1")).as_deref(), Some(lower.as_str()));
        assert_eq!(normalize_address(&format!("{addr}?value=1")).as_deref(), Some(lower.as_str()));
    }

    #[test]
    fn rejects_invalid() {
        assert!(normalize_address("hello").is_none());
        assert!(normalize_address("0x1234").is_none());
        assert!(normalize_address("bc1qxyz").is_none());
    }
}
