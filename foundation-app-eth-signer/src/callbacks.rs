// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Slint `Callbacks` global: account list actions and the lazily-derived
//! address model backing the explore-address page.

use {
    crate::{account_id::AccountId, gui_permissions::GuiPermissions, state::AppState, tr, Callbacks, TrId},
    slint_keyos_platform::{
        gui_server_api::navigation::qrscanner::ScanQrOptions,
        navigation::open_qr_scanner,
        slint::{ComponentHandle, ModelRc, SharedString},
        StoredValue,
    },
    std::{cell::RefCell, rc::Rc},
};

pub fn init_callbacks(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let callbacks = ui.global::<Callbacks>();

    callbacks.on_account_addresses(move |id| {
        let account_id = match id.as_str().parse::<AccountId>() {
            Ok(id) => id,
            Err(_) => return Default::default(),
        };
        ModelRc::new(AddressModel { account_id, state, cache: Default::default() })
    });

    callbacks.on_scan_clicked({
        move || {
            // Expect an ERC-4527 eth-sign-request UR; anything else lands on
            // the sign page's error state.
            let opts = ScanQrOptions {
                header_title: tr::lookup_id(TrId::ScanTitle).into(),
                header_right_icon: String::from("close"),
                ..ScanQrOptions::default()
            };
            match open_qr_scanner::<GuiPermissions>(opts) {
                Ok(Some(scan)) => crate::sign_tx::handle_scan(state, scan),
                Ok(None) => log::info!("nothing returned from qr scanner"),
                Err(e) => log::error!("error while scanning QR: {e:?}"),
            }
        }
    });

    callbacks.on_account_details({
        move |id| state.borrow().get_account_view_str(&id).map(|(_id, acct)| acct).unwrap_or_default()
    });

    callbacks.on_update_account_name(move |id, name| {
        let id = match id.as_str().parse::<AccountId>() {
            Ok(id) => id,
            Err(_) => return,
        };
        AppState::update_account_config(state, id, |config| {
            config.name = name.to_string();
        });
    });

    callbacks.on_set_archive_mode_inner(move |mode| {
        AppState::set_archive_mode(state, mode);
    });

    callbacks.on_update_account_archived(move |id, archived| {
        let id = match id.as_str().parse::<AccountId>() {
            Ok(id) => id,
            Err(_) => return,
        };
        AppState::update_account_config(state, id, |config| {
            config.archived = archived;
        });
    });

    callbacks.on_delete_account(move |id| {
        let id = match id.as_str().parse::<AccountId>() {
            Ok(id) => id,
            Err(_) => return,
        };
        AppState::delete_account(state, id);
    });
}

struct AddressModel {
    account_id: AccountId,
    state: StoredValue<AppState>,
    cache: Rc<RefCell<Vec<String>>>,
}

const MAX_ADDRESS_COUNT: usize = 1000;

impl slint_keyos_platform::slint::Model for AddressModel {
    type Data = SharedString;

    fn row_count(&self) -> usize {
        MAX_ADDRESS_COUNT
    }

    fn row_data(&self, row: usize) -> Option<Self::Data> {
        const WINDOW_SIZE: usize = 50;

        if row >= MAX_ADDRESS_COUNT {
            return None;
        }

        let mut cache = self.cache.borrow_mut();

        if row < cache.len() {
            return Some(SharedString::from(&cache[row]));
        }

        // Derive the next window of addresses. One non-hardened BIP-32 child
        // derivation per row off the cached account xprv — cheap enough for
        // the UI thread.
        let state = self.state.borrow();
        let keys = state.keys()?;
        let start = cache.len() as u32;
        let end = (row + 1).max(cache.len() + WINDOW_SIZE).min(MAX_ADDRESS_COUNT) as u32;
        for i in start..end {
            match keys.address(self.account_id.index, i) {
                Ok(address) => cache.push(address),
                Err(e) => {
                    log::error!("address derivation failed at {i}: {e:?}");
                    return None;
                }
            }
        }

        cache.get(row).map(SharedString::from)
    }

    fn model_tracker(&self) -> &dyn slint_keyos_platform::slint::ModelTracker {
        &()
    }
}
