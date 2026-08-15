// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Create-account flow (single Ethereum account, label only).

use {
    crate::{state::AppState, CreateAccount, CreateAccountState},
    slint_keyos_platform::{
        slint::{ComponentHandle, ToSharedString},
        StoredValue,
    },
};

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<CreateAccount>();

    global.on_create_single_sig({
        move |options| {
            let ui = state.borrow().ui();
            let global = ui.global::<CreateAccount>();

            global.set_state(CreateAccountState::Creating);

            let fingerprint = state.borrow().current_fingerprint();
            // The UI blocks creation on an unparseable index; first-free as a
            // backstop.
            let index = options.index.trim().parse::<u32>().ok();
            let result = state.borrow_mut().store.create(&options.label, &fingerprint, index);
            match result {
                Ok(account_id) => {
                    global.set_state(CreateAccountState::Success);
                    global.set_new_account_id(account_id.to_shared_string());
                    state.borrow().refresh_slint_accounts();
                }
                Err(e) => {
                    log::error!("failed to create account: {e:?}");
                    global.set_state(CreateAccountState::Error);
                }
            }
        }
    });

    global.on_validate_new_label({
        move |label| {
            let s = state.borrow();
            let fingerprint = s.current_fingerprint();
            s.store.validate_label(&label, &fingerprint).unwrap_or_default().into()
        }
    });

    global.on_validate_new_index({
        move |index| {
            let s = state.borrow();
            let fingerprint = s.current_fingerprint();
            match index.trim().parse::<u32>() {
                Ok(index) => s.store.validate_index(&fingerprint, index).unwrap_or_default().into(),
                // The empty/unparseable case greys the input via has-disabled.
                Err(_) => "".into(),
            }
        }
    });

    global.on_get_next_index({
        move || {
            let s = state.borrow();
            let fingerprint = s.current_fingerprint();
            s.store.next_index(&fingerprint).to_string().into()
        }
    });

    global.on_update_account_name({
        move |id, name| {
            let id = match id.as_str().parse::<crate::account_id::AccountId>() {
                Ok(id) => id,
                Err(_) => return,
            };
            AppState::update_account_config(state, id, |config| {
                config.name = name.to_string();
            });
        }
    });
}
