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

            let result = state.borrow_mut().store.create(&options.label);
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
        move |label| state.borrow().store.validate_label(&label).unwrap_or_default().into()
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
