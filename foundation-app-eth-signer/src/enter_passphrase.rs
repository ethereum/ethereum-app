// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Passphrase flow stub. The page and its global are kept compiling and
//! reachable; the logic will later be wired using the key-source approach
//! from the my-coin example (device app-seed vs imported phrase).

use {
    crate::{state::AppState, EnterPassphrase},
    slint_keyos_platform::{slint::ComponentHandle, StoredValue},
};

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<EnterPassphrase>();

    global.on_try(move |_passphrase| {
        log::info!("passphrase try: not implemented yet");
        let ui = state.borrow().ui();
        let global = ui.global::<EnterPassphrase>();
        global.set_fingerprint_loading(false);
        global.set_fingerprint("".into());
    });

    global.on_confirm(move |_passphrase| {
        log::info!("passphrase confirm: not implemented yet");
    });

    global.on_clear_passphrase(move || {
        log::info!("passphrase clear: not implemented yet");
    });

    global.on_create_initial_account(move |_passphrase| {
        log::info!("passphrase create-initial-account: not implemented yet");
    });

    global.on_reapply(move |_passphrase| {
        log::info!("passphrase reapply: not implemented yet");
    });

    global.on_switch_view(move |_index| {
        log::info!("passphrase switch-view: not implemented yet");
    });
}
