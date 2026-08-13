// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Passphrase flow (Bitcoin-app parity). Only available when the seed source
//! is an imported recovery phrase; the home-menu entry is disabled otherwise.
//!
//! `try` previews the fingerprint of the passphrase wallet, `confirm` switches
//! to it (optionally creating its first account), the Default/Passphrase
//! segmented control switches views using the cached keys.

use {
    crate::{state::AppState, EnterPassphrase, EnterPassphraseState, Navigate},
    slint_keyos_platform::{slint::ComponentHandle, spawn_local, StoredValue},
};

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<EnterPassphrase>();

    global.on_try(move |passphrase| {
        try_passphrase(state, passphrase.into());
    });

    global.on_confirm(move |passphrase| confirm_passphrase(state, passphrase.into()));

    global.on_clear_passphrase(move || AppState::apply_passphrase(state, String::new()));

    global.on_reapply(move |passphrase| AppState::apply_passphrase(state, passphrase.into()));

    global.on_switch_view(move |index| {
        let passphrase: String = {
            if index == 0 {
                String::new()
            } else {
                let app_state = state.borrow();
                let ui = app_state.ui();
                ui.global::<EnterPassphrase>().get_passphrase().into()
            }
        };
        AppState::switch_view_locally(state, passphrase);
    });

    global.on_create_initial_account(move |label| {
        let passphrase: String =
            state.borrow().ui().global::<EnterPassphrase>().get_passphrase().into();
        {
            let s = state.borrow();
            let ui = s.ui();
            ui.global::<EnterPassphrase>().set_state(EnterPassphraseState::Clear);
            ui.global::<Navigate>().invoke_backward();
        }
        spawn_local(async move {
            create_initial_account(state, label.into(), passphrase).await;
        })
        .detach();
    });
}

fn try_passphrase(state: StoredValue<AppState>, passphrase: String) {
    state.borrow().ui().global::<EnterPassphrase>().set_fingerprint_loading(true);
    spawn_local(async move {
        // Derives + caches the passphrase wallet and publishes the
        // fingerprint / no-accounts preview. The view is not switched yet.
        AppState::derive_passphrase_keys(state, passphrase)
            .await
            .inspect_err(|e| log::error!("failed to compute passphrase fingerprint: {e:?}"))
            .ok();
        state.borrow().ui().global::<EnterPassphrase>().set_fingerprint_loading(false);
    })
    .detach();
}

fn confirm_passphrase(state: StoredValue<AppState>, passphrase: String) {
    AppState::apply_passphrase(state, passphrase);
    let app_state = state.borrow();
    let ui = app_state.ui();
    ui.global::<EnterPassphrase>().set_state(EnterPassphraseState::Clear);
    ui.global::<Navigate>().invoke_backward();
}

async fn create_initial_account(state: StoredValue<AppState>, label: String, passphrase: String) {
    let keys = match AppState::derive_passphrase_keys(state, passphrase).await {
        Ok(keys) => keys,
        Err(e) => {
            log::error!("failed to derive passphrase keys: {e:?}");
            return;
        }
    };

    {
        let mut s = state.borrow_mut();
        s.use_passphrase = true;
        let fingerprint = keys.master_fingerprint().to_string();
        s.store
            .create(&label, &fingerprint)
            .inspect_err(|e| log::error!("failed to create initial passphrase account: {e:?}"))
            .ok();
        s.refresh_slint_accounts();
    }
}
