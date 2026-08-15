// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! The Settings global: seed-source switching and UI flags.

use {
    crate::{seed_source::SeedSource, state::AppState, EnterPassphrase, EnterPassphraseState, Settings, SeedSourceKind},
    slint_keyos_platform::{slint::ComponentHandle, StoredValue},
};

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<Settings>();

    // Publish the persisted values.
    {
        let s = state.borrow();
        global.set_seed_source(match s.settings.seed_source() {
            SeedSource::Device => SeedSourceKind::Device,
            SeedSource::UserMnemonic { .. } => SeedSourceKind::UserMnemonic,
        });
        global.set_show_passphrase_warning(s.settings.show_passphrase_warning());
    }

    global.on_switch_to_device(move || {
        {
            let mut s = state.borrow_mut();
            // Forgets the sealed phrase and everything derived from it.
            s.settings.set_seed_source(SeedSource::Device);
            s.store.delete_all();

            let ui = s.ui();
            ui.global::<Settings>().set_seed_source(SeedSourceKind::Device);
            let passphrase = ui.global::<EnterPassphrase>();
            passphrase.set_passphrase("".into());
            passphrase.set_fingerprint("".into());
            passphrase.set_slider_index(0);
            passphrase.set_state(EnterPassphraseState::Idle);
        }
        AppState::rebuild_default_keys(state);
    });

    global.on_set_show_passphrase_warning(move |show| {
        state.borrow_mut().settings.set_show_passphrase_warning(show);
        state.borrow().ui().global::<Settings>().set_show_passphrase_warning(show);
    });
}
