// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! The Settings global: seed-source selection and UI flags.

use {
    crate::{
        seed_source::SeedSource, state::AppState, EnterPassphrase, EnterPassphraseState, Navigate,
        SeedSourceKind, Settings,
    },
    slint_keyos_platform::{slint::ComponentHandle, StoredValue},
};

/// How the UI names the configured source.
pub fn kind_of(source: Option<&SeedSource>) -> SeedSourceKind {
    match source {
        Some(SeedSource::AppSeed) => SeedSourceKind::AppSeed,
        Some(SeedSource::UserMnemonic { .. }) => SeedSourceKind::UserMnemonic,
        None => SeedSourceKind::Unset,
    }
}

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<Settings>();

    // Publish the persisted values.
    {
        let s = state.borrow();
        global.set_seed_source(kind_of(s.settings.seed_source().as_ref()));
        global.set_show_passphrase_warning(s.settings.show_passphrase_warning());
    }

    global.on_choose_seed_source(move |kind| choose(state, kind));

    global.on_set_show_passphrase_warning(move |show| {
        state.borrow_mut().settings.set_show_passphrase_warning(show);
        state.borrow().ui().global::<Settings>().set_show_passphrase_warning(show);
    });
}

/// Commit a choice from the seed-source page.
///
/// The app seed is committed here and takes effect at once. A recovery phrase
/// cannot be: there is nothing to commit until the user has typed a valid one,
/// so it routes on to the import flow, which persists the source itself once
/// the phrase checks out. Backing out of the import therefore leaves the
/// current wallet untouched.
fn choose(state: StoredValue<AppState>, kind: SeedSourceKind) {
    match kind {
        SeedSourceKind::AppSeed => {}
        SeedSourceKind::UserMnemonic => {
            state.borrow().ui().global::<Navigate>().invoke_import_seed(Default::default());
            return;
        }
        SeedSourceKind::Unset => {
            log::error!("seed source committed with no choice made");
            return;
        }
    }

    {
        let mut s = state.borrow_mut();
        // Accounts belong to the wallet they were created under, so leaving a
        // source drops them — and with an imported phrase, that is also where
        // the sealed copy goes. Answering the first-launch question is not
        // leaving anything, so it keeps whatever is already on disk.
        let replacing = s.settings.seed_source().is_some();
        s.settings.set_seed_source(SeedSource::AppSeed);
        if replacing {
            s.store.delete_all();
        }

        let ui = s.ui();
        ui.global::<Settings>().set_seed_source(SeedSourceKind::AppSeed);
        let passphrase = ui.global::<EnterPassphrase>();
        passphrase.set_passphrase("".into());
        passphrase.set_fingerprint("".into());
        passphrase.set_slider_index(0);
        passphrase.set_state(EnterPassphraseState::Idle);
    }

    AppState::rebuild_default_keys(state);
    state.borrow().ui().global::<Navigate>().invoke_home(Default::default());
}
