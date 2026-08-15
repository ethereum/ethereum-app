// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Recovery-phrase import flow (my-coin's word-entry logic). The draft lives
//! in Rust — Slint arrays are not reactively tracked on element mutation.
//!
//! Nothing changes until `commit-import` succeeds: it seals the entropy under
//! an app-seed-derived key, persists it as the seed source, deletes all
//! accounts and rebuilds the keys. Backing out of the page keeps everything.

use {
    crate::{
        seed_source, state::AppState, tr, EnterPassphrase, EnterPassphraseState, ImportSeed,
        SeedSourceKind, Settings, TrId,
    },
    slint_keyos_platform::{
        slint::{ComponentHandle, ModelRc, SharedString, VecModel},
        StoredValue,
    },
};

/// Autocomplete chips that fit on one row at 480px.
const MAX_SUGGESTIONS: usize = 3;

pub fn init(state: StoredValue<AppState>) {
    let ui = state.borrow().ui();
    let global = ui.global::<ImportSeed>();

    global.on_begin_import(move |word_count| {
        {
            let mut s = state.borrow_mut();
            s.import_words.clear();
            s.import_word_count = if word_count == 24 { 24 } else { 12 };
        }
        state.borrow().ui().global::<ImportSeed>().set_error("".into());
        publish_draft(state);
    });

    global.on_is_word(|word| seed_source::is_word(&word));

    global.on_suggestions(|prefix| {
        let words: Vec<SharedString> = seed_source::suggestions(&prefix)
            .into_iter()
            .take(MAX_SUGGESTIONS)
            .map(SharedString::from)
            .collect();
        ModelRc::new(VecModel::from(words))
    });

    global.on_push_word(move |word| {
        let word = word.trim().to_lowercase();
        {
            let mut s = state.borrow_mut();
            if word.is_empty() || s.import_words.len() >= s.import_word_count {
                return;
            }
            s.import_words.push(word);
        }
        publish_draft(state);
    });

    global.on_pop_word(move || {
        state.borrow_mut().import_words.pop();
        state.borrow().ui().global::<ImportSeed>().set_error("".into());
        publish_draft(state);
    });

    global.on_commit_import(move || commit_import(state));
}

fn publish_draft(state: StoredValue<AppState>) {
    let s = state.borrow();
    let words: Vec<SharedString> =
        s.import_words.iter().map(|w| SharedString::from(w.as_str())).collect();
    let ui = s.ui();
    let global = ui.global::<ImportSeed>();
    global.set_entered(s.import_words.len() as i32);
    global.set_word_count(s.import_word_count as i32);
    global.set_words(ModelRc::new(VecModel::from(words)));
}

fn commit_import(state: StoredValue<AppState>) -> bool {
    // A phrase can be complete, every word from the wordlist, and still fail —
    // the BIP39 checksum catches a word in the wrong position.
    let entropy = match seed_source::entropy_from_words(&state.borrow().import_words) {
        Ok(entropy) => entropy,
        Err(_) => {
            state
                .borrow()
                .ui()
                .global::<ImportSeed>()
                .set_error(tr::lookup_id(TrId::ImportSeedInvalid).into());
            return false;
        }
    };

    let source = match seed_source::seal_entropy(&entropy, &seed_source::app_seed()) {
        Ok(source) => source,
        Err(e) => {
            log::error!("failed to seal the recovery phrase: {e:?}");
            state.borrow().ui().global::<ImportSeed>().set_error(format!("{e}").into());
            return false;
        }
    };

    {
        let mut s = state.borrow_mut();
        // The new seed source owns no accounts: delete everything.
        s.settings.set_seed_source(source);
        s.store.delete_all();
        s.import_words.clear();

        let ui = s.ui();
        ui.global::<Settings>().set_seed_source(SeedSourceKind::UserMnemonic);
        // Reset any passphrase state left over from the previous source.
        let passphrase = ui.global::<EnterPassphrase>();
        passphrase.set_passphrase("".into());
        passphrase.set_fingerprint("".into());
        passphrase.set_slider_index(0);
        passphrase.set_state(EnterPassphraseState::Idle);
    }

    AppState::rebuild_default_keys(state);
    true
}
