// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Ethereum Signer — account management UI ported from the Passport Prime
//! Bitcoin app. Keys are rooted in the configured seed source (device app
//! seed or an imported recovery phrase); addresses derive as
//! m/44'/60'/j'/0/i via common-eth-signer's signer-signing crate.

mod account_id;
mod callbacks;
mod connect_account;
mod create_account;
mod enter_passphrase;
mod eth_keys;
mod import_seed;
mod seed_source;
mod settings;
mod sign_tx;
mod state;
mod store;
mod theme;
mod verify_address;

use {
    crate::state::AppState,
    slint_keyos_platform::{app_ui2, slint::ComponentHandle, StoredValue},
};

//app_ui2!("Ethereum Signer");
app_ui2!("eth-signer");

security::use_api!();

// Translation tables (`mod tr` + the `init_tr!` macro wiring TR/TR2).
include!(concat!(env!("OUT_DIR"), "/tr.rs"));

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);
    init_tr!(ui);

    // Legacy `Utils` global (qrcode, skia helpers, string utils) — same
    // binding set the in-tree apps use.
    slint_keyos_platform::_internal_init_ui_utils!(Utils, ui);

    // Legacy image loaders. `Images.icon` is re-bound from the ui2 icon set to
    // the vendored per-app icons in resources/images/, and `CompatImages`
    // serves the legacy `common`/`nine-slice` loaders.
    {
        let fs = cx.fs.clone();
        let cache = Default::default();
        ui.global::<Images>().on_icon(move |name, _size| {
            // Legacy widgets bind Icon sources unconditionally, so an unset
            // icon comes through as "" — that's a blank, not a missing asset.
            if name.is_empty() {
                return Default::default();
            }
            slint_keyos_platform::raw_image::load_raw_image(
                &fs,
                &cache,
                format!("images/{name}").into(),
                false,
                false,
            )
        });

        let fs = cx.fs.clone();
        let cache = Default::default();
        let ui_weak = ui.as_weak();
        ui.global::<CompatImages>().on_common(move |name| {
            let is_dark = ui_weak
                .upgrade()
                .map(|ui| ui.global::<CurrentTheme>().get_is_dark())
                .unwrap_or(false);
            slint_keyos_platform::raw_image::load_raw_image(&fs, &cache, name, false, is_dark)
        });

        let fs = cx.fs.clone();
        let cache = Default::default();
        let ui_weak = ui.as_weak();
        ui.global::<CompatImages>().on_nine_slice(move |name| {
            let is_dark = ui_weak
                .upgrade()
                .map(|ui| ui.global::<CurrentTheme>().get_is_dark())
                .unwrap_or(false);
            slint_keyos_platform::raw_image::load_raw_image(&fs, &cache, name, true, is_dark)
        });
    }

    let state = StoredValue::new(AppState::new(ui.as_weak()));

    // Derive the default wallet's keys from the configured seed source
    // (device app seed — see seed_source::app_seed for the temporary dev
    // constant — or the sealed imported phrase). PBKDF2 runs on a worker.
    AppState::rebuild_default_keys(state);

    callbacks::init_callbacks(state);
    connect_account::init(state);
    create_account::init(state);
    verify_address::init(state);
    enter_passphrase::init(state);
    import_seed::init(state);
    settings::init(state);
    sign_tx::init(state);

    state.borrow().refresh_slint_accounts();

    ui.run().expect("UI running");
}
