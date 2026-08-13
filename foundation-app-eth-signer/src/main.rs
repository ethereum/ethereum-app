// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Ethereum Signer — account management UI ported from the Passport Prime
//! Bitcoin app. Keys are rooted in the per-app seed (`GetAppSeed`); addresses
//! derive as m/44'/60'/0'/0/i via common-eth-signer's signer-signing crate.

mod account_id;
mod callbacks;
mod create_account;
mod enter_passphrase;
mod eth_keys;
mod state;
mod store;
mod theme;
mod verify_address;

use {
    crate::state::AppState,
    slint_keyos_platform::{app_ui2, slint::ComponentHandle, spawn_local, spawn_worker, StoredValue},
    std::sync::Arc,
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

    // TODO(sim): GetAppSeed hangs the simulator — using a fixed dev seed until
    // that's debugged separately. To restore, replace DEV_APP_SEED with:
    //
    //     let app_seed = Security::default().app_seed().expect("app seed unavailable");
    //     ... KeyCache::init(app_seed.as_bytes()) ...
    //
    // GOTCHA when restoring: the first GetAppSeed call must happen on the main
    // thread, before any background worker needs it — the grantOnFirstUse
    // consent prompt is presented against this app's gui connection and is
    // dropped (=> denied, app aborts) when the call comes from a detached
    // worker at launch.
    // const DEV_APP_SEED: [u8; 32] = [0x42; 32];
    let app_seed = Security::default().app_seed().expect("app seed unavailable");

    let state = StoredValue::new(AppState::new(ui.as_weak()));

    // The BIP-39 PBKDF2 expansion and hardened chain to the coin level are too
    // slow for the UI thread; run once on a worker and publish the cache.
    spawn_local(async move {
        let result = spawn_worker(async move {
            //eth_keys::KeyCache::init(&DEV_APP_SEED)
            eth_keys::KeyCache::init(app_seed.as_bytes())
        })
        .await;
        match result {
            Ok(cache) => {
                state.borrow_mut().keys = Some(Arc::new(cache));
                // Refresh so account views pick up the master fingerprint.
                state.borrow().refresh_slint_accounts();
            }
            Err(e) => log::error!("key derivation failed: {e:?}"),
        }
    })
    .detach();

    callbacks::init_callbacks(state);
    create_account::init(state);
    verify_address::init(state);
    enter_passphrase::init(state);

    state.borrow().refresh_slint_accounts();

    ui.run().expect("UI running");
}
