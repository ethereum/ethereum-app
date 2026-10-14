// SPDX-FileCopyrightText: 2026 Ethereum Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ethereum Signer: Ethereum accounts and offline signing on Passport Prime.
//! Keys are rooted in the configured seed source (device app
//! seed or an imported recovery phrase); addresses derive as
//! m/44'/60'/j'/0/i via common-eth-signer's signer-signing crate.

mod account_id;
mod callbacks;
mod connect_account;
mod create_account;
mod enter_passphrase;
mod eth_keys;
mod eth_ui;
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

    let gui = cx.gui.clone();
    theme::init(
        &ui,
        std::rc::Rc::new(move |color| {
            gui.set_control_center_color(color)
                .inspect_err(|e| log::warn!("control-center colour refused: {e:?}"))
                .ok();
        }),
    );
    init_tr!(ui);

    eth_ui::init(&ui);

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
