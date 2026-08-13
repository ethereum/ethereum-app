// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Shared application state and the Slint account-list synchronisation.

use {
    crate::{
        account_id::AccountId, eth_keys::KeyCache, store::AccountStore, AccountView, AppWindow,
        Callbacks, CardColor, SingleSigView,
    },
    slint_keyos_platform::{
        slint::{self, ComponentHandle, ModelRc, VecModel},
        StoredValue,
    },
    std::{rc::Rc, sync::Arc},
};

pub struct AppState {
    pub ui: slint::Weak<AppWindow>,
    pub store: AccountStore,
    /// Derived key material; `None` until the startup derivation finishes.
    pub keys: Option<Arc<KeyCache>>,
    pub model: Rc<VecModel<AccountView>>,
    pub archive_mode: bool,
}

impl AppState {
    pub fn new(ui: slint::Weak<AppWindow>) -> Self {
        Self {
            ui,
            store: AccountStore::load(),
            keys: None,
            model: Rc::new(VecModel::default()),
            archive_mode: false,
        }
    }

    pub fn ui(&self) -> AppWindow {
        self.ui.unwrap()
    }

    pub fn get_account_view_str(&self, account_id: &str) -> Option<(AccountId, AccountView)> {
        let account_id = match account_id.parse::<AccountId>() {
            Ok(acct) => acct,
            Err(e) => {
                log::error!("failed to parse account id {account_id} {e:?}");
                return None;
            }
        };
        let account = self.get_account_view(&account_id)?;

        Some((account_id, account))
    }

    pub fn get_account_view(&self, account_id: &AccountId) -> Option<AccountView> {
        let config = self.store.get(account_id)?;
        Some(self.convert_account(account_id, &config))
    }

    pub fn refresh_slint_accounts(&self) {
        self.model.clear();
        let accounts: Vec<AccountView> = self
            .store
            .accounts()
            .filter(|(_id, config)| config.archived == self.archive_mode)
            .map(|(id, config)| self.convert_account(&id, &config))
            .collect();
        self.model.extend(accounts);

        let ui = self.ui();
        let cb = ui.global::<Callbacks>();
        cb.set_accounts(ModelRc::from(self.model.clone()));
    }

    fn convert_account(
        &self,
        account_id: &AccountId,
        config: &crate::store::EthAccountConfig,
    ) -> AccountView {
        let fingerprint =
            self.keys.as_ref().map(|k| k.master_fingerprint().to_string()).unwrap_or_default();

        AccountView {
            id: account_id.to_string().into(),
            name: config.name.clone().into(),
            color: AccountColor::for_account_index(account_id.index).into(),
            archived: config.archived,
            single: SingleSigView {
                account_number: account_id.index as i32,
                fingerprint: fingerprint.into(),
                public_key: "".into(),
            },
        }
    }

    pub fn update_account_config<F>(state: StoredValue<AppState>, id: AccountId, f: F)
    where
        F: FnOnce(&mut crate::store::EthAccountConfig),
    {
        state.borrow_mut().store.update(&id, f);
        state.borrow().refresh_slint_accounts();
    }

    pub fn set_archive_mode(state: StoredValue<AppState>, mode: bool) {
        state.borrow_mut().archive_mode = mode;
        state.borrow().refresh_slint_accounts();
    }

    pub fn delete_account(state: StoredValue<AppState>, id: AccountId) {
        state.borrow_mut().store.delete(&id);
        state.borrow().refresh_slint_accounts();
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum AccountColor {
    DarkGrey,
    Purple,
    Green,
    Pine,
    #[default]
    LightCopper,
    DarkCopper,
    Teal,
    Blue,
}

impl AccountColor {
    // Match Core/Envoy's acct_num % 6 cycling (same as the Bitcoin app).
    pub fn for_account_index(index: u32) -> Self {
        match index % 6 {
            0 => AccountColor::DarkCopper,
            1 => AccountColor::Blue,
            2 => AccountColor::Pine,
            3 => AccountColor::LightCopper,
            4 => AccountColor::Teal,
            _ => AccountColor::Green,
        }
    }
}

impl From<AccountColor> for CardColor {
    fn from(color: AccountColor) -> Self {
        match color {
            AccountColor::DarkGrey => CardColor::DarkGrey,
            AccountColor::Purple => CardColor::Purple,
            AccountColor::Green => CardColor::Green,
            AccountColor::Pine => CardColor::Pine,
            AccountColor::LightCopper => CardColor::LightCopper,
            AccountColor::DarkCopper => CardColor::DarkCopper,
            AccountColor::Teal => CardColor::Teal,
            AccountColor::Blue => CardColor::Blue,
        }
    }
}
