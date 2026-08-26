// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Shared application state, wallet (seed + passphrase) management and the
//! Slint account-list synchronisation.

use {
    crate::{
        account_id::AccountId,
        eth_keys::KeyCache,
        seed_source,
        store::{AccountStore, SettingsStore},
        AccountView, AppWindow, Callbacks, CardColor, EnterPassphrase, SingleSigView,
    },
    slint_keyos_platform::{
        slint::{self, ComponentHandle, ModelRc, VecModel},
        spawn_local, spawn_worker, StoredValue,
    },
    std::{rc::Rc, sync::Arc},
    zeroize::Zeroizing,
};

pub struct AppState {
    pub ui: slint::Weak<AppWindow>,
    pub store: AccountStore,
    pub settings: SettingsStore,

    /// Keys of the default wallet (configured seed source, empty passphrase).
    /// `None` until the startup derivation finishes.
    pub default_keys: Option<Arc<KeyCache>>,
    /// Keys of the passphrase wallet, cached with the passphrase they belong
    /// to so Default/Passphrase view switches never re-run the PBKDF2.
    pub passphrase_keys: Option<(String, Arc<KeyCache>)>,
    /// Which wallet the account list currently shows.
    pub use_passphrase: bool,

    pub model: Rc<VecModel<AccountView>>,
    pub archive_mode: bool,

    /// Draft of the recovery-phrase import flow.
    pub import_words: Vec<String>,
    pub import_word_count: usize,

    /// A decoded eth-sign-request awaiting the user's slide-to-sign.
    pub pending_sign_tx: Option<crate::sign_tx::PendingSignTx>,
}

impl AppState {
    pub fn new(ui: slint::Weak<AppWindow>) -> Self {
        Self {
            ui,
            store: AccountStore::load(),
            settings: SettingsStore::load(),
            default_keys: None,
            passphrase_keys: None,
            use_passphrase: false,
            model: Rc::new(VecModel::default()),
            archive_mode: false,
            import_words: Vec::new(),
            import_word_count: 12,
            pending_sign_tx: None,
        }
    }

    pub fn ui(&self) -> AppWindow {
        self.ui.unwrap()
    }

    /// Keys of the wallet the UI currently shows.
    pub fn keys(&self) -> Option<Arc<KeyCache>> {
        if self.use_passphrase {
            self.passphrase_keys.as_ref().map(|(_, k)| k.clone())
        } else {
            self.default_keys.clone()
        }
    }

    /// Master fingerprint of the active wallet (empty until keys are ready).
    pub fn current_fingerprint(&self) -> String {
        self.keys().map(|k| k.master_fingerprint().to_string()).unwrap_or_default()
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
        Some(convert_account(account_id, &config))
    }

    pub fn refresh_slint_accounts(&self) {
        self.model.clear();
        let fingerprint = self.current_fingerprint();
        let accounts: Vec<AccountView> = self
            .store
            .accounts_for(&fingerprint)
            .filter(|(_id, config)| config.archived == self.archive_mode)
            .map(|(id, config)| convert_account(&id, &config))
            .collect();
        self.model.extend(accounts);

        let ui = self.ui();
        let cb = ui.global::<Callbacks>();
        cb.set_accounts(ModelRc::from(self.model.clone()));
        // Scanning a sign request is pointless (and blocked) until the active
        // wallet owns at least one account, archived or not.
        cb.set_can_scan(!fingerprint.is_empty() && self.store.count_for(&fingerprint) > 0);
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

    /// Rebuild the default wallet's keys from the configured seed source,
    /// dropping any passphrase wallet. Runs the PBKDF2 on a worker; refreshes
    /// the account list when done.
    pub fn rebuild_default_keys(state: StoredValue<AppState>) {
        // No source chosen yet: ask, and touch nothing until the answer is in.
        // Two different wallets sit behind that choice, so there is no sensible
        // one to derive in the meantime.
        let Some(source) = state.borrow().settings.seed_source() else {
            let s = state.borrow();
            s.refresh_slint_accounts();
            s.ui().global::<crate::Navigate>().invoke_seed_source(Default::default());
            return;
        };

        let entropy = {
            match seed_source::resolve_entropy(&source, &seed_source::app_seed()) {
                Ok(entropy) => entropy,
                Err(e) => {
                    log::error!("failed to resolve the seed source: {e:?}");
                    return;
                }
            }
        };
        {
            let mut s = state.borrow_mut();
            s.default_keys = None;
            s.passphrase_keys = None;
            s.use_passphrase = false;
        }
        spawn_local(async move {
            let result = spawn_worker({
                let entropy: Zeroizing<Vec<u8>> = entropy;
                async move { KeyCache::init(&entropy, "") }
            })
            .await;
            match result {
                Ok(cache) => {
                    let fingerprint = cache.master_fingerprint().to_string();
                    let mut s = state.borrow_mut();
                    s.default_keys = Some(Arc::new(cache));
                    // Stamp legacy pre-fingerprint account entries.
                    s.store.backfill_fingerprint(&fingerprint);
                    s.refresh_slint_accounts();
                }
                Err(e) => log::error!("key derivation failed: {e:?}"),
            }
        })
        .detach();
    }

    /// Apply (or clear, with an empty string) a passphrase: switch the active
    /// wallet to the passphrase wallet, deriving its keys if they are not the
    /// cached ones.
    pub fn apply_passphrase(state: StoredValue<AppState>, passphrase: String) {
        if passphrase.is_empty() {
            let mut s = state.borrow_mut();
            s.use_passphrase = false;
            s.passphrase_keys = None;
            s.refresh_slint_accounts();
            return;
        }

        // Cached from `try` (fingerprint preview) or an earlier apply?
        let cached = {
            let s = state.borrow();
            s.passphrase_keys.as_ref().filter(|(p, _)| *p == passphrase).map(|(_, k)| k.clone())
        };
        if cached.is_some() {
            let mut s = state.borrow_mut();
            s.use_passphrase = true;
            s.refresh_slint_accounts();
            return;
        }

        spawn_local(async move {
            match Self::derive_passphrase_keys(state, passphrase.clone()).await {
                Ok(_) => {
                    let mut s = state.borrow_mut();
                    s.use_passphrase = true;
                    s.refresh_slint_accounts();
                }
                Err(e) => log::error!("failed to apply passphrase: {e:?}"),
            }
        })
        .detach();
    }

    /// Switch between Default and Passphrase views using cached keys only.
    pub fn switch_view_locally(state: StoredValue<AppState>, passphrase: String) {
        let mut s = state.borrow_mut();
        if passphrase.is_empty() {
            s.use_passphrase = false;
        } else if s.passphrase_keys.as_ref().is_some_and(|(p, _)| *p == passphrase) {
            s.use_passphrase = true;
        } else {
            drop(s);
            AppState::apply_passphrase(state, passphrase);
            return;
        }
        s.refresh_slint_accounts();
    }

    /// Derive and cache the passphrase wallet's keys (worker thread), also
    /// publishing the fingerprint/no-accounts preview to the UI.
    pub async fn derive_passphrase_keys(
        state: StoredValue<AppState>,
        passphrase: String,
    ) -> anyhow::Result<Arc<KeyCache>> {
        let entropy = {
            let s = state.borrow();
            let source = s
                .settings
                .seed_source()
                .ok_or_else(|| anyhow::anyhow!("no seed source chosen"))?;
            seed_source::resolve_entropy(&source, &seed_source::app_seed())?
        };
        let cache = spawn_worker({
            let passphrase = passphrase.clone();
            async move { KeyCache::init(&entropy, &passphrase) }
        })
        .await?;
        let cache = Arc::new(cache);

        let fingerprint = cache.master_fingerprint().to_string();
        let mut s = state.borrow_mut();
        s.passphrase_keys = Some((passphrase, cache.clone()));
        let no_accounts = s.store.count_for(&fingerprint) == 0;
        let ui = s.ui();
        let global = ui.global::<EnterPassphrase>();
        global.set_fingerprint(fingerprint.to_uppercase().into());
        global.set_no_accounts(no_accounts);
        Ok(cache)
    }
}

fn convert_account(account_id: &AccountId, config: &crate::store::EthAccountConfig) -> AccountView {
    AccountView {
        id: account_id.to_string().into(),
        name: config.name.clone().into(),
        color: AccountColor::for_account_index(account_id.index).into(),
        archived: config.archived,
        single: SingleSigView {
            account_number: account_id.index as i32,
            fingerprint: config.fingerprint.to_uppercase().into(),
            public_key: "".into(),
        },
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
