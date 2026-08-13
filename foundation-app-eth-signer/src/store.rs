// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Persistence. `accounts.json` holds the account configs (scoped by the
//! owning wallet's fingerprint, like the Bitcoin app), `settings.json` the
//! seed source and UI flags. No key material is ever stored — addresses
//! re-derive deterministically (account #j owns m/44'/60'/j'/0/i).

use {
    crate::{
        account_id::AccountId, fs_permissions::FileSystemPermissions, seed_source::SeedSource, tr,
        TrId,
    },
    file_backed::JsonBacked,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EthAccountConfig {
    /// BIP-44 account index (the j in m/44'/60'/j'/0/i).
    pub index: u32,
    pub name: String,
    #[serde(default)]
    pub archived: bool,
    /// Master fingerprint (hex) of the owning wallet (seed + optional
    /// passphrase). Empty on legacy entries; backfilled at startup.
    #[serde(default)]
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredAccounts {
    #[serde(default)]
    pub accounts: Vec<EthAccountConfig>,
}

pub struct AccountStore {
    data: JsonBacked<StoredAccounts, FileSystemPermissions>,
}

impl AccountStore {
    pub fn load() -> Self {
        let (data, restored): (JsonBacked<StoredAccounts, FileSystemPermissions>, bool) =
            JsonBacked::new("accounts.json", fs::Location::AppData);
        log::info!("account store restored={restored}, accounts={}", data.accounts.len());
        Self { data }
    }

    pub fn get(&self, id: &AccountId) -> Option<EthAccountConfig> {
        self.data
            .accounts
            .iter()
            .find(|a| a.index == id.index && a.fingerprint == id.fingerprint)
            .cloned()
    }

    /// Accounts owned by `fingerprint`, ordered by index.
    pub fn accounts_for(
        &self,
        fingerprint: &str,
    ) -> impl Iterator<Item = (AccountId, EthAccountConfig)> + '_ {
        let mut accounts: Vec<EthAccountConfig> =
            self.data.accounts.iter().filter(|a| a.fingerprint == fingerprint).cloned().collect();
        accounts.sort_by_key(|a| a.index);
        accounts
            .into_iter()
            .map(|config| (AccountId { fingerprint: config.fingerprint.clone(), index: config.index }, config))
    }

    pub fn count_for(&self, fingerprint: &str) -> usize {
        self.data.accounts.iter().filter(|a| a.fingerprint == fingerprint).count()
    }

    /// Lowest unused account index under `fingerprint` (deletion frees it).
    fn next_index(&self, fingerprint: &str) -> u32 {
        (0..)
            .find(|i| {
                !self.data.accounts.iter().any(|a| a.fingerprint == fingerprint && a.index == *i)
            })
            .unwrap_or(0)
    }

    pub fn create(&mut self, label: &str, fingerprint: &str) -> anyhow::Result<AccountId> {
        if fingerprint.is_empty() {
            anyhow::bail!("keys not initialized yet");
        }
        if let Some(msg) = self.validate_label(label, fingerprint) {
            anyhow::bail!("invalid label: {msg}");
        }
        let index = self.next_index(fingerprint);
        self.data.guard().accounts.push(EthAccountConfig {
            index,
            name: label.trim().to_string(),
            archived: false,
            fingerprint: fingerprint.to_string(),
        });
        Ok(AccountId { fingerprint: fingerprint.to_string(), index })
    }

    pub fn update<F: FnOnce(&mut EthAccountConfig)>(&mut self, id: &AccountId, f: F) {
        let mut guard = self.data.guard();
        if let Some(config) =
            guard.accounts.iter_mut().find(|a| a.index == id.index && a.fingerprint == id.fingerprint)
        {
            f(config);
        }
    }

    pub fn delete(&mut self, id: &AccountId) {
        self.data.guard().accounts.retain(|a| !(a.index == id.index && a.fingerprint == id.fingerprint));
    }

    /// Remove every account (any wallet) — used when the seed source changes.
    pub fn delete_all(&mut self) {
        self.data.guard().accounts.clear();
    }

    /// Stamp legacy entries (written before fingerprint scoping) with the
    /// default wallet's fingerprint.
    pub fn backfill_fingerprint(&mut self, fingerprint: &str) {
        if self.data.accounts.iter().any(|a| a.fingerprint.is_empty()) {
            let mut guard = self.data.guard();
            for account in guard.accounts.iter_mut().filter(|a| a.fingerprint.is_empty()) {
                account.fingerprint = fingerprint.to_string();
            }
        }
    }

    /// None when valid; a user-facing message otherwise. Labels are unique
    /// within the owning wallet.
    pub fn validate_label(&self, label: &str, fingerprint: &str) -> Option<String> {
        if self.data.accounts.iter().any(|a| a.fingerprint == fingerprint && a.name == label) {
            return Some(tr::lookup_id(TrId::CommonCreateAccountsanitizedRepeatedLabel).to_string());
        }

        if label.trim().is_empty() {
            return Some(tr::lookup_id(TrId::CommonCreateAccountsanitizedEmptyLabel).to_string());
        }

        None
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub seed_source: SeedSource,
    #[serde(default = "default_true")]
    pub show_passphrase_warning: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self { seed_source: SeedSource::default(), show_passphrase_warning: true }
    }
}

pub struct SettingsStore {
    data: JsonBacked<AppSettings, FileSystemPermissions>,
}

impl SettingsStore {
    pub fn load() -> Self {
        let (data, _restored): (JsonBacked<AppSettings, FileSystemPermissions>, bool) =
            JsonBacked::new("settings.json", fs::Location::AppData);
        Self { data }
    }

    pub fn seed_source(&self) -> SeedSource {
        self.data.seed_source.clone()
    }

    pub fn set_seed_source(&mut self, source: SeedSource) {
        self.data.guard().seed_source = source;
    }

    pub fn show_passphrase_warning(&self) -> bool {
        self.data.show_passphrase_warning
    }

    pub fn set_show_passphrase_warning(&mut self, show: bool) {
        self.data.guard().show_passphrase_warning = show;
    }
}
