// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Account persistence. One JSON file at `fs::Location::AppData` holding the
//! Ethereum account configs. No key material is ever stored — addresses
//! re-derive deterministically from the app seed (account #j owns
//! m/44'/60'/j'/0/i).

use {
    crate::{account_id::AccountId, fs_permissions::FileSystemPermissions, tr, TrId},
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
        self.data.accounts.iter().find(|a| a.index == id.index).cloned()
    }

    /// All accounts, ordered by index.
    pub fn accounts(&self) -> impl Iterator<Item = (AccountId, EthAccountConfig)> + '_ {
        let mut accounts = self.data.accounts.clone();
        accounts.sort_by_key(|a| a.index);
        accounts.into_iter().map(|config| (AccountId { index: config.index }, config))
    }

    /// Lowest unused account index (deleting an account frees its index).
    fn next_index(&self) -> u32 {
        (0..).find(|i| !self.data.accounts.iter().any(|a| a.index == *i)).unwrap_or(0)
    }

    pub fn create(&mut self, label: &str) -> anyhow::Result<AccountId> {
        if let Some(msg) = self.validate_label(label) {
            anyhow::bail!("invalid label: {msg}");
        }
        let index = self.next_index();
        self.data.guard().accounts.push(EthAccountConfig {
            index,
            name: label.trim().to_string(),
            archived: false,
        });
        Ok(AccountId { index })
    }

    pub fn update<F: FnOnce(&mut EthAccountConfig)>(&mut self, id: &AccountId, f: F) {
        let mut guard = self.data.guard();
        if let Some(config) = guard.accounts.iter_mut().find(|a| a.index == id.index) {
            f(config);
        }
    }

    pub fn delete(&mut self, id: &AccountId) {
        self.data.guard().accounts.retain(|a| a.index != id.index);
    }

    /// None when valid; a user-facing message otherwise.
    pub fn validate_label(&self, label: &str) -> Option<String> {
        if self.data.accounts.iter().any(|a| a.name == label) {
            return Some(tr::lookup_id(TrId::CommonCreateAccountsanitizedRepeatedLabel).to_string());
        }

        if label.trim().is_empty() {
            return Some(tr::lookup_id(TrId::CommonCreateAccountsanitizedEmptyLabel).to_string());
        }

        None
    }
}
