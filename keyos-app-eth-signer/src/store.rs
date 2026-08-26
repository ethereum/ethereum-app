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

    /// Whether the wallet owns an account with this BIP-44 index, active or
    /// archived.
    pub fn has_account_index(&self, fingerprint: &str, index: u32) -> bool {
        self.data.accounts.iter().any(|a| a.fingerprint == fingerprint && a.index == index)
    }

    /// Lowest unused account index under `fingerprint` (deletion frees it).
    pub fn next_index(&self, fingerprint: &str) -> u32 {
        (0..)
            .find(|i| {
                !self.data.accounts.iter().any(|a| a.fingerprint == fingerprint && a.index == *i)
            })
            .unwrap_or(0)
    }

    /// None when the index is usable; a user-facing warning otherwise.
    pub fn validate_index(&self, fingerprint: &str, index: u32) -> Option<String> {
        if index >= 0x8000_0000 {
            return Some(format!("Index {index} exceeds maximum BIP32 hardened index (2147483647)"));
        }
        self.data
            .accounts
            .iter()
            .find(|a| a.fingerprint == fingerprint && a.index == index)
            .map(|a| {
                if a.archived {
                    tr::lookup_id(TrId::CommonCreateAccountIndexArchived).to_string()
                } else {
                    tr::lookup_id(TrId::CommonCreateAccountIndexUsed).to_string()
                }
            })
    }

    /// Create an account at `index`, or at the first unused index when None.
    pub fn create(
        &mut self,
        label: &str,
        fingerprint: &str,
        index: Option<u32>,
    ) -> anyhow::Result<AccountId> {
        if fingerprint.is_empty() {
            anyhow::bail!("keys not initialized yet");
        }
        if let Some(msg) = self.validate_label(label, fingerprint) {
            anyhow::bail!("invalid label: {msg}");
        }
        let index = index.unwrap_or_else(|| self.next_index(fingerprint));
        if let Some(msg) = self.validate_index(fingerprint, index) {
            anyhow::bail!("invalid index: {msg}");
        }
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
    /// `None` until the user has chosen. Two different wallets sit behind this
    /// field, so an absent or unreadable value sends them to the chooser rather
    /// than picking one.
    #[serde(default, deserialize_with = "lenient_seed_source")]
    pub seed_source: Option<SeedSource>,
    #[serde(default = "default_true")]
    pub show_passphrase_warning: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self { seed_source: None, show_passphrase_warning: true }
    }
}

/// Read `seed_source` without letting a value this build does not recognise
/// take the rest of the settings down with it.
///
/// A source written by a build that offers more of them than this one reads as
/// unchosen, and the user is asked, rather than the whole settings file falling
/// back to defaults and taking their other preferences with it.
fn lenient_seed_source<'de, D>(deserializer: D) -> Result<Option<SeedSource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(raw.and_then(|value| match serde_json::from_value(value) {
        Ok(source) => Some(source),
        Err(e) => {
            log::warn!("unrecognised seed source in settings, asking again: {e}");
            None
        }
    }))
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

    /// `None` when the user has not chosen a source yet.
    pub fn seed_source(&self) -> Option<SeedSource> {
        self.data.seed_source.clone()
    }

    pub fn set_seed_source(&mut self, source: SeedSource) {
        self.data.guard().seed_source = Some(source);
    }

    pub fn show_passphrase_warning(&self) -> bool {
        self.data.show_passphrase_warning
    }

    pub fn set_show_passphrase_warning(&mut self, show: bool) {
        self.data.guard().show_passphrase_warning = show;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(json: &str) -> AppSettings {
        serde_json::from_str(json).expect("settings always parse")
    }

    /// Both sources round-trip by name, because the name on disk is the only
    /// thing standing between a user and a different wallet.
    #[test]
    fn each_source_round_trips() {
        for source in [SeedSource::AppSeed, SeedSource::UserMnemonic { sealed_hex: "abcd".into() }] {
            let stored =
                AppSettings { seed_source: Some(source.clone()), show_passphrase_warning: true };
            let json = serde_json::to_string(&stored).unwrap();
            assert_eq!(settings(&json).seed_source, Some(source));
        }
    }

    /// A fresh install has made no choice, which is what routes to the chooser.
    #[test]
    fn absent_means_unchosen() {
        assert_eq!(settings("{}").seed_source, None);
        assert!(settings("{}").show_passphrase_warning);
    }

    /// Before the source became a choice it was written as `Device`, and it
    /// meant this same app seed. Existing installs must keep their wallet and
    /// never be asked to pick.
    #[test]
    fn the_legacy_name_is_the_app_seed() {
        let legacy = settings(r#"{"seed_source":{"kind":"Device"},"show_passphrase_warning":false}"#);
        assert_eq!(legacy.seed_source, Some(SeedSource::AppSeed));
        assert!(!legacy.show_passphrase_warning);
    }

    /// A source this build does not know reads as unchosen, and must not take
    /// the rest of the settings down with it.
    #[test]
    fn an_unknown_source_asks_again() {
        let future = settings(r#"{"seed_source":{"kind":"SomethingElse"},"show_passphrase_warning":false}"#);
        assert_eq!(future.seed_source, None);
        assert!(!future.show_passphrase_warning);
    }

    /// A stored phrase has to survive the upgrade: the sealed blob is the only
    /// copy on the device, so losing it loses the wallet.
    #[test]
    fn a_stored_phrase_survives_the_upgrade() {
        let stored = settings(
            r#"{"seed_source":{"kind":"UserMnemonic","sealed_hex":"0badc0de"},"show_passphrase_warning":true}"#,
        );
        assert_eq!(
            stored.seed_source,
            Some(SeedSource::UserMnemonic { sealed_hex: "0badc0de".into() })
        );
    }
}
