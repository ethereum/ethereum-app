use std::io::{Read, Write};

pub const SEED_DICT: &str = "eth.signer.seeds";
/// Kept separate from SEED_DICT so config entries never show up in the seed listing
pub const CONFIG_DICT: &str = "eth.signer.config";
const SELECTED_SEED_KEY: &str = "selected_seed";
/// BIP-44 accounts: key = seed name, value = one "index:name" line per account
pub const ACCOUNTS_DICT: &str = "eth.signer.accounts";
/// PDDB rejects key names of KEY_NAME_LEN (95) bytes or more
pub const MAX_SEED_NAME_LEN: usize = 94;
/// Hardened BIP-32 child indices span [0, 2^31)
pub const MAX_ACCOUNT_INDEX: u32 = 0x7fff_ffff;
pub const MAX_ACCOUNT_NAME_LEN: usize = 60;

/// A BIP-44 account under the selected seed: m/44'/60'/index'/0/address_index
#[derive(Clone, Debug)]
pub struct Account {
    pub index: u32,
    pub name: String,
}

impl Account {
    pub fn path(&self) -> String {
        format!("m/44'/60'/{}'", self.index)
    }

    /// Radio-list label; unique per seed because the index is unique
    pub fn display(&self) -> String {
        format!("#{} {}", self.index, self.name)
    }
}

/// One key per named seed under SEED_DICT; the value is the raw BIP-39 entropy
/// (16/20/24/28/32 bytes), which is exactly what `modals.input_bip39()` returns and
/// what the signing milestone's `key_from_entropy()` consumes.
pub struct SeedStore {
    pddb: pddb::Pddb,
}

impl SeedStore {
    pub fn new() -> Self {
        SeedStore { pddb: pddb::Pddb::new() }
    }

    pub fn list_seeds(&self) -> Vec<String> {
        // the dict doesn't exist until the first seed is stored; treat that as "no seeds"
        match self.pddb.list_keys(SEED_DICT, None) {
            Ok(mut keys) => {
                keys.sort();
                keys
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn seed_exists(&self, name: &str) -> bool {
        self.pddb.get(SEED_DICT, name, None, false, false, None, None::<fn()>).is_ok()
    }

    pub fn store_seed(&self, name: &str, entropy: &[u8]) -> Result<(), std::io::Error> {
        let mut key = self.pddb.get(SEED_DICT, name, None, true, true, Some(entropy.len()), None::<fn()>)?;
        key.write_all(entropy)?;
        self.pddb.sync()
    }

    pub fn replace_seed(&self, name: &str, entropy: &[u8]) -> Result<(), std::io::Error> {
        // the new entropy is a different wallet, so accounts attached to this name
        // are stale — drop them along with the old seed
        self.pddb.delete_key(ACCOUNTS_DICT, name, None).ok();
        // PDDB keys don't truncate on rewrite; delete-then-recreate is the overwrite idiom
        self.pddb.delete_key(SEED_DICT, name, None)?;
        self.store_seed(name, entropy)
    }

    fn read_value(&self, dict: &str, key: &str) -> Option<Vec<u8>> {
        let mut record = self.pddb.get(dict, key, None, false, false, None, None::<fn()>).ok()?;
        let mut data = Vec::new();
        record.read_to_end(&mut data).ok()?;
        Some(data)
    }

    fn write_value(&self, dict: &str, key: &str, value: &[u8]) -> Result<(), std::io::Error> {
        // the key may not exist yet; the delete only serves the no-truncate-on-rewrite idiom
        self.pddb.delete_key(dict, key, None).ok();
        let mut record =
            self.pddb.get(dict, key, None, true, true, Some(value.len().max(32)), None::<fn()>)?;
        record.write_all(value)?;
        self.pddb.sync()
    }

    pub fn list_accounts(&self, seed: &str) -> Vec<Account> {
        let Some(data) = self.read_value(ACCOUNTS_DICT, seed) else {
            return Vec::new();
        };
        let mut accounts: Vec<Account> = String::from_utf8_lossy(&data)
            .lines()
            .filter_map(|line| {
                let (index, name) = line.split_once(':')?;
                Some(Account { index: index.parse().ok()?, name: name.to_string() })
            })
            .collect();
        accounts.sort_by_key(|a| a.index);
        accounts
    }

    fn write_accounts(&self, seed: &str, accounts: &[Account]) -> Result<(), std::io::Error> {
        let mut ser = String::new();
        for a in accounts {
            ser.push_str(&format!("{}:{}\n", a.index, a.name));
        }
        self.write_value(ACCOUNTS_DICT, seed, ser.as_bytes())
    }

    /// Lowest index not yet in use; `accounts` must be sorted by index (list_accounts sorts)
    pub fn first_free_index(accounts: &[Account]) -> u32 {
        let mut candidate = 0u32;
        for a in accounts {
            if a.index == candidate {
                candidate += 1;
            } else if a.index > candidate {
                break;
            }
        }
        candidate
    }

    pub fn add_account(&self, seed: &str, account: Account) -> Result<(), std::io::Error> {
        let mut accounts = self.list_accounts(seed);
        if accounts.iter().any(|a| a.index == account.index) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "account index already in use",
            ));
        }
        accounts.push(account);
        accounts.sort_by_key(|a| a.index);
        self.write_accounts(seed, &accounts)
    }

    pub fn delete_account(&self, seed: &str, index: u32) -> Result<(), std::io::Error> {
        let mut accounts = self.list_accounts(seed);
        accounts.retain(|a| a.index != index);
        if accounts.is_empty() {
            self.pddb.delete_key(ACCOUNTS_DICT, seed, None).ok();
            self.pddb.sync()
        } else {
            self.write_accounts(seed, &accounts)
        }
    }

    /// Returns the persisted selection, or None if nothing was persisted or the named
    /// seed no longer exists.
    pub fn load_selected_seed(&self) -> Option<String> {
        let mut key =
            match self.pddb.get(CONFIG_DICT, SELECTED_SEED_KEY, None, false, false, None, None::<fn()>) {
                Ok(key) => key,
                Err(e) => {
                    log::info!("no persisted selection ({:?})", e.kind());
                    return None;
                }
            };
        let mut name = String::new();
        if let Err(e) = key.read_to_string(&mut name) {
            log::warn!("persisted selection unreadable: {:?}", e);
            return None;
        }
        log::info!("persisted selection read: '{}'", name);
        if !name.is_empty() && self.seed_exists(&name) { Some(name) } else { None }
    }

    pub fn save_selected_seed(&self, name: &str) -> Result<(), std::io::Error> {
        self.write_value(CONFIG_DICT, SELECTED_SEED_KEY, name.as_bytes())
    }

    pub fn read_seed(&self, name: &str) -> Option<Vec<u8>> {
        let mut key = self.pddb.get(SEED_DICT, name, None, false, false, None, None::<fn()>).ok()?;
        let mut data = Vec::new();
        key.read_to_end(&mut data).ok()?;
        Some(data)
    }
}
