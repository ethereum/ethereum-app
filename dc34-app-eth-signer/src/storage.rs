use std::io::{Read, Write};

pub const SEED_DICT: &str = "eth.signer.seeds";
/// Kept separate from SEED_DICT so config entries never show up in the seed listing
pub const CONFIG_DICT: &str = "eth.signer.config";
const SELECTED_SEED_KEY: &str = "selected_seed";
/// PDDB rejects key names of KEY_NAME_LEN (95) bytes or more
pub const MAX_SEED_NAME_LEN: usize = 94;

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
        // PDDB keys don't truncate on rewrite; delete-then-recreate is the overwrite idiom
        self.pddb.delete_key(SEED_DICT, name, None)?;
        self.store_seed(name, entropy)
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
        // the key may not exist yet; the delete only serves the no-truncate-on-rewrite idiom
        self.pddb.delete_key(CONFIG_DICT, SELECTED_SEED_KEY, None).ok();
        let mut key = self.pddb.get(
            CONFIG_DICT,
            SELECTED_SEED_KEY,
            None,
            true,
            true,
            Some(MAX_SEED_NAME_LEN),
            None::<fn()>,
        )?;
        key.write_all(name.as_bytes())?;
        self.pddb.sync()
    }

    #[allow(dead_code)] // consumed by the upcoming signing milestone
    pub fn read_seed(&self, name: &str) -> Option<Vec<u8>> {
        let mut key = self.pddb.get(SEED_DICT, name, None, false, false, None, None::<fn()>).ok()?;
        let mut data = Vec::new();
        key.read_to_end(&mut data).ok()?;
        Some(data)
    }
}
