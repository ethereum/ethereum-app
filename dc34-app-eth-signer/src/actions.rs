use std::cell::RefCell;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;

#[cfg(feature = "hosted-baosec")]
use bao1x_emu::trng::Trng;
#[cfg(feature = "board-baosec")]
use bao1x_hal_service::trng::Trng;
use num_traits::*;
use ux_api::widgets::TextEntryPayload;
use xous::{Message, send_message};

use crate::api::{ActionOp, MainOp};
use crate::storage::{MAX_SEED_NAME_LEN, SeedStore};

const GENERATE_ENTRY: &str = "[ Generate new seed ]";
const IMPORT_ENTRY: &str = "[ Import seed ]";
const SHOW_WORDS_PROMPT: &str = "Record these words in order";

/// Spawn the actions thread: it owns its own server plus all blocking modal calls, so the
/// main loop stays free to service redraws and menu keys while a modal flow is running.
pub fn spawn_actions(
    main_conn: xous::CID,
    sid: xous::SID,
    selected_seed: Arc<Mutex<Option<String>>>,
    action_active: Arc<AtomicBool>,
) {
    let _ = thread::spawn(move || {
        let mut manager = ActionManager::new(main_conn, selected_seed, action_active);
        loop {
            let msg = xous::receive_message(sid).unwrap();
            let opcode: Option<ActionOp> = FromPrimitive::from_usize(msg.body.id());
            log::debug!("action op: {:?}", opcode);
            match opcode {
                Some(ActionOp::Startup) => {
                    manager.activate();
                    manager.startup_flow();
                    manager.deactivate();
                }
                Some(ActionOp::SelectSeed) => {
                    manager.activate();
                    manager.select_seed_flow();
                    manager.deactivate();
                }
                Some(ActionOp::CreateSeed) => {
                    manager.activate();
                    manager.generate_seed_flow();
                    manager.deactivate();
                }
                Some(ActionOp::ImportSeed) => {
                    manager.activate();
                    manager.import_seed_flow();
                    manager.deactivate();
                }
                Some(ActionOp::MenuClose) => {
                    manager.activate();
                    manager.deactivate();
                }
                Some(ActionOp::Quit) => break,
                None => log::error!("msg could not be decoded {:?}", msg),
            }
        }
        xous::destroy_server(sid).ok();
    });
}

struct ActionManager {
    modals: modals::Modals,
    store: SeedStore,
    trng: RefCell<Trng>,
    main_conn: xous::CID,
    selected_seed: Arc<Mutex<Option<String>>>,
    action_active: Arc<AtomicBool>,
}

impl ActionManager {
    fn new(
        main_conn: xous::CID,
        selected_seed: Arc<Mutex<Option<String>>>,
        action_active: Arc<AtomicBool>,
    ) -> Self {
        let xns = xous_names::XousNames::new().unwrap();
        ActionManager {
            modals: modals::Modals::new(&xns).unwrap(),
            store: SeedStore::new(),
            trng: RefCell::new(Trng::new(&xns).unwrap()),
            main_conn,
            selected_seed,
            action_active,
        }
    }

    fn activate(&self) {
        self.action_active.store(true, Ordering::SeqCst);
    }

    fn deactivate(&self) {
        self.action_active.store(false, Ordering::SeqCst);
        send_message(self.main_conn, Message::new_scalar(MainOp::Redraw.to_usize().unwrap(), 0, 0, 0, 0))
            .ok();
    }

    /// Radio-button helper; None means the user aborted the modal.
    fn radio(&self, prompt: &str, items: &[&str]) -> Option<String> {
        for item in items {
            self.modals.add_list_item(item).ok()?;
        }
        self.modals.get_radiobutton(prompt).ok()
    }

    /// Make `name` the active seed, both in shared state and persistently.
    fn select_and_persist(&self, name: &str) {
        *self.selected_seed.lock().unwrap() = Some(name.to_string());
        if let Err(e) = self.store.save_selected_seed(name) {
            // selection still works for this session; only the persistence failed
            log::error!("couldn't persist seed selection: {:?}", e);
        }
    }

    pub fn startup_flow(&mut self) {
        log::info!("startup: loading persisted selection");
        // restore the last selection silently; the menu can change it at any time
        if let Some(name) = self.store.load_selected_seed() {
            log::info!("restored persisted seed selection '{}'", name);
            *self.selected_seed.lock().unwrap() = Some(name);
            return;
        }
        log::info!("startup: no persisted selection, listing seeds");
        if self.store.list_seeds().is_empty() {
            match self.radio("No seeds found", &["Generate new seed", "Import seed", "Later"]).as_deref() {
                Some("Generate new seed") => self.generate_seed_flow(),
                Some("Import seed") => self.import_seed_flow(),
                _ => {}
            }
        } else {
            self.select_seed_flow();
        }
    }

    pub fn select_seed_flow(&mut self) {
        for name in self.store.list_seeds() {
            self.modals.add_list_item(&name).ok();
        }
        self.modals.add_list_item(GENERATE_ENTRY).ok();
        self.modals.add_list_item(IMPORT_ENTRY).ok();
        match self.modals.get_radiobutton("Select seed") {
            Ok(sel) if sel == GENERATE_ENTRY => self.generate_seed_flow(),
            Ok(sel) if sel == IMPORT_ENTRY => self.import_seed_flow(),
            Ok(sel) => {
                self.select_and_persist(&sel);
                self.modals.show_notification(&format!("Selected seed:\n{}", sel), None).ok();
            }
            Err(_) => {} // user aborted; no state change
        }
    }

    pub fn generate_seed_flow(&mut self) {
        let n_bytes = match self.radio("Seed length", &["12 words", "24 words"]).as_deref() {
            Some("12 words") => 16,
            Some("24 words") => 32,
            _ => return,
        };
        let mut entropy = vec![0u8; n_bytes];
        self.trng.borrow_mut().fill_bytes_via_next(&mut entropy);

        self.modals.show_bip39(Some(SHOW_WORDS_PROMPT), &entropy).ok();

        if self.confirm_backup(&entropy) {
            self.name_and_store(&mut entropy, "created");
        } else {
            self.modals.show_notification("Seed creation aborted.\nNothing was saved.", None).ok();
            zeroize(&mut entropy);
        }
    }

    pub fn import_seed_flow(&mut self) {
        match self.modals.input_bip39(Some("Enter seed phrase")) {
            Ok(mut entropy) => self.name_and_store(&mut entropy, "imported"),
            Err(_) => {} // user aborted entry
        }
    }

    /// Ask the user to re-enter the phrase they just saw, proving it was backed up.
    fn confirm_backup(&mut self, entropy: &Vec<u8>) -> bool {
        loop {
            match self.modals.input_bip39(Some("Re-enter phrase to confirm backup")) {
                Ok(mut entered) => {
                    let ok = entered == *entropy;
                    zeroize(&mut entered);
                    if ok {
                        return true;
                    }
                }
                Err(_) => {} // aborted entry: fall through to the retry menu
            }
            match self
                .radio("Backup not confirmed", &["Try again", "Show words again", "Abort creation"])
                .as_deref()
            {
                Some("Try again") => {}
                Some("Show words again") => {
                    self.modals.show_bip39(Some(SHOW_WORDS_PROMPT), entropy).ok();
                }
                _ => return false,
            }
        }
    }

    /// Shared tail of the generate/import flows: name the seed, store it, select it.
    /// Zeroes the entropy buffer on every exit path.
    fn name_and_store(&mut self, entropy: &mut Vec<u8>, verb: &str) {
        loop {
            let name = match self.prompt_seed_name() {
                Some(n) => n,
                None => {
                    self.modals.show_notification("Aborted.\nNothing was saved.", None).ok();
                    break;
                }
            };
            let result = if self.store.seed_exists(&name) {
                match self
                    .radio(
                        &format!("'{}' already exists", name),
                        &["Pick another name", "Overwrite existing", "Abort"],
                    )
                    .as_deref()
                {
                    Some("Pick another name") => continue,
                    Some("Overwrite existing") => self.store.replace_seed(&name, entropy),
                    _ => {
                        self.modals.show_notification("Aborted.\nNothing was saved.", None).ok();
                        break;
                    }
                }
            } else {
                self.store.store_seed(&name, entropy)
            };
            match result {
                Ok(()) => {
                    self.select_and_persist(&name);
                    self.modals
                        .show_notification(&format!("Seed '{}' {} and selected", name, verb), None)
                        .ok();
                }
                Err(e) => {
                    self.modals.show_notification(&format!("Error saving seed:\n{:?}", e), None).ok();
                }
            }
            break;
        }
        zeroize(entropy);
    }

    fn prompt_seed_name(&self) -> Option<String> {
        match self.modals.alert_builder("Name this seed:").field(None, Some(seed_name_validator)).build() {
            Ok(text) => Some(text.first().as_str().trim().to_string()),
            Err(_) => None, // user aborted
        }
    }
}

fn seed_name_validator(input: &TextEntryPayload) -> Option<String> {
    let name = input.as_str().trim();
    if name.is_empty() {
        Some(String::from("Name cannot be empty"))
    } else if name.len() > MAX_SEED_NAME_LEN {
        Some(String::from("Name too long"))
    } else {
        None
    }
}

/// Best-effort wipe of secret material before the buffer is freed.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}
