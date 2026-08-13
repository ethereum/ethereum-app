//! Slint GUI backend (feature `slint`).
//!
//! Renders the confirmation view-model into the declarative `ConfirmWindow` and
//! runs the event loop until the user taps Approve or Reject. Running requires a
//! windowing/platform backend (present on the device); on a headless host use
//! [`crate::ConsoleUi`] or [`crate::HeadlessUi`] instead.

use std::cell::Cell;
use std::rc::Rc;

use signer_core::SignerError;

use crate::backends::{render_text, ConfirmationUi, Decision};
use crate::view_model::ConfirmViewModel;

slint::include_modules!();

/// The Slint-backed confirmation UI.
pub struct SlintUi;

impl ConfirmationUi for SlintUi {
    fn confirm(&mut self, vm: &ConfirmViewModel) -> Result<Decision, SignerError> {
        let window = ConfirmWindow::new().map_err(|e| SignerError::Ui(e.to_string()))?;
        window.set_screen_title(vm.title.clone().into());
        window.set_details(render_text(vm).into());

        let decision = Rc::new(Cell::new(Decision::Reject));

        {
            let decision = decision.clone();
            let weak = window.as_weak();
            window.on_approve(move || {
                decision.set(Decision::Approve);
                if let Some(w) = weak.upgrade() {
                    let _ = w.hide();
                }
            });
        }
        {
            let decision = decision.clone();
            let weak = window.as_weak();
            window.on_reject(move || {
                decision.set(Decision::Reject);
                if let Some(w) = weak.upgrade() {
                    let _ = w.hide();
                }
            });
        }

        window.run().map_err(|e| SignerError::Ui(e.to_string()))?;
        Ok(decision.get())
    }
}
