//! Confirmation UI for the signer.
//!
//! Rendering is decoupled from logic: [`build_view_model`] is a pure projection
//! of a `SignRequest` into display-ready strings, and every backend implements
//! the [`ConfirmationUi`] trait over that view-model. The default build has no
//! GUI dependency; the Slint declarative UI lives behind the `slint` feature.

mod backends;
mod view_model;

#[cfg(feature = "slint")]
mod slint_backend;

pub use backends::{render_frame_details, render_text, ConfirmationUi, ConsoleUi, Decision, HeadlessUi};
pub use view_model::{
    build_view_model, ConfirmBody, ConfirmViewModel, FrameTxView, FrameView, SignatureEntryView,
    TxView,
};

#[cfg(feature = "slint")]
pub use slint_backend::SlintUi;
