//! The confirmation trait and the non-GUI backends (headless + console).

use std::collections::VecDeque;

use signer_core::SignerError;

use crate::view_model::{ConfirmBody, ConfirmViewModel, FrameTxView};

/// The user's decision on a signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
}

/// Abstraction over "show this request and get an approve/reject decision".
///
/// The orchestration flow is written against this trait, so the exact same code
/// runs interactively (console / Slint) and under automated tests (headless).
pub trait ConfirmationUi {
    fn confirm(&mut self, vm: &ConfirmViewModel) -> Result<Decision, SignerError>;
}

/// A scriptable, window-free backend for automated host tests.
///
/// Records every view-model shown (for inspection) and returns either the next
/// scripted decision or a fixed default.
pub struct HeadlessUi {
    scripted: VecDeque<Decision>,
    default: Decision,
    /// View-models shown so far, in order.
    pub shown: Vec<ConfirmViewModel>,
}

impl HeadlessUi {
    pub fn auto_approve() -> Self {
        Self::new(Decision::Approve)
    }

    pub fn auto_reject() -> Self {
        Self::new(Decision::Reject)
    }

    /// Return the given decisions in order, then fall back to `Reject`.
    pub fn scripted(decisions: impl IntoIterator<Item = Decision>) -> Self {
        Self {
            scripted: decisions.into_iter().collect(),
            default: Decision::Reject,
            shown: Vec::new(),
        }
    }

    fn new(default: Decision) -> Self {
        Self {
            scripted: VecDeque::new(),
            default,
            shown: Vec::new(),
        }
    }
}

impl ConfirmationUi for HeadlessUi {
    fn confirm(&mut self, vm: &ConfirmViewModel) -> Result<Decision, SignerError> {
        self.shown.push(vm.clone());
        Ok(self.scripted.pop_front().unwrap_or(self.default))
    }
}

/// A plain-text terminal backend: prints the request and reads `y`/`n` from
/// stdin. Useful for driving the real flow on a headless host without a GUI.
pub struct ConsoleUi;

impl ConfirmationUi for ConsoleUi {
    fn confirm(&mut self, vm: &ConfirmViewModel) -> Result<Decision, SignerError> {
        use std::io::Write;

        print!("{}", render_text(vm));
        print!("\nApprove this request? [y/N]: ");
        std::io::stdout()
            .flush()
            .map_err(|e| SignerError::Ui(e.to_string()))?;

        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| SignerError::Ui(e.to_string()))?;

        let answer = line.trim().eq_ignore_ascii_case("y");
        Ok(if answer {
            Decision::Approve
        } else {
            Decision::Reject
        })
    }
}

/// Render a view-model as a human-readable text block (used by [`ConsoleUi`] and
/// handy for snapshot tests).
pub fn render_text(vm: &ConfirmViewModel) -> String {
    let mut s = String::new();
    s.push_str(&format!("=== {} ===\n", vm.title));
    if let Some(origin) = &vm.origin {
        s.push_str(&format!("Origin:      {origin}\n"));
    }
    // Request-level chain-id, when the wallet sent one. For transactions the
    // body below prints the authoritative chain id from the signed RLP.
    if let Some(chain_id) = vm.chain_id {
        s.push_str(&format!("Chain ID:    {chain_id}\n"));
    }
    s.push_str(&format!("Signer:      {}\n", vm.signer_address));
    s.push_str(&format!("Path:        {}\n", vm.derivation_path));
    s.push_str("---\n");

    match &vm.body {
        ConfirmBody::Message { text, is_hex } => {
            s.push_str(if *is_hex {
                "Message (hex):\n"
            } else {
                "Message:\n"
            });
            s.push_str(text);
            s.push('\n');
        }
        ConfirmBody::TypedData {
            json_pretty,
            eip712_digest,
            domain_hash,
            message_hash,
        } => {
            s.push_str("Typed data:\n");
            s.push_str(json_pretty);
            s.push_str("\n---\n");
            s.push_str(&format!("EIP-712 Digest: {eip712_digest}\n"));
            s.push_str(&format!("Domain Hash:    {domain_hash}\n"));
            s.push_str(&format!("Message Hash:   {message_hash}\n"));
        }
        ConfirmBody::Transaction(tx) => {
            s.push_str(&format!("Type:        {}\n", tx.tx_type));
            s.push_str(&format!("To:          {}\n", tx.to));
            s.push_str(&format!("Value:       {}\n", tx.value));
            s.push_str(&format!("Max fee:     {}\n", tx.max_fee));
            s.push_str(&format!("Chain ID:    {}\n", tx.chain_id));
            if let Some(hex) = &tx.calldata_hex {
                s.push_str(&format!("Calldata:    {hex}\n"));
            }
            if let Some(digest) = &tx.calldata_digest {
                s.push_str(&format!("Calldata Digest: {digest}\n"));
            }
            if let Some(frame) = &tx.frame {
                s.push_str(&render_frame_details(frame));
            }
        }
    }
    s
}

/// Render an EIP-8141 frame-transaction breakdown as a human-readable text
/// block: every frame and every signature entry, with explicit-digest entries
/// visibly flagged. Shared by [`render_text`] and by device UIs that show the
/// breakdown in a scrollable card — both must present the same facts.
pub fn render_frame_details(f: &FrameTxView) -> String {
    let mut s = String::new();
    s.push_str("--- Frame transaction ---\n");
    s.push_str(&format!("Sender:      {}\n", f.sender));
    s.push_str(&format!("Nonce:       {}\n", f.nonce));
    s.push_str(&format!("Signing as:  {}\n", f.signing_role));
    s.push_str(&format!("Max priority fee: {}\n", f.max_priority_fee_per_gas));
    s.push_str(&format!("Max fee per gas:  {}\n", f.max_fee_per_gas));
    s.push_str(&format!("Max blob fee:     {}\n", f.max_fee_per_blob_gas));
    s.push_str(&format!("Blob hashes: {}\n", f.blob_hash_count));

    s.push_str(&format!("Frames ({}):\n", f.frames.len()));
    for fr in &f.frames {
        let data = match &fr.data_digest {
            Some(digest) => format!("digest {digest} ({} bytes)", fr.data_len),
            None => "(empty)".to_string(),
        };
        s.push_str(&format!(
            "  [{}] {}  target: {}  value: {}  approve: {}  limits: exec {} / state {}  data: {}\n",
            fr.index, fr.mode, fr.target, fr.value, fr.approval_scope, fr.execution_limit,
            fr.state_limit, data,
        ));
        if fr.atomic_batch {
            s.push_str(&format!("      [atomic batch with frame {}]\n", fr.index + 1));
        }
    }

    s.push_str(&format!("Signatures ({}):\n", f.signatures.len()));
    for sig in &f.signatures {
        let signs = if sig.signs_canonical_hash {
            "canonical tx hash (covers all frames)".to_string()
        } else {
            format!(
                "EXPLICIT DIGEST {} -- WARNING: not bound to this transaction's frames",
                sig.explicit_digest.as_deref().unwrap_or("(missing)"),
            )
        };
        let status = match (sig.pending, sig.is_device_slot) {
            (true, true) => "  [to be signed by this device]",
            (false, true) => "  [this device's slot, already filled]",
            (true, false) => "  [pending]",
            (false, false) => "",
        };
        s.push_str(&format!(
            "  [{}] {}  signer: {}  signs: {}{}\n",
            sig.index, sig.scheme, sig.signer, signs, status,
        ));
    }
    s
}
