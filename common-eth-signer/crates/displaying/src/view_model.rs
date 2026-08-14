//! The pure view-model: a `SignRequest` projected into display-ready strings.
//!
//! This module has no I/O and no UI dependency, so it is fully unit-testable
//! without a window. Every backend (headless, console, Slint) renders the same
//! [`ConfirmViewModel`].

use alloy_primitives::{Address, B256, U256};
use signer_core::frame_tx::{Frame, FrameTx, SignatureEntry, SignatureScheme};
use signer_core::{calldata_digest, DecodedTx, MessageKind, SignRequest, TxDisplay};

/// What the screen shows for one confirmation, fully pre-formatted.
#[derive(Debug, Clone)]
pub struct ConfirmViewModel {
    pub title: String,
    pub origin: Option<String>,
    /// The request-level `chain-id` (envelope metadata; absent when the wallet
    /// omitted it). For transactions the authoritative value is
    /// [`TxView::chain_id`], taken from the RLP body that is actually signed;
    /// decoding guarantees the two agree whenever this one is present.
    pub chain_id: Option<u64>,
    pub derivation_path: String,
    /// The derived signer address (EIP-55 checksummed).
    pub signer_address: String,
    pub body: ConfirmBody,
}

#[derive(Debug, Clone)]
pub enum ConfirmBody {
    /// EIP-191 personal_sign message.
    Message { text: String, is_hex: bool },
    /// EIP-712 typed data with the ERC-8213 digests.
    TypedData {
        json_pretty: String,
        eip712_digest: String,
        domain_hash: String,
        message_hash: String,
    },
    /// A transaction summary.
    Transaction(TxView),
}

#[derive(Debug, Clone)]
pub struct TxView {
    pub tx_type: String,
    pub to: String,
    pub value: String,
    pub max_fee: String,
    /// The chain id from the RLP transaction body — the value the signature
    /// commits to. This, not the request-level `chain-id`, is what sign pages
    /// must render.
    pub chain_id: String,
    /// Advanced tab: raw calldata hex (only when calldata is present).
    pub calldata_hex: Option<String>,
    /// Advanced tab: ERC-8213 Calldata Digest (only when calldata is present).
    pub calldata_digest: Option<String>,
    /// EIP-8141 frame-transaction breakdown; `None` for every other tx type.
    /// When present, the sign page must render every frame and every
    /// signature entry (WYSIWYS — the canonical hash commits to all of them).
    /// Boxed to keep the view-model enum small.
    pub frame: Option<Box<FrameTxView>>,
}

/// The full breakdown of an EIP-8141 frame transaction.
#[derive(Debug, Clone)]
pub struct FrameTxView {
    /// `tx.sender` (EIP-55 checksummed).
    pub sender: String,
    pub nonce: String,
    /// Which role the device key plays: `"sender (0x…)"`, or
    /// `"0x… — NOT the sender (0x…)"` for sponsor/payer flows.
    pub signing_role: String,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub max_fee_per_blob_gas: String,
    pub blob_hash_count: usize,
    pub frames: Vec<FrameView>,
    pub signatures: Vec<SignatureEntryView>,
}

/// One frame, fully spelled out.
#[derive(Debug, Clone)]
pub struct FrameView {
    pub index: usize,
    /// `DEFAULT` / `VERIFY` / `SENDER`.
    pub mode: String,
    /// The resolved target: `frame.target`, or `"sender (0x…)"`.
    pub target: String,
    pub value: String,
    /// Approval scope spelled out: none / payment / execution /
    /// execution+payment.
    pub approval_scope: String,
    /// Atomic-batch flag: this frame is batched with the next one.
    pub atomic_batch: bool,
    pub execution_limit: String,
    pub state_limit: String,
    /// Frame data length in bytes (0 when empty).
    pub data_len: usize,
    /// ERC-8213 Calldata Digest of the frame data; `None` when empty.
    pub data_digest: Option<String>,
}

/// One signature entry, with explicit-digest entries visibly flagged.
#[derive(Debug, Clone)]
pub struct SignatureEntryView {
    pub index: usize,
    /// `ARBITRARY` / `SECP256K1` / `P256`.
    pub scheme: String,
    /// The resolved signer (`sig.signer` or `tx.sender`), or a label for
    /// `ARBITRARY` entries which have none.
    pub signer: String,
    /// `true`: signs the canonical transaction hash (empty `msg`), which
    /// commits to every frame. `false`: signs an explicit digest — an
    /// authorization NOT bound to this transaction's frames; must be shown
    /// with a warning.
    pub signs_canonical_hash: bool,
    /// The explicit digest, when `signs_canonical_hash` is false.
    pub explicit_digest: Option<String>,
    /// Signature bytes are still empty (a slot to be filled after signing).
    pub pending: bool,
    /// This is the slot the device's own signature will fill.
    pub is_device_slot: bool,
}

/// Build the view-model for a decoded request and its derived signer address.
pub fn build_view_model(req: &SignRequest, signer: Address) -> ConfirmViewModel {
    let body = match &req.message {
        MessageKind::Eip191(m) => match &m.as_utf8 {
            Some(text) => ConfirmBody::Message {
                text: text.clone(),
                is_hex: false,
            },
            None => ConfirmBody::Message {
                text: format!("0x{}", hex::encode(&m.raw)),
                is_hex: true,
            },
        },
        MessageKind::Eip712(td) => ConfirmBody::TypedData {
            json_pretty: pretty_json(&td.json),
            eip712_digest: hex0x(td.eip712_digest),
            domain_hash: hex0x(td.domain_hash),
            message_hash: hex0x(td.message_hash),
        },
        MessageKind::Transaction(tx) => ConfirmBody::Transaction(tx_view(tx, signer)),
    };

    let title = match &body {
        ConfirmBody::Message { .. } => "Sign Message",
        ConfirmBody::TypedData { .. } => "Sign Typed Data",
        ConfirmBody::Transaction(_) => "Sign Transaction",
    }
    .to_string();

    ConfirmViewModel {
        title,
        origin: req.origin.clone(),
        chain_id: req.chain_id,
        derivation_path: req.derivation_path.to_string(),
        signer_address: signer.to_string(),
        body,
    }
}

fn tx_view(tx: &DecodedTx, signer: Address) -> TxView {
    let tx_type = match tx {
        DecodedTx::Legacy(_) => "Legacy",
        DecodedTx::Eip1559(_) => "EIP-1559",
        DecodedTx::Eip7702(_) => "EIP-7702",
        DecodedTx::Frame(_) => "EIP-8141 Frame",
    }
    .to_string();

    let frame = match tx {
        DecodedTx::Frame(t) => Some(Box::new(frame_tx_view(t, signer))),
        _ => None,
    };

    let TxDisplay {
        to,
        value,
        max_fee,
        chain_id,
        calldata,
        calldata_digest,
    } = tx.display();

    let to = match (&to, &frame) {
        (Some(a), _) => a.to_string(),
        (None, Some(f)) => format!("(frame transaction: {} frames)", f.frames.len()),
        (None, None) => "(contract creation)".to_string(),
    };
    // For frame transactions the aggregate fee is an upper bound (state gas
    // may be priced below max_fee_per_gas); say so on the summary line.
    let max_fee = if frame.is_some() {
        format!("{} (upper bound)", format_ether(max_fee))
    } else {
        format_ether(max_fee)
    };

    TxView {
        tx_type,
        to,
        value: format_ether(value),
        max_fee,
        chain_id: chain_id
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(unspecified)".to_string()),
        calldata_hex: (!calldata.is_empty()).then(|| format!("0x{}", hex::encode(&calldata))),
        calldata_digest: calldata_digest.map(hex0x),
        frame,
    }
}

/// Project a frame transaction into its full display breakdown. `signer` is
/// the device's derived address, used to name the signing role and mark the
/// device's signature slot.
fn frame_tx_view(tx: &FrameTx, signer: Address) -> FrameTxView {
    let signing_role = if signer == tx.sender {
        format!("sender ({})", tx.sender)
    } else {
        format!("{signer} — NOT the sender ({})", tx.sender)
    };

    FrameTxView {
        sender: tx.sender.to_string(),
        nonce: tx.nonce.to_string(),
        signing_role,
        max_priority_fee_per_gas: format!("{} wei/gas", tx.fees.max_priority_fee_per_gas),
        max_fee_per_gas: format!("{} wei/gas", tx.fees.max_fee_per_gas),
        max_fee_per_blob_gas: format!("{} wei/gas", tx.fees.max_fee_per_blob_gas),
        blob_hash_count: tx.blob_versioned_hashes.len(),
        frames: tx
            .frames
            .iter()
            .enumerate()
            .map(|(index, f)| frame_view(index, f, tx.sender))
            .collect(),
        signatures: tx
            .signatures
            .iter()
            .enumerate()
            .map(|(index, e)| signature_entry_view(index, e, tx.sender, signer))
            .collect(),
    }
}

fn frame_view(index: usize, f: &Frame, sender: Address) -> FrameView {
    let approval_scope = match f.approval_scope() {
        0x0 => "none",
        0x1 => "payment",
        0x2 => "execution",
        0x3 => "execution+payment",
        // Unreachable: the scope mask is two bits.
        _ => "(invalid)",
    }
    .to_string();

    FrameView {
        index,
        mode: f.mode.name().to_string(),
        target: match f.target {
            Some(t) => t.to_string(),
            None => format!("sender ({sender})"),
        },
        value: format_ether(f.value),
        approval_scope,
        atomic_batch: f.is_atomic_batch(),
        execution_limit: f.limits.execution.to_string(),
        state_limit: f.limits.state.to_string(),
        data_len: f.data.len(),
        data_digest: (!f.data.is_empty()).then(|| hex0x(calldata_digest(&f.data))),
    }
}

fn signature_entry_view(
    index: usize,
    e: &SignatureEntry,
    sender: Address,
    device: Address,
) -> SignatureEntryView {
    let resolved = e.resolved_signer(sender);
    let signer = match resolved {
        None => "(none — arbitrary witness)".to_string(),
        Some(a) if a == sender => format!("sender ({a})"),
        Some(a) => a.to_string(),
    };
    SignatureEntryView {
        index,
        scheme: e.scheme.name().to_string(),
        signer,
        signs_canonical_hash: e.signs_canonical_hash(),
        explicit_digest: e.msg.map(hex0x),
        pending: e.signature.is_empty(),
        is_device_slot: e.scheme == SignatureScheme::Secp256k1
            && e.signs_canonical_hash()
            && resolved == Some(device),
    }
}

fn hex0x(h: B256) -> String {
    h.to_string()
}

/// Format wei as a decimal ETH string (18 decimals, trailing zeros trimmed).
fn format_ether(wei: U256) -> String {
    let divisor = U256::from(10u64).pow(U256::from(18u64));
    let whole = wei / divisor;
    let frac = wei % divisor;
    if frac.is_zero() {
        return format!("{whole} ETH");
    }
    let frac_padded = format!("{:0>18}", frac.to_string());
    let trimmed = frac_padded.trim_end_matches('0');
    format!("{whole}.{trimmed} ETH")
}

fn pretty_json(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or_else(|_| json.to_string())
}
