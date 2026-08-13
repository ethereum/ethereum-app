//! The pure view-model: a `SignRequest` projected into display-ready strings.
//!
//! This module has no I/O and no UI dependency, so it is fully unit-testable
//! without a window. Every backend (headless, console, Slint) renders the same
//! [`ConfirmViewModel`].

use alloy_primitives::{Address, B256, U256};
use signer_core::{DecodedTx, MessageKind, SignRequest, TxDisplay};

/// What the screen shows for one confirmation, fully pre-formatted.
#[derive(Debug, Clone)]
pub struct ConfirmViewModel {
    pub title: String,
    pub origin: Option<String>,
    pub chain_id: u64,
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
    pub chain_id: String,
    /// Advanced tab: raw calldata hex (only when calldata is present).
    pub calldata_hex: Option<String>,
    /// Advanced tab: ERC-8213 Calldata Digest (only when calldata is present).
    pub calldata_digest: Option<String>,
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
        MessageKind::Transaction(tx) => ConfirmBody::Transaction(tx_view(tx)),
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

fn tx_view(tx: &DecodedTx) -> TxView {
    let tx_type = match tx {
        DecodedTx::Legacy(_) => "Legacy",
        DecodedTx::Eip1559(_) => "EIP-1559",
        DecodedTx::Eip7702(_) => "EIP-7702",
    }
    .to_string();

    let TxDisplay {
        to,
        value,
        max_fee,
        chain_id,
        calldata,
        calldata_digest,
    } = tx.display();

    TxView {
        tx_type,
        to: to
            .map(|a| a.to_string())
            .unwrap_or_else(|| "(contract creation)".to_string()),
        value: format_ether(value),
        max_fee: format_ether(max_fee),
        chain_id: chain_id
            .map(|c| c.to_string())
            .unwrap_or_else(|| "(unspecified)".to_string()),
        calldata_hex: (!calldata.is_empty()).then(|| format!("0x{}", hex::encode(&calldata))),
        calldata_digest: calldata_digest.map(hex0x),
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
