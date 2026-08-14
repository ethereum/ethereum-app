use alloy_consensus::{TxEip1559, TxEip7702, TxLegacy};
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, B256, U256};
use core::fmt;

use crate::digest::calldata_digest;
use crate::error::SignerError;
use crate::frame_tx::FrameTx;

/// A single BIP-32 derivation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildNumber {
    /// The child index *without* the hardening bit (0..=0x7fff_ffff).
    pub index: u32,
    pub hardened: bool,
}

impl ChildNumber {
    /// The raw 32-bit value, with the hardening bit set when hardened.
    pub fn to_u32(self) -> u32 {
        if self.hardened {
            self.index | 0x8000_0000
        } else {
            self.index
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.index, if self.hardened { "'" } else { "" })
    }
}

/// A BIP-32 derivation path (`crypto-keypath` in ERC-4527).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivationPath {
    pub components: Vec<ChildNumber>,
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for c in &self.components {
            write!(f, "/{c}")?;
        }
        Ok(())
    }
}

/// An EIP-191 `personal_sign` message (ERC-4527 data-type 3 / `eth-raw-bytes`).
#[derive(Debug, Clone)]
pub struct PersonalMessage {
    /// The raw message bytes exactly as received in `sign-data`.
    pub raw: Vec<u8>,
    /// The message decoded as UTF-8 for display, if it is valid UTF-8.
    pub as_utf8: Option<String>,
}

impl PersonalMessage {
    pub fn new(raw: Vec<u8>) -> Self {
        let as_utf8 = core::str::from_utf8(&raw).ok().map(str::to_owned);
        Self { raw, as_utf8 }
    }
}

/// EIP-712 typed data (ERC-4527 data-type 2) plus the ERC-8213 display digests.
#[derive(Debug, Clone)]
pub struct TypedData712 {
    /// The original UTF-8 JSON string, kept for readable scrolling display.
    pub json: String,
    /// The parsed typed data, used for hashing.
    pub typed_data: TypedData,
    /// ERC-8213 "EIP-712 Digest": the value actually signed.
    pub eip712_digest: B256,
    /// ERC-8213 "Domain Hash": `hashStruct(eip712Domain)`.
    pub domain_hash: B256,
    /// ERC-8213 "Message Hash": `hashStruct(message)`.
    pub message_hash: B256,
}

/// A decoded Ethereum transaction. Named to avoid clashing with
/// [`alloy_primitives::TxKind`] (the create/call destination type).
#[derive(Debug, Clone)]
pub enum DecodedTx {
    /// Legacy transaction (ERC-4527 data-type 1).
    Legacy(TxLegacy),
    /// EIP-1559 typed transaction (EIP-2718 type `0x02`).
    Eip1559(TxEip1559),
    /// EIP-7702 typed transaction (EIP-2718 type `0x04`).
    Eip7702(TxEip7702),
    /// EIP-8141 frame transaction (EIP-2718 type `0x06`).
    Frame(FrameTx),
}

impl DecodedTx {
    /// Project the transaction into the common fields shown to the user.
    pub fn display(&self) -> TxDisplay {
        match self {
            DecodedTx::Legacy(t) => TxDisplay {
                to: t.to.to().copied(),
                value: t.value,
                max_fee: fee(t.gas_price, t.gas_limit),
                chain_id: t.chain_id,
                calldata: t.input.to_vec(),
                calldata_digest: digest_of(&t.input),
            },
            DecodedTx::Eip1559(t) => TxDisplay {
                to: t.to.to().copied(),
                value: t.value,
                max_fee: fee(t.max_fee_per_gas, t.gas_limit),
                chain_id: Some(t.chain_id),
                calldata: t.input.to_vec(),
                calldata_digest: digest_of(&t.input),
            },
            DecodedTx::Eip7702(t) => TxDisplay {
                to: Some(t.to),
                value: t.value,
                max_fee: fee(t.max_fee_per_gas, t.gas_limit),
                chain_id: Some(t.chain_id),
                calldata: t.input.to_vec(),
                calldata_digest: digest_of(&t.input),
            },
            // A frame transaction has no single target or calldata; these
            // aggregates feed the summary line only, and the display layer
            // renders the full per-frame breakdown separately.
            DecodedTx::Frame(t) => TxDisplay {
                to: None,
                value: t.total_value(),
                max_fee: t.max_fee_upper_bound(),
                chain_id: Some(t.chain_id),
                calldata: Vec::new(),
                calldata_digest: None,
            },
        }
    }
}

fn fee(per_gas: u128, gas_limit: u64) -> U256 {
    U256::from(per_gas).saturating_mul(U256::from(gas_limit))
}

fn digest_of(calldata: &[u8]) -> Option<B256> {
    if calldata.is_empty() {
        None
    } else {
        Some(calldata_digest(calldata))
    }
}

/// Common transaction fields projected for display (per the brief + ERC-8213).
#[derive(Debug, Clone)]
pub struct TxDisplay {
    pub to: Option<Address>,
    pub value: U256,
    /// Maximum fee = gas_price * gas_limit (legacy) or max_fee_per_gas * gas_limit.
    pub max_fee: U256,
    pub chain_id: Option<u64>,
    pub calldata: Vec<u8>,
    /// ERC-8213 Calldata Digest, present only when calldata is non-empty.
    pub calldata_digest: Option<B256>,
}

/// The kind of data being signed, decoded from `data-type` + `sign-data`.
#[derive(Debug, Clone)]
pub enum MessageKind {
    Eip191(PersonalMessage),
    Eip712(TypedData712),
    Transaction(DecodedTx),
}

/// A fully decoded ERC-4527 `eth-sign-request`.
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// `request-id` (UUID), echoed back in the `eth-signature`.
    pub request_id: Option<[u8; 16]>,
    /// `chain-id` (ERC-4527 key 4, optional). `None` when the wallet omitted
    /// it. This is envelope metadata only: the signature commits to the chain
    /// id inside the transaction body, and [`SignRequest::validate_chain_binding`]
    /// rejects any disagreement between the two.
    pub chain_id: Option<u64>,
    /// `derivation-path` of the signing key.
    pub derivation_path: DerivationPath,
    /// Optional `address` for verifying the derived key.
    pub address: Option<Address>,
    /// Optional `origin` (e.g. wallet name).
    pub origin: Option<String>,
    /// The raw `sign-data` bytes, kept verbatim for audit / re-hashing.
    pub raw_sign_data: Vec<u8>,
    /// The decoded payload.
    pub message: MessageKind,
}

impl SignRequest {
    /// Fail-closed cross-check between the request-level `chain-id` (envelope
    /// metadata a malicious wallet controls independently) and the chain id
    /// embedded in the transaction the signature actually commits to.
    ///
    /// - A legacy transaction without an EIP-155 chain id is refused outright:
    ///   its signature would replay on every EVM chain
    ///   ([`SignerError::PreEip155Unsupported`]).
    /// - When the request carries an explicit `chain-id`, it must equal the
    ///   transaction's ([`SignerError::ChainIdMismatch`]); an absent request
    ///   `chain-id` (optional per ERC-4527) skips only this equality check.
    /// - Non-transaction payloads (EIP-191 / EIP-712) have no chain id in the
    ///   signed bytes, so there is nothing to cross-check.
    ///
    /// Called at the decode boundary and again immediately before signing, so
    /// a fault on one check does not authorize a mismatched signature.
    pub fn validate_chain_binding(&self) -> Result<(), SignerError> {
        let MessageKind::Transaction(tx) = &self.message else {
            return Ok(());
        };
        let tx_chain_id = match tx {
            DecodedTx::Legacy(t) => t.chain_id.ok_or(SignerError::PreEip155Unsupported)?,
            DecodedTx::Eip1559(t) => t.chain_id,
            DecodedTx::Eip7702(t) => t.chain_id,
            DecodedTx::Frame(t) => t.chain_id,
        };
        if let Some(request) = self.chain_id {
            if request != tx_chain_id {
                return Err(SignerError::ChainIdMismatch {
                    request,
                    transaction: tx_chain_id,
                });
            }
        }
        Ok(())
    }
}
