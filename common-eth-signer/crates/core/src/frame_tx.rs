//! EIP-8141 frame transactions (EIP-2718 type `0x06`).
//!
//! alloy has no type for this transaction yet, so the struct, its canonical
//! RLP encoding, the static validity constraints, and the elided signature
//! hash (`compute_sig_hash`) are implemented here from the EIP text.
//!
//! Trust model: the payload arrives from a hostile QR code. Everything here is
//! fail-closed — the decoder (in `signer-decoding`) enforces canonical RLP and
//! full buffer consumption, then calls [`FrameTx::validate`]; the signing path
//! calls it again so a single skipped check cannot authorize a signature.

use alloy_primitives::{address, b256, keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{length_of_length, Encodable, Header, EMPTY_STRING_CODE};
use thiserror::Error;

use crate::error::SignerError;

/// EIP-2718 transaction type of a frame transaction.
pub const FRAME_TX_TYPE: u8 = 0x06;
/// EIP-8141 `MAX_FRAMES`.
pub const MAX_FRAMES: usize = 64;
/// Device policy cap (not in the EIP): the EIP does not bound the signature
/// list statically, but a QR-transported request never legitimately needs
/// more entries than frames. Bounds hostile-input allocation.
pub const MAX_SIGNATURE_ENTRIES: usize = 64;
/// Device policy cap (not in the EIP): protocol blob-per-transaction limits
/// are far below this; bounds hostile-input allocation.
pub const MAX_BLOB_HASHES: usize = 64;

/// EIP-8141 `ATOMIC_BATCH_FLAG` (flags bit 2).
pub const ATOMIC_BATCH_FLAG: u8 = 0x4;
/// EIP-8141 `APPROVE_SCOPE_MASK` (flags bits 0-1).
pub const APPROVE_SCOPE_MASK: u8 = 0x3;
/// `APPROVE` scope bit: payment.
pub const APPROVE_PAYMENT: u8 = 0x1;
/// `APPROVE` scope bit: execution.
pub const APPROVE_EXECUTION: u8 = 0x2;
/// All flag bits with defined meaning; anything else is reserved and invalid.
const KNOWN_FLAGS_MASK: u8 = APPROVE_SCOPE_MASK | ATOMIC_BATCH_FLAG;

/// EIP-4844 `VERSIONED_HASH_VERSION_KZG`.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// EIP-8141 `EXPIRY_VERIFIER` (`address(0x8141)`).
pub const EXPIRY_VERIFIER: Address = address!("0000000000000000000000000000000000008141");
/// EIP-8141 `EXPIRY_DATA_LENGTH`: an expiry frame's data is an 8-byte
/// unsigned big-endian timestamp.
pub const EXPIRY_DATA_LENGTH: usize = 8;

/// EIP-8141 `FRAME_TX_INTRINSIC_COST` (used only for the fee upper bound).
pub const FRAME_TX_INTRINSIC_COST: u64 = 12_000;
/// EIP-8141 `FRAME_TX_PER_FRAME_COST` (used only for the fee upper bound).
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;
/// EIP-4844 `GAS_PER_BLOB` (used only for the fee upper bound).
pub const GAS_PER_BLOB: u64 = 131_072;

/// secp256k1 group order `n` (EIP-8141 `SECP256K1N`).
const SECP256K1N: B256 = b256!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
/// P-256 group order `n` (EIP-8141 `SECP256R1N`).
const SECP256R1N: B256 = b256!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/// Everything that makes a frame transaction structurally or statically
/// invalid (the EIP's Constraints section, plus device policy caps).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameTxError {
    #[error("RLP: {0}")]
    Rlp(alloy_rlp::Error),

    #[error("trailing bytes in {0}")]
    TrailingBytes(&'static str),

    #[error("chain id does not fit 64 bits")]
    ChainIdTooLarge,

    #[error("sender must be 20 bytes, got {0}")]
    InvalidSenderLength(usize),

    #[error("frame list is empty")]
    NoFrames,

    #[error("more than {MAX_FRAMES} frames")]
    TooManyFrames,

    #[error("more than {MAX_SIGNATURE_ENTRIES} signature entries")]
    TooManySignatures,

    #[error("more than {MAX_BLOB_HASHES} blob versioned hashes")]
    TooManyBlobHashes,

    #[error("frame {frame}: invalid mode {mode}")]
    InvalidMode { frame: usize, mode: u8 },

    #[error("frame {frame}: invalid flags {flags:#04x} (reserved bits set)")]
    InvalidFlags { frame: usize, flags: u8 },

    #[error("frame {frame}: atomic-batch flag on a VERIFY frame")]
    AtomicBatchOnVerify { frame: usize },

    #[error("frame {frame}: atomic-batch flag on the last frame")]
    AtomicBatchOnLastFrame { frame: usize },

    #[error("frame {frame}: atomic batch followed by a VERIFY frame")]
    AtomicBatchIntoVerify { frame: usize },

    #[error("frame {frame}: target must be empty or 20 bytes, got {len}")]
    InvalidTargetLength { frame: usize, len: usize },

    #[error("frame {frame}: non-zero value on a non-SENDER frame")]
    ValueOnNonSenderFrame { frame: usize },

    #[error("frame {frame}: APPROVE_EXECUTION flag with a target other than the sender")]
    ApproveExecutionForeignTarget { frame: usize },

    #[error("total frame gas overflows 64 bits")]
    GasLimitOverflow,

    #[error("frame {frame}: invalid expiry verifier frame (requires flags = 0, value = 0, state limit = 0, 8-byte data)")]
    InvalidExpiryFrame { frame: usize },

    #[error("more than one expiry verifier frame")]
    MultipleExpiryFrames,

    #[error("blob hash {index}: not a 32-byte version-0x01 versioned hash")]
    InvalidBlobHash { index: usize },

    #[error("max_fee_per_blob_gas must be 0 when there are no blobs")]
    BlobFeeWithoutBlobs,

    #[error("signature {index}: unknown scheme {scheme}")]
    UnknownSignatureScheme { index: usize, scheme: u8 },

    #[error("signature {index}: signer must be empty or 20 bytes, got {len}")]
    InvalidSignerLength { index: usize, len: usize },

    #[error("signature {index}: ARBITRARY entries must have an empty signer")]
    ArbitrarySignerNotEmpty { index: usize },

    #[error("signature {index}: msg must be empty or 32 bytes, got {len}")]
    InvalidMsgLength { index: usize, len: usize },

    #[error("signature {index}: the explicit all-zero digest is invalid")]
    ZeroExplicitDigest { index: usize },

    #[error("signature {index}: invalid signature length {len} for the scheme")]
    InvalidSignatureLength { index: usize, len: usize },

    #[error("signature {index}: non-canonical signature (v/r/s bounds)")]
    NonCanonicalSignature { index: usize },

    #[error("signature {index}: P256 public key does not hash to the resolved signer")]
    P256SignerMismatch { index: usize },

    /// An explicit-digest entry with empty signature bytes can never become
    /// valid: filling it later would change the canonical signature hash and
    /// void every canonical-hash signature. It is therefore refused outright
    /// (this is also how a wallet would "ask" the device to sign an explicit
    /// digest, which is open-ended authorization per the EIP's security
    /// considerations).
    #[error("signature {index}: explicit-digest entry with empty signature bytes")]
    EmptyExplicitDigestSignature { index: usize },

    /// The canonical re-encoding of the decoded transaction does not
    /// reproduce the received bytes. Defense in depth: with canonical RLP
    /// enforced during decoding this is unreachable, but it guarantees the
    /// signature hash commits to exactly the wire bytes that were decoded
    /// and displayed.
    #[error("payload re-encoding does not reproduce the received bytes")]
    EncodingRoundTripMismatch,
}

/// Frame execution mode (EIP-8141 `mode`). Values ≥ 3 are rejected at decode,
/// so an invalid mode is unrepresentable past the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameMode {
    Default = 0,
    Verify = 1,
    Sender = 2,
}

impl FrameMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Default),
            1 => Some(Self::Verify),
            2 => Some(Self::Sender),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Default => "DEFAULT",
            Self::Verify => "VERIFY",
            Self::Sender => "SENDER",
        }
    }
}

/// Per-frame gas limits (EIP-8141 `limits = [execution, state]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    pub execution: u64,
    pub state: u64,
}

/// One frame: `[mode, flags, target, limits, value, data]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub mode: FrameMode,
    pub flags: u8,
    /// `None` (empty on the wire) resolves to `tx.sender`.
    pub target: Option<Address>,
    pub limits: FrameLimits,
    pub value: U256,
    pub data: Bytes,
}

impl Frame {
    /// The address the frame actually calls (`frame.target` or `tx.sender`).
    pub fn resolved_target(&self, sender: Address) -> Address {
        self.target.unwrap_or(sender)
    }

    /// The `APPROVE` scope bits (flags bits 0-1).
    pub fn approval_scope(&self) -> u8 {
        self.flags & APPROVE_SCOPE_MASK
    }

    /// Whether the atomic-batch flag (bit 2) is set.
    pub fn is_atomic_batch(&self) -> bool {
        self.flags & ATOMIC_BATCH_FLAG != 0
    }

    fn limits_rlp_payload_length(&self) -> usize {
        self.limits.execution.length() + self.limits.state.length()
    }

    fn rlp_payload_length(&self) -> usize {
        let limits = self.limits_rlp_payload_length();
        (self.mode as u8).length()
            + self.flags.length()
            + opt_addr_rlp_length(&self.target)
            + limits
            + length_of_length(limits)
            + self.value.length()
            + self.data.length()
    }

    fn encode_rlp(&self, out: &mut Vec<u8>) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        (self.mode as u8).encode(out);
        self.flags.encode(out);
        encode_opt_addr(&self.target, out);
        Header { list: true, payload_length: self.limits_rlp_payload_length() }.encode(out);
        self.limits.execution.encode(out);
        self.limits.state.encode(out);
        self.value.encode(out);
        self.data.encode(out);
    }
}

/// Signature verification scheme (EIP-8141 `scheme`). Unknown schemes are
/// rejected at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureScheme {
    Arbitrary = 0,
    Secp256k1 = 1,
    P256 = 2,
}

impl SignatureScheme {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Arbitrary),
            1 => Some(Self::Secp256k1),
            2 => Some(Self::P256),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Arbitrary => "ARBITRARY",
            Self::Secp256k1 => "SECP256K1",
            Self::P256 => "P256",
        }
    }
}

/// One signature entry: `[scheme, signer, msg, signature]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub scheme: SignatureScheme,
    /// `None` (empty on the wire) resolves to `tx.sender` for the
    /// protocol-validated schemes; must be `None` for `ARBITRARY`.
    pub signer: Option<Address>,
    /// `None` (empty on the wire): the entry signs the canonical
    /// `compute_sig_hash(tx)`, and its raw `signature` bytes are elided from
    /// that hash. `Some`: an explicit 32-byte digest — the signature bytes
    /// then DO participate in the hash, and the authorization is not bound to
    /// this transaction's frames (flagged prominently on the display).
    pub msg: Option<B256>,
    /// Raw signature bytes. Empty means a placeholder slot to be filled after
    /// signing — only meaningful together with `msg == None`, whose bytes are
    /// elided from the signature hash.
    pub signature: Bytes,
}

impl SignatureEntry {
    /// The signer address this entry claims (`sig.signer` or `tx.sender`);
    /// `None` for `ARBITRARY`, which has no protocol-resolved signer.
    pub fn resolved_signer(&self, sender: Address) -> Option<Address> {
        match self.scheme {
            SignatureScheme::Arbitrary => None,
            SignatureScheme::Secp256k1 | SignatureScheme::P256 => {
                Some(self.signer.unwrap_or(sender))
            }
        }
    }

    /// Whether this entry signs the canonical transaction signature hash
    /// (empty `msg`) rather than an explicit digest.
    pub fn signs_canonical_hash(&self) -> bool {
        self.msg.is_none()
    }

    fn rlp_payload_length(&self, elide: bool) -> usize {
        let signature_len = if elide && self.msg.is_none() {
            1 // empty byte string
        } else {
            self.signature.length()
        };
        (self.scheme as u8).length()
            + opt_addr_rlp_length(&self.signer)
            + opt_b256_rlp_length(&self.msg)
            + signature_len
    }

    fn encode_rlp(&self, elide: bool, out: &mut Vec<u8>) {
        Header { list: true, payload_length: self.rlp_payload_length(elide) }.encode(out);
        (self.scheme as u8).encode(out);
        encode_opt_addr(&self.signer, out);
        encode_opt_b256(&self.msg, out);
        if elide && self.msg.is_none() {
            out.push(EMPTY_STRING_CODE);
        } else {
            self.signature.encode(out);
        }
    }
}

/// Fee parameters: `[max_priority_fee_per_gas, max_fee_per_gas,
/// max_fee_per_blob_gas]`. The EIP allows the full 256-bit range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameTxFees {
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_fee_per_blob_gas: U256,
}

impl FrameTxFees {
    fn rlp_payload_length(&self) -> usize {
        self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.max_fee_per_blob_gas.length()
    }

    fn encode_rlp(&self, out: &mut Vec<u8>) {
        Header { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.max_fee_per_blob_gas.encode(out);
    }
}

/// The role the device key plays in a frame transaction it is asked to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSignerRole {
    /// The device key is `tx.sender` (the common case).
    Sender,
    /// The device key is a distinct signer (sponsor / payer flows). The
    /// display must say so explicitly.
    CoSigner,
}

/// A decoded EIP-8141 frame transaction:
/// `[chain_id, nonce, sender, frames, signatures, fees, blob_versioned_hashes]`.
///
/// `chain_id` is held as `u64`. The EIP allows the full 256-bit range, but the
/// ERC-4527 envelope, the display layer, and every other transaction type in
/// this workspace (alloy's `ChainId`) treat chain ids as 64-bit; a larger
/// value could neither be cross-checked nor displayed faithfully, so it is
/// rejected at decode (fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub sender: Address,
    pub frames: Vec<Frame>,
    pub signatures: Vec<SignatureEntry>,
    pub fees: FrameTxFees,
    pub blob_versioned_hashes: Vec<B256>,
}

impl FrameTx {
    /// Static validity constraints from the EIP's Constraints and Signature
    /// Validation sections, as checkable offline, plus device policy caps.
    ///
    /// Bounds already made unrepresentable by decoding (mode < 3, field
    /// widths, 20-byte addresses, 32-byte digests) are not re-checked here.
    /// Called at the decode boundary and again in the signing path.
    pub fn validate(&self) -> Result<(), FrameTxError> {
        if self.frames.is_empty() {
            return Err(FrameTxError::NoFrames);
        }
        if self.frames.len() > MAX_FRAMES {
            return Err(FrameTxError::TooManyFrames);
        }
        if self.signatures.len() > MAX_SIGNATURE_ENTRIES {
            return Err(FrameTxError::TooManySignatures);
        }
        if self.blob_versioned_hashes.len() > MAX_BLOB_HASHES {
            return Err(FrameTxError::TooManyBlobHashes);
        }

        for (index, hash) in self.blob_versioned_hashes.iter().enumerate() {
            if hash.0[0] != VERSIONED_HASH_VERSION_KZG {
                return Err(FrameTxError::InvalidBlobHash { index });
            }
        }
        if self.blob_versioned_hashes.is_empty() && !self.fees.max_fee_per_blob_gas.is_zero() {
            return Err(FrameTxError::BlobFeeWithoutBlobs);
        }

        let mut total_frame_gas: u64 = 0;
        let mut expiry_frames = 0usize;
        for (i, frame) in self.frames.iter().enumerate() {
            if frame.flags & !KNOWN_FLAGS_MASK != 0 {
                return Err(FrameTxError::InvalidFlags { frame: i, flags: frame.flags });
            }
            // Expiry verifier frame: a VERIFY frame targeting EXPIRY_VERIFIER.
            // At most one per transaction, with a fixed rigid shape.
            if frame.mode == FrameMode::Verify && frame.target == Some(EXPIRY_VERIFIER) {
                expiry_frames += 1;
                if expiry_frames > 1 {
                    return Err(FrameTxError::MultipleExpiryFrames);
                }
                if frame.flags != 0
                    || !frame.value.is_zero()
                    || frame.limits.state != 0
                    || frame.data.len() != EXPIRY_DATA_LENGTH
                {
                    return Err(FrameTxError::InvalidExpiryFrame { frame: i });
                }
            }
            if frame.is_atomic_batch() {
                if frame.mode == FrameMode::Verify {
                    return Err(FrameTxError::AtomicBatchOnVerify { frame: i });
                }
                match self.frames.get(i + 1) {
                    None => return Err(FrameTxError::AtomicBatchOnLastFrame { frame: i }),
                    Some(next) if next.mode == FrameMode::Verify => {
                        return Err(FrameTxError::AtomicBatchIntoVerify { frame: i });
                    }
                    Some(_) => {}
                }
            }
            if frame.approval_scope() & APPROVE_EXECUTION != 0 {
                if let Some(target) = frame.target {
                    if target != self.sender {
                        return Err(FrameTxError::ApproveExecutionForeignTarget { frame: i });
                    }
                }
            }
            if frame.mode != FrameMode::Sender && !frame.value.is_zero() {
                return Err(FrameTxError::ValueOnNonSenderFrame { frame: i });
            }
            total_frame_gas = frame
                .limits
                .execution
                .checked_add(frame.limits.state)
                .and_then(|g| total_frame_gas.checked_add(g))
                .ok_or(FrameTxError::GasLimitOverflow)?;
        }

        for (index, entry) in self.signatures.iter().enumerate() {
            if let Some(digest) = entry.msg {
                if digest == B256::ZERO {
                    return Err(FrameTxError::ZeroExplicitDigest { index });
                }
            }
            match entry.scheme {
                SignatureScheme::Arbitrary => {
                    if entry.signer.is_some() {
                        return Err(FrameTxError::ArbitrarySignerNotEmpty { index });
                    }
                    // Raw witness bytes are unconstrained by the protocol.
                }
                SignatureScheme::Secp256k1 => {
                    if entry.signature.is_empty() {
                        if entry.msg.is_some() {
                            return Err(FrameTxError::EmptyExplicitDigestSignature { index });
                        }
                    } else {
                        if entry.signature.len() != 65 {
                            return Err(FrameTxError::InvalidSignatureLength {
                                index,
                                len: entry.signature.len(),
                            });
                        }
                        // v (recovery id) must be 0 or 1; r/s canonical low-s.
                        let v = entry.signature.first().copied();
                        let r = entry.signature.get(1..33);
                        let s = entry.signature.get(33..65);
                        let canonical = matches!(v, Some(0 | 1))
                            && canonical_scalar_pair(r, s, &SECP256K1N);
                        if !canonical {
                            return Err(FrameTxError::NonCanonicalSignature { index });
                        }
                    }
                }
                SignatureScheme::P256 => {
                    if entry.signature.is_empty() {
                        if entry.msg.is_some() {
                            return Err(FrameTxError::EmptyExplicitDigestSignature { index });
                        }
                    } else {
                        if entry.signature.len() != 128 {
                            return Err(FrameTxError::InvalidSignatureLength {
                                index,
                                len: entry.signature.len(),
                            });
                        }
                        let r = entry.signature.get(0..32);
                        let s = entry.signature.get(32..64);
                        if !canonical_scalar_pair(r, s, &SECP256R1N) {
                            return Err(FrameTxError::NonCanonicalSignature { index });
                        }
                        // The signer address is derivable offline:
                        // keccak256(qx || qy)[12:] must equal the resolved signer.
                        let q = entry
                            .signature
                            .get(64..128)
                            .ok_or(FrameTxError::InvalidSignatureLength { index, len: 0 })?;
                        let resolved = entry.signer.unwrap_or(self.sender);
                        let h = keccak256(q);
                        if h.as_slice().get(12..) != Some(resolved.as_slice()) {
                            return Err(FrameTxError::P256SignerMismatch { index });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// The EIP-2718 payload: `rlp(tx)` with the raw signature bytes exactly
    /// as they stand (no elision). Prepend `0x06` for the full typed
    /// transaction bytes.
    pub fn encode_payload(&self, out: &mut Vec<u8>) {
        self.encode_rlp(false, out);
    }

    /// The canonical signature hash (EIP-8141 `compute_sig_hash`):
    /// `keccak256(0x06 || rlp(tx))` where every signature entry with empty
    /// `msg` has its raw `signature` bytes replaced by the empty string.
    /// Entries with an explicit `msg` keep their bytes and DO affect the hash.
    pub fn sig_hash(&self) -> B256 {
        let payload = self.rlp_payload_length(true);
        let mut buf = Vec::with_capacity(1 + payload + length_of_length(payload));
        buf.push(FRAME_TX_TYPE);
        self.encode_rlp(true, &mut buf);
        keccak256(&buf)
    }

    /// Fail-closed signing policy for a device holding the key for `device`:
    ///
    /// - There must be at least one `SECP256K1` entry with empty `msg` whose
    ///   resolved signer is `device` — the slot our canonical-hash signature
    ///   fills ([`SignerError::FrameNoSignatureSlot`] otherwise).
    /// - If any unfilled entry resolving to `device` carries an explicit
    ///   digest, the request is asking the device for an open-ended
    ///   authorization and is refused
    ///   ([`SignerError::FrameExplicitDigestRefused`]). This is redundant
    ///   with [`FrameTx::validate`] (which rejects all unfilled
    ///   explicit-digest entries) by design.
    ///
    /// Returns whether the device signs as the sender or as a distinct
    /// co-signer, so the display can say which.
    pub fn signer_role(&self, device: Address) -> Result<FrameSignerRole, SignerError> {
        let mut has_canonical_slot = false;
        let mut has_explicit_ask = false;
        for entry in &self.signatures {
            if entry.scheme != SignatureScheme::Secp256k1 {
                continue;
            }
            if entry.resolved_signer(self.sender) != Some(device) {
                continue;
            }
            match entry.msg {
                None => has_canonical_slot = true,
                Some(_) if entry.signature.is_empty() => has_explicit_ask = true,
                // A filled explicit-digest co-signature: not a request for
                // this device to sign; it is verified cryptographically in
                // the signing path and flagged on the display.
                Some(_) => {}
            }
        }
        if has_explicit_ask {
            return Err(SignerError::FrameExplicitDigestRefused);
        }
        if !has_canonical_slot {
            return Err(SignerError::FrameNoSignatureSlot);
        }
        Ok(if device == self.sender {
            FrameSignerRole::Sender
        } else {
            FrameSignerRole::CoSigner
        })
    }

    /// Total wei leaving the sender across all frames (saturating; display
    /// only — per-frame values are shown individually).
    pub fn total_value(&self) -> U256 {
        self.frames
            .iter()
            .fold(U256::ZERO, |acc, f| acc.saturating_add(f.value))
    }

    /// Upper bound on the total fee: `max_fee_per_gas × (intrinsic + per-frame
    /// + Σ(execution + state))` plus the blob fee bound. Saturating; display
    /// only. Never understates (state gas may be priced below `max_fee_per_gas`).
    pub fn max_fee_upper_bound(&self) -> U256 {
        let frame_gas = self.frames.iter().fold(0u64, |acc, f| {
            acc.saturating_add(f.limits.execution)
                .saturating_add(f.limits.state)
        });
        let total_gas = frame_gas
            .saturating_add(FRAME_TX_INTRINSIC_COST)
            .saturating_add(FRAME_TX_PER_FRAME_COST.saturating_mul(self.frames.len() as u64));
        let exec_fee = U256::from(total_gas).saturating_mul(self.fees.max_fee_per_gas);
        let blob_gas = U256::from(GAS_PER_BLOB)
            .saturating_mul(U256::from(self.blob_versioned_hashes.len() as u64));
        exec_fee.saturating_add(blob_gas.saturating_mul(self.fees.max_fee_per_blob_gas))
    }

    fn rlp_payload_length(&self, elide: bool) -> usize {
        let frames: usize = self
            .frames
            .iter()
            .map(|f| {
                let p = f.rlp_payload_length();
                p + length_of_length(p)
            })
            .sum();
        let signatures: usize = self
            .signatures
            .iter()
            .map(|e| {
                let p = e.rlp_payload_length(elide);
                p + length_of_length(p)
            })
            .sum();
        let fees = self.fees.rlp_payload_length();
        let blobs: usize = self.blob_versioned_hashes.iter().map(|h| h.length()).sum();

        self.chain_id.length()
            + self.nonce.length()
            + self.sender.length()
            + frames
            + length_of_length(frames)
            + signatures
            + length_of_length(signatures)
            + fees
            + length_of_length(fees)
            + blobs
            + length_of_length(blobs)
    }

    fn encode_rlp(&self, elide: bool, out: &mut Vec<u8>) {
        Header { list: true, payload_length: self.rlp_payload_length(elide) }.encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.sender.encode(out);

        let frames: usize = self
            .frames
            .iter()
            .map(|f| {
                let p = f.rlp_payload_length();
                p + length_of_length(p)
            })
            .sum();
        Header { list: true, payload_length: frames }.encode(out);
        for frame in &self.frames {
            frame.encode_rlp(out);
        }

        let signatures: usize = self
            .signatures
            .iter()
            .map(|e| {
                let p = e.rlp_payload_length(elide);
                p + length_of_length(p)
            })
            .sum();
        Header { list: true, payload_length: signatures }.encode(out);
        for entry in &self.signatures {
            entry.encode_rlp(elide, out);
        }

        self.fees.encode_rlp(out);

        let blobs: usize = self.blob_versioned_hashes.iter().map(|h| h.length()).sum();
        Header { list: true, payload_length: blobs }.encode(out);
        for hash in &self.blob_versioned_hashes {
            hash.encode(out);
        }
    }
}

fn opt_addr_rlp_length(v: &Option<Address>) -> usize {
    match v {
        Some(a) => a.length(),
        None => 1,
    }
}

fn encode_opt_addr(v: &Option<Address>, out: &mut Vec<u8>) {
    match v {
        Some(a) => a.encode(out),
        None => out.push(EMPTY_STRING_CODE),
    }
}

fn opt_b256_rlp_length(v: &Option<B256>) -> usize {
    match v {
        Some(h) => h.length(),
        None => 1,
    }
}

fn encode_opt_b256(v: &Option<B256>, out: &mut Vec<u8>) {
    match v {
        Some(h) => h.encode(out),
        None => out.push(EMPTY_STRING_CODE),
    }
}

/// Canonical scalar-pair check: `0 < r < n` and `0 < s <= n // 2` (low-s, so
/// each signature has exactly one encoding). Inputs are optional subslices so
/// callers never index; anything but two 32-byte slices fails closed.
fn canonical_scalar_pair(r: Option<&[u8]>, s: Option<&[u8]>, curve_order: &B256) -> bool {
    let (Some(r), Some(s)) = (r, s) else {
        return false;
    };
    let (Ok(r), Ok(s)) = (<[u8; 32]>::try_from(r), <[u8; 32]>::try_from(s)) else {
        return false;
    };
    let n = U256::from_be_bytes(curve_order.0);
    let r = U256::from_be_bytes(r);
    let s = U256::from_be_bytes(s);
    // n is odd, so `n >> 1 == n // 2` (floor), matching the EIP's pseudocode.
    let half = n >> 1;
    !r.is_zero() && r < n && !s.is_zero() && s <= half
}
