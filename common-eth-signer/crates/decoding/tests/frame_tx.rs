//! EIP-8141 frame transaction decoding tests: round-trips through the full
//! ERC-4527 request (data-type 4, type byte 0x06), constraint rejections, and
//! malformed / non-canonical RLP built with a raw byte-level builder.

use alloy_primitives::{address, Address, Bytes, B256, U256};
use alloy_rlp::{Encodable, Header};
use ciborium::value::{Integer, Value};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameTx, FrameTxError, FrameTxFees, SignatureEntry,
    SignatureScheme, EXPIRY_VERIFIER, MAX_FRAMES,
};
use signer_core::{DecodedTx, MessageKind, SignerError};
use signer_decoding::decode_sign_request;

const SENDER: Address = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");
const DESTINATION: Address = address!("4675c7e5baafbffbca748158becba61ef3b0a263");
const SPONSOR: Address = address!("00000000000000000000000000000000deadbeef");

fn int(n: i128) -> Value {
    Value::Integer(Integer::try_from(n).unwrap())
}

/// Build the CBOR `eth-sign-request` framing (data-type 4, m/44'/60'/0'/0/0)
/// around a typed-transaction `sign-data` payload — same shape as the other
/// decoding tests.
fn build_request(sign_data: Vec<u8>, chain_id: Option<i128>) -> Vec<u8> {
    let comps = Value::Array(vec![
        int(44),
        Value::Bool(true),
        int(60),
        Value::Bool(true),
        int(0),
        Value::Bool(true),
        int(0),
        Value::Bool(false),
        int(0),
        Value::Bool(false),
    ]);
    let keypath = Value::Map(vec![(int(1), comps)]);

    let mut entries = vec![(int(2), Value::Bytes(sign_data)), (int(3), int(4))];
    if let Some(c) = chain_id {
        entries.push((int(4), int(c)));
    }
    entries.push((int(5), keypath));

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

/// EIP-2718 `sign-data` bytes for a frame tx: `0x06 || rlp(tx)`.
fn sign_data_of(tx: &FrameTx) -> Vec<u8> {
    let mut out = vec![0x06];
    tx.encode_payload(&mut out);
    out
}

fn decode(tx: &FrameTx) -> Result<signer_core::SignRequest, SignerError> {
    decode_sign_request(&build_request(sign_data_of(tx), Some(tx.chain_id as i128)))
}

fn decode_err(tx: &FrameTx) -> SignerError {
    decode(tx).unwrap_err()
}

fn canonical_slot() -> SignatureEntry {
    SignatureEntry {
        scheme: SignatureScheme::Secp256k1,
        signer: None,
        msg: None,
        signature: Bytes::new(),
    }
}

/// A structurally canonical (but cryptographically meaningless) 65-byte
/// SECP256K1 signature: v = 0, r = 1, s = 1.
fn dummy_canonical_sig() -> Bytes {
    let mut sig = vec![0u8; 65];
    sig[32] = 1; // r = 1
    sig[64] = 1; // s = 1
    Bytes::from(sig)
}

/// EIP-8141 Example 1a: simple ETH transfer.
/// Frame 0: VERIFY, APPROVE_EXECUTION_AND_PAYMENT, target = sender, no data.
/// Frame 1: SENDER, no approvals, target = destination, value = 1 ETH.
fn example_1a() -> FrameTx {
    FrameTx {
        chain_id: 1,
        nonce: 7,
        sender: SENDER,
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x3, // APPROVE_EXECUTION_AND_PAYMENT
                target: None,
                limits: FrameLimits { execution: 65_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0x0,
                target: Some(DESTINATION),
                limits: FrameLimits { execution: 21_000, state: 0 },
                value: U256::from(1_000_000_000_000_000_000u128),
                data: Bytes::new(),
            },
        ],
        signatures: vec![canonical_slot()],
        fees: FrameTxFees {
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
        },
        blob_versioned_hashes: vec![],
    }
}

/// EIP-8141 Example 3: sponsored transaction (fee payment in ERC-20).
fn example_3_sponsored() -> FrameTx {
    let erc20 = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let transfer = Bytes::from(hex::decode(concat!(
        "a9059cbb",
        "00000000000000000000000000000000000000000000000000000000deadbeef",
        "0000000000000000000000000000000000000000000000000000000000989680",
    )).unwrap());
    FrameTx {
        chain_id: 1,
        nonce: 3,
        sender: SENDER,
        frames: vec![
            // 0: VERIFY, APPROVE_EXECUTION, target = sender.
            Frame {
                mode: FrameMode::Verify,
                flags: 0x2,
                target: None,
                limits: FrameLimits { execution: 65_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::new(),
            },
            // 1: VERIFY, APPROVE_PAYMENT, target = sponsor.
            Frame {
                mode: FrameMode::Verify,
                flags: 0x1,
                target: Some(SPONSOR),
                limits: FrameLimits { execution: 80_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::from(vec![0x01, 0x02, 0x03]),
            },
            // 2: SENDER, ERC-20 transfer of the fee to the sponsor.
            Frame {
                mode: FrameMode::Sender,
                flags: 0x0,
                target: Some(erc20),
                limits: FrameLimits { execution: 60_000, state: 100 },
                value: U256::ZERO,
                data: transfer,
            },
            // 3: SENDER, the actual user operation.
            Frame {
                mode: FrameMode::Sender,
                flags: 0x0,
                target: Some(DESTINATION),
                limits: FrameLimits { execution: 21_000, state: 0 },
                value: U256::from(5u8),
                data: Bytes::new(),
            },
            // 4: DEFAULT, sponsor post-op.
            Frame {
                mode: FrameMode::Default,
                flags: 0x0,
                target: Some(SPONSOR),
                limits: FrameLimits { execution: 30_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::new(),
            },
        ],
        signatures: vec![
            // The sender's canonical-hash slot (unfilled).
            canonical_slot(),
            // The sponsor's canonical-hash signature, already present
            // (structurally canonical; crypto verification happens at signing).
            SignatureEntry {
                scheme: SignatureScheme::Secp256k1,
                signer: Some(SPONSOR),
                msg: None,
                signature: dummy_canonical_sig(),
            },
        ],
        fees: FrameTxFees {
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
        },
        blob_versioned_hashes: vec![],
    }
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_example_1a() {
    let tx = example_1a();
    let req = decode(&tx).unwrap();
    let MessageKind::Transaction(DecodedTx::Frame(decoded)) = &req.message else {
        panic!("expected a frame tx, got {:?}", req.message);
    };
    assert_eq!(decoded, &tx);
    // Re-encoding the decoded struct reproduces the wire bytes exactly.
    assert_eq!(sign_data_of(decoded), sign_data_of(&tx));
}

#[test]
fn roundtrip_example_3_sponsored() {
    let tx = example_3_sponsored();
    let req = decode(&tx).unwrap();
    let MessageKind::Transaction(DecodedTx::Frame(decoded)) = &req.message else {
        panic!("expected a frame tx");
    };
    assert_eq!(decoded, &tx);
}

#[test]
fn roundtrip_with_blob_hashes() {
    let mut tx = example_1a();
    let mut hash = [0x11u8; 32];
    hash[0] = 0x01; // VERSIONED_HASH_VERSION_KZG
    tx.blob_versioned_hashes = vec![B256::from(hash)];
    tx.fees.max_fee_per_blob_gas = U256::from(7u8);
    let req = decode(&tx).unwrap();
    let MessageKind::Transaction(DecodedTx::Frame(decoded)) = &req.message else {
        panic!("expected a frame tx");
    };
    assert_eq!(decoded, &tx);
}

#[test]
fn absent_envelope_chain_id_is_accepted() {
    let cbor = build_request(sign_data_of(&example_1a()), None);
    let req = decode_sign_request(&cbor).unwrap();
    assert_eq!(req.chain_id, None);
}

// ---------------------------------------------------------------------------
// Chain binding (extends the HIGH-1 envelope/body cross-check)
// ---------------------------------------------------------------------------

#[test]
fn reject_chain_id_mismatch_between_request_and_frame_tx() {
    let mut tx = example_1a();
    tx.chain_id = 56;
    let cbor = build_request(sign_data_of(&tx), Some(1));
    let err = decode_sign_request(&cbor).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "expected ChainIdMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Constraint rejections (struct-representable, via the canonical encoder)
// ---------------------------------------------------------------------------

fn expect_frame_err(tx: &FrameTx, expected: FrameTxError) {
    let err = decode_err(tx);
    match err {
        SignerError::InvalidFrameTx(e) => assert_eq!(e, expected),
        other => panic!("expected InvalidFrameTx({expected:?}), got {other:?}"),
    }
}

#[test]
fn reject_empty_frame_list() {
    let mut tx = example_1a();
    tx.frames.clear();
    expect_frame_err(&tx, FrameTxError::NoFrames);
}

#[test]
fn reject_more_than_max_frames() {
    let mut tx = example_1a();
    let filler = Frame {
        mode: FrameMode::Sender,
        flags: 0,
        target: Some(DESTINATION),
        limits: FrameLimits { execution: 100, state: 0 },
        value: U256::ZERO,
        data: Bytes::new(),
    };
    tx.frames = vec![filler; MAX_FRAMES + 1];
    expect_frame_err(&tx, FrameTxError::TooManyFrames);
}

#[test]
fn reject_value_on_verify_frame() {
    let mut tx = example_1a();
    tx.frames[0].value = U256::from(1u8);
    expect_frame_err(&tx, FrameTxError::ValueOnNonSenderFrame { frame: 0 });
}

#[test]
fn reject_value_on_default_frame() {
    let mut tx = example_3_sponsored();
    tx.frames[4].value = U256::from(1u8);
    expect_frame_err(&tx, FrameTxError::ValueOnNonSenderFrame { frame: 4 });
}

#[test]
fn reject_atomic_batch_on_last_frame() {
    let mut tx = example_1a();
    tx.frames[1].flags = 0x4; // ATOMIC_BATCH_FLAG on the final frame
    expect_frame_err(&tx, FrameTxError::AtomicBatchOnLastFrame { frame: 1 });
}

#[test]
fn reject_atomic_batch_on_verify_frame() {
    let mut tx = example_1a();
    tx.frames[0].flags = 0x4;
    expect_frame_err(&tx, FrameTxError::AtomicBatchOnVerify { frame: 0 });
}

#[test]
fn reject_atomic_batch_followed_by_verify() {
    let mut tx = example_3_sponsored();
    // Frame 0 is VERIFY and frame 1 is VERIFY: put the batch flag on a
    // DEFAULT frame we insert before frame 1.
    tx.frames[0] = Frame {
        mode: FrameMode::Default,
        flags: 0x4,
        target: Some(DESTINATION),
        limits: FrameLimits { execution: 100, state: 0 },
        value: U256::ZERO,
        data: Bytes::new(),
    };
    expect_frame_err(&tx, FrameTxError::AtomicBatchIntoVerify { frame: 0 });
}

#[test]
fn reject_reserved_flag_bits() {
    let mut tx = example_1a();
    tx.frames[1].flags = 0x8; // reserved bit 3
    expect_frame_err(&tx, FrameTxError::InvalidFlags { frame: 1, flags: 0x8 });
}

#[test]
fn reject_approve_execution_with_foreign_target() {
    let mut tx = example_1a();
    // APPROVE_EXECUTION on a frame whose target is neither empty nor sender.
    tx.frames[0].target = Some(DESTINATION);
    expect_frame_err(&tx, FrameTxError::ApproveExecutionForeignTarget { frame: 0 });
}

#[test]
fn approve_execution_with_explicit_sender_target_is_accepted() {
    let mut tx = example_1a();
    tx.frames[0].target = Some(SENDER);
    assert!(decode(&tx).is_ok());
}

#[test]
fn reject_gas_limit_overflow() {
    let mut tx = example_1a();
    tx.frames[0].limits = FrameLimits { execution: u64::MAX, state: 1 };
    expect_frame_err(&tx, FrameTxError::GasLimitOverflow);
}

#[test]
fn reject_blob_hash_with_wrong_version() {
    let mut tx = example_1a();
    tx.blob_versioned_hashes = vec![B256::repeat_byte(0x02)];
    tx.fees.max_fee_per_blob_gas = U256::from(1u8);
    expect_frame_err(&tx, FrameTxError::InvalidBlobHash { index: 0 });
}

#[test]
fn reject_blob_fee_without_blobs() {
    let mut tx = example_1a();
    tx.fees.max_fee_per_blob_gas = U256::from(1u8);
    expect_frame_err(&tx, FrameTxError::BlobFeeWithoutBlobs);
}

#[test]
fn reject_arbitrary_entry_with_signer() {
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::Arbitrary,
        signer: Some(DESTINATION),
        msg: None,
        signature: Bytes::new(),
    });
    expect_frame_err(&tx, FrameTxError::ArbitrarySignerNotEmpty { index: 1 });
}

#[test]
fn reject_zero_explicit_digest() {
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::Secp256k1,
        signer: Some(DESTINATION),
        msg: Some(B256::ZERO),
        signature: dummy_canonical_sig(),
    });
    expect_frame_err(&tx, FrameTxError::ZeroExplicitDigest { index: 1 });
}

#[test]
fn reject_secp_signature_with_wrong_length() {
    let mut tx = example_1a();
    tx.signatures[0].signature = Bytes::from(vec![0u8; 64]);
    expect_frame_err(&tx, FrameTxError::InvalidSignatureLength { index: 0, len: 64 });
}

#[test]
fn reject_secp_signature_with_v_27() {
    let mut tx = example_1a();
    let mut sig = dummy_canonical_sig().to_vec();
    sig[0] = 27; // v must be the recovery id 0/1, never 27/28
    tx.signatures[0].signature = Bytes::from(sig);
    expect_frame_err(&tx, FrameTxError::NonCanonicalSignature { index: 0 });
}

#[test]
fn reject_secp_signature_with_high_s() {
    // s = n - 1 > n // 2.
    let n_minus_1 =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140").unwrap();
    let mut sig = vec![0u8; 65];
    sig[32] = 1; // r = 1
    sig[33..65].copy_from_slice(&n_minus_1);
    let mut tx = example_1a();
    tx.signatures[0].signature = Bytes::from(sig);
    expect_frame_err(&tx, FrameTxError::NonCanonicalSignature { index: 0 });
}

#[test]
fn reject_secp_signature_with_zero_r_or_s() {
    let mut tx = example_1a();
    let mut sig = dummy_canonical_sig().to_vec();
    sig[32] = 0; // r = 0
    tx.signatures[0].signature = Bytes::from(sig);
    expect_frame_err(&tx, FrameTxError::NonCanonicalSignature { index: 0 });

    let mut tx = example_1a();
    let mut sig = dummy_canonical_sig().to_vec();
    sig[64] = 0; // s = 0
    tx.signatures[0].signature = Bytes::from(sig);
    expect_frame_err(&tx, FrameTxError::NonCanonicalSignature { index: 0 });
}

#[test]
fn reject_explicit_digest_entry_with_empty_signature() {
    // An unfilled explicit-digest slot is how a wallet would ask the device
    // (or anyone) for an open-ended digest signature; also, filling it later
    // would change the canonical sig hash. Refused outright.
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::Secp256k1,
        signer: Some(DESTINATION),
        msg: Some(B256::repeat_byte(0x42)),
        signature: Bytes::new(),
    });
    expect_frame_err(&tx, FrameTxError::EmptyExplicitDigestSignature { index: 1 });
}

#[test]
fn reject_p256_signature_with_wrong_length() {
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::P256,
        signer: Some(DESTINATION),
        msg: None,
        signature: Bytes::from(vec![0u8; 65]),
    });
    expect_frame_err(&tx, FrameTxError::InvalidSignatureLength { index: 1, len: 65 });
}

#[test]
fn reject_p256_signer_that_does_not_match_the_public_key() {
    // Canonical r = s = 1, arbitrary qx/qy: keccak(qx||qy)[12:] will not be
    // DESTINATION.
    let mut sig = vec![0u8; 128];
    sig[31] = 1; // r = 1
    sig[63] = 1; // s = 1
    sig[64..].fill(0x77); // qx || qy
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::P256,
        signer: Some(DESTINATION),
        msg: None,
        signature: Bytes::from(sig),
    });
    expect_frame_err(&tx, FrameTxError::P256SignerMismatch { index: 1 });
}

#[test]
fn accept_p256_entry_whose_signer_matches_the_public_key() {
    let mut sig = vec![0u8; 128];
    sig[31] = 1;
    sig[63] = 1;
    sig[64..].fill(0x77);
    let expected_signer =
        Address::from_slice(&alloy_primitives::keccak256(&sig[64..])[12..]);
    let mut tx = example_1a();
    tx.signatures.push(SignatureEntry {
        scheme: SignatureScheme::P256,
        signer: Some(expected_signer),
        msg: None,
        signature: Bytes::from(sig),
    });
    assert!(decode(&tx).is_ok());
}

/// A well-formed expiry verifier frame: VERIFY targeting `address(0x8141)`
/// with flags 0, value 0, state limit 0, and an 8-byte big-endian timestamp.
fn expiry_frame() -> Frame {
    Frame {
        mode: FrameMode::Verify,
        flags: 0x0,
        target: Some(EXPIRY_VERIFIER),
        limits: FrameLimits { execution: 5_000, state: 0 },
        value: U256::ZERO,
        data: Bytes::from(0x0000_0001_0000_0000u64.to_be_bytes().to_vec()),
    }
}

#[test]
fn accept_a_valid_expiry_verifier_frame() {
    let mut tx = example_1a();
    tx.frames.insert(0, expiry_frame());
    assert!(decode(&tx).is_ok());
}

#[test]
fn reject_expiry_frame_with_wrong_data_length() {
    let mut tx = example_1a();
    let mut f = expiry_frame();
    f.data = Bytes::from(vec![0x01; 7]);
    tx.frames.insert(0, f);
    expect_frame_err(&tx, FrameTxError::InvalidExpiryFrame { frame: 0 });
}

#[test]
fn reject_expiry_frame_with_flags() {
    let mut tx = example_1a();
    let mut f = expiry_frame();
    f.flags = 0x1;
    tx.frames.insert(0, f);
    expect_frame_err(&tx, FrameTxError::InvalidExpiryFrame { frame: 0 });
}

#[test]
fn reject_expiry_frame_with_state_gas() {
    let mut tx = example_1a();
    let mut f = expiry_frame();
    f.limits.state = 1;
    tx.frames.insert(0, f);
    expect_frame_err(&tx, FrameTxError::InvalidExpiryFrame { frame: 0 });
}

#[test]
fn reject_two_expiry_frames() {
    let mut tx = example_1a();
    tx.frames.insert(0, expiry_frame());
    tx.frames.insert(0, expiry_frame());
    expect_frame_err(&tx, FrameTxError::MultipleExpiryFrames);
}

// ---------------------------------------------------------------------------
// Malformed / non-canonical RLP (raw byte-level builder)
// ---------------------------------------------------------------------------

fn enc_u64(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    n.encode(&mut out);
    out
}

fn enc_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    Bytes::copy_from_slice(b).encode(&mut out);
    out
}

fn enc_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::new();
    Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

/// A raw, hand-assembled valid frame: `[mode, flags, target, [exec, state],
/// value, data]`.
fn raw_frame(mode: u64, flags: u64, target: &[u8], value: u64, data: &[u8]) -> Vec<u8> {
    enc_list(&[
        enc_u64(mode),
        enc_u64(flags),
        enc_bytes(target),
        enc_list(&[enc_u64(21_000), enc_u64(0)]),
        enc_u64(value),
        enc_bytes(data),
    ])
}

fn raw_entry(scheme: u64, signer: &[u8], msg: &[u8], signature: &[u8]) -> Vec<u8> {
    enc_list(&[enc_u64(scheme), enc_bytes(signer), enc_bytes(msg), enc_bytes(signature)])
}

/// Assemble `0x06 || rlp([chain, nonce, sender, frames, sigs, fees, blobs])`
/// from raw pieces.
fn raw_sign_data(
    chain: Vec<u8>,
    nonce: Vec<u8>,
    sender: Vec<u8>,
    frames: &[Vec<u8>],
    sigs: &[Vec<u8>],
    fees: Vec<u8>,
    blobs: &[Vec<u8>],
) -> Vec<u8> {
    let body = enc_list(&[
        chain,
        nonce,
        sender,
        enc_list(frames),
        enc_list(sigs),
        fees,
        enc_list(blobs),
    ]);
    let mut out = vec![0x06];
    out.extend_from_slice(&body);
    out
}

/// Raw RLP pieces of a valid frame transaction; each negative test replaces
/// exactly one of them.
struct RawParts {
    chain: Vec<u8>,
    nonce: Vec<u8>,
    sender: Vec<u8>,
    frames: Vec<Vec<u8>>,
    sigs: Vec<Vec<u8>>,
    fees: Vec<u8>,
    blobs: Vec<Vec<u8>>,
}

fn default_raw_parts() -> RawParts {
    RawParts {
        chain: enc_u64(1),
        nonce: enc_u64(0),
        sender: enc_bytes(SENDER.as_slice()),
        frames: vec![
            raw_frame(1, 3, &[], 0, &[]),                    // VERIFY, approve both
            raw_frame(2, 0, DESTINATION.as_slice(), 5, &[]), // SENDER
        ],
        sigs: vec![raw_entry(1, &[], &[], &[])], // canonical slot
        fees: enc_list(&[enc_u64(1), enc_u64(2), enc_u64(0)]),
        blobs: vec![],
    }
}

impl RawParts {
    fn sign_data(&self) -> Vec<u8> {
        raw_sign_data(
            self.chain.clone(),
            self.nonce.clone(),
            self.sender.clone(),
            &self.frames,
            &self.sigs,
            self.fees.clone(),
            &self.blobs,
        )
    }
}

fn decode_raw(sign_data: Vec<u8>) -> SignerError {
    decode_sign_request(&build_request(sign_data, Some(1))).unwrap_err()
}

#[test]
fn raw_baseline_decodes() {
    let p = default_raw_parts();
    assert!(decode_sign_request(&build_request(p.sign_data(), Some(1))).is_ok());
}

#[test]
fn reject_mode_3() {
    let mut p = default_raw_parts();
    p.frames = vec![raw_frame(1, 3, &[], 0, &[]), raw_frame(3, 0, DESTINATION.as_slice(), 0, &[])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::InvalidMode { frame: 1, mode: 3 })),
        "got {err:?}"
    );
}

#[test]
fn reject_target_of_19_bytes() {
    let mut p = default_raw_parts();
    p.frames = vec![raw_frame(1, 3, &[], 0, &[]), raw_frame(2, 0, &[0x22; 19], 0, &[])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::InvalidTargetLength { frame: 1, len: 19 })
        ),
        "got {err:?}"
    );
}

#[test]
fn reject_sender_of_19_bytes() {
    let mut p = default_raw_parts();
    p.sender = enc_bytes(&[0x11; 19]);
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::InvalidSenderLength(19))),
        "got {err:?}"
    );
}

#[test]
fn reject_unknown_signature_scheme() {
    let mut p = default_raw_parts();
    p.sigs = vec![raw_entry(1, &[], &[], &[]), raw_entry(3, &[], &[], &[0xAB; 4])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::UnknownSignatureScheme { index: 1, scheme: 3 })
        ),
        "got {err:?}"
    );
}

#[test]
fn reject_msg_of_16_bytes() {
    let mut p = default_raw_parts();
    p.sigs = vec![raw_entry(1, &[], &[0x42; 16], &[0u8; 65])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::InvalidMsgLength { index: 0, len: 16 })
        ),
        "got {err:?}"
    );
}

#[test]
fn reject_blob_hash_of_31_bytes() {
    let mut p = default_raw_parts();
    p.fees = enc_list(&[enc_u64(1), enc_u64(2), enc_u64(1)]);
    p.blobs = vec![enc_bytes(&[0x01; 31])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::InvalidBlobHash { index: 0 })),
        "got {err:?}"
    );
}

#[test]
fn reject_trailing_item_in_frame() {
    let mut p = default_raw_parts();
    // A frame with an extra 7th field appended.
    let mut frame = vec![
        enc_u64(2),
        enc_u64(0),
        enc_bytes(DESTINATION.as_slice()),
        enc_list(&[enc_u64(21_000), enc_u64(0)]),
        enc_u64(0),
        enc_bytes(&[]),
    ];
    frame.push(enc_u64(0)); // trailing
    p.frames = vec![raw_frame(1, 3, &[], 0, &[]), enc_list(&frame)];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::TrailingBytes("frame"))),
        "got {err:?}"
    );
}

#[test]
fn reject_trailing_item_in_limits() {
    let mut p = default_raw_parts();
    let frame = enc_list(&[
        enc_u64(2),
        enc_u64(0),
        enc_bytes(DESTINATION.as_slice()),
        enc_list(&[enc_u64(21_000), enc_u64(0), enc_u64(0)]), // 3 limits
        enc_u64(0),
        enc_bytes(&[]),
    ]);
    p.frames = vec![raw_frame(1, 3, &[], 0, &[]), frame];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::TrailingBytes("frame limits"))),
        "got {err:?}"
    );
}

#[test]
fn reject_trailing_item_in_signature_entry() {
    let mut p = default_raw_parts();
    p.sigs = vec![enc_list(&[
        enc_u64(1),
        enc_bytes(&[]),
        enc_bytes(&[]),
        enc_bytes(&[]),
        enc_u64(0), // trailing 5th field
    ])];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::TrailingBytes("signature entry"))),
        "got {err:?}"
    );
}

#[test]
fn reject_trailing_field_in_tx_body() {
    let p = default_raw_parts();
    let body = enc_list(&[
        p.chain,
        p.nonce,
        p.sender,
        enc_list(&p.frames),
        enc_list(&p.sigs),
        p.fees,
        enc_list(&p.blobs),
        enc_u64(0), // 8th field
    ]);
    let mut sd = vec![0x06];
    sd.extend_from_slice(&body);
    let err = decode_raw(sd);
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::TrailingBytes("frame transaction body"))
        ),
        "got {err:?}"
    );
}

#[test]
fn reject_trailing_bytes_after_the_outer_list() {
    let mut sd = default_raw_parts().sign_data();
    sd.push(0x00);
    let err = decode_raw(sd);
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::TrailingBytes("frame transaction payload"))
        ),
        "got {err:?}"
    );
}

#[test]
fn reject_non_canonical_integer_encoding() {
    // chain_id = 1 encoded as a 2-byte string with a leading zero.
    let mut p = default_raw_parts();
    p.chain = vec![0x82, 0x00, 0x01];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::Rlp(_))),
        "got {err:?}"
    );
}

#[test]
fn reject_non_canonical_single_byte() {
    // nonce = 1 encoded as 0x81 0x01 instead of 0x01.
    let mut p = default_raw_parts();
    p.nonce = vec![0x81, 0x01];
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::Rlp(_))),
        "got {err:?}"
    );
}

#[test]
fn reject_chain_id_wider_than_64_bits() {
    let mut p = default_raw_parts();
    p.chain = enc_bytes(&[0x01; 9]); // 9-byte integer
    let err = decode_raw(p.sign_data());
    assert!(
        matches!(err, SignerError::InvalidFrameTx(FrameTxError::ChainIdTooLarge)),
        "got {err:?}"
    );
}

#[test]
fn reject_truncated_payload() {
    let mut sd = default_raw_parts().sign_data();
    sd.truncate(sd.len() - 1);
    let err = decode_raw(sd);
    assert!(matches!(err, SignerError::InvalidFrameTx(FrameTxError::Rlp(_))), "got {err:?}");
}
