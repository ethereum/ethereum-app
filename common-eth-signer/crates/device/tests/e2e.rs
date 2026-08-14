//! End-to-end tests: hex inputs through the full flow with a headless UI.

use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use ciborium::value::{Integer, Value};
use device::run_scenario;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameTx, FrameTxFees, SignatureEntry, SignatureScheme,
};
use signer_core::SignerError;
use signer_displaying::{ConfirmBody, HeadlessUi};

const ZERO_ENTROPY_HEX: &str = "00000000000000000000000000000000";
const EXPECTED: Address = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");
const REQUEST_ID: [u8; 16] = [0x42; 16];

fn int(n: i128) -> Value {
    Value::Integer(Integer::try_from(n).unwrap())
}

/// Build an `eth-sign-request` (m/44'/60'/0'/0/0, `chain-id` key 4 set to
/// `chain_id`) and return it as a hex string.
fn build_request_hex(
    data_type: i128,
    sign_data: Vec<u8>,
    addr: Option<Address>,
    chain_id: u64,
) -> String {
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
    let keypath = Value::Tag(304, Box::new(Value::Map(vec![(int(1), comps)])));

    let mut entries = vec![
        (
            int(1),
            Value::Tag(37, Box::new(Value::Bytes(REQUEST_ID.to_vec()))),
        ),
        (int(2), Value::Bytes(sign_data)),
        (int(3), int(data_type)),
        (int(4), int(chain_id as i128)),
        (int(5), keypath),
    ];
    if let Some(a) = addr {
        entries.push((int(6), Value::Bytes(a.to_vec())));
    }

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
    hex::encode(out)
}

fn sample_tx() -> TxEip1559 {
    TxEip1559 {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
        access_list: Default::default(),
    }
}

/// Pull the (variable-length) signature and echoed request-id out of an
/// eth-signature CBOR.
fn parse_signature(cbor: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let value: Value = ciborium::from_reader(cbor).unwrap();
    let Value::Map(m) = value else { panic!("not a map") };
    let mut sig = None;
    let mut id = None;
    for (k, v) in &m {
        match (k, v) {
            (Value::Integer(i), Value::Bytes(b)) if *i == Integer::from(2u32) => {
                sig = Some(b.clone());
            }
            (Value::Integer(i), Value::Tag(37, inner)) if *i == Integer::from(1u32) => {
                if let Value::Bytes(b) = inner.as_ref() {
                    id = Some(<[u8; 16]>::try_from(b.as_slice()).unwrap());
                }
            }
            _ => {}
        }
    }
    (sig.expect("signature"), id.expect("request-id"))
}

/// Big-endian `v` from `r||s||v`.
fn parse_v(sig: &[u8]) -> u64 {
    sig[64..].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn recover_typed_tx(hash: &[u8], sig: &[u8]) -> Address {
    let signature = Signature::from_slice(&sig[..64]).unwrap();
    let rid = RecoveryId::from_byte(parse_v(sig) as u8).unwrap(); // typed tx: v = y_parity
    let vk = VerifyingKey::recover_from_prehash(hash, &signature, rid).unwrap();
    let enc = vk.to_encoded_point(false);
    let h = alloy_primitives::keccak256(&enc.as_bytes()[1..]);
    Address::from_slice(&h[12..])
}

#[test]
fn eip1559_happy_path_signs_and_echoes_request_id() {
    let tx = sample_tx();
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    let req_hex = build_request_hex(4, sign_data, Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let out = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap();

    let (sig, echoed_id) = parse_signature(&out);
    assert_eq!(echoed_id, REQUEST_ID);
    assert_eq!(ui.shown.len(), 1, "user was shown exactly one screen");
    assert_eq!(recover_typed_tx(tx.signature_hash().as_slice(), &sig), EXPECTED);
}

#[test]
fn legacy_eip155_sepolia_v_is_full_eip155() {
    const SEPOLIA: u64 = 11_155_111;
    let tx = TxLegacy {
        chain_id: Some(SEPOLIA),
        nonce: 5,
        gas_price: 1_460_067_559,
        gas_limit: 111_366,
        to: TxKind::Call(address!("8b2bf3cc1a6594a8f901bed9d606e1750e82c229")),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    let req_hex = build_request_hex(1, sign_data, Some(EXPECTED), SEPOLIA);

    let mut ui = HeadlessUi::auto_approve();
    let out = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap();
    let (sig, _) = parse_signature(&out);

    // Sepolia's full EIP-155 v needs 4 bytes => 64 + 4 = 68-byte signature.
    assert_eq!(sig.len(), 68, "large-chain-id legacy sig carries a multi-byte v");
    let v = parse_v(&sig);
    let recid = v - 35 - 2 * SEPOLIA;
    assert!(recid <= 1, "v = chain_id*2 + 35 + recid");
    // v decodes back to the chain id, as ethereumjs does on the consumer side.
    assert_eq!((v - 35 - recid) / 2, SEPOLIA);

    let signature = Signature::from_slice(&sig[..64]).unwrap();
    let rid = RecoveryId::from_byte(recid as u8).unwrap();
    let vk = VerifyingKey::recover_from_prehash(tx.signature_hash().as_slice(), &signature, rid)
        .unwrap();
    let enc = vk.to_encoded_point(false);
    let addr = Address::from_slice(&alloy_primitives::keccak256(&enc.as_bytes()[1..])[12..]);
    assert_eq!(addr, EXPECTED);
}

#[test]
fn eip191_happy_path() {
    let req_hex = build_request_hex(3, b"Hello, Bob!".to_vec(), Some(EXPECTED), 1);
    let mut ui = HeadlessUi::auto_approve();
    let out = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap();
    let (sig, _) = parse_signature(&out);
    assert_eq!(sig.len(), 65);
    assert!((27..=28).contains(&parse_v(&sig)), "EIP-191 uses 27/28");
}

#[test]
fn rejection_yields_user_rejected() {
    let req_hex = build_request_hex(3, b"nope".to_vec(), Some(EXPECTED), 1);
    let mut ui = HeadlessUi::auto_reject();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(matches!(err, SignerError::UserRejected));
}

#[test]
fn wrong_address_yields_mismatch_before_ui() {
    let wrong = address!("00000000000000000000000000000000deadbeef");
    let req_hex = build_request_hex(3, b"hi".to_vec(), Some(wrong), 1);
    let mut ui = HeadlessUi::auto_approve();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(matches!(err, SignerError::AddressMismatch));
    assert_eq!(ui.shown.len(), 0, "must reject before showing anything");
}

#[test]
fn garbage_input_is_rejected() {
    let mut ui = HeadlessUi::auto_approve();
    assert!(run_scenario("ff00", ZERO_ENTROPY_HEX, &mut ui).is_err());
}

/// EIP-8141 Example 1a: a two-frame ETH transfer with `sender` as the
/// transaction sender and one canonical-hash signature slot.
fn sample_frame_tx(sender: Address) -> FrameTx {
    FrameTx {
        chain_id: 1,
        nonce: 4,
        sender,
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
                target: Some(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
                limits: FrameLimits { execution: 21_000, state: 0 },
                value: U256::from(1_000_000_000_000_000_000u128),
                data: Bytes::new(),
            },
        ],
        signatures: vec![SignatureEntry {
            scheme: SignatureScheme::Secp256k1,
            signer: None, // resolves to the sender
            msg: None,    // canonical transaction hash
            signature: Bytes::new(),
        }],
        fees: FrameTxFees {
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
        },
        blob_versioned_hashes: vec![],
    }
}

fn frame_sign_data(tx: &FrameTx) -> Vec<u8> {
    let mut out = vec![0x06];
    tx.encode_payload(&mut out);
    out
}

/// EIP-8141 end-to-end: decode → display (with the full frame breakdown) →
/// sign. The signature is the 65-byte entry encoding `v || r || s` with
/// v ∈ {0, 1} and recovers to the device address over the canonical
/// `compute_sig_hash` (empty-msg signature bytes elided).
#[test]
fn frame_tx_happy_path_signs_with_v_r_s_entry_encoding() {
    let tx = sample_frame_tx(EXPECTED);
    let req_hex = build_request_hex(4, frame_sign_data(&tx), Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let out = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap();

    // The user was shown the full frame breakdown.
    assert_eq!(ui.shown.len(), 1);
    let ConfirmBody::Transaction(view) = &ui.shown[0].body else {
        panic!("expected a transaction body");
    };
    let frame_view = view.frame.as_ref().expect("frame breakdown shown");
    assert_eq!(frame_view.frames.len(), 2);
    assert!(frame_view.signing_role.starts_with("sender ("));

    let (sig, echoed_id) = parse_signature(&out);
    assert_eq!(echoed_id, REQUEST_ID);
    assert_eq!(sig.len(), 65, "frame signature entry is v || r || s");
    let v = sig[0];
    assert!(v <= 1, "v is the recovery id, never 27/28 or EIP-155; got {v}");

    // Recover over the canonical sig hash and check low-s.
    let signature = Signature::from_slice(&sig[1..65]).unwrap();
    let rid = RecoveryId::from_byte(v).unwrap();
    let vk =
        VerifyingKey::recover_from_prehash(tx.sig_hash().as_slice(), &signature, rid).unwrap();
    let enc = vk.to_encoded_point(false);
    let addr = Address::from_slice(&alloy_primitives::keccak256(&enc.as_bytes()[1..])[12..]);
    assert_eq!(addr, EXPECTED);
    let n = U256::from_be_slice(
        &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap(),
    );
    assert!(U256::from_be_slice(&sig[33..65]) <= n >> 1, "s must be low-s");
}

/// A frame transaction whose signature entries never resolve to the device
/// key must be rejected before the user is shown anything: the produced
/// signature could not be inserted into the transaction.
#[test]
fn frame_tx_without_device_slot_is_rejected_before_ui() {
    // The sender (and thus the only slot) is someone else.
    let tx = sample_frame_tx(address!("00000000000000000000000000000000deadbeef"));
    let req_hex = build_request_hex(4, frame_sign_data(&tx), Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(matches!(err, SignerError::FrameNoSignatureSlot), "got {err:?}");
    assert_eq!(ui.shown.len(), 0, "must reject before showing anything");
}

/// Chain binding end-to-end for frame transactions: envelope says mainnet,
/// the frame tx body says chain 56 — rejected before the UI.
#[test]
fn frame_tx_chain_id_mismatch_is_rejected_before_ui() {
    let mut tx = sample_frame_tx(EXPECTED);
    tx.chain_id = 56;
    let req_hex = build_request_hex(4, frame_sign_data(&tx), Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "got {err:?}"
    );
    assert_eq!(ui.shown.len(), 0, "must reject before showing anything");
}

/// HIGH-1 end-to-end: the CBOR envelope claims mainnet while the RLP body —
/// the thing the signature commits to — targets chain 56. The request must be
/// rejected before the user is shown anything.
#[test]
fn chain_id_mismatch_is_rejected_before_ui() {
    let mut tx = sample_tx();
    tx.chain_id = 56;
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    let req_hex = build_request_hex(4, sign_data, Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "expected ChainIdMismatch, got {err:?}"
    );
    assert_eq!(ui.shown.len(), 0, "must reject before showing anything");
}

/// HIGH-2 end-to-end: a 6-field pre-EIP-155 legacy transaction (replayable on
/// every chain) must be rejected before the user is shown anything.
#[test]
fn pre_eip155_legacy_is_rejected_before_ui() {
    let tx = TxLegacy {
        chain_id: None,
        nonce: 5,
        gas_price: 1_460_067_559,
        gas_limit: 111_366,
        to: TxKind::Call(address!("8b2bf3cc1a6594a8f901bed9d606e1750e82c229")),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    let req_hex = build_request_hex(1, sign_data, Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let err = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap_err();
    assert!(
        matches!(err, SignerError::PreEip155Unsupported),
        "expected PreEip155Unsupported, got {err:?}"
    );
    assert_eq!(ui.shown.len(), 0, "must reject before showing anything");
}
