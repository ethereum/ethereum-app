//! End-to-end tests: hex inputs through the full flow with a headless UI.

use alloy_consensus::{SignableTransaction, TxEip1559, TxLegacy};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use ciborium::value::{Integer, Value};
use device::run_scenario;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use signer_core::SignerError;
use signer_displaying::HeadlessUi;

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

/// Deliberate pre-EIP-155 policy, end to end: a 6-field legacy tx (the
/// replay-anywhere form behind deterministic multi-chain deployments) signs
/// with v = 27/28, and the screen the user approved carried the ALL CHAINS
/// warning instead of a chain number — even though the envelope said chain 1.
#[test]
fn pre_eip155_legacy_signs_with_v27_and_shows_all_chains_warning() {
    let tx = TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 100_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    let req_hex = build_request_hex(1, sign_data, Some(EXPECTED), 1);

    let mut ui = HeadlessUi::auto_approve();
    let out = run_scenario(&req_hex, ZERO_ENTROPY_HEX, &mut ui).unwrap();
    let (sig, _) = parse_signature(&out);

    let v = parse_v(&sig);
    assert!((27..=28).contains(&v), "pre-EIP-155 v is 27/28, got {v}");
    let signature = Signature::from_slice(&sig[..64]).unwrap();
    let rid = RecoveryId::from_byte((v - 27) as u8).unwrap();
    let vk = VerifyingKey::recover_from_prehash(tx.signature_hash().as_slice(), &signature, rid)
        .unwrap();
    let enc = vk.to_encoded_point(false);
    let addr = Address::from_slice(&alloy_primitives::keccak256(&enc.as_bytes()[1..])[12..]);
    assert_eq!(addr, EXPECTED);

    // WYSIWYS: the confirmation the user approved named the consequence.
    assert_eq!(ui.shown.len(), 1);
    let text = signer_displaying::render_text(&ui.shown[0]);
    assert!(
        text.contains("Chain ID:    ALL CHAINS (no replay protection)"),
        "rendered:\n{text}"
    );
    assert!(!text.contains("Chain ID:    1\n"), "rendered:\n{text}");
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
