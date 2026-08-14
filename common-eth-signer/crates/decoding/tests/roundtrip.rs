//! Decoding tests. Transactions are cross-checked against alloy's own
//! `encode_for_signing` output (the exact bytes a watch-only wallet places in
//! `sign-data`), and CBOR framing is hand-built to exercise tag leniency.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEip7702, TxLegacy};
use alloy_primitives::{address, Address, Bytes, TxKind, U256};
use ciborium::value::{Integer, Value};
use signer_decoding::{decode_sign_request, encode_eth_signature};
use signer_core::{DecodedTx, MessageKind, SignerError};

fn int(n: i128) -> Value {
    Value::Integer(Integer::try_from(n).unwrap())
}

/// Build the CBOR `eth-sign-request` framing around a `sign-data` payload with
/// `chain-id` (key 4) set to 1. `with_tags` toggles the EIP-text tag wrapping
/// (data-type #401, keypath #304, request-id #37) to exercise the lenient
/// decoder against both encodings.
fn build_request(data_type: i128, sign_data: Vec<u8>, with_tags: bool) -> Vec<u8> {
    build_request_with_chain(data_type, sign_data, with_tags, Some(1))
}

/// Like [`build_request`], but with an explicit (or absent) `chain-id` (key 4).
fn build_request_with_chain(
    data_type: i128,
    sign_data: Vec<u8>,
    with_tags: bool,
    chain_id: Option<i128>,
) -> Vec<u8> {
    // m/44'/60'/0'/0/0 as a flat [index, hardened, ...] array.
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
    let keypath_map = Value::Map(vec![(int(1), comps)]);
    let keypath = if with_tags {
        Value::Tag(304, Box::new(keypath_map))
    } else {
        keypath_map
    };
    let dt = if with_tags {
        Value::Tag(401, Box::new(int(data_type)))
    } else {
        int(data_type)
    };
    let request_id = Value::Tag(37, Box::new(Value::Bytes(vec![0xAB; 16])));

    let mut entries = vec![
        (int(1), request_id),
        (int(2), Value::Bytes(sign_data)),
        (int(3), dt),
    ];
    if let Some(c) = chain_id {
        entries.push((int(4), int(c)));
    }
    entries.push((int(5), keypath));
    entries.push((int(7), Value::Text("Test Wallet".into())));
    let map = Value::Map(entries);

    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).unwrap();
    out
}

const TO: Address = address!("4675c7e5baafbffbca748158becba61ef3b0a263");

#[test]
fn decode_legacy_tx() {
    let tx = TxLegacy {
        chain_id: Some(1),
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(TO),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);

    let req = decode_sign_request(&build_request(1, sign_data, false)).unwrap();
    assert_eq!(req.chain_id, Some(1));
    assert_eq!(req.derivation_path.to_string(), "m/44'/60'/0'/0/0");
    assert_eq!(req.origin.as_deref(), Some("Test Wallet"));
    assert_eq!(req.request_id, Some([0xAB; 16]));

    let MessageKind::Transaction(DecodedTx::Legacy(d)) = req.message else {
        panic!("expected legacy tx");
    };
    assert_eq!(d.chain_id, Some(1));
    assert_eq!(d.to, TxKind::Call(TO));
    let disp = DecodedTx::Legacy(d).display();
    assert_eq!(disp.to, Some(TO));
    assert_eq!(disp.value, U256::from(1_000_000_000_000_000_000u128));
    assert_eq!(disp.max_fee, U256::from(20_000_000_000u128 * 21_000));
}

#[test]
fn decode_eip1559_tx_with_calldata() {
    let calldata = hex::decode(
        "a9059cbb\
         0000000000000000000000004675c7e5baafbffbca748158becba61ef3b0a263\
         0000000000000000000000000000000000000000000000000de0b6b3a7640000",
    )
    .unwrap();
    let tx = TxEip1559 {
        chain_id: 1,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 60_000,
        to: TxKind::Call(TO),
        value: U256::ZERO,
        input: Bytes::from(calldata.clone()),
        access_list: Default::default(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    assert_eq!(sign_data[0], 0x02, "typed-tx must be EIP-2718 type 2");

    let req = decode_sign_request(&build_request(4, sign_data, true)).unwrap();
    let MessageKind::Transaction(d) = &req.message else {
        panic!("expected tx");
    };
    let disp = d.display();
    assert_eq!(disp.chain_id, Some(1));
    assert_eq!(disp.to, Some(TO));
    assert_eq!(disp.max_fee, U256::from(20_000_000_000u128 * 60_000));
    assert_eq!(disp.calldata, calldata);
    // ERC-8213 Calldata Digest for this exact ERC-20 transfer payload.
    assert_eq!(
        hex::encode(disp.calldata_digest.unwrap()),
        "812cee5d9cc7461c04bbcd7b70af9c28b243ac5d74d3453b008b93b7dac69985"
    );
}

#[test]
fn decode_eip7702_tx() {
    let tx = TxEip7702 {
        chain_id: 1,
        nonce: 3,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 100_000,
        to: TO,
        value: U256::ZERO,
        input: Bytes::new(),
        access_list: Default::default(),
        authorization_list: vec![],
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    assert_eq!(sign_data[0], 0x04, "typed-tx must be EIP-2718 type 4");

    let req = decode_sign_request(&build_request(4, sign_data, false)).unwrap();
    let MessageKind::Transaction(DecodedTx::Eip7702(d)) = &req.message else {
        panic!("expected 7702 tx");
    };
    assert_eq!(d.to, TO);
    assert_eq!(d.max_fee_per_gas, 30_000_000_000);
}

#[test]
fn decode_eip191_message() {
    let req = decode_sign_request(&build_request(3, b"Hello, Bob!".to_vec(), false)).unwrap();
    let MessageKind::Eip191(m) = &req.message else {
        panic!("expected EIP-191");
    };
    assert_eq!(m.as_utf8.as_deref(), Some("Hello, Bob!"));
    assert_eq!(m.raw, b"Hello, Bob!");
}

#[test]
fn decode_eip712_typed_data() {
    let json = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],"Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#;
    let req = decode_sign_request(&build_request(2, json.to_vec(), true)).unwrap();
    let MessageKind::Eip712(td) = &req.message else {
        panic!("expected EIP-712");
    };
    assert_eq!(
        hex::encode(td.eip712_digest),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
}

#[test]
fn reject_garbage() {
    assert!(decode_sign_request(&[0xff, 0x00, 0x12]).is_err());
}

/// An unsigned EIP-1559 body on the given chain, as `sign-data` bytes.
fn eip1559_sign_data(chain_id: u64) -> Vec<u8> {
    let tx = TxEip1559 {
        chain_id,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(TO),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    sign_data
}

/// An unsigned legacy transaction, as `sign-data` bytes. `chain_id: None`
/// yields the 6-field pre-EIP-155 list.
fn legacy_sign_data(chain_id: Option<u64>) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id,
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(TO),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
    };
    let mut sign_data = Vec::new();
    tx.encode_for_signing(&mut sign_data);
    sign_data
}

/// The CBOR envelope says mainnet, but the signature would commit to the
/// chain id inside the RLP body (BNB Chain). Must be rejected at decode.
#[test]
fn reject_chain_id_mismatch_between_request_and_typed_tx() {
    let cbor = build_request_with_chain(4, eip1559_sign_data(56), false, Some(1));
    let err = decode_sign_request(&cbor).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "expected ChainIdMismatch, got {err:?}"
    );
}

#[test]
fn reject_chain_id_mismatch_between_request_and_legacy_tx() {
    let cbor = build_request_with_chain(1, legacy_sign_data(Some(56)), false, Some(1));
    let err = decode_sign_request(&cbor).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "expected ChainIdMismatch, got {err:?}"
    );
}

/// ERC-4527 makes the request `chain-id` optional: when absent there is no
/// envelope claim to contradict, and the RLP body alone is authoritative.
#[test]
fn absent_request_chain_id_defers_to_the_tx_body() {
    let cbor = build_request_with_chain(4, eip1559_sign_data(56), false, None);
    let req = decode_sign_request(&cbor).unwrap();
    assert_eq!(req.chain_id, None);
    let MessageKind::Transaction(tx) = &req.message else {
        panic!("expected tx");
    };
    assert_eq!(tx.display().chain_id, Some(56));
}

/// A matching explicit chain-id is of course accepted.
#[test]
fn matching_request_and_tx_chain_ids_are_accepted() {
    let cbor = build_request_with_chain(4, eip1559_sign_data(56), false, Some(56));
    assert_eq!(decode_sign_request(&cbor).unwrap().chain_id, Some(56));
}

/// Deliberate policy: a 6-field pre-EIP-155 legacy list stays decodable —
/// it is the mechanism for deterministic multi-chain deployments (CreateX /
/// Nick's method). Its body carries no chain id, so an envelope `chain-id`
/// (present or absent) has nothing to contradict; honest display of the
/// ALL CHAINS consequence is the safety measure (see the displaying tests).
#[test]
fn accept_pre_eip155_legacy_tx() {
    for envelope_chain in [Some(1), None] {
        let cbor = build_request_with_chain(1, legacy_sign_data(None), false, envelope_chain);
        let req = decode_sign_request(&cbor).unwrap();
        let MessageKind::Transaction(DecodedTx::Legacy(d)) = &req.message else {
            panic!("expected legacy tx");
        };
        assert_eq!(d.chain_id, None, "pre-EIP-155 body has no chain id");
    }
}

/// The unsigned EIP-155 trailer must be exactly `chain_id, 0, 0`; non-zero r
/// or s is not a valid unsigned transaction.
#[test]
fn reject_eip155_trailer_with_nonzero_r_or_s() {
    // encode_for_signing ends with the trailer `..., chain_id, 0x80, 0x80`
    // (RLP for r = 0, s = 0); each is a single byte we can corrupt in place
    // without changing the list length.
    let good = legacy_sign_data(Some(1));
    let n = good.len();
    assert_eq!(&good[n - 2..], &[0x80, 0x80], "trailer must end with r=0, s=0");

    let mut bad_s = good.clone();
    bad_s[n - 1] = 0x01; // s = 1
    let err = decode_sign_request(&build_request(1, bad_s, false)).unwrap_err();
    assert!(matches!(err, SignerError::InvalidTransaction(_)), "got {err:?}");

    let mut bad_r = good.clone();
    bad_r[n - 2] = 0x01; // r = 1
    let err = decode_sign_request(&build_request(1, bad_r, false)).unwrap_err();
    assert!(matches!(err, SignerError::InvalidTransaction(_)), "got {err:?}");

    // The untouched encoding still decodes.
    assert!(decode_sign_request(&build_request(1, good, false)).is_ok());
}

#[test]
fn eth_signature_roundtrip() {
    let sig = [0x11u8; 65];
    let id = [0x22u8; 16];
    let bytes = encode_eth_signature(Some(id), &sig, Some("Device X"));

    // Decode back with ciborium and check the fields/tags.
    let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    let Value::Map(m) = value else { panic!("not a map") };
    // request-id is tagged 37
    let (_, rid) = m.iter().find(|(k, _)| *k == int(1)).unwrap();
    assert!(matches!(rid, Value::Tag(37, _)));
    // signature is 65 raw bytes
    let (_, s) = m.iter().find(|(k, _)| *k == int(2)).unwrap();
    let Value::Bytes(b) = s else { panic!("sig not bytes") };
    assert_eq!(b.len(), 65);
}
