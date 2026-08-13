//! Signing tests: a known BIP-39 address vector, plus sign->recover round-trips
//! for each message kind asserting the recovered signer matches the key.

use alloy_consensus::{TxEip1559, TxLegacy};
use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use signer_core::{
    ChildNumber, DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest,
};
use signer_signing::{address_of, key_from_entropy, signing_hash, sign_request};

/// m/44'/60'/0'/0/0
fn eth_path() -> DerivationPath {
    DerivationPath {
        components: vec![
            ChildNumber { index: 44, hardened: true },
            ChildNumber { index: 60, hardened: true },
            ChildNumber { index: 0, hardened: true },
            ChildNumber { index: 0, hardened: false },
            ChildNumber { index: 0, hardened: false },
        ],
    }
}

/// 16 zero bytes => "abandon abandon ... about" => well-known test address.
const ZERO_ENTROPY: [u8; 16] = [0u8; 16];
const EXPECTED: Address = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");

fn request(message: MessageKind) -> SignRequest {
    SignRequest {
        request_id: None,
        chain_id: 1,
        derivation_path: eth_path(),
        address: Some(EXPECTED),
        origin: None,
        raw_sign_data: vec![],
        message,
    }
}

/// Read the variable-length big-endian `v` from `r||s||v`.
fn parse_v(sig: &[u8]) -> u64 {
    sig[64..].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// Recover the signer address given the prehash and an explicit recovery id.
fn recover(hash: &[u8], sig: &[u8], recid: u8) -> Address {
    let signature = Signature::from_slice(&sig[..64]).unwrap();
    let rid = RecoveryId::from_byte(recid).unwrap();
    let vk = VerifyingKey::recover_from_prehash(hash, &signature, rid).unwrap();
    let encoded = vk.to_encoded_point(false);
    let h = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&h[12..])
}

#[test]
fn derives_known_address() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    assert_eq!(address_of(&key), EXPECTED);
}

#[test]
fn sign_eip191_recovers_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let req = request(MessageKind::Eip191(PersonalMessage::new(b"Hello, Bob!".to_vec())));
    let sig = sign_request(&req, &key).unwrap();
    let v = parse_v(&sig);
    assert!((27..=28).contains(&v), "EIP-191 uses 27/28");
    assert_eq!(
        recover(signing_hash(&req).as_slice(), &sig, (v - 27) as u8),
        EXPECTED
    );
}

#[test]
fn sign_legacy_recovers_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxLegacy {
        chain_id: Some(1),
        nonce: 1,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
    };
    let req = request(MessageKind::Transaction(DecodedTx::Legacy(tx)));
    let sig = sign_request(&req, &key).unwrap();
    // EIP-155 with chain_id = 1: v = 2*1 + 35 + recid = 37/38.
    let v = parse_v(&sig);
    assert!((37..=38).contains(&v), "legacy EIP-155 v = chain_id*2+35+recid");
    assert_eq!(
        recover(signing_hash(&req).as_slice(), &sig, (v - 37) as u8),
        EXPECTED
    );
}

#[test]
fn sign_eip1559_recovers_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxEip1559 {
        chain_id: 1,
        nonce: 1,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::ZERO,
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let req = request(MessageKind::Transaction(DecodedTx::Eip1559(tx)));
    let sig = sign_request(&req, &key).unwrap();
    // Typed tx: v = y_parity (0/1), minimal big-endian (0 => no v byte).
    let v = parse_v(&sig);
    assert!(v <= 1, "typed tx uses y-parity 0/1");
    assert_eq!(recover(signing_hash(&req).as_slice(), &sig, v as u8), EXPECTED);
}
