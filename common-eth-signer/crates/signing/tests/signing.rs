//! Signing tests: a known BIP-39 address vector, plus sign->recover round-trips
//! for each message kind asserting the recovered signer matches the key.

use alloy_consensus::{TxEip1559, TxLegacy};
use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use signer_core::{
    ChildNumber, DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest, SignerError,
};
use signer_signing::{
    address_of, key_from_entropy, key_from_seed, seed_from_entropy, signing_hash, sign_request,
    AccountKey, AccountXpub,
};

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
        chain_id: Some(1),
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

/// Deliberate pre-EIP-155 policy: a legacy tx with no chain id signs with the
/// replay-anywhere v = 27/28 (the mechanism behind deterministic multi-chain
/// deployments); the display layer warns it is valid on ALL chains.
#[test]
fn sign_pre_eip155_legacy_uses_v27_and_recovers_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 100_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    // The envelope chain-id (Some(1) from request()) has nothing to
    // contradict in a chain-id-less body and must not block signing.
    let req = request(MessageKind::Transaction(DecodedTx::Legacy(tx)));
    let sig = sign_request(&req, &key).unwrap();
    let v = parse_v(&sig);
    assert!((27..=28).contains(&v), "pre-EIP-155 v is 27/28, got {v}");
    assert_eq!(
        recover(signing_hash(&req).as_slice(), &sig, (v - 27) as u8),
        EXPECTED
    );
}

/// A hostile RLP chain id near u64::MAX must fail closed instead of
/// overflowing `chain_id * 2 + 35 + y` (debug panic / release wrap).
#[test]
fn refuse_eip155_v_overflow_instead_of_panicking() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxLegacy {
        chain_id: Some(u64::MAX),
        nonce: 0,
        gas_price: 100_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    // A matching envelope chain-id, so the overflow path itself is exercised.
    let mut req = request(MessageKind::Transaction(DecodedTx::Legacy(tx)));
    req.chain_id = Some(u64::MAX);
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(err, SignerError::Signing(_)),
        "expected Signing error, got {err:?}"
    );
}

/// Defense in depth: even if a mismatched request slipped past the decode
/// boundary, `sign_request` re-checks the envelope/transaction chain-id
/// binding before any signature is produced.
#[test]
fn refuse_to_sign_on_chain_id_mismatch() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxEip1559 {
        chain_id: 56, // request() sets the envelope chain-id to 1
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
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "expected ChainIdMismatch, got {err:?}"
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

#[test]
fn account_key_matches_direct_derivation() {
    use signer_core::request::{ChildNumber, DerivationPath};
    use signer_signing::AccountKey;

    let entropy = [0u8; 16]; // abandon x11 + about
    let account_path = DerivationPath {
        components: vec![
            ChildNumber { index: 44, hardened: true },
            ChildNumber { index: 60, hardened: true },
            ChildNumber { index: 0, hardened: true },
        ],
    };
    let account = AccountKey::from_entropy(&entropy, &account_path).unwrap();
    // master fingerprint of the standard "abandon ... about" mnemonic
    assert_eq!(account.master_fingerprint(), 0x73c5da0a);
    // address 0/0 must equal the full-path derivation used for signing
    let full_path = DerivationPath {
        components: vec![
            ChildNumber { index: 44, hardened: true },
            ChildNumber { index: 60, hardened: true },
            ChildNumber { index: 0, hardened: true },
            ChildNumber { index: 0, hardened: false },
            ChildNumber { index: 0, hardened: false },
        ],
    };
    let direct = signer_signing::address_of(&signer_signing::key_from_entropy(&entropy, &full_path).unwrap());
    assert_eq!(account.address(0, 0).unwrap(), direct);
    assert_eq!(
        account.address(0, 0).unwrap().to_checksum(None),
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    // different indexes give different addresses
    assert_ne!(account.address(0, 1).unwrap(), account.address(0, 0).unwrap());
}

/// The entropy forms have to stay exactly the empty-passphrase case of the seed
/// forms, since they are now written as wrappers over them.
#[test]
fn the_entropy_forms_are_the_empty_passphrase_seed_forms() {
    let entropy = [0u8; 16];
    let path = eth_path();
    let seed = seed_from_entropy(&entropy, "").unwrap();

    assert_eq!(
        address_of(&key_from_seed(&seed, &path).unwrap()),
        address_of(&key_from_entropy(&entropy, &path).unwrap())
    );

    let account = DerivationPath { components: path.components[..3].to_vec() };
    assert_eq!(
        AccountKey::from_seed(&seed, &account).unwrap().public_key_bytes(),
        AccountKey::from_entropy(&entropy, &account).unwrap().public_key_bytes()
    );
}

/// A passphrase is a different wallet, which is the case the entropy forms
/// cannot reach at all.
#[test]
fn a_passphrase_derives_a_different_wallet() {
    let entropy = [0u8; 16];
    let path = eth_path();
    let plain = seed_from_entropy(&entropy, "").unwrap();
    let passphrased = seed_from_entropy(&entropy, "sator arepo").unwrap();

    assert_ne!(plain, passphrased);
    assert_ne!(
        address_of(&key_from_seed(&plain, &path).unwrap()),
        address_of(&key_from_seed(&passphrased, &path).unwrap())
    );
}

/// The four bytes have to be the integer form's big-endian encoding, so the two
/// accessors cannot drift apart.
#[test]
fn the_fingerprint_accessors_agree() {
    let account = DerivationPath { components: eth_path().components[..3].to_vec() };
    let key = AccountKey::from_entropy(&[0u8; 16], &account).unwrap();
    assert_eq!(key.master_fingerprint_bytes(), key.master_fingerprint().to_be_bytes());
}

/// The public-only node has to derive exactly what the private one does, for
/// every child a wallet will ever show. This is the whole warrant for an app
/// deriving addresses locally from a custodian's `GetAccountKey` answer: if
/// these ever diverge, the app shows addresses nobody can spend from.
#[test]
fn the_public_account_node_agrees_with_the_private_one() {
    let entropy = [0u8; 16];
    let account = DerivationPath { components: eth_path().components[..3].to_vec() };
    let private = AccountKey::from_entropy(&entropy, &account).unwrap();
    let public =
        AccountXpub::from_parts(&private.public_key_bytes(), private.chain_code()).unwrap();

    for index in [0u32, 1, 2, 41, 999] {
        assert_eq!(public.address(0, index).unwrap(), private.address(0, index).unwrap());
    }
    // The change branch is derived the same way and must not be special-cased.
    assert_eq!(public.address(1, 0).unwrap(), private.address(1, 0).unwrap());
}

/// And it has to land on the published vector, not merely agree with a sibling
/// that could be wrong in the same way.
#[test]
fn the_public_account_node_derives_the_reference_address() {
    let account = DerivationPath { components: eth_path().components[..3].to_vec() };
    let private = AccountKey::from_entropy(&[0u8; 16], &account).unwrap();
    let public =
        AccountXpub::from_parts(&private.public_key_bytes(), private.chain_code()).unwrap();

    assert_eq!(
        public.address(0, 0).unwrap().to_checksum(None),
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
}

/// A public key that is not a point on the curve is a refusal, not a panic.
#[test]
fn a_malformed_public_key_is_refused() {
    assert!(AccountXpub::from_parts(&[0u8; 33], [0u8; 32]).is_err());
}
