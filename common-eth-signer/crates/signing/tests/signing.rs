//! Signing tests: a known BIP-39 address vector, plus sign->recover round-trips
//! for each message kind asserting the recovered signer matches the key.

use alloy_consensus::{TxEip1559, TxLegacy};
use alloy_primitives::{address, keccak256, Address, Bytes, TxKind, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameSignerRole, FrameTx, FrameTxError, FrameTxFees,
    SignatureEntry, SignatureScheme,
};
use signer_core::{
    ChildNumber, DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest, SignerError,
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

/// Defense in depth for HIGH-2: the decoder never yields a legacy tx without
/// a chain id, but `sign_request` must independently refuse one — its
/// signature (v = 27/28, pre-EIP-155 preimage) would be valid on every chain.
#[test]
fn refuse_to_sign_pre_eip155_legacy() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = TxLegacy {
        chain_id: None,
        nonce: 1,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::from(1_000_000_000_000_000_000u128),
        input: Bytes::new(),
    };
    let req = request(MessageKind::Transaction(DecodedTx::Legacy(tx)));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(err, SignerError::PreEip155Unsupported),
        "expected PreEip155Unsupported, got {err:?}"
    );
}

/// Defense in depth for HIGH-1: even if a mismatched request slipped past the
/// decode boundary, `sign_request` re-checks the envelope/transaction chain-id
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

/// m/44'/60'/0'/0/i — used to derive distinct co-signer keys.
fn eth_path_at(i: u32) -> DerivationPath {
    DerivationPath {
        components: vec![
            ChildNumber { index: 44, hardened: true },
            ChildNumber { index: 60, hardened: true },
            ChildNumber { index: 0, hardened: true },
            ChildNumber { index: 0, hardened: false },
            ChildNumber { index: i, hardened: false },
        ],
    }
}

/// An Example-1a-shaped frame transaction (VERIFY approve-both + SENDER
/// transfer) with `sender` and one canonical-hash signature slot per entry in
/// `signatures`.
fn frame_tx(sender: Address, signatures: Vec<SignatureEntry>) -> FrameTx {
    FrameTx {
        chain_id: 1,
        nonce: 7,
        sender,
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x3,
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
        signatures,
        fees: FrameTxFees {
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_fee_per_blob_gas: U256::ZERO,
        },
        blob_versioned_hashes: vec![],
    }
}

fn canonical_slot(signer: Option<Address>) -> SignatureEntry {
    SignatureEntry {
        scheme: SignatureScheme::Secp256k1,
        signer,
        msg: None,
        signature: Bytes::new(),
    }
}

/// Assert the EIP-8141 signature-entry encoding: 65 bytes `v || r || s`, with
/// v ∈ {0, 1} and low-s, recovering to `expected` over `hash`.
fn assert_frame_signature(sig: &[u8], hash: B256, expected: Address) {
    assert_eq!(sig.len(), 65, "frame signature is v || r || s");
    let v = sig[0];
    assert!(v <= 1, "v must be the recovery id (0/1), got {v}");
    // Low-s: s <= n >> 1.
    let n = U256::from_be_slice(
        &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap(),
    );
    let s = U256::from_be_slice(&sig[33..65]);
    assert!(s <= n >> 1, "s must be canonical low-s");
    let signature = Signature::from_slice(&sig[1..65]).unwrap();
    let rid = RecoveryId::from_byte(v).unwrap();
    let vk = VerifyingKey::recover_from_prehash(hash.as_slice(), &signature, rid).unwrap();
    let enc = vk.to_encoded_point(false);
    let addr = Address::from_slice(&keccak256(&enc.as_bytes()[1..])[12..]);
    assert_eq!(addr, expected);
}

/// The happy path: the device is `tx.sender` and fills the canonical slot.
#[test]
fn sign_frame_tx_as_sender_recovers_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let tx = frame_tx(EXPECTED, vec![canonical_slot(None)]);
    let hash = tx.sig_hash();
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx)));

    // The generic signing-hash projection agrees with the frame hash.
    assert_eq!(signing_hash(&req), hash);

    let sig = sign_request(&req, &key).unwrap();
    assert_frame_signature(&sig, hash, EXPECTED);
}

/// Sponsor/payer flow: the device key is NOT the sender; it fills a slot
/// naming its own address explicitly.
#[test]
fn sign_frame_tx_as_distinct_co_signer() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let sender = address!("00000000000000000000000000000000deadbeef");
    let tx = frame_tx(
        sender,
        vec![canonical_slot(None), canonical_slot(Some(EXPECTED))],
    );
    assert_eq!(tx.signer_role(EXPECTED).unwrap(), FrameSignerRole::CoSigner);
    let hash = tx.sig_hash();
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx)));
    let sig = sign_request(&req, &key).unwrap();
    assert_frame_signature(&sig, hash, EXPECTED);
}

/// No signature entry resolves to the device key: refuse (the signature could
/// never be inserted into this transaction).
#[test]
fn refuse_frame_tx_without_a_device_slot() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let sender = address!("00000000000000000000000000000000deadbeef");
    let tx = frame_tx(sender, vec![canonical_slot(None)]); // resolves to sender, not us
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx)));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(matches!(err, SignerError::FrameNoSignatureSlot), "got {err:?}");
}

/// A request whose device-addressed entry carries an explicit digest is an
/// open-ended authorization ask: refused. The unfilled explicit-digest entry
/// is already structurally invalid (validate), and `signer_role`
/// independently refuses it even when a canonical slot coexists.
#[test]
fn refuse_frame_tx_explicit_digest_signing() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let explicit_ask = SignatureEntry {
        scheme: SignatureScheme::Secp256k1,
        signer: None,
        msg: Some(B256::repeat_byte(0x42)),
        signature: Bytes::new(),
    };
    let tx = frame_tx(EXPECTED, vec![canonical_slot(None), explicit_ask]);

    // Layer 1: static validation refuses the unfilled explicit-digest entry.
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx.clone())));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::EmptyExplicitDigestSignature { index: 1 })
        ),
        "got {err:?}"
    );

    // Layer 2 (fault redundancy): the signing policy itself refuses the ask,
    // even though a canonical slot is also present.
    let err = tx.signer_role(EXPECTED).unwrap_err();
    assert!(matches!(err, SignerError::FrameExplicitDigestRefused), "got {err:?}");
}

/// A filled co-signature (sponsor flow) must verify against its resolved
/// signer before the device adds its own signature.
#[test]
fn frame_co_signature_is_verified_before_signing() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let sponsor_key = key_from_entropy(&ZERO_ENTROPY, &eth_path_at(1)).unwrap();
    let sponsor = address_of(&sponsor_key);

    // The sponsor signs the canonical hash of the tx (elision makes the hash
    // independent of whether our slot or theirs is filled).
    let tx = frame_tx(EXPECTED, vec![canonical_slot(None), canonical_slot(Some(sponsor))]);
    let hash = tx.sig_hash();
    let (sponsor_sig, rid) = sponsor_key.sign_prehash_recoverable(hash.as_slice()).unwrap();
    let mut sponsor_bytes = vec![rid.to_byte()];
    sponsor_bytes.extend_from_slice(&sponsor_sig.r().to_bytes());
    sponsor_bytes.extend_from_slice(&sponsor_sig.s().to_bytes());

    // Valid sponsor signature: the device signs.
    let mut tx_ok = tx.clone();
    tx_ok.signatures[1].signature = Bytes::from(sponsor_bytes.clone());
    assert_eq!(tx_ok.sig_hash(), hash, "filling an empty-msg slot must not change the hash");
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx_ok)));
    let sig = sign_request(&req, &key).unwrap();
    assert_frame_signature(&sig, hash, EXPECTED);

    // Same signature bytes, but the entry claims a different signer: the
    // recovered address no longer matches and the device refuses.
    let mut tx_bad = tx.clone();
    tx_bad.signatures[1].signer = Some(address!("00000000000000000000000000000000deadbeef"));
    tx_bad.signatures[1].signature = Bytes::from(sponsor_bytes);
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx_bad)));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(matches!(err, SignerError::FrameInvalidCoSignature(1)), "got {err:?}");
}

/// Chain binding holds for frame transactions too: envelope chain-id 1 vs
/// tx.chain_id 56 is refused before any signature exists.
#[test]
fn refuse_frame_tx_on_chain_id_mismatch() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let mut tx = frame_tx(EXPECTED, vec![canonical_slot(None)]);
    tx.chain_id = 56;
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx)));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(err, SignerError::ChainIdMismatch { request: 1, transaction: 56 }),
        "got {err:?}"
    );
}

/// The signing path re-validates the transaction independently of the decode
/// boundary (fault-injection redundancy).
#[test]
fn frame_signing_revalidates_the_transaction() {
    let key = key_from_entropy(&ZERO_ENTROPY, &eth_path()).unwrap();
    let mut tx = frame_tx(EXPECTED, vec![canonical_slot(None)]);
    tx.frames[0].value = U256::from(1u8); // value on a VERIFY frame
    let req = request(MessageKind::Transaction(DecodedTx::Frame(tx)));
    let err = sign_request(&req, &key).unwrap_err();
    assert!(
        matches!(
            err,
            SignerError::InvalidFrameTx(FrameTxError::ValueOnNonSenderFrame { frame: 0 })
        ),
        "got {err:?}"
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
