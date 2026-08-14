//! EIP-8141 frame transaction: encoding known-answer vector (independently
//! hand-assembled RLP bytes) and the `compute_sig_hash` elision property.

use alloy_primitives::{address, keccak256, Bytes, B256, U256};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameTx, FrameTxFees, SignatureEntry, SignatureScheme,
    FRAME_TX_TYPE,
};

const SENDER: alloy_primitives::Address = address!("1111111111111111111111111111111111111111");
const TARGET: alloy_primitives::Address = address!("2222222222222222222222222222222222222222");

/// A minimal single-frame transaction whose RLP is small enough to assemble
/// by hand (the known-answer vector below).
fn minimal_tx() -> FrameTx {
    FrameTx {
        chain_id: 1,
        nonce: 0,
        sender: SENDER,
        frames: vec![Frame {
            mode: FrameMode::Sender,
            flags: 0,
            target: Some(TARGET),
            limits: FrameLimits { execution: 21_000, state: 0 },
            value: U256::from(1_000_000_000_000_000_000u128), // 0x0de0b6b3a7640000
            data: Bytes::new(),
        }],
        signatures: vec![SignatureEntry {
            scheme: SignatureScheme::Secp256k1,
            signer: None,
            msg: None,
            signature: Bytes::new(),
        }],
        fees: FrameTxFees {
            max_priority_fee_per_gas: U256::from(1u8),
            max_fee_per_gas: U256::from(2u8),
            max_fee_per_blob_gas: U256::from(3u8),
        },
        blob_versioned_hashes: vec![],
    }
}

/// The RLP of `minimal_tx()`, assembled byte by byte from the RLP rules and
/// the EIP's payload layout — independent of the encoder under test:
///
/// ```text
/// f84a                     outer list, payload 74
///   01                     chain_id = 1
///   80                     nonce = 0
///   94 11*20               sender
///   e7 e6                  frames = [ frame(payload 38) ]
///     02 80                mode = SENDER, flags = 0
///     94 22*20             target
///     c4 82 5208 80        limits = [21000, 0]
///     88 0de0b6b3a7640000  value = 1 ETH
///     80                   data = empty
///   c5 c4 01 80 80 80      signatures = [[SECP256K1, empty, empty, empty]]
///   c3 01 02 03            fees = [1, 2, 3]
///   c0                     blob_versioned_hashes = []
/// ```
fn minimal_tx_expected_rlp() -> Vec<u8> {
    hex::decode(concat!(
        "f84a",
        "01",
        "80",
        "941111111111111111111111111111111111111111",
        "e7e6",
        "0280",
        "942222222222222222222222222222222222222222",
        "c482520880",
        "880de0b6b3a7640000",
        "80",
        "c5c401808080",
        "c3010203",
        "c0",
    ))
    .unwrap()
}

#[test]
fn encode_payload_matches_hand_assembled_rlp() {
    let mut encoded = Vec::new();
    minimal_tx().encode_payload(&mut encoded);
    assert_eq!(hex::encode(&encoded), hex::encode(minimal_tx_expected_rlp()));
}

#[test]
fn sig_hash_is_keccak_of_type_byte_plus_elided_rlp() {
    // With the (canonical, empty-msg) signature slot still empty, elision is
    // a no-op and the hash is keccak256(0x06 || hand-assembled rlp).
    let mut preimage = vec![FRAME_TX_TYPE];
    preimage.extend_from_slice(&minimal_tx_expected_rlp());
    let expected = keccak256(&preimage);
    assert_eq!(minimal_tx().sig_hash(), expected);

    // Filling the canonical slot changes the wire encoding but must NOT
    // change the hash: empty-msg signature bytes are elided.
    let mut filled = minimal_tx();
    filled.signatures[0].signature = Bytes::from(vec![0x01; 65]);
    let mut filled_encoded = Vec::new();
    filled.encode_payload(&mut filled_encoded);
    assert_ne!(filled_encoded, minimal_tx_expected_rlp());
    assert_eq!(filled.sig_hash(), expected);
}

#[test]
fn elision_covers_canonical_entries_only() {
    let base = FrameTx {
        signatures: vec![
            // Canonical-hash SECP256K1 entry (bytes elided).
            SignatureEntry {
                scheme: SignatureScheme::Secp256k1,
                signer: None,
                msg: None,
                signature: Bytes::from(vec![0xAA; 65]),
            },
            // Explicit-digest SECP256K1 entry (bytes committed).
            SignatureEntry {
                scheme: SignatureScheme::Secp256k1,
                signer: Some(TARGET),
                msg: Some(B256::repeat_byte(0x42)),
                signature: Bytes::from(vec![0xBB; 65]),
            },
            // Canonical-hash ARBITRARY witness (bytes elided).
            SignatureEntry {
                scheme: SignatureScheme::Arbitrary,
                signer: None,
                msg: None,
                signature: Bytes::from(vec![0xCC; 7]),
            },
        ],
        ..minimal_tx()
    };
    let hash = base.sig_hash();

    // Changing raw bytes of empty-msg entries does not affect the hash...
    let mut mutated = base.clone();
    mutated.signatures[0].signature = Bytes::from(vec![0xDD; 65]);
    mutated.signatures[2].signature = Bytes::from(vec![0xEE; 99]);
    assert_eq!(mutated.sig_hash(), hash, "empty-msg signature bytes must be elided");

    // ...but changing the explicit-digest entry's bytes DOES.
    let mut mutated = base.clone();
    mutated.signatures[1].signature = Bytes::from(vec![0xBC; 65]);
    assert_ne!(mutated.sig_hash(), hash, "explicit-msg signature bytes are committed");

    // And the entry metadata (scheme/signer/msg) is always committed, even on
    // elided entries.
    let mut mutated = base.clone();
    mutated.signatures[0].signer = Some(TARGET);
    assert_ne!(mutated.sig_hash(), hash);
    let mut mutated = base;
    mutated.signatures[1].msg = Some(B256::repeat_byte(0x43));
    assert_ne!(mutated.sig_hash(), hash);
}
