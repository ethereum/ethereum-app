//! Unit tests for the pure view-model — no window, no backend.

use alloy_primitives::{address, Address, Bytes, TxKind, B256, U256};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameTx, FrameTxFees, SignatureEntry, SignatureScheme,
};
use signer_core::{DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest};
use signer_displaying::{build_view_model, ConfirmBody, HeadlessUi, ConfirmationUi, Decision};

const SIGNER: alloy_primitives::Address = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");

fn req(message: MessageKind) -> SignRequest {
    SignRequest {
        request_id: None,
        chain_id: Some(1),
        derivation_path: DerivationPath::default(),
        address: None,
        origin: Some("Test Wallet".into()),
        raw_sign_data: vec![],
        message,
    }
}

#[test]
fn message_view_model() {
    let vm = build_view_model(
        &req(MessageKind::Eip191(PersonalMessage::new(b"Hello".to_vec()))),
        SIGNER,
    );
    assert_eq!(vm.title, "Sign Message");
    assert_eq!(vm.signer_address, SIGNER.to_string());
    match vm.body {
        ConfirmBody::Message { text, is_hex } => {
            assert_eq!(text, "Hello");
            assert!(!is_hex);
        }
        _ => panic!("expected message body"),
    }
}

#[test]
fn transaction_view_model_formats_value_fee_and_digest() {
    let calldata =
        hex::decode("a9059cbb0000000000000000000000004675c7e5baafbffbca748158becba61ef3b0a2630000000000000000000000000000000000000000000000000de0b6b3a7640000")
            .unwrap();
    let tx = alloy_consensus::TxEip1559 {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 60_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::from(1_500_000_000_000_000_000u128), // 1.5 ETH
        input: Bytes::from(calldata),
        access_list: Default::default(),
    };
    let vm = build_view_model(&req(MessageKind::Transaction(DecodedTx::Eip1559(tx))), SIGNER);
    let ConfirmBody::Transaction(t) = vm.body else {
        panic!("expected tx body");
    };
    assert_eq!(t.tx_type, "EIP-1559");
    assert_eq!(t.value, "1.5 ETH");
    assert_eq!(t.max_fee, "0.0012 ETH"); // 20 gwei * 60000 = 1.2e15 wei
    assert!(t.calldata_hex.is_some());
    assert_eq!(
        t.calldata_digest.as_deref(),
        Some("0x812cee5d9cc7461c04bbcd7b70af9c28b243ac5d74d3453b008b93b7dac69985")
    );
}

/// HIGH-1 (display honesty): the transaction body's chain id — the value the
/// signature commits to — is what the sign page renders, never the
/// request-level (attacker-chosen) CBOR chain-id. Decoding rejects such a
/// mismatched request outright; this locks the projection itself so no future
/// backend can regress to the envelope value.
#[test]
fn tx_view_renders_the_rlp_chain_id_not_the_request_one() {
    let tx = alloy_consensus::TxEip1559 {
        chain_id: 56, // what would actually be signed
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4675c7e5baafbffbca748158becba61ef3b0a263")),
        value: U256::ZERO,
        input: Bytes::new(),
        access_list: Default::default(),
    };
    // The envelope claims mainnet.
    let vm = build_view_model(&req(MessageKind::Transaction(DecodedTx::Eip1559(tx))), SIGNER);
    let ConfirmBody::Transaction(t) = &vm.body else {
        panic!("expected tx body");
    };
    assert_eq!(t.chain_id, "56");
    // The console rendering shows the transaction's own chain id.
    let text = signer_displaying::render_text(&vm);
    assert!(text.contains("Chain ID:    56"), "rendered:\n{text}");
}

/// A two-frame ETH transfer (EIP-8141 Example 1a) with three signature
/// entries: the sender's canonical slot, a sponsor's explicit-digest entry,
/// and an arbitrary witness.
fn sample_frame_tx(sender: Address) -> FrameTx {
    let destination = address!("4675c7e5baafbffbca748158becba61ef3b0a263");
    let calldata = Bytes::from(hex::decode("a9059cbb00").unwrap());
    FrameTx {
        chain_id: 56,
        nonce: 9,
        sender,
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x3, // approve execution + payment
                target: None,
                limits: FrameLimits { execution: 65_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0x4, // atomic batch with the next frame
                target: Some(destination),
                limits: FrameLimits { execution: 21_000, state: 12 },
                value: U256::from(1_500_000_000_000_000_000u128),
                data: calldata,
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0x0,
                target: Some(destination),
                limits: FrameLimits { execution: 21_000, state: 0 },
                value: U256::ZERO,
                data: Bytes::new(),
            },
        ],
        signatures: vec![
            SignatureEntry {
                scheme: SignatureScheme::Secp256k1,
                signer: None, // resolves to the sender
                msg: None,    // canonical hash
                signature: Bytes::new(),
            },
            SignatureEntry {
                scheme: SignatureScheme::Secp256k1,
                signer: Some(address!("00000000000000000000000000000000deadbeef")),
                msg: Some(B256::repeat_byte(0x42)), // explicit digest!
                signature: Bytes::from(vec![0u8; 65]),
            },
            SignatureEntry {
                scheme: SignatureScheme::Arbitrary,
                signer: None,
                msg: None,
                signature: Bytes::from(vec![0xAB; 8]),
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

/// WYSIWYS for frame transactions: the view carries every frame and every
/// signature entry, resolves targets/signers, spells out approval flags, and
/// visibly flags explicit-digest entries.
#[test]
fn frame_tx_view_shows_every_frame_and_flags_explicit_digests() {
    let tx = sample_frame_tx(SIGNER);
    let vm = build_view_model(&req(MessageKind::Transaction(DecodedTx::Frame(tx))), SIGNER);
    let ConfirmBody::Transaction(t) = &vm.body else {
        panic!("expected tx body");
    };
    assert_eq!(t.tx_type, "EIP-8141 Frame");
    // The authoritative chain id comes from the RLP body.
    assert_eq!(t.chain_id, "56");
    // Aggregate value = sum of frame values.
    assert_eq!(t.value, "1.5 ETH");

    let f = t.frame.as_ref().expect("frame breakdown present");
    assert_eq!(f.sender, SIGNER.to_string());
    assert_eq!(f.nonce, "9");
    assert!(f.signing_role.starts_with("sender ("), "role: {}", f.signing_role);
    assert_eq!(f.blob_hash_count, 0);

    // Every frame is present and fully described.
    assert_eq!(f.frames.len(), 3);
    assert_eq!(f.frames[0].mode, "VERIFY");
    assert!(f.frames[0].target.starts_with("sender ("), "resolved: {}", f.frames[0].target);
    assert_eq!(f.frames[0].approval_scope, "execution+payment");
    assert!(!f.frames[0].atomic_batch);
    assert_eq!(f.frames[0].data_len, 0);
    assert!(f.frames[0].data_digest.is_none(), "empty data shows as such");

    assert_eq!(f.frames[1].mode, "SENDER");
    assert_eq!(f.frames[1].approval_scope, "none");
    assert!(f.frames[1].atomic_batch);
    assert_eq!(f.frames[1].value, "1.5 ETH");
    assert_eq!(f.frames[1].data_len, 5);
    // ERC-8213 Calldata Digest of the frame data:
    // keccak256(uint256(5) || a9059cbb00).
    let expected = signer_core::calldata_digest(&hex::decode("a9059cbb00").unwrap());
    assert_eq!(f.frames[1].data_digest.as_deref(), Some(expected.to_string().as_str()));

    // Every signature entry is present; the explicit-digest one is flagged.
    assert_eq!(f.signatures.len(), 3);
    assert!(f.signatures[0].signs_canonical_hash);
    assert!(f.signatures[0].pending);
    assert!(f.signatures[0].is_device_slot);
    assert!(f.signatures[0].signer.starts_with("sender ("));

    assert!(!f.signatures[1].signs_canonical_hash, "explicit digest must be flagged");
    assert_eq!(
        f.signatures[1].explicit_digest.as_deref(),
        Some(B256::repeat_byte(0x42).to_string().as_str())
    );
    assert!(!f.signatures[1].is_device_slot);

    assert_eq!(f.signatures[2].scheme, "ARBITRARY");
    assert_eq!(f.signatures[2].signer, "(none — arbitrary witness)");

    // The rendered text spells all of it out, including the warning.
    let text = signer_displaying::render_text(&vm);
    assert!(text.contains("Signing as:  sender ("), "rendered:\n{text}");
    assert!(text.contains("Frames (3):"), "rendered:\n{text}");
    assert!(text.contains("[atomic batch with frame 2]"), "rendered:\n{text}");
    assert!(
        text.contains("EXPLICIT DIGEST") && text.contains("WARNING"),
        "explicit-digest entries must be visibly flagged:\n{text}"
    );
    assert!(text.contains("[to be signed by this device]"), "rendered:\n{text}");
}

/// Sponsor/payer flow: when the device key is not the sender, the role line
/// must say so explicitly.
#[test]
fn frame_tx_view_names_the_co_signer_role() {
    let other_sender = address!("00000000000000000000000000000000deadbeef");
    let mut tx = sample_frame_tx(other_sender);
    // Give the device (SIGNER) its own canonical slot.
    tx.signatures[0].signer = Some(SIGNER);
    let vm = build_view_model(&req(MessageKind::Transaction(DecodedTx::Frame(tx))), SIGNER);
    let ConfirmBody::Transaction(t) = &vm.body else {
        panic!("expected tx body");
    };
    let f = t.frame.as_ref().unwrap();
    assert!(
        f.signing_role.contains("NOT the sender"),
        "co-signer role must be explicit: {}",
        f.signing_role
    );
    assert!(f.signatures[0].is_device_slot);
    let text = signer_displaying::render_text(&vm);
    assert!(text.contains("NOT the sender"), "rendered:\n{text}");
}

#[test]
fn headless_records_and_decides() {
    let mut ui = HeadlessUi::scripted([Decision::Reject, Decision::Approve]);
    let vm = build_view_model(
        &req(MessageKind::Eip191(PersonalMessage::new(b"hi".to_vec()))),
        SIGNER,
    );
    assert_eq!(ui.confirm(&vm).unwrap(), Decision::Reject);
    assert_eq!(ui.confirm(&vm).unwrap(), Decision::Approve);
    assert_eq!(ui.confirm(&vm).unwrap(), Decision::Reject); // default after script
    assert_eq!(ui.shown.len(), 3);
}
