//! Unit tests for the pure view-model — no window, no backend.

use alloy_primitives::{address, Bytes, TxKind, U256};
use signer_core::{DecodedTx, DerivationPath, MessageKind, PersonalMessage, SignRequest};
use signer_displaying::{build_view_model, ConfirmBody, HeadlessUi, ConfirmationUi, Decision};

const SIGNER: alloy_primitives::Address = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");

fn req(message: MessageKind) -> SignRequest {
    SignRequest {
        request_id: None,
        chain_id: 1,
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
