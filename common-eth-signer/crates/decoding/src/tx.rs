//! RLP decoding of unsigned legacy / EIP-1559 / EIP-7702 transactions.
//!
//! ERC-4527 carries the RLP encoding of the *unsigned* transaction in
//! `sign-data`. For data-type 1 it is a bare legacy list; for data-type 4 it is
//! an EIP-2718 typed payload prefixed by a type byte (`0x02` / `0x04`).

use alloy_consensus::{TxEip1559, TxEip7702, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_eips::eip7702::SignedAuthorization;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_rlp::{Decodable, Header};
use signer_core::{DecodedTx, SignerError};

fn map_rlp(e: alloy_rlp::Error) -> SignerError {
    SignerError::InvalidTransaction(e.to_string())
}

fn expect_list(buf: &mut &[u8]) -> Result<(), SignerError> {
    let header = Header::decode(buf).map_err(map_rlp)?;
    if !header.list {
        return Err(SignerError::InvalidTransaction(
            "expected an RLP list".into(),
        ));
    }
    Ok(())
}

/// Decode an unsigned legacy transaction (data-type 1).
///
/// Accepts both pre-EIP-155 (6 fields) and EIP-155 (`..., chain_id, 0, 0`) forms.
pub fn decode_legacy(mut buf: &[u8]) -> Result<TxLegacy, SignerError> {
    expect_list(&mut buf)?;
    let mut tx = TxLegacy {
        chain_id: None,
        nonce: u64::decode(&mut buf).map_err(map_rlp)?,
        gas_price: u128::decode(&mut buf).map_err(map_rlp)?,
        gas_limit: u64::decode(&mut buf).map_err(map_rlp)?,
        to: TxKind::decode(&mut buf).map_err(map_rlp)?,
        value: U256::decode(&mut buf).map_err(map_rlp)?,
        input: Bytes::decode(&mut buf).map_err(map_rlp)?,
    };
    // Optional EIP-155 trailer: chain_id, r(=0), s(=0).
    if !buf.is_empty() {
        tx.chain_id = Some(u64::decode(&mut buf).map_err(map_rlp)?);
        let _r = U256::decode(&mut buf).map_err(map_rlp)?;
        let _s = U256::decode(&mut buf).map_err(map_rlp)?;
    }
    Ok(tx)
}

/// Decode an unsigned EIP-1559 transaction body (the bytes after the `0x02` tag).
pub fn decode_eip1559(mut buf: &[u8]) -> Result<TxEip1559, SignerError> {
    expect_list(&mut buf)?;
    Ok(TxEip1559 {
        chain_id: u64::decode(&mut buf).map_err(map_rlp)?,
        nonce: u64::decode(&mut buf).map_err(map_rlp)?,
        max_priority_fee_per_gas: u128::decode(&mut buf).map_err(map_rlp)?,
        max_fee_per_gas: u128::decode(&mut buf).map_err(map_rlp)?,
        gas_limit: u64::decode(&mut buf).map_err(map_rlp)?,
        to: TxKind::decode(&mut buf).map_err(map_rlp)?,
        value: U256::decode(&mut buf).map_err(map_rlp)?,
        input: Bytes::decode(&mut buf).map_err(map_rlp)?,
        access_list: AccessList::decode(&mut buf).map_err(map_rlp)?,
    })
}

/// Decode an unsigned EIP-7702 transaction body (the bytes after the `0x04` tag).
pub fn decode_eip7702(mut buf: &[u8]) -> Result<TxEip7702, SignerError> {
    expect_list(&mut buf)?;
    Ok(TxEip7702 {
        chain_id: u64::decode(&mut buf).map_err(map_rlp)?,
        nonce: u64::decode(&mut buf).map_err(map_rlp)?,
        max_priority_fee_per_gas: u128::decode(&mut buf).map_err(map_rlp)?,
        max_fee_per_gas: u128::decode(&mut buf).map_err(map_rlp)?,
        gas_limit: u64::decode(&mut buf).map_err(map_rlp)?,
        // EIP-7702 disallows contract creation, so `to` is a plain address.
        to: Address::decode(&mut buf).map_err(map_rlp)?,
        value: U256::decode(&mut buf).map_err(map_rlp)?,
        input: Bytes::decode(&mut buf).map_err(map_rlp)?,
        access_list: AccessList::decode(&mut buf).map_err(map_rlp)?,
        authorization_list: Vec::<SignedAuthorization>::decode(&mut buf).map_err(map_rlp)?,
    })
}

/// Decode an EIP-2718 typed transaction (data-type 4) by its leading type byte.
pub fn decode_typed_tx(sign_data: &[u8]) -> Result<DecodedTx, SignerError> {
    let (ty, rest) = sign_data
        .split_first()
        .ok_or_else(|| SignerError::InvalidTransaction("empty typed-tx sign-data".into()))?;
    match ty {
        0x02 => Ok(DecodedTx::Eip1559(decode_eip1559(rest)?)),
        0x04 => Ok(DecodedTx::Eip7702(decode_eip7702(rest)?)),
        other => Err(SignerError::InvalidTransaction(format!(
            "unsupported EIP-2718 transaction type 0x{other:02x}"
        ))),
    }
}
