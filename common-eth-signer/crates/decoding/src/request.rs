//! Top-level decoding of the ERC-4527 `eth-sign-request` CBOR.

use alloy_dyn_abi::TypedData;
use alloy_primitives::Address;
use ciborium::value::Value;
use signer_core::{
    eip712_digests, MessageKind, PersonalMessage, SignRequest, SignerError, TypedData712,
};

use crate::keypath::decode_keypath;
use crate::tx::{decode_legacy, decode_typed_tx};
use crate::value::{as_bytes, as_int, as_map, as_text, err, get, untag};

// ERC-4527 `sign-data-type` values.
const DATA_TYPE_LEGACY: i128 = 1;
const DATA_TYPE_TYPED_DATA: i128 = 2;
const DATA_TYPE_RAW_BYTES: i128 = 3;
const DATA_TYPE_TYPED_TX: i128 = 4;

/// Decode the CBOR bytes of an `eth-sign-request` into a [`SignRequest`].
pub fn decode_sign_request(cbor: &[u8]) -> Result<SignRequest, SignerError> {
    let value: Value =
        ciborium::from_reader(cbor).map_err(|e| err(format!("invalid CBOR: {e}")))?;
    let map = as_map(&value).ok_or_else(|| err("eth-sign-request is not a CBOR map"))?;

    // sign-data (key 2, required)
    let sign_data = as_bytes(get(map, 2).ok_or_else(|| err("missing sign-data (key 2)"))?)
        .ok_or_else(|| err("sign-data is not a byte string"))?
        .to_vec();

    // data-type (key 3, required)
    let data_type =
        decode_data_type(get(map, 3).ok_or_else(|| err("missing data-type (key 3)"))?)?;

    // chain-id (key 4, optional). Absent and explicit values are kept
    // distinct: an explicit chain-id must match the transaction body (checked
    // below), while an absent one skips only that equality check.
    let chain_id = match get(map, 4) {
        Some(v) => {
            let i = as_int(v).ok_or_else(|| err("chain-id is not an integer"))?;
            Some(u64::try_from(i).map_err(|_| err("chain-id out of range"))?)
        }
        None => None,
    };

    // derivation-path (key 5, required)
    let derivation_path =
        decode_keypath(get(map, 5).ok_or_else(|| err("missing derivation-path (key 5)"))?)?;

    // request-id (key 1, optional)
    let request_id = match get(map, 1) {
        Some(v) => {
            let b = as_bytes(v).ok_or_else(|| err("request-id is not a byte string"))?;
            let arr: [u8; 16] = b
                .try_into()
                .map_err(|_| err("request-id must be 16 bytes"))?;
            Some(arr)
        }
        None => None,
    };

    // address (key 6, optional)
    let address = match get(map, 6) {
        Some(v) => {
            let b = as_bytes(v).ok_or_else(|| err("address is not a byte string"))?;
            let arr: [u8; 20] = b.try_into().map_err(|_| err("address must be 20 bytes"))?;
            Some(Address::from(arr))
        }
        None => None,
    };

    // origin (key 7, optional)
    let origin = match get(map, 7) {
        Some(v) => Some(
            as_text(v)
                .ok_or_else(|| err("origin is not text"))?
                .to_owned(),
        ),
        None => None,
    };

    let message = decode_message(data_type, &sign_data)?;

    let request = SignRequest {
        request_id,
        chain_id,
        derivation_path,
        address,
        origin,
        raw_sign_data: sign_data,
        message,
    };

    // Fail closed at the boundary: the envelope chain-id must agree with the
    // chain id inside the transaction the signature commits to (and
    // pre-EIP-155 legacy transactions are refused as replayable-anywhere).
    request.validate_chain_binding()?;

    Ok(request)
}

/// `data-type` may be a bare integer (Keystone) or a `#3.401`-tagged
/// `sign-data-type` map `{ type: int }` (EIP text). Accept both.
fn decode_data_type(v: &Value) -> Result<i128, SignerError> {
    let inner = untag(v);
    if let Some(i) = as_int(inner) {
        return Ok(i);
    }
    if let Value::Map(m) = inner {
        if let Some((_, val)) = m.first() {
            if let Some(i) = as_int(val) {
                return Ok(i);
            }
        }
    }
    Err(err("data-type is neither an integer nor a recognizable map"))
}

fn decode_message(data_type: i128, sign_data: &[u8]) -> Result<MessageKind, SignerError> {
    match data_type {
        DATA_TYPE_LEGACY => Ok(MessageKind::Transaction(
            signer_core::DecodedTx::Legacy(decode_legacy(sign_data)?),
        )),
        DATA_TYPE_TYPED_TX => Ok(MessageKind::Transaction(decode_typed_tx(sign_data)?)),
        DATA_TYPE_RAW_BYTES => Ok(MessageKind::Eip191(PersonalMessage::new(sign_data.to_vec()))),
        DATA_TYPE_TYPED_DATA => Ok(MessageKind::Eip712(decode_typed_data(sign_data)?)),
        other => Err(SignerError::UnsupportedDataType(other as u64)),
    }
}

fn decode_typed_data(sign_data: &[u8]) -> Result<TypedData712, SignerError> {
    let json = core::str::from_utf8(sign_data)
        .map_err(|_| SignerError::InvalidTypedData("sign-data is not valid UTF-8".into()))?
        .to_owned();
    let typed_data: TypedData =
        serde_json::from_str(&json).map_err(|e| SignerError::InvalidTypedData(e.to_string()))?;
    let (eip712_digest, domain_hash, message_hash) = eip712_digests(&typed_data)?;
    Ok(TypedData712 {
        json,
        typed_data,
        eip712_digest,
        domain_hash,
        message_hash,
    })
}
