//! Encoding of the ERC-4527 `eth-signature` CBOR.

use ciborium::value::{Integer, Value};

/// Encode an `eth-signature`: a CBOR map with `request-id` (key 1, uuid tag 37),
/// `signature` (key 2, `r||s||v`) and optional `origin` (key 3).
///
/// The signature is variable-length: `r (32) || s (32) || v`, where `v` is a
/// minimal big-endian integer (65 bytes for most cases, but e.g. 68 bytes for a
/// large-chain-id legacy EIP-155 transaction, or 64 bytes when `v == 0`).
pub fn encode_eth_signature(
    request_id: Option<[u8; 16]>,
    signature: &[u8],
    origin: Option<&str>,
) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    if let Some(id) = request_id {
        entries.push((int(1), Value::Tag(37, Box::new(Value::Bytes(id.to_vec())))));
    }
    entries.push((int(2), Value::Bytes(signature.to_vec())));
    if let Some(o) = origin {
        entries.push((int(3), Value::Text(o.to_owned())));
    }

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out)
        .expect("CBOR serialization to a Vec cannot fail");
    out
}

fn int(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}
