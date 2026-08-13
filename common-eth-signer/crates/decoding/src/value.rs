//! Helpers for walking a `ciborium::value::Value` leniently.
//!
//! ERC-4527's text and the Keystone `ur-registry-eth` reference implementation
//! disagree on whether several fields are wrapped in semantic CBOR tags
//! (e.g. data-type `#3.401`, keypath `#5.304`, uuid `#6.37`). We therefore
//! always strip tags before inspecting scalars, accepting both encodings.

use ciborium::value::Value;
use signer_core::SignerError;

pub fn err(msg: impl Into<String>) -> SignerError {
    SignerError::Decode(msg.into())
}

/// Strip any nested semantic CBOR tags, returning the inner value.
pub fn untag(v: &Value) -> &Value {
    let mut cur = v;
    while let Value::Tag(_, inner) = cur {
        cur = inner.as_ref();
    }
    cur
}

pub fn as_int(v: &Value) -> Option<i128> {
    match untag(v) {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

pub fn as_bytes(v: &Value) -> Option<&[u8]> {
    match untag(v) {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

pub fn as_text(v: &Value) -> Option<&str> {
    match untag(v) {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

pub fn as_map(v: &Value) -> Option<&[(Value, Value)]> {
    match untag(v) {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

pub fn as_array(v: &Value) -> Option<&[Value]> {
    match untag(v) {
        Value::Array(a) => Some(a),
        _ => None,
    }
}

/// Look up a map entry by integer key (keys may themselves be tagged).
pub fn get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| as_int(k) == Some(key))
        .map(|(_, v)| v)
}
