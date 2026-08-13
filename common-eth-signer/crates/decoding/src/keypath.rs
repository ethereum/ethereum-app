//! Decoding of the ERC-4527 `crypto-keypath` (derivation path).

use ciborium::value::Value;
use signer_core::{ChildNumber, DerivationPath, SignerError};

use crate::value::{as_array, as_int, as_map, err, get, untag};

/// Decode a `crypto-keypath` map into a [`DerivationPath`].
///
/// `components` (key 1) is a flat CBOR array alternating `child-index` and
/// `is-hardened`: `[i0, h0, i1, h1, ...]`. Only concrete indices are supported
/// (index ranges and wildcards are meaningless for a signing path).
pub fn decode_keypath(v: &Value) -> Result<DerivationPath, SignerError> {
    let map = as_map(v).ok_or_else(|| err("derivation-path is not a map"))?;
    let comps = get(map, 1).ok_or_else(|| err("keypath missing components (key 1)"))?;
    let arr = as_array(comps).ok_or_else(|| err("keypath components is not an array"))?;

    if arr.len() % 2 != 0 {
        return Err(err("keypath components must be index/hardened pairs"));
    }

    let mut components = Vec::with_capacity(arr.len() / 2);
    for pair in arr.chunks_exact(2) {
        let index =
            as_int(&pair[0]).ok_or_else(|| err("path index is not an integer (ranges/wildcards unsupported)"))?;
        if !(0..=0x7fff_ffff).contains(&index) {
            return Err(err("path index out of range"));
        }
        let hardened = match untag(&pair[1]) {
            Value::Bool(b) => *b,
            _ => return Err(err("path hardened flag is not a bool")),
        };
        components.push(ChildNumber {
            index: index as u32,
            hardened,
        });
    }

    Ok(DerivationPath { components })
}
