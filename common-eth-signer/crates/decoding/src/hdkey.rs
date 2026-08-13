//! Encoding of the ERC-4527 `crypto-hdkey` CBOR (BCR-2020-007).
//!
//! Used by an offline signer to hand its extended public key to a watch-only
//! wallet, which then derives child addresses and builds `eth-sign-request`s.

use ciborium::value::{Integer, Value};
use signer_core::DerivationPath;

/// CBOR tag for an embedded `crypto-keypath` (per the ERC-4527 CDDL).
const CRYPTO_KEYPATH_TAG: u64 = 304;

/// Encode a `crypto-hdkey`: a CBOR map with `key-data` (key 3, 33-byte
/// compressed public key), `chain-code` (key 4, 32 bytes), `origin` (key 6,
/// tag 304 `crypto-keypath`) and optional `name` (key 9) / `source` (key 10).
///
/// The origin keypath carries `components` (key 1, flat `[index, hardened,
/// ...]` pairs), `source-fingerprint` (key 2, fingerprint of the master key
/// the path starts from) and `depth` (key 3).
pub fn encode_crypto_hdkey(
    key_data: &[u8; 33],
    chain_code: &[u8; 32],
    origin: &DerivationPath,
    source_fingerprint: u32,
    name: Option<&str>,
    source: Option<&str>,
) -> Vec<u8> {
    let mut components: Vec<Value> = Vec::with_capacity(origin.components.len() * 2);
    for component in &origin.components {
        components.push(int(component.index as u64));
        components.push(Value::Bool(component.hardened));
    }

    let keypath: Vec<(Value, Value)> = vec![
        (int(1), Value::Array(components)),
        (int(2), int(source_fingerprint as u64)),
        (int(3), int(origin.components.len() as u64)),
    ];

    let mut entries: Vec<(Value, Value)> = vec![
        (int(3), Value::Bytes(key_data.to_vec())),
        (int(4), Value::Bytes(chain_code.to_vec())),
        (int(6), Value::Tag(CRYPTO_KEYPATH_TAG, Box::new(Value::Map(keypath)))),
    ];
    if let Some(n) = name {
        entries.push((int(9), Value::Text(n.to_owned())));
    }
    if let Some(s) = source {
        entries.push((int(10), Value::Text(s.to_owned())));
    }

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out)
        .expect("CBOR serialization to a Vec cannot fail");
    out
}

fn int(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypath::decode_keypath;
    use signer_core::ChildNumber;

    fn eth_origin(account: u32) -> DerivationPath {
        DerivationPath {
            components: vec![
                ChildNumber { index: 44, hardened: true },
                ChildNumber { index: 60, hardened: true },
                ChildNumber { index: account, hardened: true },
            ],
        }
    }

    #[test]
    fn roundtrips_through_cbor() {
        let key_data = [2u8; 33];
        let chain_code = [7u8; 32];
        let cbor = encode_crypto_hdkey(
            &key_data,
            &chain_code,
            &eth_origin(1),
            0xdead_beef,
            Some("Savings"),
            Some("Passport Prime"),
        );

        let value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        let map = value.as_map().unwrap();
        let get = |k: u64| {
            map.iter()
                .find(|(key, _)| key.as_integer() == Some(Integer::from(k)))
                .map(|(_, v)| v)
        };

        assert_eq!(get(3).unwrap().as_bytes().unwrap(), &key_data);
        assert_eq!(get(4).unwrap().as_bytes().unwrap(), &chain_code);
        assert_eq!(get(9).unwrap().as_text().unwrap(), "Savings");
        assert_eq!(get(10).unwrap().as_text().unwrap(), "Passport Prime");

        let (tag, keypath) = get(6).unwrap().as_tag().unwrap();
        assert_eq!(tag, CRYPTO_KEYPATH_TAG);
        // The origin decodes back with the project's own keypath decoder.
        let path = decode_keypath(keypath).unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/1'");

        let keypath_map = keypath.as_map().unwrap();
        let kp = |k: u64| {
            keypath_map
                .iter()
                .find(|(key, _)| key.as_integer() == Some(Integer::from(k)))
                .map(|(_, v)| v)
        };
        assert_eq!(kp(2).unwrap().as_integer().unwrap(), Integer::from(0xdead_beefu64));
        assert_eq!(kp(3).unwrap().as_integer().unwrap(), Integer::from(3));
    }

    #[test]
    fn optional_fields_are_omitted() {
        let cbor =
            encode_crypto_hdkey(&[2u8; 33], &[7u8; 32], &eth_origin(0), 1, None, None);
        let value: Value = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(value.as_map().unwrap().len(), 3);
    }
}
