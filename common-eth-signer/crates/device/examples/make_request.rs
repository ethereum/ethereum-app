//! Print a sample `eth-sign-request` (EIP-191 "Hello, Bob!") as hex, for feeding
//! to the `device` binary:
//!
//!   REQ=$(cargo run -q --example make_request)
//!   echo y | cargo run -q -- "$REQ" 00000000000000000000000000000000

use alloy_primitives::address;
use ciborium::value::{Integer, Value};

fn int(n: i128) -> Value {
    Value::Integer(Integer::try_from(n).unwrap())
}

fn main() {
    // m/44'/60'/0'/0/0
    let comps = Value::Array(vec![
        int(44),
        Value::Bool(true),
        int(60),
        Value::Bool(true),
        int(0),
        Value::Bool(true),
        int(0),
        Value::Bool(false),
        int(0),
        Value::Bool(false),
    ]);
    let keypath = Value::Tag(304, Box::new(Value::Map(vec![(int(1), comps)])));
    // Address derived from the all-zero test entropy.
    let signer = address!("9858EfFD232B4033E47d90003D41EC34EcaEda94");

    let map = Value::Map(vec![
        (int(1), Value::Tag(37, Box::new(Value::Bytes(vec![0x42; 16])))),
        (int(2), Value::Bytes(b"Hello, Bob!".to_vec())),
        (int(3), int(3)), // data-type 3 = EIP-191 raw bytes
        (int(4), int(1)), // chain-id
        (int(5), keypath),
        (int(6), Value::Bytes(signer.to_vec())),
        (int(7), Value::Text("Example Wallet".into())),
    ]);

    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).unwrap();
    println!("{}", hex::encode(out));
}
