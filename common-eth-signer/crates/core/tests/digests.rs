use alloy_dyn_abi::TypedData;
use signer_core::{calldata_digest, eip712_digests};

#[test]
fn calldata_digest_matches_erc8213_vector() {
    // ERC-20 transfer(address,uint256) calldata from ERC-8213 §Test Cases.
    let calldata = hex::decode(
        "a9059cbb\
         0000000000000000000000004675c7e5baafbffbca748158becba61ef3b0a263\
         0000000000000000000000000000000000000000000000000de0b6b3a7640000",
    )
    .unwrap();
    assert_eq!(calldata.len(), 68);

    let digest = calldata_digest(&calldata);
    assert_eq!(
        hex::encode(digest),
        "812cee5d9cc7461c04bbcd7b70af9c28b243ac5d74d3453b008b93b7dac69985"
    );
}

#[test]
fn calldata_digest_empty() {
    // keccak256(uint256(0)) — sanity check the length-prefix path on empty input.
    let digest = calldata_digest(&[]);
    assert_eq!(
        hex::encode(digest),
        "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
    );
}

#[test]
fn eip712_digests_match_mail_example() {
    // Canonical "Mail" example from the EIP-712 specification.
    let json = r#"{
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    let td: TypedData = serde_json::from_str(json).unwrap();
    let (digest, domain_hash, message_hash) = eip712_digests(&td).unwrap();

    // Well-known reference values for the Mail example.
    assert_eq!(
        hex::encode(domain_hash),
        "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    );
    assert_eq!(
        hex::encode(message_hash),
        "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    );
    assert_eq!(
        hex::encode(digest),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
}
