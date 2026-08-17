"""Generate ERC-4527 UR test vectors for the ur-bridge HTML tool and the device.

CBOR payloads come from common-eth-signer (the make_request example and the
encode_eth_signature / encode_crypto_hdkey functions), so anything that decodes
these vectors is compatible with the signing stack the device will use.

Outputs test-vectors.json next to this script. Run urlib.py first (or trust
that this module runs its self-test on import via main).
"""

import json
import os
import uuid

import urlib

HERE = os.path.dirname(os.path.abspath(__file__))

# eth-sign-request produced by `cargo run --example make_request -p device`
# in /workspace/common-eth-signer: EIP-191 personal message "Hello, Bob!",
# path m/44'/60'/0'/0/0, request-id 42424242..., origin "Example Wallet".
SIGN_REQUEST_SMALL = bytes.fromhex(
    "a701d8255042424242424242424242424242424242024b48656c6c6f2c20426f6221030304"
    "0105d90130a1018a182cf5183cf500f500f400f406549858effd232b4033e47d90003d41ec"
    "34ecaeda94076e4578616d706c652057616c6c6574"
)

# eth-signature / crypto-hdkey produced by signer-decoding's encoders
# (see the vector-helper scratch crate in the session notes).
ETH_SIGNATURE = bytes.fromhex(
    "a301d8255042424242424242424242424242424242025841000102030405060708090a0b0c"
    "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"
    "32333435363738393a3b3c3d3e3f1b036f646333342d6574682d7369676e6572"
)
CRYPTO_HDKEY = bytes.fromhex(
    "a5035821030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "045820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf06d9"
    "0130a30186182cf5183cf500f5021ad90cfea103030964646333340a6f646333342d657468"
    "2d7369676e6572"
)


def cbor_text(s: str) -> bytes:
    b = s.encode()
    header = urlib.cbor_uint(len(b))
    return bytes([0x60 | header[0]]) + header[1:] + b


def cbor_tag(tag: int, content: bytes) -> bytes:
    header = urlib.cbor_uint(tag)
    return bytes([0xC0 | header[0]]) + header[1:] + content


def keypath_m44600_00() -> bytes:
    # crypto-keypath {1: [44,true,60,true,0,true,0,false,0,false]}
    components = b"\x8a" + b"".join(
        urlib.cbor_uint(i) + (b"\xf5" if h else b"\xf4")
        for i, h in [(44, True), (60, True), (0, True), (0, False), (0, False)]
    )
    return cbor_tag(304, b"\xa1\x01" + components)


TX_TRANSFER = bytes.fromhex(
    "02f001078459682f008506fc23ac008252089468b3465833fb72a70ecdf485e0e4c7bd8665"
    "fc458806f05b59d3b2000080c0"
)
TX_ERC20 = bytes.fromhex(
    "02f86d0108843b9aca008505d21dba0082fde894a0b86991c6218b36c1d19d4a2e9eb0ce36"
    "06eb4880b844a9059cbb0000000000000000000000009858effd232b4033e47d90003d41ec"
    "34ecaeda94000000000000000000000000000000000000000000000000000000003b9aca00"
    "c0"
)


def make_tx_sign_request(tx_payload: bytes, request_id_byte: int) -> bytes:
    """eth-sign-request with data-type 4 (eth-typed-transaction), chain 1,
    path m/44'/60'/0'/0/0 and the matching zero-entropy test-seed address."""
    body = (
        b"\xa7"
        + b"\x01" + cbor_tag(37, urlib.cbor_bytes(bytes([request_id_byte]) * 16))
        + b"\x02" + urlib.cbor_bytes(tx_payload)
        + b"\x03" + urlib.cbor_uint(4)  # eth-typed-transaction
        + b"\x04" + urlib.cbor_uint(1)  # chain id
        + b"\x05" + keypath_m44600_00()
        + b"\x06" + urlib.cbor_bytes(bytes.fromhex("9858EfFD232B4033E47d90003D41EC34EcaEda94".replace("0x", "")))
        + b"\x07" + cbor_text("UR Bridge Test")
    )
    return body


def make_large_sign_request() -> bytes:
    """EIP-712 typed-data eth-sign-request large enough to need several parts."""
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        },
        "message": {
            "owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "spender": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
            "value": "1000000000000000000",
            "nonce": "0",
            "deadline": "1893456000",
        },
    }
    sign_data = json.dumps(typed_data, separators=(",", ":")).encode()
    request_id = uuid.UUID("6c3a3c3e-8a2b-4e6f-9d10-5152535455aa").bytes
    body = (
        b"\xa7"
        + b"\x01" + cbor_tag(37, urlib.cbor_bytes(request_id))
        + b"\x02" + urlib.cbor_bytes(sign_data)
        + b"\x03" + urlib.cbor_uint(2)  # eth-typed-data
        + b"\x04" + urlib.cbor_uint(1)  # chain id
        + b"\x05" + keypath_m44600_00()
        + b"\x06" + urlib.cbor_bytes(bytes.fromhex("9858EfFD232B4033E47d90003D41EC34EcaEda94".replace("0x", "")))
        + b"\x07" + cbor_text("UR Bridge Test")
    )
    return body


def vector(name, description, ur_type, cbor: bytes, max_fragment_len):
    parts = urlib.ur_encode(ur_type, cbor, max_fragment_len)
    return {
        "name": name,
        "description": description,
        "urType": ur_type,
        "cborHex": cbor.hex(),
        "maxFragmentLen": max_fragment_len,
        "parts": [p.upper() for p in parts],
    }


def main():
    urlib.self_test()
    large = make_large_sign_request()
    vectors = [
        vector(
            "sign-request-small-single",
            "EIP-191 'Hello, Bob!' request as one QR (from common-eth-signer make_request)",
            "eth-sign-request", SIGN_REQUEST_SMALL, None,
        ),
        vector(
            "sign-request-small-3parts",
            "Same request forced into 3 parts (fragment cap 40 bytes)",
            "eth-sign-request", SIGN_REQUEST_SMALL, 40,
        ),
        vector(
            "sign-request-eip712-multipart",
            "EIP-712 Permit typed-data request, splits at 100-byte fragments",
            "eth-sign-request", large, 100,
        ),
        vector(
            "tx-eip1559-transfer",
            "EIP-1559 0.5 ETH transfer (data-type 4), signable by the zero-entropy test seed",
            "eth-sign-request", make_tx_sign_request(TX_TRANSFER, 0x51), None,
        ),
        vector(
            "tx-eip1559-erc20",
            "EIP-1559 ERC-20 transfer call with calldata (exercises the 8213 data hash)",
            "eth-sign-request", make_tx_sign_request(TX_ERC20, 0x52), 80,
        ),
        vector(
            "eth-signature-single",
            "eth-signature response (from signer-decoding encode_eth_signature)",
            "eth-signature", ETH_SIGNATURE, None,
        ),
        vector(
            "crypto-hdkey-single",
            "crypto-hdkey xpub export m/44'/60'/0' (from signer-decoding encode_crypto_hdkey)",
            "crypto-hdkey", CRYPTO_HDKEY, None,
        ),
    ]
    out = os.path.join(HERE, "test-vectors.json")
    with open(out, "w") as f:
        json.dump(vectors, f, indent=2)
    print("wrote", out)
    for v in vectors:
        print("  %-32s %d part(s), cbor %d bytes" % (v["name"], len(v["parts"]), len(v["cborHex"]) // 2))
    print("large request hex (validate with vector-helper):")
    print(large.hex())


if __name__ == "__main__":
    main()
