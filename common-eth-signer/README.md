# eth-signer

A prototype Ethereum signer for an embedded device, written in Rust and tested
on a Linux host. Given an [ERC-4527](../specs/erc-4527.md) `eth-sign-request`
(CBOR) and the signer's BIP-39 entropy, it decodes the request, derives the key,
displays the operation for user confirmation, signs it, and returns an
`eth-signature` (CBOR).

## Workspace

| Crate | Responsibility |
|-------|----------------|
| `signer-core` | Shared decoded types, [ERC-8213](../specs/erc-8213.md) digests, errors. The dependency-cycle breaker. |
| `signer-decoding` | CBOR `eth-sign-request` → typed `SignRequest`; `eth-signature` encoding. |
| `signer-signing` | BIP-39 entropy → BIP-32 key; per-kind signing hash; 65-byte `r‖s‖v`. |
| `signer-displaying` | Pure view-model + `ConfirmationUi` trait; headless / console / Slint backends. |
| `device` | End-to-end flow + the host test-scenario entry point + binary. |

Dependency graph: `signer-core` ← {decoding, signing, displaying} ← `device`.

## Flow

`decode → derive key & verify against request address → build view-model →
confirm (approve/reject) → sign → encode eth-signature`.

Supported payloads (ERC-4527 `data-type`):

- **1** legacy transaction (RLP)
- **2** EIP-712 typed data (shows readable JSON + EIP-712 Digest / Domain Hash / Message Hash)
- **3** EIP-191 `personal_sign` message (shows text, or hex if non-UTF-8)
- **4** EIP-2718 typed transaction: EIP-1559 (`0x02`), EIP-7702 (`0x04`), and
  EIP-8141 frame transactions (`0x06`)

Transactions display To, Value, Max fee (`gas_price × gas_limit`), Chain ID,
and — when calldata is present — the raw hex plus the ERC-8213 Calldata Digest.

Frame transactions (EIP-8141) additionally display the sender, nonce, the
three fee fields, the blob-hash count, every frame (mode, resolved target,
value, approval scope, atomic-batch marker, gas limits, and the ERC-8213
digest + length of the frame data) and every signature entry (scheme, resolved
signer, canonical-hash vs explicit-digest — the latter with a warning, since
an explicit-digest approval is not bound to the transaction's frames). The
device only signs the canonical `compute_sig_hash` (empty-`msg` semantics,
signature bytes elided per the EIP), only when a `SECP256K1` canonical-hash
entry resolves to the device key, and states whether it signs as the sender or
as a distinct co-signer (sponsor/payer flows). Filled `SECP256K1`
co-signatures are verified before signing.

> Scope: only the binary CBOR payload is handled. The ERC-4527 UR / animated-QR
> transport layer is out of scope (it belongs to the host/QR scanner).

## Build & test

```sh
cargo test --workspace        # headless; Slint is NOT compiled
```

Run the device interactively with the console UI (works on a headless host):

```sh
REQ=$(cargo run -q --example make_request -p device)
echo y | cargo run -q -p device -- "$REQ" 00000000000000000000000000000000
```

### Slint GUI (optional)

The declarative 480×800 UI lives behind the `slint` feature. It needs system
libraries for font handling:

```sh
sudo apt-get install -y pkg-config libfontconfig1-dev
cargo build -p device --features slint   # interactive run needs a display
```

Keeping Slint feature-gated means CI and automated tests build the entire flow
without any GUI system dependencies.

## Testing notes

- Decoding: transactions are cross-checked against alloy's own
  `encode_for_signing` output; CBOR tag leniency (bare vs `#304`/`#37`/`#401`)
  is exercised; the ERC-8213 Calldata Digest and EIP-712 Mail digests use the
  spec's published vectors.
- Signing: the all-zero BIP-39 entropy derives the well-known test address
  `0x9858…Eda94` at `m/44'/60'/0'/0/0`; every signature is recovered back to it.
- `v` convention (matches the Keystone reference; the signature is
  variable-length `r‖s‖v` with `v` as minimal big-endian):
  - legacy **EIP-155**: full `v = chain_id*2 + 35 + recovery_id` (multi-byte for
    large chain ids — e.g. 68-byte signature on Sepolia);
  - legacy pre-EIP-155: refused (`PreEip155Unsupported`);
  - EIP-2718 typed txs (1559 / 7702): `y_parity` (0/1);
  - EIP-191 and EIP-712: `{27, 28}`.
  Every signature is recovered back to the test address in the tests.
- **EIP-8141 frame transactions are the one exception to `r‖s‖v`**: the
  returned signature is the EIP's 65-byte signature-entry encoding
  `v (1) ‖ r (32) ‖ s (32)` with `v` the recovery id (0/1, never 27/28 or
  EIP-155) and canonical low-s, so the wallet can place it verbatim into the
  entry's `signature` field.
