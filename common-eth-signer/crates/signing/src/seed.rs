//! BIP-39 entropy -> seed -> BIP-32 derivation -> secp256k1 signing key.

use alloy_primitives::{keccak256, Address};
use bip39::Mnemonic;
use bip32::XPrv;
use k256::ecdsa::SigningKey;
use signer_core::{DerivationPath, SignerError};

fn derivation_err(e: impl ToString) -> SignerError {
    SignerError::Derivation(e.to_string())
}

/// Derive the secp256k1 signing key for `path` from raw BIP-39 entropy.
///
/// Path: entropy -> mnemonic (`from_entropy`) -> 64-byte seed (`to_seed`, empty
/// passphrase) -> BIP-32 master key -> child derivation.
pub fn key_from_entropy(entropy: &[u8], path: &DerivationPath) -> Result<SigningKey, SignerError> {
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(derivation_err)?;
    let seed = mnemonic.to_seed("");

    let mut xprv = XPrv::new(seed).map_err(derivation_err)?;
    for component in &path.components {
        let child = bip32::ChildNumber::new(component.index, component.hardened)
            .map_err(derivation_err)?;
        xprv = xprv.derive_child(child).map_err(derivation_err)?;
    }
    Ok(xprv.private_key().clone())
}

/// The Ethereum address for a signing key: last 20 bytes of
/// `keccak256(uncompressed_public_key[1..])`.
pub fn address_of(key: &SigningKey) -> Address {
    let encoded = key.verifying_key().to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}
