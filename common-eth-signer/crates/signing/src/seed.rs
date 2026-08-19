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

/// An account-level extended key (e.g. at m/44'/60'/account'), kept resident so
/// that many child addresses can be derived without re-running the expensive
/// BIP-39 seed stretch (PBKDF2) for each one. Also carries what a
/// `crypto-hdkey` export (ERC-4527 wallet connection) needs: the compressed
/// public key, chain code, and master key fingerprint.
pub struct AccountKey {
    xprv: XPrv,
    master_fingerprint: [u8; 4],
}

impl AccountKey {
    pub fn from_entropy(entropy: &[u8], path: &DerivationPath) -> Result<Self, SignerError> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(derivation_err)?;
        let seed = mnemonic.to_seed("");
        let mut xprv = XPrv::new(seed).map_err(derivation_err)?;
        let master_fingerprint = xprv.public_key().fingerprint();
        for component in &path.components {
            let child = bip32::ChildNumber::new(component.index, component.hardened)
                .map_err(derivation_err)?;
            xprv = xprv.derive_child(child).map_err(derivation_err)?;
        }
        Ok(AccountKey { xprv, master_fingerprint })
    }

    /// Compressed (33-byte) public key of the account node.
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.xprv.public_key().to_bytes()
    }

    pub fn chain_code(&self) -> [u8; 32] {
        self.xprv.attrs().chain_code
    }

    /// Fingerprint of the master key this account was derived from
    /// (the `source-fingerprint` of a crypto-keypath).
    pub fn master_fingerprint(&self) -> u32 {
        u32::from_be_bytes(self.master_fingerprint)
    }

    /// Address at `<account>/change/index` (non-hardened, so watch-only
    /// wallets holding the exported xpub can derive the same addresses).
    pub fn address(&self, change: u32, index: u32) -> Result<Address, SignerError> {
        let mut xprv = self
            .xprv
            .derive_child(bip32::ChildNumber::new(change, false).map_err(derivation_err)?)
            .map_err(derivation_err)?;
        xprv = xprv
            .derive_child(bip32::ChildNumber::new(index, false).map_err(derivation_err)?)
            .map_err(derivation_err)?;
        Ok(address_of(xprv.private_key()))
    }
}
