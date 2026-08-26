//! BIP-39 entropy -> seed -> BIP-32 derivation -> secp256k1 signing key.
//!
//! The seed is the real input: a signer that stores an already-expanded seed,
//! or applies a BIP-39 passphrase, never holds the entropy the `*_from_entropy`
//! forms need. Those are wrappers over the seed forms with an empty passphrase.

use alloy_primitives::{keccak256, Address};
use bip39::Mnemonic;
use bip32::XPrv;
use k256::ecdsa::{SigningKey, VerifyingKey};
use signer_core::{DerivationPath, SignerError};

fn derivation_err(e: impl ToString) -> SignerError {
    SignerError::Derivation(e.to_string())
}

/// Expand BIP-39 entropy into the 64-byte BIP-32 seed under `passphrase`.
///
/// An empty passphrase is the plain BIP-39 seed. This is the expensive step
/// (PBKDF2), so a caller deriving many keys should do it once.
pub fn seed_from_entropy(entropy: &[u8], passphrase: &str) -> Result<[u8; 64], SignerError> {
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(derivation_err)?;
    Ok(mnemonic.to_seed(passphrase))
}

/// Walk `path` from an extended key.
fn derive(mut xprv: XPrv, path: &DerivationPath) -> Result<XPrv, SignerError> {
    for component in &path.components {
        let child = bip32::ChildNumber::new(component.index, component.hardened)
            .map_err(derivation_err)?;
        xprv = xprv.derive_child(child).map_err(derivation_err)?;
    }
    Ok(xprv)
}

/// Derive the secp256k1 signing key for `path` from a 64-byte BIP-32 seed.
pub fn key_from_seed(seed: &[u8; 64], path: &DerivationPath) -> Result<SigningKey, SignerError> {
    let xprv = derive(XPrv::new(seed).map_err(derivation_err)?, path)?;
    Ok(xprv.private_key().clone())
}

/// Derive the secp256k1 signing key for `path` from raw BIP-39 entropy, with no
/// passphrase. Compose [`seed_from_entropy`] with [`key_from_seed`] to use one.
pub fn key_from_entropy(entropy: &[u8], path: &DerivationPath) -> Result<SigningKey, SignerError> {
    key_from_seed(&seed_from_entropy(entropy, "")?, path)
}

/// The Ethereum address for a public key: last 20 bytes of
/// `keccak256(uncompressed_public_key[1..])`.
pub fn address_of_public(key: &VerifyingKey) -> Address {
    let encoded = key.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

/// The Ethereum address for a signing key.
pub fn address_of(key: &SigningKey) -> Address {
    address_of_public(key.verifying_key())
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
    /// Derive the account node at `path` from a 64-byte BIP-32 seed.
    pub fn from_seed(seed: &[u8; 64], path: &DerivationPath) -> Result<Self, SignerError> {
        let master = XPrv::new(seed).map_err(derivation_err)?;
        let master_fingerprint = master.public_key().fingerprint();
        Ok(AccountKey { xprv: derive(master, path)?, master_fingerprint })
    }

    /// As [`AccountKey::from_seed`], from raw BIP-39 entropy with no passphrase.
    pub fn from_entropy(entropy: &[u8], path: &DerivationPath) -> Result<Self, SignerError> {
        Self::from_seed(&seed_from_entropy(entropy, "")?, path)
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

    /// The same fingerprint as the four bytes BIP-32 defines it to be, for a
    /// caller that renders or transmits it rather than doing arithmetic on it.
    pub fn master_fingerprint_bytes(&self) -> [u8; 4] {
        self.master_fingerprint
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

/// The same account node as [`AccountKey`], reconstructed from its **public**
/// parts alone: the compressed public key and chain code that a key custodian
/// hands out (KeyOS's `os/ethereum-signer` returns exactly this pair from
/// `GetAccountKey`).
///
/// It derives the non-hardened `change/index` children under the account, which
/// is every address a BIP-44 wallet shows, without any private key in reach.
/// [`AccountKey`] is the private-key twin; the two agree by construction and a
/// test pins that.
pub struct AccountXpub {
    xpub: bip32::XPub,
}

impl AccountXpub {
    /// Rebuild the node from a compressed SEC1 public key and its chain code.
    ///
    /// Only the chain code and the key take part in non-hardened derivation, so
    /// the remaining BIP-32 attributes (depth, parent fingerprint, child number)
    /// are placeholders: they would only matter to a serialiser, and this type
    /// never serialises itself.
    pub fn from_parts(public_key: &[u8; 33], chain_code: [u8; 32]) -> Result<Self, SignerError> {
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(derivation_err)?;
        let attrs = bip32::ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: bip32::ChildNumber::new(0, false).map_err(derivation_err)?,
            chain_code,
        };
        Ok(AccountXpub { xpub: bip32::XPub::new(key, attrs) })
    }

    /// Address at `<account>/change/index`.
    pub fn address(&self, change: u32, index: u32) -> Result<Address, SignerError> {
        let mut xpub = self
            .xpub
            .derive_child(bip32::ChildNumber::new(change, false).map_err(derivation_err)?)
            .map_err(derivation_err)?;
        xpub = xpub
            .derive_child(bip32::ChildNumber::new(index, false).map_err(derivation_err)?)
            .map_err(derivation_err)?;
        Ok(address_of_public(xpub.public_key()))
    }
}
