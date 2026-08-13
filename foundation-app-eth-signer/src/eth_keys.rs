// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Ethereum key derivation on top of `signer-signing`.
//!
//! The canonical pipeline (`signer_signing::key_from_entropy`) runs the full
//! BIP-39 PBKDF2 seed expansion plus the whole BIP-32 chain on every call —
//! too slow to run once per row while the address list scrolls. `KeyCache`
//! pays the PBKDF2 once at startup, keeps the coin-level xprv for m/44'/60'
//! in memory, and derives account'/0/i per address (three cheap child
//! derivations). A unit test pins this fast path to the canonical pipeline.
//!
//! Account #j owns addresses m/44'/60'/j'/0/i (BIP-44 account level).
//!
//! Nothing here is ever persisted; the cache is memory-only and derived from
//! the app seed on each launch.

use alloy_primitives::Address;
use anyhow::Context;
use bip32::XPrv;
use bip39::Mnemonic;
use signer_core::{ChildNumber, DerivationPath};

/// m/44'/60' — the coin-level prefix; account j appends /j'/0, address i /i.
const COIN_PATH: [(u32, bool); 2] = [(44, true), (60, true)];

pub struct KeyCache {
    /// xprv for m/44'/60'.
    coin: XPrv,
    /// BIP-32 fingerprint of the master key, hex-encoded (shown in account
    /// details, mirroring the Bitcoin app's fingerprint row).
    master_fingerprint: String,
}

impl KeyCache {
    /// Derive the cache from raw BIP-39 entropy plus an optional BIP-39
    /// passphrase (empty string for the default wallet).
    pub fn init(entropy: &[u8], passphrase: &str) -> anyhow::Result<Self> {
        let mnemonic = Mnemonic::from_entropy(entropy).context("invalid entropy")?;
        let seed = mnemonic.to_seed(passphrase);

        let master = XPrv::new(seed).context("bip32 master")?;
        let master_fingerprint = hex::encode(master.public_key().fingerprint());

        let mut coin = master;
        for (index, hardened) in COIN_PATH {
            let child = bip32::ChildNumber::new(index, hardened).context("child number")?;
            coin = coin.derive_child(child).context("derive coin level")?;
        }

        Ok(Self { coin, master_fingerprint })
    }

    pub fn master_fingerprint(&self) -> &str {
        &self.master_fingerprint
    }

    /// Master fingerprint as the u32 used by `crypto-keypath`'s
    /// source-fingerprint field.
    pub fn master_fingerprint_u32(&self) -> u32 {
        let mut bytes = [0u8; 4];
        hex::decode_to_slice(&self.master_fingerprint, &mut bytes)
            .expect("fingerprint is 4 hex-encoded bytes");
        u32::from_be_bytes(bytes)
    }

    /// The account-level extended public key for m/44'/60'/account':
    /// (compressed public key, chain code). This is what a watch-only wallet
    /// needs to derive the 0/i child addresses (ERC-4527 `crypto-hdkey`).
    pub fn account_hdkey(&self, account: u32) -> anyhow::Result<([u8; 33], [u8; 32])> {
        let child = bip32::ChildNumber::new(account, true).context("child number")?;
        let xprv = self.coin.derive_child(child).context("derive account level")?;
        let xpub = xprv.public_key();
        Ok((xpub.to_bytes(), xpub.attrs().chain_code))
    }

    /// The origin keypath for account's hdkey: m/44'/60'/account'.
    pub fn account_origin(account: u32) -> DerivationPath {
        let mut components: Vec<ChildNumber> = COIN_PATH
            .iter()
            .map(|&(index, hardened)| ChildNumber { index, hardened })
            .collect();
        components.push(ChildNumber { index: account, hardened: true });
        DerivationPath { components }
    }

    /// The full path for account `j`, address index `i`, for display and
    /// future signing.
    #[allow(dead_code)] // exercised by tests today; the signing flow will use it
    pub fn path_for(account: u32, i: u32) -> DerivationPath {
        let mut components: Vec<ChildNumber> = COIN_PATH
            .iter()
            .map(|&(index, hardened)| ChildNumber { index, hardened })
            .collect();
        components.push(ChildNumber { index: account, hardened: true });
        components.push(ChildNumber { index: 0, hardened: false });
        components.push(ChildNumber { index: i, hardened: false });
        DerivationPath { components }
    }

    /// The signing key for a request's derivation path. Only paths under this
    /// wallet's m/44'/60' prefix can be served from the cached coin xprv;
    /// anything else is refused rather than silently mis-derived.
    pub fn signing_key(&self, path: &DerivationPath) -> anyhow::Result<k256::ecdsa::SigningKey> {
        let prefix_ok = path.components.len() >= COIN_PATH.len()
            && COIN_PATH.iter().zip(&path.components).all(|(&(index, hardened), c)| {
                c.index == index && c.hardened == hardened
            });
        if !prefix_ok {
            anyhow::bail!("unsupported derivation path {path}: expected an m/44'/60' prefix");
        }

        let mut xprv = self.coin.clone();
        for component in &path.components[COIN_PATH.len()..] {
            let child = bip32::ChildNumber::new(component.index, component.hardened)
                .context("child number")?;
            xprv = xprv.derive_child(child).context("derive request path")?;
        }
        Ok(xprv.private_key().clone())
    }

    fn address_at(&self, account: u32, i: u32) -> anyhow::Result<Address> {
        let mut xprv = self.coin.clone();
        for (index, hardened) in [(account, true), (0, false), (i, false)] {
            let child = bip32::ChildNumber::new(index, hardened).context("child number")?;
            xprv = xprv.derive_child(child).context("derive address")?;
        }
        Ok(signer_signing::address_of(xprv.private_key()))
    }

    /// EIP-55 checksummed address for m/44'/60'/account'/0/i.
    pub fn address(&self, account: u32, i: u32) -> anyhow::Result<String> {
        Ok(self.address_at(account, i)?.to_checksum(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signer_signing::{address_of, key_from_entropy};

    #[test]
    fn fast_path_matches_canonical_pipeline() {
        let entropy = [7u8; 32];
        let cache = KeyCache::init(&entropy, "").unwrap();
        for (account, i) in [(0u32, 0u32), (0, 1), (1, 3), (5, 100)] {
            let canonical =
                address_of(&key_from_entropy(&entropy, &KeyCache::path_for(account, i)).unwrap());
            assert_eq!(cache.address(account, i).unwrap(), canonical.to_checksum(None));
        }
    }

    #[test]
    fn known_vector() {
        // 16 zero bytes -> "abandon ... about"; m/44'/60'/0'/0/0 is the
        // standard test vector address.
        let cache = KeyCache::init(&[0u8; 16], "").unwrap();
        assert_eq!(cache.address(0, 0).unwrap(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn accounts_differ() {
        let cache = KeyCache::init(&[7u8; 32], "").unwrap();
        assert_ne!(cache.address(0, 0).unwrap(), cache.address(1, 0).unwrap());
    }

    #[test]
    fn passphrase_changes_the_wallet() {
        let entropy = [7u8; 32];
        let default = KeyCache::init(&entropy, "").unwrap();
        let passphrased = KeyCache::init(&entropy, "hunter2").unwrap();
        assert_ne!(default.master_fingerprint(), passphrased.master_fingerprint());
        assert_ne!(default.address(0, 0).unwrap(), passphrased.address(0, 0).unwrap());
    }

    #[test]
    fn path_formatting() {
        assert_eq!(KeyCache::path_for(2, 3).to_string(), "m/44'/60'/2'/0/3");
        assert_eq!(KeyCache::account_origin(2).to_string(), "m/44'/60'/2'");
    }

    #[test]
    fn signing_key_matches_canonical_pipeline() {
        let entropy = [7u8; 32];
        let cache = KeyCache::init(&entropy, "").unwrap();
        let path = KeyCache::path_for(1, 3);
        let fast = cache.signing_key(&path).unwrap();
        let canonical = key_from_entropy(&entropy, &path).unwrap();
        assert_eq!(fast.to_bytes(), canonical.to_bytes());

        // A non-Ethereum path is refused.
        let foreign = DerivationPath {
            components: vec![
                ChildNumber { index: 44, hardened: true },
                ChildNumber { index: 0, hardened: true },
            ],
        };
        assert!(cache.signing_key(&foreign).is_err());
    }

    #[test]
    fn hdkey_matches_canonical_account_key() {
        let entropy = [7u8; 32];
        let cache = KeyCache::init(&entropy, "").unwrap();
        for account in [0u32, 1] {
            let (key_data, chain_code) = cache.account_hdkey(account).unwrap();
            let canonical =
                key_from_entropy(&entropy, &KeyCache::account_origin(account)).unwrap();
            let expected = canonical.verifying_key().to_encoded_point(true);
            assert_eq!(key_data.as_slice(), expected.as_bytes());
            assert_ne!(chain_code, [0u8; 32]);
        }
    }
}
