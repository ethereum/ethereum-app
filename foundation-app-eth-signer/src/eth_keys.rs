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
    /// Derive the cache from raw BIP-39 entropy (the 32-byte app seed on
    /// device; tests may pass 16 bytes).
    pub fn init(entropy: &[u8]) -> anyhow::Result<Self> {
        let mnemonic = Mnemonic::from_entropy(entropy).context("invalid entropy")?;
        let seed = mnemonic.to_seed("");

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
        let cache = KeyCache::init(&entropy).unwrap();
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
        let cache = KeyCache::init(&[0u8; 16]).unwrap();
        assert_eq!(cache.address(0, 0).unwrap(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn accounts_differ() {
        let cache = KeyCache::init(&[7u8; 32]).unwrap();
        assert_ne!(cache.address(0, 0).unwrap(), cache.address(1, 0).unwrap());
    }

    #[test]
    fn path_formatting() {
        assert_eq!(KeyCache::path_for(2, 3).to_string(), "m/44'/60'/2'/0/3");
    }
}
