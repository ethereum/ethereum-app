// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Account identifier: the owning wallet's master fingerprint (hex) plus the
//! BIP-44 account index — mirroring the Bitcoin app's fingerprint-scoped ids.
//! Kept stringly-typed round-trippable because Slint routes pass
//! `account-id: string` through navigation params.

use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId {
    /// Master fingerprint of the owning wallet (seed + optional passphrase),
    /// 8 lowercase hex chars.
    pub fingerprint: String,
    pub index: u32,
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "eth-{}-{}", self.fingerprint, self.index)
    }
}

impl FromStr for AccountId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix("eth-").ok_or_else(|| anyhow::anyhow!("invalid account id: {s}"))?;
        let (fingerprint, index) =
            rest.split_once('-').ok_or_else(|| anyhow::anyhow!("invalid account id: {s}"))?;
        if fingerprint.is_empty() || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("invalid fingerprint in account id: {s}");
        }
        let index = index.parse::<u32>().map_err(|e| anyhow::anyhow!("invalid account index in {s}: {e}"))?;
        Ok(Self { fingerprint: fingerprint.to_lowercase(), index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for index in [0u32, 1, 42, u32::MAX] {
            let id = AccountId { fingerprint: "d34db33f".into(), index };
            let s = id.to_string();
            assert_eq!(s.parse::<AccountId>().unwrap(), id);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!("".parse::<AccountId>().is_err());
        assert!("eth-0".parse::<AccountId>().is_err());
        assert!("eth--0".parse::<AccountId>().is_err());
        assert!("eth-zzzz-0".parse::<AccountId>().is_err());
        assert!("eth-d34db33f-x".parse::<AccountId>().is_err());
    }
}
