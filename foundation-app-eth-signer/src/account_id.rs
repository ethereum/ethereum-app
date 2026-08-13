// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Account identifier. The app currently manages a single Ethereum account
//! (index 0), but the id keeps its stringly-typed round-trip form because the
//! Slint routes pass `account-id: string` through navigation params.

use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AccountId {
    pub index: u32,
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "eth-{}", self.index)
    }
}

impl FromStr for AccountId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let index = s
            .strip_prefix("eth-")
            .ok_or_else(|| anyhow::anyhow!("invalid account id: {s}"))?
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("invalid account index in {s}: {e}"))?;
        Ok(Self { index })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for index in [0u32, 1, 42, u32::MAX] {
            let id = AccountId { index };
            let s = id.to_string();
            assert_eq!(s.parse::<AccountId>().unwrap(), id);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!("".parse::<AccountId>().is_err());
        assert!("single-abc".parse::<AccountId>().is_err());
        assert!("eth-".parse::<AccountId>().is_err());
        assert!("eth-x".parse::<AccountId>().is_err());
    }
}
