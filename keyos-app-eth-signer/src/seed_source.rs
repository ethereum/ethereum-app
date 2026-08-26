// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! Where the wallet's keys come from (my-coin's key-source pattern).
//!
//! Two sources, one destination: both resolve to BIP-39 entropy that
//! [`crate::eth_keys::KeyCache`] expands with an optional passphrase. They are
//! different wallets with different addresses, so the user picks one on first
//! launch rather than being defaulted into either.
//!
//! - `AppSeed`: the per-app seed, treated as BIP-39 entropy (24 words).
//! - `UserMnemonic`: a phrase the user typed, held as entropy sealed under a
//!   key derived from the app seed (see [`seal`]/[`unseal`]) so the blob is
//!   useless without both the device and the master seed it was imported
//!   under, and any edit to it is detected rather than loaded as key material.

use {
    bip39::{Language, Mnemonic},
    chacha20poly1305::{
        aead::{Aead, Payload},
        Key, KeyInit, XChaCha20Poly1305, XNonce,
    },
    hmac::{Hmac, Mac},
    serde::{Deserialize, Serialize},
    sha2::Sha256,
    zeroize::Zeroizing,
};

type HmacSha256 = Hmac<Sha256>;

const KDF_CONTEXT: &[u8] = b"eth-signer/seed-store/v1";
const AAD: &[u8] = b"eth-signer/imported-entropy/v1";
const NONCE_LEN: usize = 24;

/// GOTCHA: the first GetAppSeed call must happen on the main thread, before any
/// background worker needs it — the grantOnFirstUse consent prompt is presented
/// against this app's gui connection and is dropped (=> denied, app aborts)
/// when the call comes from a detached worker at launch.
pub fn app_seed() -> [u8; 32] {
    let seed = crate::Security::default().app_seed().expect("app seed unavailable");
    *seed.as_bytes()
}

/// There is deliberately no `Default`: an unchosen source is `None` in
/// [`crate::store::AppSettings`], which is what sends the user to the chooser.
/// Guessing would silently pick one of two different wallets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SeedSource {
    /// Re-derived from the app seed on every launch. No key bytes are stored.
    ///
    /// Reads `Device` too: that is what this same wallet was called before the
    /// source became a choice, so an existing install keeps its addresses and
    /// is never asked to pick.
    #[serde(alias = "Device")]
    AppSeed,
    /// A phrase the user typed, held as BIP-39 entropy sealed under a key
    /// derived from the app seed.
    UserMnemonic { sealed_hex: String },
}

/// The BIP-39 entropy behind whichever source is configured.
pub fn resolve_entropy(source: &SeedSource, app_seed: &[u8; 32]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match source {
        SeedSource::AppSeed => Ok(Zeroizing::new(app_seed.to_vec())),
        SeedSource::UserMnemonic { sealed_hex } => {
            let blob = hex::decode(sealed_hex)
                .map_err(|_| anyhow::anyhow!("the stored recovery phrase is unreadable"))?;
            let entropy = unseal(&key_from_app_seed(app_seed), &blob)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(Zeroizing::new(entropy))
        }
    }
}

/// Turn an accepted phrase's entropy into a storable seed source.
pub fn seal_entropy(entropy: &[u8], app_seed: &[u8; 32]) -> anyhow::Result<SeedSource> {
    let blob = seal(&key_from_app_seed(app_seed), entropy).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(SeedSource::UserMnemonic { sealed_hex: hex::encode(blob) })
}

/// Word count, wordlist membership and the BIP-39 checksum, in one call.
pub fn entropy_from_words(words: &[String]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let phrase = words.iter().map(|w| w.trim().to_lowercase()).collect::<Vec<_>>().join(" ");
    Mnemonic::parse_normalized(&phrase)
        .map(|mnemonic| Zeroizing::new(mnemonic.to_entropy()))
        .map_err(|_| anyhow::anyhow!("invalid recovery phrase"))
}

/// Per-keystroke feedback: a complete wordlist word?
pub fn is_word(word: &str) -> bool {
    Language::English.find_word(word.trim().to_lowercase().as_str()).is_some()
}

/// Autocomplete. The wordlist is lexicographically ordered, so every word
/// sharing a prefix is one contiguous slice.
pub fn suggestions(prefix: &str) -> Vec<&'static str> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Vec::new();
    }
    Language::English.words_by_prefix(prefix).to_vec()
}

/// Domain-separated wrapping key. Never the wallet seed itself.
fn key_from_app_seed(app_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(KDF_CONTEXT).expect("HMAC accepts any key length");
    mac.update(app_seed);
    mac.finalize().into_bytes().into()
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    // Routed to the hardware TRNG by the SDK's getrandom fork.
    getrandom::getrandom(&mut nonce).map_err(|e| format!("no randomness available: {e}"))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: AAD })
        .map_err(|_| "could not protect the recovery phrase for storage".to_string())?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn unseal(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() <= NONCE_LEN {
        return Err("the stored recovery phrase is truncated".to_string());
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: AAD })
        .map_err(|_| "the stored recovery phrase does not belong to this Passport".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWELVE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";

    fn words(phrase: &str) -> Vec<String> {
        phrase.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn seal_round_trips_through_the_source() {
        let app_seed = [7u8; 32];
        let entropy = entropy_from_words(&words(TWELVE)).unwrap();
        let source = seal_entropy(&entropy, &app_seed).unwrap();
        assert_eq!(*resolve_entropy(&source, &app_seed).unwrap(), *entropy);
        // A different app seed cannot open it.
        assert!(resolve_entropy(&source, &[8u8; 32]).is_err());
    }

    #[test]
    fn app_seed_source_is_the_app_seed() {
        let app_seed = [7u8; 32];
        assert_eq!(*resolve_entropy(&SeedSource::AppSeed, &app_seed).unwrap(), app_seed.to_vec());
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut w = words(TWELVE);
        w[11] = "abandon".to_string();
        assert!(entropy_from_words(&w).is_err());
    }

    #[test]
    fn wordlist_helpers() {
        assert!(is_word("abandon"));
        assert!(!is_word("abando"));
        assert!(suggestions("aband").contains(&"abandon"));
    }
}
