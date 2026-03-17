//! Cryptographic operations for the Ethereum app.
//!
//! This module provides:
//! - Keccak256 hashing (Ethereum's hash function)
//! - BIP32/BIP44 key derivation
//! - ECDSA signing with secp256k1
//! - Signature normalization (low-S, EIP-155 v value)
//!
//! # Security
//!
//! - All operations use constant-time implementations where available
//! - Private keys are zeroized on drop
//! - No secret-dependent memory access patterns

#[cfg(target_os = "xous")]
use alloc::vec::Vec;

#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

use ethapp_common::{Bip32Path, EthAddress, EthAppError, Hash256, Signature, TransactionType};
use k256::{
    ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};
use zeroize::Zeroize;

// =============================================================================
// Keccak256
// =============================================================================

/// Keccak256 hash function as used by Ethereum.
///
/// # Security
///
/// Uses tiny-keccak which has a constant-time Keccak-f[1600] permutation.
/// Memory access pattern is fixed regardless of input content.
pub fn keccak256(data: &[u8]) -> Hash256 {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Streaming Keccak256 hasher for large inputs.
pub struct Keccak256Hasher {
    inner: Keccak,
}

impl Keccak256Hasher {
    /// Creates a new hasher.
    pub fn new() -> Self {
        Self {
            inner: Keccak::v256(),
        }
    }

    /// Updates the hasher with data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes and returns the hash.
    pub fn finalize(self) -> Hash256 {
        let mut output = [0u8; 32];
        self.inner.finalize(&mut output);
        output
    }
}

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Key Derivation
// =============================================================================

/// Seed for key derivation.
///
/// In production, this would come from secure storage (PDDB/keystore).
/// For development, we use a test seed.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(*bytes)
    }

    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Development test seed (BIP39: "abandon abandon ... about").
///
/// WARNING: NEVER use this in production!
#[cfg(feature = "dev-mode")]
pub fn get_dev_seed() -> Seed {
    // This is the seed for the standard test mnemonic:
    // "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let seed_bytes: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];
    Seed::from_bytes(&seed_bytes)
}

/// Derive a private key from seed using BIP32/BIP44 path.
///
/// # Security
///
/// - Uses bip32 crate which provides constant-time operations
/// - Private key is zeroized on drop
pub fn derive_private_key(seed: &Seed, path: &Bip32Path) -> Result<SigningKey, EthAppError> {
    use bip32::{ChildNumber, XPrv};

    // Derive the key iteratively using child numbers
    let mut xprv = XPrv::new(seed.as_bytes())
        .map_err(|_| EthAppError::KeyDerivationFailed)?;

    for &component in path.as_slice() {
        let child = if component & Bip32Path::HARDENED != 0 {
            ChildNumber::new(component & !Bip32Path::HARDENED, true)
                .map_err(|_| EthAppError::InvalidDerivationPath)?
        } else {
            ChildNumber::new(component, false)
                .map_err(|_| EthAppError::InvalidDerivationPath)?
        };
        xprv = xprv.derive_child(child)
            .map_err(|_| EthAppError::KeyDerivationFailed)?;
    }

    // Convert to signing key
    let private_key_bytes = xprv.private_key().to_bytes();
    let signing_key =
        SigningKey::from_bytes((&private_key_bytes[..]).into())
            .map_err(|_| EthAppError::KeyDerivationFailed)?;

    Ok(signing_key)
}

/// Get public key from signing key.
pub fn get_public_key(signing_key: &SigningKey) -> PublicKey {
    signing_key.verifying_key().into()
}

/// Get Ethereum address from public key.
///
/// Address = keccak256(pubkey[1..])[12..32]
/// (Skip the 0x04 prefix of uncompressed key, take last 20 bytes of hash)
pub fn public_key_to_address(pubkey: &PublicKey) -> EthAddress {
    let encoded = pubkey.to_encoded_point(false);
    let bytes = encoded.as_bytes();

    // Skip the 0x04 prefix
    let hash = keccak256(&bytes[1..]);

    // Take last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Get compressed public key (33 bytes).
pub fn get_compressed_pubkey(signing_key: &SigningKey) -> [u8; 33] {
    let pubkey = get_public_key(signing_key);
    let encoded = pubkey.to_encoded_point(true);
    let mut result = [0u8; 33];
    result.copy_from_slice(encoded.as_bytes());
    result
}

// =============================================================================
// Signing
// =============================================================================

/// Sign a hash with recovery ID.
///
/// # Security
///
/// - Uses k256 crate which provides constant-time signing
/// - Automatically produces low-S signatures
pub fn sign_hash_recoverable(
    signing_key: &SigningKey,
    hash: &Hash256,
) -> Result<(K256Signature, RecoveryId), EthAppError> {
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(hash)
        .map_err(|_| EthAppError::SigningFailed)?;

    Ok((sig, recid))
}

/// Sign a hash and return Ethereum-format signature.
///
/// # Arguments
/// * `signing_key` - The private key to sign with
/// * `hash` - The 32-byte hash to sign
/// * `chain_id` - Optional chain ID for EIP-155
/// * `tx_type` - Transaction type (affects v calculation)
pub fn sign_eth(
    signing_key: &SigningKey,
    hash: &Hash256,
    chain_id: Option<u64>,
    tx_type: TransactionType,
) -> Result<Signature, EthAppError> {
    let (sig, recid) = sign_hash_recoverable(signing_key, hash)?;

    // Extract r and s
    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    // Compute v value
    let v = compute_v(recid.to_byte(), chain_id, tx_type)?;

    Ok(Signature { v, r, s })
}

/// Sign an EIP-191 personal message.
///
/// Computes: keccak256("\x19Ethereum Signed Message:\n" + len + message)
pub fn sign_personal_message(
    signing_key: &SigningKey,
    message: &[u8],
) -> Result<Signature, EthAppError> {
    // Build EIP-191 prefixed message
    let prefix = b"\x19Ethereum Signed Message:\n";
    let len_str = message.len().to_string();

    let mut prefixed = Vec::with_capacity(prefix.len() + len_str.len() + message.len());
    prefixed.extend_from_slice(prefix);
    prefixed.extend_from_slice(len_str.as_bytes());
    prefixed.extend_from_slice(message);

    let hash = keccak256(&prefixed);

    // Sign with v = 27 + recid (personal message format)
    let (sig, recid) = sign_hash_recoverable(signing_key, &hash)?;

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    Ok(Signature {
        v: 27u64 + recid.to_byte() as u64,
        r,
        s,
    })
}

/// Sign EIP-712 typed data.
///
/// Computes: keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))
pub fn sign_eip712(
    signing_key: &SigningKey,
    domain_hash: &Hash256,
    message_hash: &Hash256,
) -> Result<Signature, EthAppError> {
    // EIP-712 hash computation
    let mut data = Vec::with_capacity(66);
    data.push(0x19);
    data.push(0x01);
    data.extend_from_slice(domain_hash);
    data.extend_from_slice(message_hash);

    let hash = keccak256(&data);

    // Sign with v = 27 + recid (EIP-712 uses message signing format)
    let (sig, recid) = sign_hash_recoverable(signing_key, &hash)?;

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_bytes);
    s.copy_from_slice(&s_bytes);

    Ok(Signature {
        v: 27u64 + recid.to_byte() as u64,
        r,
        s,
    })
}

// =============================================================================
// V Value Computation
// =============================================================================

/// Compute the v value from recovery ID.
///
/// - Legacy with chain ID (EIP-155): v = chain_id * 2 + 35 + recovery_id
/// - Legacy without chain ID: v = 27 + recovery_id
/// - Typed transactions (EIP-2930/EIP-1559): v = recovery_id (0 or 1)
///
/// Returns u64 to support large chain IDs per EIP-155.
fn compute_v(
    recovery_id: u8,
    chain_id: Option<u64>,
    tx_type: TransactionType,
) -> Result<u64, EthAppError> {
    match tx_type {
        TransactionType::Legacy => {
            if let Some(cid) = chain_id {
                // EIP-155: v = chain_id * 2 + 35 + recovery_id
                let v = cid
                    .checked_mul(2)
                    .and_then(|x| x.checked_add(35))
                    .and_then(|x| x.checked_add(recovery_id as u64))
                    .ok_or(EthAppError::InvalidTransaction)?;

                Ok(v)
            } else {
                // Pre-EIP-155
                Ok(27u64 + recovery_id as u64)
            }
        }
        TransactionType::AccessList | TransactionType::FeeMarket => {
            // Typed transactions use just recovery_id (0 or 1)
            Ok(recovery_id as u64)
        }
    }
}

// =============================================================================
// Address Formatting
// =============================================================================

/// Format address with EIP-55 checksum.
pub fn format_address_checksummed(address: &EthAddress) -> [u8; 42] {
    let hex_lower = hex::encode(address);
    let hash = keccak256(hex_lower.as_bytes());

    let mut result = [0u8; 42];
    result[0] = b'0';
    result[1] = b'x';

    for (i, c) in hex_lower.bytes().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0F
        };

        result[2 + i] = if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keccak256 test vectors from Ethereum
    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        let expected = hex_literal::hex!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        let expected = hex_literal::hex!(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_keccak256_streaming() {
        let mut hasher = Keccak256Hasher::new();
        hasher.update(b"hello");
        hasher.update(b" ");
        hasher.update(b"world");
        let hash = hasher.finalize();

        let expected = keccak256(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_compute_v_legacy_eip155() {
        // Chain ID 1: v = 1 * 2 + 35 + 0 = 37
        let v = compute_v(0, Some(1), TransactionType::Legacy).unwrap();
        assert_eq!(v, 37u64);

        // Chain ID 1: v = 1 * 2 + 35 + 1 = 38
        let v = compute_v(1, Some(1), TransactionType::Legacy).unwrap();
        assert_eq!(v, 38u64);
    }

    #[test]
    fn test_compute_v_legacy_no_chain() {
        let v = compute_v(0, None, TransactionType::Legacy).unwrap();
        assert_eq!(v, 27u64);

        let v = compute_v(1, None, TransactionType::Legacy).unwrap();
        assert_eq!(v, 28u64);
    }

    #[test]
    fn test_compute_v_typed() {
        let v = compute_v(0, Some(1), TransactionType::FeeMarket).unwrap();
        assert_eq!(v, 0u64);

        let v = compute_v(1, Some(1), TransactionType::FeeMarket).unwrap();
        assert_eq!(v, 1u64);
    }

    #[test]
    fn test_compute_v_large_chain_id() {
        // Chain ID 56 (BSC): v = 56 * 2 + 35 + 0 = 147
        let v = compute_v(0, Some(56), TransactionType::Legacy).unwrap();
        assert_eq!(v, 147u64);

        // Chain ID 137 (Polygon): v = 137 * 2 + 35 + 1 = 310
        // This previously overflowed u8 (max 255)
        let v = compute_v(1, Some(137), TransactionType::Legacy).unwrap();
        assert_eq!(v, 310u64);

        // Chain ID 999999: v = 999999 * 2 + 35 + 0 = 2000033
        let v = compute_v(0, Some(999_999), TransactionType::Legacy).unwrap();
        assert_eq!(v, 2_000_033u64);
    }

    #[test]
    fn test_address_checksum() {
        // Standard EIP-55 test address
        let address = hex_literal::hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        let checksummed = format_address_checksummed(&address);
        let expected = b"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert_eq!(&checksummed, expected);
    }

    #[cfg(feature = "dev-mode")]
    #[test]
    fn test_key_derivation() {
        let seed = get_dev_seed();
        let path = Bip32Path::ethereum(0, 0, 0);

        let key = derive_private_key(&seed, &path).unwrap();
        let address = public_key_to_address(&get_public_key(&key));

        // Expected address for test mnemonic at m/44'/60'/0'/0/0
        // "abandon abandon ... about" -> 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
        let expected = hex_literal::hex!("9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(address, expected);
    }
}
