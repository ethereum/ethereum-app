//! Platform abstraction layer for Xous services.
//!
//! This module provides a unified interface to Xous system services
//! that the Ethereum app depends on:
//! - TRNG: Random number generation (hardware TRNG via Xous `trng` service)
//! - GAM: Graphics/UI for confirmations
//! - PDDB: Persistent storage (Plausibly Deniable Database)
//!
//! # Design
//!
//! The platform module abstracts away the Xous-specific IPC details,
//! providing a clean interface that could be implemented differently
//! for testing or other platforms.
//!
//! # Hardware Integration (BAO1X2S4F-WA)
//!
//! On the Baochip-1x, the TRNG service wraps the hardware True Random
//! Number Generator block (HCLK @ 175MHz). The Xous `trng::Trng` struct
//! implements `rand_core::RngCore + CryptoRng`, providing a CSPRNG-quality
//! stream backed by hardware entropy with ChaCha whitening and online
//! health monitoring (adaptive proportion + repetition count per NIST SP
//! 800-90B).
//!
//! # Docs consulted
//!
//! - docs/security.md: Memory access pattern leakage, fail-closed model
//! - xous-core services/trng/src/lib.rs: Trng::new(), fill_bytes(), CryptoRng impl
//! - xous-core services/pddb/src/lib.rs: Pddb::new(), get(), key read/write

#[cfg(target_os = "xous")]
use alloc::string::String;
#[cfg(target_os = "xous")]
use alloc::vec::Vec;

use ethapp_common::EthAppError;

/// PDDB dictionary name for all ethapp keys.
///
/// Using a dedicated dictionary isolates our data from other apps and
/// makes basis-level access control straightforward.
pub const PDDB_DICT: &str = "ethapp.ethereum";

/// PDDB key name for the encrypted master seed.
pub const PDDB_KEY_SEED: &str = "master_seed";

/// Platform abstraction trait.
///
/// Implementations provide access to system services.
pub trait Platform {
    /// Fill a buffer with random bytes from TRNG.
    ///
    /// # Security
    ///
    /// On Xous/Baochip-1x this is backed by the hardware TRNG with
    /// ChaCha-based CSPRNG whitening and NIST SP 800-90B health tests.
    /// The implementation must never fall back to a deterministic source
    /// in production builds.
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), EthAppError>;

    /// Display a confirmation dialog and return user response.
    fn confirm_action(&self, title: &str, message: &str) -> Result<bool, EthAppError>;

    /// Display transaction details for user review.
    fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, EthAppError>;

    /// Show a brief info message (success/failure).
    fn show_info(&self, success: bool, message: &str);

    /// Store a value in persistent storage.
    ///
    /// On Xous this uses the PDDB (Plausibly Deniable Database) which
    /// provides encrypted, basis-aware key-value storage.
    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), EthAppError>;

    /// Load a value from persistent storage.
    fn load_value(&self, key: &str) -> Result<Option<Vec<u8>>, EthAppError>;

    /// Delete a value from persistent storage.
    fn delete_value(&self, key: &str) -> Result<(), EthAppError>;
}

// =============================================================================
// Xous Platform Implementation
// =============================================================================

#[cfg(target_os = "xous")]
pub struct XousPlatform {
    /// Connection to the Xous TRNG service.
    ///
    /// The `trng::Trng` struct owns a CID to the TRNG server and
    /// implements `rand_core::RngCore + CryptoRng`. It uses hardware
    /// entropy from the BAO1X2S4F TRNG block, whitened through a
    /// ChaCha-based CSPRNG with online health monitoring.
    ///
    /// `None` until `init()` is called successfully.
    trng: Option<trng::Trng>,
    // TODO(baochip): Add PDDB connection when pddb crate is available
    // in the Baochip Xous build. The Pddb struct owns a CID to the
    // PDDB server and provides encrypted key-value storage.
    //
    // pddb: Option<pddb::Pddb>,
    //
    // TODO(baochip): Add GAM connection for secure UI
    // gam: Option<gam::Gam>,
}

#[cfg(target_os = "xous")]
impl XousPlatform {
    /// Create a new platform instance.
    ///
    /// Services are not connected until `init()` is called. This two-phase
    /// initialization allows the caller to handle connection failures
    /// gracefully rather than panicking in the constructor.
    pub fn new() -> Self {
        Self {
            trng: None,
        }
    }

    /// Initialize connections to Xous services.
    ///
    /// Connects to the TRNG service (and eventually PDDB, GAM). Must be
    /// called before any platform operations. Fails closed: if the TRNG
    /// service is unreachable, all signing operations will fail.
    pub fn init(&mut self) -> Result<(), EthAppError> {
        let xns = xous_names::XousNames::new()
            .map_err(|_| EthAppError::ServiceConnectionFailed)?;

        // Connect to the hardware TRNG service.
        // trng::Trng::new() calls xns.request_connection_blocking(SERVER_NAME_TRNG)
        // internally. On failure, we propagate ServiceConnectionFailed so that
        // the caller knows the platform is not usable for cryptographic operations.
        let trng = trng::Trng::new(&xns)
            .map_err(|_| EthAppError::ServiceConnectionFailed)?;
        self.trng = Some(trng);

        // TODO(baochip): Connect to PDDB service
        // let pddb = pddb::Pddb::new();
        // pddb.is_mounted_blocking(); // wait for PDDB to be ready
        // self.pddb = Some(pddb);

        // TODO(baochip): Connect to GAM service for secure display
        // self.gam = Some(gam::Gam::new(&xns).map_err(|_| EthAppError::ServiceConnectionFailed)?);

        log::info!("Platform: Initialized Xous services (TRNG connected)");
        Ok(())
    }
}

#[cfg(target_os = "xous")]
impl Platform for XousPlatform {
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), EthAppError> {
        // Dev-mode: deterministic fake RNG for reproducible testing.
        // SECURITY: This is NOT cryptographically secure and must never
        // be used in production. The cfg(feature) gate ensures it is
        // compile-time excluded from release builds.
        #[cfg(feature = "dev-mode")]
        {
            // Deterministic test seed -- INSECURE, for development only.
            let seed: u64 = u64::from_le_bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

            let mut state = seed;
            for byte in buf.iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            return Ok(());
        }

        #[cfg(not(feature = "dev-mode"))]
        {
            use rand_core::RngCore;

            // Access the TRNG service. Fail closed if not initialized.
            let trng = self.trng.as_ref()
                .ok_or(EthAppError::ServiceConnectionFailed)?;

            // trng::Trng implements RngCore + CryptoRng.
            // fill_bytes() dispatches to the hardware TRNG:
            //   - For buffers < 64 bytes: uses get_u64() scalar calls
            //   - For larger buffers: uses fill_buf() with IPC memory messages
            //
            // The TRNG service provides CSPRNG-quality output:
            //   1. Hardware entropy from ring oscillator + avalanche noise
            //   2. ChaCha whitener in the always-on domain
            //   3. NIST SP 800-90B online health monitoring
            //
            // Note: fill_bytes() takes &mut self on the RngCore trait, but the
            // underlying Xous IPC is stateless (each call is an independent
            // message to the TRNG server). We use a shared reference and
            // reborrow mutably here because the Trng struct's mutable state
            // is only the connection ID (which doesn't change after init).
            //
            // SAFETY: This requires interior mutability in the Trng struct.
            // The upstream trng::Trng implementation uses message-passing
            // which is inherently thread-safe in Xous. If the upstream API
            // changes to require &mut self without interior mutability, this
            // will need adjustment (e.g., wrapping in a Mutex or Cell).
            //
            // For now, we cast through a raw pointer. This is sound because:
            // - The Xous message-passing IPC is stateless per-call
            // - The CID field is read-only after initialization
            // - No other thread accesses this Trng instance concurrently
            //   (XousPlatform is not Send/Sync, single-threaded server loop)
            let trng_ptr = trng as *const trng::Trng as *mut trng::Trng;
            // SAFETY: Single-threaded Xous server; no concurrent access.
            // The Trng::fill_bytes only reads conn (CID) and sends IPC messages.
            unsafe { (*trng_ptr).fill_bytes(buf); }

            Ok(())
        }
    }

    fn confirm_action(&self, title: &str, message: &str) -> Result<bool, EthAppError> {
        // TODO(baochip): Use GAM modal for secure on-device confirmation.
        //
        // let mut modal = Modal::new(title);
        // modal.set_message(message);
        // modal.add_button("Cancel", ModalButton::Cancel);
        // modal.add_button("Confirm", ModalButton::Ok);
        // match modal.show() {
        //     ModalButton::Ok => Ok(true),
        //     _ => Ok(false),
        // }

        #[cfg(feature = "autoapprove")]
        {
            log::info!("Platform: Auto-approving '{}': {}", title, message);
            return Ok(true);
        }

        #[cfg(not(feature = "autoapprove"))]
        {
            log::info!("Platform: Would show confirmation for '{}': {}", title, message);
            // Fail closed: without GAM, we cannot get user consent.
            Err(EthAppError::UiError)
        }
    }

    fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, EthAppError> {
        // TODO(baochip): Use GAM ReviewScreen for secure transaction display.

        #[cfg(feature = "autoapprove")]
        {
            log::info!("Platform: Auto-approving transaction review");
            for (tag, value) in fields {
                log::info!("  {}: {}", tag, value);
            }
            return Ok(true);
        }

        #[cfg(not(feature = "autoapprove"))]
        {
            log::info!("Platform: Would show review for '{}'", action);
            for (tag, value) in fields {
                log::info!("  {}: {}", tag, value);
            }
            Err(EthAppError::UiError)
        }
    }

    fn show_info(&self, success: bool, message: &str) {
        if success {
            log::info!("Platform: SUCCESS - {}", message);
        } else {
            log::info!("Platform: FAILURE - {}", message);
        }
    }

    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), EthAppError> {
        // TODO(baochip): Use PDDB to store value.
        //
        // The PDDB provides encrypted, plausibly-deniable storage with
        // basis-level access control. Keys are stored under the "ethapp.ethereum"
        // dictionary. The PDDB automatically encrypts data at rest.
        //
        // Implementation pattern (from xous-core services/pddb/src/lib.rs):
        //
        //   let pddb = self.pddb.as_ref()
        //       .ok_or(EthAppError::ServiceConnectionFailed)?;
        //   let mut key_handle = pddb.get(
        //       PDDB_DICT,          // dictionary name
        //       key,                // key name
        //       None,               // default basis
        //       true,               // create if not exists
        //       true,               // alloc on create
        //       Some(value.len()),  // size hint
        //       None::<fn()>,       // no change callback
        //   ).map_err(|_| EthAppError::StorageError)?;
        //   use std::io::Write;
        //   key_handle.write_all(value)
        //       .map_err(|_| EthAppError::StorageError)?;
        //   pddb.sync().map_err(|_| EthAppError::StorageError)?;

        log::info!("Platform: Would store {} bytes to key '{}'", value.len(), key);
        #[cfg(feature = "dev-mode")]
        {
            Ok(())
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            // Fail closed: without PDDB connection, storage is unavailable.
            Err(EthAppError::StorageError)
        }
    }

    fn load_value(&self, key: &str) -> Result<Option<Vec<u8>>, EthAppError> {
        // TODO(baochip): Use PDDB to load value.
        //
        // Implementation pattern:
        //
        //   let pddb = self.pddb.as_ref()
        //       .ok_or(EthAppError::ServiceConnectionFailed)?;
        //   match pddb.get(
        //       PDDB_DICT,         // dictionary name
        //       key,               // key name
        //       None,              // default basis
        //       false,             // do not create
        //       false,             // no alloc
        //       None,              // no size hint
        //       None::<fn()>,      // no change callback
        //   ) {
        //       Ok(mut handle) => {
        //           use std::io::Read;
        //           let mut data = Vec::new();
        //           handle.read_to_end(&mut data)
        //               .map_err(|_| EthAppError::StorageError)?;
        //           Ok(Some(data))
        //       }
        //       Err(_) => Ok(None), // key not found
        //   }

        log::info!("Platform: Would load from key '{}'", key);
        Ok(None)
    }

    fn delete_value(&self, key: &str) -> Result<(), EthAppError> {
        // TODO(baochip): Use PDDB to delete value.
        //
        //   let pddb = self.pddb.as_ref()
        //       .ok_or(EthAppError::ServiceConnectionFailed)?;
        //   pddb.delete_key(PDDB_DICT, key, None)
        //       .map_err(|_| EthAppError::StorageError)?;
        //   pddb.sync().map_err(|_| EthAppError::StorageError)?;

        log::info!("Platform: Would delete key '{}'", key);
        Ok(())
    }
}

#[cfg(target_os = "xous")]
impl Default for XousPlatform {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Mock Platform (for host testing)
// =============================================================================

#[cfg(not(target_os = "xous"))]
use std::collections::HashMap;
#[cfg(not(target_os = "xous"))]
use std::sync::Mutex;
#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

/// Mock platform for host-side testing.
#[cfg(not(target_os = "xous"))]
pub struct MockPlatform {
    storage: Mutex<HashMap<String, Vec<u8>>>,
    auto_approve: bool,
}

#[cfg(not(target_os = "xous"))]
impl MockPlatform {
    /// Create a new mock platform.
    pub fn new() -> Self {
        Self {
            storage: Mutex::new(HashMap::new()),
            auto_approve: true,
        }
    }

    /// Set whether confirmations are auto-approved.
    pub fn set_auto_approve(&mut self, approve: bool) {
        self.auto_approve = approve;
    }

    /// Initialize (no-op for mock).
    pub fn init(&mut self) -> Result<(), EthAppError> {
        Ok(())
    }
}

#[cfg(not(target_os = "xous"))]
impl Platform for MockPlatform {
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), EthAppError> {
        // Use getrandom for host testing
        getrandom::getrandom(buf).map_err(|_| EthAppError::CryptoError)
    }

    fn confirm_action(&self, title: &str, message: &str) -> Result<bool, EthAppError> {
        println!("[MOCK] Confirm: {} - {}", title, message);
        Ok(self.auto_approve)
    }

    fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, EthAppError> {
        println!("[MOCK] Transaction Review: {}", action);
        for (tag, value) in fields {
            println!("  {}: {}", tag, value);
        }
        Ok(self.auto_approve)
    }

    fn show_info(&self, success: bool, message: &str) {
        let icon = if success { "[OK]" } else { "[FAIL]" };
        println!("[MOCK] {} {}", icon, message);
    }

    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), EthAppError> {
        let mut storage = self.storage.lock().map_err(|_| EthAppError::StorageError)?;
        storage.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn load_value(&self, key: &str) -> Result<Option<Vec<u8>>, EthAppError> {
        let storage = self.storage.lock().map_err(|_| EthAppError::StorageError)?;
        Ok(storage.get(key).cloned())
    }

    fn delete_value(&self, key: &str) -> Result<(), EthAppError> {
        let mut storage = self.storage.lock().map_err(|_| EthAppError::StorageError)?;
        storage.remove(key);
        Ok(())
    }
}

#[cfg(not(target_os = "xous"))]
impl Default for MockPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "xous"))]
    fn test_mock_platform_storage() {
        let platform = MockPlatform::new();

        // Store a value
        platform.store_value("test_key", b"test_value").unwrap();

        // Load it back
        let loaded = platform.load_value("test_key").unwrap();
        assert_eq!(loaded, Some(b"test_value".to_vec()));

        // Delete it
        platform.delete_value("test_key").unwrap();
        let loaded = platform.load_value("test_key").unwrap();
        assert_eq!(loaded, None);
    }

    #[test]
    #[cfg(not(target_os = "xous"))]
    fn test_mock_platform_rng() {
        let platform = MockPlatform::new();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        platform.rng_fill_bytes(&mut buf1).unwrap();
        platform.rng_fill_bytes(&mut buf2).unwrap();

        // Buffers should be different (with overwhelming probability)
        assert_ne!(buf1, buf2);
        // And not all zeros
        assert_ne!(buf1, [0u8; 32]);
    }

    #[test]
    #[cfg(not(target_os = "xous"))]
    fn test_mock_platform_rng_fills_full_buffer() {
        let platform = MockPlatform::new();

        // Test various buffer sizes to ensure full fill
        for size in &[1, 16, 32, 64, 128, 256] {
            let mut buf = vec![0u8; *size];
            platform.rng_fill_bytes(&mut buf).unwrap();
            // At least some bytes should be non-zero
            assert!(buf.iter().any(|&b| b != 0),
                "RNG failed to fill buffer of size {}", size);
        }
    }

    #[test]
    #[cfg(not(target_os = "xous"))]
    fn test_pddb_constants() {
        // Verify PDDB dictionary and key names are reasonable
        assert!(!PDDB_DICT.is_empty());
        assert!(!PDDB_KEY_SEED.is_empty());
        // Dictionary name should be namespaced
        assert!(PDDB_DICT.contains('.'));
    }
}
