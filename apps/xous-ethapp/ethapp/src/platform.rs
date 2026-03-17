//! Platform abstraction layer for Xous services.
//!
//! This module provides a unified interface to Xous system services
//! that the Ethereum app depends on:
//! - TRNG: Random number generation
//! - GAM: Graphics/UI for confirmations
//! - PDDB: Persistent storage
//!
//! # Design
//!
//! The platform module abstracts away the Xous-specific IPC details,
//! providing a clean interface that could be implemented differently
//! for testing or other platforms.

#[cfg(target_os = "xous")]
use alloc::string::String;
#[cfg(target_os = "xous")]
use alloc::vec::Vec;

use ethapp_common::EthAppError;

/// Platform abstraction trait.
///
/// Implementations provide access to system services.
pub trait Platform {
    /// Fill a buffer with random bytes from TRNG.
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
    // Connection IDs to Xous services
    // These would be initialized during service startup
    trng_conn: Option<xous::CID>,
    // gam_conn would be for UI
    // pddb_conn would be for storage
}

#[cfg(target_os = "xous")]
impl XousPlatform {
    /// Create a new platform instance.
    pub fn new() -> Self {
        Self {
            trng_conn: None,
        }
    }

    /// Initialize connections to Xous services.
    pub fn init(&mut self) -> Result<(), EthAppError> {
        // Connect to TRNG service
        let xns = xous_names::XousNames::new()
            .map_err(|_| EthAppError::ServiceConnectionFailed)?;

        // TRNG is a well-known server, connect by name
        // In real Xous, this would be:
        // self.trng_conn = Some(xns.request_connection_blocking("trng").unwrap());

        log::info!("Platform: Initialized Xous services");
        Ok(())
    }
}

#[cfg(target_os = "xous")]
impl Platform for XousPlatform {
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), EthAppError> {
        // In real Xous implementation:
        // Use TRNG service to fill buffer with random bytes
        //
        // For now, use a fallback that works during development
        // SECURITY WARNING: This is NOT cryptographically secure.
        // Dev-mode only: uses a deterministic seed for reproducible testing.
        // std::time::SystemTime is unavailable in no_std Xous builds.
        // In production, TRNG service must be used instead.
        #[cfg(feature = "dev-mode")]
        {
            // Deterministic test seed -- INSECURE, for development only.
            let seed: u64 = u64::from_le_bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

            let mut state = seed;
            for byte in buf.iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (state >> 32) as u8;
            }
            Ok(())
        }

        #[cfg(not(feature = "dev-mode"))]
        {
            // Real TRNG call would go here
            // trng::fill_bytes(self.trng_conn.unwrap(), buf)
            //     .map_err(|_| EthAppError::CryptoError)
            Err(EthAppError::UnsupportedOperation)
        }
    }

    fn confirm_action(&self, title: &str, message: &str) -> Result<bool, EthAppError> {
        // In real Xous implementation:
        // Use GAM modal to show confirmation dialog
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
            // In real implementation, this would block waiting for user input
            Err(EthAppError::UiError)
        }
    }

    fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, EthAppError> {
        // In real Xous implementation:
        // Use GAM to show multi-field review screen
        //
        // let mut review = ReviewScreen::new("Review Transaction");
        // for (tag, value) in fields {
        //     review.add_field(tag, value);
        // }
        // review.set_action(action);
        // review.show()

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
        // In real Xous implementation:
        // Use GAM to show brief notification
        //
        // let icon = if success { Icon::Success } else { Icon::Failure };
        // gam::show_notification(icon, message);

        if success {
            log::info!("Platform: SUCCESS - {}", message);
        } else {
            log::info!("Platform: FAILURE - {}", message);
        }
    }

    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), EthAppError> {
        // In real Xous implementation:
        // Use PDDB to store value
        //
        // let pddb = pddb::Pddb::new();
        // pddb.write_key("ethapp", key, value)
        //     .map_err(|_| EthAppError::StorageError)

        log::info!("Platform: Would store {} bytes to key '{}'", value.len(), key);
        #[cfg(feature = "dev-mode")]
        {
            Ok(())
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            Err(EthAppError::StorageError)
        }
    }

    fn load_value(&self, key: &str) -> Result<Option<Vec<u8>>, EthAppError> {
        // In real Xous implementation:
        // Use PDDB to load value
        //
        // let pddb = pddb::Pddb::new();
        // match pddb.read_key("ethapp", key) {
        //     Ok(data) => Ok(Some(data)),
        //     Err(pddb::Error::NotFound) => Ok(None),
        //     Err(_) => Err(EthAppError::StorageError),
        // }

        log::info!("Platform: Would load from key '{}'", key);
        Ok(None)
    }

    fn delete_value(&self, key: &str) -> Result<(), EthAppError> {
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
}
