//! Xous Native Ethereum App Service
//!
//! This service provides secure Ethereum transaction and message signing
//! for Baochip-1x hardware running Xous OS.
//!
//! # Architecture
//!
//! The service runs as a standard Xous server:
//! 1. Registers with xous-names as "ethapp.ethereum"
//! 2. Receives messages via `xous::receive_message()`
//! 3. Dispatches to handlers based on opcode
//! 4. Returns responses via scalar or memory messages
//!
//! # Security Model
//!
//! - All cryptographic operations use constant-time implementations
//! - Private keys never leave service memory
//! - User confirmation required for all signing operations
//! - Fail closed on any validation error
//!
//! # Docs consulted
//!
//! - Xous Book: Server patterns, message passing
//! - Vanadium docs/security.md: Security invariants
//! - EIP-155, EIP-191, EIP-712: Ethereum standards

#![cfg_attr(target_os = "xous", no_std)]
#![cfg_attr(target_os = "xous", no_main)]

#[cfg(target_os = "xous")]
extern crate alloc;

mod crypto;
mod handlers;
mod parsing;
mod platform;
mod state;
mod ui;

use ethapp_common::{EthAppError, EthAppOp, SERVER_NAME};
use num_traits::FromPrimitive;

#[cfg(target_os = "xous")]
use xous_ipc::Buffer;

/// Main entry point for the Xous ethapp service.
#[cfg(target_os = "xous")]
#[xous::xous_main]
fn xmain() -> ! {
    // Initialize logging
    log_server::init_wait().unwrap();
    log::info!("ethapp: Starting Ethereum App service");

    // Initialize the name server connection
    let xns = xous_names::XousNames::new().expect("ethapp: Failed to connect to xous-names");

    // Register our server with the name server
    let sid = xns
        .register_name(SERVER_NAME, None)
        .expect("ethapp: Failed to register server name");

    log::info!("ethapp: Registered as '{}'", SERVER_NAME);

    // Initialize service state
    let mut state = state::ServiceState::new();

    // Initialize platform services (TRNG, GAM, PDDB)
    if let Err(e) = state.init_platform() {
        log::error!("ethapp: Failed to initialize platform: {:?}", e);
        // Continue anyway - some operations may still work
    }

    log::info!("ethapp: Service initialized, entering message loop");

    // Main message loop
    loop {
        let msg = xous::receive_message(sid).expect("ethapp: Failed to receive message");

        // Extract opcode from message ID
        let opcode = EthAppOp::from_usize(msg.body.id());

        match opcode {
            Some(op) => {
                let result = handle_message(&mut state, op, msg);
                if let Err(e) = result {
                    log::warn!("ethapp: Handler error for {:?}: {:?}", op, e);
                }
            }
            None => {
                log::warn!("ethapp: Unknown opcode: {}", msg.body.id());
            }
        }
    }
}

/// Dispatch a message to the appropriate handler.
#[cfg(target_os = "xous")]
fn handle_message(
    state: &mut state::ServiceState,
    op: EthAppOp,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous::Message;

    match op {
        // === Configuration Commands ===
        EthAppOp::GetAppConfiguration => {
            handlers::handle_get_app_configuration(state, msg)?;
        }
        EthAppOp::GetChallenge => {
            handlers::handle_get_challenge(state, msg)?;
        }
        EthAppOp::Ping => {
            // Simple health check - respond immediately
            if let Message::Scalar(s) = &msg.body {
                xous::return_scalar(msg.sender, s.arg1).ok();
            }
        }
        EthAppOp::Exit => {
            log::info!("ethapp: Received exit command");
            // In production, this should be restricted to authorized callers
            #[cfg(feature = "dev-mode")]
            {
                // Use Xous-native process termination, not std::process::exit
                // which is unavailable in no_std Xous builds.
                xous::terminate_process(0);
                // terminate_process may not return, but if it does,
                // the main loop continues safely.
            }
        }

        // === Transaction Signing ===
        EthAppOp::SignTransaction => {
            handlers::handle_sign_transaction(state, msg)?;
        }
        EthAppOp::ClearSignTransaction => {
            handlers::handle_clear_sign_transaction(state, msg)?;
        }

        // === Message Signing ===
        EthAppOp::SignPersonalMessage => {
            handlers::handle_sign_personal_message(state, msg)?;
        }
        EthAppOp::SignEip712Hashed => {
            handlers::handle_sign_eip712_hashed(state, msg)?;
        }
        EthAppOp::SignEip712Message => {
            handlers::handle_sign_eip712_message(state, msg)?;
        }

        // === Metadata Provision ===
        EthAppOp::ProvideErc20TokenInfo => {
            handlers::handle_provide_erc20_token_info(state, msg)?;
        }
        EthAppOp::ProvideNftInfo => {
            handlers::handle_provide_nft_info(state, msg)?;
        }
        EthAppOp::ProvideDomainName => {
            handlers::handle_provide_domain_name(state, msg)?;
        }
        EthAppOp::LoadContractMethodInfo => {
            handlers::handle_load_contract_method_info(state, msg)?;
        }
        EthAppOp::ByContractAddressAndChain => {
            handlers::handle_by_contract_address_and_chain(state, msg)?;
        }

        // === Key Operations ===
        EthAppOp::GetPublicKey => {
            handlers::handle_get_public_key(state, msg)?;
        }
        EthAppOp::GetAddress => {
            handlers::handle_get_address(state, msg)?;
        }

        // === Eth2 (placeholder) ===
        EthAppOp::Eth2GetPublicKey | EthAppOp::Eth2SetWithdrawalIndex => {
            // Return unsupported error
            handlers::return_error(msg, EthAppError::UnsupportedOperation)?;
        }

        // === Internal ===
        EthAppOp::ClearMetadataCache => {
            state.clear_metadata_cache();
            handlers::return_success(msg)?;
        }
        EthAppOp::GetStats => {
            handlers::handle_get_stats(state, msg)?;
        }
    }

    Ok(())
}

// =============================================================================
// Native/Host Build (for testing)
// =============================================================================

#[cfg(not(target_os = "xous"))]
fn main() {
    println!("ethapp: Native build for testing only");
    println!("ethapp: This binary should be built for target_os = xous");
    println!();
    println!("To test on host, use the ethapp-cli crate with mock transport.");

    // Run unit tests
    #[cfg(test)]
    {
        println!("Running tests...");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_parsing() {
        assert_eq!(EthAppOp::from_usize(0x01), Some(EthAppOp::GetAppConfiguration));
        assert_eq!(EthAppOp::from_usize(0x10), Some(EthAppOp::SignTransaction));
        assert_eq!(EthAppOp::from_usize(0xFF), Some(EthAppOp::Ping));
        assert_eq!(EthAppOp::from_usize(0x1234), None);
    }
}
