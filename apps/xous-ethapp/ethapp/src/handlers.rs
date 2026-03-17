//! Message handlers for the ethapp service.
//!
//! Each handler processes a specific opcode and returns a response.
//! Handlers are responsible for:
//! - Deserializing request data
//! - Validating parameters
//! - Performing the operation
//! - Serializing and returning the response

#[cfg(target_os = "xous")]
use alloc::string::String;
#[cfg(target_os = "xous")]
use alloc::vec::Vec;

#[cfg(not(target_os = "xous"))]
use std::string::String;
#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

use ethapp_common::{
    AppConfiguration, Bip32Path, EthAppError, Hash256, ProvideTokenInfoRequest,
    PublicKeyResponse, Signature, SignEip712HashedRequest, SignEip712MessageRequest,
    SignPersonalMessageRequest, SignTransactionRequest, TransactionType,
};
use rkyv::{Deserialize, Serialize};

use crate::crypto::{
    derive_private_key, format_address_checksummed, get_compressed_pubkey, keccak256,
    public_key_to_address, sign_eth, sign_eip712, sign_personal_message, get_public_key,
};
use crate::parsing::{ParsedTransaction, TransactionParser};
use crate::platform::Platform;
use crate::state::ServiceState;
use crate::ui;

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns a success scalar response.
#[cfg(target_os = "xous")]
pub fn return_success(msg: xous::MessageEnvelope) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 0)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn return_success(_msg: ()) -> Result<(), EthAppError> {
    Ok(())
}

/// Returns an error scalar response.
#[cfg(target_os = "xous")]
pub fn return_error(msg: xous::MessageEnvelope, error: EthAppError) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, error.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn return_error(_msg: (), error: EthAppError) -> Result<(), EthAppError> {
    Err(error)
}

/// Safely extract a Buffer from a Xous memory message.
///
/// Encapsulates the single `unsafe` call to `Buffer::from_memory_message`,
/// validating the message type first. This is the only place in the codebase
/// where this unsafe operation occurs.
///
/// # Safety justification
/// `Buffer::from_memory_message` is unsafe because it constructs a Buffer from
/// a raw kernel-provided memory region. The safety is ensured by:
/// - The Xous kernel guarantees valid memory mapping for Borrow/MutableBorrow messages
/// - We validate the message type before calling the unsafe function
/// - The Buffer lifetime is bounded by the message lifetime
#[cfg(target_os = "xous")]
fn extract_buffer(msg: &xous::MessageEnvelope) -> Result<xous_ipc::Buffer, EthAppError> {
    use xous::Message;
    use xous_ipc::Buffer;
    match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            // SAFETY: The Xous kernel guarantees that Borrow/MutableBorrow messages
            // contain valid memory regions mapped into our address space.
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)
        }
        _ => Err(EthAppError::InvalidData),
    }
}

/// Get the seed for key derivation.
///
/// Both dev-mode and production paths return the same type to prevent
/// compilation errors where callers use `?` for one cfg but not the other.
#[cfg(feature = "dev-mode")]
fn get_seed() -> Result<crate::crypto::Seed, EthAppError> {
    Ok(crate::crypto::get_dev_seed())
}

#[cfg(not(feature = "dev-mode"))]
fn get_seed() -> Result<crate::crypto::Seed, EthAppError> {
    // TODO: In production, load the master seed from PDDB secure storage.
    // The seed should be derived during device initialization and stored
    // encrypted under the user's PIN/password. This placeholder returns an
    // error until real key storage is implemented.
    Err(EthAppError::UnsupportedOperation)
}

// =============================================================================
// Configuration Handlers
// =============================================================================

/// Handle GetAppConfiguration request.
#[cfg(target_os = "xous")]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let config = state.config.clone();

    // Serialize response
    let bytes = rkyv::to_bytes::<_, 256>(&config)
        .map_err(|_| EthAppError::SerializationError)?;

    // Return via memory message
    let mut buffer = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    buffer.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    _msg: (),
) -> Result<AppConfiguration, EthAppError> {
    Ok(state.config.clone())
}

/// Handle GetChallenge request.
#[cfg(target_os = "xous")]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;

    let mut buffer = Buffer::into_buf(challenge.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    buffer.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    _msg: (),
) -> Result<[u8; 32], EthAppError> {
    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;
    Ok(challenge)
}

// =============================================================================
// Transaction Signing Handlers
// =============================================================================

/// Handle SignTransaction request.
#[cfg(target_os = "xous")]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    // Extract request from memory message
    let buffer = extract_buffer(&msg)?;

    let request: SignTransactionRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    // Process the signing request
    let signature = process_sign_transaction(state, &request)?;

    // Serialize and return signature
    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_transaction(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

/// Process a sign transaction request.
fn process_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Parse transaction
    let tx = TransactionParser::parse(&request.tx_data)
        .map_err(|_| EthAppError::InvalidTransaction)?;

    // Display transaction for user confirmation
    if !ui::display_transaction(&state.platform, &tx, false)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed()?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        // seed is Zeroize+Drop, signing_key has ZeroizeOnDrop
        sign_eth(&signing_key, &tx.sign_hash, tx.chain_id, tx.tx_type)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Transaction signed");

    Ok(signature)
}

/// Handle ClearSignTransaction request.
#[cfg(target_os = "xous")]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    // For now, delegate to regular sign transaction
    // Full implementation would use cached metadata
    handle_sign_transaction(state, msg)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    handle_sign_transaction(state, request)
}

// =============================================================================
// Message Signing Handlers
// =============================================================================

/// Handle SignPersonalMessage request.
#[cfg(target_os = "xous")]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let buffer = extract_buffer(&msg)?;

    let request: SignPersonalMessageRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_personal_message(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_personal_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate message size
    if request.message.is_empty() || request.message.len() > 65536 {
        return Err(EthAppError::InvalidMessage);
    }

    // Display message for confirmation
    if !ui::display_personal_message(&state.platform, &request.message)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed()?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_personal_message(&signing_key, &request.message)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Message signed");

    Ok(signature)
}

/// Handle SignEip712Hashed request.
#[cfg(target_os = "xous")]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    // Check if blind signing is enabled
    if !state.config.blind_signing_enabled {
        return Err(EthAppError::BlindSigningDisabled);
    }

    let buffer = extract_buffer(&msg)?;

    let request: SignEip712HashedRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_eip712_hashed(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    if !state.config.blind_signing_enabled {
        return Err(EthAppError::BlindSigningDisabled);
    }
    let signature = process_sign_eip712_hashed(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Display for confirmation (blind signing warning)
    if !ui::display_eip712_hashed(&state.platform, &request.domain_hash, &request.message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed()?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_eip712(&signing_key, &request.domain_hash, &request.message_hash)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

/// Handle SignEip712Message request.
#[cfg(target_os = "xous")]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let buffer = extract_buffer(&msg)?;

    let request: SignEip712MessageRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_eip712_message(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_eip712_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate typed data size
    if request.typed_data.is_empty() || request.typed_data.len() > 65536 {
        return Err(EthAppError::InvalidTypedData);
    }

    // Parse typed data - minimal implementation expects pre-computed hashes
    if request.typed_data.len() < 64 {
        return Err(EthAppError::InvalidTypedData);
    }

    let mut domain_hash = [0u8; 32];
    let mut message_hash = [0u8; 32];
    domain_hash.copy_from_slice(&request.typed_data[..32]);
    message_hash.copy_from_slice(&request.typed_data[32..64]);

    // Display for confirmation
    if !ui::display_eip712_message(&state.platform, &domain_hash, &message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key; sign in a tight scope so the signing key
    // is dropped (and zeroized via k256's ZeroizeOnDrop) immediately after use.
    let signature = {
        let seed = get_seed()?;
        let signing_key = derive_private_key(&seed, &request.path)?;
        sign_eip712(&signing_key, &domain_hash, &message_hash)?
        // signing_key and seed dropped here, secret material zeroized
    };

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

// =============================================================================
// Metadata Handlers
// =============================================================================

/// Handle ProvideErc20TokenInfo request.
#[cfg(target_os = "xous")]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    let buffer = extract_buffer(&msg)?;

    let request: ProvideTokenInfoRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    // Validate basic constraints
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }

    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }

    // SECURITY WARNING (CRITICAL-04): Metadata signature is NOT verified.
    // An attacker can provide arbitrary token info (fake ticker, wrong decimals)
    // which will be displayed to the user during transaction signing.
    // This can trick users into signing transactions that transfer different
    // amounts or different tokens than displayed.
    //
    // TODO: Implement signature verification against a trusted Ledger/provider
    // public key before accepting metadata. Until then, all cached metadata
    // is marked as unverified and displayed with an "[UNVERIFIED]" prefix.
    //
    // The `request.signature` field is present but currently ignored.
    // Verification should check: ECDSA(sha256(chain_id || address || ticker || decimals))
    // against a known trusted public key embedded at build time.

    log::warn!(
        "ethapp: Accepted UNVERIFIED token info for chain={}, ticker={}",
        request.info.chain_id,
        request.info.ticker
    );

    // Prefix ticker with [UNVERIFIED] to warn the user during display
    let mut unverified_info = request.info;
    let mut unverified_ticker = String::from("[UNVERIFIED] ");
    unverified_ticker.push_str(&unverified_info.ticker);
    unverified_info.ticker = unverified_ticker;

    state.cache_token_info(unverified_info);

    xous::return_scalar(msg.sender, 1) // accepted = true (but unverified)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    request: &ProvideTokenInfoRequest,
) -> Result<bool, EthAppError> {
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }
    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }

    // SECURITY WARNING (CRITICAL-04): Metadata signature NOT verified.
    // See Xous-target handler for full explanation.
    let mut unverified_info = request.info.clone();
    let mut unverified_ticker = String::from("[UNVERIFIED] ");
    unverified_ticker.push_str(&unverified_info.ticker);
    unverified_info.ticker = unverified_ticker;

    state.cache_token_info(unverified_info);
    Ok(true)
}

// Stub handlers for other metadata operations.
// These validate the incoming message format but return UnsupportedOperation
// since the actual metadata processing is not yet implemented.

#[cfg(target_os = "xous")]
pub fn handle_provide_nft_info(
    _state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideNftInfoRequest;

    // Validate that we received a well-formed memory message
    let buffer = extract_buffer(&msg)?;

    // Deserialize to validate format (discard result)
    let _request: ProvideNftInfoRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_provide_nft_info called but not yet implemented");

    // Return error code indicating not yet implemented
    xous::return_scalar(msg.sender, EthAppError::UnsupportedOperation.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(target_os = "xous")]
pub fn handle_provide_domain_name(
    _state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideDomainNameRequest;

    // Validate that we received a well-formed memory message
    let buffer = extract_buffer(&msg)?;

    // Deserialize to validate format (discard result)
    let _request: ProvideDomainNameRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_provide_domain_name called but not yet implemented");

    // Return error code indicating not yet implemented
    xous::return_scalar(msg.sender, EthAppError::UnsupportedOperation.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(target_os = "xous")]
pub fn handle_load_contract_method_info(
    _state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use ethapp_common::ProvideMethodInfoRequest;

    // Validate that we received a well-formed memory message
    let buffer = extract_buffer(&msg)?;

    // Deserialize to validate format (discard result)
    let _request: ProvideMethodInfoRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    log::warn!("ethapp: handle_load_contract_method_info called but not yet implemented");

    // Return error code indicating not yet implemented
    xous::return_scalar(msg.sender, EthAppError::UnsupportedOperation.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

/// Handle ByContractAddressAndChain request.
///
/// Uses a memory message to receive chain_id (u64) + address (20 bytes).
/// A scalar message cannot carry a full Ethereum address on RV32:
/// 4 scalar args * 4 bytes (usize on RV32) = 16 bytes, but
/// chain_id (8 bytes) + address (20 bytes) = 28 bytes total needed.
#[cfg(target_os = "xous")]
pub fn handle_by_contract_address_and_chain(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    // Use memory message to receive the full chain_id + address payload.
    // Reject scalar messages -- they cannot carry a full 20-byte
    // Ethereum address on RV32 (usize = 4, so 4 args = 16 bytes max).
    let buffer = extract_buffer(&msg).map_err(|e| {
        log::warn!(
            "ethapp: handle_by_contract_address_and_chain requires a memory message, \
             scalar messages truncate the 20-byte address on RV32"
        );
        e
    })?;

    let raw: &[u8] = buffer.as_flat::<u8, _>()
        .map_err(|_| EthAppError::InvalidData)?;

    // Expect exactly 28 bytes: chain_id (8 bytes BE) + address (20 bytes)
    if raw.len() < 28 {
        return Err(EthAppError::InvalidData);
    }

    let mut chain_id_bytes = [0u8; 8];
    chain_id_bytes.copy_from_slice(&raw[..8]);
    let chain_id = u64::from_be_bytes(chain_id_bytes);

    let mut address = [0u8; 20];
    address.copy_from_slice(&raw[8..28]);

    state.set_context(chain_id, address);

    xous::return_scalar(msg.sender, 1)
        .map_err(|_| EthAppError::InternalError)
}

// =============================================================================
// Key Operation Handlers
// =============================================================================

/// Handle GetPublicKey request.
#[cfg(target_os = "xous")]
pub fn handle_get_public_key(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let buffer = extract_buffer(&msg)?;

    let path: Bip32Path = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let response = process_get_public_key(&path)?;

    let bytes = rkyv::to_bytes::<_, 128>(&response)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response_buf = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response_buf.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_public_key(
    _state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<PublicKeyResponse, EthAppError> {
    process_get_public_key(path)
}

fn process_get_public_key(path: &Bip32Path) -> Result<PublicKeyResponse, EthAppError> {
    if !path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Derive key in a scope to ensure prompt zeroization of secret material.
    let (pubkey, address) = {
        let seed = get_seed()?;
        let signing_key = derive_private_key(&seed, path)?;
        let pk = get_compressed_pubkey(&signing_key);
        let addr = public_key_to_address(&get_public_key(&signing_key));
        (pk, addr)
        // signing_key and seed dropped here, secret material zeroized
    };

    Ok(PublicKeyResponse { pubkey, address })
}

/// Handle GetAddress request.
#[cfg(target_os = "xous")]
pub fn handle_get_address(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let buffer = extract_buffer(&msg)?;

    let path: Bip32Path = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let response = process_get_public_key(&path)?;

    let mut response_buf = Buffer::into_buf(response.address.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response_buf.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_address(
    _state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<[u8; 20], EthAppError> {
    let response = process_get_public_key(path)?;
    Ok(response.address)
}

// =============================================================================
// Statistics Handler
// =============================================================================

#[cfg(target_os = "xous")]
pub fn handle_get_stats(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    let stats = state.get_stats();

    // Return stats as scalar values
    xous::return_scalar2(
        msg.sender,
        stats.signs_completed as usize,
        stats.signs_rejected as usize,
    ).map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_stats(
    state: &mut ServiceState,
    _msg: (),
) -> Result<(u64, u64, u64), EthAppError> {
    let stats = state.get_stats();
    Ok((stats.signs_completed, stats.signs_rejected, stats.errors))
}
