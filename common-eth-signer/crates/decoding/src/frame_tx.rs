//! Bounded RLP decoding of EIP-8141 frame transactions (type `0x06`).
//!
//! Unlike the legacy decoders in `tx.rs`, every nesting level here honors the
//! declared list payload length: a list's items are decoded from exactly the
//! sub-slice its header declares, trailing bytes inside any list are rejected,
//! and the outer buffer must be fully consumed. `alloy_rlp::Header::decode`
//! enforces canonical header forms (minimal lengths, no non-canonical single
//! bytes) and the integer decoders reject leading zeros, so exactly one byte
//! string decodes to any given transaction. As defense in depth the decoded
//! struct is re-encoded and compared to the input before being accepted.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Header};
use signer_core::frame_tx::{
    Frame, FrameLimits, FrameMode, FrameTx, FrameTxError, FrameTxFees, SignatureEntry,
    SignatureScheme, MAX_BLOB_HASHES, MAX_FRAMES, MAX_SIGNATURE_ENTRIES,
};
use signer_core::SignerError;

fn rlp_err(e: alloy_rlp::Error) -> SignerError {
    FrameTxError::Rlp(e).into()
}

/// Decode a list header and split off exactly its declared payload.
fn take_list<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], SignerError> {
    let header = Header::decode(buf).map_err(rlp_err)?;
    if !header.list {
        return Err(rlp_err(alloy_rlp::Error::UnexpectedString));
    }
    let (payload, rest) = buf
        .split_at_checked(header.payload_length)
        .ok_or_else(|| rlp_err(alloy_rlp::Error::InputTooShort))?;
    *buf = rest;
    Ok(payload)
}

/// Decode a byte-string header and split off exactly its declared payload.
fn take_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], SignerError> {
    let header = Header::decode(buf).map_err(rlp_err)?;
    if header.list {
        return Err(rlp_err(alloy_rlp::Error::UnexpectedList));
    }
    let (payload, rest) = buf
        .split_at_checked(header.payload_length)
        .ok_or_else(|| rlp_err(alloy_rlp::Error::InputTooShort))?;
    *buf = rest;
    Ok(payload)
}

/// An optional 20-byte address field: empty byte string or exactly 20 bytes.
fn take_opt_address(
    buf: &mut &[u8],
    on_bad_len: impl FnOnce(usize) -> FrameTxError,
) -> Result<Option<Address>, SignerError> {
    let bytes = take_bytes(buf)?;
    match bytes.len() {
        0 => Ok(None),
        20 => Ok(Some(Address::try_from(bytes).map_err(|_| on_bad_len(20))?)),
        n => Err(on_bad_len(n).into()),
    }
}

/// Decode the payload of a type-`0x06` transaction (the bytes after the type
/// byte): `[chain_id, nonce, sender, frames, signatures, fees,
/// blob_versioned_hashes]`. Validates all static constraints; fails closed.
pub fn decode_frame_tx(input: &[u8]) -> Result<FrameTx, SignerError> {
    let mut buf = input;
    let mut payload = take_list(&mut buf)?;
    if !buf.is_empty() {
        return Err(FrameTxError::TrailingBytes("frame transaction payload").into());
    }

    // chain_id: the EIP allows up to 2**256 - 1, but this signer bounds it to
    // 64 bits (see `FrameTx` docs); larger values fail the u64 decode.
    let chain_id = u64::decode(&mut payload)
        .map_err(|e| match e {
            alloy_rlp::Error::Overflow => FrameTxError::ChainIdTooLarge.into(),
            other => rlp_err(other),
        })?;
    let nonce = u64::decode(&mut payload).map_err(rlp_err)?;

    let sender_bytes = take_bytes(&mut payload)?;
    let sender = Address::try_from(sender_bytes)
        .map_err(|_| FrameTxError::InvalidSenderLength(sender_bytes.len()))?;

    let frames = decode_frames(&mut payload)?;
    let signatures = decode_signatures(&mut payload)?;
    let fees = decode_fees(&mut payload)?;
    let blob_versioned_hashes = decode_blob_hashes(&mut payload)?;

    if !payload.is_empty() {
        return Err(FrameTxError::TrailingBytes("frame transaction body").into());
    }

    let tx = FrameTx {
        chain_id,
        nonce,
        sender,
        frames,
        signatures,
        fees,
        blob_versioned_hashes,
    };

    // Defense in depth: the canonical re-encoding must reproduce the wire
    // bytes, so the signature hash provably commits to exactly what was
    // decoded (and therefore displayed).
    let mut reencoded = Vec::with_capacity(input.len());
    tx.encode_payload(&mut reencoded);
    if reencoded != input {
        return Err(FrameTxError::EncodingRoundTripMismatch.into());
    }

    // Fail closed at the boundary; the signing path re-validates.
    tx.validate()?;

    Ok(tx)
}

fn decode_frames(payload: &mut &[u8]) -> Result<Vec<Frame>, SignerError> {
    let mut list = take_list(payload)?;
    let mut frames = Vec::new();
    while !list.is_empty() {
        // Cap before allocating/decoding the next item (hostile input).
        if frames.len() >= MAX_FRAMES {
            return Err(FrameTxError::TooManyFrames.into());
        }
        let index = frames.len();
        let mut f = take_list(&mut list)?;

        let mode_raw = u8::decode(&mut f).map_err(rlp_err)?;
        let mode = FrameMode::from_u8(mode_raw)
            .ok_or(FrameTxError::InvalidMode { frame: index, mode: mode_raw })?;
        let flags = u8::decode(&mut f).map_err(rlp_err)?;
        let target = take_opt_address(&mut f, |len| FrameTxError::InvalidTargetLength {
            frame: index,
            len,
        })?;

        let mut limits_payload = take_list(&mut f)?;
        let limits = FrameLimits {
            execution: u64::decode(&mut limits_payload).map_err(rlp_err)?,
            state: u64::decode(&mut limits_payload).map_err(rlp_err)?,
        };
        if !limits_payload.is_empty() {
            return Err(FrameTxError::TrailingBytes("frame limits").into());
        }

        let value = U256::decode(&mut f).map_err(rlp_err)?;
        let data = Bytes::copy_from_slice(take_bytes(&mut f)?);

        if !f.is_empty() {
            return Err(FrameTxError::TrailingBytes("frame").into());
        }
        frames.push(Frame { mode, flags, target, limits, value, data });
    }
    Ok(frames)
}

fn decode_signatures(payload: &mut &[u8]) -> Result<Vec<SignatureEntry>, SignerError> {
    let mut list = take_list(payload)?;
    let mut entries = Vec::new();
    while !list.is_empty() {
        if entries.len() >= MAX_SIGNATURE_ENTRIES {
            return Err(FrameTxError::TooManySignatures.into());
        }
        let index = entries.len();
        let mut e = take_list(&mut list)?;

        let scheme_raw = u8::decode(&mut e).map_err(rlp_err)?;
        let scheme = SignatureScheme::from_u8(scheme_raw)
            .ok_or(FrameTxError::UnknownSignatureScheme { index, scheme: scheme_raw })?;
        let signer = take_opt_address(&mut e, |len| FrameTxError::InvalidSignerLength {
            index,
            len,
        })?;

        let msg_bytes = take_bytes(&mut e)?;
        let msg = match msg_bytes.len() {
            0 => None,
            32 => Some(
                B256::try_from(msg_bytes)
                    .map_err(|_| FrameTxError::InvalidMsgLength { index, len: 32 })?,
            ),
            n => return Err(FrameTxError::InvalidMsgLength { index, len: n }.into()),
        };
        let signature = Bytes::copy_from_slice(take_bytes(&mut e)?);

        if !e.is_empty() {
            return Err(FrameTxError::TrailingBytes("signature entry").into());
        }
        entries.push(SignatureEntry { scheme, signer, msg, signature });
    }
    Ok(entries)
}

fn decode_fees(payload: &mut &[u8]) -> Result<FrameTxFees, SignerError> {
    let mut f = take_list(payload)?;
    let fees = FrameTxFees {
        max_priority_fee_per_gas: U256::decode(&mut f).map_err(rlp_err)?,
        max_fee_per_gas: U256::decode(&mut f).map_err(rlp_err)?,
        max_fee_per_blob_gas: U256::decode(&mut f).map_err(rlp_err)?,
    };
    if !f.is_empty() {
        return Err(FrameTxError::TrailingBytes("fees").into());
    }
    Ok(fees)
}

fn decode_blob_hashes(payload: &mut &[u8]) -> Result<Vec<B256>, SignerError> {
    let mut list = take_list(payload)?;
    let mut hashes = Vec::new();
    while !list.is_empty() {
        if hashes.len() >= MAX_BLOB_HASHES {
            return Err(FrameTxError::TooManyBlobHashes.into());
        }
        let index = hashes.len();
        let bytes = take_bytes(&mut list)?;
        let hash = B256::try_from(bytes)
            .map_err(|_| FrameTxError::InvalidBlobHash { index })?;
        hashes.push(hash);
    }
    Ok(hashes)
}
