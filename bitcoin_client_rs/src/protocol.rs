//! This module contains types that are specific to the Ledger Bitcoin application protocol.

use bitcoin::{
    consensus::encode::{deserialize_partial, VarInt},
    hashes::Hash,
    taproot::TapLeafHash,
    PublicKey,
};

use crate::psbt::{PartialSignature, PartialSignatureError};

/// Tag yielded by the device to introduce a MuSig2 pubnonce payload.
pub const CCMD_YIELD_MUSIG_PUBNONCE_TAG: u64 = 0xFFFFFFFF;
/// Tag yielded by the device to introduce a MuSig2 partial-signature payload.
pub const CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG: u64 = 0xFFFFFFFE;

/// A MuSig2 public nonce yielded by the device during the first round of a
/// MuSig2 signing session, as specified in BIP-373.
#[derive(Debug, Clone)]
pub struct MusigPubNonce {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 66-byte pubnonce.
    pub pubnonce: [u8; 66],
}

/// A MuSig2 partial signature yielded by the device during the second round of
/// a MuSig2 signing session, as specified in BIP-373
///
/// Note: not to be confused with [`PartialSignature`], which represents a
/// regular ECDSA or Schnorr signature for a single input.
#[derive(Debug, Clone)]
pub struct MusigPartialSignature {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 32-byte partial signature for this participant.
    pub partial_signature: [u8; 32],
}

/// An object yielded by the device while signing a PSBT.
///
/// The variants cover the different kinds of payload the device can produce.
/// The enum is `#[non_exhaustive]`: callers must include a wildcard arm so that
/// new payload kinds introduced in future protocol versions do not cause
/// compilation failures in existing code.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SignPsbtYieldedObject {
    /// A regular partial signature for a PSBT input.
    Partial(PartialSignature),
    /// A MuSig2 public nonce (round 1).
    MusigPubNonce(MusigPubNonce),
    /// A MuSig2 partial signature (round 2).
    MusigPartialSignature(MusigPartialSignature),
    /// An unknown payload with an unrecognized tag; the original bytes are included for reference.
    Unknown(Vec<u8>),
}

/// Parses a single payload yielded by the device during `sign_psbt`.
///
/// On success returns the input index together with the decoded object.
pub fn parse_sign_psbt_yielded(
    data: &[u8],
) -> Result<(usize, SignPsbtYieldedObject), PartialSignatureError> {
    let (tag, i): (VarInt, usize) =
        deserialize_partial(data).map_err(|_| PartialSignatureError::InvalidLength)?;

    match tag.0 {
        CCMD_YIELD_MUSIG_PUBNONCE_TAG => {
            let (input_index, j): (VarInt, usize) = deserialize_partial(&data[i..])
                .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 66-byte pubnonce || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 132 && rest.len() != 164 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut pubnonce = [0u8; 66];
            pubnonce.copy_from_slice(&rest[0..66]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[66..99]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[99..132]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 164 {
                Some(
                    TapLeafHash::from_slice(&rest[132..164])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                input_index.0 as usize,
                SignPsbtYieldedObject::MusigPubNonce(MusigPubNonce {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    pubnonce,
                }),
            ))
        }
        CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG => {
            let (input_index, j): (VarInt, usize) = deserialize_partial(&data[i..])
                .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 32-byte partial signature || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 98 && rest.len() != 130 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut partial_signature = [0u8; 32];
            partial_signature.copy_from_slice(&rest[0..32]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[32..65]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[65..98]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 130 {
                Some(
                    TapLeafHash::from_slice(&rest[98..130])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                input_index.0 as usize,
                SignPsbtYieldedObject::MusigPartialSignature(MusigPartialSignature {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    partial_signature,
                }),
            ))
        }
        // Reserved tag range used by the protocol for non-input-index payloads.
        // Tags in this range that are not explicitly handled above are unknown to this client version, and reserved
        // for future use.
        tag_value if tag_value >= 0x80000000 => {
            // Future tags are expected to follow the same layout, using the first varint to refer to the input index
            let (input_index, j): (VarInt, usize) = deserialize_partial(&data[i..])
                .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            Ok((
                input_index.0 as usize,
                SignPsbtYieldedObject::Unknown(rest.to_vec()),
            ))
        }
        // Otherwise the leading varint is the input index and the remainder is a regular partial signature.
        // These are the only payloads that were used in protocol versions prior to the introduction of the tags.
        _ => {
            let input_index = tag.0 as usize;
            let ps = PartialSignature::from_slice(&data[i..])?;
            Ok((input_index, SignPsbtYieldedObject::Partial(ps)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use hex_literal::hex;

    // Arbitrary valid compressed secp256k1 pubkey (no special meaning).
    const PUBKEY: [u8; 33] =
        hex!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // x-only version of the same pubkey (drops the 0x03 prefix).
    const XONLY: [u8; 32] =
        hex!("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // 32-byte tapleaf hash placeholder (any 32 bytes are accepted by from_slice).
    const TAPLEAF: [u8; 32] =
        hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    fn parse_ok(payload: &[u8]) -> (usize, SignPsbtYieldedObject) {
        match parse_sign_psbt_yielded(payload) {
            Ok(v) => v,
            Err(_) => panic!("parse_sign_psbt_yielded returned an unexpected error"),
        }
    }

    #[test]
    fn parse_legacy_partial_taproot_no_tapleaf() {
        // Layout (untagged, used by protocol versions <= 2.1):
        //   varint(input_index) || key_augment_len(=32) || 32-byte x-only pk || 64-byte schnorr sig
        let mut payload = serialize(&VarInt(3));
        payload.push(32);
        payload.extend(XONLY);
        payload.extend([0xAAu8; 64]);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 3);
        match obj {
            SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(_, tlh, _)) => {
                assert!(tlh.is_none());
            }
            other => panic!("expected TapScriptSig without tapleaf, got {:?}", other),
        }
    }

    fn build_musig_pubnonce(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&VarInt(CCMD_YIELD_MUSIG_PUBNONCE_TAG));
        payload.extend(serialize(&VarInt(input_index)));
        payload.extend([0xAAu8; 66]); // pubnonce
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_pubnonce_without_tapleaf() {
        let payload = build_musig_pubnonce(7, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 7);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                assert!(n.tapleaf_hash.is_none());
                assert_eq!(n.pubnonce, [0xAAu8; 66]);
                assert_eq!(n.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(n.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_with_tapleaf() {
        let payload = build_musig_pubnonce(0, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 0);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                let tlh = n.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    fn build_musig_partial_sig(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&VarInt(CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG));
        payload.extend(serialize(&VarInt(input_index)));
        payload.extend([0xBBu8; 32]); // partial signature
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_partial_signature_without_tapleaf() {
        let payload = build_musig_partial_sig(2, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 2);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                assert!(s.tapleaf_hash.is_none());
                assert_eq!(s.partial_signature, [0xBBu8; 32]);
                assert_eq!(s.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(s.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_partial_signature_with_tapleaf() {
        let payload = build_musig_partial_sig(42, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 42);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                let tlh = s.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_reserved_tag() {
        // Any tag in the reserved range (>= 0x80000000) that this client version does
        // not explicitly handle must surface as `Unknown` while preserving input_index
        // and the trailing payload verbatim.
        const UNKNOWN_TAG: u64 = 0x89AB_CDEF;
        let trailer = hex!("deadbeef");

        let mut payload = serialize(&VarInt(UNKNOWN_TAG));
        payload.extend(serialize(&VarInt(11)));
        payload.extend(&trailer);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 11);
        match obj {
            SignPsbtYieldedObject::Unknown(bytes) => assert_eq!(bytes, trailer),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_wrong_trailer_length_is_error() {
        // Drop one byte from the aggregate pubkey to make the trailer length invalid
        // (133 bytes instead of 132 or 164).
        let mut payload = build_musig_pubnonce(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_partial_signature_wrong_trailer_length_is_error() {
        let mut payload = build_musig_partial_sig(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_pubnonce_truncated_input_is_error() {
        // Truncate so the participant pubkey is missing entirely.
        let full = build_musig_pubnonce(0, false);
        // tag(5) + input_index(1) + pubnonce(66) = 72 bytes; cut everything after that.
        let truncated = &full[..72];
        assert!(matches!(
            parse_sign_psbt_yielded(truncated),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_pubnonce_invalid_participant_pubkey_is_error() {
        // Replace the participant pubkey (33 bytes after the 66-byte nonce) with all
        // zeros, which is not a valid encoded compressed pubkey.
        let mut payload = build_musig_pubnonce(0, false);
        // tag(5 bytes for 0xFFFFFFFF) + input_index(1) + pubnonce(66) = 72.
        let pubkey_offset = 72;
        for b in &mut payload[pubkey_offset..pubkey_offset + 33] {
            *b = 0x00;
        }
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::PubKey(_))
        ));
    }
}
