//! Builds the PSBTv2 key-value maps that the Ledger bitcoin app expects.
//!
//! Note: only PSBTv2 is supported by the Ledger bitcoin app, while rust-bitcoin's `Psbt` is a
//! PSBTv0. This module implements the translation from rust-bitcoin's PSBTv0 to the PSBTv2
//! key-value maps expected by the Ledger bitcoin app, while leaving the
//! serialization/deserialization logic to rust-psbt (for known fields), and propagating unknown
//! fields unchanged.

use bitcoin::{
    consensus::encode::{serialize, Decodable},
    ecdsa,
    hashes::Hash,
    key::FromSliceError as KeyError,
    psbt::Psbt,
    secp256k1::{self, XOnlyPublicKey},
    taproot,
    taproot::TapLeafHash,
    PublicKey,
};

use crate::protocol::UncheckedVarInt;

/// V0 only: the unsigned transaction. Its contents are re-expressed by the global v2 fields
/// below and by each input's and output's own keys, so it is dropped.
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_VERSION: u8 = 0xFB;

const PSBT_IN_PREVIOUS_TXID: u8 = 0x0E;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0F;
const PSBT_IN_SEQUENCE: u8 = 0x10;

const PSBT_OUT_AMOUNT: u8 = 0x03;
const PSBT_OUT_SCRIPT: u8 = 0x04;

/// The `psbt` magic and its `0xff` separator, which precede the global map.
const PSBT_MAGIC_LEN: usize = 5;

/// One PSBT key-value map, in the form the app's merkleized maps take: each key is
/// `<keytype> || <keydata>` and each value is the raw value bytes, with no length prefixes.
pub type PsbtMap = Vec<(Vec<u8>, Vec<u8>)>;

/// The key-value maps of a PSBT, translated to PSBTv2.
pub struct PsbtV2Maps {
    pub global: PsbtMap,
    /// One map per PSBT input, in order.
    pub inputs: Vec<PsbtMap>,
    /// One map per PSBT output, in order.
    pub outputs: Vec<PsbtMap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtV2Error {
    /// The number of inputs or outputs of the unsigned transaction differs from the number of
    /// input or output maps, which BIP-174 requires to be equal.
    TxMapCountMismatch,
    /// The PSBT's own serialization could not be split into key-value maps. Unreachable for a
    /// `Psbt` that rust-bitcoin built.
    MalformedSerialization,
    /// An unexpected PSBTv2 field was encountered in a Psbtv0.
    UnexpectedV2Field(u8),
}

/// Returns the PSBTv2 maps for `psbt`: the global map, then one map per input, then one per
/// output.
pub fn get_v2_maps(psbt: &Psbt) -> Result<PsbtV2Maps, PsbtV2Error> {
    let n_inputs = psbt.inputs.len();
    let n_outputs = psbt.outputs.len();

    if psbt.unsigned_tx.input.len() != n_inputs || psbt.unsigned_tx.output.len() != n_outputs {
        return Err(PsbtV2Error::TxMapCountMismatch);
    }

    let mut maps = split_maps(&psbt.serialize(), 1 + n_inputs + n_outputs)
        .ok_or(PsbtV2Error::MalformedSerialization)?;

    let mut outputs = maps.split_off(1 + n_inputs);
    let mut inputs = maps.split_off(1);
    let mut global = maps.pop().ok_or(PsbtV2Error::MalformedSerialization)?;

    global.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_UNSIGNED_TX]);

    push_v2_field(
        &mut global,
        PSBT_GLOBAL_TX_VERSION,
        psbt.unsigned_tx.version.0.to_le_bytes().to_vec(),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_FALLBACK_LOCKTIME,
        serialize(&psbt.unsigned_tx.lock_time),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_INPUT_COUNT,
        serialize(&UncheckedVarInt(n_inputs as u64)),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_OUTPUT_COUNT,
        serialize(&UncheckedVarInt(n_outputs as u64)),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_VERSION,
        2_u32.to_le_bytes().to_vec(),
    )?;

    for (map, txin) in inputs.iter_mut().zip(psbt.unsigned_tx.input.iter()) {
        push_v2_field(
            map,
            PSBT_IN_PREVIOUS_TXID,
            serialize(&txin.previous_output.txid),
        )?;
        push_v2_field(
            map,
            PSBT_IN_OUTPUT_INDEX,
            serialize(&txin.previous_output.vout),
        )?;
        push_v2_field(map, PSBT_IN_SEQUENCE, serialize(&txin.sequence))?;
    }

    for (map, txout) in outputs.iter_mut().zip(psbt.unsigned_tx.output.iter()) {
        push_v2_field(
            map,
            PSBT_OUT_AMOUNT,
            txout.value.to_sat().to_le_bytes().to_vec(),
        )?;
        push_v2_field(
            map,
            PSBT_OUT_SCRIPT,
            txout.script_pubkey.as_bytes().to_vec(),
        )?;
    }

    Ok(PsbtV2Maps {
        global,
        inputs,
        outputs,
    })
}

/// Adds a keyless PSBTv2 field synthesized from the v0 unsigned transaction, erroring if the
/// PSBT already carries that key.
///
/// Only fields with no keydata go through here, so no keydata argument is present.
fn push_v2_field(map: &mut PsbtMap, key_type: u8, value: Vec<u8>) -> Result<(), PsbtV2Error> {
    if map.iter().any(|(key, _)| key.as_slice() == [key_type]) {
        return Err(PsbtV2Error::UnexpectedV2Field(key_type));
    }
    map.push((vec![key_type], value));
    Ok(())
}

/// Splits a serialized PSBT into `n_maps` key-value maps, dropping the length prefixes.
///
/// Returns `None` if the bytes are not a well-formed PSBT holding exactly that many maps.
fn split_maps(bytes: &[u8], n_maps: usize) -> Option<Vec<PsbtMap>> {
    let mut d: &[u8] = bytes.get(PSBT_MAGIC_LEN..)?;

    let mut maps = Vec::with_capacity(n_maps);
    for _ in 0..n_maps {
        let mut pairs: PsbtMap = Vec::new();
        loop {
            // <map> := <keypair>* 0x00, and a key is never empty, so a zero length is the
            // separator rather than a pair.
            if *d.first()? == 0x00 {
                d = &d[1..];
                break;
            }
            let key = read_prefixed(&mut d)?;
            let value = read_prefixed(&mut d)?;
            pairs.push((key, value));
        }
        maps.push(pairs);
    }
    Some(maps)
}

/// Reads one `<compact size length> <bytes>` field, advancing `d` past it.
fn read_prefixed(d: &mut &[u8]) -> Option<Vec<u8>> {
    let len = UncheckedVarInt::consensus_decode(d).ok()?.0;
    if len > d.len() as u64 {
        return None;
    }
    let (bytes, rest) = d.split_at(len as usize);
    *d = rest;
    Some(bytes.to_vec())
}

#[derive(Debug, Clone)]
pub enum PartialSignature {
    /// signature stored in pbst.partial_sigs
    Sig(PublicKey, ecdsa::Signature),
    /// signature stored in pbst.tap_script_sigs
    TapScriptSig(XOnlyPublicKey, Option<TapLeafHash>, taproot::Signature),
}

impl PartialSignature {
    pub fn from_slice(slice: &[u8]) -> Result<Self, PartialSignatureError> {
        let key_augment_byte = slice
            .first()
            .ok_or(PartialSignatureError::BadKeyAugmentLength)?;
        let key_augment_len = u8::from_le_bytes([*key_augment_byte]) as usize;

        if key_augment_len >= slice.len() {
            Err(PartialSignatureError::BadKeyAugmentLength)
        } else if key_augment_len == 64 {
            let key = XOnlyPublicKey::from_slice(&slice[1..33])
                .map_err(PartialSignatureError::XOnlyPubKey)?;
            let tap_leaf_hash =
                TapLeafHash::from_slice(&slice[33..65]).map_err(PartialSignatureError::TapLeaf)?;
            let sig = taproot::Signature::from_slice(&slice[key_augment_len + 1..])
                .map_err(PartialSignatureError::TaprootSig)?;
            Ok(Self::TapScriptSig(key, Some(tap_leaf_hash), sig))
        } else if key_augment_len == 32 {
            let key = XOnlyPublicKey::from_slice(&slice[1..33])
                .map_err(PartialSignatureError::XOnlyPubKey)?;
            let sig = taproot::Signature::from_slice(&slice[key_augment_len + 1..])
                .map_err(PartialSignatureError::TaprootSig)?;
            Ok(Self::TapScriptSig(key, None, sig))
        } else {
            let key = PublicKey::from_slice(&slice[1..key_augment_len + 1])
                .map_err(PartialSignatureError::PubKey)?;
            let sig = ecdsa::Signature::from_slice(&slice[key_augment_len + 1..])
                .map_err(PartialSignatureError::EcdsaSig)?;
            Ok(Self::Sig(key, sig))
        }
    }
}

pub enum PartialSignatureError {
    BadKeyAugmentLength,
    InvalidLength,
    XOnlyPubKey(secp256k1::Error),
    PubKey(KeyError),
    EcdsaSig(ecdsa::Error),
    TaprootSig(taproot::SigFromSliceError),
    TapLeaf(bitcoin::hashes::FromSliceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, psbt::raw, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };

    const LOCKTIME: u32 = 1_000;

    fn unsigned_psbt() -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(LOCKTIME),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(tx).expect("no input is signed")
    }

    fn keyless(key_type: u8) -> raw::Key {
        raw::Key {
            type_value: key_type,
            key: vec![],
        }
    }

    fn values_for(map: &[(Vec<u8>, Vec<u8>)], key_type: u8) -> Vec<&Vec<u8>> {
        map.iter()
            .filter(|(key, _)| key.as_slice() == [key_type])
            .map(|(_, value)| value)
            .collect()
    }

    #[test]
    fn global_map_is_translated_to_v2() {
        let maps = get_v2_maps(&unsigned_psbt()).unwrap();

        assert_eq!(maps.inputs.len(), 1);
        assert_eq!(maps.outputs.len(), 1);

        assert!(
            values_for(&maps.global, PSBT_GLOBAL_UNSIGNED_TX).is_empty(),
            "the v0 unsigned transaction must not be forwarded"
        );
        for key_type in [
            PSBT_GLOBAL_TX_VERSION,
            PSBT_GLOBAL_FALLBACK_LOCKTIME,
            PSBT_GLOBAL_INPUT_COUNT,
            PSBT_GLOBAL_OUTPUT_COUNT,
            PSBT_GLOBAL_VERSION,
        ]
        .iter()
        {
            assert_eq!(
                values_for(&maps.global, *key_type).len(),
                1,
                "global key type {:#04x} must be present exactly once",
                key_type
            );
        }

        // with no required locktime of its own, the PSBT's fallback comes from the unsigned tx
        assert_eq!(
            values_for(&maps.global, PSBT_GLOBAL_FALLBACK_LOCKTIME)[0],
            &LOCKTIME.to_le_bytes().to_vec()
        );
        assert_eq!(
            values_for(&maps.global, PSBT_GLOBAL_VERSION)[0],
            &2_u32.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn input_and_output_maps_get_their_v2_fields() {
        let maps = get_v2_maps(&unsigned_psbt()).unwrap();

        assert_eq!(
            values_for(&maps.inputs[0], PSBT_IN_SEQUENCE)[0],
            &Sequence::MAX.0.to_le_bytes().to_vec()
        );
        assert_eq!(values_for(&maps.inputs[0], PSBT_IN_PREVIOUS_TXID).len(), 1);
        assert_eq!(values_for(&maps.inputs[0], PSBT_IN_OUTPUT_INDEX).len(), 1);

        assert_eq!(
            values_for(&maps.outputs[0], PSBT_OUT_AMOUNT)[0],
            &1_000_u64.to_le_bytes().to_vec()
        );
        assert_eq!(values_for(&maps.outputs[0], PSBT_OUT_SCRIPT).len(), 1);
    }

    /// A key type rust-bitcoin does not know must still reach the app: this is what lets it read
    /// the BIP-370 per-input required locktimes.
    #[test]
    fn keys_unknown_to_rust_bitcoin_are_forwarded() {
        const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
        let height = 10_000_u32.to_le_bytes().to_vec();

        let mut psbt = unsigned_psbt();
        psbt.inputs[0]
            .unknown
            .insert(keyless(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME), height.clone());

        let maps = get_v2_maps(&psbt).unwrap();
        assert_eq!(
            values_for(&maps.inputs[0], PSBT_IN_REQUIRED_HEIGHT_LOCKTIME),
            vec![&height]
        );
    }

    /// A v0 PSBT that already re-encodes part of its unsigned transaction as a v2 field is a
    /// hybrid whose two encodings may disagree. It is rejected rather than resolved: emitting
    /// both would also duplicate a key, which the app rejects, since a map's keys must be
    /// strictly increasing.
    #[test]
    fn an_existing_v2_key_is_rejected() {
        // a value that contradicts the unsigned transaction, and one that agrees with it: both
        // are refused, because the PSBT is malformed either way
        for fallback in [42_u32, LOCKTIME] {
            let mut psbt = unsigned_psbt();
            psbt.unknown.insert(
                keyless(PSBT_GLOBAL_FALLBACK_LOCKTIME),
                fallback.to_le_bytes().to_vec(),
            );
            assert_eq!(
                get_v2_maps(&psbt).err(),
                Some(PsbtV2Error::UnexpectedV2Field(
                    PSBT_GLOBAL_FALLBACK_LOCKTIME
                ))
            );
        }

        let mut psbt = unsigned_psbt();
        psbt.inputs[0]
            .unknown
            .insert(keyless(PSBT_IN_SEQUENCE), 7_u32.to_le_bytes().to_vec());
        assert_eq!(
            get_v2_maps(&psbt).err(),
            Some(PsbtV2Error::UnexpectedV2Field(PSBT_IN_SEQUENCE))
        );

        let mut psbt = unsigned_psbt();
        psbt.outputs[0]
            .unknown
            .insert(keyless(PSBT_OUT_AMOUNT), 9_u64.to_le_bytes().to_vec());
        assert_eq!(
            get_v2_maps(&psbt).err(),
            Some(PsbtV2Error::UnexpectedV2Field(PSBT_OUT_AMOUNT))
        );
    }

    #[test]
    fn a_truncated_serialization_is_an_error_not_a_panic() {
        assert!(split_maps(b"psbt", 1).is_none());
        assert!(split_maps(b"psbt\xff", 1).is_none(), "no map separator");
        assert!(
            split_maps(b"psbt\xff\x00", 2).is_none(),
            "fewer maps than asked for"
        );
        // a key length that runs past the end of the buffer
        assert!(split_maps(b"psbt\xff\x08\x01\x02", 1).is_none());
    }
}
