//! Builds the PSBTv2 key-value maps that the Ledger bitcoin app expects.
//!
//! Note: only PSBTv2 is supported by the Ledger bitcoin app, while rust-bitcoin's `Psbt` is a
//! PSBTv0. This module implements the translation from rust-bitcoin's PSBTv0 to the PSBTv2
//! key-value maps expected by the Ledger bitcoin app, while leaving the
//! serialization/deserialization logic to rust-psbt (for known fields), and propagating unknown
//! fields unchanged.

use core::{convert::TryFrom, fmt};

use bitcoin::{
    consensus::encode::{deserialize, serialize, Decodable},
    ecdsa,
    hashes::Hash,
    key::FromSliceError as KeyError,
    psbt::Psbt,
    secp256k1::{self, XOnlyPublicKey},
    taproot,
    taproot::TapLeafHash,
    PublicKey, Transaction,
};

use crate::protocol::UncheckedVarInt;

/// V0 only: the unsigned transaction. Its contents are re-expressed by the global v2 fields
/// below and by each input's and output's own keys, so it is dropped.
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const PSBT_GLOBAL_VERSION: u8 = 0xFB;

const PSBT_IN_PREVIOUS_TXID: u8 = 0x0E;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0F;
const PSBT_IN_SEQUENCE: u8 = 0x10;
const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;

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

#[non_exhaustive]
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
    /// The serialization does not start with the `psbt` magic and its `0xff` separator.
    InvalidMagic,
    /// The global `PSBT_GLOBAL_VERSION` is neither 0 nor 2.
    UnsupportedVersion(u32),
    /// A field required by the PSBT's version is missing (the v0 unsigned transaction, or the
    /// v2 input or output count), or its value cannot be decoded. Holds the global key type.
    InvalidGlobalField(u8),
    /// The same key appears twice in one map.
    DuplicateKey,
}

impl fmt::Display for PsbtV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TxMapCountMismatch => {
                f.write_str("The unsigned transaction and the PSBT maps disagree on counts")
            }
            Self::MalformedSerialization => f.write_str("Malformed PSBT serialization"),
            Self::UnexpectedV2Field(key_type) => {
                write!(f, "Unexpected PSBTv2 field {:#04x} in a PSBTv0", key_type)
            }
            Self::InvalidMagic => f.write_str("Invalid PSBT magic bytes"),
            Self::UnsupportedVersion(version) => write!(f, "Unsupported PSBT version {}", version),
            Self::InvalidGlobalField(key_type) => {
                write!(f, "Missing or invalid global PSBT field {:#04x}", key_type)
            }
            Self::DuplicateKey => f.write_str("Duplicate key in a PSBT map"),
        }
    }
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

    let outputs = maps.split_off(1 + n_inputs);
    let inputs = maps.split_off(1);
    let global = maps.pop().ok_or(PsbtV2Error::MalformedSerialization)?;

    lower_v0_maps(global, inputs, outputs, &psbt.unsigned_tx)
}

/// Returns the PSBTv2 maps of a serialized PSBT of version 0 or 2.
///
/// Unlike [`get_v2_maps`], the PSBT is not parsed into a [`Psbt`]: every key-value pair reaches
/// the maps byte for byte, so the device sees exactly the fields the caller serialized, whether
/// or not rust-bitcoin knows (or accepts) them. Only the fields needed to find the maps are
/// decoded: the unsigned transaction of a v0 PSBT, which is then lowered to its v2 fields like
/// [`get_v2_maps`] does, or the input and output counts of a v2 PSBT.
pub fn get_v2_maps_from_bytes(bytes: &[u8]) -> Result<PsbtV2Maps, PsbtV2Error> {
    let mut d = match bytes.get(..PSBT_MAGIC_LEN) {
        Some(b"psbt\xff") => &bytes[PSBT_MAGIC_LEN..],
        _ => return Err(PsbtV2Error::InvalidMagic),
    };
    let mut global = read_map(&mut d)?;

    let version = match global_value(&global, PSBT_GLOBAL_VERSION) {
        None => 0,
        Some(value) => <[u8; 4]>::try_from(value)
            .map(u32::from_le_bytes)
            .map_err(|_| PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_VERSION))?,
    };

    match version {
        0 => {
            let tx: Transaction = global_value(&global, PSBT_GLOBAL_UNSIGNED_TX)
                .and_then(|value| deserialize(value).ok())
                .ok_or(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_UNSIGNED_TX))?;
            let inputs = read_maps(&mut d, tx.input.len())?;
            let outputs = read_maps(&mut d, tx.output.len())?;
            if !d.is_empty() {
                return Err(PsbtV2Error::MalformedSerialization);
            }
            // an explicit version 0 is replaced by the synthesized version 2
            global.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_VERSION]);
            lower_v0_maps(global, inputs, outputs, &tx)
        }
        2 => {
            let n_inputs = global_count(&global, PSBT_GLOBAL_INPUT_COUNT)?;
            let n_outputs = global_count(&global, PSBT_GLOBAL_OUTPUT_COUNT)?;
            let inputs = read_maps(&mut d, n_inputs)?;
            let outputs = read_maps(&mut d, n_outputs)?;
            if !d.is_empty() {
                return Err(PsbtV2Error::MalformedSerialization);
            }
            Ok(PsbtV2Maps {
                global,
                inputs,
                outputs,
            })
        }
        version => Err(PsbtV2Error::UnsupportedVersion(version)),
    }
}

/// Replaces the unsigned transaction of v0 maps with the equivalent PSBTv2 fields.
fn lower_v0_maps(
    mut global: PsbtMap,
    mut inputs: Vec<PsbtMap>,
    mut outputs: Vec<PsbtMap>,
    tx: &Transaction,
) -> Result<PsbtV2Maps, PsbtV2Error> {
    if tx.input.len() != inputs.len() || tx.output.len() != outputs.len() {
        return Err(PsbtV2Error::TxMapCountMismatch);
    }

    // Fields that BIP-370 excludes from PSBTv0 would acquire meaning after the conversion
    // (e.g. the required locktimes override the fallback locktime), so they are rejected.
    reject_v2_fields(
        &global,
        &[
            PSBT_GLOBAL_TX_VERSION,
            PSBT_GLOBAL_FALLBACK_LOCKTIME,
            PSBT_GLOBAL_INPUT_COUNT,
            PSBT_GLOBAL_OUTPUT_COUNT,
            PSBT_GLOBAL_TX_MODIFIABLE,
        ],
    )?;
    for map in &inputs {
        reject_v2_fields(
            map,
            &[
                PSBT_IN_PREVIOUS_TXID,
                PSBT_IN_OUTPUT_INDEX,
                PSBT_IN_SEQUENCE,
                PSBT_IN_REQUIRED_TIME_LOCKTIME,
                PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
            ],
        )?;
    }
    for map in &outputs {
        reject_v2_fields(map, &[PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT])?;
    }

    global.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_UNSIGNED_TX]);

    push_v2_field(
        &mut global,
        PSBT_GLOBAL_TX_VERSION,
        tx.version.0.to_le_bytes().to_vec(),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_FALLBACK_LOCKTIME,
        serialize(&tx.lock_time),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_INPUT_COUNT,
        serialize(&UncheckedVarInt(inputs.len() as u64)),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_OUTPUT_COUNT,
        serialize(&UncheckedVarInt(outputs.len() as u64)),
    )?;
    push_v2_field(
        &mut global,
        PSBT_GLOBAL_VERSION,
        2_u32.to_le_bytes().to_vec(),
    )?;

    for (map, txin) in inputs.iter_mut().zip(tx.input.iter()) {
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

    for (map, txout) in outputs.iter_mut().zip(tx.output.iter()) {
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

/// Errors if `map` has a key of any of `key_types`, whatever its keydata.
fn reject_v2_fields(map: &PsbtMap, key_types: &[u8]) -> Result<(), PsbtV2Error> {
    match map
        .iter()
        .find_map(|(key, _)| key.first().filter(|t| key_types.contains(t)))
    {
        Some(key_type) => Err(PsbtV2Error::UnexpectedV2Field(*key_type)),
        None => Ok(()),
    }
}

/// The value of the keyless global field `key_type`, if present.
fn global_value(global: &PsbtMap, key_type: u8) -> Option<&[u8]> {
    global
        .iter()
        .find(|(key, _)| key.as_slice() == [key_type])
        .map(|(_, value)| value.as_slice())
}

/// Decodes the compact-size count held by the global field `key_type`.
fn global_count(global: &PsbtMap, key_type: u8) -> Result<usize, PsbtV2Error> {
    let mut value =
        global_value(global, key_type).ok_or(PsbtV2Error::InvalidGlobalField(key_type))?;
    let count = UncheckedVarInt::consensus_decode(&mut value)
        .map_err(|_| PsbtV2Error::InvalidGlobalField(key_type))?;
    if !value.is_empty() {
        return Err(PsbtV2Error::InvalidGlobalField(key_type));
    }
    usize::try_from(count.0).map_err(|_| PsbtV2Error::InvalidGlobalField(key_type))
}

/// Reads `n_maps` maps. `n_maps` comes from untrusted input, so nothing is preallocated for it:
/// a count larger than the data fails once the data runs out.
fn read_maps(d: &mut &[u8], n_maps: usize) -> Result<Vec<PsbtMap>, PsbtV2Error> {
    let mut maps = Vec::new();
    for _ in 0..n_maps {
        maps.push(read_map(d)?);
    }
    Ok(maps)
}

/// Reads one map up to its separator, rejecting duplicate keys.
fn read_map(d: &mut &[u8]) -> Result<PsbtMap, PsbtV2Error> {
    let map = read_map_pairs(d).ok_or(PsbtV2Error::MalformedSerialization)?;
    let mut keys: Vec<&[u8]> = map.iter().map(|(key, _)| key.as_slice()).collect();
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PsbtV2Error::DuplicateKey);
    }
    Ok(map)
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
        maps.push(read_map_pairs(&mut d)?);
    }
    Some(maps)
}

/// Reads the key-value pairs of one map and its separator, advancing `d` past them.
fn read_map_pairs(d: &mut &[u8]) -> Option<PsbtMap> {
    let mut pairs: PsbtMap = Vec::new();
    loop {
        // <map> := <keypair>* 0x00, and a key is never empty, so a zero length is the
        // separator rather than a pair.
        if *d.first()? == 0x00 {
            *d = &d[1..];
            return Some(pairs);
        }
        let key = read_prefixed(d)?;
        let value = read_prefixed(d)?;
        pairs.push((key, value));
    }
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

/// A yielded signature referred to an input that is not present in the PSBT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputIndexError {
    pub input_index: usize,
}

impl fmt::Display for InputIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PSBT input index {} is out of bounds", self.input_index)
    }
}

/// Applies a regular signature, replacing any signature already stored for that key.
/// An invalid input index leaves the PSBT unchanged.
///
/// `TapScriptSig(_, None, _)` replaces `tap_key_sig` without checking the supplied
/// key against the input's internal key. MuSig objects are not regular signatures
/// and are outside this helper's scope; clients continue to return them as yields.
pub fn apply_partial_signature(
    psbt: &mut Psbt,
    input_index: usize,
    signature: PartialSignature,
) -> Result<(), InputIndexError> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(InputIndexError { input_index })?;
    match signature {
        PartialSignature::Sig(key, signature) => {
            input.partial_sigs.insert(key, signature);
        }
        PartialSignature::TapScriptSig(key, Some(leaf), signature) => {
            input.tap_script_sigs.insert((key, leaf), signature);
        }
        PartialSignature::TapScriptSig(_, None, signature) => {
            input.tap_key_sig = Some(signature);
        }
    }
    Ok(())
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

#[derive(Debug)]
pub enum PartialSignatureError {
    BadKeyAugmentLength,
    InvalidLength,
    InvalidInputIndex,
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

    /// A key type rust-bitcoin does not know must still reach the app.
    #[test]
    fn keys_unknown_to_rust_bitcoin_are_forwarded() {
        const UNKNOWN_KEY_TYPE: u8 = 0x30;
        let value = vec![1, 2, 3];

        let mut psbt = unsigned_psbt();
        psbt.inputs[0]
            .unknown
            .insert(keyless(UNKNOWN_KEY_TYPE), value.clone());

        let maps = get_v2_maps(&psbt).unwrap();
        assert_eq!(values_for(&maps.inputs[0], UNKNOWN_KEY_TYPE), vec![&value]);
    }

    /// The BIP-370 per-input required locktimes are excluded from PSBTv0: once converted, they
    /// would override the locktime of the unsigned transaction.
    #[test]
    fn required_locktimes_are_rejected() {
        for key_type in [
            PSBT_IN_REQUIRED_TIME_LOCKTIME,
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
        ] {
            let mut psbt = unsigned_psbt();
            psbt.inputs[0]
                .unknown
                .insert(keyless(key_type), 1_u32.to_le_bytes().to_vec());
            assert_eq!(
                get_v2_maps(&psbt).err(),
                Some(PsbtV2Error::UnexpectedV2Field(key_type))
            );
        }
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

    #[test]
    fn unknown_and_proprietary_fields_survive_in_every_map() {
        let mut psbt = unsigned_psbt();
        let unknown = raw::Key {
            type_value: 0x70,
            key: vec![9],
        };
        let proprietary = raw::ProprietaryKey {
            prefix: b"hw".to_vec(),
            subtype: 1,
            key: vec![9],
        };
        psbt.unknown.insert(unknown.clone(), vec![1]);
        psbt.inputs[0].unknown.insert(unknown.clone(), vec![2]);
        psbt.outputs[0].unknown.insert(unknown, vec![3]);
        psbt.proprietary.insert(proprietary.clone(), vec![4]);
        psbt.inputs[0]
            .proprietary
            .insert(proprietary.clone(), vec![5]);
        psbt.outputs[0].proprietary.insert(proprietary, vec![6]);
        let maps = get_v2_maps(&psbt).unwrap();
        for (i, map) in [&maps.global, &maps.inputs[0], &maps.outputs[0]]
            .iter()
            .enumerate()
        {
            assert!(map.contains(&(vec![0x70, 9], vec![i as u8 + 1])));
            assert!(map.contains(&(vec![0xfc, 2, b'h', b'w', 1, 9], vec![i as u8 + 4])));
        }
    }

    #[test]
    fn every_synthesized_v2_field_rejects_conflicts() {
        for (map_index, key_types) in [
            (
                0,
                &[
                    PSBT_GLOBAL_TX_VERSION,
                    PSBT_GLOBAL_FALLBACK_LOCKTIME,
                    PSBT_GLOBAL_INPUT_COUNT,
                    PSBT_GLOBAL_OUTPUT_COUNT,
                    PSBT_GLOBAL_VERSION,
                ][..],
            ),
            (
                1,
                &[
                    PSBT_IN_PREVIOUS_TXID,
                    PSBT_IN_OUTPUT_INDEX,
                    PSBT_IN_SEQUENCE,
                ][..],
            ),
            (2, &[PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT][..]),
        ] {
            for &key_type in key_types {
                let mut psbt = unsigned_psbt();
                let map = match map_index {
                    0 => &mut psbt.unknown,
                    1 => &mut psbt.inputs[0].unknown,
                    _ => &mut psbt.outputs[0].unknown,
                };
                map.insert(keyless(key_type), vec![42]);
                assert_eq!(
                    get_v2_maps(&psbt).err(),
                    Some(PsbtV2Error::UnexpectedV2Field(key_type))
                );
            }
        }
        let mut psbt = unsigned_psbt();
        psbt.inputs.clear();
        assert_eq!(
            get_v2_maps(&psbt).err(),
            Some(PsbtV2Error::TxMapCountMismatch)
        );
    }

    fn push_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend(serialize(&UncheckedVarInt(bytes.len() as u64)));
        out.extend_from_slice(bytes);
    }

    /// Serializes maps the way a PSBT does: the magic, then each map as length-prefixed pairs
    /// ended by a separator.
    fn serialize_maps<'a>(maps: impl IntoIterator<Item = &'a PsbtMap>) -> Vec<u8> {
        let mut out = b"psbt\xff".to_vec();
        for map in maps {
            for (key, value) in map {
                push_prefixed(&mut out, key);
                push_prefixed(&mut out, value);
            }
            out.push(0x00);
        }
        out
    }

    fn all_maps(maps: &PsbtV2Maps) -> Vec<&PsbtMap> {
        let mut all = vec![&maps.global];
        all.extend(maps.inputs.iter());
        all.extend(maps.outputs.iter());
        all
    }

    fn assert_same_maps(a: &PsbtV2Maps, b: &PsbtV2Maps) {
        assert_eq!(all_maps(a), all_maps(b));
    }

    #[test]
    fn raw_v0_is_lowered_like_a_parsed_psbt() {
        let mut psbt = unsigned_psbt();
        psbt.inputs[0].unknown.insert(keyless(0x30), vec![1, 2, 3]);
        let from_bytes = get_v2_maps_from_bytes(&psbt.serialize()).unwrap();
        assert_same_maps(&from_bytes, &get_v2_maps(&psbt).unwrap());
    }

    /// Like [`get_v2_maps`], the raw path rejects the fields that BIP-370 excludes from PSBTv0.
    #[test]
    fn raw_v0_rejects_v2_only_fields() {
        for key_type in [
            PSBT_IN_REQUIRED_TIME_LOCKTIME,
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
        ] {
            let mut psbt = unsigned_psbt();
            psbt.inputs[0]
                .unknown
                .insert(keyless(key_type), 1_u32.to_le_bytes().to_vec());
            assert_eq!(
                get_v2_maps_from_bytes(&psbt.serialize()).err(),
                Some(PsbtV2Error::UnexpectedV2Field(key_type))
            );
        }
    }

    #[test]
    fn raw_v0_with_explicit_version_zero_is_lowered() {
        let psbt = unsigned_psbt();
        let maps = split_maps(&psbt.serialize(), 3).unwrap();
        let mut global = maps[0].clone();
        global.push((vec![PSBT_GLOBAL_VERSION], 0_u32.to_le_bytes().to_vec()));
        let bytes = serialize_maps([&global, &maps[1], &maps[2]]);
        let from_bytes = get_v2_maps_from_bytes(&bytes).unwrap();
        assert_same_maps(&from_bytes, &get_v2_maps(&psbt).unwrap());
    }

    /// A v2 PSBT is forwarded byte for byte, including values that a parser would reject.
    #[test]
    fn raw_v2_maps_are_forwarded_unchanged() {
        let mut maps = get_v2_maps(&unsigned_psbt()).unwrap();
        // not a valid sequence (too short), and an unknown key type
        maps.inputs[0].retain(|(key, _)| key.as_slice() != [PSBT_IN_SEQUENCE]);
        maps.inputs[0].push((vec![PSBT_IN_SEQUENCE], vec![1, 2]));
        maps.outputs[0].push((vec![0x77, 1], vec![]));
        // no fallback locktime at all
        maps.global
            .retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_FALLBACK_LOCKTIME]);

        let bytes = serialize_maps(all_maps(&maps));
        assert_same_maps(&get_v2_maps_from_bytes(&bytes).unwrap(), &maps);
    }

    #[test]
    fn raw_parsing_rejects_malformed_psbts() {
        let maps = get_v2_maps(&unsigned_psbt()).unwrap();
        let v2 = serialize_maps(all_maps(&maps));
        assert_eq!(
            get_v2_maps_from_bytes(&v2[1..]).err(),
            Some(PsbtV2Error::InvalidMagic)
        );

        let mut trailing = v2.clone();
        trailing.push(0x00);
        assert_eq!(
            get_v2_maps_from_bytes(&trailing).err(),
            Some(PsbtV2Error::MalformedSerialization)
        );
        assert_eq!(
            get_v2_maps_from_bytes(&v2[..v2.len() - 1]).err(),
            Some(PsbtV2Error::MalformedSerialization)
        );

        let with_global = |f: &dyn Fn(&mut PsbtMap)| {
            let mut global = maps.global.clone();
            f(&mut global);
            let mut all = vec![&global];
            all.extend(maps.inputs.iter());
            all.extend(maps.outputs.iter());
            get_v2_maps_from_bytes(&serialize_maps(all)).err()
        };
        let set = |global: &mut PsbtMap, key_type: u8, value: Vec<u8>| {
            global.retain(|(key, _)| key.as_slice() != [key_type]);
            global.push((vec![key_type], value));
        };

        assert_eq!(
            with_global(&|g| set(g, PSBT_GLOBAL_VERSION, 1_u32.to_le_bytes().to_vec())),
            Some(PsbtV2Error::UnsupportedVersion(1))
        );
        assert_eq!(
            with_global(&|g| set(g, PSBT_GLOBAL_VERSION, vec![2])),
            Some(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_VERSION))
        );
        assert_eq!(
            with_global(&|g| g.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_INPUT_COUNT])),
            Some(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_INPUT_COUNT))
        );
        assert_eq!(
            with_global(&|g| set(g, PSBT_GLOBAL_OUTPUT_COUNT, vec![1, 0])),
            Some(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_OUTPUT_COUNT))
        );
        // a huge count fails when the maps run out, without trying to allocate for it
        assert_eq!(
            with_global(&|g| set(g, PSBT_GLOBAL_INPUT_COUNT, vec![0xff; 9])),
            Some(PsbtV2Error::MalformedSerialization)
        );
        assert_eq!(
            with_global(&|g| g.push((vec![0x70], vec![]))),
            None,
            "an unknown key is fine"
        );
        assert_eq!(
            with_global(&|g| {
                g.push((vec![0x70], vec![]));
                g.push((vec![0x70], vec![1]));
            }),
            Some(PsbtV2Error::DuplicateKey)
        );

        // a v0 PSBT without (or with an undecodable) unsigned transaction
        let v0 = split_maps(&unsigned_psbt().serialize(), 3).unwrap();
        let mut global = v0[0].clone();
        global.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_UNSIGNED_TX]);
        assert_eq!(
            get_v2_maps_from_bytes(&serialize_maps([&global, &v0[1], &v0[2]])).err(),
            Some(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_UNSIGNED_TX))
        );
        global.push((vec![PSBT_GLOBAL_UNSIGNED_TX], vec![1, 2, 3]));
        assert_eq!(
            get_v2_maps_from_bytes(&serialize_maps([&global, &v0[1], &v0[2]])).err(),
            Some(PsbtV2Error::InvalidGlobalField(PSBT_GLOBAL_UNSIGNED_TX))
        );
    }
}
