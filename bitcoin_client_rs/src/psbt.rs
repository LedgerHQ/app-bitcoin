//! Builds the PSBTv2 key-value maps that the Ledger bitcoin app expects.
//!
//! Note: only PSBTv2 is supported by the Ledger bitcoin app, while rust-bitcoin's `Psbt` is a
//! PSBTv0. The translation is deliberately *subtractive and additive over the whole map* rather
//! than field by field: the pairs come from rust-bitcoin's own serialization, so every key it
//! round-trips is forwarded -- typed fields, proprietary keys and unknown keys alike -- and only
//! the handful of keys where v0 and v2 actually differ is touched.
//!
//! This matters because rust-bitcoin gives types only to the fields it knows. A field it learns
//! to parse in some future version moves out of `unknown` and into a typed field; an enumeration
//! of the fields to forward would then silently stop forwarding it, with no compile error. Two
//! concrete examples of keys rust-bitcoin 0.32 does not type, and which the app does read:
//! PSBT_IN_REQUIRED_TIME_LOCKTIME (0x11) and PSBT_IN_REQUIRED_HEIGHT_LOCKTIME (0x12), which the
//! app uses to determine the transaction's nLockTime per BIP-370.

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
    /// input or output maps, which BIP-174 requires to be equal. With fewer inputs or outputs
    /// than maps, a map would have no prevout or txout to take its v2 fields from; with more,
    /// the surplus would be dropped, silently signing a different transaction.
    TxMapCountMismatch,
    /// The PSBT's own serialization could not be split into key-value maps. Unreachable for a
    /// `Psbt` that rust-bitcoin built; it exists so that this module never panics.
    MalformedSerialization,
}

/// Returns the PSBTv2 maps for `psbt`: the global map, then one map per input, then one per
/// output.
pub fn get_v2_maps(psbt: &Psbt) -> Result<PsbtV2Maps, PsbtV2Error> {
    let n_inputs = psbt.inputs.len();
    let n_outputs = psbt.outputs.len();

    if psbt.unsigned_tx.input.len() != n_inputs || psbt.unsigned_tx.output.len() != n_outputs {
        return Err(PsbtV2Error::TxMapCountMismatch);
    }

    // One serialization for the whole PSBT, split into its maps: the global map, then one per
    // input, then one per output (see Psbt::serialize_to_writer).
    let mut maps = split_maps(&psbt.serialize(), 1 + n_inputs + n_outputs)
        .ok_or(PsbtV2Error::MalformedSerialization)?;

    let mut outputs = maps.split_off(1 + n_inputs);
    let mut inputs = maps.split_off(1);
    let mut global = maps.pop().ok_or(PsbtV2Error::MalformedSerialization)?;

    global.retain(|(key, _)| key.as_slice() != [PSBT_GLOBAL_UNSIGNED_TX]);

    push_if_absent(&mut global, PSBT_GLOBAL_TX_VERSION, || {
        psbt.unsigned_tx.version.0.to_le_bytes().to_vec()
    });
    push_if_absent(&mut global, PSBT_GLOBAL_FALLBACK_LOCKTIME, || {
        serialize(&psbt.unsigned_tx.lock_time)
    });
    push_if_absent(&mut global, PSBT_GLOBAL_INPUT_COUNT, || {
        serialize(&UncheckedVarInt(n_inputs as u64))
    });
    push_if_absent(&mut global, PSBT_GLOBAL_OUTPUT_COUNT, || {
        serialize(&UncheckedVarInt(n_outputs as u64))
    });
    push_if_absent(&mut global, PSBT_GLOBAL_VERSION, || {
        2_u32.to_le_bytes().to_vec()
    });

    for (map, txin) in inputs.iter_mut().zip(psbt.unsigned_tx.input.iter()) {
        push_if_absent(map, PSBT_IN_PREVIOUS_TXID, || {
            serialize(&txin.previous_output.txid)
        });
        push_if_absent(map, PSBT_IN_OUTPUT_INDEX, || {
            serialize(&txin.previous_output.vout)
        });
        push_if_absent(map, PSBT_IN_SEQUENCE, || serialize(&txin.sequence));
    }

    for (map, txout) in outputs.iter_mut().zip(psbt.unsigned_tx.output.iter()) {
        push_if_absent(map, PSBT_OUT_AMOUNT, || {
            txout.value.to_sat().to_le_bytes().to_vec()
        });
        push_if_absent(map, PSBT_OUT_SCRIPT, || {
            txout.script_pubkey.as_bytes().to_vec()
        });
    }

    Ok(PsbtV2Maps {
        global,
        inputs,
        outputs,
    })
}

/// Adds a keyless PSBTv2 field, unless the PSBT already carries that key.
///
/// The guard is what lets a PSBT that already holds genuine v2 keys keep its own values instead
/// of having ones synthesized from the v0 unsigned transaction pushed next to them. Pushing both
/// would put the same key in the map twice, and the app rejects a map whose keys are not strictly
/// increasing.
///
/// Only the keyless fields this module synthesizes go through here, so a key is "the same" when
/// it is the type byte alone: a keyed or proprietary field that happens to share the type byte
/// has a different key and does not suppress anything.
fn push_if_absent<F>(map: &mut PsbtMap, key_type: u8, value: F)
where
    F: FnOnce() -> Vec<u8>,
{
    if map.iter().any(|(key, _)| key.as_slice() == [key_type]) {
        return;
    }
    map.push((vec![key_type], value()));
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

    /// A PSBT that already carries a v2 key keeps its own value, and the key appears once: a
    /// duplicate would make the app reject the map, whose keys must be strictly increasing.
    #[test]
    fn an_existing_v2_key_is_not_duplicated() {
        let own_fallback = 42_u32.to_le_bytes().to_vec();

        let mut psbt = unsigned_psbt();
        psbt.unknown
            .insert(keyless(PSBT_GLOBAL_FALLBACK_LOCKTIME), own_fallback.clone());
        psbt.inputs[0]
            .unknown
            .insert(keyless(PSBT_IN_SEQUENCE), 7_u32.to_le_bytes().to_vec());

        let maps = get_v2_maps(&psbt).unwrap();
        assert_eq!(
            values_for(&maps.global, PSBT_GLOBAL_FALLBACK_LOCKTIME),
            vec![&own_fallback],
            "the PSBT's own fallback locktime must win over the unsigned tx's"
        );
        assert_eq!(
            values_for(&maps.inputs[0], PSBT_IN_SEQUENCE),
            vec![&7_u32.to_le_bytes().to_vec()]
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
