/// code is from github.com/rust-bitcoin/rust-bitcoin
/// SPDX-License-Identifier: CC0-1.0
///
/// Note: Only psbt V2 is supported by the ledger bitcoin app.
/// rust-bitcoin currently support V0.
use bitcoin::{
    blockdata::transaction::{TxIn, TxOut},
    consensus::encode::{deserialize, serialize, VarInt},
    ecdsa,
    hashes::Hash,
    key::FromSliceError as KeyError,
    psbt::{raw, Input, Output, Psbt},
    secp256k1::{self, XOnlyPublicKey},
    taproot,
    taproot::TapLeafHash,
    PublicKey,
};

use serialize::Serialize;

#[rustfmt::skip]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push(bitcoin::psbt::raw::Pair {
                key: bitcoin::psbt::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push(bitcoin::psbt::raw::Pair {
                key: bitcoin::psbt::raw::Key {
                    type_value: $keyed_typeval,
                    key: Serialize::serialize(key),
                },
                value: Serialize::serialize(val),
            });
        }
    };
}

/// V0, Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
/// const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// V2 field
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
/// V2 field
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// V2 field
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// V2 field
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// V2 field
/// const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;

pub fn get_v2_global_pairs(psbt: &Psbt) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    for (xpub, (fingerprint, derivation)) in &psbt.xpub {
        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSBT_GLOBAL_XPUB,
                key: xpub.encode().to_vec(),
            },
            value: {
                let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                ret.extend(fingerprint.as_bytes());
                derivation
                    .into_iter()
                    .for_each(|n| ret.extend(u32::from(*n).to_le_bytes()));
                ret
            },
        });
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_FALLBACK_LOCKTIME,
            key: vec![],
        },
        value: serialize(&psbt.unsigned_tx.lock_time),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_INPUT_COUNT,
            key: vec![],
        },
        value: serialize(&VarInt(psbt.inputs.len() as u64)),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_OUTPUT_COUNT,
            key: vec![],
        },
        value: serialize(&VarInt(psbt.outputs.len() as u64)),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_TX_VERSION,
            key: vec![],
        },
        value: psbt.unsigned_tx.version.0.to_le_bytes().to_vec(),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_VERSION,
            key: vec![],
        },
        value: 2_u32.to_le_bytes().to_vec(),
    });

    for (key, value) in psbt.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in psbt.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Witness UTXO PSBT_IN_WITNESS_UTXO = 0x01
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: Witness Script PSBT_IN_WITNESS_SCRIPT = 0x05
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Type: BIP 32 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: Finalized scriptWitness PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// V2
const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
/// V2
const PSBT_IN_SEQUENCE: u8 = 0x10;
/// V2
/// const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
/// V2
///const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
const PSBT_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
const PSBT_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
const PSBT_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
const PSBT_IN_HASH256: u8 = 0x0d;
/// Type: Schnorr Signature in Key Spend PSBT_IN_TAP_KEY_SIG = 0x13
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
/// Type: Schnorr Signature in Script Spend PSBT_IN_TAP_SCRIPT_SIG = 0x14
const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Type: Taproot Leaf Script PSBT_IN_TAP_LEAF_SCRIPT = 0x14
const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_IN_TAP_BIP32_DERIVATION = 0x16
const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
/// Type: Taproot Internal Key PSBT_IN_TAP_INTERNAL_KEY = 0x17
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Type: Taproot Merkle Root PSBT_IN_TAP_MERKLE_ROOT = 0x18
const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;

pub fn get_v2_input_pairs(input: &Input, txin: &TxIn) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    impl_psbt_get_pair! {
        rv.push(input.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
    }

    impl_psbt_get_pair! {
        rv.push(input.witness_utxo, PSBT_IN_WITNESS_UTXO)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.partial_sigs, PSBT_IN_PARTIAL_SIG)
    }

    impl_psbt_get_pair! {
        rv.push(input.sighash_type, PSBT_IN_SIGHASH_TYPE)
    }

    impl_psbt_get_pair! {
        rv.push(input.redeem_script, PSBT_IN_REDEEM_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push(input.witness_script, PSBT_IN_WITNESS_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.bip32_derivation, PSBT_IN_BIP32_DERIVATION)
    }

    impl_psbt_get_pair! {
        rv.push(input.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_PREVIOUS_TXID,
            key: vec![],
        },
        value: serialize(&txin.previous_output.txid),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_OUTPUT_INDEX,
            key: vec![],
        },
        value: serialize(&txin.previous_output.vout),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_SEQUENCE,
            key: vec![],
        },
        value: serialize(&txin.sequence),
    });

    impl_psbt_get_pair! {
        rv.push(input.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.ripemd160_preimages, PSBT_IN_RIPEMD160)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.sha256_preimages, PSBT_IN_SHA256)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.hash160_preimages, PSBT_IN_HASH160)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.hash256_preimages, PSBT_IN_HASH256)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
    }

    for (key, value) in input.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in input.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

/// Type: Redeem Script PSBT_OUT_REDEEM_SCRIPT = 0x00
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness Script PSBT_OUT_WITNESS_SCRIPT = 0x01
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSBT_OUT_BIP32_DERIVATION = 0x02
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
/// V2
const PSBT_OUT_AMOUNT: u8 = 0x03;
/// V2
const PSBT_OUT_SCRIPT: u8 = 0x04;
/// Type: Taproot Internal Key PSBT_OUT_TAP_INTERNAL_KEY = 0x05
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
/// Type: Taproot Tree PSBT_OUT_TAP_TREE = 0x06
const PSBT_OUT_TAP_TREE: u8 = 0x06;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;

pub fn get_v2_output_pairs(output: &Output, txout: &TxOut) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    impl_psbt_get_pair! {
        rv.push(output.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push(output.witness_script, PSBT_OUT_WITNESS_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(output.bip32_derivation, PSBT_OUT_BIP32_DERIVATION)
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_OUT_AMOUNT,
            key: vec![],
        },
        value: txout.value.to_sat().to_le_bytes().to_vec(),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_OUT_SCRIPT,
            key: vec![],
        },
        value: txout.script_pubkey.as_bytes().to_vec(),
    });

    impl_psbt_get_pair! {
        rv.push(output.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
    }

    impl_psbt_get_pair! {
        rv.push(output.tap_tree, PSBT_OUT_TAP_TREE)
    }

    impl_psbt_get_pair! {
        rv.push_map(output.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
    }

    for (key, value) in output.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in output.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

pub fn deserialize_pair(pair: raw::Pair) -> (Vec<u8>, Vec<u8>) {
    (
        deserialize(&Serialize::serialize(&pair.key)).unwrap(),
        pair.value,
    )
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

mod serialize {
    use core::convert::{TryFrom, TryInto};

    use bitcoin::{
        bip32::{ChildNumber, Fingerprint, KeySource},
        blockdata::{
            script::ScriptBuf,
            transaction::{Transaction, TxOut},
            witness::Witness,
        },
        consensus::encode::{self, deserialize_partial, serialize, Decodable, Encodable},
        ecdsa,
        hashes::{hash160, ripemd160, sha256, sha256d, Hash},
        key::PublicKey,
        psbt::{Error, PsbtSighashType},
        secp256k1::{self, XOnlyPublicKey},
        taproot,
        taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTree, TaprootBuilder},
        VarInt,
    };

    macro_rules! impl_psbt_de_serialize {
        ($thing:ty) => {
            impl_psbt_serialize!($thing);
            impl_psbt_deserialize!($thing);
        };
    }

    macro_rules! impl_psbt_deserialize {
        ($thing:ty) => {
            impl Deserialize for $thing {
                fn deserialize(bytes: &[u8]) -> Result<Self, bitcoin::psbt::Error> {
                    bitcoin::consensus::deserialize(&bytes[..])
                        .map_err(|e| bitcoin::psbt::Error::from(e))
                }
            }
        };
    }

    macro_rules! impl_psbt_serialize {
        ($thing:ty) => {
            impl Serialize for $thing {
                fn serialize(&self) -> Vec<u8> {
                    bitcoin::consensus::serialize(self)
                }
            }
        };
    }

    // macros for serde of hashes
    macro_rules! impl_psbt_hash_de_serialize {
        ($hash_type:ty) => {
            impl_psbt_hash_serialize!($hash_type);
            impl_psbt_hash_deserialize!($hash_type);
        };
    }

    macro_rules! impl_psbt_hash_deserialize {
        ($hash_type:ty) => {
            impl $crate::psbt::serialize::Deserialize for $hash_type {
                fn deserialize(bytes: &[u8]) -> Result<Self, bitcoin::psbt::Error> {
                    <$hash_type>::from_slice(&bytes[..]).map_err(|e| bitcoin::psbt::Error::from(e))
                }
            }
        };
    }

    macro_rules! impl_psbt_hash_serialize {
        ($hash_type:ty) => {
            impl $crate::psbt::serialize::Serialize for $hash_type {
                fn serialize(&self) -> Vec<u8> {
                    self.as_byte_array().to_vec()
                }
            }
        };
    }

    /// A trait for serializing a value as raw data for insertion into PSBT
    /// key-value maps.
    pub(crate) trait Serialize {
        /// Serialize a value as raw data.
        fn serialize(&self) -> Vec<u8>;
    }

    /// A trait for deserializing a value from raw data in PSBT key-value maps.
    pub(crate) trait Deserialize: Sized {
        /// Deserialize a value from raw data.
        fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
    }

    impl_psbt_de_serialize!(Transaction);
    impl_psbt_de_serialize!(TxOut);
    impl_psbt_de_serialize!(Witness);
    impl_psbt_hash_de_serialize!(ripemd160::Hash);
    impl_psbt_hash_de_serialize!(sha256::Hash);
    impl_psbt_hash_de_serialize!(TapLeafHash);
    impl_psbt_hash_de_serialize!(TapNodeHash);
    impl_psbt_hash_de_serialize!(hash160::Hash);
    impl_psbt_hash_de_serialize!(sha256d::Hash);

    // taproot
    impl_psbt_de_serialize!(Vec<TapLeafHash>);

    impl Serialize for bitcoin::psbt::raw::Key {
        fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            VarInt((self.key.len() + 1) as u64)
                .consensus_encode(&mut buf)
                .expect("in-memory writers don't error");

            self.type_value
                .consensus_encode(&mut buf)
                .expect("in-memory writers don't error");

            for key in &self.key {
                key.consensus_encode(&mut buf)
                    .expect("in-memory writers don't error");
            }

            buf
        }
    }

    impl Serialize for ScriptBuf {
        fn serialize(&self) -> Vec<u8> {
            self.to_bytes()
        }
    }

    impl Deserialize for ScriptBuf {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self::from(bytes.to_vec()))
        }
    }

    impl Serialize for PublicKey {
        fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            self.write_into(&mut buf).expect("vecs don't error");
            buf
        }
    }

    impl Deserialize for PublicKey {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            PublicKey::from_slice(bytes).map_err(Error::InvalidPublicKey)
        }
    }

    impl Serialize for secp256k1::PublicKey {
        fn serialize(&self) -> Vec<u8> {
            self.serialize().to_vec()
        }
    }

    impl Deserialize for secp256k1::PublicKey {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            secp256k1::PublicKey::from_slice(bytes).map_err(Error::InvalidSecp256k1PublicKey)
        }
    }

    impl Serialize for ecdsa::Signature {
        fn serialize(&self) -> Vec<u8> {
            self.to_vec()
        }
    }

    impl Deserialize for ecdsa::Signature {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            // NB: Since BIP-174 says "the signature as would be pushed to the stack from
            // a scriptSig or witness" we should ideally use a consensus deserialization and do
            // not error on a non-standard values. However,
            //
            // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
            // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
            // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
            // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
            //
            // 2) This would cause to have invalid signatures because the sighash message
            // also has a field sighash_u32 (See BIP141). For example, when signing with non-standard
            // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
            // would use check the signature assuming sighash_u32 as `0x01`.
            ecdsa::Signature::from_slice(bytes).map_err(|e| match e {
                ecdsa::Error::EmptySignature => Error::InvalidEcdsaSignature(e),
                ecdsa::Error::SighashType(flag) => Error::NonStandardSighashType(flag.0),
                ecdsa::Error::Secp256k1(..) => Error::InvalidEcdsaSignature(e),
                ecdsa::Error::Hex(..) => {
                    unreachable!("Decoding from slice, not hex")
                }
                _ => Error::InvalidEcdsaSignature(e),
            })
        }
    }

    impl Serialize for KeySource {
        fn serialize(&self) -> Vec<u8> {
            let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

            rv.append(&mut self.0.to_bytes().to_vec());

            for cnum in self.1.into_iter() {
                rv.append(&mut serialize(&u32::from(*cnum)))
            }

            rv
        }
    }

    impl Deserialize for KeySource {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() < 4 {
                return Err(Error::ConsensusEncoding(
                    bitcoin::consensus::encode::Error::ParseFailed(
                        "Not enough bytes for key source",
                    ),
                ));
            }

            let fprint: Fingerprint = bytes[0..4].try_into().expect("4 is the fingerprint length");
            let mut dpath: Vec<ChildNumber> = Default::default();

            let mut d = &bytes[4..];
            while !d.is_empty() {
                match u32::consensus_decode(&mut d) {
                    Ok(index) => dpath.push(index.into()),
                    Err(e) => return Err(e)?,
                }
            }

            Ok((fprint, dpath.into()))
        }
    }

    // partial sigs
    impl Serialize for Vec<u8> {
        fn serialize(&self) -> Vec<u8> {
            self.clone()
        }
    }

    impl Deserialize for Vec<u8> {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            Ok(bytes.to_vec())
        }
    }

    impl Serialize for PsbtSighashType {
        fn serialize(&self) -> Vec<u8> {
            serialize(&self.to_u32())
        }
    }

    impl Deserialize for PsbtSighashType {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            let raw: u32 = encode::deserialize(bytes)?;
            Ok(PsbtSighashType::from_u32(raw))
        }
    }

    // Taproot related ser/deser
    impl Serialize for XOnlyPublicKey {
        fn serialize(&self) -> Vec<u8> {
            XOnlyPublicKey::serialize(self).to_vec()
        }
    }

    impl Deserialize for XOnlyPublicKey {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            XOnlyPublicKey::from_slice(bytes).map_err(|_| Error::InvalidXOnlyPublicKey)
        }
    }

    impl Serialize for taproot::Signature {
        fn serialize(&self) -> Vec<u8> {
            self.to_vec()
        }
    }

    impl Deserialize for taproot::Signature {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            taproot::Signature::from_slice(bytes).map_err(Error::InvalidTaprootSignature)
        }
    }

    impl Serialize for (XOnlyPublicKey, TapLeafHash) {
        fn serialize(&self) -> Vec<u8> {
            let ser_pk = self.0.serialize();
            let mut buf = Vec::with_capacity(ser_pk.len() + self.1.as_byte_array().len());
            buf.extend(ser_pk);
            buf.extend(self.1.as_byte_array());
            buf
        }
    }

    impl Deserialize for (XOnlyPublicKey, TapLeafHash) {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() < 32 {
                return Err(Error::ConsensusEncoding(
                    bitcoin::consensus::encode::Error::ParseFailed(
                        "Not enough bytes for public key and tapleaf hash",
                    ),
                ));
            }
            let a: XOnlyPublicKey = Deserialize::deserialize(&bytes[..32])?;
            let b: TapLeafHash = Deserialize::deserialize(&bytes[32..])?;
            Ok((a, b))
        }
    }

    impl Serialize for ControlBlock {
        fn serialize(&self) -> Vec<u8> {
            ControlBlock::serialize(self)
        }
    }

    impl Deserialize for ControlBlock {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            Self::decode(bytes).map_err(|_| Error::InvalidControlBlock)
        }
    }

    // Versioned ScriptBuf
    impl Serialize for (ScriptBuf, LeafVersion) {
        fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::with_capacity(self.0.len() + 1);
            buf.extend(self.0.as_bytes());
            buf.push(self.1.to_consensus());
            buf
        }
    }

    impl Deserialize for (ScriptBuf, LeafVersion) {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.is_empty() {
                return Err(Error::ConsensusEncoding(
                    bitcoin::consensus::encode::Error::ParseFailed(
                        "Not enough bytes for script buf and leaf version",
                    ),
                ));
            }
            // The last byte is LeafVersion.
            let script = ScriptBuf::deserialize(&bytes[..bytes.len() - 1])?;
            let leaf_ver = LeafVersion::from_consensus(bytes[bytes.len() - 1])
                .map_err(|_| Error::InvalidLeafVersion)?;
            Ok((script, leaf_ver))
        }
    }

    impl Serialize for (Vec<TapLeafHash>, KeySource) {
        fn serialize(&self) -> Vec<u8> {
            let mut buf = Vec::with_capacity(32 * self.0.len() + key_source_len(&self.1));
            self.0
                .consensus_encode(&mut buf)
                .expect("Vecs don't error allocation");
            // TODO: Add support for writing into a writer for key-source
            buf.extend(self.1.serialize());
            buf
        }
    }

    impl Deserialize for (Vec<TapLeafHash>, KeySource) {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            let (leafhash_vec, consumed) = deserialize_partial::<Vec<TapLeafHash>>(bytes)?;
            let key_source = KeySource::deserialize(&bytes[consumed..])?;
            Ok((leafhash_vec, key_source))
        }
    }

    impl Serialize for TapTree {
        fn serialize(&self) -> Vec<u8> {
            let capacity = self
                .script_leaves()
                .map(|l| {
                    l.script().len() + VarInt(l.script().len() as u64).size() // script version
            + 1 // merkle branch
            + 1 // leaf version
                })
                .sum::<usize>();
            let mut buf = Vec::with_capacity(capacity);
            for leaf_info in self.script_leaves() {
                // # Cast Safety:
                //
                // TaprootMerkleBranch can only have len atmost 128(TAPROOT_CONTROL_MAX_NODE_COUNT).
                // safe to cast from usize to u8
                buf.push(leaf_info.merkle_branch().len() as u8);
                buf.push(leaf_info.version().to_consensus());
                leaf_info
                    .script()
                    .consensus_encode(&mut buf)
                    .expect("Vecs dont err");
            }
            buf
        }
    }

    impl Deserialize for TapTree {
        fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            let mut builder = TaprootBuilder::new();
            let mut bytes_iter = bytes.iter();
            while let Some(depth) = bytes_iter.next() {
                let version = bytes_iter
                    .next()
                    .ok_or(Error::Taproot("Invalid Taproot Builder"))?;
                let (script, consumed) = deserialize_partial::<ScriptBuf>(bytes_iter.as_slice())?;
                if consumed > 0 {
                    bytes_iter.nth(consumed - 1);
                }
                let leaf_version =
                    LeafVersion::from_consensus(*version).map_err(|_| Error::InvalidLeafVersion)?;
                builder = builder
                    .add_leaf_with_ver(*depth, script, leaf_version)
                    .map_err(|_| Error::Taproot("Tree not in DFS order"))?;
            }
            TapTree::try_from(builder).map_err(Error::TapTree)
        }
    }

    // Helper function to compute key source len
    fn key_source_len(key_source: &KeySource) -> usize {
        4 + 4 * (key_source.1).as_ref().len()
    }
}
