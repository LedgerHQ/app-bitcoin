use std::str::FromStr;

use bitcoin::{bip32::DerivationPath, hashes::{sha256, Hash}};
use ledger_bitcoin_client::{command, interpreter::ClientCommandInterpreter, merkle::MerkleTree, wallet::{Version, WalletPolicy, WalletPubKey}};

const KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";

fn wallet(version: Version) -> WalletPolicy {
    WalletPolicy::new("".into(), version, "tr(@0/**)".into(), [WalletPubKey::from_str(KEY).unwrap()])
}

fn hash(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

#[test]
fn public_command_builders() {
    assert_eq!(command::get_version().encode(), hex::decode("b001000000").unwrap());
    assert_eq!(command::get_master_fingerprint().encode(), hex::decode("e105000100").unwrap());
    let path = DerivationPath::from_str("m/44'/1/0").unwrap();
    assert_eq!(command::get_extended_pubkey(&path, true).encode(), hex::decode("e10000010e01038000002c0000000100000000").unwrap());
    assert_eq!(command::continue_interrupted(vec![1, 2]).encode(), vec![0xf8, 1, 0, 1, 2, 1, 2]);
    let wallet = wallet(Version::V2);
    let mut registration = vec![wallet.serialize().len() as u8];
    registration.extend(wallet.serialize());
    let cmd = command::register_wallet(&wallet);
    assert_eq!((cmd.cla, cmd.ins, cmd.p1, cmd.p2), (0xe1, 2, 0, 1));
    assert_eq!(cmd.data, registration);
    let mut address = vec![1];
    address.extend(wallet.id());
    address.extend([7; 32]);
    address.extend([1, 0, 0, 0, 9]);
    let cmd = command::get_wallet_address(&wallet, Some(&[7; 32]), true, 9, true);
    assert_eq!(cmd.ins, 3);
    assert_eq!(cmd.data, address);
    let mut psbt = vec![8, 1];
    psbt.extend([2; 32]);
    psbt.push(3);
    psbt.extend([4; 32]);
    psbt.extend(wallet.id());
    psbt.extend([0; 32]);
    let cmd = command::sign_psbt(&[8], 1, &[2; 32], 3, &[4; 32], &wallet, None);
    assert_eq!(cmd.ins, 4);
    assert_eq!(cmd.data, psbt);
    let cmd = command::sign_message(5, &[6; 32], &path);
    assert_eq!(cmd.ins, 0x10);
    let mut message = hex::decode("038000002c000000010000000005").unwrap();
    message.extend([6; 32]);
    assert_eq!(cmd.data, message);
}

#[test]
fn wallet_versions_and_repeated_templates() {
    let key_leaf = hash(&[&[0][..], KEY.as_bytes()].concat());
    for version in [Version::V1, Version::V2] {
        let wallet = wallet(version);
        let mut expected = vec![version as u8, 0, 9];
        if version == Version::V1 {
            expected.extend(b"tr(@0/**)");
        } else {
            expected.extend(hash(b"tr(@0/**)"));
        }
        expected.push(1);
        expected.extend(key_leaf);
        assert_eq!(wallet.serialize(), expected);
        assert_eq!(wallet.id(), hash(&expected));
    }
    assert_eq!(hex::encode(wallet(Version::V2).id()), "627535418bc03eeee2b62b3a0254dc0624881f8bc6fc20c4d3b2c1c4fc929893");
    let mut repeated = wallet(Version::V2);
    repeated.descriptor_template = "tr(@0/**,pk(@0/<2;3>/*))".into();
    assert_eq!(repeated.keys.len(), 1);
    assert_eq!(repeated.get_descriptor(false).unwrap(), format!("tr({KEY}/0/*,pk({KEY}/2/*))"));
    assert_eq!(repeated.get_descriptor(true).unwrap(), format!("tr({KEY}/1/*,pk({KEY}/3/*))"));
}

#[test]
fn public_merkle_and_interpreter() {
    let leaf = hash(b"\0hello");
    let tree = MerkleTree::new(vec![leaf]);
    assert_eq!(tree.size(), 1);
    assert_eq!(tree.root_hash(), &leaf);
    assert_eq!(tree.get_leaf(0), Some(&leaf));
    assert_eq!(tree.get_leaf_proof(0), Some(vec![]));
    assert_eq!(tree.get_leaf_proof(1), None);
    let mut interpreter = ClientCommandInterpreter::new();
    assert_eq!(interpreter.add_known_list(&[b"hello"]), leaf);
    let mut request = vec![0x40, 0];
    request.extend(leaf);
    assert_eq!(interpreter.execute(request).unwrap(), b"\x06\x06\0hello");
    assert_eq!(interpreter.execute(vec![0x10, 1, 2]).unwrap(), Vec::<u8>::new());
    assert_eq!(interpreter.yielded(), vec![vec![1, 2]]);
}

#[test]
fn missing_leaves_and_unknown_roots_are_distinct() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&[b"hello"]);
    let mut index = vec![0x42];
    index.extend(root);
    index.extend([9; 32]);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [0, 0]);
    index[33..].copy_from_slice(&root);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [1, 0]);
    index[1..33].fill(8);
    assert!(matches!(interpreter.execute(index), Err(InterpreterError::UnknownMerkleRoot)));
    let mut proof = vec![0x41];
    proof.extend([8; 32]);
    proof.extend([1, 0]);
    assert!(matches!(interpreter.execute(proof), Err(InterpreterError::UnknownMerkleRoot)));
    let mut preimage = vec![0x40, 0];
    preimage.extend([9; 32]);
    assert!(matches!(interpreter.execute(preimage), Err(InterpreterError::UnknownHash)));
}

#[test]
fn preimage_and_proof_fragmentation_and_queue_transitions() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let preimage = vec![0x55; 600];
    interpreter.add_known_preimage(preimage.clone());
    let mut request = vec![0x40, 0];
    request.extend(hash(&preimage));
    let first = interpreter.execute(request).unwrap();
    assert_eq!(&first[..4], &[0xfd, 0x58, 2, 251]);
    let mut reconstructed = first[4..].to_vec();
    assert!(matches!(interpreter.execute(vec![0x41]), Err(InterpreterError::UnexpectedQueue)));
    for expected_count in [253, 96] {
        let next = interpreter.execute(vec![0xa0]).unwrap();
        assert_eq!(&next[..2], &[expected_count, 1]);
        reconstructed.extend(&next[2..]);
    }
    assert_eq!(reconstructed, preimage);
    assert!(matches!(interpreter.execute(vec![0xa0]), Err(InterpreterError::UnexpectedQueue)));

    let elements: Vec<Vec<u8>> = (0u16..256).map(|i| i.to_le_bytes().to_vec()).collect();
    let leaves: Vec<_> = elements.iter().map(|e| hash(&[&[0][..], e].concat())).collect();
    let tree = MerkleTree::new(leaves);
    let root = interpreter.add_known_list(&elements);
    let mut request = vec![0x41];
    request.extend(root);
    request.extend([0xfd, 0, 1, 0]);
    let first = interpreter.execute(request.clone()).unwrap();
    assert_eq!(&first[..32], tree.get_leaf(0).unwrap());
    assert_eq!(&first[32..34], &[8, 6]);
    assert!(matches!(interpreter.execute(request.clone()), Err(InterpreterError::UnexpectedQueue)));
    let rest = interpreter.execute(vec![0xa0]).unwrap();
    assert_eq!(&rest[..2], &[2, 32]);
    let mut proof = first[34..].to_vec();
    proof.extend(&rest[2..]);
    assert_eq!(proof, tree.get_leaf_proof(0).unwrap().concat());
    assert!(matches!(interpreter.execute(vec![0xa0]), Err(InterpreterError::UnexpectedQueue)));
    request.pop();
    request.push(1);
    assert!(interpreter.execute(request).is_ok());
    assert!(matches!(interpreter.execute(vec![]), Err(InterpreterError::EmptyInput)));
    assert!(matches!(interpreter.execute(vec![0xff]), Err(InterpreterError::UnknownCommand(0xff))));
    assert!(matches!(interpreter.execute(vec![0x40]), Err(InterpreterError::UnsupportedRequest(0x40))));
}

fn compact_size(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => [&[0xfd][..], &value.to_le_bytes()[..2]].concat(),
        0x10000..=0xffff_ffff => [&[0xfe][..], &value.to_le_bytes()[..4]].concat(),
        _ => [&[0xff][..], &value.to_le_bytes()].concat(),
    }
}

const PUBKEY: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

fn musig_yield(tag: u64, index: u64, tapleaf: bool) -> Vec<u8> {
    let mut payload = compact_size(tag);
    payload.extend(compact_size(index));
    payload.extend(vec![0xaa; if tag == 0xffff_ffff { 66 } else { 32 }]);
    payload.extend(hex::decode(PUBKEY).unwrap());
    payload.extend(hex::decode(PUBKEY).unwrap());
    if tapleaf {
        payload.extend([1; 32]);
    }
    payload
}

#[test]
fn yielded_indices_and_malformed_payloads() {
    use ledger_bitcoin_client::{protocol::{parse_sign_psbt_yielded, SignPsbtYieldedObject}, PartialSignatureError};
    for tag in [0xffff_ffff, 0xffff_fffe, 0x8000_0000] {
        let payload = if tag == 0x8000_0000 {
            [compact_size(tag), compact_size(0x1_0000_0000)].concat()
        } else {
            musig_yield(tag, 0x1_0000_0000, false)
        };
        let parsed = parse_sign_psbt_yielded(&payload);
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(parsed, Err(PartialSignatureError::InvalidLength)));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(parsed.ok().expect("representable index").0, 0x1_0000_0000);
    }
    let mut regular = compact_size(0x7fff_ffff);
    regular.push(32);
    regular.extend(&hex::decode(PUBKEY).unwrap()[1..]);
    regular.extend([0xaa; 64]);
    assert_eq!(parse_sign_psbt_yielded(&regular).ok().unwrap().0, 0x7fff_ffff);
    for malformed in [vec![], vec![0xfd], vec![0xfd, 1, 0], vec![0xfe, 0, 1, 0, 0], vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0]] {
        assert!(matches!(parse_sign_psbt_yielded(&malformed), Err(PartialSignatureError::InvalidLength)));
    }
    for tag in [0xffff_ffff, 0xffff_fffe] {
        for tapleaf in [false, true] {
            let valid = musig_yield(tag, 2, tapleaf);
            assert_eq!(parse_sign_psbt_yielded(&valid).ok().unwrap().0, 2);
            assert!(parse_sign_psbt_yielded(&valid[..valid.len() - 1]).is_err());
            let mut bad_key = valid;
            let offset = 6 + if tag == 0xffff_ffff { 66 } else { 32 };
            bad_key[offset] = 0xff;
            assert!(parse_sign_psbt_yielded(&bad_key).is_err());
        }
    }
    let mut unknown = compact_size(0x8000_0000);
    unknown.extend([3, 7, 8]);
    assert!(matches!(parse_sign_psbt_yielded(&unknown), Ok((3, SignPsbtYieldedObject::Unknown(bytes))) if bytes == [7, 8]));
    for malformed in [vec![0], vec![0, 64, 1], vec![0, 32], vec![0, 33, 0, 0]] {
        assert!(parse_sign_psbt_yielded(&malformed).is_err());
    }
    let mut bad_schnorr = regular;
    bad_schnorr.pop();
    assert!(parse_sign_psbt_yielded(&bad_schnorr).is_err());
}

#[test]
fn response_parsers_preserve_wire_contracts() {
    use ledger_bitcoin_client::protocol::*;
    let mut version = hex::decode("010c426974636f696e205465737405322e312e300100").unwrap();
    assert_eq!(parse_version(&version).unwrap(), ("Bitcoin Test".into(), "2.1.0".into(), vec![0]));
    version.extend([9, 8]);
    assert_eq!(parse_version(&version).unwrap().2, [0]);
    assert!(matches!(parse_version(&[]), Err(ResponseError::Truncated { .. })));
    assert!(matches!(parse_version(&[2]), Err(ResponseError::InvalidFormat { .. })));
    for (bytes, field) in [(&[1][..], "name"), (&[1, 0][..], "version"), (&[1, 0, 0][..], "flags")] {
        assert!(matches!(parse_version(bytes), Err(ResponseError::Decode { field: actual, .. }) if actual == field));
    }
    assert!(parse_version(&[1, 0xfd, 0, 0]).is_err());
    assert_eq!(parse_master_fingerprint(&[1, 2, 3, 4, 5]).unwrap().to_string(), "01020304");
    for len in 0..4 {
        assert!(matches!(parse_master_fingerprint(&[0; 4][..len]), Err(ResponseError::InvalidLength { expected: 4, actual, .. }) if actual == len));
    }
    let registration: Vec<u8> = (0..65).collect();
    let (id, hmac) = parse_wallet_registration(&registration).unwrap();
    assert_eq!(&id, &registration[..32]);
    assert_eq!(&hmac, &registration[32..64]);
    assert!(parse_wallet_registration(&registration[..63]).is_err());
    let xpub = KEY.split(']').nth(1).unwrap();
    assert_eq!(parse_extended_pubkey(xpub.as_bytes()).unwrap().to_string(), xpub);
    assert!(parse_extended_pubkey(format!("{xpub}\n").as_bytes()).is_err());
    assert!(parse_extended_pubkey(&[0xff]).is_err());
    let address = "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7";
    assert_eq!(parse_wallet_address(address.as_bytes()).unwrap().assume_checked().to_string(), address);
    assert!(parse_wallet_address(format!(" {address}").as_bytes()).is_err());
    assert!(parse_wallet_address(&[0xff]).is_err());
    let mut signature = vec![255];
    signature.extend([1; 64]);
    let (header, sig) = parse_message_signature(&signature).unwrap();
    assert_eq!(header, 255);
    assert_eq!(sig.serialize_compact(), [1; 64]);
    for len in [0, 1, 64, 66] {
        assert!(matches!(parse_message_signature(&vec![0; len]), Err(ResponseError::InvalidLength { expected: 65, actual, .. }) if actual == len));
    }
    assert!(matches!(parse_message_signature(&[255; 65]), Err(ResponseError::InvalidFormat { .. })));
}

#[test]
fn wallet_and_message_preparation_supply_delegated_preimages() {
    use ledger_bitcoin_client::protocol::prepare_sign_message;
    for version in [Version::V1, Version::V2] {
        let wallet = wallet(version);
        let mut interpreter = ClientCommandInterpreter::for_wallet(&wallet);
        for preimage in [wallet.serialize(), wallet.descriptor_template.as_bytes().to_vec(), [&[0][..], KEY.as_bytes()].concat()] {
            let mut request = vec![0x40, 0];
            request.extend(hash(&preimage));
            let mut expected = vec![preimage.len() as u8, preimage.len() as u8];
            expected.extend(preimage);
            assert_eq!(interpreter.execute(request).unwrap(), expected);
        }
    }
    let path = DerivationPath::from_str("m/44'/1'/0'/0").unwrap();
    for length in [1, 64, 65, 128, 129] {
        let message = vec![0x55; length];
        let (command, mut interpreter) = prepare_sign_message(&message, &path);
        let chunks: Vec<_> = message.chunks(64).collect();
        let leaves = chunks.iter().map(|chunk| hash(&[&[0][..], chunk].concat())).collect();
        let root = *MerkleTree::new(leaves).root_hash();
        assert_eq!(command.encode(), command::sign_message(length, &root, &path).encode());
        for chunk in chunks {
            let preimage = [&[0][..], chunk].concat();
            let mut request = vec![0x40, 0];
            request.extend(hash(&preimage));
            let response = interpreter.execute(request).unwrap();
            assert_eq!(&response[2..], preimage);
        }
    }
}

fn unsigned_psbt() -> bitcoin::psbt::Psbt {
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    bitcoin::psbt::Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
    }).unwrap()
}

#[test]
fn psbt_maps_forward_unknown_and_proprietary_keys_and_reject_conflicts() {
    use bitcoin::psbt::raw::{Key, ProprietaryKey};
    use ledger_bitcoin_client::{protocol::prepare_sign_psbt, psbt::{get_v2_maps, PsbtV2Error}};
    let mut psbt = unsigned_psbt();
    let unknown = Key { type_value: 0x70, key: vec![9] };
    let proprietary = ProprietaryKey { prefix: b"hw".to_vec(), subtype: 1, key: vec![9] };
    psbt.unknown.insert(unknown.clone(), vec![1]);
    psbt.inputs[0].unknown.insert(unknown.clone(), vec![2]);
    psbt.outputs[0].unknown.insert(unknown, vec![3]);
    psbt.proprietary.insert(proprietary.clone(), vec![4]);
    psbt.inputs[0].proprietary.insert(proprietary.clone(), vec![5]);
    psbt.outputs[0].proprietary.insert(proprietary, vec![6]);
    let maps = get_v2_maps(&psbt).unwrap();
    for (i, map) in [&maps.global, &maps.inputs[0], &maps.outputs[0]].iter().enumerate() {
        assert!(map.contains(&(vec![0x70, 9], vec![i as u8 + 1])));
        assert!(map.contains(&(vec![0xfc, 2, b'h', b'w', 1, 9], vec![i as u8 + 4])));
    }
    let (_, mut interpreter) = prepare_sign_psbt(&psbt, &wallet(Version::V2), None).unwrap();
    for value in 1..=6 {
        let preimage = [0, value];
        let mut request = vec![0x40, 0];
        request.extend(hash(&preimage));
        assert_eq!(interpreter.execute(request).unwrap(), [2, 2, 0, value]);
    }
    for (map_index, key_types) in [(0, &[2, 3, 4, 5, 0xfb][..]), (1, &[0x0e, 0x0f, 0x10][..]), (2, &[3, 4][..])] {
        for &key_type in key_types {
            let mut conflict = unsigned_psbt();
            let map = match map_index {
                0 => &mut conflict.unknown,
                1 => &mut conflict.inputs[0].unknown,
                _ => &mut conflict.outputs[0].unknown,
            };
            map.insert(Key { type_value: key_type, key: vec![] }, vec![42]);
            assert_eq!(get_v2_maps(&conflict).err(), Some(PsbtV2Error::UnexpectedV2Field(key_type)));
            assert_eq!(prepare_sign_psbt(&conflict, &wallet(Version::V2), None).err(), Some(PsbtV2Error::UnexpectedV2Field(key_type)));
        }
    }
    psbt.inputs.clear();
    assert_eq!(prepare_sign_psbt(&psbt, &wallet(Version::V2), None).err(), Some(PsbtV2Error::TxMapCountMismatch));
}

#[test]
fn public_psbt_preparation_replays_recorded_delegated_exchanges() {
    use ledger_bitcoin_client::protocol::{prepare_sign_psbt, parse_sign_psbt_yielded};
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!("data/sign_psbt.json")).unwrap();
    for case in cases {
        let psbt = bitcoin::psbt::Psbt::deserialize(&base64::decode(case["psbt"].as_str().unwrap()).unwrap()).unwrap();
        let keys: Vec<_> = case["keys"].as_array().unwrap().iter().map(|key| WalletPubKey::from_str(key.as_str().unwrap()).unwrap()).collect();
        let wallet = WalletPolicy::new(case["name"].as_str().unwrap().into(), Version::V2, case["policy"].as_str().unwrap().into(), keys);
        let hmac = case["hmac"].as_str().map(|value| {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(&hex::decode(value).unwrap());
            bytes
        });
        let (mut command, mut interpreter) = prepare_sign_psbt(&psbt, &wallet, hmac.as_ref()).unwrap();
        for pair in case["exchanges"].as_array().unwrap().chunks_exact(2) {
            let expected = hex::decode(pair[0].as_str().unwrap().trim_start_matches("=> ")).unwrap();
            assert_eq!(command.encode(), expected);
            let response = hex::decode(pair[1].as_str().unwrap().trim_start_matches("<= ")).unwrap();
            if response.ends_with(&[0xe0, 0]) {
                command = command::continue_interrupted(interpreter.execute(response[..response.len() - 2].to_vec()).unwrap());
            } else {
                assert!(response.ends_with(&[0x90, 0]));
            }
        }
        let results = interpreter.yielded();
        let expected_count: usize = ["sigs", "musig_pub_nonces", "musig_partial_signatures"].iter().map(|key| case[*key].as_array().map_or(0, Vec::len)).sum();
        assert_eq!(results.len(), expected_count);
        for result in results {
            assert!(parse_sign_psbt_yielded(&result).is_ok());
        }
    }
}

#[test]
fn signature_application_validates_before_mutation_and_overwrites() {
    use ledger_bitcoin_client::{psbt::{apply_partial_signature, InputIndexError}, PartialSignature};
    use bitcoin::{ecdsa, secp256k1, taproot::{Signature, TapLeafHash}, PublicKey};
    let key = PublicKey::from_str(PUBKEY).unwrap();
    let xonly = key.inner.x_only_public_key().0;
    let leaf = TapLeafHash::from_byte_array([3; 32]);
    let mut psbt = unsigned_psbt();
    for byte in [1, 2] {
        let ecdsa = ecdsa::Signature::sighash_all(secp256k1::ecdsa::Signature::from_compact(&[byte; 64]).unwrap());
        let taproot = Signature::from_slice(&[byte; 64]).unwrap();
        for signature in [
            PartialSignature::Sig(key, ecdsa),
            PartialSignature::TapScriptSig(xonly, None, taproot),
            PartialSignature::TapScriptSig(xonly, Some(leaf), taproot),
        ] {
            let before = psbt.clone();
            for input_index in [1, usize::MAX] {
                assert_eq!(apply_partial_signature(&mut psbt, input_index, signature.clone()), Err(InputIndexError { input_index }));
                assert_eq!(psbt, before);
            }
            apply_partial_signature(&mut psbt, 0, signature).unwrap();
        }
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert_eq!(psbt.inputs[0].partial_sigs[&key], ecdsa);
        assert_eq!(psbt.inputs[0].tap_key_sig, Some(taproot));
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(psbt.inputs[0].tap_script_sigs[&(xonly, leaf)], taproot);
        let mut payload = vec![0, 33];
        payload.extend(key.to_bytes());
        payload.extend(ecdsa.to_vec());
        assert!(ledger_bitcoin_client::protocol::parse_sign_psbt_yielded(&payload).is_ok());
        payload.pop();
        assert!(ledger_bitcoin_client::protocol::parse_sign_psbt_yielded(&payload).is_err());
    }
}
