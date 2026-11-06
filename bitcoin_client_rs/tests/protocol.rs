use std::str::FromStr;

use bitcoin::{
    bip32::DerivationPath,
    hashes::{sha256, Hash},
};
use ledger_bitcoin_client::{
    apdu::ClientCommandCode,
    command,
    interpreter::ClientCommandInterpreter,
    merkle::MerkleTree,
    wallet::{Version, WalletPolicy, WalletPubKey},
};

const KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
const MERKLE_LEAF_PREFIX: u8 = 0;
const SHA256_HASH_TYPE: u8 = 0;
const COMMAND_CODE_LEN: usize = 1;
const HASH_LEN: usize = 32;
const MORE_ELEMENTS_HEADER_LEN: usize = 2;

// Expected wire values are independent of the production APDU constants.
const EXPECTED_BITCOIN_CLA: u8 = 0xe1;
const EXPECTED_PROTOCOL_VERSION: u8 = 0x01;
const EXPECTED_REGISTER_WALLET_INS: u8 = 0x02;
const EXPECTED_GET_WALLET_ADDRESS_INS: u8 = 0x03;
const EXPECTED_SIGN_PSBT_INS: u8 = 0x04;
const EXPECTED_SIGN_MESSAGE_INS: u8 = 0x10;

fn wallet(version: Version) -> WalletPolicy {
    WalletPolicy::new(
        "".into(),
        version,
        "tr(@0/**)".into(),
        [WalletPubKey::from_str(KEY).unwrap()],
    )
}

fn hash(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

#[test]
fn version_command_wire_encoding() {
    assert_eq!(
        command::get_version().encode(),
        hex::decode("b001000000").unwrap()
    );
}

#[test]
fn fingerprint_command_wire_encoding() {
    assert_eq!(
        command::get_master_fingerprint().encode(),
        hex::decode("e105000100").unwrap()
    );
}

#[test]
fn extended_pubkey_command_wire_encoding() {
    let path = DerivationPath::from_str("m/44'/1/0").unwrap();
    assert_eq!(
        command::get_extended_pubkey(&path, true).encode(),
        hex::decode("e10000010e01038000002c0000000100000000").unwrap()
    );
}

#[test]
fn continuation_command_wire_encoding() {
    assert_eq!(
        command::continue_interrupted(vec![1, 2]).encode(),
        vec![0xf8, 1, 0, 1, 2, 1, 2]
    );
}

#[test]
fn registration_command_wire_encoding() {
    let wallet = wallet(Version::V2);
    let mut registration = vec![wallet.serialize().len() as u8];
    registration.extend(wallet.serialize());
    let cmd = command::register_wallet(&wallet);
    assert_eq!(
        (cmd.cla, cmd.ins, cmd.p1, cmd.p2),
        (
            EXPECTED_BITCOIN_CLA,
            EXPECTED_REGISTER_WALLET_INS,
            0,
            EXPECTED_PROTOCOL_VERSION
        )
    );
    assert_eq!(cmd.data, registration);
}

#[test]
fn address_command_wire_encoding() {
    let wallet = wallet(Version::V2);
    let mut address = vec![1];
    address.extend(wallet.id());
    address.extend([7; 32]);
    address.extend([1, 0, 0, 0, 9]);
    let cmd = command::get_wallet_address(&wallet, Some(&[7; 32]), true, 9, true);
    assert_eq!(cmd.ins, EXPECTED_GET_WALLET_ADDRESS_INS);
    assert_eq!(cmd.data, address);
}

#[test]
fn psbt_command_wire_encoding() {
    let wallet = wallet(Version::V2);
    let mut psbt = vec![8, 1];
    psbt.extend([2; 32]);
    psbt.push(3);
    psbt.extend([4; 32]);
    psbt.extend(wallet.id());
    psbt.extend([0; 32]);
    let cmd = command::sign_psbt(&[8], 1, &[2; 32], 3, &[4; 32], &wallet, None);
    assert_eq!(cmd.ins, EXPECTED_SIGN_PSBT_INS);
    assert_eq!(cmd.data, psbt);
}

#[test]
fn message_command_wire_encoding() {
    let path = DerivationPath::from_str("m/44'/1/0").unwrap();
    let cmd = command::sign_message(5, &[6; 32], &path);
    assert_eq!(cmd.ins, EXPECTED_SIGN_MESSAGE_INS);
    let mut message = hex::decode("038000002c000000010000000005").unwrap();
    message.extend([6; 32]);
    assert_eq!(cmd.data, message);
}

#[test]
fn wallet_versions_and_repeated_templates() {
    let key_leaf = hash(&[&[MERKLE_LEAF_PREFIX][..], KEY.as_bytes()].concat());
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
    assert_eq!(
        hex::encode(wallet(Version::V2).id()),
        "627535418bc03eeee2b62b3a0254dc0624881f8bc6fc20c4d3b2c1c4fc929893"
    );
    let mut repeated = wallet(Version::V2);
    repeated.descriptor_template = "tr(@0/**,pk(@0/<2;3>/*))".into();
    assert_eq!(repeated.keys.len(), 1);
    assert_eq!(
        repeated.get_descriptor(false).unwrap(),
        format!("tr({KEY}/0/*,pk({KEY}/2/*))")
    );
    assert_eq!(
        repeated.get_descriptor(true).unwrap(),
        format!("tr({KEY}/1/*,pk({KEY}/3/*))")
    );
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
    let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    request.extend(leaf);
    assert_eq!(interpreter.execute(request).unwrap(), b"\x06\x06\0hello");
    assert_eq!(
        interpreter
            .execute(vec![ClientCommandCode::Yield as u8, 1, 2])
            .unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(interpreter.yielded(), vec![vec![1, 2]]);
}

#[test]
fn missing_leaves_and_unknown_roots_are_distinct() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&[b"hello"]);
    let mut index = vec![ClientCommandCode::GetMerkleLeafIndex as u8];
    index.extend(root);
    index.extend([9; 32]);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [0, 0]);
    let leaf_hash_offset = COMMAND_CODE_LEN + HASH_LEN;
    index[leaf_hash_offset..].copy_from_slice(&root);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), [1, 0]);
    index[COMMAND_CODE_LEN..leaf_hash_offset].fill(8);
    assert!(matches!(
        interpreter.execute(index),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut proof = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    proof.extend([8; 32]);
    proof.extend([1, 0]);
    assert!(matches!(
        interpreter.execute(proof),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    preimage.extend([9; 32]);
    assert!(matches!(
        interpreter.execute(preimage),
        Err(InterpreterError::UnknownHash)
    ));
}

#[test]
fn long_preimage_continuations_reconstruct_and_reset_the_queue() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    const PREIMAGE_HEADER_LEN: usize = 4;
    let preimage = vec![0x55; 600];
    interpreter.add_known_preimage(preimage.clone());
    let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    request.extend(hash(&preimage));
    let first = interpreter.execute(request).unwrap();
    assert_eq!(&first[..PREIMAGE_HEADER_LEN], &[0xfd, 0x58, 2, 251]);
    let mut reconstructed = first[PREIMAGE_HEADER_LEN..].to_vec();
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMerkleLeafProof as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    for expected_count in [253, 96] {
        let next = interpreter
            .execute(vec![ClientCommandCode::GetMoreElements as u8])
            .unwrap();
        assert_eq!(&next[..MORE_ELEMENTS_HEADER_LEN], &[expected_count, 1]);
        reconstructed.extend(&next[MORE_ELEMENTS_HEADER_LEN..]);
    }
    assert_eq!(reconstructed, preimage);
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMoreElements as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    assert!(interpreter
        .execute(vec![ClientCommandCode::Yield as u8, 1, 2])
        .is_ok());
}

#[test]
fn eight_sibling_proof_continuations_reconstruct_and_reset_the_queue() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    const PROOF_HEADER_LEN: usize = HASH_LEN + 2;
    let mut interpreter = ClientCommandInterpreter::new();

    let elements: Vec<Vec<u8>> = (0u16..256).map(|i| i.to_le_bytes().to_vec()).collect();
    let leaves: Vec<_> = elements
        .iter()
        .map(|e| hash(&[&[MERKLE_LEAF_PREFIX][..], e].concat()))
        .collect();
    let tree = MerkleTree::new(leaves);
    let root = interpreter.add_known_list(&elements);
    let mut request = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    request.extend(root);
    request.extend([0xfd, 0, 1, 0]);
    let first = interpreter.execute(request.clone()).unwrap();
    assert_eq!(&first[..HASH_LEN], tree.get_leaf(0).unwrap());
    assert_eq!(&first[HASH_LEN..PROOF_HEADER_LEN], &[8, 6]);
    assert!(matches!(
        interpreter.execute(request.clone()),
        Err(InterpreterError::UnexpectedQueue)
    ));
    let rest = interpreter
        .execute(vec![ClientCommandCode::GetMoreElements as u8])
        .unwrap();
    assert_eq!(&rest[..MORE_ELEMENTS_HEADER_LEN], &[2, 32]);
    let mut proof = first[PROOF_HEADER_LEN..].to_vec();
    proof.extend(&rest[MORE_ELEMENTS_HEADER_LEN..]);
    assert_eq!(proof, tree.get_leaf_proof(0).unwrap().concat());
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMoreElements as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    request.pop();
    request.push(1);
    assert!(interpreter.execute(request).is_ok());
}

#[test]
fn interpreter_rejects_malformed_requests() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::default();
    assert!(matches!(
        interpreter.execute(vec![]),
        Err(InterpreterError::EmptyInput)
    ));
    assert!(matches!(
        interpreter.execute(vec![0xff]),
        Err(InterpreterError::UnknownCommand(0xff))
    ));
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetPreimage as u8]),
        Err(InterpreterError::UnsupportedRequest(code)) if code == ClientCommandCode::GetPreimage as u8
    ));
}
