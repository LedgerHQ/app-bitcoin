use std::str::FromStr;

use bitcoin::{
    bip32::DerivationPath,
    hashes::{sha256, Hash},
};
use ledger_bitcoin_client::{
    apdu::ClientCommandCode,
    command,
    interpreter::ClientCommandInterpreter,
    wallet::{Version, WalletPolicy, WalletPubKey},
};

const KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
const MERKLE_LEAF_PREFIX: u8 = 0;
const SHA256_HASH_TYPE: u8 = 0;
const COMMAND_CODE_LEN: usize = 1;
const HASH_LEN: usize = 32;
const MORE_ELEMENTS_HEADER_LEN: usize = 2;
// A client command response, including its headers, is at most this long.
const MAX_RESPONSE_LEN: usize = 255;

// Expected wire values are independent of the production APDU constants.
const EXPECTED_BITCOIN_CLA: u8 = 0xe1;
const EXPECTED_PROTOCOL_VERSION: u8 = 0x01;
const EXPECTED_FRAMEWORK_CLA: u8 = 0xf8;
const EXPECTED_CONTINUE_INS: u8 = 0x01;
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

/// The root of the Merkle tree of `leaves`, as defined in doc/merkle.md. This reference
/// implementation is independent of the crate's.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0; 32],
        1 => leaves[0],
        n => {
            let split = largest_power_of_two_below(n);
            let left = merkle_root(&leaves[..split]);
            let right = merkle_root(&leaves[split..]);
            hash(&[&[1][..], &left, &right].concat())
        }
    }
}

/// The proof of the leaf with index `index`: its sibling hashes, from the leaf to the root.
fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let split = largest_power_of_two_below(leaves.len());
    let (mut proof, sibling) = if index < split {
        (
            merkle_proof(&leaves[..split], index),
            merkle_root(&leaves[split..]),
        )
    } else {
        (
            merkle_proof(&leaves[split..], index - split),
            merkle_root(&leaves[..split]),
        )
    };
    proof.push(sibling);
    proof
}

fn largest_power_of_two_below(n: usize) -> usize {
    let mut power = 1;
    while 2 * power < n {
        power *= 2;
    }
    power
}

fn varint(n: u64) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(&bitcoin::VarInt(n))
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
    let response = vec![1, 2];
    let mut expected = vec![
        EXPECTED_FRAMEWORK_CLA,
        EXPECTED_CONTINUE_INS,
        0,
        EXPECTED_PROTOCOL_VERSION,
        response.len() as u8,
    ];
    expected.extend(&response);
    assert_eq!(command::continue_interrupted(response).encode(), expected);
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
    let (hmac, change, address_index, display) = ([7; 32], true, 9_u32, true);
    let mut address = vec![u8::from(display)];
    address.extend(wallet.id());
    address.extend(hmac);
    address.push(u8::from(change));
    address.extend(address_index.to_be_bytes());
    let cmd = command::get_wallet_address(&wallet, Some(&hmac), change, address_index, display);
    assert_eq!(cmd.ins, EXPECTED_GET_WALLET_ADDRESS_INS);
    assert_eq!(cmd.data, address);
}

#[test]
fn psbt_command_wire_encoding() {
    let wallet = wallet(Version::V2);
    let global_commitment = [8];
    let (n_inputs, inputs_root) = (1, [2; 32]);
    let (n_outputs, outputs_root) = (3, [4; 32]);
    let mut psbt = global_commitment.to_vec();
    psbt.extend(varint(n_inputs as u64));
    psbt.extend(inputs_root);
    psbt.extend(varint(n_outputs as u64));
    psbt.extend(outputs_root);
    psbt.extend(wallet.id());
    psbt.extend([0; 32]); // No HMAC.
    let cmd = command::sign_psbt(
        &global_commitment,
        n_inputs,
        &inputs_root,
        n_outputs,
        &outputs_root,
        &wallet,
        None,
    );
    assert_eq!(cmd.ins, EXPECTED_SIGN_PSBT_INS);
    assert_eq!(cmd.data, psbt);
}

#[test]
fn message_command_wire_encoding() {
    let path = DerivationPath::from_str("m/44'/1/0").unwrap();
    let (message_len, message_root) = (5, [6; 32]);
    let cmd = command::sign_message(message_len, &message_root, &path);
    assert_eq!(cmd.ins, EXPECTED_SIGN_MESSAGE_INS);
    let mut message = vec![3]; // Number of derivation steps.
    for step in [0x8000_002c_u32, 1, 0] {
        message.extend(step.to_be_bytes());
    }
    message.extend(varint(message_len as u64));
    message.extend(message_root);
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
fn interpreter_answers_preimages_and_yields() {
    let leaf = hash(b"\0hello");
    let mut interpreter = ClientCommandInterpreter::new();
    // The root of a one-element list is the hash of its leaf.
    assert_eq!(
        interpreter.add_known_list(&[b"hello"]),
        merkle_root(&[leaf])
    );
    assert_eq!(merkle_root(&[leaf]), leaf);
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
    // The response is a "found" byte, followed by the leaf index.
    const NOT_FOUND: [u8; 2] = [0, 0];
    const FOUND_AT_INDEX_0: [u8; 2] = [1, 0];
    let unknown_hash = [9; 32];
    let unknown_root = [8; 32];
    let root = interpreter.add_known_list(&[b"hello"]);
    let mut index = vec![ClientCommandCode::GetMerkleLeafIndex as u8];
    index.extend(root);
    index.extend(unknown_hash);
    assert_eq!(interpreter.execute(index.clone()).unwrap(), NOT_FOUND);
    // In a tree with a single leaf, the root is the leaf hash.
    let leaf_hash_offset = COMMAND_CODE_LEN + HASH_LEN;
    index[leaf_hash_offset..].copy_from_slice(&root);
    assert_eq!(
        interpreter.execute(index.clone()).unwrap(),
        FOUND_AT_INDEX_0
    );
    index[COMMAND_CODE_LEN..leaf_hash_offset].copy_from_slice(&unknown_root);
    assert!(matches!(
        interpreter.execute(index),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut proof = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    proof.extend(unknown_root);
    proof.extend(varint(1)); // Tree size.
    proof.extend(varint(0)); // Leaf index.
    assert!(matches!(
        interpreter.execute(proof),
        Err(InterpreterError::UnknownMerkleRoot)
    ));
    let mut preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    preimage.extend(unknown_hash);
    assert!(matches!(
        interpreter.execute(preimage),
        Err(InterpreterError::UnknownHash)
    ));
}

#[test]
fn long_preimage_continuations_reconstruct_and_reset_the_queue() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let preimage = vec![0x55; 600];
    // The response is the preimage length, the length of the chunk, and the chunk.
    let mut header = varint(preimage.len() as u64);
    let first_chunk_len = MAX_RESPONSE_LEN - header.len() - 1;
    header.push(first_chunk_len as u8);
    interpreter.add_known_preimage(preimage.clone());
    let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    request.extend(hash(&preimage));
    let first = interpreter.execute(request).unwrap();
    assert_eq!(&first[..header.len()], &header[..]);
    assert_eq!(first.len(), MAX_RESPONSE_LEN);
    let mut reconstructed = first[header.len()..].to_vec();
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMerkleLeafProof as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    // The rest of the preimage is queued as one-byte elements.
    let max_elements = MAX_RESPONSE_LEN - MORE_ELEMENTS_HEADER_LEN;
    let remaining = preimage.len() - first_chunk_len - max_elements;
    for expected_count in [max_elements, remaining] {
        let next = interpreter
            .execute(vec![ClientCommandCode::GetMoreElements as u8])
            .unwrap();
        assert_eq!(
            &next[..MORE_ELEMENTS_HEADER_LEN],
            &[expected_count as u8, 1]
        );
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
    // The response is the leaf hash, the proof length, the number of proof elements in the
    // response, and those elements.
    const PROOF_HEADER_LEN: usize = HASH_LEN + 2;
    const N_LEAVES: u16 = 256;
    const PROOF_LEN: usize = 8; // log2(N_LEAVES)
    const FIRST_PROOF_ELEMENTS: usize = (MAX_RESPONSE_LEN - PROOF_HEADER_LEN) / HASH_LEN;
    let mut interpreter = ClientCommandInterpreter::new();

    let elements: Vec<Vec<u8>> = (0..N_LEAVES).map(|i| i.to_le_bytes().to_vec()).collect();
    let leaves: Vec<_> = elements
        .iter()
        .map(|e| hash(&[&[MERKLE_LEAF_PREFIX][..], e].concat()))
        .collect();
    let root = interpreter.add_known_list(&elements);
    assert_eq!(root, merkle_root(&leaves));
    let mut request = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    request.extend(root);
    request.extend(varint(N_LEAVES as u64));
    request.extend(varint(0)); // Leaf index.
    let first = interpreter.execute(request.clone()).unwrap();
    assert_eq!(&first[..HASH_LEN], &leaves[0]);
    assert_eq!(
        &first[HASH_LEN..PROOF_HEADER_LEN],
        &[PROOF_LEN as u8, FIRST_PROOF_ELEMENTS as u8]
    );
    assert!(matches!(
        interpreter.execute(request.clone()),
        Err(InterpreterError::UnexpectedQueue)
    ));
    let rest = interpreter
        .execute(vec![ClientCommandCode::GetMoreElements as u8])
        .unwrap();
    assert_eq!(
        &rest[..MORE_ELEMENTS_HEADER_LEN],
        &[(PROOF_LEN - FIRST_PROOF_ELEMENTS) as u8, HASH_LEN as u8]
    );
    let mut proof = first[PROOF_HEADER_LEN..].to_vec();
    proof.extend(&rest[MORE_ELEMENTS_HEADER_LEN..]);
    assert_eq!(proof, merkle_proof(&leaves, 0).concat());
    assert!(matches!(
        interpreter.execute(vec![ClientCommandCode::GetMoreElements as u8]),
        Err(InterpreterError::UnexpectedQueue)
    ));
    // With an empty queue, the next proof can be requested.
    request.pop();
    request.extend(varint(1));
    assert!(interpreter.execute(request).is_ok());
}

#[test]
fn empty_lists_have_the_zero_root_and_no_leaves() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&[] as &[&[u8]]);
    assert_eq!(root, [0; 32]);
    let mut request = vec![ClientCommandCode::GetMerkleLeafProof as u8];
    request.extend(root);
    request.extend(varint(0)); // Tree size.
    request.extend(varint(0)); // Leaf index.
    assert!(matches!(
        interpreter.execute(request),
        Err(InterpreterError::InvalidIndexOrSize)
    ));
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

#[test]
fn preimages_cannot_be_requested_while_a_previous_answer_is_queued() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let long = vec![0x55; 300];
    interpreter.add_known_preimage(long.clone());
    interpreter.add_known_preimage(b"short".to_vec());
    let get_preimage = |preimage: &[u8]| {
        let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
        request.extend(hash(preimage));
        request
    };
    // The end of the long preimage is queued.
    interpreter.execute(get_preimage(&long)).unwrap();
    assert_eq!(
        interpreter.execute(get_preimage(b"short")),
        Err(InterpreterError::UnexpectedQueue)
    );
    interpreter
        .execute(vec![ClientCommandCode::GetMoreElements as u8])
        .unwrap();
    assert!(interpreter.execute(get_preimage(b"short")).is_ok());
}

#[test]
fn interpreter_rejects_trailing_bytes() {
    use ledger_bitcoin_client::interpreter::InterpreterError;
    let mut interpreter = ClientCommandInterpreter::new();
    let root = interpreter.add_known_list(&[b"hello"]);
    // In a tree with a single leaf, the root is the leaf hash.
    let mut get_leaf_index = vec![ClientCommandCode::GetMerkleLeafIndex as u8];
    get_leaf_index.extend(root);
    get_leaf_index.extend(root);
    assert!(interpreter.execute(get_leaf_index.clone()).is_ok());
    get_leaf_index.push(0);
    assert!(matches!(
        interpreter.execute(get_leaf_index),
        Err(InterpreterError::UnsupportedRequest(code))
            if code == ClientCommandCode::GetMerkleLeafIndex as u8
    ));

    // Fill the queue with the end of a long preimage.
    let preimage = vec![0x55; 300];
    interpreter.add_known_preimage(preimage.clone());
    let mut get_preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    get_preimage.extend(hash(&preimage));
    interpreter.execute(get_preimage).unwrap();
    let get_more_elements = ClientCommandCode::GetMoreElements as u8;
    assert!(matches!(
        interpreter.execute(vec![get_more_elements, 0]),
        Err(InterpreterError::UnsupportedRequest(code)) if code == get_more_elements
    ));
    assert!(interpreter.execute(vec![get_more_elements]).is_ok());
}

#[test]
fn version_response_encoding_and_decode_context() {
    use ledger_bitcoin_client::protocol::*;
    const FORMAT: u8 = 1;
    let mut version = vec![FORMAT];
    for field in [&b"Bitcoin Test"[..], b"2.1.0", &[0]] {
        version.extend(varint(field.len() as u64));
        version.extend(field);
    }
    assert_eq!(
        parse_version(&version).unwrap(),
        ("Bitcoin Test".into(), "2.1.0".into(), vec![0])
    );
    version.extend([9, 8]);
    assert!(matches!(
        parse_version(&version),
        Err(ResponseError::TrailingBytes { count: 2, .. })
    ));
    assert!(matches!(
        parse_version(&[]),
        Err(ResponseError::Truncated { .. })
    ));
    assert!(matches!(
        parse_version(&[FORMAT + 1]),
        Err(ResponseError::InvalidFormat { .. })
    ));
    // The dashboard's response has no flags.
    assert_eq!(
        parse_version(&[FORMAT, 5, b'B', b'O', b'L', b'O', b'S', 1, b'1']).unwrap(),
        ("BOLOS".into(), "1".into(), vec![])
    );
    // Each field is empty, until the response is truncated.
    for (bytes, field) in [
        (&[FORMAT][..], "name"),
        (&[FORMAT, 0][..], "version"),
        (&[FORMAT, 0, 0, 1][..], "flags"),
    ] {
        assert!(
            matches!(parse_version(bytes), Err(ResponseError::Decode { field: actual, .. }) if actual == field)
        );
    }
    // A name length that runs past the end of the response.
    let mut truncated_name = vec![FORMAT];
    truncated_name.extend(varint(256));
    assert!(parse_version(&truncated_name).is_err());
}

#[test]
fn fingerprint_response_has_exactly_four_bytes() {
    use ledger_bitcoin_client::protocol::{parse_master_fingerprint, ResponseError};
    assert_eq!(
        parse_master_fingerprint(&[1, 2, 3, 4]).unwrap().to_string(),
        "01020304"
    );
    for len in [0, 3, 5] {
        assert!(
            matches!(parse_master_fingerprint(&vec![0; len]), Err(ResponseError::InvalidLength { expected: 4, actual, .. }) if actual == len)
        );
    }
}

#[test]
fn registration_response_is_the_wallet_id_and_hmac() {
    use ledger_bitcoin_client::protocol::{parse_wallet_registration, ResponseError};
    let registration: Vec<u8> = (0..2 * HASH_LEN as u8).collect();
    let (id, hmac) = parse_wallet_registration(&registration).unwrap();
    assert_eq!(&id, &registration[..HASH_LEN]);
    assert_eq!(&hmac, &registration[HASH_LEN..]);
    for len in [2 * HASH_LEN - 1, 2 * HASH_LEN + 1] {
        assert!(
            matches!(parse_wallet_registration(&vec![0; len]), Err(ResponseError::InvalidLength { expected: 64, actual, .. }) if actual == len)
        );
    }
}

#[test]
fn pubkey_response_is_untrimmed_utf8() {
    use ledger_bitcoin_client::protocol::parse_extended_pubkey;
    let xpub = KEY.split(']').nth(1).unwrap();
    assert_eq!(
        parse_extended_pubkey(xpub.as_bytes()).unwrap().to_string(),
        xpub
    );
    assert!(parse_extended_pubkey(format!("{xpub}\n").as_bytes()).is_err());
    assert!(parse_extended_pubkey(&[0xff]).is_err());
}

#[test]
fn address_response_is_untrimmed_utf8() {
    use ledger_bitcoin_client::protocol::parse_wallet_address;
    let address = "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7";
    assert_eq!(
        parse_wallet_address(address.as_bytes())
            .unwrap()
            .assume_checked()
            .to_string(),
        address
    );
    assert!(parse_wallet_address(format!(" {address}").as_bytes()).is_err());
    assert!(parse_wallet_address(&[0xff]).is_err());
}

#[test]
fn message_signature_response_validates_length_and_encoding() {
    use ledger_bitcoin_client::protocol::{parse_message_signature, ResponseError};
    let mut signature = vec![255];
    signature.extend([1; 64]);
    let (header, sig) = parse_message_signature(&signature).unwrap();
    assert_eq!(header, 255);
    assert_eq!(sig.serialize_compact(), [1; 64]);
    for len in [0, 1, 64, 66] {
        assert!(
            matches!(parse_message_signature(&vec![0; len]), Err(ResponseError::InvalidLength { expected: 65, actual, .. }) if actual == len)
        );
    }
    assert!(matches!(
        parse_message_signature(&[255; 65]),
        Err(ResponseError::InvalidFormat { .. })
    ));
}
