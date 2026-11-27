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
const PUBKEY: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
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

#[test]
fn wallet_and_message_preparation_supply_delegated_preimages() {
    use ledger_bitcoin_client::protocol::{
        prepare_get_wallet_address, prepare_register_wallet, prepare_sign_message,
    };
    const MESSAGE_CHUNK_SIZE: usize = 64;
    for version in [Version::V1, Version::V2] {
        let wallet = wallet(version);
        // The commands themselves are tested by the *_command_wire_encoding tests.
        let registration = prepare_register_wallet(&wallet);
        assert_eq!(registration.command(), &command::register_wallet(&wallet));
        let mut requests = vec![registration];
        let hmac = [7; 32];
        for (hmac, change, index, display) in
            [(None, false, 0, false), (Some(&hmac), true, u32::MAX, true)]
        {
            let request = prepare_get_wallet_address(&wallet, hmac, change, index, display);
            assert_eq!(
                request.command(),
                &command::get_wallet_address(&wallet, hmac, change, index, display)
            );
            requests.push(request);
        }
        for mut request in requests {
            let interpreter = request.interpreter_mut().unwrap();
            for preimage in [
                wallet.serialize(),
                wallet.descriptor_template.as_bytes().to_vec(),
                [&[MERKLE_LEAF_PREFIX][..], KEY.as_bytes()].concat(),
            ] {
                let mut request = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
                request.extend(hash(&preimage));
                let mut expected = vec![preimage.len() as u8, preimage.len() as u8];
                expected.extend(preimage);
                assert_eq!(interpreter.execute(request).unwrap(), expected);
            }
            let key_leaf = hash(&[&[MERKLE_LEAF_PREFIX][..], KEY.as_bytes()].concat());
            let mut request = vec![ClientCommandCode::GetMerkleLeafProof as u8];
            request.extend(key_leaf);
            request.extend([1, 0]); // One-key tree, leaf zero.
            let mut expected = key_leaf.to_vec();
            expected.extend([0, 0]); // No siblings, no queued proof elements.
            assert_eq!(interpreter.execute(request).unwrap(), expected);
        }
    }
    let path = DerivationPath::from_str("m/44'/1'/0'/0").unwrap();
    for length in [
        0,
        1,
        MESSAGE_CHUNK_SIZE,
        MESSAGE_CHUNK_SIZE + 1,
        2 * MESSAGE_CHUNK_SIZE,
        2 * MESSAGE_CHUNK_SIZE + 1,
    ] {
        let message = vec![0x55; length];
        let mut request = prepare_sign_message(&message, &path);
        let chunks: Vec<_> = message.chunks(MESSAGE_CHUNK_SIZE).collect();
        let leaves: Vec<_> = chunks
            .iter()
            .map(|chunk| hash(&[&[MERKLE_LEAF_PREFIX][..], chunk].concat()))
            .collect();
        // For the empty message, the root of the empty list: 32 zero bytes.
        let root = merkle_root(&leaves);
        assert_eq!(
            request.command(),
            &command::sign_message(length, &root, &path)
        );
        let interpreter = request.interpreter_mut().unwrap();
        for chunk in chunks {
            let preimage = [&[MERKLE_LEAF_PREFIX][..], chunk].concat();
            let mut get_preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
            get_preimage.extend(hash(&preimage));
            let response = interpreter.execute(get_preimage).unwrap();
            // The preimage length, the length in this response, and the preimage.
            assert_eq!(response[..2], [preimage.len() as u8; 2]);
            assert_eq!(&response[2..], preimage);
        }
    }
}

#[test]
fn status_words_keep_their_value() {
    use ledger_bitcoin_client::apdu::StatusWord;
    // The statuses sent by the app (src/boilerplate/sw.h) and by the OS.
    for (status, value, name) in [
        (StatusWord::DeviceLocked, 0x5515, "DeviceLocked"),
        (
            StatusWord::SecurityStatusNotSatisfied,
            0x6982,
            "SecurityStatusNotSatisfied",
        ),
        (StatusWord::Deny, 0x6985, "Deny"),
        (StatusWord::IncorrectData, 0x6a80, "IncorrectData"),
        (StatusWord::NotSupported, 0x6a82, "NotSupported"),
        (StatusWord::WrongP1P2, 0x6a86, "WrongP1P2"),
        (StatusWord::WrongDataLength, 0x6a87, "WrongDataLength"),
        (StatusWord::SwapFail, 0x6b00, "SwapFail"),
        (StatusWord::InsNotSupported, 0x6d00, "InsNotSupported"),
        (StatusWord::ClaNotSupported, 0x6e00, "ClaNotSupported"),
        (
            StatusWord::WrongResponseLength,
            0xb000,
            "WrongResponseLength",
        ),
        (StatusWord::BadState, 0xb007, "BadState"),
        (StatusWord::SignatureFail, 0xb008, "SignatureFail"),
        (StatusWord::OK, 0x9000, "OK"),
        (
            StatusWord::InterruptedExecution,
            0xe000,
            "InterruptedExecution",
        ),
    ] {
        assert_eq!(StatusWord::from(value), status);
        assert_eq!(u16::from(status), value);
        assert_eq!(status.name(), Some(name));
        assert_eq!(format!("{:?}", status), name);
        assert_eq!(status.to_string(), format!("{:#06x} ({})", value, name));
    }
    let unnamed = StatusWord::from(0x6e01);
    assert_eq!(u16::from(unnamed), 0x6e01);
    assert_eq!(unnamed.name(), None);
    assert_eq!(format!("{:?}", unnamed), "StatusWord(0x6e01)");
    assert_eq!(unnamed.to_string(), "0x6e01");
}

#[test]
fn device_errors_show_the_status_and_the_response_data() {
    use ledger_bitcoin_client::{
        apdu::StatusWord,
        interpreter::InterpreterError,
        protocol::{prepare_get_master_fingerprint, RequestError},
    };
    let error = prepare_get_master_fingerprint()
        .step(StatusWord::Deny, vec![0x00, 0x17])
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Command 0x05 failed with status 0x6985 (Deny) (response data: 0017)"
    );
    let error = prepare_get_master_fingerprint()
        .step(StatusWord::from(0x6e01), vec![])
        .unwrap_err();
    assert_eq!(error.to_string(), "Command 0x05 failed with status 0x6e01");

    // An interpreter error is shown as itself, and is not repeated as the source.
    let error = RequestError::Interpreter(InterpreterError::UnknownHash);
    assert_eq!(error.to_string(), "Unknown preimage hash");
    assert!(std::error::Error::source(&error).is_none());
}

/// The CONTINUE command carrying `response` to a client command.
fn continuation(response: &[u8]) -> Vec<u8> {
    let mut command = vec![
        EXPECTED_FRAMEWORK_CLA,
        EXPECTED_CONTINUE_INS,
        0,
        EXPECTED_PROTOCOL_VERSION,
        response.len() as u8,
    ];
    command.extend(response);
    command
}

#[test]
fn steps_answer_client_commands_until_the_queue_is_empty() {
    use ledger_bitcoin_client::{
        apdu::StatusWord,
        interpreter::InterpreterError,
        protocol::{prepare_sign_message, RequestError, Step},
    };
    let path = DerivationPath::from_str("m/44'/1'/0'/0").unwrap();
    let mut request = prepare_sign_message(b"", &path);
    let preimage = vec![0x55; 256];
    request
        .interpreter_mut()
        .unwrap()
        .add_known_preimage(preimage.clone());
    let mut interrupted = |client_command: Vec<u8>| -> Result<Vec<u8>, RequestError> {
        match request.step(StatusWord::InterruptedExecution, client_command)? {
            Step::Continue(command) => Ok(command.encode()),
            Step::Done(_) => panic!("an interrupted execution must continue"),
        }
    };

    let mut get_preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
    get_preimage.extend(hash(&preimage));
    // The preimage length, the length in this response, and as much of the preimage as fits.
    let mut response = varint(preimage.len() as u64);
    let first_chunk_len = MAX_RESPONSE_LEN - response.len() - 1;
    response.push(first_chunk_len as u8);
    response.extend(&preimage[..first_chunk_len]);
    assert_eq!(interrupted(get_preimage).unwrap(), continuation(&response));

    // The rest of the preimage is queued as one-byte elements.
    let rest = &preimage[first_chunk_len..];
    let mut response = vec![rest.len() as u8, 1];
    response.extend(rest);
    let get_more_elements = vec![ClientCommandCode::GetMoreElements as u8];
    assert_eq!(
        interrupted(get_more_elements.clone()).unwrap(),
        continuation(&response)
    );

    let yielded = vec![1, 2];
    let mut yield_command = vec![ClientCommandCode::Yield as u8];
    yield_command.extend(&yielded);
    assert_eq!(
        interrupted(yield_command.clone()).unwrap(),
        continuation(&[])
    );

    // An error finishes the request.
    assert!(matches!(
        interrupted(get_more_elements),
        Err(RequestError::Interpreter(InterpreterError::UnexpectedQueue))
    ));
    assert!(matches!(
        interrupted(yield_command),
        Err(RequestError::Finished)
    ));
    assert_eq!(request.into_yielded(), vec![yielded]);

    const UNKNOWN_CLIENT_COMMAND: u8 = 0xff;
    for (client_command, expected) in [
        (vec![], InterpreterError::EmptyInput),
        (
            vec![UNKNOWN_CLIENT_COMMAND],
            InterpreterError::UnknownCommand(UNKNOWN_CLIENT_COMMAND),
        ),
    ] {
        let mut request = prepare_sign_message(b"", &path);
        assert_eq!(
            request.step(StatusWord::InterruptedExecution, client_command),
            Err(RequestError::Interpreter(expected))
        );
    }
}

#[test]
fn steps_end_on_success_and_report_errors_for_the_requests_command() {
    use ledger_bitcoin_client::{
        apdu::StatusWord,
        protocol::{
            prepare_get_master_fingerprint, prepare_sign_message, Request, RequestError, Step,
        },
    };
    const EXPECTED_GET_MASTER_FINGERPRINT_INS: u8 = 0x05;

    // Success finishes the request.
    let mut request = prepare_get_master_fingerprint();
    assert!(matches!(
        request.step(StatusWord::OK, vec![1, 2, 3]),
        Ok(Step::Done(data)) if data == [1, 2, 3]
    ));
    assert!(matches!(
        request.step(StatusWord::OK, vec![1, 2, 3]),
        Err(RequestError::Finished)
    ));

    // Without an interpreter, an interruption is an error.
    let mut request = prepare_get_master_fingerprint();
    assert!(matches!(
        request.step(
            StatusWord::InterruptedExecution,
            vec![ClientCommandCode::Yield as u8]
        ),
        Err(RequestError::Device {
            command: EXPECTED_GET_MASTER_FINGERPRINT_INS,
            status: StatusWord::InterruptedExecution,
            ..
        })
    ));

    let path = DerivationPath::from_str("m/44'/1'/0'/0").unwrap();
    let yield_command = vec![ClientCommandCode::Yield as u8, 7, 8];
    let continue_twice = |request: &mut Request| {
        for _ in 0..2 {
            assert!(matches!(
                request.step(StatusWord::InterruptedExecution, yield_command.clone()),
                Ok(Step::Continue(_))
            ));
        }
    };
    // A status without a name, sent by the SDK for an unknown default instruction.
    const UNNAMED_STATUS: StatusWord = StatusWord(0x6e01);
    // After continuations, errors still refer to the request's command, with the response data
    // (here, an error code), and finish the request.
    const ERROR_CODE: [u8; 2] = [0x00, 0x17];
    for status in [StatusWord::Deny, StatusWord::IncorrectData, UNNAMED_STATUS] {
        let mut request = prepare_sign_message(b"hello", &path);
        continue_twice(&mut request);
        assert!(matches!(
            request.step(status, ERROR_CODE.to_vec()),
            Err(RequestError::Device { command: EXPECTED_SIGN_MESSAGE_INS, status: actual, data, .. })
                if actual == status && data == ERROR_CODE
        ));
        assert!(matches!(
            request.step(StatusWord::OK, vec![]),
            Err(RequestError::Finished)
        ));
    }
    // The data of a successful response is returned, not interpreted.
    let mut request = prepare_sign_message(b"hello", &path);
    continue_twice(&mut request);
    assert!(matches!(
        request.step(StatusWord::OK, vec![0xff]),
        Ok(Step::Done(data)) if data == [0xff]
    ));
    assert_eq!(request.into_yielded(), vec![vec![7, 8], vec![7, 8]]);
}

#[test]
fn psbt_results_are_parsed_in_order_until_the_first_invalid_yield() {
    use ledger_bitcoin_client::{
        protocol::{parse_sign_psbt_results, SignPsbtYieldedObject},
        PartialSignatureError,
    };
    // Tags from 0x80000000 that are not known are parsed as unknown objects.
    const UNKNOWN_TAG: u64 = 0x8000_0000;
    let unknown = |index: u64| [varint(UNKNOWN_TAG), varint(index), vec![0xde, 0xad]].concat();

    assert!(parse_sign_psbt_results(vec![]).unwrap().is_empty());
    let parsed = parse_sign_psbt_results(vec![unknown(2), unknown(1)]).unwrap();
    assert_eq!(
        parsed.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        [2, 1]
    );
    assert!(matches!(
        &parsed[0].1,
        SignPsbtYieldedObject::Unknown { tag, data, .. } if *tag == UNKNOWN_TAG && data == &[0xde, 0xad]
    ));

    // Untagged: the input index, then a partial signature whose 33-byte public key is invalid.
    let invalid_pubkey = [varint(0), vec![33], vec![0; 33], vec![1; 8]].concat();
    let error =
        parse_sign_psbt_results(vec![unknown(0), invalid_pubkey.clone(), vec![]]).unwrap_err();
    assert_eq!(error.data, invalid_pubkey);
    assert!(matches!(error.source, PartialSignatureError::PubKey(_)));
    assert_eq!(error.to_string(), "Invalid value yielded by SIGN_PSBT");
    let source = std::error::Error::source(&error).unwrap();
    assert!(source.to_string().starts_with("Invalid public key"));

    for short in [vec![], vec![1]] {
        let error = parse_sign_psbt_results(vec![unknown(0), short.clone()]).unwrap_err();
        assert_eq!(error.data, short);
    }

    let oversized_index = [varint(UNKNOWN_TAG), varint(u32::MAX as u64 + 1)].concat();
    let error = parse_sign_psbt_results(vec![oversized_index]).unwrap_err();
    assert!(matches!(
        error.source,
        PartialSignatureError::InvalidInputIndex
    ));
}

fn unsigned_psbt() -> bitcoin::psbt::Psbt {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };
    bitcoin::psbt::Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap()
}

#[test]
fn psbt_preparation_delegates_custom_values_and_propagates_map_errors() {
    use bitcoin::psbt::raw::{Key, ProprietaryKey};
    use ledger_bitcoin_client::{protocol::prepare_sign_psbt, psbt::PsbtV2Error};
    const TEST_UNKNOWN_KEY_TYPE: u8 = 0x70;
    const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
    let mut psbt = unsigned_psbt();
    let unknown = Key {
        type_value: TEST_UNKNOWN_KEY_TYPE,
        key: vec![9],
    };
    let proprietary = ProprietaryKey {
        prefix: b"hw".to_vec(),
        subtype: 1,
        key: vec![9],
    };
    // Distinct values, which no other field of the PSBT has, so that each one shows that its map
    // was forwarded.
    let values: [&[u8]; 6] = [
        b"global unknown",
        b"input unknown",
        b"output unknown",
        b"global proprietary",
        b"input proprietary",
        b"output proprietary",
    ];
    psbt.unknown.insert(unknown.clone(), values[0].to_vec());
    psbt.inputs[0]
        .unknown
        .insert(unknown.clone(), values[1].to_vec());
    psbt.outputs[0].unknown.insert(unknown, values[2].to_vec());
    psbt.proprietary
        .insert(proprietary.clone(), values[3].to_vec());
    psbt.inputs[0]
        .proprietary
        .insert(proprietary.clone(), values[4].to_vec());
    psbt.outputs[0]
        .proprietary
        .insert(proprietary, values[5].to_vec());
    let mut request = prepare_sign_psbt(&psbt, &wallet(Version::V2), None).unwrap();
    let interpreter = request.interpreter_mut().unwrap();
    // The keys too: <keytype> || <keydata>, and for the proprietary one, the keydata is the
    // prefix (with its length), the subtype and the key.
    let unknown_key: &[u8] = &[TEST_UNKNOWN_KEY_TYPE, 9];
    let proprietary_key: &[u8] = &[0xfc, 2, b'h', b'w', 1, 9];
    for element in [unknown_key, proprietary_key].iter().chain(values.iter()) {
        let mut preimage = vec![MERKLE_LEAF_PREFIX];
        preimage.extend_from_slice(element);
        let mut get_preimage = vec![ClientCommandCode::GetPreimage as u8, SHA256_HASH_TYPE];
        get_preimage.extend(hash(&preimage));
        // The preimage length, the length in this response, and the preimage.
        let mut expected = vec![preimage.len() as u8, preimage.len() as u8];
        expected.extend(&preimage);
        assert_eq!(interpreter.execute(get_preimage).unwrap(), expected);
    }

    // Errors converting the PSBT are propagated. The psbt module tests each of them.
    let mut conflict = unsigned_psbt();
    conflict.inputs[0].unknown.insert(
        Key {
            type_value: PSBT_IN_PREVIOUS_TXID,
            key: vec![],
        },
        vec![42],
    );
    assert_eq!(
        prepare_sign_psbt(&conflict, &wallet(Version::V2), None).err(),
        Some(PsbtV2Error::UnexpectedV2Field(PSBT_IN_PREVIOUS_TXID))
    );
    psbt.inputs.clear();
    assert_eq!(
        prepare_sign_psbt(&psbt, &wallet(Version::V2), None).err(),
        Some(PsbtV2Error::TxMapCountMismatch)
    );
}

#[test]
fn public_psbt_preparation_replays_recorded_delegated_exchanges() {
    use ledger_bitcoin_client::{
        apdu::StatusWord,
        protocol::{parse_sign_psbt_results, prepare_sign_psbt, prepare_sign_psbt_bytes, Step},
    };
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("data/sign_psbt.json")).unwrap();
    for case in cases {
        let psbt_bytes = base64::decode(case["psbt"].as_str().unwrap()).unwrap();
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
        let keys: Vec<_> = case["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| WalletPubKey::from_str(key.as_str().unwrap()).unwrap())
            .collect();
        let wallet = WalletPolicy::new(
            case["name"].as_str().unwrap().into(),
            Version::V2,
            case["policy"].as_str().unwrap().into(),
            keys,
        );
        let hmac = case["hmac"].as_str().map(|value| {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(&hex::decode(value).unwrap());
            bytes
        });
        // the parsed and the serialized PSBT must produce the same exchanges
        for mut request in [
            prepare_sign_psbt(&psbt, &wallet, hmac.as_ref()).unwrap(),
            prepare_sign_psbt_bytes(&psbt_bytes, &wallet, hmac.as_ref()).unwrap(),
        ] {
            let mut command = request.command().clone();
            let mut exchanges = case["exchanges"]
                .as_array()
                .unwrap()
                .iter()
                .map(|exchange| exchange.as_str().unwrap());
            let mut done = false;
            while let Some(sent) = exchanges.next() {
                assert!(!done, "no exchange is expected after the final response");
                let received = exchanges.next().expect("every command has a response");
                let sent = hex::decode(sent.trim_start_matches("=> ")).unwrap();
                assert_eq!(command.encode(), sent);
                let mut response = hex::decode(received.trim_start_matches("<= ")).unwrap();
                let status = response.split_off(response.len() - 2);
                let status = StatusWord::from(u16::from_be_bytes([status[0], status[1]]));
                match request.step(status, response).unwrap() {
                    Step::Continue(next) => command = next,
                    Step::Done(_) => done = true,
                }
            }
            assert!(done);
            let results = parse_sign_psbt_results(request.into_yielded()).unwrap();
            // Compare with the expected values of each kind, in the test data's format.
            for kind in ["sigs", "musig_pub_nonces", "musig_partial_signatures"] {
                let actual: Vec<_> = results
                    .iter()
                    .map(|(_, object)| yielded_object_json(object))
                    .filter(|(object_kind, _)| *object_kind == kind)
                    .map(|(_, object)| object)
                    .collect();
                let expected: Vec<_> = case[kind]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut object| {
                        // An absent tapleaf hash may be written as null.
                        object
                            .as_object_mut()
                            .unwrap()
                            .retain(|_, value| !value.is_null());
                        object
                    })
                    .collect();
                assert_eq!(actual, expected, "{}", kind);
            }
        }
    }
}

/// A yielded object as in `tests/data/sign_psbt.json`, with the name of its list there.
fn yielded_object_json(
    object: &ledger_bitcoin_client::SignPsbtYieldedObject,
) -> (&'static str, serde_json::Value) {
    use ledger_bitcoin_client::{PartialSignature, SignPsbtYieldedObject};
    let leaf = |hash: &Option<bitcoin::taproot::TapLeafHash>| {
        hash.map(|hash| hex::encode(hash.to_byte_array()))
    };
    let mut json = serde_json::Map::new();
    let kind = match object {
        SignPsbtYieldedObject::Partial(PartialSignature::Sig(key, sig)) => {
            json.insert("key".into(), key.to_string().into());
            json.insert("sig".into(), hex::encode(sig.to_vec()).into());
            "sigs"
        }
        SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(key, tapleaf_hash, sig)) => {
            json.insert("key".into(), key.to_string().into());
            if let Some(hash) = leaf(tapleaf_hash) {
                json.insert("tapleaf_hash".into(), hash.into());
            }
            json.insert("sig".into(), hex::encode(sig.to_vec()).into());
            "sigs"
        }
        SignPsbtYieldedObject::MusigPubNonce(nonce) => {
            json.insert(
                "participant_pubkey".into(),
                nonce.participant_pubkey.to_string().into(),
            );
            json.insert(
                "aggregate_pubkey".into(),
                nonce.aggregate_pubkey.to_string().into(),
            );
            if let Some(hash) = leaf(&nonce.tapleaf_hash) {
                json.insert("tapleaf_hash".into(), hash.into());
            }
            json.insert("pubnonce".into(), hex::encode(nonce.pubnonce).into());
            "musig_pub_nonces"
        }
        SignPsbtYieldedObject::MusigPartialSignature(signature) => {
            json.insert(
                "participant_pubkey".into(),
                signature.participant_pubkey.to_string().into(),
            );
            json.insert(
                "aggregate_pubkey".into(),
                signature.aggregate_pubkey.to_string().into(),
            );
            if let Some(hash) = leaf(&signature.tapleaf_hash) {
                json.insert("tapleaf_hash".into(), hash.into());
            }
            json.insert(
                "partial_signature".into(),
                hex::encode(signature.partial_signature).into(),
            );
            "musig_partial_signatures"
        }
        other => panic!("Unexpected yielded object: {:?}", other),
    };
    (kind, json.into())
}

#[test]
fn signature_application_validates_before_mutation_and_overwrites() {
    use bitcoin::{
        ecdsa,
        key::TweakedPublicKey,
        secp256k1,
        taproot::{Signature, TapLeafHash},
        Amount, PublicKey, ScriptBuf, TxOut,
    };
    use ledger_bitcoin_client::{
        psbt::{apply_partial_signature, ApplySignatureError},
        PartialSignature,
    };
    let key = PublicKey::from_str(PUBKEY).unwrap();
    let xonly = key.inner.x_only_public_key().0;
    let p2tr = |key| TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key)),
    };
    let leaf = TapLeafHash::from_byte_array([3; 32]);
    let mut psbt = unsigned_psbt();
    psbt.inputs[0].witness_utxo = Some(p2tr(xonly));
    for byte in [1, 2] {
        let ecdsa = ecdsa::Signature::sighash_all(
            secp256k1::ecdsa::Signature::from_compact(&[byte; 64]).unwrap(),
        );
        let taproot = Signature::from_slice(&[byte; 64]).unwrap();
        for signature in [
            PartialSignature::Sig(key, ecdsa),
            PartialSignature::TapScriptSig(xonly, None, taproot),
            PartialSignature::TapScriptSig(xonly, Some(leaf), taproot),
        ] {
            let before = psbt.clone();
            for input_index in [1, usize::MAX] {
                assert!(matches!(
                    apply_partial_signature(&mut psbt, input_index, signature.clone()),
                    Err(ApplySignatureError::InputIndexOutOfBounds { input_index: actual, .. })
                        if actual == input_index
                ));
                assert_eq!(psbt, before);
            }
            apply_partial_signature(&mut psbt, 0, signature).unwrap();
        }
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert_eq!(psbt.inputs[0].partial_sigs[&key], ecdsa);
        assert_eq!(psbt.inputs[0].tap_key_sig, Some(taproot));
        assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
        assert_eq!(psbt.inputs[0].tap_script_sigs[&(xonly, leaf)], taproot);
    }

    // A key-path signature must be for the output key of the spent P2TR output.
    let key_path =
        PartialSignature::TapScriptSig(xonly, None, Signature::from_slice(&[1; 64]).unwrap());
    // The generator point.
    let other_key =
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .inner
            .x_only_public_key()
            .0;
    let p2wpkh = TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new_p2wpkh(&key.wpubkey_hash().unwrap()),
    };
    // The non-witness UTXO is not used.
    let p2tr_transaction = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![p2tr(xonly)],
    };
    for (witness_utxo, non_witness_utxo, expected) in [
        (None, None, ApplySignatureError::MissingWitnessUtxo),
        (
            None,
            Some(p2tr_transaction),
            ApplySignatureError::MissingWitnessUtxo,
        ),
        (
            Some(p2tr(other_key)),
            None,
            ApplySignatureError::OutputKeyMismatch,
        ),
        (Some(p2wpkh), None, ApplySignatureError::OutputKeyMismatch),
    ] {
        let mut psbt = unsigned_psbt();
        psbt.inputs[0].witness_utxo = witness_utxo;
        psbt.inputs[0].non_witness_utxo = non_witness_utxo;
        let before = psbt.clone();
        assert_eq!(
            apply_partial_signature(&mut psbt, 0, key_path.clone()),
            Err(expected)
        );
        assert_eq!(psbt, before);
    }
}

#[test]
fn signatures_are_applied_to_the_given_input() {
    use bitcoin::{
        ecdsa, key::TweakedPublicKey, secp256k1, taproot::Signature, Amount, OutPoint, PublicKey,
        ScriptBuf, TxOut,
    };
    use ledger_bitcoin_client::{
        psbt::{apply_partial_signature, ApplySignatureError},
        PartialSignature,
    };
    let p2tr = |key| TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key)),
    };
    let key = PublicKey::from_str(PUBKEY).unwrap();
    let xonly = key.inner.x_only_public_key().0;
    // The generator point.
    let other_xonly =
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .inner
            .x_only_public_key()
            .0;
    // Two inputs, spending P2TR outputs with different output keys.
    let mut tx = unsigned_psbt().unsigned_tx;
    let mut second_input = tx.input[0].clone();
    second_input.previous_output = OutPoint {
        vout: 1,
        ..second_input.previous_output
    };
    tx.input.push(second_input);
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(p2tr(other_xonly));
    psbt.inputs[1].witness_utxo = Some(p2tr(xonly));
    let untouched_input = psbt.inputs[0].clone();

    let ecdsa =
        ecdsa::Signature::sighash_all(secp256k1::ecdsa::Signature::from_compact(&[1; 64]).unwrap());
    let taproot = Signature::from_slice(&[1; 64]).unwrap();
    apply_partial_signature(&mut psbt, 1, PartialSignature::Sig(key, ecdsa)).unwrap();
    apply_partial_signature(
        &mut psbt,
        1,
        PartialSignature::TapScriptSig(xonly, None, taproot),
    )
    .unwrap();
    assert_eq!(psbt.inputs[1].partial_sigs[&key], ecdsa);
    assert_eq!(psbt.inputs[1].tap_key_sig, Some(taproot));
    assert_eq!(psbt.inputs[0], untouched_input);

    // The key-path signature for the first input's output key does not fit the second input.
    let before = psbt.clone();
    assert_eq!(
        apply_partial_signature(
            &mut psbt,
            1,
            PartialSignature::TapScriptSig(other_xonly, None, taproot)
        ),
        Err(ApplySignatureError::OutputKeyMismatch)
    );
    assert_eq!(psbt, before);
}

#[cfg(feature = "paranoid_client")]
#[test]
fn independent_address_verification_and_error_categories() {
    use ledger_bitcoin_client::wallet::AddressCheckError;
    let policy = wallet(Version::V2);
    let address = bitcoin::Address::from_str(
        "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7",
    )
    .unwrap();
    assert_eq!(policy.check_address(false, 0, &address), Ok(()));
    assert_eq!(
        policy.check_address(true, 0, &address),
        Err(AddressCheckError::Mismatch)
    );
    assert_eq!(
        policy.check_address(false, 1, &address),
        Err(AddressCheckError::Mismatch)
    );
    let other_network = bitcoin::Address::from_script(
        &address.assume_checked_ref().script_pubkey(),
        bitcoin::Network::Bitcoin,
    )
    .unwrap()
    .into_unchecked();
    assert_eq!(policy.check_address(false, 0, &other_network), Ok(()));
    assert_eq!(
        policy.check_address(false, 1 << 31, &address),
        Err(AddressCheckError::Derivation)
    );
    let mut invalid = wallet(Version::V2);
    invalid.descriptor_template = "tr(@0/<0;1;2>/*)".into();
    assert_eq!(
        invalid.check_address(false, 0, &address),
        Err(AddressCheckError::GetDescriptor)
    );
    invalid.descriptor_template = "invalid(@0/**)".into();
    assert_eq!(
        invalid.check_address(false, 0, &address),
        Err(AddressCheckError::Descriptor)
    );
    invalid.descriptor_template = "tr(musig(@0)/**)".into();
    assert!(matches!(
        invalid.check_address(false, 0, &address),
        Err(AddressCheckError::Musig(_))
    ));

    let keys = [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
    ];
    let musig = WalletPolicy::new(
        "".into(),
        Version::V2,
        "tr(musig(@0,@1)/**)".into(),
        keys.iter().map(|key| WalletPubKey::from_str(key).unwrap()),
    );
    let aggregate = "tr(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBaQqFP72F6Sdr6LkYSK7RSHasFxRSq6Vfa4Cn1g47oASGeLixXb/0/*)";
    let aggregate =
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(aggregate).unwrap();
    let expected = aggregate
        .at_derivation_index(9)
        .unwrap()
        .address(bitcoin::Network::Testnet)
        .unwrap()
        .into_unchecked();
    assert_eq!(musig.check_address(false, 9, &expected), Ok(()));
    assert_eq!(
        musig.check_address(true, 9, &expected),
        Err(AddressCheckError::Mismatch)
    );
}
