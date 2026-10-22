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
