//! Replays the recorded device transcripts of the core crate through [`Operation`], and checks
//! the operation's state handling and error reporting.

use ledger_bitcoin_client_bindings::{wallet_policy, Apdu, Error, Operation, Output, Yielded};
use serde_json::Value;

const KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";

fn cases(data: &str) -> Vec<Value> {
    serde_json::from_str(data).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn hex_field(case: &Value, field: &str) -> Option<Vec<u8>> {
    case[field].as_str().map(|v| hex::decode(v).unwrap())
}

/// Parses recorded exchanges into (APDU, status word, response data) triples. Entries are
/// "=> apdu" or "<= response" hex strings, possibly with spaces; others are comments.
fn exchanges(entries: &[Value]) -> Vec<(Vec<u8>, u16, Vec<u8>)> {
    let mut result = Vec::new();
    let mut command = Vec::new();
    for entry in entries {
        let entry = entry.as_str().unwrap().replace(' ', "");
        if let Some(apdu) = entry.strip_prefix("=>") {
            command = hex::decode(apdu).unwrap();
        } else if let Some(response) = entry.strip_prefix("<=") {
            let mut response = hex::decode(response).unwrap();
            let sw_offset = response.len() - 2;
            let sw = u16::from_be_bytes([response[sw_offset], response[sw_offset + 1]]);
            response.truncate(sw_offset);
            result.push((command.clone(), sw, response));
        }
    }
    result
}

/// Plays the recorded `entries` against `operation`, checking every APDU it sends, and returns
/// the largest yielded count observed.
fn replay(operation: &mut Operation, entries: &[Value]) -> usize {
    let mut max_yielded = 0;
    for (expected, sw, response) in exchanges(entries) {
        assert_eq!(operation.next_apdu().unwrap().encode(), expected);
        operation.step(sw, response).unwrap();
        max_yielded = max_yielded.max(operation.yielded_count());
    }
    assert_eq!(
        operation.next_apdu(),
        None,
        "the transcript must complete the operation"
    );
    max_yielded
}

#[test]
fn register_wallet_transcripts_include_the_address_check() {
    for case in cases(include_str!("../../../tests/data/register_wallet.json")) {
        let wallet = wallet_policy(
            case["name"].as_str().unwrap(),
            case["policy"].as_str().unwrap(),
            &strings(&case["keys"]),
            case["version"].as_u64().unwrap() as u8,
        )
        .unwrap();
        let id = wallet.id();
        let mut operation = Operation::register_wallet(wallet);
        let mut exchanges = case["exchanges"].as_array().unwrap().clone();
        exchanges.extend(
            case["address_exchanges"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
        replay(&mut operation, &exchanges);
        let hmac = hex_field(&case, "hmac").unwrap();
        assert_eq!(
            operation.output().unwrap(),
            Output::WalletRegistration {
                id,
                hmac: hmac.try_into().unwrap()
            }
        );
    }
}

#[test]
fn get_wallet_address_transcripts() {
    for case in cases(include_str!("../../../tests/data/get_wallet_address.json")) {
        let wallet = wallet_policy(
            case["name"].as_str().unwrap(),
            case["policy"].as_str().unwrap(),
            &strings(&case["keys"]),
            2,
        )
        .unwrap();
        let mut operation = Operation::get_wallet_address(
            wallet,
            hex_field(&case, "hmac").as_deref(),
            case["change"].as_bool().unwrap() as u32,
            case["address_index"].as_u64().unwrap() as u32,
            case["display"].as_bool().unwrap(),
        )
        .unwrap();
        replay(&mut operation, case["exchanges"].as_array().unwrap());
        assert_eq!(
            operation.output().unwrap(),
            Output::WalletAddress(case["address"].as_str().unwrap().to_string())
        );
    }
}

#[test]
fn get_extended_pubkey_transcripts() {
    for case in cases(include_str!("../../../tests/data/get_extended_pubkey.json")) {
        let mut operation = Operation::get_extended_pubkey(
            case["derivation_path"].as_str().unwrap(),
            case["display"].as_bool().unwrap(),
        )
        .unwrap();
        replay(&mut operation, case["exchanges"].as_array().unwrap());
        assert_eq!(
            operation.output().unwrap(),
            Output::ExtendedPubkey(case["result"].as_str().unwrap().to_string())
        );
    }
}

#[test]
fn sign_psbt_transcripts() {
    for case in cases(include_str!("../../../tests/data/sign_psbt.json")) {
        let wallet = wallet_policy(
            case["name"].as_str().unwrap(),
            case["policy"].as_str().unwrap(),
            &strings(&case["keys"]),
            2,
        )
        .unwrap();
        let psbt = base64::decode(case["psbt"].as_str().unwrap()).unwrap();
        let mut operation =
            Operation::sign_psbt(&psbt, &wallet, hex_field(&case, "hmac").as_deref()).unwrap();
        let max_yielded = replay(&mut operation, case["exchanges"].as_array().unwrap());
        let Output::PsbtSignatures(results) = operation.output().unwrap() else {
            panic!("expected signatures");
        };
        let expected: usize = ["sigs", "musig_pub_nonces", "musig_partial_signatures"]
            .iter()
            .map(|key| case[*key].as_array().map_or(0, Vec::len))
            .sum();
        assert_eq!(results.len(), expected);
        assert_eq!(max_yielded, expected, "progress is visible while signing");

        // regular signatures are returned exactly as recorded
        let sigs = case["sigs"].as_array().cloned().unwrap_or_default();
        for (sig, (_, result)) in sigs.iter().zip(results.iter()) {
            let Yielded::PartialSignature {
                pubkey,
                signature,
                tapleaf_hash,
            } = result
            else {
                panic!("expected a regular signature");
            };
            assert_eq!(hex::encode(pubkey), sig["key"].as_str().unwrap());
            assert_eq!(hex::encode(signature), sig["sig"].as_str().unwrap());
            assert_eq!(
                tapleaf_hash.as_ref().map(hex::encode),
                sig["tapleaf_hash"].as_str().map(String::from)
            );
        }
        if sigs.is_empty() {
            assert!(results.iter().all(|(_, result)| matches!(
                result,
                Yielded::MusigPubNonce { .. } | Yielded::MusigPartialSignature { .. }
            )));
        }
    }
}

fn single_key_wallet() -> ledger_bitcoin_client::wallet::WalletPolicy {
    wallet_policy("", "tr(@0/**)", &[KEY], 2).unwrap()
}

#[test]
fn device_errors_end_the_operation_with_the_request_instruction() {
    let mut operation = Operation::get_master_fingerprint();
    let ins = operation.next_apdu().unwrap().ins;
    assert_eq!(
        operation.step(0x6985, vec![1, 2]),
        Err(Error::Device {
            ins,
            sw: 0x6985,
            data: vec![1, 2]
        })
    );
    assert_eq!(operation.next_apdu(), None);
    assert!(matches!(
        operation.step(0x9000, vec![]),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(operation.output(), Err(Error::InvalidState(_))));

    // a failure in a continuation still reports the original instruction; unknown status words
    // are reported as they are
    let mut operation = Operation::sign_message(b"hello", "m/44'/1'/0'").unwrap();
    let ins = operation.next_apdu().unwrap().ins;
    // the device asks for the Merkle leaf of the only chunk of the message
    let preimage_request = {
        let mut request = vec![0x40, 0x00];
        let mut leaf = vec![0x00];
        leaf.extend_from_slice(b"hello");
        use bitcoin::hashes::{sha256, Hash};
        request.extend_from_slice(sha256::Hash::hash(&leaf).as_byte_array());
        request
    };
    let next = operation.step(0xE000, preimage_request).unwrap().unwrap();
    assert_eq!(next.cla, 0xF8, "a continuation follows");
    assert_eq!(
        operation.step(0x5515, vec![]),
        Err(Error::Device {
            ins,
            sw: 0x5515,
            data: vec![]
        })
    );
}

#[test]
fn interruptions_require_delegated_state() {
    // a request that the device never interrupts: the interruption is a device error
    let mut operation = Operation::get_version();
    let ins = operation.next_apdu().unwrap().ins;
    assert_eq!(
        operation.step(0xE000, vec![0x40]),
        Err(Error::Device {
            ins,
            sw: 0xE000,
            data: vec![0x40]
        })
    );

    let mut operation = Operation::register_wallet(single_key_wallet());
    // an unknown client command
    assert!(matches!(
        operation.step(0xE000, vec![0xff]),
        Err(Error::InvalidResponse(_))
    ));
}

#[test]
fn simple_outputs() {
    let mut operation = Operation::get_master_fingerprint();
    assert_eq!(
        operation.step(0x9000, vec![0xf5, 0xac, 0xc2, 0xfd]),
        Ok(None)
    );
    assert!(matches!(
        operation.step(0x9000, vec![]),
        Err(Error::InvalidState(_))
    ));
    assert_eq!(
        operation.output(),
        Ok(Output::MasterFingerprint([0xf5, 0xac, 0xc2, 0xfd]))
    );

    let mut operation = Operation::get_version();
    let apdu = operation.next_apdu().unwrap();
    assert_eq!(
        apdu,
        Apdu {
            cla: 0xB0,
            ins: 0x01,
            p1: 0,
            p2: 0,
            data: vec![]
        }
    );
    let mut response = vec![1, 4];
    response.extend_from_slice(b"Test");
    response.extend_from_slice(&[5]);
    response.extend_from_slice(b"2.4.6");
    response.extend_from_slice(&[1, 2]);
    operation.step(0x9000, response).unwrap();
    assert_eq!(
        operation.output(),
        Ok(Output::Version {
            name: "Test".into(),
            version: "2.4.6".into(),
            flags: vec![2]
        })
    );

    let mut operation = Operation::get_master_fingerprint();
    assert!(matches!(
        operation.step(0x9000, vec![1]),
        Err(Error::InvalidResponse(_))
    ));
}

#[test]
fn addresses_are_verified_independently() {
    // the first receive address of the transcript's wallet, at index 1 instead of 0
    let address = "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7";
    let mut operation =
        Operation::get_wallet_address(single_key_wallet(), None, 0, 1, false).unwrap();
    assert!(matches!(
        operation.step(0x9000, address.as_bytes().to_vec()),
        Err(Error::InvalidResponse(message)) if message.starts_with("Invalid address")
    ));
    let mut operation =
        Operation::get_wallet_address(single_key_wallet(), None, 0, 0, false).unwrap();
    assert_eq!(
        operation.step(0x9000, address.as_bytes().to_vec()),
        Ok(None)
    );
    assert_eq!(
        operation.output(),
        Ok(Output::WalletAddress(address.into()))
    );
}

#[test]
fn invalid_arguments_are_rejected_before_any_exchange() {
    let invalid = |result: Result<Operation, Error>| {
        assert!(matches!(result, Err(Error::InvalidArgument(_))))
    };
    invalid(Operation::get_extended_pubkey("m/x", false));
    invalid(Operation::sign_message(b"", "m/1/2'/z"));
    invalid(Operation::get_wallet_address(
        single_key_wallet(),
        None,
        2,
        0,
        false,
    ));
    invalid(Operation::get_wallet_address(
        single_key_wallet(),
        Some(&[0; 31]),
        0,
        0,
        false,
    ));
    invalid(Operation::sign_psbt(b"psbt", &single_key_wallet(), None));
    invalid(Operation::sign_psbt(
        b"psbt\xff\x00",
        &single_key_wallet(),
        Some(&[0; 33]),
    ));

    assert!(matches!(
        wallet_policy("", "tr(@0/**)", &[KEY], 3),
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        wallet_policy("", "tr(@0/**)", &["not a key"], 2),
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        wallet_policy(&"x".repeat(256), "tr(@0/**)", &[KEY], 2),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn derivation_paths_accept_both_hardened_markers() {
    let encode = |path| {
        Operation::get_extended_pubkey(path, false)
            .unwrap()
            .next_apdu()
            .unwrap()
            .data
    };
    assert_eq!(encode("m/84'/1'/0'"), encode("84h/1h/0h"));
    assert_eq!(encode("m"), vec![0, 0]);
}

/// Signs the PSBT of the first transcript, answering its SIGN_PSBT request with a single yield.
fn sign_psbt_with_yield(yielded: Vec<u8>) -> Result<Output, Error> {
    let case = &cases(include_str!("../../../tests/data/sign_psbt.json"))[0];
    let wallet = wallet_policy(
        case["name"].as_str().unwrap(),
        case["policy"].as_str().unwrap(),
        &strings(&case["keys"]),
        2,
    )
    .unwrap();
    let psbt = base64::decode(case["psbt"].as_str().unwrap()).unwrap();
    let mut operation =
        Operation::sign_psbt(&psbt, &wallet, hex_field(case, "hmac").as_deref()).unwrap();
    let mut request = vec![0x10];
    request.extend(yielded);
    operation.step(0xE000, request)?;
    operation.step(0x9000, vec![])?;
    operation.output()
}

#[test]
fn unknown_yields_keep_their_tag() {
    // tag 0x80000001, input 3, opaque data
    let mut yielded = vec![0xFE, 0x01, 0x00, 0x00, 0x80, 0x03];
    yielded.extend_from_slice(&[9, 8, 7]);
    assert_eq!(
        sign_psbt_with_yield(yielded),
        Ok(Output::PsbtSignatures(vec![(
            3,
            Yielded::Unknown {
                tag: 0x80000001,
                data: vec![9, 8, 7]
            }
        )]))
    );
    assert!(matches!(
        sign_psbt_with_yield(vec![0x00]),
        Err(Error::InvalidResponse(_))
    ));
}
