mod utils;
use std::str::FromStr;

use bitcoin::{
    bip32::DerivationPath,
    hashes::{hex::FromHex, Hash},
    psbt::Psbt,
};
use ledger_bitcoin_client::{
    async_client, client, psbt::PartialSignature, wallet, MusigPartialSignature, MusigPubNonce,
    SignPsbtYieldedObject,
};

fn test_cases(path: &str) -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string(path).expect("Unable to read file");
    serde_json::from_str(&data).expect("Wrong tests data")
}

#[tokio::test]
async fn test_get_version() {
    let exchanges: Vec<String> = vec![
        "=> b001000000".into(),
        "<= 010c426974636f696e205465737405322e312e3001009000".into(),
    ];

    let store = utils::RecordStore::new(&exchanges);
    let (name, version, flags) =
        client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .get_version()
            .unwrap();

    assert_eq!(name, "Bitcoin Test".to_string());
    assert_eq!(version, "2.1.0".to_string());
    assert_eq!(flags, vec![0x00]);

    let (name, version, flags) =
        async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .get_version()
            .await
            .unwrap();

    assert_eq!(name, "Bitcoin Test".to_string());
    assert_eq!(version, "2.1.0".to_string());
    assert_eq!(flags, vec![0x00]);
}

#[tokio::test]
async fn test_sign_message() {
    let exchanges: Vec<String> = vec![
        "=> e110000132048000002c800000018000000000000000058a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db827".into(),
        "<= 418a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db8270100e000".into(),
        "=> f8010001228a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db8270000".into(),
        "<= 40008a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db827e000".into(),
        "=> f80100010806060068656c6c6f".into(),
        "<= 20bdeef462c0ce01b905db5206a51ed05a36671d1494ac12b18c764dbb955f45542c5819611050096d16ed03a5b01fc9806c163619777986235ed75fc91ee933e69000".into(),
    ];

    let path = DerivationPath::from_str("m/44'/1'/0'/0").unwrap();
    let store = utils::RecordStore::new(&exchanges);
    let (header, ecdsa_sig) =
        client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .sign_message("hello".as_bytes(), &path)
            .unwrap();

    assert_eq!(header, 0x20);
    let mut sig = vec![header];
    sig.extend(ecdsa_sig.serialize_compact());
    assert_eq!(
        "IL3u9GLAzgG5BdtSBqUe0Fo2Zx0UlKwSsYx2TbuVX0VULFgZYRBQCW0W7QOlsB/JgGwWNhl3eYYjXtdfyR7pM+Y=",
        base64::encode(sig)
    );

    let (header, ecdsa_sig) =
        async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .sign_message("hello".as_bytes(), &path)
            .await
            .unwrap();

    assert_eq!(header, 0x20);
    let mut sig = vec![header];
    sig.extend(ecdsa_sig.serialize_compact());
    assert_eq!(
        "IL3u9GLAzgG5BdtSBqUe0Fo2Zx0UlKwSsYx2TbuVX0VULFgZYRBQCW0W7QOlsB/JgGwWNhl3eYYjXtdfyR7pM+Y=",
        base64::encode(sig)
    );
}

#[tokio::test]
async fn test_get_extended_pubkey() {
    for case in test_cases("./tests/data/get_extended_pubkey.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let derivation_path: DerivationPath = case
            .get("derivation_path")
            .map(|v| v.as_str().unwrap())
            .map(|s| DerivationPath::from_str(&s).unwrap())
            .unwrap();

        let display: bool = case
            .get("display")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let xpk_str: String = case
            .get("result")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let store = utils::RecordStore::new(&exchanges);
        let key = client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .get_extended_pubkey(&derivation_path, display)
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);

        let key = async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .get_extended_pubkey(&derivation_path, display)
            .await
            .unwrap();

        assert_eq!(key.to_string(), xpk_str);
    }
}

#[tokio::test]
async fn test_register_wallet() {
    for case in test_cases("./tests/data/register_wallet.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let name: String = case
            .get("name")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let policy: String = case
            .get("policy")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys_str: Vec<String> = case
            .get("keys")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys: Vec<wallet::WalletPubKey> = keys_str
            .iter()
            .map(|s| wallet::WalletPubKey::from_str(s).unwrap())
            .collect();

        let hmac_result: String = case
            .get("hmac")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let version: usize = case
            .get("version")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let version = if version == 1 {
            wallet::Version::V1
        } else {
            wallet::Version::V2
        };

        let wallet = wallet::WalletPolicy::new(name, version, policy, keys);

        let store = utils::RecordStore::new(&exchanges);
        let (_id, hmac) = client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .register_wallet(&wallet)
            .unwrap();

        assert_eq!(hmac, <[u8; 32]>::from_hex(&hmac_result).unwrap());

        let (_id, hmac) =
            async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
                .register_wallet(&wallet)
                .await
                .unwrap();

        assert_eq!(hmac, <[u8; 32]>::from_hex(&hmac_result).unwrap());
    }
}

#[tokio::test]
async fn test_get_wallet_address() {
    for case in test_cases("./tests/data/get_wallet_address.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let name: String = case
            .get("name")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let policy: String = case
            .get("policy")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys_str: Vec<String> = case
            .get("keys")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys: Vec<wallet::WalletPubKey> = keys_str
            .iter()
            .map(|s| wallet::WalletPubKey::from_str(s).unwrap())
            .collect();

        let hmac: Option<String> = case
            .get("hmac")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();
        let hmac = hmac.map(|s| {
            let mut h = [b'\0'; 32];
            h.copy_from_slice(&Vec::from_hex(&s).unwrap());
            h
        });

        let change: bool = case
            .get("change")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let display: bool = case
            .get("display")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let address_index: u32 = case
            .get("address_index")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let address_result: String = case
            .get("address")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let wallet = wallet::WalletPolicy::new(name, wallet::Version::V2, policy, keys);

        let store = utils::RecordStore::new(&exchanges);
        let address = client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .get_wallet_address(&wallet, hmac.as_ref(), change, address_index, display)
            .unwrap();

        assert_eq!(address.assume_checked().to_string(), address_result);

        let address =
            async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
                .get_wallet_address(&wallet, hmac.as_ref(), change, address_index, display)
                .await
                .unwrap();

        assert_eq!(address.assume_checked().to_string(), address_result);
    }
}

#[tokio::test]
async fn test_sign_psbt() {
    for case in test_cases("./tests/data/sign_psbt.json") {
        let exchanges: Vec<String> = case
            .get("exchanges")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let name: String = case
            .get("name")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let policy: String = case
            .get("policy")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys_str: Vec<String> = case
            .get("keys")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let keys: Vec<wallet::WalletPubKey> = keys_str
            .iter()
            .map(|s| wallet::WalletPubKey::from_str(s).unwrap())
            .collect();

        let hmac: Option<String> = case
            .get("hmac")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();
        let hmac = hmac.map(|s| {
            let mut h = [b'\0'; 32];
            h.copy_from_slice(&Vec::from_hex(&s).unwrap());
            h
        });

        let sigs: Vec<serde_json::Value> = case
            .get("sigs")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap_or_default();

        let musig_pub_nonces: Vec<serde_json::Value> = case
            .get("musig_pub_nonces")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap_or_default();

        let musig_partial_signatures: Vec<serde_json::Value> = case
            .get("musig_partial_signatures")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap_or_default();

        let psbt_str: String = case
            .get("psbt")
            .map(|v| serde_json::from_value(v.clone()).unwrap())
            .unwrap();

        let psbt = Psbt::deserialize(&base64::decode(&psbt_str).unwrap()).unwrap();

        let wallet = wallet::WalletPolicy::new(name, wallet::Version::V2, policy, keys);

        let store = utils::RecordStore::new(&exchanges);
        let res = client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .sign_psbt(&psbt, &wallet, hmac.as_ref())
            .unwrap();

        let get_str = |v: &serde_json::Value, key: &str| -> String {
            serde_json::from_value::<String>(v.get(key).unwrap().clone()).unwrap()
        };

        let check_optional_tapleaf =
            |expected: &serde_json::Value, actual: &Option<bitcoin::taproot::TapLeafHash>| {
                if let Some(expected_hash) = expected.get("tapleaf_hash") {
                    let expected_hash: String =
                        serde_json::from_value(expected_hash.clone()).unwrap();
                    assert_eq!(expected_hash, hex::encode(actual.unwrap().to_byte_array()));
                } else {
                    assert!(actual.is_none());
                }
            };

        let check_results = |sigs: &[serde_json::Value],
                             musig_pub_nonces: &[serde_json::Value],
                             musig_partial_sigs: &[serde_json::Value],
                             res: &[(usize, SignPsbtYieldedObject)]| {
            let mut partial_results: Vec<&(usize, SignPsbtYieldedObject)> = Vec::new();
            let mut nonce_results: Vec<&(usize, SignPsbtYieldedObject)> = Vec::new();
            let mut partialsig_results: Vec<&(usize, SignPsbtYieldedObject)> = Vec::new();

            for item in res {
                match &item.1 {
                    SignPsbtYieldedObject::Partial(_) => partial_results.push(item),
                    SignPsbtYieldedObject::MusigPubNonce(_) => nonce_results.push(item),
                    SignPsbtYieldedObject::MusigPartialSignature(_) => {
                        partialsig_results.push(item)
                    }
                    other => panic!("Unexpected variant: {:?}", other),
                }
            }

            // Check partial signatures (Sig and TapScriptSig)
            assert_eq!(
                sigs.len(),
                partial_results.len(),
                "Expected {} partial sigs, got {}",
                sigs.len(),
                partial_results.len()
            );
            for (expected, (i, obj)) in sigs.iter().zip(partial_results.iter()) {
                match obj {
                    SignPsbtYieldedObject::Partial(PartialSignature::Sig(key, sig)) => {
                        assert_eq!(get_str(expected, "key"), key.to_string(), "input {i}");
                        assert_eq!(
                            get_str(expected, "sig"),
                            hex::encode(sig.to_vec()),
                            "input {i}"
                        );
                    }
                    SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                        key,
                        tapleaf_hash,
                        sig,
                    )) => {
                        assert_eq!(get_str(expected, "key"), key.to_string(), "input {i}");
                        check_optional_tapleaf(expected, tapleaf_hash);
                        assert_eq!(
                            get_str(expected, "sig"),
                            hex::encode(sig.to_vec()),
                            "input {i}"
                        );
                    }
                    _ => unreachable!(),
                }
            }

            // Check musig pub nonces
            assert_eq!(
                musig_pub_nonces.len(),
                nonce_results.len(),
                "Expected {} musig pub nonces, got {}",
                musig_pub_nonces.len(),
                nonce_results.len()
            );
            for (expected, (i, obj)) in musig_pub_nonces.iter().zip(nonce_results.iter()) {
                match obj {
                    SignPsbtYieldedObject::MusigPubNonce(MusigPubNonce {
                        participant_pubkey,
                        aggregate_pubkey,
                        tapleaf_hash,
                        pubnonce,
                    }) => {
                        assert_eq!(
                            get_str(expected, "participant_pubkey"),
                            participant_pubkey.to_string(),
                            "input {i}"
                        );
                        assert_eq!(
                            get_str(expected, "aggregate_pubkey"),
                            aggregate_pubkey.to_string(),
                            "input {i}"
                        );
                        assert_eq!(
                            get_str(expected, "pubnonce"),
                            hex::encode(pubnonce),
                            "input {i}"
                        );
                        check_optional_tapleaf(expected, tapleaf_hash);
                    }
                    _ => unreachable!(),
                }
            }

            // Check musig partial signatures
            assert_eq!(
                musig_partial_sigs.len(),
                partialsig_results.len(),
                "Expected {} musig partial sigs, got {}",
                musig_partial_sigs.len(),
                partialsig_results.len()
            );
            for (expected, (i, obj)) in musig_partial_sigs.iter().zip(partialsig_results.iter()) {
                match obj {
                    SignPsbtYieldedObject::MusigPartialSignature(MusigPartialSignature {
                        participant_pubkey,
                        aggregate_pubkey,
                        tapleaf_hash,
                        partial_signature,
                    }) => {
                        assert_eq!(
                            get_str(expected, "participant_pubkey"),
                            participant_pubkey.to_string(),
                            "input {i}"
                        );
                        assert_eq!(
                            get_str(expected, "aggregate_pubkey"),
                            aggregate_pubkey.to_string(),
                            "input {i}"
                        );
                        assert_eq!(
                            get_str(expected, "partial_signature"),
                            hex::encode(partial_signature),
                            "input {i}"
                        );
                        check_optional_tapleaf(expected, tapleaf_hash);
                    }
                    _ => unreachable!(),
                }
            }
        };

        check_results(&sigs, &musig_pub_nonces, &musig_partial_signatures, &res);

        let res = async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .sign_psbt(&psbt, &wallet, hmac.as_ref())
            .await
            .unwrap();

        check_results(&sigs, &musig_pub_nonces, &musig_partial_signatures, &res);
    }
}
