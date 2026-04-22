mod utils;
use std::str::FromStr;

use bitcoin::{
    bip32::DerivationPath,
    hashes::{hex::FromHex, Hash},
    psbt::Psbt,
};
use ledger_bitcoin_client::{
    async_client, client, psbt::PartialSignature, wallet, SignPsbtYieldedObject,
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
            .unwrap();

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

        let check_signatures =
            |sigs: &[serde_json::Value], res: Vec<(usize, SignPsbtYieldedObject)>| {
                for (i, psbt_sig) in res {
                    for (j, res_sig) in sigs.iter().enumerate() {
                        if i == j {
                            match psbt_sig {
                                SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                                    key,
                                    tapleaf_hash,
                                    sig,
                                )) => {
                                    assert_eq!(
                                        res_sig
                                            .get("key")
                                            .map(|v| serde_json::from_value::<String>(v.clone())
                                                .unwrap())
                                            .unwrap(),
                                        key.to_string()
                                    );
                                    if let Some(tapleaf_hash_res) =
                                        res_sig.get("tapleaf_hash").map(|v| {
                                            serde_json::from_value::<String>(v.clone()).unwrap()
                                        })
                                    {
                                        assert_eq!(
                                            tapleaf_hash_res,
                                            hex::encode(tapleaf_hash.unwrap().to_byte_array())
                                        );
                                    }
                                    assert_eq!(
                                        res_sig
                                            .get("sig")
                                            .map(|v| serde_json::from_value::<String>(v.clone())
                                                .unwrap())
                                            .unwrap(),
                                        hex::encode(sig.to_vec())
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }
            };

        check_signatures(&sigs, res);

        let res = async_client::BitcoinClient::new(utils::TransportReplayer::new(store.clone()))
            .sign_psbt(&psbt, &wallet, hmac.as_ref())
            .await
            .unwrap();

        check_signatures(&sigs, res);
    }
}
