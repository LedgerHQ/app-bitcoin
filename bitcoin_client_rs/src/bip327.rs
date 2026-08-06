/// Minimal BIP-327 key aggregation (KeyAgg only) for paranoid client address verification.
/// This module implements just enough of BIP-327 to aggregate musig() public keys into a
/// single combined public key, enabling independent address derivation for wallet policies
/// containing musig() expressions.
use core::str::FromStr;

use bitcoin::{
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpub},
    hashes::{sha256, Hash, HashEngine},
    network::NetworkKind,
    secp256k1::{self, PublicKey, Scalar, Secp256k1},
};

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn hash_keys(pubkeys: &[PublicKey]) -> [u8; 32] {
    let concat: Vec<u8> = pubkeys
        .iter()
        .flat_map(|pk| pk.serialize().to_vec())
        .collect();
    tagged_hash("KeyAgg list", &concat)
}

fn get_second_key(pubkeys: &[PublicKey]) -> Option<PublicKey> {
    for pk in pubkeys.iter().skip(1) {
        if pk != &pubkeys[0] {
            return Some(*pk);
        }
    }
    None
}

/// Performs BIP-327 key aggregation on a list of compressed public keys.
pub fn key_agg(pubkeys: &[PublicKey]) -> Result<PublicKey, secp256k1::Error> {
    let secp = Secp256k1::verification_only();

    let second_key = get_second_key(pubkeys);
    let keys_hash = hash_keys(pubkeys);

    let mut tweaked_keys: Vec<PublicKey> = Vec::with_capacity(pubkeys.len());
    for pk in pubkeys {
        if Some(*pk) == second_key {
            // coefficient is 1 for the second unique key
            tweaked_keys.push(*pk);
        } else {
            let mut coeff_input = keys_hash.to_vec();
            coeff_input.extend_from_slice(&pk.serialize());
            let coeff_bytes = tagged_hash("KeyAgg coefficient", &coeff_input);
            // fails with negligible probability, if the hash happens to be >= the curve order
            let scalar =
                Scalar::from_be_bytes(coeff_bytes).map_err(|_| secp256k1::Error::InvalidTweak)?;
            tweaked_keys.push(pk.mul_tweak(&secp, &scalar)?);
        }
    }

    let refs: Vec<&PublicKey> = tweaked_keys.iter().collect();
    PublicKey::combine_keys(&refs)
}

/// BIP-328 chain code used for the synthetic xpub produced by musig key aggregation.
const BIP_328_CHAINCODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// Replaces all `musig(key1,key2,...)` expressions in a descriptor string with the
/// corresponding BIP-327 aggregate xpub. This allows the descriptor to be parsed by
/// rust-miniscript, which does not natively support musig() at this time.
/// NOTE: this does not work with nested musig() expressions, which are not supported anyway.
pub(crate) fn replace_musigs(desc: &str) -> Result<String, String> {
    let mut desc = desc.to_string();
    loop {
        let musig_start = match desc.find("musig(") {
            Some(pos) => pos,
            None => break,
        };
        let musig_end = match desc[musig_start..].find(')') {
            Some(pos) => musig_start + pos,
            None => return Err("Invalid descriptor: unmatched musig(".to_string()),
        };

        let keys_str = &desc[musig_start + 6..musig_end];
        let key_strs: Vec<&str> = keys_str.split(',').collect();

        let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(key_strs.len());
        let mut network: Option<NetworkKind> = None;

        for key_str in &key_strs {
            let key_str = key_str.trim();
            // Strip origin info [fingerprint/path]
            let xpub_str = if let Some(bracket_end) = key_str.find(']') {
                &key_str[bracket_end + 1..]
            } else {
                key_str
            };
            let xpub = Xpub::from_str(xpub_str)
                .map_err(|e| format!("Failed to parse xpub '{}': {}", xpub_str, e))?;
            match network {
                None => network = Some(xpub.network),
                Some(n) if n != xpub.network => {
                    return Err("Invalid descriptor: musig() keys have mixed networks".to_string())
                }
                _ => {}
            }
            pubkeys.push(xpub.public_key);
        }
        let network = network.unwrap_or(NetworkKind::Main);

        if pubkeys.len() < 2 {
            return Err("musig() must contain at least 2 keys".to_string());
        }

        // Sort pubkeys before aggregation (as specified by BIP-327/BIP-328)
        pubkeys.sort();

        let aggregate_pubkey =
            key_agg(&pubkeys).map_err(|e| format!("Key aggregation failed: {}", e))?;

        let synthetic_xpub = Xpub {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            chain_code: ChainCode::from(BIP_328_CHAINCODE),
            public_key: aggregate_pubkey,
        };

        desc = format!(
            "{}{}{}",
            &desc[..musig_start],
            synthetic_xpub,
            &desc[musig_end + 1..]
        );
    }
    Ok(desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_musigs() {
        // (input, expected_output) — None means the result should be an error
        let cases: &[(&str, Option<&str>)] = &[
            // No musig: descriptor is returned unchanged
            (
                "wpkh(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/<0;1>/*)",
                Some("wpkh(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/<0;1>/*)"),
            ),
            // musig() with origin-prefixed keys
            (
                "tr(musig([76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF,[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK)/<0;1>/*)",
                Some("tr(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBaQqFP72F6Sdr6LkYSK7RSHasFxRSq6Vfa4Cn1g47oASGeLixXb/<0;1>/*)"),
            ),
            // musig() without origin info produces the same aggregate
            (
                "tr(musig(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF,tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK)/<0;1>/*)",
                Some("tr(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBaQqFP72F6Sdr6LkYSK7RSHasFxRSq6Vfa4Cn1g47oASGeLixXb/<0;1>/*)"),
            ),
            // Two musig() expressions in the same descriptor
            (
                "tr(musig(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF,tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK)/<0;1>/*,pk(musig(tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm,tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN)/<0;1>/*))",
                Some("tr(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBaQqFP72F6Sdr6LkYSK7RSHasFxRSq6Vfa4Cn1g47oASGeLixXb/<0;1>/*,pk(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBYxU9s7tLUd3f8yJNQQoJti5S2SnZCtiyXkbqRLWwD6DbA1kmyX/<0;1>/*))"),
            ),
            // Empty musig(): error
            (
                "tr(musig()/<0;1>/*)",
                None,
            ),
            // Unmatched parenthesis: error
            (
                "tr(musig(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                None,
            ),
            // musig() with only one key: error
            (
                "tr(musig(tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF)/<0;1>/*)",
                None,
            ),
            // Mixed mainnet/testnet keys: error
            (
                "tr(musig(xpub6ERApfzeWPeNZbNJ3FKMT8SZNJncpBBBbdcuWkMpJeFfFBPDcKHgZ7hiKthVEEPqRHJFZ1vnJtGqmjJnx2z4f5mRezvGJ7mP1DqxbNkk7pE,tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK)/<0;1>/*)",
                None,
            ),
        ];

        for (input, expected) in cases {
            let result = replace_musigs(input);
            match expected {
                Some(expected_str) => {
                    assert_eq!(result.unwrap(), *expected_str, "input: {}", input)
                }
                None => assert!(result.is_err(), "expected error for input: {}", input),
            }
        }
    }
}
