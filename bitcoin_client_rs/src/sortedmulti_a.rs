//! `sortedmulti_a()` support for the independent address verification of the paranoid client.
//!
//! rust-miniscript does not parse `sortedmulti_a(k,KEY_1,...,KEY_n)`, the taproot multisig with
//! sorted keys of BIP-388 wallet policies. At a given derivation index, it is equivalent to
//! `multi_a(k,...)` with the derived x-only keys in lexicographic order, which rust-miniscript
//! parses.

use core::str::FromStr;

use bitcoin::secp256k1::Secp256k1;
use miniscript::DescriptorPublicKey;

use crate::wallet::AddressCheckError;

const SORTEDMULTI_A: &str = "sortedmulti_a(";

/// Replaces each `sortedmulti_a(k,KEY_1,...,KEY_n)` in a descriptor with the equivalent
/// `multi_a(k,...)` at `address_index`: the keys derived at that index, as sorted x-only keys.
/// The keys must not contain multipath expressions.
pub(crate) fn replace_sortedmulti_a(
    desc: &str,
    address_index: u32,
) -> Result<String, AddressCheckError> {
    let secp = Secp256k1::verification_only();
    let mut desc = desc.to_string();
    while let Some(start) = desc.find(SORTEDMULTI_A) {
        let args_start = start + SORTEDMULTI_A.len();
        // key expressions contain no parentheses, so the first one closes sortedmulti_a()
        let end = desc[args_start..]
            .find(')')
            .map(|pos| args_start + pos)
            .ok_or(AddressCheckError::Descriptor)?;

        let mut args = desc[args_start..end].split(',');
        let threshold = args.next().unwrap_or_default().trim().to_string();
        let mut keys = args
            .map(|key| {
                let key = DescriptorPublicKey::from_str(key.trim())
                    .map_err(|_| AddressCheckError::Descriptor)?;
                let key = key
                    .at_derivation_index(address_index)
                    .map_err(|_| AddressCheckError::Derivation)?
                    .derive_public_key(&secp)
                    .map_err(|_| AddressCheckError::Derivation)?;
                Ok(key.inner.x_only_public_key().0)
            })
            .collect::<Result<Vec<_>, _>>()?;
        keys.sort_by_key(|key| key.serialize());

        let keys: Vec<String> = keys.iter().map(|key| key.to_string()).collect();
        desc = format!(
            "{}multi_a({},{}){}",
            &desc[..start],
            threshold,
            keys.join(","),
            &desc[end + 1..]
        );
    }
    Ok(desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_1: &str = "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/0/*";
    const KEY_2: &str = "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/0/*";

    #[test]
    fn keys_are_derived_and_sorted() {
        let derived = |key: &str, index| {
            DescriptorPublicKey::from_str(key)
                .unwrap()
                .at_derivation_index(index)
                .unwrap()
                .derive_public_key(&Secp256k1::verification_only())
                .unwrap()
                .inner
                .x_only_public_key()
                .0
        };
        for index in [0, 1, 7] {
            let mut keys = [derived(KEY_1, index), derived(KEY_2, index)];
            keys.sort_by_key(|key| key.serialize());
            let expected = format!("tr(pk({}),multi_a(2,{},{}))", KEY_1, keys[0], keys[1]);
            for (a, b) in [(KEY_1, KEY_2), (KEY_2, KEY_1)] {
                let desc = format!("tr(pk({}),sortedmulti_a(2,{},{}))", KEY_1, a, b);
                assert_eq!(replace_sortedmulti_a(&desc, index).unwrap(), expected);
            }
        }
    }

    #[test]
    fn other_descriptors_are_unchanged_and_errors_are_reported() {
        let desc = format!("tr({},multi_a(1,{}))", KEY_1, KEY_2);
        assert_eq!(replace_sortedmulti_a(&desc, 0).unwrap(), desc);
        assert_eq!(
            replace_sortedmulti_a("tr(sortedmulti_a(1,not_a_key))", 0),
            Err(AddressCheckError::Descriptor)
        );
        assert_eq!(
            replace_sortedmulti_a(&format!("tr(sortedmulti_a(1,{}", KEY_1), 0),
            Err(AddressCheckError::Descriptor)
        );
        assert_eq!(
            replace_sortedmulti_a(&format!("tr(sortedmulti_a(1,{}))", KEY_1), 1 << 31),
            Err(AddressCheckError::Derivation)
        );
    }
}
