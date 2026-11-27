
This page describes the wallet policies used in the _deprecated_ version 0 of the protocol, as implemented in the v2.0.0 of the Bitcoin app. This protocol is still supported at this time, but we encourage integrations to switch to the [wallet policies in version 1 of the protocol](../wallet.md).

# Wallet policy

A _wallet descriptor template_ follows the same language as output descriptor, except that each `KEY` expression is replaced with the `@` character followed by non-negative  decimal number (starting with `0`). Each of them is a placeholder for the key information that is kept in a separate vector.
A *wallet policy* is the pair of the _wallet descriptor template_ and the vector of key information; some additional metadata is associated, as described below.

Each key information is an expression similar to the `KEY` expressions of output descriptors, except that
- only serialized extended public keys ("xpubs") are supported;
- key origin information is compulsory
- it is followed by a `/**` prefix implying the last two steps of derivation (change and address index). A formalized description follows below.

## Reference

A wallet descriptor template is a `SCRIPT` expression, described as follows:

`SCRIPT` expressions:
-   `sh(SCRIPT)` (top level only): P2SH embed the argument.
-   `wsh(SCRIPT)` (top level or inside `sh` only): P2WSH embed the argument.
-   `pkh(KP)` (not inside `tr`): P2PKH output for the given public key (use `addr` if you only know the pubkey hash).
-   `wpkh(KP)` (top level or inside `sh` only): P2WPKH output for the given compressed pubkey.
-   `multi(k,KP_1,KP_2,...,KP_n)`: k-of-n multisig script.
-   `sortedmulti(k,KP_1,KP_2,...,KP_n)`: k-of-n multisig script with keys sorted lexicographically in the resulting script.

Key placeholder `KP` expressions consist of
- a single character `@`
- followed by a non-negative decimal number, with no leading zeros (except for `@0`).

The placeholder `@i` for some number *i* represents the *i*-th key in the vector of key origin information (which must be of size at least *i* + 1, or the wallet is invalid.

Each element of the *key origin information* list is a `KEY` expression.
`KEY` expressions:

-   Key origin information, consisting of:
    -   An open bracket `[`
    -   Exactly 8 hex characters for the fingerprint of the master key from which this key is derived from (see [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for details)
    -   Followed by zero or more `/NUM'` path elements to indicate hardened derivation steps between the fingerprint and the xpub that follows
    -   A closing bracket `]`
-   Followed by the actual key, which is a serialized extended public key (`xpub`) (as defined in [BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)).
-   Followed by the string `/**`

Note that this format is much more restricted (by design) than the format used in output descriptors. In particular, the key origin information is compulsory.

The `/**` in the descriptor template represents all the possible paths used in the wallet.

## Descriptor derivation

From a descriptor template (and the associated vector of keys), one can therefore obtain the descriptor for receive and change addresses by:

- replacing each key placeholder with the corresponding key / key origin, and then
-  replacing `/**` with either `/0/*` (receive addresses descriptor) or `/1/*` (change addresses descriptor).

For example, the wallet descriptor `pkh(@0)` with key information `["[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/**"]` produces the following two descriptors:

- Receive descriptor: `pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)`
- Change descriptor: `pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)`

# Policy registration and usage
The app supports a number of features related to wallet policies. In order to securely sign transactions with a policy wallet (for example in a multisignature), it is necessary to be able to:

- register a wallet, validating all the information (policy and keys involved) with the user on the trusted screen;
- show the addresses for a registered wallet on the trusted screen;
- sign spends from the wallet.

Since the application is stateless, wallet registration is not persisted on device. In order to make it possible to use a registered wallet in future requests, the device returns a hmac-sha256 (32 bytes long) for the wallet upon a successful registration. The client side is responsible for persisting the wallet policy *and* the returned hmac-sha256, and to provide this information in future requests.

As the symmetric key used for hmac-sha256 is deterministically derived from the hardware wallet seed (using [SLIP-0021](https://github.com/satoshilabs/slips/blob/master/slip-0021.md)), the completed wallet registration is non-revokable.

## Wallet policy serialization

A registered wallet policy comprises the following:
- The wallet name, up to 16 bytes long; the name is shown to the user on-screen in order to identify the wallet.
- The wallet descriptor template as a string.
- The list of keys.

The wallet policy is serialized as the concatenation of:

- `1 byte`: a byte equal to `0x01`, reserved for future use
- `1 byte`: the length of the wallet name (0 for standard wallet)
- `<variable length>`:  the wallet name (empty for standard wallets)
- `<variable length>`: the length of the wallet descriptor template, encoded as a Bitcoin-style variable-length integer
- `<variable length>`: the wallet descriptor template, as an ascii string (no terminating 0)
- `<variable length>`: the number of keys in the list of keys, encoded as a Bitcoin-style variable-length integer
- `<32 bytes>`: the root of the canonical Merkle tree of the list of keys.

See [merkle](../merkle.md) for information on Merkle trees.

The sha256 hash of a serialized wallet policy is used as a *wallet policy id*.

## Wallet name

The wallet name must be recognizable from the user when shown on-screen. Currently, the following limitations apply during wallet registration:
- The wallet name must be between 1 and 16 characters long.
- Each character must be an ASCII character with code at least 32 = 0x20 (the 'space' character) and at most 125 = 0x7e (the '~' character).
- The first and the last character must _not_ be spaces.

The hardware wallet will reject registration for wallet names not respecting the above constraints.

## Supported policies

As a precaution, at this time only a limited set of commonly used policies can be registered. More will be added in the future, to support new use cases.

The following policy types are currently supported:

- `sh(multi(...))` and `sh(sortedmulti(...))` (legacy multisignature wallets);
- `sh(wsh(multi(...)))` and `sh(wsh(sortedmulti(...)))` (wrapped-segwit multisignature wallets);
- `wsh(multi(...))` and `wsh(sortedmulti(...))` (native segwit multisignature wallets).

## Other technical limitations

At this time, there are some technical limitations on the accepted wallet policies:
- `multi` and `sortedmulti` support at most 5 keys;

These limitations will likely be removed in the future.

# Default wallets
A few policies that correspond to standardized single-key wallets can be used without requiring any registration; in the serialization, the wallet name must be a zero-length string. Those are the following policies:

- ``pkh(@0)`` - legacy addresses as per [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- ``wpkh(@0)`` - native segwit addresses per [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- ``sh(wpkh(@0))`` - nested segwit addresses as per [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- ``tr(@0)`` - single Key P2TR as per [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)

Note that the wallet policy is considered standard (and therefore usable for signing without prior registration) only if the signing paths (defined in the key origin information) adheres to the corresponding BIP.
