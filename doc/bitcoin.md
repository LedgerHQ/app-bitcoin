# Bitcoin application: Technical Specifications

This page details the protocol implemented since version 2.1.0 of the app.

The protocol documentation for version from 2.0.0 and before 2.1.0 is [here](./v0/bitcoin.md) and is now deprecated.

## Framework

### APDUs

The messaging format of the app is compatible with the [APDU protocol](https://developers.ledger.com/docs/device-app/explanation/io#apdu-interpretation-loop). The `P1` field is reserved for future use and must be set to `0` in all messages. The `P2` field is used as a protocol version identifier; the current version is `1`, while version `0` is still supported. No other value must be used.

The main commands use `CLA = 0xE1`, unlike the legacy Bitcoin application that used `CLA = 0xE0`.

| CLA | INS | COMMAND NAME           | DESCRIPTION |
|-----|-----|------------------------|-------------|
|  E1 |  00 | GET_EXTENDED_PUBKEY    | Return (and optionally show on screen) extended pubkey |
|  E1 |  02 | REGISTER_WALLET        | Register a wallet policy on the device (with user's approval) |
|  E1 |  03 | GET_WALLET_ADDRESS     | Return and show on screen an address for a registered or default wallet |
|  E1 |  04 | SIGN_PSBT              | Sign a PSBT with a registered or default wallet |
|  E1 |  05 | GET_MASTER_FINGERPRINT | Return the fingerprint of the master public key |
|  E1 |  10 | SIGN_MESSAGE           | Sign a message with a key from a BIP32 path (Bitcoin Message Signing) |

The `CLA = 0xF8` is used for framework-specific (rather than app-specific) APDUs; at this time, only one command is present.

| CLA | INS | COMMAND NAME | DESCRIPTION |
|-----|-----|--------------|-------------|
|  F8 |  01 | CONTINUE     | Respond to an interruption and continue processing a command |

The `CONTINUE` command is sent as a response to a client command from the Hardware Wallet; the format and content on the response depends on the client command, and is documented below for each client command.

### Interactive commands

Several commands are executed via an interactive protocol that requires multiple rounds. At any time after receiving the command and before returning the commands final response (which is status word `0x9000` in case of success), the Hardware Wallet can respond with a special status word `SW_INTERRUPTED_EXECUTION` (`0xE000`), containing a request for the client in the response data. The first byte of the response is the *client command code*, identified what kind of request the Hardware Wallet is asking the client to perform. The client *must* comply with the request and send a special *CONTINUE* command `CLA = 0xF8` and `INS = 0x01`, with the appropriate response.

The specs for the client commands are detailed below.

## Descriptors and wallet policies

The Bitcoin app uses a language similar to [output script descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) in order to represent the wallets that can be used to sign transactions.
Wallet policies need to be registered on the device, with an interactive process that requires user's approval.

See [here](wallet.md) for detailed information on the wallet policy language.

## Wallet registration flow

In order to use a wallet policy that is not one of the default ones, the policy must first be registered on the wallet, which is a protocol that requires explicit approval from the user.

A wallet policy is initiated using the `REGISTER_WALLET` command. The screen of the hardware wallet will ask the user to inspect the wallet descriptor template, followed by each of the keys of the cosigners that are part of the wallet policy.

Once the user approves, the `REGISTER_WALLET` returns to the client a 32-byte HMAC-SHA256. This will be provided to any future command that makes use of the wallet policy; therefore, the HMAC should be permanently stored on the client. In case of loss of the HMAC, the registration flow must be repeated from scratch.

## Status Words

| SW     | SW name                      | Description |
|--------|------------------------------|-------------|
| 0x6985 | `SW_DENY`                    | Rejected by user |
| 0x6A86 | `SW_WRONG_P1P2`              | Either `P1` or `P2` is incorrect |
| 0x6A87 | `SW_WRONG_DATA_LENGTH`       | `Lc` or minimum APDU length is incorrect |
| 0x6D00 | `SW_INS_NOT_SUPPORTED`       | No command exists with `INS` |
| 0x6E00 | `SW_CLA_NOT_SUPPORTED`       | Bad `CLA` used for this application |
| 0xB000 | `SW_WRONG_RESPONSE_LENGTH`   | Wrong response length (buffer size problem) |
| 0xB007 | `SW_BAD_STATE`               | Aborted because unexpected state reached |
| 0xB008 | `SW_SIGNATURE_FAIL`          | Invalid signature or HMAC |
| 0xE000 | `SW_INTERRUPTED_EXECUTION`   | The command is interrupted, and requires the client's response |
| 0x9000 | `SW_OK`                      | Success |

<!-- TODO: add an introduction section explaining the command reference notations (e.g. the Bitcoin style varint) -->

## Commands

### GET_EXTENDED_PUBKEY

Returns an extended public key at the given derivation path, serialized as per BIP-32.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 00    |

**Input data**

| Length | Name              | Description |
|--------|-------------------|-------------|
| `1`    | `display`         | `0` or `1`  |
| `1`    | `n`               | Number of derivation steps (maximum 8) |
| `4`    | `bip32_path[0]`   | First derivation step (big endian) |
| `4`    | `bip32_path[1]`   | Second derivation step (big endian) |
|        | ...               |             |
| `4`    | `bip32_path[n-1]` | `n`-th derivation step (big endian) |

**Output data**

| Length | Description |
|--------|-------------|
| `<variable>` | The full serialized extended public key as per BIP-32 |

#### Description

This command returns the extended public key for the given BIP 32 path.

The paths defined in [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-48](https://github.com/bitcoin/bips/blob/master/bip-0048.mediawiki), [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki), [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki), [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) and [BIP-87](https://github.com/bitcoin/bips/blob/master/bip-0087.mediawiki), either in full or are at the deepest hardened level (excluding `change` and `address_index`), are considered standard.

If the `display` parameter is `0` and the path is not standard, an error is returned.

If the `display` parameter is `1`, the result is also shown on the secure screen for verification. The UX flow shows on the device screen the exact path and the complete serialized extended pubkey as defined in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for that path. If the path is not standard, an additional warning is shown to the user.

### REGISTER_WALLET

Registers a wallet policy on the device, after validating it with the user.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 02    |

**Input data**

| Length          | Name            | Description |
|-----------------|-----------------|-------------|
| `<variable>`    | `policy_length` | The length of the policy (unsigned varint) |
| `policy_length` | `policy`        | The serialized wallet policy |

The `policy` is serialized as described [here](wallet.md). At this time, no policy can be longer than 252 bytes, therefore the `policy_length` field is always encoded as 1 byte.

**Output data**

| Length | Description                |
|--------|----------------------------|
| `32`   | The `wallet_id`            |
| `32`   | The `hmac` for this wallet |

#### Description

This command allows to register a wallet policy on the device. The wallet's name, descriptor template and each of the keys information is shown to the user.

After user's validation is completed successfully, the application returns the `wallet_id` (sha256 of the wallet serialization), and the `hmac` for this wallet.

#### Client commands

`GET_PREIMAGE` must know and respond for the full serialized wallet policy whose sha256 hash is `wallet_id`; moreover, it must know and respond for the sha256 hash of its descriptor template.

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries related to the Merkle tree of the list of keys information.

The `GET_MORE_ELEMENTS` command must be handled.

### GET_WALLET_ADDRESS

Get a receive or change a address for a registered or default wallet, after validating it with the user using the trusted screen.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 03    |

**Input data**

| Length | Name            | Description |
|--------|-----------------|-------------|
| `1`    | `display`       | `0` or `1`  |
| `32`   | `wallet_id`     | The id of the wallet |
| `32`   | `wallet_hmac`   | The hmac of a registered wallet, or exactly 32 0 bytes |
| `1`    | `change`        | `0` for a receive address, `1` for a change address |
| `4`    | `address_index` | The desired address index (big-endian) |


**Output data**

| Length      | Description     |
|-------------|-----------------|
| <variable>  | The wallet address for the given change/address_index |

#### Description

For a registered wallet, the hmac must be correct. Once that is validated, this command computes the address of the wallet for the given `change` and `address_index` choice.

For a default wallet, `hmac` must be equal to 32 bytes `0`.

If the `display` parameter is `1`, the resulting wallet address is also shown on the secure screen, and only returns successfully after the user confirms it. If the `display` parameter is `0`, the result is silently returned.

#### Client commands

`GET_PREIMAGE` must know and respond for the full serialized wallet policy whose sha256 hash is `wallet_id`; moreover, it must know and respond for the sha256 hash of its descriptor template.

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries related to the Merkle tree of the list of keys information.

The `GET_MORE_ELEMENTS` command must be handled.

### SIGN_PSBT

Given a PSBTv2 and a registered wallet (or a standard one), sign all the inputs that are owned by that wallet.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 04    |

**Input data**

| Length  | Name                   | Description |
|---------|------------------------|-------------|
| `<var>` | `global_map_size`      | The number of key/value pairs of the global map of the psbt |
| `32`    | `global_map_keys_root` | The Merkle root of the keys of the global map |
| `32`    | `global_map_vals_root` | The Merkle root of the values of the global map |
| `<var>` | `n_inputs`             | The number of inputs of the psbt |
| `32`    | `inputs_maps_root`     | The Merkle root of the vector of Merkleized map commitments for the input maps |
| `<var>` | `n_outputs`            | The number of outputs of the psbt |
| `32`    | `outputs_maps_root`    | The Merkle root of the vector of Merkleized map commitments for the output maps |
| `32`    | `wallet_id`            | The id of the wallet |
| `32`    | `wallet_hmac`          | The hmac of a registered wallet, or exactly 32 0 bytes |

**Output data**

No output data; the signature are returned using the YIELD client command.

#### Description

Using the information in the PSBT and the wallet description, this command verifies what inputs are internal and what outputs match the pattern for a change address. After validating all the external outputs and the transaction fee with the user, it signs each of the internal inputs; each signature is sent to the client using the YIELD command, in the format described below. If multiple key placeholders of the wallet policy are internal, the process is repeated for each of them.

For a registered wallet, the hmac must be correct.

For a default wallet, `hmac` must be equal to 32 bytes `0`.

The data yielded begins with `<tag_or_input_index>`, represented as a bitcoin-style varint; the rest of the message depends on the value of `<tag_or_input_index>`, as specified in the following subsections.

##### If `<tag_or_input_index>` is at most 65535

If `<tag_or_input index>` is at most 65535, then it is an `<input_index>` and a partial_signature is being yielded.

The results yielded via the YIELD command respect the following format: `<input_index> <pubkey_augm_len> <pubkey_augm> <signature>`, where:
- `input_index` is a Bitcoin style varint, the index input of the input being signed (starting from 0);
- `pubkey_augm_len` is an unsigned byte equal to the length of `pubkey_augm`;
- `pubkey_augm` is the `pubkey` used for signing for legacy, segwit or taproot keypath spends (a compressed pubkey if non-taproot, a 32-byte x-only pubkey if taproot); for taproot script path spends, it is the concatenation of the `x-only` pubkey and the 32-byte *tapleaf hash* as defined in [BIP-0341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki);
- `signature` is the returned signature, possibly concatenated with the sighash byte (as it would be pushed on the stack).

##### If `<tag_or_input_index>` is more than 65535

In this case `<tag_or_input_index>` is a `<tag>` that specifies what the rest of the data contains.

- If `<tag>` equals `0xFFFFFFFF`: a pubnonce is being yielded during Round 1 of the MuSig2 protocol. The format is: `<tag> <input_index: varint)> <pubnonce: 66 bytes> <participant_pk: 33 bytes> <aggregate_pubkey: 33 bytes> <tapleaf_hash: 0 or 32 bytes>`.
- If `<tag>` equals `0xFFFFFFFE`: a partial signature is being yielded, completing Round 2 of the MuSig2 protocol. The format is: `<tag> <input_index: varint)> <partial_signature: 32 bytes> <participant_pk: 33 bytes> <aggregate_pubkey: 33 bytes> <tapleaf_hash: 0 or 32 bytes>`

In both cases, the `tapleaf_hash` is only present for a Script path spend.

Other values of the `<tag>` are undefined and reserved for future use.


#### Client commands

`GET_PREIMAGE` must know and respond for the full serialized wallet policy whose sha256 hash is `wallet_id`; moreover, it must know and respond for the sha256 hash of its descriptor template.

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries for all the Merkle trees in the input, including each of the Merkle trees for keys and values of the Merkleized map commitments of each of the inputs/outputs maps of the psbt.

The `GET_MORE_ELEMENTS` command must be handled.

The `YIELD` command must be processed in order to receive the signatures, or the MuSig2 partial nonces or partial signatures.

### GET_MASTER_FINGERPRINT

Returns the fingerprint of the master public key, as defined in [BIP-0032#Key identifiers](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 05    |

**Input data**

No input data.

**Output data**

| Length | Description                |
|--------|----------------------------|
| `4`    | The master key fingerprint |

#### Description

The fingerprint is necessary to fill the key origin information for some PSBT fields, or to create wallet descriptors.

User interaction is not required for this command.


### SIGN_MESSAGE

Signs a message, according to the standard Bitcoin Message Signing.

The device shows on its secure screen the BIP-32 path used for signing and the message information:
- either the content of the message (if its length does not exceed 640 bytes in current version and contains only ASCII printable characters (`0x20-0x7E` range) plus Line Feed (`0x0A`));
- or the SHA256 hash of the message (the hash should be verified by the user using an external tool if the client is untrusted).

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 10    |

**Input data**

| Length  | Name              | Description |
|---------|-------------------|-------------|
| `1`     | `n`               | Number of derivation steps (maximum 8) |
| `4`     | `bip32_path[0]`   | First derivation step (big endian) |
| `4`     | `bip32_path[1]`   | Second derivation step (big endian) |
|         | ...               |             |
| `4`     | `bip32_path[n-1]` | `n`-th derivation step (big endian) |
| `<var>` | `msg_length`      | The byte length of the message to sign (Bitcoin-style varint) |
| `32`    | `msg_merkle_root` | The Merkle root of the message, split in 64-byte chunks |

The message to be signed is split into `ceil(msg_length/64)` chunks of 64 bytes (except the last chunk that could be smaller); `msg_merkle_root` is the root of the Merkle tree of the corresponding list of chunks.

The theoretical maximum valid length of the message is 2<sup>32</sup>-1 = 4&nbsp;294&nbsp;967&nbsp;295 bytes.

**Output data**

| Length | Description |
|--------|-------------|
| `65`   | The returned signature, encoded in the standard Bitcoin message signing format |

The signature is returned as a 65-byte binary string (1 byte equal to 32 or 33, followed by `r` and `s`, each of them represented as a 32-byte big-endian integer).

#### Description

The digest being signed is the double-SHA256 of the message, after prefixing the message with:

- the magic string `"\x18Bitcoin Signed Message:\n"` (equal to `18426974636f696e205369676e6564204d6573736167653a0a` in hexadecimal)
- the length of the message, encoded as a Bitcoin-style variable length integer.

#### Client commands

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries for the Merkle tree of the list of chunks in the message.

## Client commands reference

This section documents the commands that the Hardware Wallet can request to the client when returning with a `SW_INTERRUPTED_EXECUTION` status word.

| CMD | COMMAND NAME          | DESCRIPTION |
|-----|-----------------------|-------------|
|  10 | YIELD                 | Receive some elements during command execution |
|  40 | GET_PREIMAGE          | Return the preimage corresponding to the given sha256 hash |
|  41 | GET_MERKLE_LEAF_PROOF | Returns the Merkle proof for a given leaf |
|  42 | GET_MERKLE_LEAF_INDEX | Returns the index of a leaf in a Merkle tree |
|  A0 | GET_MORE_ELEMENTS     | Receive more data that could not fit in the previous responses |

### YIELD

**Command code**: 0x10

The `YIELD` client command is sent to the client to communicate some result during the execution of a command. Currently only used during `SIGN_PSBT` in order to communicate each of the signatures. The format of the attached message is documented for each command that uses `YIELD`.

The client must respond with an empty message.

### GET_PREIMAGE

**Command code**: 0x40

The `GET_PREIMAGE` command requests the client to reveal a SHA-256 preimage.

The request contains:
- `1` byte: must equal 0, reserved for future usage. (The client should abort if non-zero);
- `32` bytes: a sha-256 hash.

The response must contain:
- `<var>`: the length of the preimage, encoded as a Bitcoin-style varint;
- `1` byte: a 1-byte unsigned integer `b`, the length of the prefix of the pre-image that is part of the response;
- `b` bytes: corresponding to the first `b` bytes of the preimage.

If the pre-image is too long to be contained in a single response, the client should choose `b` to be as large as possible; subsequent bytes are enqueued as single-byte elements that the Hardware Wallet will request with one or more `GET_MORE_ELEMENTS` requests.

### GET_MERKLE_LEAF_PROOF

**Command code**: 0x41

The `GET_MERKLE_LEAF_PROOF` command requests the hash of a given leaf of a Merkle tree, together with the Merkle proof.

The request contains:
- `32` bytes: the Merkle root hash;
- `<var>` bytes: the tree size `n`, encoded as a Bitcoin-style varint;
- `<var>` bytes: the leaf index `i`, encoded as a Bitcoin-style varint.

The client must respond with:
- `32` bytes: the hash of the leaf with index `i` in the requested Merkle tree;
- `1` byte: the length of the Merkle proof;
- `1` byte: the amount `p` of hashes of the proof that are contained in the response;
- `32 * p` bytes: the concatenation of the first `p` hashes in the Merkle proof.

If the proof is too long to be contained in a single response, the client should choose `p` to be as large as possible; subsequent bytes are enqueued as 32-byte elements that the Hardware Wallet will request with one or more `GET_MORE_ELEMENTS` requests.

### GET_MERKLE_LEAF_INDEX

**Command code**: 0x42

The `GET_MERKLE_LEAF_INDEX` requests the index of a leaf with a certain hash. if multiple leafs have the same hash, the client could respond with either.

The request contains:
- `32` bytes: the Merkle root hash;
- `32` bytes: the leaf hash.

The response contains:
- `1` byte: `1` if the leaf is found, `0` if matching leaf exists;
- `<var>`: the index of the leaf, encoded as a Bitcoin-style varint.

### GET_MORE_ELEMENTS

**Command code**: 0xA0

The `GET_MORE_ELEMENTS` command requests the client to return more elements that were enqueued by previous client commands (like `GET_PREIMAGE` and `GET_MERKLE_LEAF_PROOF`).

All of the elements in the queue must all be byte strings of the same length; the command fails otherwise. The client should return as many elements as it is possible to fit in the response, while leaving the remaining ones (if any) in the queue.

The request is empty.

The response contains:
- `1` byte: the number `n` of returned element;
- `1` byte: the size `s` of each returned element;
- `n * s` bytes: the concatenation of the `n` returned elements.


## Security considerations

Some of the client commands are used to allow the client to reveal some information that is not known to the hardware wallet. This approach allows to create protocols that work with an amount of data that is too large to fit in a single APDU, or even in the limited RAM of a device like a Ledger Nano S.

In designing the interactive protocol, care is taken to avoid security risks associated with a malicious, possibly compromised client.

All the current commands use a commit-and-reveal approach: the APDU that starts the protocol (first message) commits to all the relevant data (for example, the entirety of the PSBT), by using hashes and/or Merkle trees. Any time the client is asked to reveal some committed information, the app does not consider it trusted:
- If a preimage is asked via `GET_PREIMAGE`, the hash is computed to validate that the correct preimage is returned by the client.
- If a Merkle proof is asked via `GET_MERKLE_LEAF_PROOF`, the proof is verified.
- If the index of a leaf is asked `GET_MERKLE_LEAF_INDEX`, the proof for that element is requested via `GET_MERKLE_LEAF_PROOF` and the proof verified, *even if the leaf value is known*.

Care needs to be taken in designing protocols, as the client might lie by omission (for example, fail to reveal that a leaf of a Merkle tree is present during a call to `GET_MERKLE_LEAF_INDEX`).
