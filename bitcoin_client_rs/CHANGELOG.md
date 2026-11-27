# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [0.8.0] - XX-XX-XXXX

This release exposes the protocol without the transport, for applications that own the device I/O.

### Changed

- The synchronous client, the `error` module and the `BitcoinClient` and `Transport` re-exports are behind the new `client` feature. In 0.7, `default-features = false` still exposed them; add `features = ["client"]` to keep them, or `features = ["async"]` for both clients. The default features are unchanged in practice: `client`, `async` and `paranoid_client`.
- `BitcoinClientError`, `InterpreterError` and `WalletError` are `#[non_exhaustive]`, and so is the `BitcoinClientError::UnexpectedResult` variant.
- `apdu::Cla`, `BitcoinCommandCode`, `FrameworkCommandCode` and `ClientCommandCode` are `#[non_exhaustive]`, as the app and its client commands can gain new codes.
- The minimum supported Rust version is 1.78, declared as `rust-version` in Cargo.toml. The README claimed 1.60, which the dependencies no longer support.
- An unknown Merkle root in the GET_MERKLE_LEAF_PROOF and GET_MERKLE_LEAF_INDEX client commands is reported as `InterpreterError::UnknownMerkleRoot` instead of `UnknownHash`.
- Client commands with unexpected trailing bytes (GET_MERKLE_LEAF_INDEX, GET_MORE_ELEMENTS) are rejected with `InterpreterError::UnsupportedRequest`, like the other client commands.
- A GET_PREIMAGE client command is rejected with `InterpreterError::UnexpectedQueue` while elements of a previous answer are still queued, as GET_MERKLE_LEAF_PROOF already was.
- `PartialSignatureError` has a new variant, `InvalidInputIndex`, and is `#[non_exhaustive]`.
- `SignPsbtYieldedObject::Unknown` is a non-exhaustive struct variant with the object's `tag`, and the `data` that follows the input index. It previously had only the data, so the tag was lost.
- Responses are parsed strictly: fixed-length responses (master fingerprint, wallet registration) must have exactly the expected length, GET_VERSION must not have trailing bytes, and the extended pubkey and address must be valid UTF-8. The Bitcoin app always sends such responses; anything else is now an `UnexpectedResult` error.
- `PsbtV2Error` is `#[non_exhaustive]`.
- `StatusWord` is a newtype over the raw status word, so that statuses without a name are no longer lost. Build it with `StatusWord::from(u16)` instead of `TryFrom`, and read it with `u16::from` or `.0` instead of `as u16`. The named statuses are associated constants with the same names as the former variants (so `StatusWord::Deny` still works, in patterns too), plus `DeviceLocked` (0x5515), `SecurityStatusNotSatisfied` (0x6982), `SwapFail` (0x6B00) and `WrongResponseLength` (0xB000).
- `BitcoinClientError::Device` contains the response data, which is the app's 2-byte error code when it reports one; the variant is `#[non_exhaustive]`.
- When a value yielded during `sign_psbt` cannot be parsed, the `UnexpectedResult` error contains that value. Previously, if any value had at most one byte, it contained all the yielded values concatenated.
- `PsbtV2Error` no longer implements `Copy`, as its new `DuplicateKey` variant contains the key.

### Removed

- `StatusWord::Unknown`: a status without a name keeps its value in a `StatusWord`.

### Added

- The `command`, `interpreter` and `protocol` modules are public, and can be used without either client. `protocol` includes `parse_sign_psbt_yielded` and the tags of the objects yielded by SIGN_PSBT.
- `BitcoinClientError`, `InterpreterError` and `WalletError` implement `Display` and `std::error::Error`. `ClientCommandInterpreter` implements `Default` and `Debug`, and `InterpreterError` implements `Clone`, `PartialEq` and `Eq`.
- `PartialSignatureError` implements `Debug`.
- `protocol::parse_*`: parsers for the responses to the commands, with a detailed `ResponseError`. The values yielded by SIGN_PSBT have their own parsers.
- `protocol::Request`, and a `protocol::prepare_*` function for each command, returning the command to send together with the state needed to answer the client commands of the device. `ClientCommandInterpreter::for_wallet` builds that state for a wallet policy.
- `PsbtV2Error` implements `Display` and `std::error::Error`, and `PsbtV2Maps` implements `Debug`. `APDUCommand` implements `Debug`, `PartialEq` and `Eq`.
- `protocol::Request::step`: handles each response of the device, answering its client commands, and returns a `protocol::Step`: the next command to send, or the response data once the request is done. Errors are reported as `protocol::RequestError`, for which `BitcoinClientError` implements `From`. A `Request` is single-use.
- `StatusWord::name` returns the name of a known status. `StatusWord` implements `Display` (the value, and the name if known) and `Hash`, and its `Debug` shows the name, or `StatusWord(0x…)` for other values.
- `protocol::parse_sign_psbt_results`: parses all the values yielded during SIGN_PSBT, with a `SignPsbtResultsError`.
- `PartialSignatureError` implements `Display` and `std::error::Error`.
- `WalletPolicy::check_address`, with the `paranoid_client` feature (which does not require either client): derives an address of the wallet policy independently, to verify the one returned by the device. Errors are reported as `wallet::AddressCheckError`, for which `BitcoinClientError` implements `From`.
- `psbt::apply_partial_signature`: adds an ECDSA or Schnorr signature yielded by `sign_psbt` to a PSBT, with an `ApplySignatureError`. A key-path signature is only added if the input's `witness_utxo` is a P2TR output with the signature's key as output key.

### Fixed

- PSBTv2-only fields in a PSBTv0 are rejected when converting it for `sign_psbt`, as they would acquire meaning after the conversion.
- Signing an empty message, or a PSBT without inputs or outputs, panicked while building the Merkle tree of an empty list.
- A GET_MERKLE_LEAF_INDEX client command for a leaf that is not in a known tree is answered as not found, instead of failing.
- `WalletPolicy::get_descriptor` looped forever on a descriptor template with an unterminated `/<`, and panicked on one with a `>` before a `/<`. The former is now a `WalletError::InvalidPolicy` error, and the latter is expanded like any other template.
- Input indices yielded by `sign_psbt` must fit in a `u32`; larger well-encoded indices are rejected with `PartialSignatureError::InvalidInputIndex`, instead of being truncated on 32-bit targets and accepted on 64-bit ones. Malformed CompactSize encodings still return `InvalidLength`.
- A PSBT with a duplicate key in one of its maps is rejected: `prepare_sign_psbt` returns `PsbtV2Error::DuplicateKey`, and the clients' `sign_psbt` returns `InvalidPsbt`. rust-bitcoin serializes such a PSBT when an `unknown` field has the key of a field that it knows. The device rejected it with an unclear error, except for a duplicate of the unsigned transaction's key, which was silently ignored.
- An empty response to SIGN_MESSAGE caused a panic; it is now an `UnexpectedResult` error.
- `get_version` accepts the dashboard's response, which has no flags.
