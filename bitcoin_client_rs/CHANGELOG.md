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

### Added

- The `command`, `interpreter` and `protocol` modules are public, and can be used without either client. `protocol` includes `parse_sign_psbt_yielded` and the tags of the objects yielded by SIGN_PSBT.
- `BitcoinClientError`, `InterpreterError` and `WalletError` implement `Display` and `std::error::Error`. `ClientCommandInterpreter` implements `Default` and `Debug`, and `InterpreterError` implements `Clone`, `PartialEq` and `Eq`.

### Fixed

- PSBTv2-only fields in a PSBTv0 are rejected when converting it for `sign_psbt`, as they would acquire meaning after the conversion.
- Signing an empty message, or a PSBT without inputs or outputs, panicked while building the Merkle tree of an empty list.
- A GET_MERKLE_LEAF_INDEX client command for a leaf that is not in a known tree is answered as not found, instead of failing.
- `WalletPolicy::get_descriptor` looped forever on a descriptor template with an unterminated `/<`, and panicked on one with a `>` before a `/<`. The former is now a `WalletError::InvalidPolicy` error, and the latter is expanded like any other template.
