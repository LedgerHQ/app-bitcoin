# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [1.0.0] - Unreleased

The package is now a binding of the [Rust client](https://github.com/LedgerHQ/app-bitcoin/tree/develop/bitcoin_client_rs), which implements the protocol; the Python code only owns the transport. Its source moved to `bitcoin_client_rs/bindings/python`.

### Added

- Wheels for Python 3.9 and later (abi3); building from the source distribution requires a Rust toolchain.
- `UnsupportedAppVersionError`, raised by `createClient` for versions of the app before 2.1.0.
- `sign_psbt` accepts any object whose `serialize()` method returns the PSBT (binary or base64), and sends its fields exactly as serialized.

### Changed

- Addresses returned by `get_wallet_address` and `register_wallet` are verified with rust-miniscript instead of embit.
- `NewClient` is an alias of `Client`.

### Removed

- Support for the versions of the app before 2.1.0 (`LegacyClient`, and the vendored `btchip` library).
- The `PSBT`, transaction and key classes, and the vendored copy of embit. Use a PSBT library, like the ones of [HWI](https://github.com/bitcoin-core/HWI) or [embit](https://github.com/diybitcoinhardware/embit).

## [0.4.3] - 24-11-2026

### Added

- `PSBT.musig2_session_id`: support for the proprietary global field with identifier `MUSIG2_SESSION_ID` (subtype 0, no keydata), in both PSBT versions. It lets a software wallet run parallel MuSig2 signing sessions for the same wallet policy. This is supported from version 2.6.0 of the Ledger Bitcoin app.

### Fixed

- Stricter PSBT parsing in `sign_psbt` and `PSBT.deserialize`: reject duplicate keys, truncated maps, missing map separators, trailing data after the PSBT maps, and PSBTv2-only fields in a PSBTv0. Previously, such malformed PSBTs could be silently accepted.
- `PSBT.convert_to_v2()` clears the required time/height locktimes of the inputs when converting from a PSBTv0: the locktime of a PSBTv0 is defined by its unsigned transaction.


## [0.4.2] - 29-09-2026

### Added

- `PSBT.generic_signed_message`: support for the `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` global field (0x09) of [BIP-0322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki), in both PSBT versions.

### Fixed

- Improve support of PsbtV2 fields and V0-to-V2 conversion.

## [0.4.1] - 16-04-2026

### Added

- Support for `INS_GET_MASTER_FINGERPRINT` (for legacy app)

## [0.4.0] - 06-03-2025

### Added

- Support for MuSig2.

## [0.3.0] - 15-02-2024

### Changed

- Removed external dependencies by using a local clone of [embit](https://github.com/diybitcoinhardware/embit) to perform the address checks introduced in version 0.2.2.

## [0.2.2] - 26-06-2023

### Added

- The client library now independently computes the expected address for `get_wallet_address` using the wallet policy, raising an error in case of mismatch. Similarly, `register_wallet` computes and checks the first receive address.

## [0.2.1] - 18-04-2023

### Changed
- Avoid using miniscript policies containing an `a:` fragment on versions below `2.1.2` of the bitcoin app.

## [0.2.0] - 3-04-2023

This release introduces a breaking change in the return type of the `sign_psbt`method.

### Added
- Added new `PartialSignature` data class together with support for taproot script signing, which is supported in version `2.1.2` of the bitcoin app.

## [0.1.2] - 09-01-2023

### Fixed
- Added missing dependency.

## [0.1.1] - 26-10-2022

### Changed

- Improved interface of TransportClient for better interoperability with HID.
- `sign_psbt` now accepts the psbt to be passed as `bytes` or `str`.

## [0.1.0] - 18-10-2022

### Changed

Upgraded library to version 2.1.0 of the app.

## [0.0.3] - 25-04-2022

### Changed

Imported upstream changes to auxiliary classes from bitcoin-core/HWI.

### Fixed

Solved incorrect handling of signature responses for transactions with more than 252 inputs.

## [0.0.2] - 09-02-2022

### Added

Support for Bitcoin Message Signing, for Ledger Nano app 2.0.2.

## [0.0.1] - 02-12-2021

### Added

First public release. 🎉
