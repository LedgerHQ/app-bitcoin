# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [1.0.0] - Unreleased

The package is now a binding of the [Rust client](https://github.com/LedgerHQ/app-bitcoin/tree/develop/bitcoin_client_rs), compiled to WebAssembly, which implements the protocol; the TypeScript code only owns the transport. Its source moved to `bitcoin_client_rs/bindings/js`.

### Added

- `signPsbt` returns the MuSig2 objects of the app (`MusigPubNonce`, `MusigPartialSignature`), and `UnknownSignPsbtYieldedObject` for objects added by future versions of the app.
- `signPsbt` accepts an object with a `toBuffer()` method, like the `Psbt` class of bitcoinjs-lib, or with a `serialize()` method; the PSBT's fields are sent exactly as serialized.
- An ES module build, for bundlers that support WebAssembly.

### Changed

- `signPsbt` returns `[number, SignPsbtYieldedObject][]`.
- Addresses returned by `getWalletAddress` and `registerWallet` are verified with rust-miniscript instead of `@bitcoinerlab/descriptors`, without an extra `getAppAndVersion` request.
- Errors raised by the client (rather than by the transport) have a `code` property.

### Removed

- The `PsbtV2` class, and the dependencies on bitcoinjs-lib, `@bitcoinerlab/descriptors`, `@bitcoinerlab/secp256k1` and bip32-path.
