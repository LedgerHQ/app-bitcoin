# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [2.X.X] - XX-XX-2026

### Added

- Stateful, SDK-native fuzzing framework (Absolution-based) with semantic continuation host for `SIGN_PSBT` (developer tooling).
- Support for [BIP-0322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) generic signed messages: a PSBT carrying the `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` global field (0x09) is now verified to have the exact BIP-322 *to_sign* structure and reviewed on-screen as a message signature (account, address and message), instead of being shown as a transaction with an `OP_RETURN` output and no fees. Proof-of-funds requests (additional inputs spending real coins of the account) are supported, with the total proven amount shown in the review. Works with any supported wallet policy, including multisig and miniscript.

## [2.5.0] - 24-07-2026

### Changed

- Improved the registration UX for multisig and many taproot miniscript wallet policies by showing the *clear-text, human-readable* meaning of the policy. For simple multisig policies, the clear-text description replaces the descriptor template. For a large class of supported taproot miniscript policies, it is shown *in addition to*, and *before*, the raw descriptor template. This lets the user understand the policy while still being able to compare the template against their backup.
- Signing transactions using non-standard sighash flags now requires enabling the corresponding persistent application setting.
- Improved the signing display for transactions using non-default sighash flags: the effective signing rule is shown, and the trusted screen now only presents amounts that the signatures actually commit to, falling back to the net amount spent/received (or a warning when nothing can be shown reliably) instead of a potentially misleading breakdown.
- Improved the signing display for transactions with external inputs: in addition to the existing warning and external outputs, the trusted screen now shows the total amount of the external inputs when it can be reliably determined, and the net amount spent from or received into the account.
- Standard BIP-87 xpubs can now be exported without explicit user confirmation.
- Enabled stack protector.

## [2.4.6] - 30-03-2026

### Changed

- Small updates for on-screen wording.

### Fixed

- Disable registering miniscript wallet policies containing `older(n)` fragments where `n` has no consensus meaning.
- Various bug fixes and code modernizations; adopted lib_standard_app from the SDK.

## [2.4.5] - 10-02-2026

### Changed

- For `bitcoin_recovery`
    - `HAVE_APPLICATION_FLAG_DERIVE_MASTER` enabled so fully non-hardened paths can be used
    -  A warning dispalyed on home screen

### Fixed

- Getting xpub at purpose level (for permitted paths)
- Bug causing signing failures if the client sends data in small chunks

## [2.4.4] - 15-12-2025

### Changed

- Derivation Path Hardening - 2 more allowed paths added:
    - Electrum one
    - BIP-45 tree

## [2.4.3] - 25-11-2025

### Changed

- Alignment to the UI guidelines:
    - Standard graphics API use instead of streaming one for:
        - `SIGN_PSBT` operation with up to 16 external outputs
        - `SIGN_MESSAGE` operation with message split handled by graphics library and Line Feed allowed
    - Security risk information is shown before transaction review and made interruptable, no "suspicious" path warning for `GET_EXTENDED_PUBKEY` operation
    - Ticker moved to the right for swap operations, other minor UI updates
- Derivation Path Hardening:
    - New master key fingerprint syscall use, `HAVE_APPLICATION_FLAG_DERIVE_MASTER` is removed
    - BIP-32 derivation paths is reinforced using wildcard syntax (`m/*/<COIN_TYPE>`)

## [2.4.2] - 08-09-2025

### Added

- Apex P porting

## [2.4.1] - 03-07-2025

### Added

### Changed

- UX rehaul, especially on Nano X and Nano S Plus devices.

### Fixed

- Signing failure for certain PSBTs with wallet policies containing both `musig()` and script paths.

## [2.4.0] - 07-03-2025

### Added

- Support for `musig()` key expressions in taproot wallet policies.

### Changed

- For wallet policies with multiple internal spending paths, the app will only sign for key expressions for which the corresponding `PSBT_IN_BIP32_DERIVATION` or `PSBT_IN_TAP_BIP32_DERIVATION` is present in the PSBT. This improves performance when signing for certain spending paths is not desired.
- Increased the maximum supported number of cosigners in a wallet policy to 15.
- Some common errors now return an [error code](src/error_codes.h) in addition to the usual status word.

## [2.3.0] - 26-08-2024

### Added

- Support for crosschain swap protocol.

### Changed

- Improvements in signing performance, especially for large transactions.

### Fixed

- `signMessage` would fail since version 2.2.2 for certain message lengths.

## [2.2.4] - 09-07-2024

### Changed

- Major revamp of the UI for transaction signing and wallet policy registration on Stax. Changed "wallet policy" with the simpler wording "account".
- Slight performance improvements in the signing flow.
- Added a technical limit of at most 10 distinct cosigners in a wallet policy.

### Fixed

- OP_RETURN outputs with a `0x00` data push were incorrectly rejected.

## [2.2.3] - 06-05-2024

### Added

- Support for signing transactions with `OP_RETURN` outputs extended to up to 5 push opcodes, instead of a single one.

## [2.2.2] - 08-04-2024

### Added

- During wallet policy registration, the app will recognize and explicitly label as `dummy` any extended public key whose compressed pubkey is `0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`. This is useful especially for taproot miniscript policies which do not intend to use keypath spending.

### Changed

- Message signing: will now show the full text of the message, instead of its hash. If the message is too long (over 640 characters) or it contains non-printable characters (not in the range `0x20..0x70`, inclusive), then the SHA256 hash will be shown, as in previous versions of the app.
- Transaction signing: changed the wording to make the ux slightly simpler and clearer.

## [2.2.1] - 18-03-2024

### Fixed

- Signing failure for certain taproot policies in versions 2.1.2, 2.1.3 and 2.2.0: returned tapleaf hashes (and corresponding signatures) are incorrect if the descriptor template has a derivation path not ending for `/**` or `/<0;1>/*` for that key.

## [2.2.0] - 29-01-2024

### Added

- 🥕 Support for miniscript on taproot wallet policies.
- Warning if the fees are above 10% of the amount, if the total amount is above 10000 sats (0.0001 ₿).

### Changed

- Increased limits for the maximum in-memory size of wallet policies.

## [2.1.3] - 21-06-2023

### Changed

- Improved UX for self-transfers, that is, transactions where all the outputs are change outputs.
- Outputs containing a single `OP_RETURN` (without any data push) can now be signed in order to support [BIP-0322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) implementations.


### Fixed

- Wrong address generation for miniscript policies containing an unusual `thresh(1,X)` fragment (that is, with threshold 1, and a single condition). This should not happen in practice, as the policy is redundant for just `X`. Client libraries have been updated to detect and prevent usage of these policies.
- Resolved a slight regression in signing performance introduced in v2.1.2.

## [2.1.2] - 03-04-2023

### Added

- 🥕 Initial support for taproot scripts; taproot trees support up to 8 leaves, and the only supported scripts in tapleaves are `pk`, `multi_a` and `sortedmulti_a`.

### Fixed

- Miniscript policies containing an `a:` fragment returned an incorrect address in versions `2.1.0` and `2.1.1` of the app. The **upgrade is strongly recommended** for users of miniscript wallets.
- The app will now reject showing or returning an address for a wallet policy if the `address_index` is larger than or equal to `2147483648`; previous version would return an address for a hardened derivation, which is undesirable.
- Nested segwit transactions (P2SH-P2WPKH and P2SH-P2WSH) can now be signed (with a warning) if the PSBT contains the witness-utxo but no non-witness-utxo. This aligns their behavior to other types of Segwitv0 transactions since version 2.0.6.

## [2.1.1] - 23-01-2023

### Changed

- Allow silent xpub exports at the `m/45'/coin_type'/account'` derivation paths.
- Allow silent xpub exports for any unhardened child of an allowed path.
- Allow up to 8 derivation steps for BIP-32 paths (instead of 6).

## [2.1.0] - 16-11-2022

### Added

- Miniscript support on SegWit.
- Improved support for wallet policies.
- Support for sighash flags.

### Changed

- Wallet policies now allow external keys with no key origin information.
- Wallet policies now allow multiple internal keys.

### Removed

- Support for legacy protocol (pre-2.0.0 version) and support for altcoins, now done via separate apps. Substantial binary size reduction as a consequence.

## [2.0.6] - 06-06-2022

### Added

- Support signing of segwit V0 transactions with unverified inputs for compatibility with software unable to provide the previous transaction.

### Fixed

- Fixed bug preventing signing transactions with external inputs (or with mixed script types).

## [2.0.5] - 03-05-2022

### Changed

- Technical release; restore compatibility with some client libraries that rely on deprecated legacy behavior.

## [2.0.4] - 28-03-2022

### Added

- Support for OP_RETURN outputs.
- Full support for app-exchange swaps.
- JS/TypeScript client library.

### Changed

- Increased max number of inputs during signing from 64 to 512; removed limit on the number of outputs.
- Various performance improvements.

### Fixed

- Fixed bug preventing signing segwit inputs in the presence of legacy inputs.

## [2.0.3] - 19-02-2022

### Fixed

Fix bug in visualization of large transaction amounts.

## [2.0.2] - 19-01-2022

### Added

Native support for Bitcoin Message Signing.

## [2.0.1] - 17-11-2021

### Changed

Thecnical release for Nano S Firmware v2.1.0. Small reduction in app size.

## [2.0.0] - 10-11-2021

### Added

First public release. 🎉
