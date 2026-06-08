# Features and capabilities

This document gives a high-level overview of what the Ledger Bitcoin app can do. It is
aimed at technical users and developers who want to understand the app's features, or
build an integration on top of one of the existing client libraries, without needing the
details of the wire protocol.

If you are implementing a client library from scratch, or need the exact byte-level
encoding of each command, refer instead to [bitcoin.md](bitcoin.md).

## Overview

The Bitcoin app is a **stateless signer** that runs on a Ledger device. It never holds wallet
state between commands. The host application drives it through one of the client libraries, and
every sensitive operation (revealing a public key, registering a wallet, showing an address,
signing a transaction or a message) is confirmed by the user on the device's **trusted screen**.

Because the device is stateless, the host (typically, a software wallet) is always the source of
wallet and transaction information.

The concepts behind this model — wallet policies, registration, and on-device
verification — are described in [integration.md](integration.md).

## Supported operations

Each operation maps to a method in the client libraries
([Python](../bitcoin_client), [JavaScript](../bitcoin_client_js),
[Rust](../bitcoin_client_rs)); see their READMEs for ready-to-run code examples.

| Operation | What it does |
|-----------|--------------|
| Get master key fingerprint | Returns the 4-byte fingerprint of the master key, used in key origin information. |
| Get extended public key | Returns the `xpub` at a given BIP-32 path, optionally displaying it on-screen for verification. |
| Register a wallet policy | Has the user approve a wallet policy on the trusted screen and returns an HMAC that authorizes future use of that policy. |
| Get / verify a wallet address | Derives an address for a registered or default wallet, optionally displaying it on-screen so the user can verify it. |
| Sign a transaction | Signs a PSBT and returns the partial signatures it can produce. |
| Sign a message | Signs an arbitrary message using the Bitcoin signed-message format, at a given BIP-32 path. |

## Supported account and script types

The app describes accounts using **wallet policies** (see
[integration.md](integration.md) and [wallet.md](wallet.md)). The script types below are
supported.

### Single-key standard accounts

These four single-key account types follow widely adopted BIPs and can be used **without
registration** (see *default wallets* in [integration.md](integration.md)):

| Policy template | Address type | Standard |
|-----------------|--------------|----------|
| `pkh(@0/**)` | Legacy | [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) |
| `sh(wpkh(@0/**))` | Nested SegWit | [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) |
| `wpkh(@0/**)` | Native SegWit | [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) |
| `tr(@0/**)` | Taproot | [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) |

### Multisig

- Native SegWit: `wsh(multi(...))` and `wsh(sortedmulti(...))`.
- Legacy and wrapped SegWit: `sh(multi(...))`, `sh(sortedmulti(...))`,
  `sh(wsh(multi(...)))`, `sh(wsh(sortedmulti(...)))`.
- Taproot: `tr(KP, multi_a(...))` / `tr(KP, sortedmulti_a(...))` as a script path.

`sortedmulti` variants sort the keys lexicographically in the resulting script, so the
order of the keys in the policy does not affect the addresses.

### Taproot

The app supports `tr(...)` outputs with both **keypath** and **script-path** spends, and
arbitrary trees of script leaves.

### Miniscript

[Miniscript](https://github.com/bitcoin/bips/blob/master/bip-0379.md) is supported inside top-level
`wsh(...)` and inside taproot script leaves. It allows expressing richer spending conditions than
plain multisig — for example timelocks, recovery/backup keys, or threshold policies that
change over time. See [integration.md](integration.md) for an example.

### MuSig2

Taproot policies may use `musig()` key expressions to aggregate several keys into a
single on-chain key, following [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
The signing-flow details are covered in [musig.md](musig.md).

## Networks

The app is built per network: the mainnet build is named **Bitcoin**, and the testnet
build is named **Bitcoin Test**. They are ***separate applications***.

The **Bitcoin Test** app can be used for all test networks, including Bitcoin Core's regtest.
Note, however, that SegWit (and taproot) addresses are shown on-screen and returned to the
host using the human readable part `tb1`, while bitcoin-core uses `bcrt`.

## Version and feature compatibility

This documentation describes the current (v2) protocol. Some features might not be available
in older versions of the app. Consult the [CHANGELOG.md](../CHANGELOG.md) to check when a
specific capability became available.

## Where to go next

- **Build something** → the client library READMEs
  ([Python](../bitcoin_client), [JavaScript](../bitcoin_client_js),
  [Rust](../bitcoin_client_rs)) contain runnable examples.
- **Understand the model** → [integration.md](integration.md) explains wallet policies,
  registration, and the security model.
- **Wallet policy language** → [wallet.md](wallet.md) and
  [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki).
- **Wire protocol** → [bitcoin.md](bitcoin.md).
