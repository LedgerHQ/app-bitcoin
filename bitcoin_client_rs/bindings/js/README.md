# Ledger Bitcoin application client

## Overview

TypeScript client for Ledger Bitcoin application. Supports versions 2.1.0 and above of the app.

Since version 1.0.0, this package is a binding of the [Rust client](https://github.com/LedgerHQ/app-bitcoin/tree/develop/bitcoin_client_rs), compiled to WebAssembly, which is the reference implementation of the protocol: the package itself only owns the transport.

It works in Node.js (CommonJS, version 18.14 or later) and with bundlers that support WebAssembly ES modules (for example webpack 5 with `experiments.asyncWebAssembly`, or Vite with `vite-plugin-wasm`). As before, the API uses `Buffer`, which must be polyfilled in browsers.

Main repository and documentation: https://github.com/LedgerHQ/app-bitcoin

## Install

```bash
$ yarn add @ledgerhq/ledger-bitcoin
```

Or if you prefer using npm:

```bash
$ npm install @ledgerhq/ledger-bitcoin
```

## Building

Building requires a Rust toolchain with the `wasm32-unknown-unknown` target, and the [wasm-bindgen CLI](https://rustwasm.github.io/docs/wasm-bindgen/reference/cli.html) with the same version as the `wasm-bindgen` crate in `Cargo.toml`:

```bash
$ rustup target add wasm32-unknown-unknown
$ cargo install wasm-bindgen-cli --version 0.2.105
$ npm install
$ npm run build
```

`npm run test:replay` runs the tests that replay recorded device transcripts; `npm test` also runs the tests against the app in the [Speculos](https://github.com/LedgerHQ/speculos) emulator (set `SPECULOS` to the path of `speculos.py`; the app must be built in `bin/app.elf` at the root of the repository).

## Getting started

The following example showcases all the main methods of the `Client`'s interface.

More examples can be found in the [test suite](ts/__tests__/appClient.test.ts).

Testing the `signPsbt` method requires a valid PSBT, and provide the corresponding wallet policy; it is skipped by default in the following example.

```javascript
import { AppClient, DefaultWalletPolicy, WalletPolicy } from '@ledgerhq/ledger-bitcoin';
import Transport from '@ledgerhq/hw-transport-node-hid';

// This examples assumes the Bitcoin Testnet app is running.
// Make sure to use addresses compatible with mainnet otherwise, by using paths where the BIP-44 coin_type
// is "0'" and not "1'".

async function main(transport) {
    const app = new AppClient(transport);

    // ==> Get the master key fingerprint
    const fpr = await app.getMasterFingerprint();
    console.log("Master key fingerprint:", fpr.toString("hex"));

    // ==> Get and display on screen the first taproot address
    const firstTaprootAccountPubkey = await app.getExtendedPubkey("m/86'/1'/0'");
    const firstTaprootAccountPolicy = new DefaultWalletPolicy(
        "tr(@0/**)",
        `[${fpr}/86'/1'/0']${firstTaprootAccountPubkey}`
    );

    const firstTaprootAccountAddress = await app.getWalletAddress(
        firstTaprootAccountPolicy,
        null,
        0,
        0,
        true // show address on the wallet's screen
    );

    console.log("First taproot account receive address:", firstTaprootAccountAddress);

    // ==> Register a multisig wallet named "Cold storage"

    const ourPubkey = await app.getExtendedPubkey("m/48'/1'/0'/2'");
    const ourKeyInfo = `[${fpr}/48'/1'/0'/2']${ourPubkey}`;
    const otherKeyInfo = "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF";

    const multisigPolicy = new WalletPolicy(
        "Cold storage",
        "wsh(sortedmulti(2,@0/**,@1/**))", // a 2-of-2 multisig policy template
        [
            otherKeyInfo, // some other bitcoiner
            ourKeyInfo,   // that's us
        ]
    )

    const [policyId, policyHmac] = await app.registerWallet(multisigPolicy);

    console.log(`Policy hmac: ${policyHmac.toString("hex")}. Store it safely (together with the policy).`);

    console.assert(policyId.compare(multisigPolicy.getId()) == 0)  //  should never fail

    // ==> Derive and show an address for "Cold storage" that was just registered

    const multisigAddress = await app.getWalletAddress(multisigPolicy, policyHmac, 0, 0, true);
    console.log(`Multisig wallet address: ${multisigAddress}`);

    // ==> Sign a psbt

    // TODO: set a wallet policy and a valid psbt file in order to test psbt signing
    const psbt = null; // a base64-encoded psbt, or a binary psbt in a Buffer
    const signingPolicy = null; // an instance of WalletPolicy
    const signingPolicyHmac = null; // if not a default wallet policy, this must also be set
    if (!psbt || !signingPolicy) {
        console.log("Nothing to sign :(");
        await transport.close();
        return;
    }

    // result will be a list of pairs [i, yielded], where:
    // - i is the input index
    // - yielded is an instance of PartialSignature, which contains a pubkey and a signature,
    //   and might contain a tapleafHash; for MuSig2 inputs, it is a MusigPubNonce or a
    //   MusigPartialSignature instead.
    const result = await app.signPsbt(psbt, signingPolicy, signingPolicyHmac);

    console.log("Returned signatures:");
    console.log(result);

    await transport.close();
}

Transport.default.create()
    .then(main)
    .catch(console.log);
```

## Upgrading from 0.x

- `signPsbt` returns `[number, SignPsbtYieldedObject][]`: besides `PartialSignature`, it can return the `MusigPubNonce` and `MusigPartialSignature` objects of MuSig2 signing sessions (and `UnknownSignPsbtYieldedObject` for objects introduced by future versions of the app). Narrow the type (for example with `instanceof PartialSignature`) before accessing the fields of a signature.
- The `PsbtV2` class was removed. `signPsbt` takes a PSBT of version 0 or 2 as a base64 string, as a `Buffer`/`Uint8Array`, or as an object with a `toBuffer()` method (like the `Psbt` class of bitcoinjs-lib) or a `serialize()` method. Its fields are sent to the device exactly as serialized.
- The addresses returned by `getWalletAddress` and `registerWallet` are verified with [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) instead of `@bitcoinerlab/descriptors`; this no longer requires an extra `getAppAndVersion` request. A mismatch throws an error whose message starts with `Invalid address`.
- Errors raised by the client itself (as opposed to the transport, which still throws a `TransportStatusError` for any status word other than success) are `Error`s with a `code` property: `InvalidArgument`, `InvalidResponse` or `InvalidState`.
