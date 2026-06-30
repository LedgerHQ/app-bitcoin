# Ledger Bitcoin application client

## Overview

TypeScript client for Ledger Bitcoin application. Supports versions 2.1.0 and above of the app.

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

```bash
$ npm install
$ npm run build
```

## Getting started

The following example showcases all the main methods of the `Client`'s interface.

More examples can be found in the [test suite](src/__tests__/appClient.test.ts).

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

    // result will be a list of triples [i, partialSig], where:
    // - i is the input index
    // - partialSig is an instance of PartialSignature; it contains a pubkey and a signature,
    //   and it might contain a tapleaf_hash.
    const result = await app.signPsbt(psbt, signingPolicy, signingPolicyHmac);

    console.log("Returned signatures:");
    console.log(result);

    await transport.close();
}

Transport.default.create()
    .then(main)
    .catch(console.log);
```
