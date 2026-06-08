# Integration concepts and security model

This document explains the concepts an integrator needs in order to build on top of the
Ledger Bitcoin app using one of the existing client libraries
([Python](../bitcoin_client), [JavaScript](../bitcoin_client_js),
[Rust](../bitcoin_client_rs)). It complements the feature overview in
[features.md](features.md) and the protocol-level specifications in
[bitcoin.md](bitcoin.md) and [wallet.md](wallet.md).

## The device is stateless

The app does **not** persist any wallet-related or transaction-related information between
calls. There is no notion of "the wallet currently loaded on the device": every request that
involves an account (deriving an address, signing a transaction) must carry the full
description of that account, supplied by the host.

This means the **host application is responsible for storing** the account definitions
(and, for registered wallets, the authorization HMAC described below) and providing them
on each call. The host is *not* trusted, however: it merely supplies the information the
device needs. Anything that matters for security is verified by the user on the device's
trusted screen (see [On-device verification](#on-device-verification-and-the-trusted-screen)
below), so a compromised host cannot make the device sign or display something the user
did not approve.

## Wallet policies

An account is described by a **wallet policy**, which is the standard defined in
[BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki). A wallet
policy has two parts:

1. A **descriptor template** — an output descriptor in which each key is replaced by a
   key placeholder `@0`, `@1`, … The placeholder is followed by `/**` (a shorthand for
   the receive/change derivation `/<0;1>/*`).
2. A **key information vector** — the actual keys (`xpub`s), each optionally preceded by
   its **key origin information**: the master key fingerprint and the derivation steps
   used to reach that `xpub`, e.g. `[f5acc2fd/48'/1'/0'/2']xpub6E...`.

Separating the template from the keys lets the device recognize the *shape* of a policy
independently of the specific keys, and lets `sortedmulti`-style policies be order
independent.

For the exact grammar, the app's serialization, and implementation-specific
restrictions, see [wallet.md](wallet.md).

### Examples

A single-key taproot account (a *default wallet*, see below — no registration needed):

```
tr(@0/**)
keys: ["[f5acc2fd/86'/0'/0']xpub6C..."]
```

A 2-of-3 native SegWit multisig (must be registered before use):

```
wsh(sortedmulti(2,@0/**,@1/**,@2/**))
keys: [
  "[f5acc2fd/48'/0'/0'/2']xpub6E...",   // this device
  "[1a2b3c4d/48'/0'/0'/2']xpub6E...",   // cosigner 2
  "[5e6f7a8b/48'/0'/0'/2']xpub6E..."    // cosigner 3
]
```

A miniscript "recovery vault" — spendable by the primary key at any time, or by a backup
key after a relative timelock of `65535` blocks:

```
wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(65535))))
keys: [
  "[f5acc2fd/48'/0'/0'/2']xpub6E...",   // primary key
  "[1a2b3c4d/48'/0'/0'/2']xpub6E..."    // recovery key
]
```

## Default vs registered wallets

- **Default (standard) wallet accounts** are the four single-key account types listed in
  [features.md](features.md) (`pkh`, `sh(wpkh)`, `wpkh`, `tr`), with the corresponding
  standard derivation paths. They can be used for address derivation and signing **without registration**. In the serialization, a default wallet has an empty name.
- **Any other policy** (multisig, miniscript, taproot trees, MuSig2, or even a standard
  single-key account using a non-standard path) must be **registered** before it can be
  used.

This guarantees the following security property (except on default accounts):
- **Strong Account Segregation**: address verification and transaction signing will always
  inform the user about the involved account.

This is particularly important for accounts involving multiple parties (multisig,
miniscript, etc).

## Registration and the HMAC

Registration is the step where the user reviews a non-standard policy — its name, the
script template, and every key — on the trusted screen and approves it once. This protects
the user from a compromised host silently substituting a malicious policy.

Because the device is stateless, it does not store the approved policy. Instead, a
successful registration returns a **32-byte HMAC-SHA256** that authorizes that exact
policy. The host wallet **must persist exactly** the wallet policy (descriptor template
and keys information), its name and the returned HMAC, and supply them together on every
later call related to the same account (address derivation, signing).

The HMAC key is deterministically derived from the device seed
([SLIP-0021](https://github.com/satoshilabs/slips/blob/master/slip-0021.md)), so the same
wallet policy (and name) always yields the same HMAC on the same seed.
A consequence is that registration is **non-revocable**: there is no on-device list to delete
an entry from. See [wallet.md](wallet.md) for the serialization and the *wallet policy id*.

## On-device verification and the trusted screen

The device's security guarantee rests on the **trusted screen**: anything the user
approves there cannot be forged by a compromised host, because the host has no control
over what the device displays.

In practice:

- When showing a **receive address** to a user, an integration should derive it with the
  display option enabled so the user verifies, on the device, that the address belongs to
  their wallet — a compromised host cannot then swap in an attacker's address. It is also
  possible to display a **change address**, if desired.
- The same applies to **public keys / xpubs**: displaying them on-device lets the user
  confirm them out of band.
- During **signing**, the device shows the amounts, destinations, and (for registered
  policies) the wallet account involved. The user is approving what the device displays,
  not what the host claims. For the user's convenience, *change addresses* are *not* displayed when signing a transaction. The device verifies that they indeed belong to the same account the transaction is spending from.

The client libraries expose this as a `display` (or equivalent) flag on the relevant
methods.

## Transaction signing model

To sign, the host builds a [PSBT](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
and passes it to the app together with the wallet policy and, for registered wallet accounts, the
HMAC. The app verifies that it can sign, has the user approve the transaction on the trusted
screen, and returns the **partial signatures** it is able to produce, keyed by input index.

**Only inputs whose corresponding BIP-32 derivations are present in the PSBT are signed**; if the
wallet policy has multiple spending paths involving the device for a given input, more than one
signature may be returned for that input.

The host is responsible for placing the returned signatures into the PSBT, **finalizing** it,
**extracting** the signed transaction and (possibly) broadcasting it to the network.

### Transactions with Wallet Policies using MuSig2

For policies that use `musig()` key expressions, signing is a two-round protocol: the first round
produces the *public nonces* (pubnonces), while the second round produces the MuSig2 Partial
Signatures. More details are described in [musig.md](musig.md).

The app uses the presence of pubnonces in the PSBT to determine which MuSig2 round should be
performed:
- if no pubnonces are present in the PSBT, the app executes MuSig2 Round 1, producing and returning
  the public nonces;
- if the PSBT contains pubnonces, the app executes the MuSig2 Round 2, and (on success) produces
  and returns the MuSig2 Partial Signatures.

If the app is only participating in MuSig2 Round 1 and not producing any signature, then user
confirmation on the trusted screen is not required. With careful coordination from the software
wallet, this can be used in many cases to provide a seamless MuSig2 signing experience, without
increasing the user's UX burden.

However, user confirmation is required if, for the same PSBT, the device is able to produce a
signature (for any spending path), including a MuSig2 Partial Signature (as produced by MuSig2
Round 2).

It is recommended to *never rely on the signing behavior for PSBTs that contain some pubnonces*,
but not all: signing is likely to fail in this case, and exact behavior might change in future
releases.
