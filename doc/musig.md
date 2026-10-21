# MuSig2

The Ledger Bitcoin app supports wallet policies with `musig()` key expressions.

MuSig2 is a 2-round multi-signature scheme compatible with the public keys and signatures used in taproot transactions. The implementation is compliant with [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

## Specs

`musig()` key expressions are supported for all taproot policies, including taproot keypaths and miniscript.

- At most 5 keys are allowed in the musig expression; performance limitations, however, might apply in practice.
- `musig(...)` is allowed among the key expressions of `multi_a`, but not of `sortedmulti_a`.
- At most 8 MuSig2 signing sessions can be pending at the same time, due to the need to persist state in the device's memory; when the storage is full, starting a new session evicts the oldest one.
- By default, at most one session can be pending for each wallet policy. Software wallets that need multiple transactions in flight for the same wallet policy can identify each session with the [`MUSIG2_SESSION_ID`](#the-musig2_session_id-psbt-field) PSBT field (see [below](#generalization-to-multiple-psbt-signing-sessions)).
- The pubnonces can be generated before the transaction is known, and then used for a different transaction than the one given to the device in round 1 (see [below](#pre-generating-the-pubnonces)).
- Only `musig(...)/**` or `musig(...)/<M;N>/*` key expressions are supported; the public keys must be xpubs aggregated without any further derivation. Schemes where each pubkey is derived prior to aggregation (for example descriptors similar to `musig(xpub1/<0;1>/*,xpub2/<0;1>/*,...)`) are not supported.

## State minimization

This section describes implementation details that allow to minimize the amount of statefor each MuSig2 signing session, allowing secure support for multiple parallel MuSig2 on embedded device with limited storage.

### Introduction

BIP-0327 discusses at length the necessity to keep some state during a signing session. However, a "signing session" in BIP-0327 only refers to the production of a single signature.

In the typical signing flow of a wallet, it's more logical to consider a _session_ at the level of an entire transaction. All transaction inputs are likely obtained from the same [descriptor containing musig()](https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki), with the signer producing the pubnonce/signature for all the inputs at once.

Therefore, in the flow of BIP-0327, you would expect at least _one MuSig2 signing session per input_ to be active at the same time. In the context of hardware signing device support, that's somewhat problematic: it would require to persist state for an unbounded number of signing sessions, for example for a wallet that received a large number of small UTXOs. Persistent storage is often a scarce resource in embedded signing devices, and a naive approach would likely impose a maximum limit on the number of inputs of the transactions, depending on the hardware limitations.

This document describes an approach that is compatible with and builds on top of BIP-0327 to define a _psbt-level session_ with only a small amount of state persisted on the device. Each psbt-level session allows to manage in parallel all the MuSig2 sessions involved in signing a transaction (typically, at least one for each input). Each psbt-level session only requires 64 bytes of storage for the entire transaction, regardless of the amount of inputs.

### Signing flow with synthetic randomness

#### Synthetic generation of BIP-0327 state

This section presents the core idea, while the next section makes it more precise in the context of signing devices.

In BIP-0327, the internal state that is kept by the signing device is essentially the *secnonce*, which in turn is computed from a random number _rand'_, and optionally from other parameters of _NonceGen_ which depend on the transaction being signed.

The core idea for state minimization is to compute a global random `rand_root`; then, for the *i*-th input and for the *j*-th `musig()`  key that the device is signing for in the [wallet policy](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki), one defines the *rand'* in _NonceGen_ as:

$\qquad rand_{i,j} = SHA256(rand\_{root} \| i \| j)$

In the concatenation, a fixed-length encoding of $i$ and $j$ is used in order to avoid collisions. That is used as the *rand'* value in the *NonceGen* algorithm for that input/KEY pair.

The *j* parameter allows to handle wallet policies that contain more than one `musig()` key expression involving the signing device.

The other arguments of *NonceGen* are chosen so that they do not depend on the transaction, nor on the UTXO being spent:
- *pk* is the public key of the signing device in the `musig()` key expression;
- *aggpk* is the aggregate public key of the `musig()` key expression _before_ any tweak, that is, before the BIP-32 derivation steps and the BIP-0341 taptweak that depend on the UTXO;
- *msg* and *extra_in* are omitted.

Therefore, each *(secnonce, pubnonce)* pair only depends on `rand_root`, on $i$ and $j$, and on the wallet policy.

#### Signing flow in detail

This section describes the handling of the psbt-level sessions, plugging on top of the default signing flow of BIP-0327.

We assume that the signing device handles a single psbt-level session; this can be generalized to multiple parallel psbt-level sessions, where each session computes and stores a different `rand_root`.

In the following, a _session_ always refers to the psbt-level signing session; it contains `rand_root`, and possibly any other auxiliary data that the device wishes to save while signing is in progress.

The term *persistent memory* refers to secure storage that is not wiped out when the device is turned off. The term *volatile memory* refers to the working memory available while the device is involved in the signing process. In Ledger signing devices, the persistent storage is flash memory, and the volatile memory is the RAM of the app. Both are contained in the Secure Element.

**Phase 1: pubnonce generation:** A PSBT is sent to the signing device, and it does not contain any pubnonce.
- If a session already exists, it is deleted from the persistent memory.
- A new session is created in volatile memory.
- The device produces a fresh random number $rand\_{root}$, and saves it in the current session.
- The device generates the randomness for the $i$-th input and for the $j$-th key as: $rand_{i,j} = SHA256(rand\_{root} \| i \| j)$.
- Compute each *(secnonce, pubnonce)* as per the `NonceGen` algorithm, with the arguments described above.
- At completion (after all the pubnonces are returned), the session secret $rand\_{root}$ is copied into the persistent memory.

**Phase 2: partial signature generation:** A PSBT containing all the pubnonces is sent to the device.
- *A copy of the session is stored in the volatile memory, and the session is deleted from the persistent memory*.
- For each input/musig-key pair $(i, j)$:
  - Recompute the pubnonce/secnonce pair using `NonceGen` with the synthetic randomness $rand_{i,j}$ and the other arguments as above.
  - Verify that the pubnonce contained in the PSBT matches the one synthetically recomputed.
  - Continue the signing flow as per BIP-0327, generating the partial signature.

### Security considerations
#### State reuse avoidance
Storing the session in persistent memory only at the end of Phase 1, and deleting it before beginning Phase 2 simplifies auditing and making sure that there is no reuse of state across signing sessions.

#### Security of synthetic randomness

Generating $rand_{i, j}$ synthetically is not a problem, since the $rand\_{root}$ value is kept secret and never leaves the device. This ensures that all the values produced for different $i$ and $j$ are not predictable for an attacker.

#### Optional arguments of NonceGen
In BIP-0327, *aggpk*, *msg* and *extra_in* are optional arguments of _NonceGen_. They only add entropy, as a defense in depth against a faulty source of randomness. They are not needed for the uniqueness of the nonces, which comes from $rand\_{root}$ being generated by the hardware RNG, and from the $(i, j)$ domain separation in $rand_{i,j}$.

BIP-0327 suggests using the tweaked aggregate key as *aggpk*. Using the untweaked one instead is what makes the pubnonces independent of the transaction, and of the (change, address index) of the UTXO being spent. Since none of the arguments depend on the PSBT, a malicious software wallet can't affect the _secnonce_/_pubnonce_ pairs in any way. A PSBT whose pubnonces were not produced by the current session makes Phase 2 fail, as the recomputed _pubnonce_ does not match the one in the PSBT.

### Generalization to multiple PSBT signing sessions

The approach described above assumes that no attempt to sign a PSBT for a wallet policy containing `musig()` keys is initiated while a session is already in progress.

In order to generalize this to multiple parallel signing sessions, each signing session is identified by a `psbt_session_id`, which must be identical between Round 1 and Round 2 of the protocol. The device computes it as:

$\qquad psbt\_session\_id = H_{PsbtSessionId}(descriptor\_template\_hash \| keys\_info\_merkle\_root \| len(session\_id) \| session\_id)$

where $H_{tag}$ is the BIP-0340 tagged hash, the first two arguments are the hash of the descriptor template and the root of the Merkle tree of the keys information of the wallet policy, $session\_id$ is the value of the [`MUSIG2_SESSION_ID`](#the-musig2_session_id-psbt-field) field (empty if the PSBT does not contain the field), and $len(session\_id)$ is its length as a single byte (`0x00` if the field is absent). The name of the wallet policy is not committed to, as it plays no role in signing.

The `psbt_session_id` deliberately depends only on the wallet policy and on the `MUSIG2_SESSION_ID`, and not on the transaction; together with the transaction-independent arguments of _NonceGen_, this is what allows [pre-generating the pubnonces](#pre-generating-the-pubnonces). The tradeoff is that, without a `MUSIG2_SESSION_ID`, at most one session can be pending for each wallet policy.

The device can store up to 8 sessions.

Collisions of the `psbt_session_id` do not constitute a security risk: they only cause the previous session to be deleted, and the following Phase 2 to fail.

### The `MUSIG2_SESSION_ID` PSBT field

`MUSIG2_SESSION_ID` is an optional global PSBT field that lets a software wallet keep multiple MuSig2 signing sessions in flight for the same wallet policy. It is a [BIP-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) proprietary field.

| Key | Value |
|-----|-------|
| `0xFC` &#124; `0x11` &#124; `"MUSIG2_SESSION_ID"` &#124; `0x00` (proprietary type, identifier length, identifier, subtype 0; no keydata) | The session id: between 1 and 32 bytes |

- The field is optional. If it is absent, the behavior is the same as in the versions of the app that do not support it: wallets that do not need multiple sessions for the same wallet policy can ignore it.
- The `psbt_session_id` commits to its value, so that sessions with different values are independent. The value must be the same in Phase 1 and Phase 2; otherwise, the device does not find the session in Phase 2.
- Executing Phase 1 again with the same value replaces the pending session for that value.
- A present but empty value, or a value longer than 32 bytes, is rejected (error code `EC_SIGN_PSBT_INVALID_MUSIG2_SESSION_ID`).
- Wallets should use a unique value for each session. The value is not secret.
- The value is only meaningful to the device that receives the PSBT, and it is not part of the transaction: each signer's software wallet sets it, in its own copy of the PSBT, to the value it used in its own Phase 1. Different signers do not need to agree on a value, and the value does not need to be shared with the other signers.

### Pre-generating the pubnonces

Since neither the pubnonces nor the `psbt_session_id` depend on the transaction, a software wallet can execute Phase 1 before the transaction is known, for example while the device happens to be connected. It can then use the pubnonces returned by the device for a different transaction, provided that:
- the transaction is for the same wallet policy and has the same `MUSIG2_SESSION_ID` (or none), no other Phase 1 or Phase 2 for that wallet policy and `MUSIG2_SESSION_ID` was executed in the meantime, and the session was not evicted because the storage was full (see [above](#specs));
- all inputs are internal, and the PSBT used in Phase 1 has at least as many inputs as the PSBT used in Phase 2, and each pubnonce is put in the Phase 2 PSBT under the key (of the `PSBT_IN_MUSIG2_PUB_NONCE` field) computed for the new transaction. This key contains the aggregate public key _after_ the tweaks, and, for script path spends, the tapleaf hash; therefore, it depends on the transaction, not merely on the input's position.

More generally, this can also work when some inputs are not internal, as long as for each internal input of the PSBT used in Phase 2, there is a corresponding internal input in the PSBT used in Phase 1.

Phase 1 does not require any user interaction, while Phase 2 requires the user to review the transaction. Therefore, with pubnonces generated in advance, signing a transaction only takes a single interaction per signer, like for a non-MuSig2 multisig.

If the wallet policy also contains keys of the device outside of `musig()` key expressions (for example, in `tr(musig(@0,@1)/**,pk(@2/**))`, where `@0` and `@2` are keys of the device), the device also signs for those keys, and therefore asks the user to review the transaction, whenever the PSBT contains their key derivations (`PSBT_IN_BIP32_DERIVATION` or `PSBT_IN_TAP_BIP32_DERIVATION`). The PSBT used to pre-generate the pubnonces should therefore only contain the key derivations of the `musig()` key expressions.
