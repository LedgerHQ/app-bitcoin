# MuSig2

The Ledger Bitcoin app supports wallet policies with `musig()` key expressions.

MuSig2 is a 2-round multi-signature scheme compatible with the public keys and signatures used in taproot transactions. The implementation is compliant with [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).

## Specs

`musig()` key expressions are supported for all taproot policies, including taproot keypaths and miniscript.

- At most 5 keys are allowed in the musig expression; performance limitations, however, might apply in practice.
- `musig(...)` is allowed among the key expressions of `multi_a`, but not of `sortedmulti_a`.
- At most 8 parallel MuSig signing sessions are supported, due to the need to persist state in the device's memory.
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
- Compute each *(secnonce, pubnonce)* as per the `NonceGen` algorithm.
- At completion (after all the pubnonces are returned), the session secret $rand\_{root}$ is copied into the persistent memory.

**Phase 2: partial signature generation:** A PSBT containing all the pubnonces is sent to the device.
- *A copy of the session is stored in the volatile memory, and the session is deleted from the persistent memory*.
- For each input/musig-key pair $(i, j)$:
  - Recompute the pubnonce/secnonce pair using `NonceGen` with the synthetic randomness $rand_{i,j}$ as above.
  - Verify that the pubnonce contained in the PSBT matches the one synthetically recomputed.
  - Continue the signing flow as per BIP-0327, generating the partial signature.

### Security considerations
#### State reuse avoidance
Storing the session in persistent memory only at the end of Phase 1, and deleting it before beginning Phase 2 simplifies auditing and making sure that there is no reuse of state across signing sessions.

#### Security of synthetic randomness

Generating $rand_{i, j}$ synthetically is not a problem, since the $rand\_{root}$ value is kept secret and never leaves the device. This ensures that all the values produced for different $i$ and $j$ are not predictable for an attacker.

#### Malleability of the PSBT
If the optional parameters are passed to the _NonceGen_ function, they will depend on the transaction data present in the PSBT. Therefore, there is no guarantee that they will be unchanged the next time the PSBT is provided.

However, that does not constitute a security risk, as those parameters are only used as additional sources of entropy in _NonceGen_. A malicious software wallet can't affect the _secnonce_/_pubnonce_ pairs in any predictable way. Changing any of the parameters used in _NonceGen_ would cause a failure during Phase 2, as the recomputed _pubnonce_ would not match the one in the psbt.

### Generalization to multiple PSBT signing sessions

The approach described above assumes that no attempt to sign a PSBT for a wallet policy containing `musig()` keys is initiated while a session is already in progress.

In order to generalize this to an arbitrary number of parallel signing sessions, one can identify each signing session with a `psbt_session_id`. Such `psbt_session_id` should deterministically depend on the transaction being signed (ignoring all the other PSBT fields), and the wallet policy being signed. In praticular, the computed `psbt_session_id` should be identical between Round 1 and Round 2 of the protocol. Note that malicious collisions of the `psbt_session_id` (for example by tampering with some details of the PSBT, like the SIGHASH flags) _are_ possible, but they do not constitute a security risk.
