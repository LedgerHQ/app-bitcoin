# Wallet policies

The Ledger Bitcoin app describes every account using a **wallet policy**, the
representation standardized in
[BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki). A wallet policy
is a pair of:

- a **wallet descriptor template** — an output script descriptor in which each key is
  replaced by a key placeholder (`@0`, `@1`, …); and
- a **key information vector** — the actual keys (`xpub`s), each optionally preceded by its
  key origin information.

The key origin information is compulsory for xpubs controlled by the device. Without it, the xpub
will be considered external, and the device will not sign for any key derived by it.

Wallet policies are registered with a short readable *account name* provided by the host wallet, which is shown on-screen.

For a higher-level explanation of wallet policies, registration, and the security model,
see [integration.md](integration.md).

## Supported scripts

The following templates are supported as the **top-level** script:

- `pkh(KP)`, `wpkh(KP)`, `sh(wpkh(KP))` — single-key legacy, native SegWit, and nested
  SegWit;
- `sh(multi(...))`, `sh(sortedmulti(...))` — legacy multisig;
- `sh(wsh(multi(...)))`, `sh(wsh(sortedmulti(...)))` — wrapped-SegWit multisig;
- `wsh(SCRIPT)` — native SegWit;
- `tr(KP)` and `tr(KP, TREE)` — taproot, with an optional tree of script paths.

Within `wsh(...)`, `SCRIPT` can be `multi(...)`, `sortedmulti(...)`, or a valid SegWit
[miniscript](https://github.com/bitcoin/bips/blob/master/bip-0379.md) template.

Within a taproot `TREE`, each leaf script can be `multi_a(...)`, `sortedmulti_a(...)`, or a
valid taproot miniscript template.

Taproot key placeholders (both the taproot internal key, and key expressions used in tapleaves) may
also be `musig(...)` aggregate-key expressions, as described in [musig.md](musig.md).

## Default wallets

A few policies that correspond to standardized single-key accounts can be used for address
derivation and signing **without prior registration**. For these *default wallet accounts*, the
wallet name must be empty. They are:

| Policy template   | Address type   | Standard                                                                       |
|-------------------|----------------|--------------------------------------------------------------------------------|
| `pkh(@0/**)`      | Legacy         | [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)       |
| `sh(wpkh(@0/**))` | Nested SegWit  | [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)       |
| `wpkh(@0/**)`     | Native SegWit  | [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)       |
| `tr(@0/**)`       | Taproot        | [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)       |

A policy is treated as a default wallet only if its single key's origin path follows the
corresponding BIP. In addition, the BIP-44 `account` level must be at most `100`, and the
address index at most `50000`. Accounts that exceed those bounds, or use a non-standard
path, are still usable, but must be registered first.

## Serialization

A registered wallet policy comprises:

- the **wallet name**, shown to the user on-screen to identify the wallet (empty for a
  default wallet);
- the **wallet descriptor template**, as a string;
- the **key information vector**.

It is serialized as the concatenation of:

- `1 byte`: `0x02`, the version of the wallet policy language;
- `1 byte`: the length of the wallet name (`0` for a default wallet);
- `<variable length>`: the wallet name (empty for default wallets);
- `<variable length>`: the length of the wallet descriptor template, as a Bitcoin-style
  variable-length integer;
- `32 bytes`: the SHA-256 hash of the wallet descriptor template;
- `<variable length>`: the number of keys in the key information vector, as a Bitcoin-style
  variable-length integer;
- `32 bytes`: the root of the canonical Merkle tree of the key information vector.

See [merkle.md](merkle.md) for the Merkle tree construction.

The SHA-256 hash of a serialized wallet policy is the **wallet policy id**.

### Wallet name

The wallet name must be recognizable by the user when shown on-screen. During
registration the app enforces:

- the name is at least 1 and at most 64 characters long;
- every character is an ASCII character with code between `0x20` (space) and `0x7e` (`~`),
  inclusive;
- the first and last characters are not spaces.

Registration is rejected for names that do not satisfy these constraints.

## Registration and usage

Because the app is stateless, a registered policy is not persisted on the device. A
successful registration instead returns a 32-byte HMAC-SHA256 that authorizes that exact
policy; the host must store the wallet policy together with this HMAC and supply both on
every later call that uses the account. The HMAC key is derived deterministically from the
device seed ([SLIP-0021](https://github.com/satoshilabs/slips/blob/master/slip-0021.md)),
so registration is non-revocable.

The registration, address-derivation, and signing flows are described in
[integration.md](integration.md) (concepts) and [bitcoin.md](bitcoin.md) (wire protocol).
