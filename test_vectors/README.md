# Language-neutral test vectors

This directory holds **TOML test assets** that capture the deterministic core of
the app's behavioral tests as plain data: inputs and expected outputs/errors,
with no framework-specific code. The same vectors can be replayed from the Python
suite (`tests/`), the C unit-tests (`unit-tests/`, via the bundled `tomlc17`
parser), and — eventually — the Rust client (`bitcoin_client_rs/`).

The goal is to keep the *what the device must produce* separate from the *how a
given framework drives the device*. UX-only behaviors (screen-by-screen
approve/reject navigation), randomized PSBTs, multi-round MuSig2, and
bitcoind-integration end-to-end flows are intentionally **not** captured here;
they remain as bespoke code in each framework.

All vectors were generated against the Speculos test seed (see
[`fixtures.toml`](fixtures.toml)) on the **testnet** network.

## Files

| File | Operation |
|------|-----------|
| [`fixtures.toml`](fixtures.toml) | Global constants (seed, master fingerprint, network). |
| [`get_extended_pubkey.toml`](get_extended_pubkey.toml) | `get_extended_pubkey`. |
| [`sign_message.toml`](sign_message.toml) | `sign_message`. |
| [`register_wallet.toml`](register_wallet.toml) | `register_wallet`. |
| [`get_wallet_address.toml`](get_wallet_address.toml) | `get_wallet_address`. |
| [`sign_psbt.toml`](sign_psbt.toml) | `sign_psbt`. |

## Common conventions

Each file contains an array of `[[case]]` tables.

- **`name`** (string, required, unique): per-case test label.
- **`description`** (string, optional): human note.

### Wallet policy block

Operations that take a wallet policy (`register_wallet`, `get_wallet_address`,
`sign_psbt`) embed it directly in the case:

- **`descriptor_template`** (string): a V2 descriptor template, e.g.
  `"wpkh(@0/**)"`, `"sh(sortedmulti(2,@0/**,@1/**))"`, `"tr(@0/**,pk(@1/**))"`.
- **`keys_info`** (array of strings): key-info strings in `@0,@1,…` order, e.g.
  `"[f5acc2fd/44'/1'/0']tpub..."`.
- **`wallet_name`** (string, optional, default `""`): the registered wallet name.
  Default (empty) is used for standard single-key policies.

Only **V2** policies are represented (V1 is out of scope). The Python
`MultisigWallet(...)` helper is just sugar over a `descriptor_template` +
`keys_info`; vectors always store this canonical form, which both the C parser
(`parse_descriptor_template`) and the Python `WalletPolicy` accept directly.

### Error encoding

A case that expects the device to reject the request carries an **`error`** string
instead of the `expected_*` field(s). The value is a symbolic status-word name
that each framework maps to the numeric status word (see `src/boilerplate/sw.h`
and `DeviceException.exc` in the Python client):

| Name | Status word |
|------|-------------|
| `OK` | `0x9000` |
| `DENY` | `0x6985` |
| `SECURITY_STATUS_NOT_SATISFIED` | `0x6982` |
| `INCORRECT_DATA` | `0x6A80` |
| `NOT_SUPPORTED` | `0x6A82` |
| `WRONG_P1P2` | `0x6A86` |
| `WRONG_DATA_LENGTH` | `0x6A87` |
| `BAD_STATE` | `0xB007` |
| `SIGNATURE_FAIL` | `0xB008` |

Only **deterministic** errors (those derivable from the inputs) are encoded here.
`DENY` errors that arise purely from UI rejection are *not* captured — they depend
on navigation, not on the request, and stay as framework-specific code.

## Per-operation fields

### `get_extended_pubkey.toml`
- `path` (string): BIP-32 path, e.g. "m/44'/1'/0'".
- `standard` (bool): whether the path is exported without user confirmation.
  - `true`: exported regardless of the display flag.
  - `false`: exported only when the UI confirmation is shown; otherwise `NOT_SUPPORTED`.
- `expected_pubkey` (string, optional) on success — *or* `error` (e.g. `NOT_SUPPORTED`,
  `INCORRECT_DATA`).

### `sign_message.toml`
- `message` (string) *or* `message_hex` (hex string) for raw/binary input.
- `path` (string).
- `expected_signature` (base64 string) on success — *or* `error`.

### `register_wallet.toml`
- wallet policy block (`descriptor_template`, `keys_info`, `wallet_name`).
- `expected_wallet_id` (hex, 32 bytes): the policy id (sha256 of the registration);
  secret-free, checkable by any framework.
- `expected_wallet_hmac` (hex, 32 bytes, optional): reproducible only with the
  Speculos registration key.
- *or* `error` (e.g. `INCORRECT_DATA` for a bad name, `NOT_SUPPORTED` for a
  non-sane policy).

### `get_wallet_address.toml`
- wallet policy block.
- `change` (int): `0` (receive) or `1` (change).
- `address_index` (int, non-negative).
- `expected_address` (string) on success — *or* `error`.

### `sign_psbt.toml`
- `psbt_file` (string, relative to `tests/`) *or* `psbt` (base64 string).
- wallet policy block.
- `wallet_hmac` (hex, optional): required for non-default (registered) policies.
- one or more `[[case.expected_signatures]]` sub-tables:
  - `input_index` (int).
  - `pubkey` (hex string): 33-byte compressed (legacy/segwit) or 32-byte x-only
    (taproot).
  - `sighash_type` (int, **required**): the SIGHASH flag the input is signed with
    (`ALL=1`, `NONE=2`, `SINGLE=3`, `+ANYONECANPAY=0x80`; taproot `DEFAULT=0`).
  - exactly one of:
    - `signature` (hex string): exact expected bytes. Present for deterministic
      ECDSA/DER signatures — assert byte-equality. The trailing sighash byte is
      included for non-default sighash types.
    - `sighash` (hex string, 32 bytes): the signed message **digest**. Present for
      taproot Schnorr signatures, which are *not* byte-stable; the framework
      verifies the produced signature against `pubkey` over this digest (BIP-340).
      Storing the digest directly keeps verification portable — a framework need
      not reimplement the sighash algorithm. (For a 65-byte taproot signature, drop
      the trailing sighash-type byte before verifying.)
  - `tapleaf_hash` (hex string, optional): for tapscript spends.

The top-level case may also carry `error` (instead of `expected_signatures`) for
deterministic rejections, e.g. `NOT_SUPPORTED` for `SIGHASH_SINGLE` with no
matching output, or an unsupported sighash type.
