# Vendored Rust crates: BIP-388 cleartext bindings

This directory holds a **vendored copy** of the upstream BIP-388 cleartext crates.
They produce `libbip388_c.a`, a `no_std` static library that renders a wallet-policy
descriptor template into a human-readable ("cleartext") description, used by the
register-wallet flow (see `src/common/cleartext.c` and `src/handler/register_wallet.c`).

## Contents

- `bip388/` — the reference BIP-388 descriptor-template parser + cleartext renderer
  (`ClearText::to_cleartext` / `confusion_score`). Its `build.rs` generates the
  cleartext spec tables from `src/cleartext/specs/*.toml` at compile time.
- `bip388-c/` — the C ABI binding around `bip388`. `cbindgen` (run from its `build.rs`)
  generates the committed `bip388-c/include/bip388.h`, which is the C-facing contract.
  Depends on `bip388` via a relative `path = "../bip388"`, so the two crates **must stay
  siblings** in this directory.

The two `target/` directories are git-ignored (see `../.gitignore`).

## Upstream source

Vendored from <https://github.com/LedgerHQ/vanadium>, branch `cleartext-c-bindings`,
commit `7b6271b4eadc5d32f6ce9786e2d76ef55efd9212`, paths `apps/bitcoin/bip388` and
`apps/bitcoin/bip388-c`.

### Re-syncing from upstream

From a checkout of vanadium on the desired commit:

```sh
rsync -a --exclude 'target/' apps/bitcoin/bip388/   <this-repo>/rust/bip388/
rsync -a --exclude 'target/' apps/bitcoin/bip388-c/ <this-repo>/rust/bip388-c/
```

Then rebuild (`cd rust/bip388-c && cargo build --release`) and update the commit hash above.

## Building

- **Device (linked into the app):** the top-level `Makefile` cross-compiles the
  `no_std` `staticlib` for the BOLOS target's Rust triple (e.g.
  `thumbv8m.main-none-eabi` for Nano S+/Stax/Flex) and links the resulting
  `libbip388_c.a`. The build image must have `cargo` and the matching target installed
  (`rustup target add <triple>`).
- **Host (unit tests):** `cargo build --release` produces a host `libbip388_c.a`; the
  unit-test CMake build links it. On a hosted target the precompiled Rust `alloc` is
  built with unwinding, so a `rust_eh_personality` stub is provided on the C side
  (see `examples/demo.c` and `src/common/cleartext.c`).
