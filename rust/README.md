# Vendored Rust crates: BIP-388 cleartext bindings

This directory holds a **vendored copy** of the upstream BIP-388 cleartext crates.
They produce `libbip388_c.a`, an allocation-free `no_std` static library that renders
a wallet-policy descriptor template into a human-readable ("cleartext") description,
used by the register-wallet flow (see `src/common/cleartext.c` and
`src/handler/register_wallet.c`).

## Contents

- `bip388/` — the reference BIP-388 descriptor-template parser + cleartext renderer.
  Its `build.rs` generates the cleartext spec tables from `src/cleartext/specs/*.toml`
  at compile time.
- `bip388-c/` — the C ABI binding around `bip388`. It is `no_std` with **no global
  allocator**: every entry point works inside a caller-provided scratch *arena* and an
  output buffer. The committed `bip388-c/include/bip388.h` is the C-facing contract and
  is maintained by hand (kept in sync with `bip388-c/src/lib.rs`). Depends on `bip388`
  via a relative `path = "../bip388"`, so the two crates **must stay siblings** in this
  directory.

The two `target/` directories are git-ignored (see `../.gitignore`).

## C ABI

The three entry points (see `bip388-c/include/bip388.h`):

- `bip388_min_arena_size(tmpl, tmpl_len, *out_size)` — minimum arena size (bytes) the
  other calls need for `tmpl`.
- `bip388_confusion_score(tmpl, tmpl_len, arena, arena_len, *out_score)` — an upper bound
  on how many distinct templates map to the same cleartext. Show cleartext only when it
  is `<= BIP388_MAX_CONFUSION_SCORE`.
- `bip388_to_cleartext(tmpl, tmpl_len, arena, arena_len, out, out_len, lines, max_lines,
  *out_n_lines, *out_has_cleartext)` — renders the descriptions into `out`; each line is
  reported as a `(ptr, len)` `Bip388Line` into `out`.

All return `int32_t`: `BIP388_OK` (0) or a negative error code.

## Upstream source

Vendored from <https://github.com/LedgerHQ/vanadium>, branch `bip388-arena-nostd`,
commit `547597adc474b2cc0a767b2e2bcc0f689dcbb3b8`, paths `apps/bitcoin/bip388` and
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
  `thumbv8m.main-none-eabi` for Nano S+/Stax/Flex, `thumbv7m-none-eabi` for Nano X) and
  links the resulting `libbip388_c.a`. The build image must have `cargo` and the matching
  target installed (`rustup target add <triple>`). Set `ENABLE_CLEARTEXT=0` to build
  without the feature (no Rust toolchain required).
- **Host (unit tests):** `cargo build --release` produces a host `libbip388_c.a`; the
  unit-test CMake build links it. The crate is `panic=abort` and has no allocator, so the
  C side provides a small `abort()` / `rust_eh_personality` backstop (see
  `src/common/cleartext.c`).
