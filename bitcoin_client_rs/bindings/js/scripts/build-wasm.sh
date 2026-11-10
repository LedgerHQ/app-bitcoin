#!/bin/sh
# Builds the WebAssembly module and generates its JavaScript glue:
# - ts/wasm: for Node.js (CommonJS), used by the TypeScript sources and the tests;
# - build/module/wasm: for bundlers (ES modules).
# Requires a Rust toolchain, which is installed with rustup if it is missing in CI (when the CI
# environment variable is set). The wasm32-unknown-unknown target and the wasm-bindgen CLI (with
# the same version as the wasm-bindgen crate in Cargo.toml) are installed if they are missing.
set -e

cd "$(dirname "$0")/.."
TARGET_DIR="$(cd ../.. && pwd)/target"
WASM_BINDGEN_VERSION=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' Cargo.toml)

if ! command -v cargo > /dev/null; then
    if [ -z "$CI" ]; then
        echo "Building requires a Rust toolchain: see https://rustup.rs" >&2
        exit 1
    fi
    echo "Installing a Rust toolchain"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
    PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
    export PATH
fi
if command -v rustup > /dev/null; then
    rustup target add wasm32-unknown-unknown
fi
if [ "$(wasm-bindgen --version 2> /dev/null)" != "wasm-bindgen $WASM_BINDGEN_VERSION" ]; then
    echo "Installing wasm-bindgen-cli $WASM_BINDGEN_VERSION"
    cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked
fi

# optimize for size; these only apply to this build of the workspace
CARGO_PROFILE_RELEASE_LTO=true \
CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
CARGO_PROFILE_RELEASE_PANIC=abort \
CARGO_TARGET_DIR="$TARGET_DIR/wasm-release" \
    cargo build -p ledger_bitcoin_wasm --target wasm32-unknown-unknown --release

WASM="$TARGET_DIR/wasm-release/wasm32-unknown-unknown/release/ledger_bitcoin_wasm.wasm"
wasm-bindgen --target nodejs --out-dir ts/wasm "$WASM"
wasm-bindgen --target bundler --out-dir build/module/wasm "$WASM"
