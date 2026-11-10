#!/bin/sh
# Builds the WebAssembly module and generates its JavaScript glue:
# - ts/wasm: for Node.js (CommonJS), used by the TypeScript sources and the tests;
# - build/module/wasm: for bundlers (ES modules).
# Requires the wasm32-unknown-unknown Rust target, and the wasm-bindgen CLI with the same version
# as the wasm-bindgen crate in Cargo.toml.
set -e

cd "$(dirname "$0")/.."
TARGET_DIR="$(cd ../.. && pwd)/target"

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
