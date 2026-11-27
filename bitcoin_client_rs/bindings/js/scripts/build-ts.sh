#!/bin/sh
# Compiles the TypeScript sources for Node.js (build/main, CommonJS) and for bundlers
# (build/module, ES modules), next to the corresponding WebAssembly glue.
set -e

cd "$(dirname "$0")/.."
tsc -p tsconfig.json
mkdir -p build/main/wasm
cp ts/wasm/ledger_bitcoin_wasm.js ts/wasm/ledger_bitcoin_wasm.d.ts ts/wasm/ledger_bitcoin_wasm_bg.wasm build/main/wasm/
tsc -p tsconfig.module.json
