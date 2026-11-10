# Test utils

This folder contains shared python utility functions for several pytest test suites in this repository.

`bitcoin/` contains the Bitcoin primitives that the tests use to build and inspect transactions and PSBTs (PSBTv0 and PSBTv2, transactions, scripts, BIP-32 keys, and a vendored copy of [embit](https://github.com/diybitcoinhardware/embit) for miniscript). They used to be part of the pure-Python `ledger_bitcoin` client; the client itself is now a binding of the Rust client, and does not depend on them.
