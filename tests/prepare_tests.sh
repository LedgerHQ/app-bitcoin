#!/bin/bash
cd ..
make clean
make DEBUG=1  # compile optionally with PRINTF
mv bin/ tests/bitcoin-bin
make clean
make DEBUG=1 COIN=bitcoin_testnet
mv bin/ tests/bitcoin-testnet-bin
