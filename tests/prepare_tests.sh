#!/bin/bash
cd ..
make clean
make -j DEBUG=1  # compile optionally with PRINTF
rm -rf tests/zcash-bin
mv bin/ tests/zcash-bin
