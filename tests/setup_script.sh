#!/bin/bash

apt update -y && sudo apt install -y curl
curl -o /tmp/bitcoin.tar.gz https://bitcoincore.org/bin/bitcoin-core-26.0/bitcoin-26.0-x86_64-linux-gnu.tar.gz && \
    sudo tar -xf /tmp/bitcoin.tar.gz -C / && \
    sudo mv /bitcoin-26.0 /bitcoin

# Add bitcoin binaries to path
export PATH=/bitcoin/bin:$PATH
