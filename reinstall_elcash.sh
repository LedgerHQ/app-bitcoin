#!/usr/bin/env bash

export COIN="elcash"
make delete
export COIN="bitcoin"
make clean && make load
export COIN="elcash"
make clean && make load
