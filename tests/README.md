# End-to-end tests using Bitcoin Testnet

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S/X.
Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/)

```
pip install -r requirements.txt
```

## Prerequisite

You need to compile the Bitcoin application and the Bitcoin Testnet application as below

```
make DEBUG=1  # compile optionally with PRINTF
mv bin/ bitcoin-bin/
make clean
make DEBUG=1 COIN=bitcoin_testnet
mv bin/ bitcoin_testnet-bin
```

The seed used for tests is the default one of Speculos.

## Launch with Speculos

First start Bitcoin Testnet application with Speculos

```
./path/to/speculos.py /path/to/app-bitcoin/bitcoin_testnet-bin/app.elf -l Bitcoin:/path/to/app-bitcoin/bitcoin-bin/app.elf --sdk 1.6
```

then in the `tests` folder run

```
pytest
```

## Launch with your Nano S/X

To run the tests on your Ledger Nano S/X you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --hid
```
