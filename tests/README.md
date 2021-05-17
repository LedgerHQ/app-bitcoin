# End-to-end tests using Bitcoin Testnet

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S/X.

All the commands in this folder are meant to be ran from the `tests` folder, not from the root.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/)

```
pip install -r requirements.txt
```

## Launch with Speculos

In order to create the necessary binaries for the Bitcoin Testnet application, you can use the convenience script `prepare_tests.sh`:

```
bash ./prepare_tests.sh
```

Then run all the tests using:

```
pytest
```

You can delete the test binaries with

```
bash ./clean_tests.sh
```

## Launch with your Nano S/X

Compile and install the app on your device as normal.

To run the tests on your Ledger Nano S/X you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --hid
```

Please note that tests that require an automation file are meant for speculos, and will currently hang the test suite.