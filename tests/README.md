# End-to-end tests using Bitcoin Testnet

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger device

All the commands in this folder are meant to be ran from the root.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/)

```
pip install -r requirements.txt
```

## Launch with Speculos

In order to create the necessary binaries for the Bitcoin Testnet application, you can must first compile the binairies

Then run all the tests using:

```
pytest --device all
```

## Launch with your Nano S/X

Compile and install the app on your device as normal.

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --device `your_device` --backend ledgerblue
```