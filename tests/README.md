# End-to-end tests

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S/X.

All the commands in this folder are meant to be ran from the `tests` folder, not from the root.

Install the following system dependencies:

```
sudo apt-get install -y python3-pytest autoconf automake build-essential libffi-dev libtool pkg-config python3-dev
```

Python dependencies are listed in [requirements.txt](../requirements.txt), install them using [pip](https://pypi.org/project/pip/) from the root of the repository:

```
pip install -r requirements.txt
```

Some tests require the `bitcoind` binary from [Bitcoin Core](https://bitcoincore.org/) (the CI uses version 32.1). It must be in the `$PATH` variable, or alternatively be set as the `BITCOIND` environment variable in the shell running the tests:

```
export BITCOIND=/path/to/my/bitcoind
```

The [setup_script.sh](setup_script.sh) script downloads, verifies and installs the same pinned release used by the CI (in `/opt` by default, or in `$BITCOIN_CORE_INSTALL_PREFIX` if set), and prints the command to add it to your `PATH`.

## Launch with Speculos

Build the app as normal from the root folder. For convenience, you probably want to enable DEBUG:

```
DEBUG=1 make
```

Then run all the tests from this folder, specifying the device: nanox, nanosp, stax, flex, apex_p or all:

```
pytest --device yourdevice
```
You can enable the screen display with the option `--display`

## Launch with your Nano S/X/SP or Stax

Compile and install the app on your device as normal.

To run the tests on your Ledger device you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --device yourdevice --backend ledgercomm
```
