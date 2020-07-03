## Basic BTC app APDU-level tests 

This folder contains some examples of APDU-level tests for the BTC app. These tests are in no way exhaustive as they only cover a subset of the APDU commands supported by the app:
- Generation of trusted inputs from Segwit and Zcash inputs
- Signature of legacy, Segwit & Zcash tx
- Message signature
- Public key export


### Test environment
The tests are run with pytest and rely on a small, evolving framework located in the `helpers` folder.

The tests are manual for now and require user interaction with the app to validate the signature operations. Automation for CI/CD is planned for later (see [WIP](#wip) section).

Tests can be run:
 - either with a real Ledger device loaded with the BTC and the Zcash apps
 - or with the apps running under [Speculos](https://github.com/LedgerHQ/speculos)


### Launching the tests
Because tests are available for both the BTC app and the Zcash app (using the BTC app as a library), they require the appropriate app to be started and cannot be launched all at once. However, they are gathered categorized under two `pytest` markers: `btc` and `zcash` to allow for launching all the tests of a category at once.

#### With a real Ledger Nano S or Blue device
###### BTC tests
The BTC app must be loaded on the device and started.
```shell script
cd <app-bitcoin-repo-path>/tests
pytest -x -v [-s] -m btc
```

###### Zcash tests
Both the BTC and the Zcash apps must be loaded on the device. Only the Zcash app must be started.
```shell script
cd <app-bitcoin-repo-path>/tests
pytest -x -v [-s] -m zcash
```

#### With Speculos
Procedure below assumes that the BTC and the Zcash app binaries are available.
###### BTC tests
```shell script
# Start speculos (assuming BTC app is bin/app.elf) 
cd <speculos-folder> 
./speculos.py --ontop -m nanos -k 1.6 -s <24-word seed> <app-bitcoin-repo-path>/bin/app.elf
 
# Launch tests
cd <app-bitcoin-repo-path>/tests
LEDGER_PROXY_ADDRESS=127.0.0.1 LEDGER_PROXY_PATH=9999 pytest -x -v [-s] -m btc
```

###### Zcash tests
```shell script
# Start speculos (assuming BTC app is lib/btc.elf and Zcash app is in bin/app.elf) 
cd <speculos-folder> 
./speculos.py --ontop -m nanos -k 1.6 -s <24-word seed> -l Bitcoin:<app-bitcoin-repo-path>/lib/btc.elf <app-bitcoin-repo-path>/bin/app.elf

# Launch tests
cd <app-bitcoin-repo-path>/tests
LEDGER_PROXY_ADDRESS=127.0.0.1 LEDGER_PROXY_PATH=9999 pytest -x -v [-s] -m zcash
```

**Note**: 
- When provided, the `-s` parameter triggers the display of the APDUs exchanged between the test and the device.
- Tests pass green as long as user confirms the transactions/message signatures. They fail if user rejects the signing operation.


### Automation
Very early work has started to add test automation with [Speculos](https://github.com/LedgerHQ/speculos), in order to enable integration in a CI/CD environment. This is still WIP at the moment. 


### Test framework details
WIP
