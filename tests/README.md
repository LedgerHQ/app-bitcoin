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
cd $APP_BITCOIN_REPO_PATH/tests
pytest -x -v [-s] -m btc
```

###### Zcash tests
Both the BTC and the Zcash apps must be loaded on the device. Only the Zcash app must be started.
```shell script
cd $APP_BITCOIN_REPO_PATH/tests
pytest -x -v [-s] -m zcash
```

#### With Speculos
Procedure below assumes that the BTC and the Zcash app binaries are available.
###### BTC tests
```shell script
# Start speculos (assuming BTC app is bin/app.elf) 
cd $SPECULOS_REPO_PATH 
./speculos.py --ontop -m nanos -k 1.6 -s <24-word seed> <app-bitcoin-repo-path>/bin/app.elf
 
# Launch tests
cd $APP_BITCOIN_REPO_PATH/tests
LEDGER_PROXY_ADDRESS=127.0.0.1 LEDGER_PROXY_PATH=9999 pytest -x -v [-s] -m btc
```

###### Zcash tests
```shell script
# Start speculos (assuming BTC app is lib/btc.elf and Zcash app is in bin/app.elf) 
cd $SPECULOS_REPO_PATH 
./speculos.py --ontop -m nanos -k 1.6 -s <24-word seed> -l Bitcoin:<app-bitcoin-repo-path>/lib/btc.elf <app-bitcoin-repo-path>/bin/app.elf

# Launch tests
cd $APP_BITCOIN_REPO_PATH/tests
LEDGER_PROXY_ADDRESS=127.0.0.1 LEDGER_PROXY_PATH=9999 pytest -x -v [-s] -m zcash
```

**Note**: 
- When provided, the `-s` parameter triggers the display of the APDUs exchanged between the test script and the device.
- Tests pass green as long as user confirms the transactions/message signatures. They fail if user rejects the signing operation.


### Automation
Very early work has started to add test automation with [Speculos](https://github.com/LedgerHQ/speculos), in order to enable integration in a CI/CD environment. This is still WIP at the moment. 
 
=== 

### Test framework details
The tests and framework are organized as described below:
```
|
|-- tests: Contains the test scripts written in python (pytest). `btc`, `zcash` and `manual` pytest
      |    marks are available.
      |
      |-- basetest.py: Provides some base classes for BTC and Zcash test classes. They contain 
      |       some methods that tests can call to either check the format of various data returned by
      |       the app (signatures, trusted inputs,...) or perform some specific actions (e.g. sending
      |       some raw APDUs extracted from Ledgerjs logs in Zcash tests).
      |
      |-- helpers: Abstraction layers to the app under test & to the BTC raw transaction data.
            |
            |
            |-- txparser: In-house raw BTC tx parser, based on a dataclass + specific types.
            |     |   Supports legacy & segwit BTC tx + Zcash tx.
            |     |
            |     |-- transaction.py: Implements the `TxParse` class + its `from_raw()` method 
            |     |       that parses a raw tx into named attributes of the `Tx` class.
            |     |
            |     |-- txtypes.py: Various types used by `TxParse`, notably `TxInt8` (resp. `16, `32`) 
            |             and `TxVarInt` which store some of the tx fields as both integers and 
            |             bytes buffer.
            |
            |-- deviceappproxy: Defines the `DeviceAppProxy` class that abstracts APDU-level 
            |       communication between the app & the tests. 
            |
            |-- apduabstract.py: Define the `CApdu` dataclass (abstract representation of an APDU)
            |       and the `ApduSet` class which is a collection of `CApdu`s supported by an app
            |       I.e. `CApdu` collects the values of CLA, INS, P1, P2 bytes for a command 
            |       supported by an app and `ApduSet` gathers these `CApdu`s in one place.
            |
            |-- deviceappbtc.py: class derived from `DeviceAppProxy` that defines the `ApduSet` of
                    `CApdu`s supported by the BTC app (actually only the subset useful for the tests)
                    and "hides" them behind an higher-level API that the tests can call. That API 
                    takes care of all the app-specific intricacies of sending data to the app (e.g.
                    payload chunking is often required to send big data to the app but is not well
                    documented, so `DeviceAppBtc` takes care of that in place of the tester).
```
 
 ===
 
### Next steps
Below is a compilation of the various things to do to structure and rationalize  the test framework even more, so that it could easily be reused for testing another app than BTC (of course, provided the implementation of the appropriate APDU abstraction API in a `DeviceAppProxy`-derived class).

- `helpers/basetests.py`: 
  - [ ] Replace the raw APDU from Ledgerjs logs (mostly some GetVersion-kind of APDUs) in Segwit/Zcash tests with a proper `DeviceAppBtc`-based implementation. 
  - [ ] Whether to leave the `LedgerjsApdu` class (in `conftest.py`) & the associated `BaseTestZcash.send_ljs_apdus()` method (but moved to `LedgerjsApdu` for consistency) available as utilities for potential reuse or to scrap them alltoghether is a decision left to the maintainers.
  - [ ] Dataclass `BtcPublicKey` to be re-written and made more useful, as suggested by @onyb

- `helpers/txparser/txtypes.py`: 
  - [ ] Class `Tx` is generic (as it describes most, if not all, blockchains transactions formats) and should be moved from `transaction.py` to `txtypes.py`. File `txtypes.py` should be in a separate folder/module at the same level as `txparser` since it can be reused other parsers than a BTC tx parser.

- `helpers/txparser/tansaction.py + helpers/txparser/txtypes.py`: 
  Goal is to facilitate writing parsers for other blockchains transactions. So writing a new parser for e.g. ETH blockchain tx would be a matter of deriving the `TxParse` base class and implementing its `from_raw()` method. 
  -  [ ] Class `TxParse` should be made into a base class with a pure virtual `from_raw()` method which raises `NotImplementedError`. And moved to a separate file too.
  - [ ] Following that, the current BTC tx parser should be derived from that base class and renamed `BtcTxParse` or something. AndFile `transaction.py` should be renamed to properly reflect its BTC-inclined orientation. 
  - [ ] Additionally, a `to_bytes(parsed_tx: Tx) -> bytes` method which concatenates "anonymously" (by parsing recursively the class object, see `_recursive_hash_obj()` for an example of such parsing) all the fields of `parsed_tx` into a raw tx bytes buffer.
  - [ ] The Weblue's `field()` method should be used to check fields size when possible at runtime. This will impact the definition of the `byte`, `bytes2`, `bytes4`, ...`bytes64` types in `txtypes.py` which would simply become based on the `bytes` type.

- `helpers/deviceappproxy/deviceappproxy.py`: As an initial effort to add event automation support to the tests;, this fille contains the `run()` and `stop()` methods to launch/close the app being tested under speculos. Launching/closing an app by calling these methods work but are not enough to support automation.
   - [ ] Implement all missing parts related to automation (e.g. listening to touch/click events & propagating them to the app). This will allow for deployement of the tests in a CI/CD environment. 
  - [ ] The hardware-related parameters of the `run()`  method (i.e. `model`, `finger_port` (actually `event_port`), `deterministic_rng`, `rampage`) should be moved to `__init__()` instead, with sensible default values.

- `conftest.py`: 
  - [ ] This file being pytest-specific, should dataclasses `SignTxTestData` and `TrustedInputTestData` be moved into a separate file, possibly `basetest.py`? 
    - Pro: it makes them reusable with other test environemnts than pytest but Cons: it creates a coupling between `conftest.py` and that other file.

- Misc:
  - [ ] Add support for Bitcoin Cash (potentially nothing to do?)
  - [ ] Turn `deviceappproxy` and `txparser` folders into proper packages installable into any virtualenv through pip. Meaning they would have their own repo in LedgerHQ and evolve separately from the BTC app.
  - Either:
    - [ ] Add new `deviceapp<coin>.py` files in newly modularized `deviceappproxy` to support formatting APDus for other coins e.g. Eth, Xrp, etc
    - [ ] Or move Bitcoin-specific `deviceappbtc.py` out of `deviceappproxy` module and put in at `helper` folder (other coins tests will define a similar `deviceapp<coin>.py` based on `deviceappproxy` module in their own repo)
  - [X] Fix style warnings from `pylint` & `pycodestyle`
  - [X] Replace `BytesOrStr` type with `AnyStr` built-in type
  - [X] Rename `lbstr` type to something more verbose like `ByteOrder`
