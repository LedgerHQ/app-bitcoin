# Ledger Bitcoin Application

This is the Bitcoin application for Ledger devices.

## Quick start guide

### With VSCode

You can quickly setup a convenient environment to build and test your application by using [Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools) which leverages the [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image.

It will allow you, whether you are developing on macOS, Windows or Linux to quickly **build** your apps, **test** them on **Speculos** and **load** them on any supported device.

* Install and run [Docker](https://www.docker.com/products/docker-desktop/).
* Make sure you have an X11 server running :
    * On Ubuntu Linux, it should be running by default.
    * On macOS, install and launch [XQuartz](https://www.xquartz.org/) (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
    * On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/) (make sure to configure it to disable access control).
* Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
* Open a terminal and clone `app-bitcoin` with `git clone git@github.com:LedgerHQ/app-bitcoin.git`.
* Open the `app-bitcoin` folder with VSCode.
* Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b` (`command + shift + b` on a Mac) to conveniently execute actions :
    * Build the app for the device model of your choice with `Build`.
    * Test your binary on [Speculos](https://github.com/LedgerHQ/speculos) with `Run with Speculos`.
    * You can also run functional tests, load the app on a physical device, and more.

:information_source: The terminal tab of VSCode will show you what commands the extension runs behind the scene.

### With a terminal

The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) docker image contains all the required tools and libraries to **build**, **test** and **load** an application.

You can download it from the ghcr.io docker repository:

```shell
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

You can then enter this development environment by executing the following command from the directory of the application `git` repository:

**Linux (Ubuntu)**

```shell
sudo docker run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

**macOS**

```shell
sudo docker run  --rm -ti --user "$(id -u):$(id -g)" --privileged -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

**Windows (with PowerShell)**

```shell
docker run --rm -ti --privileged -v "$(Get-Location):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

The application's code will be available from inside the docker container, you can proceed to the following compilation steps to build your app.

## Compilation and load

To easily setup a development environment for compilation and loading on a physical device, you can use the [VSCode integration](#with-vscode) whether you are on Linux, macOS or Windows.

If you prefer using a terminal to perform the steps manually, you can use the guide below.

### Compilation

Setup a compilation environment by following the [shell with docker approach](#with-a-terminal).

From inside the container, use the following command to build the app :

```shell
make DEBUG=1  # compile optionally with PRINTF
```

You can choose which device to compile and load for by setting the `BOLOS_SDK` environment variable to the following values :

* `BOLOS_SDK=$NANOX_SDK`
* `BOLOS_SDK=$NANOSP_SDK`
* `BOLOS_SDK=$STAX_SDK`
* `BOLOS_SDK=$FLEX_SDK`
* `BOLOS_SDK=$APEX_P_SDK`

By default this variable is set to build/load for Nano S+.

The app is compiled for testnet by default. In order to compile the app for mainnet, add `COIN=bitcoin` when running the `make` command.

### Loading on a physical device

This step will vary slightly depending on your platform.

:information_source: Your physical device must be connected, unlocked and the screen showing the dashboard (not inside an application).

**Linux (Ubuntu)**

First make sure you have the proper udev rules added on your host :

```shell
# Run these commands on your host, from the app's source folder.
sudo cp .vscode/20-ledger.ledgerblue.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules 
sudo udevadm trigger
```

Then once you have [opened a terminal](#with-a-terminal) in the `app-builder` image and [built the app](#compilation-and-load) for the device you want, run the following command :

```shell
# Run this command from the app-builder container terminal.
make load    # load the app on a Nano S+ by default
```

[Setting the BOLOS_SDK environment variable](#compilation-and-load) will allow you to load on whichever supported device you want.

**macOS / Windows (with PowerShell)**

:information_source: It is assumed you have [Python](https://www.python.org/downloads/) installed on your computer.

Run these commands on your host from the app's source folder once you have [built the app](#compilation-and-load) for the device you want :

```shell
# Install Python virtualenv
python3 -m pip install virtualenv 
# Create the 'ledger' virtualenv
python3 -m virtualenv ledger
```

Enter the Python virtual environment

* macOS : `source ledger/bin/activate`
* Windows : `.\ledger\Scripts\Activate.ps1`

```shell
# Install Ledgerblue (tool to load the app)
python3 -m pip install ledgerblue 
# Load the app.
python3 -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

## Documentation

If you want to understand what the app does or build an integration on top of an existing client library, start here:
- [features.md](doc/features.md): Overview of the app's features and the account/script types it supports.
- [integration.md](doc/integration.md): Concepts and security model for integrators — wallet policies, registration, and on-device verification.

For many use cases, the code examples provided in the following client libraries are enough to get started:
- [Python client library](bitcoin_client)
- [JavaScript client library](bitcoin_client_js)
- [Rust client library](bitcoin_client_rs)

If you need to go deeper into the rabbit hole 🐇🕳️ (for example to implement a client library or work at the protocol level), refer to the following documents:
- [bitcoin.md](doc/bitcoin.md): Low-level documentation of the Bitcoin app's communication protocol and commands.
- [wallet.md](doc/wallet.md): Formal definition of the wallet policy language, its serialization, and the supported scripts.
- [merkle.md](doc/merkle.md): Advanced details on techniques used in the Bitcoin app's secured and scalable communication protocol.
- [musig.md](doc/musig.md): Details of the MuSig2 implementation and its on-device state management.
- [debugging.md](doc/debugging.md): Guidance on how to diagnose and resolve issues.

## Tests

See the [tests](tests) folder for documentation on the functional and end-to-end test suites of the bitcoin app, and the [unit-tests](unit-tests) folder for the C unit tests.

## Deployment

To have either the python client, javascript client or rust client published to their respective package registries upon a new release, please create a tag with their respective regex :

```bash
pyclient-\d+\.\d+\.\d+
jsclient-\d+\.\d+\.\d+
rsclient-\d+\.\d+\.\d+
```
