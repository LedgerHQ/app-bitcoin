
import os

from ragger_bitcoin import createRaggerClient, RaggerClient
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.conftest import configuration
from ragger.firmware import Firmware
from ragger.firmware.touch.positions import STAX_X_CENTER, FLEX_X_CENTER, APEX_P_X_CENTER
from ragger.navigator import Navigator, NavInsID, NavIns
import ledger_bitcoin._base58 as base58
from ledger_bitcoin.common import sha256
from ledger_bitcoin import Chain
from pathlib import Path
from decimal import Decimal
from time import sleep
import subprocess
import shutil
from test_utils import segwit_addr
from test_utils.authproxy import AuthServiceProxy, JSONRPCException
from test_utils.fixtures import *
from typing import List, Tuple
import random
from bip32 import BIP32


###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC
configuration.OPTIONAL.BACKEND_SCOPE = "function"


@pytest.fixture
def additional_speculos_arguments(request) -> List[str]:
    # if the --speculos_port argument is given, instruct ragger to use the given port
    # instead of using a dynamically allocated port
    speculos_port = request.config.getoption("--speculos_port")
    if speculos_port is None:
        return []
    else:
        return ["--api-port", str(speculos_port)]

#########################
### CONFIGURATION END ###
#########################
TESTS_ROOT_DIR = Path(__file__).parent

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )

random.seed(0)  # make sure tests are repeatable

# Make sure that the native client library is used with, as speculos would otherwise
# return a version number < 2.0.0 for the app
os.environ['SPECULOS_APPNAME'] = f'Bitcoin Test:{get_app_version()}'


BITCOIN_DIRNAME = os.getenv("BITCOIN_DIRNAME", "tests/.test_bitcoin")


rpc_url = "http://%s:%s@%s:%s" % (
    os.getenv("BTC_RPC_USER", "user"),
    os.getenv("BTC_RPC_PASSWORD", "passwd"),
    os.getenv("BTC_RPC_HOST", "127.0.0.1"),
    os.getenv("BTC_RPC_PORT", "18443")
)

utxos = list()
btc_addr = ""


def get_rpc() -> AuthServiceProxy:
    return AuthServiceProxy(rpc_url)


def get_wallet_rpc(wallet_name: str) -> AuthServiceProxy:
    return AuthServiceProxy(f"{rpc_url}/wallet/{wallet_name}")


def setup_node():
    global btc_addr

    # Check bitcoind is running while generating the address
    while True:
        rpc = get_rpc()
        try:
            print(rpc.createwallet(wallet_name="test_wallet", descriptors=True))
            btc_addr = rpc.getnewaddress()
            break

        except ConnectionError as e:
            sleep(1)
        except JSONRPCException as e:
            if "Loading wallet..." in str(e):
                sleep(1)

    # Mine enough blocks so coinbases are mature and we have enough funds to run everything
    rpc.generatetoaddress(105, btc_addr)


@pytest.fixture(scope="session")
def run_bitcoind():
    # Run bitcoind in a separate folder
    os.makedirs(BITCOIN_DIRNAME, exist_ok=True)

    bitcoind = os.getenv("BITCOIND", "bitcoind")

    shutil.copy(os.path.join(os.path.dirname(__file__),
                "bitcoin.conf"), BITCOIN_DIRNAME)
    subprocess.Popen([bitcoind, f"--datadir={BITCOIN_DIRNAME}"])

    # Make sure the node is ready, and generate some initial blocks
    setup_node()

    yield

    rpc = get_rpc()
    rpc.stop()

    shutil.rmtree(BITCOIN_DIRNAME)


@pytest.fixture(scope="session")
def rpc(run_bitcoind):
    return get_rpc()


@pytest.fixture(scope="session")
def rpc_test_wallet(run_bitcoind):
    return get_wallet_rpc("test_wallet")


def get_utxo():
    rpc = get_rpc()
    global utxos
    if not utxos:
        utxos = rpc.listunspent()

    if len(utxos) == 0:
        raise ValueError("There are no UTXOs.")

    utxo = utxos.pop(0)
    while utxo.get("amount") < Decimal("0.00002"):
        utxo = utxos.pop(0)

    return utxo


def seed_to_wif(seed: bytes):
    assert len(seed) == 32

    double_sha256 = sha256(sha256(b"\x80" + seed))
    return base58.encode(b"\x80" + seed + double_sha256[:4])


wallet_count = 0


def get_unique_wallet_name() -> str:
    global wallet_count

    result = f"mywallet-{wallet_count}"

    wallet_count += 1

    return result


def get_pseudorandom_keypair(wallet_name: str) -> Tuple[str, str]:
    """
    Generates a tpub and tpriv deterministically from the wallet name
    Used in tests to have deterministic wallets in bitcoin-core instances.
    """

    bip32 = BIP32.from_seed(wallet_name.encode(), network="test")

    xpub = bip32.get_xpub_from_path("m")
    xpriv = bip32.get_xpriv_from_path("m")

    return xpub, xpriv


def create_new_wallet() -> Tuple[str, str]:
    """Creates a new descriptor-enabled wallet in bitcoin-core. Each new wallet has an increasing counter as
    part of it's name in order to avoid conflicts. Returns the wallet name and the xpub (with no key origin
    information)."""

    wallet_name = get_unique_wallet_name()

    get_rpc().createwallet(wallet_name=wallet_name, descriptors=True)

    core_xpub, _ = get_pseudorandom_keypair(wallet_name)

    return wallet_name, core_xpub


def recompute_checksum(rpc: AuthServiceProxy, descriptor: str) -> str:
    # remove "#" and everything after it, if present
    if '#' in descriptor:
        descriptor = descriptor[:descriptor.index('#')]
    descriptor_info = rpc.getdescriptorinfo(descriptor)
    return descriptor + '#' + descriptor_info["checksum"]


def import_descriptors_with_privkeys(core_wallet_name: str, receive_desc: str, change_desc: str):
    wallet = get_wallet_rpc(core_wallet_name)
    wallet_xpub, wallet_xpriv = get_pseudorandom_keypair(core_wallet_name)

    assert wallet_xpub in receive_desc and wallet_xpub in change_desc

    import_desc = [{
        "desc": recompute_checksum(wallet, receive_desc.replace(wallet_xpub, wallet_xpriv)),
        "active": True,
        "internal": False,
        "timestamp": "now"
    }, {
        "desc": recompute_checksum(wallet, change_desc.replace(wallet_xpub, wallet_xpriv)),
        "active": True,
        "internal": True,
        "timestamp": "now"
    }]
    import_res = wallet.importdescriptors(import_desc)
    assert import_res[0]["success"] and import_res[1]["success"]


def generate_blocks(n):
    return get_rpc().generatetoaddress(n, btc_addr)


def testnet_to_regtest_addr(addr: str) -> str:
    """Convenience function to reencode addresses from testnet format to regtest one (bech32 prefix is different)"""
    hrp, data, spec = segwit_addr.bech32_decode(addr)
    if hrp is None:
        return addr  # bech32m decoding failed; either legacy/unknown address type, or invalid address
    if (hrp != "tb"):
        raise ValueError("Not a valid testnet bech32m string")
    return segwit_addr.bech32_encode("bcrt", data, spec)


@pytest.fixture
def client(bitcoin_network: str, backend: BackendInterface) -> RaggerClient:
    if bitcoin_network == "main":
        chain = Chain.MAIN
    elif bitcoin_network == "test":
        chain = Chain.TEST
    else:
        raise ValueError(
            f'Invalid value for BITCOIN_NETWORK: {bitcoin_network}')

    backend.raise_policy = RaisePolicy.RAISE_CUSTOM
    backend.whitelisted_status = [0x9000, 0xE000]
    return createRaggerClient(backend, chain=chain, debug=True, screenshot_dir=TESTS_ROOT_DIR)


def toggle_nonstandard_sighash_setting(navigator: Navigator, firmware: Firmware,
                                       test_case_name: str = None):
    """Navigate to app settings and toggle the 'Non-standard sighash' switch.

    Must be called at the start of any test that needs non-standard sighash types
    to be accepted (the setting is disabled by default and resets per test).

    If test_case_name* is provided, screenshots are captured and
    compared against golden images via ``navigate_and_compare``; otherwise only
    ``navigate`` (no screenshot comparison) is used.
    """
    if firmware.device.startswith("nano"):
        # Nano NBGL: scroll to settings, enter, toggle switch,
        # scroll through the choice dialog screens, confirm, exit settings
        instructions = [
            NavInsID.RIGHT_CLICK,       # home -> Settings entry
            NavInsID.BOTH_CLICK,        # enter settings (shows switch)
            NavInsID.BOTH_CLICK,        # tap switch -> triggers choice dialog
            NavInsID.RIGHT_CLICK,       # choice: icon/title -> message
            NavInsID.RIGHT_CLICK,       # choice: message -> "Confirm" button
            NavInsID.BOTH_CLICK,        # select Confirm -> back to settings
            NavInsID.RIGHT_CLICK,       # scroll to Back
            NavInsID.BOTH_CLICK,        # exit settings -> home
        ]
    else:
        # Touch devices (Stax/Flex/Apex): open settings, tap the switch row,
        # confirm the "are you sure?" warning dialog, then exit settings
        if firmware.device == "stax":
            switch_pos = (STAX_X_CENTER, 140)
        elif firmware.device == "flex":
            switch_pos = (FLEX_X_CENTER, 150)
        else:  # apex_p, apex_m
            switch_pos = (APEX_P_X_CENTER, 90)
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, switch_pos),
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ]

    if test_case_name is not None:
        navigator.navigate_and_compare(TESTS_ROOT_DIR, test_case_name, instructions,
                                       screen_change_before_first_instruction=False)
    else:
        navigator.navigate(instructions,
                           screen_change_before_first_instruction=False)
