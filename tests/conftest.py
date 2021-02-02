import subprocess
import os
import time
import logging
import pytest

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd import BitcoinCommand


logging.basicConfig(level=logging.INFO)


def pytest_addoption(parser):
    parser.addoption("--hid",
                     action="store_true")

@pytest.fixture
def hid(pytestconfig):
    return pytestconfig.getoption("hid")

@pytest.fixture
def device(request, hid):
    # If running on real hardware, nothing to do here
    if hid:
        yield
        return

    # Gets the speculos executable from the SPECULOS environtment variable,
    # or hopes that "speculos.py" is in the $PATH if not set
    speculos_executable = os.environ.get("SPECULOS", "speculos.py")

    base_args = [
        speculos_executable, "./bitcoin-testnet-bin/app.elf",
        "-l", "Bitcoin:./bitcoin-bin/app.elf",
        "--sdk", "1.6",
        "--display", "headless"
    ]

    # Look for the automation_file attribute in the test function, if present
    try:
        automation_args = ["--automation", f"file:{request.function.automation_file}"]
    except AttributeError:
        automation_args = []

    speculos_proc = subprocess.Popen([*base_args, *automation_args])

    # TODO: find a better way to make sure speculos is ready
    time.sleep(1)

    yield

    speculos_proc.terminate()
    speculos_proc.wait()


@pytest.fixture
def cmd(device, hid):
    transport = (Transport(interface="hid", debug=True)
                 if hid else Transport(interface="tcp",
                                       server="127.0.0.1",
                                       port=9999,
                                       debug=True))
    command = BitcoinCommand(transport=transport, debug=False)

    yield command

    command.transport.close()
