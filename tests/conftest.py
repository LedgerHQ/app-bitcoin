import subprocess
import os
import socket
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

    # Gets the speculos executable from the SPECULOS environment variable,
    # or hopes that "speculos.py" is in the $PATH if not set
    speculos_executable = os.environ.get("SPECULOS", "speculos.py")

    base_args = [
        speculos_executable, "./bitcoin-testnet-bin/app.elf",
        "-l", "Bitcoin:./bitcoin-bin/app.elf",
        "--sdk", "2.0",
        "--display", "headless"
    ]

    # Look for the automation_file attribute in the test function, if present
    try:
        automation_args = ["--automation", f"file:{request.function.automation_file}"]
    except AttributeError:
        automation_args = []

    speculos_proc = subprocess.Popen([*base_args, *automation_args])


    # Attempts to connect to speculos to make sure that it's ready when the test starts
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", 9999), timeout=1.0)
            connected = True
            break
        except ConnectionRefusedError:
            time.sleep(0.1)
            connected = False

    if not connected:
        raise RuntimeError("Unable to connect to speculos.")

    yield

    speculos_proc.terminate()
    speculos_proc.wait()


@pytest.fixture
def transport(device, hid):
    transport = (Transport(interface="hid", debug=True)
                 if hid else Transport(interface="tcp",
                                       server="127.0.0.1",
                                       port=9999,
                                       debug=True))
    yield transport
    transport.close()

@pytest.fixture
def cmd(transport):
    return BitcoinCommand(transport=transport, debug=False)
