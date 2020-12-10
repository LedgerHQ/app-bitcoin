import logging
import pytest

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd import BitcoinCommand


logging.basicConfig(level=logging.INFO)


def pytest_addoption(parser):
    parser.addoption("--hid",
                     action="store_true")


@pytest.fixture(scope="module")
def hid(pytestconfig):
    return pytestconfig.getoption("hid")


@pytest.fixture(scope="module")
def cmd(hid):
    transport = (Transport(interface="hid", debug=True)
                 if hid else Transport(interface="tcp",
                                       server="127.0.0.1",
                                       port=9999,
                                       debug=True))
    command = BitcoinCommand(transport=transport, debug=False)

    yield command

    command.transport.close()
