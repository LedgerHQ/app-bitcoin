import pytest

from ledger_bitcoin.exception.errors import WrongP1P2Error
from ledger_bitcoin.exception.device_exception import DeviceException

from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient

CLA_BITCOIN = 0xE1
INS_GET_MASTER_FINGERPRINT = 0x05
CURRENT_PROTOCOL_VERSION = 1


def test_high_p1_allowed(client: RaggerClient):
    # We reserve p1 for feature flags, so non-zero bits shouldn't be rejected
    # for forward-compatibility; this allows graceful degradation for optional features.

    # We can't use the client to send this apdu, so we use raw transport.
    # We're only testing that no exception is raised.
    client.transport_client.exchange(
        cla=CLA_BITCOIN,
        ins=INS_GET_MASTER_FINGERPRINT,
        p1=0xff,
        p2=CURRENT_PROTOCOL_VERSION,
        data=b''
    )


def test_p2_too_high(client: RaggerClient):
    # Tests that sending a p2 > CURRENT_PROTOCOL_VERSION fails with 0x6a86 (WRONG_P1P2)
    with pytest.raises(ExceptionRAPDU) as e:
        # We can't use the client to send this apdu, so we use raw transport
        client.transport_client.exchange(
            cla=CLA_BITCOIN,
            ins=INS_GET_MASTER_FINGERPRINT,
            p1=0,
            p2=CURRENT_PROTOCOL_VERSION + 1,
            data=b''
        )
    assert DeviceException.exc.get(e.value.status) == WrongP1P2Error
    assert len(e.value.data) == 0
