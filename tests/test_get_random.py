import pytest

from bitcoin_client.exception import IncorrectLengthError


def test_random(cmd):
    r: bytes = cmd.get_random(n=5)
    assert len(r) == 5

    r = cmd.get_random(n=32)
    assert len(r) == 32

    # max lenght is 248!
    with pytest.raises(IncorrectLengthError):
        cmd.get_random(n=249)
