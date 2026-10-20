import pytest

from bitcoin_client.ledger_bitcoin.errors import PSBTSerializationError
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint


MUSIG2_SESSION_ID_KEY = bytes.fromhex("fc11") + b"MUSIG2_SESSION_ID" + b"\x00"


def make_psbt(session_id=None) -> PSBT:
    """A PSBTv0 with one input and one output."""
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(1, 0), b"", 0)]
    tx.vout = [CTxOut(0, b"\x6a")]

    psbt = PSBT(tx)
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]
    psbt.musig2_session_id = session_id
    return psbt


def roundtrip(psbt: PSBT) -> PSBT:
    result = PSBT()
    result.deserialize(psbt.serialize())
    return result


def test_musig2_session_id_key():
    assert PSBT.PSBT_GLOBAL_MUSIG2_SESSION_ID_KEY == MUSIG2_SESSION_ID_KEY
    assert len(MUSIG2_SESSION_ID_KEY) == 20


@pytest.mark.parametrize("session_id", [bytes(range(32)), b"\x01"])
def test_musig2_session_id_roundtrip(session_id: bytes):
    """The MUSIG2_SESSION_ID proprietary field is kept in both PSBT versions."""
    psbt = make_psbt(session_id)

    psbt_v0 = roundtrip(psbt)
    assert psbt_v0.version == 0
    assert psbt_v0.musig2_session_id == session_id
    assert psbt_v0.unknown == {}

    psbt_v0.convert_to_v2()
    psbt_v2 = roundtrip(psbt_v0)
    assert psbt_v2.version == 2
    assert psbt_v2.musig2_session_id == session_id

    psbt_v2.convert_to_v0()
    assert roundtrip(psbt_v2).musig2_session_id == session_id


def test_musig2_session_id_absent():
    psbt = roundtrip(make_psbt())
    assert psbt.musig2_session_id is None


def test_musig2_session_id_set_as_unknown():
    # a field set by a tool that does not know about it is parsed as well
    psbt = make_psbt()
    psbt.unknown[MUSIG2_SESSION_ID_KEY] = b"\x42" * 32
    psbt = roundtrip(psbt)
    assert psbt.musig2_session_id == b"\x42" * 32
    assert psbt.unknown == {}


def test_musig2_session_id_other_proprietary_keys():
    # different subtype or keydata: not the MUSIG2_SESSION_ID field
    psbt = make_psbt()
    psbt.unknown[MUSIG2_SESSION_ID_KEY[:-1] + b"\x01"] = b"\x42"
    psbt.unknown[MUSIG2_SESSION_ID_KEY + b"\x00"] = b"\x43"
    psbt = roundtrip(psbt)
    assert psbt.musig2_session_id is None
    assert len(psbt.unknown) == 2


def test_musig2_session_id_duplicate_key():
    psbt = make_psbt(b"\x42" * 32)
    psbt.unknown[MUSIG2_SESSION_ID_KEY] = b"\x43" * 32
    with pytest.raises(PSBTSerializationError):
        roundtrip(psbt)
