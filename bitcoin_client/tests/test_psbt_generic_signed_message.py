import pytest

from bitcoin_client.ledger_bitcoin.errors import PSBTSerializationError
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint


def make_psbt(message=None) -> PSBT:
    """A PSBTv0 with one input and one bare OP_RETURN output, like a BIP-322 to_sign."""
    tx = CTransaction()
    tx.nVersion = 0
    tx.vin = [CTxIn(COutPoint(1, 0), b"", 0)]
    tx.vout = [CTxOut(0, b"\x6a")]

    psbt = PSBT(tx)
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]
    psbt.generic_signed_message = message
    return psbt


def roundtrip(psbt: PSBT) -> PSBT:
    result = PSBT()
    result.deserialize(psbt.serialize())
    return result


@pytest.mark.parametrize("message", [b"Hello World", b""])
def test_generic_signed_message_roundtrip(message: bytes):
    """PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (BIP-322) is kept in both PSBT versions."""
    psbt = make_psbt(message)

    psbt_v0 = roundtrip(psbt)
    assert psbt_v0.version == 0
    assert psbt_v0.generic_signed_message == message
    assert psbt_v0.unknown == {}

    psbt_v0.convert_to_v2()
    psbt_v2 = roundtrip(psbt_v0)
    assert psbt_v2.version == 2
    assert psbt_v2.generic_signed_message == message

    psbt_v2.convert_to_v0()
    assert roundtrip(psbt_v2).generic_signed_message == message


def test_generic_signed_message_absent():
    psbt = roundtrip(make_psbt())
    assert psbt.generic_signed_message is None


def test_generic_signed_message_key_with_keydata():
    # the field has no keydata
    psbt = make_psbt()
    psbt.unknown[b"\x09\x00"] = b"Hello World"
    with pytest.raises(PSBTSerializationError):
        roundtrip(psbt)


def test_generic_signed_message_duplicate_key():
    psbt = make_psbt(b"Hello World")
    psbt.unknown[b"\x09"] = b"x"
    with pytest.raises(PSBTSerializationError):
        roundtrip(psbt)
