import base64

import pytest

from bitcoin_client.ledger_bitcoin._serialize import ser_string
from bitcoin_client.ledger_bitcoin.errors import PSBTSerializationError
from bitcoin_client.ledger_bitcoin.psbt import PSBT
from bitcoin_client.ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint


LOCKTIME = 800000


def make_psbt_v0(input_entries: bytes = b"", output_entries: bytes = b"") -> str:
    """A serialized PSBTv0 with one input and one output, with the given (raw) map entries."""
    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = LOCKTIME
    tx.vin = [CTxIn(COutPoint(1, 0), b"", 0xfffffffe)]
    tx.vout = [CTxOut(1000, b"\x6a")]

    psbt = (
        b"psbt\xff"
        + ser_string(b"\x00") + ser_string(tx.serialize_without_witness())  # PSBT_GLOBAL_UNSIGNED_TX
        + b"\x00"  # end of global map
        + input_entries + b"\x00"  # end of input map
        + output_entries + b"\x00"  # end of output map
    )
    return base64.b64encode(psbt).decode()


def entry(key_type: int, value: bytes) -> bytes:
    return ser_string(bytes([key_type])) + ser_string(value)


@pytest.mark.parametrize("input_entry", [
    entry(0x0e, bytes(32)),                     # PSBT_IN_PREVIOUS_TXID
    entry(0x0f, (0).to_bytes(4, "little")),     # PSBT_IN_OUTPUT_INDEX
    entry(0x10, (0).to_bytes(4, "little")),     # PSBT_IN_SEQUENCE
    entry(0x11, (900000000).to_bytes(4, "little")),  # PSBT_IN_REQUIRED_TIME_LOCKTIME
    entry(0x12, (900000).to_bytes(4, "little")),     # PSBT_IN_REQUIRED_HEIGHT_LOCKTIME
])
def test_psbt_v0_rejects_v2_only_input_fields(input_entry: bytes):
    psbt = PSBT()
    with pytest.raises(PSBTSerializationError, match="not allowed in PSBTv0"):
        psbt.deserialize(make_psbt_v0(input_entries=input_entry))


@pytest.mark.parametrize("output_entry", [
    entry(0x03, (1000).to_bytes(8, "little")),  # PSBT_OUT_AMOUNT
    entry(0x04, b"\x6a"),                       # PSBT_OUT_SCRIPT
])
def test_psbt_v0_rejects_v2_only_output_fields(output_entry: bytes):
    psbt = PSBT()
    with pytest.raises(PSBTSerializationError, match="not allowed in PSBTv0"):
        psbt.deserialize(make_psbt_v0(output_entries=output_entry))


def test_psbt_v0_to_v2_keeps_locktime():
    psbt = PSBT()
    psbt.deserialize(make_psbt_v0())

    # required locktimes set programmatically on a PSBTv0 are ignored by the conversion
    psbt.inputs[0].height_locktime = 900000
    psbt.convert_to_v2()

    psbt_v2 = PSBT()
    psbt_v2.deserialize(psbt.serialize())
    assert psbt_v2.version == 2
    assert psbt_v2.get_unsigned_tx().nLockTime == LOCKTIME
