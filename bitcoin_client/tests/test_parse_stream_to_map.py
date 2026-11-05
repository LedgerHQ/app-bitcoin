import base64
from io import BytesIO

import pytest

from bitcoin_client.ledger_bitcoin.client import NewClient, parse_stream_to_map
from bitcoin_client.ledger_bitcoin.errors import PSBTSerializationError
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint
from bitcoin_client.ledger_bitcoin.wallet import WalletPolicy


def make_psbt_v2() -> PSBT:
    """A PSBTv2 with one input and one output."""
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(1, 0), b"", 0)]
    tx.vout = [CTxOut(1000, b"\x6a")]

    psbt = PSBT(tx)
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]
    psbt.convert_to_v2()
    return psbt


def parse_output_map(psbt: PSBT):
    f = BytesIO(base64.b64decode(psbt.serialize()))
    assert f.read(5) == b"psbt\xff"
    parse_stream_to_map(f)  # global map
    parse_stream_to_map(f)  # input map
    return parse_stream_to_map(f)


def test_parse_stream_to_map():
    output_map = parse_output_map(make_psbt_v2())
    assert output_map[b"\x03"] == (1000).to_bytes(8, "little")
    assert output_map[b"\x04"] == b"\x6a"


def test_parse_stream_to_map_rejects_duplicate_keys():
    # an unknown entry colliding with PSBT_OUT_AMOUNT is serialized as a duplicate key
    psbt = make_psbt_v2()
    psbt.outputs[0].unknown[b"\x03"] = (1).to_bytes(8, "little")

    with pytest.raises(ValueError, match="Duplicate key"):
        parse_output_map(psbt)


class NoDeviceTransport:
    def apdu_exchange(self, *args, **kwargs):
        raise AssertionError("no APDU must be sent")


@pytest.mark.parametrize("as_base64", [False, True])
def test_sign_psbt_rejects_trailing_data(as_base64: bool):
    psbt_bytes = base64.b64decode(make_psbt_v2().serialize()) + b"\x00"
    psbt = base64.b64encode(psbt_bytes).decode() if as_base64 else psbt_bytes

    wallet = WalletPolicy("", "wpkh(@0/**)", ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"])
    client = NewClient(NoDeviceTransport())
    with pytest.raises(PSBTSerializationError, match="trailing data"):
        client.sign_psbt(psbt, wallet, None)


# Dropping 1 byte removes the separator of the last output map; dropping 2 bytes also truncates
# the value of its last entry. Reserializing the PSBT would restore the missing bytes, so these
# must be rejected while deserializing.
@pytest.mark.parametrize("as_base64", [False, True])
@pytest.mark.parametrize("n_dropped", [1, 2])
def test_sign_psbt_rejects_truncated_psbt(as_base64: bool, n_dropped: int):
    psbt_bytes = base64.b64decode(make_psbt_v2().serialize())[:-n_dropped]
    psbt = base64.b64encode(psbt_bytes).decode() if as_base64 else psbt_bytes

    wallet = WalletPolicy("", "wpkh(@0/**)", ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"])
    client = NewClient(NoDeviceTransport())
    with pytest.raises((PSBTSerializationError, ValueError)):
        client.sign_psbt(psbt, wallet, None)
