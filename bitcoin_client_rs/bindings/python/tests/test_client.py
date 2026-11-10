"""Runs the client against the recorded device transcripts of the Rust client
(bitcoin_client_rs/tests/data), through a transport that replays them."""

import base64
import json
from pathlib import Path
from typing import List, Tuple

import pytest

from ledger_bitcoin import (Client, MultisigWallet, PartialSignature, WalletPolicy, WalletType,
                            AddressType, createClient, UnsupportedAppVersionError)
from ledger_bitcoin.client import BitcoinInsType
from ledger_bitcoin.exception import DeviceException
from ledger_bitcoin.exception.errors import DenyError, UnknownDeviceError
from ledger_bitcoin.transport import ApduException

DATA_DIR = Path(__file__).resolve().parents[3] / "tests" / "data"


def load(name: str) -> list:
    return json.loads((DATA_DIR / name).read_text())


def parse_exchanges(entries: List[str]) -> List[Tuple[bytes, int, bytes]]:
    """(apdu, sw, data) triples from "=> apdu" / "<= response" entries; others are comments."""
    result = []
    command = b""
    for entry in entries:
        entry = entry.replace(" ", "")
        if entry.startswith("=>"):
            command = bytes.fromhex(entry[2:])
        elif entry.startswith("<="):
            response = bytes.fromhex(entry[2:])
            result.append((command, int.from_bytes(response[-2:], "big"), response[:-2]))
    return result


class ReplayTransport:
    """A TransportClient that checks each APDU against a transcript and replays its response."""

    def __init__(self, exchanges: List[Tuple[bytes, int, bytes]]):
        self.exchanges = list(exchanges)
        self.stopped = False

    def apdu_exchange(self, cla: int, ins: int, data: bytes = b"", p1: int = 0, p2: int = 0) -> bytes:
        assert self.exchanges, "unexpected APDU"
        expected, sw, response = self.exchanges.pop(0)
        assert bytes([cla, ins, p1, p2, len(data)]) + data == expected
        if sw != 0x9000:
            raise ApduException(sw, response)
        return response

    def stop(self) -> None:
        self.stopped = True

    def done(self) -> bool:
        return not self.exchanges


@pytest.mark.parametrize("case", load("register_wallet.json"))
def test_register_wallet(case):
    transport = ReplayTransport(parse_exchanges(case["exchanges"] + case["address_exchanges"]))
    wallet = WalletPolicy(case["name"], case["policy"], case["keys"], WalletType(case["version"]))
    with Client(transport) as client:
        wallet_id, wallet_hmac = client.register_wallet(wallet)
    assert transport.done() and transport.stopped
    assert wallet_id == wallet.id
    assert wallet_hmac.hex() == case["hmac"]


@pytest.mark.parametrize("case", load("get_wallet_address.json"))
def test_get_wallet_address(case):
    transport = ReplayTransport(parse_exchanges(case["exchanges"]))
    wallet = WalletPolicy(case["name"], case["policy"], case["keys"])
    hmac = bytes.fromhex(case["hmac"]) if case["hmac"] else None
    address = Client(transport).get_wallet_address(
        wallet, hmac, int(case["change"]), case["address_index"], case["display"])
    assert transport.done()
    assert address == case["address"]


@pytest.mark.parametrize("case", load("get_extended_pubkey.json"))
def test_get_extended_pubkey(case):
    transport = ReplayTransport(parse_exchanges(case["exchanges"]))
    xpub = Client(transport).get_extended_pubkey(case["derivation_path"], case["display"])
    assert transport.done()
    assert xpub == case["result"]


@pytest.mark.parametrize("case", load("sign_psbt.json"))
@pytest.mark.parametrize("psbt_form", ["base64", "bytes", "object"])
def test_sign_psbt(case, psbt_form):
    transport = ReplayTransport(parse_exchanges(case["exchanges"]))
    wallet = WalletPolicy(case["name"], case["policy"], case["keys"])
    hmac = bytes.fromhex(case["hmac"]) if case["hmac"] else None

    class PsbtObject:
        def serialize(self) -> str:
            return case["psbt"]

    psbt = {
        "base64": case["psbt"],
        "bytes": base64.b64decode(case["psbt"]),
        "object": PsbtObject(),
    }[psbt_form]

    results = Client(transport).sign_psbt(psbt, wallet, hmac)
    assert transport.done()

    sigs = [r for _, r in results if isinstance(r, PartialSignature)]
    for sig, expected in zip(sigs, case.get("sigs") or []):
        assert sig.pubkey.hex() == expected["key"]
        assert sig.signature.hex() == expected["sig"]
        assert (sig.tapleaf_hash.hex() if sig.tapleaf_hash else None) == expected.get("tapleaf_hash")
    expected_count = sum(len(case.get(k) or []) for k in ["sigs", "musig_pub_nonces", "musig_partial_signatures"])
    assert len(results) == expected_count


def test_device_errors_raise_the_status_word_exception():
    transport = ReplayTransport([(bytes.fromhex("e105000100"), 0x6985, b"")])
    with pytest.raises(DenyError):
        Client(transport).get_master_fingerprint()

    transport = ReplayTransport([(bytes.fromhex("e105000100"), 0x6123, b"")])
    with pytest.raises(UnknownDeviceError) as e:
        Client(transport).get_master_fingerprint()
    assert repr(BitcoinInsType.GET_MASTER_FINGERPRINT) in str(e.value)


def test_simple_requests():
    transport = ReplayTransport([(bytes.fromhex("e105000100"), 0x9000, bytes.fromhex("f5acc2fd"))])
    assert Client(transport).get_master_fingerprint() == bytes.fromhex("f5acc2fd")

    version_response = b"\x01\x0cBitcoin Test\x052.1.0\x01\x02"
    transport = ReplayTransport([(bytes.fromhex("b001000000"), 0x9000, version_response)])
    assert Client(transport).get_version() == ("Bitcoin Test", "2.1.0", b"\x02")

    transport = ReplayTransport([(bytes.fromhex("b001000000"), 0x9000, version_response)])
    assert isinstance(createClient(transport), Client)

    legacy_response = b"\x01\x0cBitcoin Test\x052.0.6\x01\x02"
    transport = ReplayTransport([(bytes.fromhex("b001000000"), 0x9000, legacy_response)])
    with pytest.raises(UnsupportedAppVersionError):
        createClient(transport)


def test_invalid_arguments_raise_before_any_exchange():
    client = Client(ReplayTransport([]))
    wallet = WalletPolicy("", "tr(@0/**)", [
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"])
    with pytest.raises(ValueError):
        client.get_wallet_address(wallet, None, 2, 0, False)
    with pytest.raises(ValueError):
        client.get_wallet_address(wallet, b"\0" * 31, 0, 0, False)
    with pytest.raises(ValueError):
        client.get_wallet_address("not a wallet", None, 0, 0, False)
    with pytest.raises(ValueError):
        client.get_extended_pubkey("m/x")
    with pytest.raises(ValueError):
        client.sign_psbt(b"not a psbt", wallet, None)
    with pytest.raises(ValueError):
        WalletPolicy("", "tr(@0/**)", ["not a key"]).serialize()
    with pytest.raises(ValueError):
        WalletPolicy("", "tr(@0/**)", [], 3)


def test_wallet_policy_serialization():
    wallet = MultisigWallet(
        "Cold storage",
        AddressType.WIT,
        2,
        [
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )
    assert wallet.descriptor_template == "wsh(sortedmulti(2,@0/**,@1/**))"
    assert wallet.serialize().hex() == "020c436f6c642073746f726167651fb56c3d5542fa09b3956834a9ff6a1df5c36a38e5b02c63c54b41a9a04403b82602516d2c50a89476ecffeec658057f0110674bbfafc18797dc480c7ed53802f3fb"
    import hashlib
    assert wallet.id == hashlib.sha256(wallet.serialize()).digest()
    assert wallet.get_descriptor(True).endswith("/1/*))")
