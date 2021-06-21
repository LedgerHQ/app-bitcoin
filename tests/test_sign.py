from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import automation


def sign_from_json(cmd, filepath: Path):
    tx_dct: Dict[str, Any] = json.load(open(filepath, "r"))

    raw_utxos: List[Tuple[bytes, int]] = [
        (bytes.fromhex(utxo_dct["raw"]), output_index)
        for utxo_dct in tx_dct["utxos"]
        for output_index in utxo_dct["output_indexes"]
    ]
    to_address: str = tx_dct["to"]
    to_amount: int = tx_dct["amount"]
    fees: int = tx_dct["fees"]

    sigs = cmd.sign_new_tx(address=to_address,
                           amount=to_amount,
                           fees=fees,
                           change_path=tx_dct["change_path"],
                           sign_paths=tx_dct["sign_paths"],
                           raw_utxos=raw_utxos,
                           lock_time=tx_dct["lock_time"])

    expected_tx = CTransaction.from_bytes(bytes.fromhex(tx_dct["raw"]))
    witnesses = expected_tx.wit.vtxinwit
    for witness, (tx_hash_digest, sign_pub_key, (v, der_sig)) in zip(witnesses, sigs):
        expected_der_sig, expected_pubkey = witness.scriptWitness.stack
        assert expected_pubkey == sign_pub_key
        assert expected_der_sig == der_sig
        pk: VerifyingKey = VerifyingKey.from_string(
            sign_pub_key,
            curve=SECP256k1,
            hashfunc=sha256
        )
        assert pk.verify_digest(signature=der_sig[:-1],  # remove sighash
                                digest=tx_hash_digest,
                                sigdecode=sigdecode_der) is True


#def test_untrusted_hash_sign_fail_nonzero_p1_p2(cmd, transport):
#    # payloads do not matter, should check and fail before checking it (but non-empty is required)
#    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x01, None, b"\x00")
#    assert sw == 0x6B00, "should fail with p1 and p2 both non-zero"
#    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x00, None, b"\x00")
#    assert sw == 0x6B00, "should fail with non-zero p1"
#    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x01, None, b"\x00")
#    assert sw == 0x6B00, "should fail with non-zero p2"


#def test_untrusted_hash_sign_fail_short_payload(cmd, transport):
#    # should fail if the payload is less than 7 bytes
#    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x00, None, b"\x01\x02\x03\x04\x05\x06")
#    assert sw == 0x6700


#@automation("automations/accept.json")
#def test_sign_p2wpkh_accept(cmd):
#    for filepath in Path("data").rglob("p2wpkh/tx.json"):
#        sign_from_json(cmd, filepath)


#@automation("automations/accept.json")
#def test_sign_p2sh_p2wpkh_accept(cmd):
#    for filepath in Path("data").rglob("p2sh-p2wpkh/tx.json"):
#        sign_from_json(cmd, filepath)


#@automation("automations/accept.json")
#def test_sign_p2pkh_accept(cmd):
#    for filepath in Path("data").rglob("p2pkh/tx.json"):
#        sign_from_json(cmd, filepath)


#@automation("automations/reject.json")
#def test_sign_fail_p2pkh_reject(cmd):
#    with pytest.raises(ConditionOfUseNotSatisfiedError):
#        sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")

def test_sign(cmd):
    sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")