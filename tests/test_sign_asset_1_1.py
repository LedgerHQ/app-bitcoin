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
from electrum_clone.ledger_sign_funcs import sign_transaction
from electrum_clone.electrumravencoin.electrum import transaction

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
def test_sign_p2pkh_accept(cmd):
    #for filepath in Path("data").rglob("p2pkh/tx.json"):
    #    sign_from_json(cmd, filepath)
    #sign_from_json(cmd, './data/one-to-one/p2pkh/tx.json')

    tx = transaction.PartialTransaction()

    in_tx = transaction.Transaction('020000000115eb8abda69e314c60a693f1499871fe319587df46b24ab9c89b83e1abb6d7bf010000006b483045022100b776d19d402b062cae744374404cf29f586e94683b5c91183abdde4a2587315202205d68a66ffcb0f96d9aba0d2f3787b07b5f200f2dd87fc345598fa096f83128c8012103c2c6118e389d65e1b281bec87efc71aabb1fa485b63e7639037e442ec61ff5fbfeffffff02794beb56531000001976a914d9f6b08d5ec82b61360988d9619e6656d7b9b75c88ac4b5bbb91210200001976a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188acd2ad1b00')
    vin_prevout = transaction.TxOutpoint.from_str('69775d5e61078b15405dfd581713fa2dd4e92231b159e52d80246aead7708693:1')
    vin = transaction.PartialTxInput(prevout=vin_prevout, script_sig=bytes.fromhex('76a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188ac'))
    vin.utxo = in_tx
    vin.script_type = 'p2pkh'
    vin.pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']

    inputs = [
        vin
    ]

    vout = transaction.PartialTxOutput(value=10, scriptpubkey=bytes.fromhex('76a914c57f73045531ac70dc2c09a1da90fff59df5635588ac'))

    outputs = [
        vout
    ]

    tx._inputs = inputs
    tx._outputs = outputs

    changePath = ''

    #RWxATTuFXo82CwgixG7Q6npT7JBvDM3Jw9
    #edb982a5fbd46f6e12e6a6402e0dfcd791acadd1
    pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']
    inputsPaths = ["44'/175'/0'/0/0"]

    sign_transaction(cmd, tx, pubkeys, inputsPaths, changePath)

    print(tx.is_complete())
    print(tx.serialize())

#@automation("automations/reject.json")
#def test_sign_fail_p2pkh_reject(cmd):
#    with pytest.raises(ConditionOfUseNotSatisfiedError):
#        sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")