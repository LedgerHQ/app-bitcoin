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

    in_tx = transaction.Transaction('0100000004f920881040f729ea2b8babd490598fe7cf5505dd9c126b16f26f8c78c63ca4ff0d0000006b483045022100a29f19cf246734c92c8db7560a23e75439b5a10c29aee685b120c63e736e5aae02206f176de9d51352358fd1107bc177c87140ef7c81cb826e31832482ee2ed99ab40121038b7583b785bb79322b6b48428a031d1f0eaf96e3ecb29e2caf506d54b049ce9affffffff6f4aef2eee7799a3bde398444241d3ca9da0490853a72a23743af821b9ddef4e010000006b483045022100dd12647f9a01a008a20e90c16e983c31d4faeea5e92d7f16ff2f6e29e37acfd20220151b69e509a9bc6343a251718b44391072a2dce628194d02c3835f71682aff500121029ef0491fbfb8926c9458e26bb1c6a5065b4b6556f378245c2e6adb354d999711ffffffff9cb900264d07430bf287e2b7b31e4c305d70f420dff7c19e14d3685da9e35129010000006a473044022073738f4a1a0f099a58785149f1fb82091dbb35d3cc4e91d21adc57ff142d6d4e02206d054c2eb52b75f8a651c02bbcb508712e80de120a9eac4bca598eed74bf47b90121025643f032b617d5f052f6d8cd9f2d40934d117cda0b62a6adeb4267d0d892910effffffff8651d6b8c2196da71adbca724c974a478dca12959390baa0bc03827d39c0f286000000006b48304502210089610c65c1c462d947c663968500023b58c09dbc3a0dfec23a4660cbb5a5f1340220210c0b45183f8c1b939c22574247311f1289feafae53749cc1a144b00e9151dd0121038b7583b785bb79322b6b48428a031d1f0eaf96e3ecb29e2caf506d54b049ce9affffffff02ba224d3c000000001976a9149730c97deaedf77d8d9c707a506bca4babadaf6988ac00000000000000003176a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188acc01572766e74085343414d434f494e00a3e111000000007500000000')
    vin_prevout = transaction.TxOutpoint.from_str('2bdf24964a886019673d9bae2e579f610d56da7bdbe50de98a8583fd19f65e67:1')
    vin = transaction.PartialTxInput(prevout=vin_prevout, script_sig=bytes.fromhex('76a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188acc01572766e74085343414d434f494e00a3e1110000000075'))
    vin.utxo = in_tx
    vin.script_type = 'p2pkh'
    vin.pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']

    inputs = [
        vin
    ]

    vout = transaction.PartialTxOutput(value=0, scriptpubkey=b'v\xa9\x14\x970\xc9}\xea\xed\xf7}\x8d\x9cpzPk\xcaK\xab\xad\xafi\x88\xac\xc0\x15rvno\x09SCAMCOIN!u')

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