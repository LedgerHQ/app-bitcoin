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

    in_tx = transaction.Transaction('0200000002905125de74ccf2772ad166bc7dec6115cd2293f25bebb2c22853a37a1859fb81000000006b483045022100fd3f1d4904a3131f23c427cf35badaa0747aa631e52a172b3fcfadf0268dabe9022034a5f4fd6ca75f9e54279f4b2775e3598db9997c8004a252d8a61e09ca0f091b01210351d088a9964f496a980f5e465c07c3647bf822562237f836cee3390520b261e9feffffff27366e81ca90bdfe13e07a878cadc5b8cfeb17af913dd6b04d6995b91e272262000000006b483045022100ab5c82658cb937e9a2630315e851c12937a3fded88702078f3013642c9796ceb02200c75cfd83839d09afd7accf6d116ca1c65ea0d2aaa366b205a5296868a6f4ea4012103fc2972ec144b6d72e4b8c03b007c2c7f02ac24ee41f5c5f7afe1a089e13ce8e3feffffff0206661500000000001976a91464c3646f741601535a6933367f30684ed7ab002788ac00000000000000003176a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188acc01572766e74085343414d434f494e00e1f505000000007556ae1b00')
    vin_prevout = transaction.TxOutpoint.from_str('bfefc88012690f1de0c75a972d3f0b6e3f7ad6e6dd9b95770d92f26d72c9ba8e:1')
    vin = transaction.PartialTxInput(prevout=vin_prevout, script_sig=bytes.fromhex('76a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188acc01572766e74085343414d434f494e00e1f5050000000075'))
    vin.utxo = in_tx
    vin.script_type = 'p2pkh'
    vin.pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']

    in_tx2 = transaction.Transaction('0200000002f9b3284f2483378bbbe6547c990e235eb28c116c1668104d658497fc6ce7ec61000000006a473044022041a7a065faa2ba5a22723c5393d915abe6ab7ef51e6ec9a810c925cfa4dffbbd022027a0f9ca5220cf6ddc5295cbeb76b82254955099c63a4fe6ad4945356b501481012103486e130d517cc6f2b8e4fa435f7885ed1514ac0797cc37f906e58abd49ae3592feffffffc6663d94a04fa54d1d066abdcd5170ca4a180de44eb34e0942f33eb5a5ea73cd000000006a4730440220653a82aa1a46d4d3b0f101aab6bffdb1cc5ccff2d10e3ff08e701493a8677e640220019582b798b2611951d1a8c297eddde1e9aa5719706aa623cff9c7e86b0b2bb70121036e41ad9136a9dd1c2942fa63ad336c52a3c90839d3fd076e364aaf97c4748e57feffffff0269d88d00000000001976a9146d3f15868643bcf95224f0cc865b680386cfb8ef88ac00e1f505000000001976a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188ac59ae1b00')
    vin_prevout = transaction.TxOutpoint.from_str('8dec0a2c4921ede211df3097f3ceed59d0ad099d353e728f5a39ca309d220440:1')
    vin2 = transaction.PartialTxInput(prevout=vin_prevout, script_sig=bytes.fromhex('76a914edb982a5fbd46f6e12e6a6402e0dfcd791acadd188ac'))
    vin2.utxo = in_tx2
    vin2.script_type = 'p2pkh'
    vin2.pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']

    inputs = [
        vin,
        vin2
    ]

    vout = transaction.PartialTxOutput(value=0, scriptpubkey=bytes.fromhex('76a9146d3f15868643bcf95224f0cc865b680386cfb8ef88acc01572766e74085343414d434f494e00e1f5050000000075'))

    outputs = [
        vout
    ]

    tx._inputs = inputs
    tx._outputs = outputs

    changePath = ''

    #RWxATTuFXo82CwgixG7Q6npT7JBvDM3Jw9
    #edb982a5fbd46f6e12e6a6402e0dfcd791acadd1
    pubkeys = [b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b',
               b'\x04\x1c\x8a\xab\x06r\xf0\x1d\x10K\x9a9\xc8&\xb2dF\xc8[\xdc\xd1b=\xbf\xb0n\xca\xd6Q\x93W<\xe2\xe0\xec\x18z\xb3X\xc5\xfe\xc0Q\xad\xbe\xeera\xd0\xb4\xc4Y\xe6\xc8\x8b\x7f\\\xcd\xf1x\xbaDS\xe1\x1b']
    inputsPaths = ["44'/175'/0'/0/0",
                   "44'/175'/0'/0/0"]

    sign_transaction(cmd, tx, pubkeys, inputsPaths, changePath)

    print(tx.is_complete())
    print(tx.serialize())

#@automation("automations/reject.json")
#def test_sign_fail_p2pkh_reject(cmd):
#    with pytest.raises(ConditionOfUseNotSatisfiedError):
#        sign_from_json(cmd, "./data/one-to-one/p2pkh/tx.json")