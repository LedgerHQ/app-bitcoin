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

from typing import Tuple, List

from ledgercomm import Transport

from bitcoin_client.hwi.serialization import (CTransaction, CTxIn, CTxOut, COutPoint,
                                              is_witness, is_p2wpkh, is_p2pkh, is_p2sh, hash160)
from bitcoin_client.hwi.bech32 import decode as bech32_decode
from bitcoin_client.hwi.base58 import decode as base58_decode
from bitcoin_client.utils import deser_trusted_input
from bitcoin_client.bitcoin_utils import bip143_digest, compress_pub_key
from bitcoin_client.bitcoin_cmd_builder import AddrType
from bitcoin_client.bitcoin_base_cmd import BitcoinBaseCommand

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

    raw_utxos = []  # (raw utxo, idx of our vin)
    sign_paths = []  # m/44'/175'...
    lock_time = 0

    # Parse the VINS
    utxos: List[Tuple[CTransaction, int, int]] = []
    for raw_tx, output_index in raw_utxos:
        utxo = CTransaction.from_bytes(raw_tx)
        utxos.append((utxo, output_index))

    # Sign our utxos
    sign_pub_keys: List[bytes] = []
    for sign_path in sign_paths:
        sign_pub_key, _, _ = cmd.get_public_key(
            addr_type=AddrType.Legacy,
            bip32_path=sign_path,
            display=False
        )
        sign_pub_keys.append(compress_pub_key(sign_pub_key))

    # Get trusted inputs
    inputs: List[Tuple[CTransaction, bytes]] = [
        (utxo, cmd.get_trusted_input(utxo=utxo, output_index=output_index))
        for utxo, output_index in utxos
    ]

    # Create new tx
    tx: CTransaction = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = lock_time

    # prepare vin
    for i, (utxo, trusted_input) in enumerate(inputs):
        if utxo.sha256 is None:
            utxo.calc_sha256(with_witness=False)

        _, _, _, prev_txid, output_index, _, _ = deser_trusted_input(trusted_input)
        assert prev_txid != utxo.sha256

        script_pub_key: bytes = utxo.vout[output_index].scriptPubKey
        tx.vin.append(CTxIn(outpoint=COutPoint(h=utxo.sha256, n=output_index),
                            scriptSig=script_pub_key,
                            nSequence=0xfffffffd))

    # TODO: these
    tx.vout.append(CTxOut(nValue=0,
                          scriptPubKey=b'v\xa9\x14\xad\xde\t|\xcfw\xea\xc3q-\xbc\x92\tG\x8d \xfc\xc3\x90\xbd\x88\xac\xc0\x15rvnt\x10SCAMCOINSCAMCOIN\x00\xa0rN\x18\t\x00\x00u'))

    tx.vout.append(CTxOut(nValue=0,
                          scriptPubKey=b'v\xa9\x14\xad\xde\t|\xcfw\xea\xc3q-\xbc\x92\tG\x8d \xfc\xc3\x90\xbd\x88\xac\xc0\x15rvno\x05TEST!u'))

    tx.vout.append(CTxOut(nValue=0,
                          scriptPubKey=bytes.fromhex('c014d4a4a095e02cd6a9b3cf15cf16cc42dc63baf3e006042342544301')))

    for i in range(len(tx.vin)):
        self.untrusted_hash_tx_input_start(tx=tx,
                                           inputs=inputs,
                                           input_index=i,
                                           script=tx.vin[i].scriptSig,
                                           is_new_transaction=(i == 0))

    cmd.untrusted_hash_tx_input_finalize(tx=tx,
                                          change_path=change_path)

    sigs: List[Tuple[bytes, bytes, Tuple[int, bytes]]] = []
    for i in range(len(tx.vin)):
        cmd.untrusted_hash_tx_input_start(tx=tx,
                                           inputs=[inputs[i]],
                                           input_index=0,
                                           script=tx.vin[i].scriptSig,
                                           is_new_transaction=False)
        _, _, amount = utxos[i]
        sigs.append(
            (bip143_digest(tx, amount, i),
             sign_pub_keys[i],
             cmd.untrusted_hash_sign(sign_path=sign_paths[i],
                                      lock_time=tx.nLockTime,
                                      sig_hash=1))
        )

    print(sigs)
