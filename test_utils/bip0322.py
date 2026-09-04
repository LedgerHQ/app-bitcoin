"""Helpers to build and verify BIP-322 message-signing PSBTs for the tests.

BIP-322 defines message signing as signing a virtual "to_sign" transaction that spends a
virtual "to_spend" transaction committing to the message. The PSBT-based flow (BIP-322 v1.0.0+)
carries the message in the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) global field, which the
signing device uses to recognize the request and display a message-signing UI.
"""

import base64
import struct
from hashlib import sha256
from typing import List

from bitcoin_client.ledger_bitcoin import WalletPolicy
from bitcoin_client.ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import (CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness)
from bitcoin_client.ledger_bitcoin._serialize import ser_compact_size, ser_string, ser_uint256

from test_utils import hash160, hash256
from test_utils.txmaker import (getScriptPubkeyFromWallet, fill_inout,
                                createFakeWalletTransaction)
from test_utils.wallet_policy import DescriptorTemplate

PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = 0x09

BIP0322_TAG = b"BIP0322-signed-message"


def bip0322_message_hash(message: bytes) -> bytes:
    """The BIP-340 tagged hash of the message, with tag "BIP0322-signed-message"."""
    tag_hash = sha256(BIP0322_TAG).digest()
    return sha256(tag_hash + tag_hash + message).digest()


def build_to_spend_tx(message: bytes, challenge_script: bytes) -> CTransaction:
    """Builds the virtual to_spend transaction for the given message and scriptPubKey."""
    to_spend = CTransaction()
    to_spend.nVersion = 0
    to_spend.nLockTime = 0

    txin = CTxIn()
    txin.prevout = COutPoint(0, 0xFFFFFFFF)
    txin.scriptSig = b"\x00\x20" + bip0322_message_hash(message)
    txin.nSequence = 0

    to_spend.vin = [txin]
    to_spend.vout = [CTxOut(0, challenge_script)]
    to_spend.wit = CTxWitness()
    to_spend.rehash()
    return to_spend


def build_bip322_psbt(wallet_policy: WalletPolicy,
                      message: bytes,
                      *,
                      is_change: bool = False,
                      address_index: int = 0,
                      tx_version: int = 0) -> PSBT:
    """Builds the PSBT of the BIP-322 to_sign transaction for the given wallet policy address
    and message, with the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE global field set."""

    challenge_script = bytes(getScriptPubkeyFromWallet(
        wallet_policy, is_change, address_index).data)
    to_spend = build_to_spend_tx(message, challenge_script)

    tx = CTransaction()
    tx.nVersion = tx_version
    tx.nLockTime = 0

    txin = CTxIn()
    txin.prevout = COutPoint(to_spend.sha256, 0)
    txin.scriptSig = b""
    txin.nSequence = 0

    tx.vin = [txin]
    tx.vout = [CTxOut(0, b"\x6a")]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0

    # Fill the global xpub map: each root key in the wallet policy maps to its key origin info
    for key_info_str in wallet_policy.keys_info:
        key_origin_end_pos = key_info_str.find("]")
        if key_origin_end_pos == -1:
            root_pubkey = ExtendedKey.deserialize(key_info_str)
            fpr = hash160(root_pubkey.pubkey)[:4]
            key_origin = KeyOriginInfo(fpr, [])
        else:
            root_pubkey = ExtendedKey.deserialize(key_info_str[key_origin_end_pos + 1:])
            key_origin = KeyOriginInfo.from_string(key_info_str[1:key_origin_end_pos])
        psbt.xpub[root_pubkey.serialize()] = key_origin

    psbt_input = PartiallySignedInput(0)

    desc_tmpl = DescriptorTemplate.from_string(wallet_policy.descriptor_template)
    if desc_tmpl.is_segwit():
        psbt_input.witness_utxo = to_spend.vout[0]
    if desc_tmpl.is_legacy() or (desc_tmpl.is_segwit() and not desc_tmpl.is_taproot()):
        psbt_input.non_witness_utxo = to_spend

    fill_inout(wallet_policy, psbt_input, is_change=is_change, address_index=address_index)

    psbt.inputs = [psbt_input]
    psbt.outputs = [PartiallySignedOutput(0)]
    psbt.tx = tx

    psbt.unknown[bytes([PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE])] = message

    return psbt


def build_bip322_pof_psbt(wallet_policy: WalletPolicy,
                          message: bytes,
                          utxo_amounts: List[int],
                          *,
                          is_change: bool = False,
                          address_index: int = 0) -> PSBT:
    """Builds a BIP-322 proof-of-funds PSBT: the to_sign transaction additionally spends one
    real (fake, wallet-owned) UTXO per entry of utxo_amounts."""

    psbt = build_bip322_psbt(wallet_policy, message,
                             is_change=is_change, address_index=address_index)

    desc_tmpl = DescriptorTemplate.from_string(wallet_policy.descriptor_template)

    for amount in utxo_amounts:
        prevout, prevout_n, prevout_is_change, prevout_addr_idx = createFakeWalletTransaction(
            1, 2, amount, wallet_policy)

        txin = CTxIn()
        txin.prevout = COutPoint(prevout.sha256, prevout_n)
        txin.scriptSig = b""
        txin.nSequence = 0
        psbt.tx.vin.append(txin)

        psbt_input = PartiallySignedInput(0)
        if desc_tmpl.is_segwit():
            psbt_input.witness_utxo = prevout.vout[prevout_n]
        if desc_tmpl.is_legacy() or (desc_tmpl.is_segwit() and not desc_tmpl.is_taproot()):
            psbt_input.non_witness_utxo = prevout

        fill_inout(wallet_policy, psbt_input, is_change=bool(prevout_is_change),
                   address_index=prevout_addr_idx)

        psbt.inputs.append(psbt_input)

    return psbt


def bip322_pof_segwitv0_sighash_all(to_sign_tx: CTransaction,
                                    input_index: int,
                                    script_code: bytes,
                                    amount: int) -> bytes:
    """BIP-143 SIGHASH_ALL sighash of one input of a (possibly multi-input, proof-of-funds)
    to_sign transaction."""
    hash_prevouts = hash256(
        b"".join(txin.prevout.serialize() for txin in to_sign_tx.vin))
    hash_sequence = hash256(
        b"".join(struct.pack("<I", txin.nSequence) for txin in to_sign_tx.vin))
    hash_outputs = hash256(b"".join(
        struct.pack("<q", txout.nValue) + ser_string(txout.scriptPubKey)
        for txout in to_sign_tx.vout))

    this_input = to_sign_tx.vin[input_index]
    preimage = b"".join([
        struct.pack("<i", to_sign_tx.nVersion),
        hash_prevouts,
        hash_sequence,
        this_input.prevout.serialize(),
        ser_string(script_code),
        struct.pack("<q", amount),
        struct.pack("<I", this_input.nSequence),
        hash_outputs,
        struct.pack("<I", to_sign_tx.nLockTime),
        struct.pack("<I", 1),  # SIGHASH_ALL
    ])
    return hash256(preimage)


def bip322_segwitv0_sighash_all(to_spend: CTransaction,
                                script_code: bytes,
                                tx_version: int = 0) -> bytes:
    """BIP-143 SIGHASH_ALL sighash of the (fixed-form) to_sign transaction spending to_spend."""
    outpoint = ser_uint256(to_spend.sha256) + struct.pack("<I", 0)
    hash_prevouts = hash256(outpoint)
    hash_sequence = hash256(struct.pack("<I", 0))
    hash_outputs = hash256(struct.pack("<q", 0) + ser_string(b"\x6a"))

    preimage = b"".join([
        struct.pack("<i", tx_version),
        hash_prevouts,
        hash_sequence,
        outpoint,
        ser_string(script_code),
        struct.pack("<q", 0),  # amount of the spent output
        struct.pack("<I", 0),  # nSequence
        hash_outputs,
        struct.pack("<I", 0),  # nLockTime
        struct.pack("<I", 1),  # SIGHASH_ALL
    ])
    return hash256(preimage)


def bip322_legacy_sighash_all(to_spend: CTransaction,
                              script_code: bytes,
                              tx_version: int = 0) -> bytes:
    """Legacy SIGHASH_ALL sighash of the (fixed-form) to_sign transaction spending to_spend."""
    ser = b"".join([
        struct.pack("<i", tx_version),
        b"\x01",  # 1 input
        ser_uint256(to_spend.sha256),
        struct.pack("<I", 0),  # prevout index
        ser_string(script_code),  # scriptSig replaced with the script code
        struct.pack("<I", 0),  # nSequence
        b"\x01",  # 1 output
        struct.pack("<q", 0),  # value
        ser_string(b"\x6a"),
        struct.pack("<I", 0),  # nLockTime
        struct.pack("<I", 1),  # SIGHASH_ALL
    ])
    return hash256(ser)


def p2wpkh_script_code(challenge_script: bytes) -> bytes:
    """The BIP-143 script code for a P2WPKH scriptPubKey (0x0014{20-byte key hash})."""
    assert len(challenge_script) == 22 and challenge_script[0:2] == b"\x00\x14"
    return b"\x76\xa9\x14" + challenge_script[2:22] + b"\x88\xac"


def ecdsa_verify(pubkey: bytes, sighash: bytes, sig_der: bytes) -> bool:
    """Verifies a DER-encoded ECDSA signature (without the sighash-type byte)."""
    from embit import ec
    return ec.PublicKey.parse(pubkey).verify(ec.Signature.parse(sig_der), sighash)


def encode_simple_signature(witness_stack: List[bytes]) -> str:
    """Encodes a witness stack as a BIP-322 "simple" signature string (smp prefix)."""
    ser = ser_compact_size(len(witness_stack)) + \
        b"".join(ser_string(item) for item in witness_stack)
    return "smp" + base64.b64encode(ser).decode()
