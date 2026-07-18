import hmac
from hashlib import sha256

import pytest

from ledger_bitcoin import MultisigWallet, WalletPolicy, AddressType, PartialSignature
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTxIn, CTxOut, COutPoint

from ragger.navigator import Navigator
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware

from ragger_bitcoin import RaggerClient

from test_utils import bip0340, SpeculosGlobals
from test_utils.bip0322 import (
    build_bip322_psbt,
    build_bip322_pof_psbt,
    build_to_spend_tx,
    bip322_segwitv0_sighash_all,
    bip322_pof_segwitv0_sighash_all,
    bip322_legacy_sighash_all,
    p2wpkh_script_code,
    ecdsa_verify,
    encode_simple_signature,
    PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
)
from test_utils.taproot_sighash import TaprootSignatureHash

from .instructions import bip322_instruction_approve

# error codes defined in error_codes.h
EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE = 0x000E
EC_SIGN_PSBT_BIP322_TOSPEND_MISMATCH = 0x000F
EC_SIGN_PSBT_BIP322_UNSUPPORTED = 0x0011
EC_SIGN_PSBT_BIP322_EXTERNAL_INPUTS = 0x0013


wallet_wpkh = WalletPolicy(
    "",
    "wpkh(@0/**)",
    [
        "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
    ],
)

wallet_tr = WalletPolicy(
    "",
    "tr(@0/**)",
    [
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
    ],
)

wallet_pkh = WalletPolicy(
    "",
    "pkh(@0/**)",
    [
        "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
    ],
)


def test_sign_bip322_p2wpkh(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str):
    message = b"Hello World"
    psbt = build_bip322_psbt(wallet_wpkh, message)

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 1
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert isinstance(partial_sig, PartialSignature)

    # verify the returned signature against the independently recomputed BIP-143 sighash of
    # the to_sign transaction
    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    to_spend = build_to_spend_tx(message, challenge_script)
    sighash = bip322_segwitv0_sighash_all(to_spend, p2wpkh_script_code(challenge_script))

    assert partial_sig.signature[-1] == 1  # SIGHASH_ALL
    assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])

    # assemble and print the final BIP-322 "simple" signature, for reference
    signature = encode_simple_signature(
        [partial_sig.signature, partial_sig.pubkey])
    print(f"BIP-322 signature for {test_name}: {signature}")


def test_sign_bip322_p2tr(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                          test_name: str):
    message = b"Hello World"
    psbt = build_bip322_psbt(wallet_tr, message)

    result = client.sign_psbt(psbt, wallet_tr, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 1
    input_index, partial_sig = result[0]
    assert input_index == 0

    # verify the schnorr signature against the recomputed BIP-341 sighash (SIGHASH_DEFAULT)
    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    sighash = TaprootSignatureHash(psbt.tx, [CTxOut(0, challenge_script)], 0, 0)

    assert len(partial_sig.signature) == 64  # SIGHASH_DEFAULT: no sighash byte appended
    assert bip0340.schnorr_verify(sighash, partial_sig.pubkey, partial_sig.signature)

    signature = encode_simple_signature([partial_sig.signature])
    print(f"BIP-322 signature for {test_name}: {signature}")


def test_sign_bip322_p2pkh(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                           test_name: str):
    # legacy addresses use the "full" variant of BIP-322; the firmware flow is the same
    message = b"Hello World"
    psbt = build_bip322_psbt(wallet_pkh, message)

    result = client.sign_psbt(psbt, wallet_pkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 1
    _, partial_sig = result[0]

    challenge_script = bytes(psbt.inputs[0].non_witness_utxo.vout[0].scriptPubKey)
    to_spend = build_to_spend_tx(message, challenge_script)
    sighash = bip322_legacy_sighash_all(to_spend, challenge_script)

    assert partial_sig.signature[-1] == 1  # SIGHASH_ALL
    assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def test_sign_bip322_multisig(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                              test_name: str, speculos_globals: SpeculosGlobals):
    # a registered multisig policy, as used by coordinators like Liana
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet.id, sha256).digest()

    message = b"I own this multisig"
    psbt = build_bip322_psbt(wallet, message)

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    # the device controls one of the two keys
    assert len(result) == 1
    _, partial_sig = result[0]

    # for P2WSH, the BIP-143 script code is the witness script itself
    witness_script = bytes(psbt.inputs[0].witness_script)
    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    assert challenge_script == b"\x00\x20" + sha256(witness_script).digest()

    to_spend = build_to_spend_tx(message, challenge_script)
    sighash = bip322_segwitv0_sighash_all(to_spend, witness_script)

    assert partial_sig.signature[-1] == 1  # SIGHASH_ALL
    assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def test_sign_bip322_long_message(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                  test_name: str):
    # messages that are too long (or not printable) are shown as their sha256 hash
    message = b"A" * 1000
    psbt = build_bip322_psbt(wallet_wpkh, message)

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 1
    _, partial_sig = result[0]

    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    to_spend = build_to_spend_tx(message, challenge_script)
    sighash = bip322_segwitv0_sighash_all(to_spend, p2wpkh_script_code(challenge_script))

    assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def expect_sign_psbt_error(client: RaggerClient, navigator: Navigator, firmware: Firmware,
                           test_name: str, psbt: PSBT, expected_error, expected_ec: int,
                           wallet=wallet_wpkh, wallet_hmac=None):
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                         instructions=bip322_instruction_approve(firmware,
                                                                 save_screenshot=False),
                         testname=test_name)

    assert DeviceException.exc.get(e.value.status) == expected_error
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, byteorder='big')
    assert error_code == expected_ec


def test_sign_bip322_wrong_message(navigator: Navigator, firmware: Firmware,
                                   client: RaggerClient, test_name: str):
    # the message in the global field is not the message committed in the transaction:
    # the device must refuse (it would otherwise display a message different from the one
    # being signed)
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")
    psbt.unknown[bytes([PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE])] = b"Another message"

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_TOSPEND_MISMATCH)


def test_sign_bip322_nonzero_amount(navigator: Navigator, firmware: Firmware,
                                    client: RaggerClient, test_name: str):
    # a real spend disguised with the BIP-322 global field must be refused.
    # Taproot is used so that no non-witness-utxo cross-check rejects the PSBT before the
    # BIP-322 validation does (for segwit v0 inputs, the existing utxo consistency checks
    # already refuse such a PSBT with a different error code).
    psbt = build_bip322_psbt(wallet_tr, b"Hello World")
    psbt.inputs[0].witness_utxo.nValue = 100_000
    psbt.tx.vout[0].nValue = 100_000

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE,
                           wallet=wallet_tr)


def test_sign_bip322_opreturn_with_data(navigator: Navigator, firmware: Firmware,
                                        client: RaggerClient, test_name: str):
    # the output must be a bare OP_RETURN, with no data push
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")
    psbt.tx.vout[0].scriptPubKey = b"\x6a\x04test"

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE)


def test_sign_bip322_extra_output(navigator: Navigator, firmware: Firmware,
                                  client: RaggerClient, test_name: str):
    # exactly one output is allowed

    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")
    psbt.tx.vout.append(CTxOut(0, b"\x6a"))
    psbt.outputs.append(PartiallySignedOutput(0))

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE)


def test_sign_bip322_wrong_tx_version(navigator: Navigator, firmware: Firmware,
                                      client: RaggerClient, test_name: str):
    # the to_sign transaction version must be 0 or 2
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World", tx_version=3)

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE)


def test_sign_bip322_locktime_unsupported(navigator: Navigator, firmware: Firmware,
                                          client: RaggerClient, test_name: str):
    # timelocked BIP-322 signatures are valid per the BIP, but not supported yet
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World", tx_version=2)
    psbt.tx.nLockTime = 800_000

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           NotSupportedError, EC_SIGN_PSBT_BIP322_UNSUPPORTED)


def test_sign_bip322_proof_of_funds(navigator: Navigator, firmware: Firmware,
                                    client: RaggerClient, test_name: str):
    # proof-of-funds: the to_sign transaction additionally spends real wallet UTXOs, whose
    # total amount is shown on the device
    message = b"I control these coins"
    utxo_amounts = [123_456, 876_544]  # 0.01 BTC total
    psbt = build_bip322_pof_psbt(wallet_wpkh, message, utxo_amounts)

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    # one signature per input: the virtual to_spend input plus the two real UTXOs
    assert len(result) == 3
    assert sorted(idx for idx, _ in result) == [0, 1, 2]

    for input_index, partial_sig in result:
        challenge_script = bytes(psbt.inputs[input_index].witness_utxo.scriptPubKey)
        amount = psbt.inputs[input_index].witness_utxo.nValue
        sighash = bip322_pof_segwitv0_sighash_all(psbt.tx, input_index,
                                                  p2wpkh_script_code(challenge_script),
                                                  amount)
        assert partial_sig.signature[-1] == 1  # SIGHASH_ALL
        assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def test_sign_bip322_proof_of_funds_p2tr(navigator: Navigator, firmware: Firmware,
                                         client: RaggerClient, test_name: str):
    message = b"I control these coins"
    utxo_amounts = [42_000]
    psbt = build_bip322_pof_psbt(wallet_tr, message, utxo_amounts)

    result = client.sign_psbt(psbt, wallet_tr, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 2
    assert sorted(idx for idx, _ in result) == [0, 1]

    spent_utxos = [CTxOut(inp.witness_utxo.nValue, bytes(inp.witness_utxo.scriptPubKey))
                   for inp in psbt.inputs]

    for input_index, partial_sig in result:
        sighash = TaprootSignatureHash(psbt.tx, spent_utxos, 0, input_index)
        assert len(partial_sig.signature) == 64  # SIGHASH_DEFAULT
        assert bip0340.schnorr_verify(sighash, partial_sig.pubkey, partial_sig.signature)


def test_sign_bip322_pof_external_input(navigator: Navigator, firmware: Firmware,
                                        client: RaggerClient, test_name: str):
    # every input of a proof-of-funds must belong to the wallet policy: the proven total
    # shown to the user must be trustworthy
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")

    txin = CTxIn()
    txin.prevout = COutPoint(12345, 0)
    txin.scriptSig = b""
    txin.nSequence = 0
    psbt.tx.vin.append(txin)

    external_input = PartiallySignedInput(0)
    external_input.witness_utxo = CTxOut(5000, b"\x00\x14" + bytes(20))
    psbt.inputs.append(external_input)

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_EXTERNAL_INPUTS)
