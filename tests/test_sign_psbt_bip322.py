import hmac
from hashlib import sha256
from io import BytesIO

import pytest

from ledger_bitcoin import MultisigWallet, WalletPolicy, AddressType, PartialSignature
from ledger_bitcoin.exception.errors import (DenyError, IncorrectDataError, NotSupportedError,
                                             SecurityStatusNotSatisfiedError)
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTxIn, CTxOut, COutPoint
from ledger_bitcoin._embit.descriptor.miniscript import Miniscript

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
)
from test_utils.musig2 import HotMusig2Cosigner, derive_plain_descriptor, run_musig2_test
from test_utils.taproot_sighash import TaprootSignatureHash

from .conftest import toggle_nonstandard_sighash_setting
from .instructions import bip322_instruction_approve, message_instruction_reject
from .test_sign_psbt_musig import LedgerMusig2Cosigner

# error codes defined in error_codes.h
EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED = 0x000d
EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE = 0x0010
EC_SIGN_PSBT_BIP322_TOSPEND_MISMATCH = 0x0011
EC_SIGN_PSBT_BIP322_FORBIDDEN_SIGHASH = 0x0012
EC_SIGN_PSBT_BIP322_UNSUPPORTED = 0x0013
EC_SIGN_PSBT_BIP322_EXTERNAL_INPUTS = 0x0015

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02


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


def test_sign_bip322_empty_message(navigator: Navigator, firmware: Firmware,
                                   client: RaggerClient, test_name: str):
    # the empty message is valid (it is one of the BIP's test vectors)
    message = b""
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


def test_sign_bip322_nonprintable_message(navigator: Navigator, firmware: Firmware,
                                          client: RaggerClient, test_name: str):
    # a short message that is not printable ASCII (here, UTF-8) is shown as its sha256 hash
    message = "café".encode()
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


def test_sign_bip322_change_address(navigator: Navigator, firmware: Firmware,
                                    client: RaggerClient, test_name: str):
    # the address being proven may be any address of the account, including a change one
    message = b"Hello World"
    psbt = build_bip322_psbt(wallet_wpkh, message, is_change=True, address_index=5)

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname=test_name)

    assert len(result) == 1
    _, partial_sig = result[0]

    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    to_spend = build_to_spend_tx(message, challenge_script)
    sighash = bip322_segwitv0_sighash_all(to_spend, p2wpkh_script_code(challenge_script))

    assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def test_sign_bip322_reject(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str):
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                         instructions=message_instruction_reject(firmware),
                         testname=test_name)

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


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
    psbt.generic_signed_message = b"Another message"

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_TOSPEND_MISMATCH)


def test_sign_bip322_wrong_prevout_index(navigator: Navigator, firmware: Firmware,
                                         client: RaggerClient, test_name: str):
    # the first input must spend output 0 of to_spend (its only output).
    # Taproot is used so that no non-witness-utxo cross-check rejects the PSBT before the
    # BIP-322 validation does (to_spend has no output at index 1).
    psbt = build_bip322_psbt(wallet_tr, b"Hello World")
    psbt.tx.vin[0].prevout.n = 1

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE,
                           wallet=wallet_tr)


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


def test_sign_bip322_p2tr_explicit_sighash_all(navigator: Navigator, firmware: Firmware,
                                             client: RaggerClient):
    # an explicit SIGHASH_ALL is allowed for taproot inputs too. The review is exactly the one
    # of test_sign_bip322_p2tr, whose snapshots are therefore reused.
    message = b"Hello World"
    psbt = build_bip322_psbt(wallet_tr, message)
    psbt.inputs[0].sighash = SIGHASH_ALL

    result = client.sign_psbt(psbt, wallet_tr, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname="test_sign_bip322_p2tr")

    assert len(result) == 1
    _, partial_sig = result[0]

    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    sighash = TaprootSignatureHash(psbt.tx, [CTxOut(0, challenge_script)], SIGHASH_ALL, 0)

    assert len(partial_sig.signature) == 65
    assert partial_sig.signature[-1] == SIGHASH_ALL
    assert bip0340.schnorr_verify(sighash, partial_sig.pubkey, partial_sig.signature[:-1])


def test_sign_bip322_nondefault_sighash_setting_disabled(navigator: Navigator,
                                                         firmware: Firmware,
                                                         client: RaggerClient, test_name: str):
    # BIP-322 requires SIGHASH_ALL (or SIGHASH_DEFAULT). With the non-standard sighash setting
    # disabled (the default), such a request is refused by the generic sighash gating, before
    # any BIP-322 check (its on-device status screen is covered by test_sighash_setting.py)
    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")
    psbt.inputs[0].sighash = SIGHASH_NONE

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           SecurityStatusNotSatisfiedError,
                           EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED)


def test_sign_bip322_nondefault_sighash_setting_enabled(navigator: Navigator,
                                                        firmware: Firmware,
                                                        client: RaggerClient, test_name: str):
    # with the non-standard sighash setting enabled, the request passes the generic sighash
    # gating, and is then refused by the BIP-322 validation
    toggle_nonstandard_sighash_setting(navigator, firmware)

    psbt = build_bip322_psbt(wallet_wpkh, b"Hello World")
    psbt.inputs[0].sighash = SIGHASH_NONE

    expect_sign_psbt_error(client, navigator, firmware, test_name, psbt,
                           IncorrectDataError, EC_SIGN_PSBT_BIP322_FORBIDDEN_SIGHASH)


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


def test_sign_bip322_proof_of_funds_witness_only_to_spend(navigator: Navigator,
                                                         firmware: Firmware,
                                                         client: RaggerClient):
    # the to_spend input is recomputed on-device, so it never triggers the warning for
    # segwitv0 inputs missing the non-witness utxo, even in a proof-of-funds. The review must
    # be exactly the one of test_sign_bip322_proof_of_funds (same message and amounts), whose
    # snapshots are therefore reused: a warning screen would make the comparison fail.
    message = b"I control these coins"
    utxo_amounts = [123_456, 876_544]
    psbt = build_bip322_pof_psbt(wallet_wpkh, message, utxo_amounts)
    psbt.inputs[0].non_witness_utxo = None

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(firmware),
                              testname="test_sign_bip322_proof_of_funds")

    assert len(result) == 3
    for input_index, partial_sig in result:
        challenge_script = bytes(psbt.inputs[input_index].witness_utxo.scriptPubKey)
        amount = psbt.inputs[input_index].witness_utxo.nValue
        sighash = bip322_pof_segwitv0_sighash_all(psbt.tx, input_index,
                                                  p2wpkh_script_code(challenge_script),
                                                  amount)
        assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


def test_sign_bip322_pof_unverified_input(navigator: Navigator, firmware: Firmware,
                                          client: RaggerClient, test_name: str):
    # a real (proof-of-funds) segwitv0 input missing the non-witness utxo has an unverified
    # amount, which is part of the total shown to the user: the usual warning is shown first
    message = b"I control these coins"
    psbt = build_bip322_pof_psbt(wallet_wpkh, message, [123_456, 876_544])
    psbt.inputs[2].non_witness_utxo = None

    result = client.sign_psbt(psbt, wallet_wpkh, None, navigator,
                              instructions=bip322_instruction_approve(
                                  firmware, has_unverifiedwarning=True),
                              testname=test_name)

    assert len(result) == 3
    for input_index, partial_sig in result:
        challenge_script = bytes(psbt.inputs[input_index].witness_utxo.scriptPubKey)
        amount = psbt.inputs[input_index].witness_utxo.nValue
        sighash = bip322_pof_segwitv0_sighash_all(psbt.tx, input_index,
                                                  p2wpkh_script_code(challenge_script),
                                                  amount)
        assert ecdsa_verify(partial_sig.pubkey, sighash, partial_sig.signature[:-1])


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


def test_sign_bip322_musig_keypath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                   test_name: str, speculos_globals: SpeculosGlobals):
    # BIP-322 message signing for a taproot keypath musig() policy. The device controls one of
    # the two musig participants; the two-round MuSig2 flow runs exactly as for a transaction,
    # except the request is reviewed (and displayed) as a message signature.
    cosigner_1_xpub = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"

    wallet_policy = WalletPolicy(
        name="Musig message signer",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[cosigner_1_xpub, cosigner_2_xpub],
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    message = b"I control this musig address"
    psbt = build_bip322_psbt(wallet_policy, message)

    # the to_sign transaction spends the single virtual to_spend output (a zero-value taproot
    # output), so the sighash is the SIGHASH_DEFAULT taproot keypath sighash over it
    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    sighash = TaprootSignatureHash(psbt.tx, [CTxOut(0, challenge_script)], 0, 0)

    # the device controls one musig participant; a hot cosigner supplies the other
    signer_1 = LedgerMusig2Cosigner(
        client, wallet_policy, wallet_hmac, navigator=navigator,
        instructions=bip322_instruction_approve(firmware, save_screenshot=False),
        testname=test_name)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], [sighash])


def test_sign_bip322_musig_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                      test_name: str, speculos_globals: SpeculosGlobals):
    # BIP-322 message signing for a musig() key expression sitting in a tapscript leaf. The
    # device signs the leaf script path, so the sighash uses the tapscript (leaf) variant.
    cosigner_1_xpub = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = ExtendedKey.deserialize(cosigner_2_xpriv).neutered().to_string()

    wallet_policy = WalletPolicy(
        name="Musig script msg",
        descriptor_template="tr(@0/**,pk(musig(@1,@2)/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            cosigner_1_xpub,
            cosigner_2_xpub,
        ],
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    message = b"Musig in a tapscript leaf"
    psbt = build_bip322_psbt(wallet_policy, message)

    # the device signs the tapscript leaf that contains the musig() key; recompute the leaf
    # script (change=0, address_index=0) to derive the corresponding tapscript sighash
    challenge_script = bytes(psbt.inputs[0].witness_utxo.scriptPubKey)
    leaf_desc = derive_plain_descriptor(
        "pk(musig(@1,@2)/**)", wallet_policy.keys_info, False, 0)
    leaf_script = Miniscript.read_from(
        BytesIO(leaf_desc.encode()), taproot=True).compile()
    sighash = TaprootSignatureHash(psbt.tx, [CTxOut(0, challenge_script)], 0, 0,
                                   scriptpath=True, script=leaf_script)

    signer_1 = LedgerMusig2Cosigner(
        client, wallet_policy, wallet_hmac, navigator=navigator,
        instructions=bip322_instruction_approve(firmware, save_screenshot=False),
        testname=test_name)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], [sighash])
