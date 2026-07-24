import copy
import pytest
from pathlib import Path
from ledger_bitcoin import WalletPolicy, MultisigWallet, AddressType
from ledger_bitcoin.exception.errors import NotSupportedError, IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT, PartiallySignedOutput
from test_utils import bip0340
from ragger.navigator import Navigator
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient

from .conftest import toggle_nonstandard_sighash_setting
from .instructions import sign_psbt_instruction_approve
tests_root: Path = Path(__file__).parent

tr_wallet = WalletPolicy(
    "",
    "tr(@0/**)",
    [
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
    ],
)

wpkh_wallet = WalletPolicy(
    "",
    "wpkh(@0/**)",
    [
        "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
    ],
)


# Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
# Therefore, for this testcase we hard-code the sighash, and we verify the produced Schnorr signature with the reference bip340 implementation.
sighash_bitcoin_core_all_0 = bytes.fromhex("2221AA462110C77A8E2DD34C3681BAA9BFFF6553B4C609EC7E3D8FF9B1D18D69")
sighash_bitcoin_core_all_1 = bytes.fromhex("D47D3FA22B4F6C50521C49E1A42E8CB10689540A227491A8FC5AD0A6E413063E")
sighash_bitcoin_core_none_0 = bytes.fromhex("965976D58A387369D970F0B6560B144E1B721D41E04675592C41AC35D30D2A56")
sighash_bitcoin_core_none_1 = bytes.fromhex("67E85534A12E4054F4AFAA434D7A7C38123DA6909DF7E45DDB9945F7B8D832D0")
sighash_bitcoin_core_single_0 = bytes.fromhex("F9B834D7FE272F9EACE2FC5F7A97468B024438EF5D55338FC243D5273534A6B5")
sighash_bitcoin_core_single_1 = bytes.fromhex("9A4DDC13C6D0EE10A41D33C6595C63F51AF4C9314387685304F515F790260F78")
sighash_bitcoin_core_all_anyone_0 = bytes.fromhex("09A6559AF84C48C8D5A7984C5A72E53ED88D160AABAE99C18F00E78A55E7EDC7")
sighash_bitcoin_core_all_anyone_1 = bytes.fromhex("9B25C319E12F4755D8A43F3295B8C61B861FB23D7EBF7F9A25E6E8CE3242F939")
sighash_bitcoin_core_none_anyone_0 = bytes.fromhex("8FCEFFAE04D320E05DE04034069FE6AF8C7CBCC93CDE3F187AB0DEC202692735")
sighash_bitcoin_core_none_anyone_1 = bytes.fromhex("A06D37C1C8EEE7EA145F9D8A98CBE79F6BB1691B37F8F26F49F8318F9443B766")
sighash_bitcoin_core_single_anyone_0 = bytes.fromhex("971886B247797E0A616489B449B5E78AE8EC63E54B55727AF626B964DD8F329D")
sighash_bitcoin_core_single_anyone_1 = bytes.fromhex("6B130F2BE5467A8BC36227B8C2A082B46CA24F91A6A6A54AA5EFA4901BE5ADBB")


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


def test_sighash_all_sign_psbt(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    _, partial_sig0 = result[0]
    assert len(partial_sig0.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x01

    _, partial_sig1 = result[1]
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig1.signature[-1] == 0x01

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_all_input_modified(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1
    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_all_output_modified(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1
    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_none_sign_psbt(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64+1
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x02
    assert partial_sig1.signature[-1] == 0x02

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_none_input_modified(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_none_output_modified(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_sign_psbt(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64+1
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x03
    assert partial_sig1.signature[-1] == 0x03

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_input_modified(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vin[1].nSequence = psbt.tx.vin[1].nSequence - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_single_output_same_index_modified(navigator: Navigator, firmware: Firmware, client:
                                                   RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_output_different_index_modified(navigator: Navigator, firmware: Firmware,
                                                        client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")
    psbt.tx.vout[1].nValue = psbt.tx.vout[1].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_single_3_ins_2_out(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-3-ins-2-outs.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError

    # defined in error_codes.h
    EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE = 0x0008

    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE


def test_sighash_all_anyone_sign(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64+1
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x81
    assert partial_sig1.signature[-1] == 0x81

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_all_anyone_input_changed(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_all_anyone_output_changed(navigator: Navigator, firmware: Firmware, client:
                                           RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_anyone_1, pubkey1, partial_sig1.signature[:-1]) == 0


def test_sighash_none_anyone_sign(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64+1
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x82
    assert partial_sig1.signature[-1] == 0x82

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_none_anyone_input_changed(navigator: Navigator, firmware: Firmware, client:
                                           RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_none_anyone_output_changed(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_anyone_sign(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64+1
    assert len(partial_sig1.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x83
    assert partial_sig1.signature[-1] == 0x83

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_anyone_input_changed(navigator: Navigator, firmware: Firmware, client:
                                             RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")
    psbt.tx.vin[0].nSequence = psbt.tx.vin[0].nSequence - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_single_anyone_output_changed(navigator: Navigator, firmware: Firmware, client:
                                              RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = psbt.tx.vout[0].nValue - 1

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)

    assert len(result) == 2

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_0, pubkey0, partial_sig0.signature[:-1]) == 0
    assert bip0340.schnorr_verify(sighash_bitcoin_core_single_anyone_1, pubkey1, partial_sig1.signature[:-1])


def test_sighash_anyonecanpay_negative_fee_shows_receive(navigator: Navigator, firmware: Firmware,
                                                         client: RaggerClient, test_name: str):
    # ANYONECANPAY (open inputs): bump the change above our inputs so we net-receive and
    # inputs < outputs. Must NOT be rejected as a negative fee; "You receive" checked by snapshots.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")
    psbt.tx.vout[0].nValue = 9929389  # > inputs total (9919389)

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 2


def test_negative_fee_rejected_default_sighash(navigator: Navigator, firmware: Firmware,
                                               client: RaggerClient, test_name: str):
    # With the default sighash the whole transaction is committed, so inputs < outputs
    # is a genuine (invalid) negative fee and must still be rejected.
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")
    psbt.tx.vout[0].nValue = 9929389  # > inputs total (9919389)

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError


def test_sighash_unsupported(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-unsupported.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0


def test_sighash_unsupported_for_segwitv0(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str):
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    psbt.inputs[0].sighash = 0

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0

    psbt.inputs[0].sighash = 0x80

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0

    psbt.inputs[0].sighash = 0x84

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0


def test_sighash_segwitv0_sighash1(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    expected_sig = b"0E\x02!\x00\xabD\xf3M\xd7\xe8|\x90TY\x12\x97\xa1\x01\xe8P\n\x06A\xd1\xd5\x91\x87\x8d\r#\xcf\x80\x96\xfay\xe8\x02 ]\x12\xd1\x06-\x92^'\xb5{\xdc\xf9\x94\xec\xf32\xad\n\x8eg\xb8\xfe@{\xab!\x01%]\xa62\xaa\x01"

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 1
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def test_sighash_segwitv0_sighash2(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    expected_sig = b'0D\x02 o\x86>\xd5\x8b\xb5\xa5\xa2KZ\xcez\xb2\x92\xd0\xce\x04!L_\x8f9\xeb#m3\x9e\xb4\x8d\xc6sK\x02 p\x8d\x95\x0b4B\x02^\xf1nB\xd2\xea\x84b\x14\xc7\x00\x88"\xed\x19o<f}E\xcc\xfa\xc2\xfc\xd3\x02'

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 2
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def test_sighash_segwitv0_sighash3(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    expected_sig = b'0D\x02 \x11.vf\xbe\x1bd2\x1cx\x89\xcf\xca(\x03\xb0\xc1\x03\x86\xcb\x08\xe4\xe9\xbf\xef/\x1e\xa1\x93\x02\x01C\x02 .)XC\x991\xa6\x85\xa2\x06\xa4\xf7\xde\xfc\xb7\xce\x0b\xc7\xf6\xd6ov\x8a\xdd\xa9\xb5\xf9\x8f\xb8\x07\x82\xc2\x03'

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 3
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def test_sighash_segwitv0_sighash81(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    expected_sig = b"0E\x02!\x00\xde\xae\xfd\x1fg\x96\x9a,\xb9\x0e\xfe\xa9\xc343L\xca=\x9f\xeb4\xcfg\xd62u\xc4c\xa5'0\xd9\x02 rd\x88\x7f s\x93\xd0\x97\xea\xc1@\xc8\xbe\xedu 7w4\x04z\x99.&\xd99\xa1Il/\x82\x81"

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 0x81
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def _wpkh_1in1out(sighash: int) -> PSBT:
    # 1-in/1-out P2WPKH from wpkh-1to2: drop the change, keep the external payment
    # (resized to keep the small fee). Exercises the SINGLE output-count carve-out.
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    input_amount = psbt.inputs[0].witness_utxo.nValue
    del psbt.tx.vout[1]
    del psbt.outputs[1]
    psbt.tx.vout[0].nValue = input_amount - 145
    psbt.inputs[0].sighash = sighash
    return psbt


def test_sighash_segwitv0_sighash82(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)
    expected_sig = b'0E\x02!\x00\xe5\r7m\xa2\x1a\xb4\x89\xd48k\x14\xeb\xd0\xa9\xcc\x00\x17\x9ch\x8b\x16\xb5\x9d&\xab\x94md9\x929\x02 "\x159\xdc\xa3\x06\x06\x9cR\n\xf1\x9a\xfb^\xde)\x1a\xe9\x1e\x07S\x96\xedARN\xfeY\xa4\xc1A\xd4\x82'

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 0x82
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def test_sighash_segwitv0_sighash83(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    toggle_nonstandard_sighash_setting(navigator, firmware)

    expected_sig = b'0D\x02 \x07q\xb3\xe4\x05\xa3|\xd4\xaa$\x95\x1c\x08\x8d~L7\t:|\xddp7\xa7h\x81\x14\xd5$V\x03v\x02 @\xff\xf9\xbc\xd0|\x00\xfa\x91-}\x1e\xed\x04\x0e\xcc\x9d\xd4\xe4NM\\\xf6\xef\x9a\x94\xaf\x83l\xd8\x7f\xdd\x83'

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 0x83
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert result[0][1].signature == expected_sig


def test_sighash_single_1in1out_spent_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # SINGLE (0x03) carve-out: one provided output is committed -> SPENT_ONLY (not the
    # UNAVAILABLE shown for SINGLE with >1 output). Non-default sighash is never FULL.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = _wpkh_1in1out(0x03)
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x03


def test_sighash_single_anyonecanpay_1in1out_spent_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # ANYONECANPAY|SINGLE (0x83), one output: output committed, inputs open -> SPENT_ONLY.
    # The coinjoin maker/taker shape (each party signs their own 1-in/1-out slice).
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = _wpkh_1in1out(0x83)
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x83


def test_sighash_registered_wallet_spent_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Registered (non-default) policy: the account row shows the registered name (not a
    # "<script> #n" default label). ANYONECANPAY|ALL (0x81) -> SPENT_ONLY.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )
    wallet_hmac = bytes.fromhex(
        "d7c7a60b4ab4a14c1bf8901ba627d72140b2fb907f2b4e35d2e693bce9fbb371"
    )
    psbt = open_psbt_from_file(f"{tests_root}/psbt/multisig/wsh-2of2.psbt")
    psbt.inputs[0].sighash = 0x81
    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x81


def _wpkh_two_external_outputs(sighash) -> PSBT:
    # Split wpkh-1to2's single payment into two external recipients, to exercise a review
    # with two output rows (Amount/Address x2). sighash=None keeps the default.
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    second = copy.deepcopy(psbt.tx.vout[0])
    psbt.tx.vout[0].nValue = 500000
    second.nValue = 400000
    psbt.tx.vout.insert(1, second)
    psbt.outputs.insert(1, PartiallySignedOutput(0))
    if sighash is not None:
        psbt.inputs[0].sighash = sighash
    return psbt


def test_sighash_two_outputs_full(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Default sighash, two external outputs -> FULL review with two Amount/Address rows + Fees.
    psbt = _wpkh_two_external_outputs(None)
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)
    assert len(result) == 1


def test_sighash_two_outputs_anyonecanpay_net_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # ANYONECANPAY|ALL with two external outputs -> NET_ONLY: both outputs are committed and
    # shown, but the fee is untrusted (open inputs), so the net "You spend" is shown instead.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = _wpkh_two_external_outputs(0x81)
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x81


def test_sighash_single_external_inputs_net_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # NET_ONLY (SIGHASH_SINGLE, one committed output) with an external input and a closed input set.
    # The input set being closed is not enough to trust the external amount: this is a segwit v0
    # (wpkh) signing, whose signatures don't commit to external inputs' amounts, and the external
    # input provides only an (unverified) witness UTXO. So the "External inputs amount" row must be
    # omitted; only the net "You spend"/"You receive" and "Fees: Not available" are shown.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    # Two-input P2WPKH PSBT: input 0 is ours with SIGHASH_SINGLE, input 1 is an external
    # 500,000-sat input, and the single output includes those external funds minus a 145-sat fee.
    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH4CAAAAAnoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////EREREREREREREREREREREREREREREREREREREREREREAAAAAAP////8BNJU4AAAAAAAZdqkUNEoPSMoVDsK5A4F2YLm2ixOmcCaIrAAAAAAAAQB9AgAAAAGvv64GWQ90H/GvWbasRhEmM2pMSoLbVT32/vq3N6wz8wEAAAAA/f///wJwEQEAAAAAACIAIP3uRBxW5bBtDfgsEkxwcBSlyhlli+C5hWvKFvHtMln3pfQwAAAAAAAWABQ6+EKa1ZVKpe6KM8mD/YoehnmSSwAAAAABAR+l9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAQMEAwAAACIGA+4sPZjrH5PAoaqOWkAJtw63tE6tFfFmbxNrASrVjTBoGPWswv1UAACAAQAAgAAAAIABAAAACAAAAAABAR8goQcAAAAAABYAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, has_external_inputs=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x03


def test_sighash_all_anyonecanpay_external_inputs_net_only(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # NET_ONLY (ANYONECANPAY | ALL) with an external input and an open input set: the output and
    # net "You spend" are shown, but the mutable "External inputs amount" must be omitted.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    # Same two-input P2WPKH structure as above, but input 0 uses ANYONECANPAY | ALL, leaving the
    # input set open even though the single output is committed.
    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH4CAAAAAnoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////EREREREREREREREREREREREREREREREREREREREREREAAAAAAP////8BNJU4AAAAAAAZdqkUNEoPSMoVDsK5A4F2YLm2ixOmcCaIrAAAAAAAAQB9AgAAAAGvv64GWQ90H/GvWbasRhEmM2pMSoLbVT32/vq3N6wz8wEAAAAA/f///wJwEQEAAAAAACIAIP3uRBxW5bBtDfgsEkxwcBSlyhlli+C5hWvKFvHtMln3pfQwAAAAAAAWABQ6+EKa1ZVKpe6KM8mD/YoehnmSSwAAAAABAR+l9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAQMEgQAAACIGA+4sPZjrH5PAoaqOWkAJtw63tE6tFfFmbxNrASrVjTBoGPWswv1UAACAAQAAgAAAAIABAAAACAAAAAABAR8goQcAAAAAABYAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, has_external_inputs=True),
                              testname=test_name)
    assert len(result) == 1
    assert result[0][1].signature[-1] == 0x81


def test_sighash_mixed_across_inputs_unavailable(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Two internal inputs signed with different (non-default) sighashes: the signed inputs
    # disagree on what is committed, so no coherent amount/fee can be shown -> UNAVAILABLE.
    toggle_nonstandard_sighash_setting(navigator, firmware)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")
    psbt.inputs[0].sighash = 0x81  # ANYONECANPAY | ALL
    psbt.inputs[1].sighash = 0x82  # ANYONECANPAY | NONE
    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_sighashwarning=True, amounts_unavailable=True),
                              testname=test_name)
    assert len(result) == 2
    assert result[0][1].signature[-1] == 0x81
    assert result[1][1].signature[-1] == 0x82
