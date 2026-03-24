"""
Tests for the non-standard sighash gating feature.

Verifies that:
1. By default, non-standard sighash types (NONE, SINGLE, ANYONECANPAY|*) are rejected
   with SW_SECURITY_STATUS_NOT_SATISFIED (0x6982) and error code
   EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED (0x000d).
2. After enabling "Non-standard sighash" in app settings, non-standard sighash types
   are accepted with a warning (previous behavior).
3. Unsupported sighash types are still rejected regardless of the setting.
4. SIGHASH_ALL and SIGHASH_DEFAULT remain unaffected by the setting.
"""
import pytest
from pathlib import Path
from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.exception.errors import NotSupportedError, SecurityStatusNotSatisfiedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT
from test_utils import bip0340
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient

from .conftest import toggle_nonstandard_sighash_setting
from .instructions import sign_psbt_instruction_approve

tests_root: Path = Path(__file__).parent

# Error codes from error_codes.h
EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED = 0x000d

# Status words
SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982

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

# Pre-computed sighash values from Bitcoin Core for verification
sighash_bitcoin_core_none_0 = bytes.fromhex(
    "965976D58A387369D970F0B6560B144E1B721D41E04675592C41AC35D30D2A56")
sighash_bitcoin_core_none_1 = bytes.fromhex(
    "67E85534A12E4054F4AFAA434D7A7C38123DA6909DF7E45DDB9945F7B8D832D0")
sighash_bitcoin_core_all_0 = bytes.fromhex(
    "2221AA462110C77A8E2DD34C3681BAA9BFFF6553B4C609EC7E3D8FF9B1D18D69")
sighash_bitcoin_core_all_1 = bytes.fromhex(
    "D47D3FA22B4F6C50521C49E1A42E8CB10689540A227491A8FC5AD0A6E413063E")


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()
    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


# =========================================================================
# Tests: Default behavior (setting disabled) - non-standard sighash REJECTED
# =========================================================================


def test_sighash_none_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                          client: RaggerClient, test_name: str):
    """SIGHASH_NONE should be rejected when the non-standard sighash setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


def test_sighash_single_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                            client: RaggerClient, test_name: str):
    """SIGHASH_SINGLE should be rejected when the non-standard sighash setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


def test_sighash_anyonecanpay_all_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                                      client: RaggerClient, test_name: str):
    """SIGHASH_ANYONECANPAY|ALL should be rejected when the setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


def test_sighash_anyonecanpay_none_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                                       client: RaggerClient, test_name: str):
    """SIGHASH_ANYONECANPAY|NONE should be rejected when the setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-anyone-can-pay-sign.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


def test_sighash_anyonecanpay_single_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                                         client: RaggerClient, test_name: str):
    """SIGHASH_ANYONECANPAY|SINGLE should be rejected when the setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-anyone-can-pay-sign.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


def test_sighash_segwitv0_sighash2_rejected_by_default(navigator: Navigator, firmware: Firmware,
                                                       client: RaggerClient, test_name: str):
    """SegWit v0 SIGHASH_NONE (0x02) should be rejected when the setting is disabled (default)."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 2

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert e.value.status == SW_SECURITY_STATUS_NOT_SATISFIED
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED


# =========================================================================
# Tests: SIGHASH_ALL is always allowed (regardless of setting)
# =========================================================================


def test_sighash_all_always_allowed(navigator: Navigator, firmware: Firmware,
                                    client: RaggerClient, test_name: str):
    """SIGHASH_ALL should always be allowed, even when the setting is disabled."""
    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2
    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_0, pubkey0, partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_all_1, pubkey1, partial_sig1.signature[:-1])


# =========================================================================
# Tests: Unsupported sighash still rejected (regardless of setting)
# =========================================================================


def test_sighash_unsupported_still_rejected_with_setting_enabled(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    """Unsupported sighash types should still be rejected even when the setting is enabled."""
    # First, enable the setting
    toggle_nonstandard_sighash_setting(navigator, firmware)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-unsupported.psbt")

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0


# =========================================================================
# Tests: After enabling the setting, non-standard sighash accepted with warning
# =========================================================================


def test_sighash_none_allowed_after_enabling_setting(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    """SIGHASH_NONE should be allowed (with warning) after enabling the setting."""
    # Enable the setting via UI navigation (with screenshot comparison)
    toggle_nonstandard_sighash_setting(navigator, firmware,
                                       test_case_name=test_name + "_settings")

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-none-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_sighashwarning=True),
                              testname=test_name)

    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]
    pubkey1 = psbt.inputs[1].witness_utxo.scriptPubKey[2:]

    assert len(result) == 2
    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert len(partial_sig0.signature) == 64 + 1
    assert len(partial_sig1.signature) == 64 + 1
    assert partial_sig0.signature[-1] == 0x02
    assert partial_sig1.signature[-1] == 0x02

    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_0, pubkey0,
                                  partial_sig0.signature[:-1])
    assert bip0340.schnorr_verify(sighash_bitcoin_core_none_1, pubkey1,
                                  partial_sig1.signature[:-1])


def test_sighash_single_allowed_after_enabling_setting(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    """SIGHASH_SINGLE should be allowed (with warning) after enabling the setting."""
    toggle_nonstandard_sighash_setting(navigator, firmware)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-single-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_sighashwarning=True),
                              testname=test_name)

    assert len(result) == 2
    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert partial_sig0.signature[-1] == 0x03
    assert partial_sig1.signature[-1] == 0x03


def test_sighash_anyonecanpay_all_allowed_after_enabling_setting(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    """SIGHASH_ANYONECANPAY|ALL should be allowed (with warning) after enabling the setting."""
    toggle_nonstandard_sighash_setting(navigator, firmware)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/sighash/sighash-all-anyone-can-pay-sign.psbt")

    result = client.sign_psbt(psbt, tr_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_sighashwarning=True),
                              testname=test_name)

    assert len(result) == 2
    _, partial_sig0 = result[0]
    _, partial_sig1 = result[1]

    assert partial_sig0.signature[-1] == 0x81
    assert partial_sig1.signature[-1] == 0x81


def test_sighash_segwitv0_sighash2_allowed_after_enabling_setting(
        navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    """SegWit v0 SIGHASH_NONE (0x02) should be allowed (with warning) after enabling the setting."""
    toggle_nonstandard_sighash_setting(navigator, firmware)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")
    psbt.inputs[0].sighash = 2

    result = client.sign_psbt(psbt, wpkh_wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_sighashwarning=True),
                              testname=test_name)
    assert len(result) == 1
