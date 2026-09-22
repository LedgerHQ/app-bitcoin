"""
End-to-end tests for the BIP-370 nLockTime derivation.

A PSBTv2 has no nLockTime field: the app derives it from
PSBT_GLOBAL_FALLBACK_LOCKTIME together with each input's PSBT_IN_REQUIRED_TIME_LOCKTIME and
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME. Since the value is never shown on screen, the only way to observe
what the app decided is through the signatures, so these tests use a taproot policy and recompute
the BIP-341 sighash with the lock time we expect: `assert_locktime` fails if and only if the app
signed over a different one.
"""

import copy
from typing import List, Optional, Tuple

import pytest
from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.exception.errors import IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator
from ragger_bitcoin import RaggerClient

from test_utils import bip0340, txmaker
from test_utils.taproot_sighash import SIGHASH_DEFAULT, TaprootSignatureHash

from .instructions import sign_psbt_instruction_approve, sign_psbt_instruction_tap

# error codes from src/error_codes.h
EC_SIGN_PSBT_UNDETERMINABLE_LOCKTIME = 0x000E
EC_SIGN_PSBT_REQUIRED_LOCKTIME_OUT_OF_RANGE = 0x000F

# the height/time boundary of BIP-370's two required-locktime fields
LOCKTIME_THRESHOLD = 500000000

tr_wallet = WalletPolicy(
    "",
    "tr(@0/**)",
    [
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
    ],
)

# one (height, time) pair per input; None means the field is absent
RequiredLocktimes = List[Tuple[Optional[int], Optional[int]]]


def build_psbt(per_input: RequiredLocktimes, fallback: Optional[int] = None) -> PSBT:
    """A PSBT spending `len(per_input)` taproot inputs, carrying the given required locktimes.

    The conversion to v2 must happen *before* the per-input fields are set:
    PartiallySignedInput.serialize() only emits key types 0x11/0x12 for a v2 PSBT, and
    convert_to_v2() overwrites fallback_locktime from the unsigned transaction.
    """
    n_inputs = len(per_input)
    psbt = txmaker.createPsbt(
        tr_wallet,
        input_amounts=[10_000] * n_inputs,
        output_amounts=[9_000],
        output_is_change=[False],
    )

    psbt.convert_to_v2()

    if fallback is not None:
        psbt.fallback_locktime = fallback

    for i, (height, time) in enumerate(per_input):
        psbt.inputs[i].height_locktime = height
        psbt.inputs[i].time_locktime = time

    return psbt


def assert_locktime(psbt: PSBT, result, expected_locktime: int, *, expect_match: bool = True):
    """Checks every returned signature against the sighash for `expected_locktime`."""
    assert len(result) == len(psbt.inputs)

    tx = copy.deepcopy(psbt.tx)
    tx.nLockTime = expected_locktime
    tx.rehash()
    spent_utxos = [psbt_in.witness_utxo for psbt_in in psbt.inputs]

    for input_index, partial_sig in result:
        sighash = TaprootSignatureHash(
            txTo=tx,
            spent_utxos=spent_utxos,
            hash_type=psbt.inputs[input_index].sighash or SIGHASH_DEFAULT,
            input_index=input_index,
        )

        # SIGHASH_DEFAULT: no sighash byte is appended
        assert len(partial_sig.signature) == 64
        assert partial_sig.pubkey == spent_utxos[input_index].scriptPubKey[2:]

        verified = bip0340.schnorr_verify(sighash, partial_sig.pubkey, partial_sig.signature)
        assert bool(verified) == expect_match


def sign(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str,
         psbt: PSBT):
    return client.sign_psbt(
        psbt,
        tr_wallet,
        None,
        navigator,
        instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False),
        testname=test_name,
    )


def sign_expecting_rejection(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                             test_name: str, psbt: PSBT, expected_error_code: int):
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_tap(firmware),
                         testname=test_name)

    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 2
    assert int.from_bytes(e.value.data, "big") == expected_error_code


# ============================================================================
# The lock time the app derives
#
# Each case is (name, per-input required locktimes, fallback, expected nLockTime). The first group
# is BIP-370's own test vectors; the second is what the vectors leave untested.
# ============================================================================

LOCKTIME_CASES = [
    # --- BIP-370 vectors ---
    ("no_fields_no_fallback", [(None, None), (None, None)], None, 0),
    ("fallback_only", [(None, None), (None, None)], 1901594, 1901594),
    ("height_and_bare_input", [(10000, None), (None, None)], None, 10000),
    ("two_heights_take_the_max", [(10000, None), (9000, None)], None, 10000),
    ("height_and_an_input_with_both", [(10000, None), (9000, 1657048460)], None, 10000),
    # every input accepts either type, so the height must be chosen
    ("both_types_everywhere_height_wins",
     [(10000, 1657048459), (9000, 1657048460)], None, 10000),
    ("a_time_only_input_forces_time", [(None, 1657048459), (9000, 1657048460)], None, 1657048460),
    ("a_time_only_input_forces_time_reversed",
     [(10000, 1657048459), (None, 1657048460)], None, 1657048460),
    ("bare_input_and_a_time", [(None, None), (None, 1657048460)], None, 1657048460),

    # --- the fallback is ignored, not a floor, once any input declares a lock time ---
    ("fallback_larger_is_ignored", [(10000, None), (None, None)], 900000, 10000),
    ("fallback_smaller_is_ignored", [(10000, None), (None, None)], 5, 10000),
    ("fallback_ignored_for_times", [(None, 1657048460), (None, None)], 1700000000, 1657048460),

    # --- the accepted range boundaries ---
    ("smallest_valid_time", [(None, LOCKTIME_THRESHOLD), (None, None)], None, LOCKTIME_THRESHOLD),
    ("largest_valid_height",
     [(LOCKTIME_THRESHOLD - 1, None), (None, None)], None, LOCKTIME_THRESHOLD - 1),
]


@pytest.mark.parametrize("per_input, fallback, expected",
                         [case[1:] for case in LOCKTIME_CASES],
                         ids=[case[0] for case in LOCKTIME_CASES])
def test_locktime_determination(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                test_name: str, per_input: RequiredLocktimes,
                                fallback: Optional[int], expected: int):
    psbt = build_psbt(per_input, fallback)
    result = sign(navigator, firmware, client, test_name, psbt)
    assert_locktime(psbt, result, expected)


def test_locktime_oracle_rejects_the_wrong_locktime(navigator: Navigator, firmware: Firmware,
                                                    client: RaggerClient, test_name: str):
    """Verify that assert_locktime fails as expected when the wrong lock time is provided."""
    psbt = build_psbt([(10000, None), (None, None)])
    result = sign(navigator, firmware, client, test_name, psbt)

    assert_locktime(psbt, result, 10000)
    assert_locktime(psbt, result, 10001, expect_match=False)


# ============================================================================
# Rejections
# ============================================================================

def test_locktime_undeterminable(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                 test_name: str):
    """One input accepts only a height, another only a time: no nLockTime satisfies both."""
    psbt = build_psbt([(10000, None), (None, 1657048460)])
    sign_expecting_rejection(navigator, firmware, client, test_name, psbt,
                             EC_SIGN_PSBT_UNDETERMINABLE_LOCKTIME)


def test_locktime_undeterminable_reversed(navigator: Navigator, firmware: Firmware,
                                          client: RaggerClient, test_name: str):
    psbt = build_psbt([(None, 1657048460), (10000, None)])
    sign_expecting_rejection(navigator, firmware, client, test_name, psbt,
                             EC_SIGN_PSBT_UNDETERMINABLE_LOCKTIME)


def test_locktime_undeterminable_not_rescued_by_a_fallback(navigator: Navigator,
                                                           firmware: Firmware,
                                                           client: RaggerClient, test_name: str):
    psbt = build_psbt([(10000, None), (None, 1657048460)], fallback=1234)
    sign_expecting_rejection(navigator, firmware, client, test_name, psbt,
                             EC_SIGN_PSBT_UNDETERMINABLE_LOCKTIME)


def test_locktime_undeterminable_not_rescued_by_a_third_input(navigator: Navigator,
                                                              firmware: Firmware,
                                                              client: RaggerClient,
                                                              test_name: str):
    """An input accepting both types does not reconcile the two that accept only one."""
    psbt = build_psbt([(10000, None), (9000, 1657048459), (None, 1657048460)])
    sign_expecting_rejection(navigator, firmware, client, test_name, psbt,
                             EC_SIGN_PSBT_UNDETERMINABLE_LOCKTIME)


@pytest.mark.parametrize("per_input", [
    pytest.param([(0, None), (None, None)], id="height_zero"),
    pytest.param([(LOCKTIME_THRESHOLD, None), (None, None)], id="height_at_the_threshold"),
    pytest.param([(0xFFFFFFFF, None), (None, None)], id="height_max_u32"),
    pytest.param([(None, LOCKTIME_THRESHOLD - 1), (None, None)], id="time_below_the_threshold"),
    pytest.param([(None, 0), (None, None)], id="time_zero"),
    pytest.param([(0, 1657048460), (None, None)], id="bad_height_next_to_a_good_time"),
])
def test_locktime_out_of_range(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                               test_name: str, per_input: RequiredLocktimes):
    psbt = build_psbt(per_input)
    sign_expecting_rejection(navigator, firmware, client, test_name, psbt,
                             EC_SIGN_PSBT_REQUIRED_LOCKTIME_OUT_OF_RANGE)


def test_locktime_required_field_of_wrong_length(navigator: Navigator, firmware: Firmware,
                                                 client: RaggerClient, test_name: str):
    """A field the client committed to but cannot produce as 4 bytes is a malformed PSBT.

    The typed attribute always packs 4 bytes, so this goes through `unknown` to put a 3-byte value
    under key type 0x12. The app must not read it as "this input declares no required lock time":
    that would silently change the lock time it signs.
    """
    psbt = build_psbt([(None, None), (None, None)])
    psbt.inputs[0].unknown[b"\x12"] = b"\x01\x02\x03"

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, tr_wallet, None, navigator,
                         instructions=sign_psbt_instruction_tap(firmware),
                         testname=test_name)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
