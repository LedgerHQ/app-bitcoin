#!/usr/bin/env python3
"""Seed corpus for the bitcoin fuzz target.

A seed here is nothing but an input the fuzzer could have produced on its own. It
authors no behaviour: it lands mutation in a region of the input space that random
bytes reach with probability near zero, and libFuzzer explores outward from there.

Why any seed is needed at all. The builders read their content off a cursor over the
harness input (the "tape"). To reach psbt_parse_rawtx.c and txhashes.c the app must
find, in a single input map, three specific one-byte PSBT keys -- NON_WITNESS_UTXO,
PREVIOUS_TXID and OUTPUT_INDEX -- with WITNESS_UTXO absent and OUTPUT_INDEX carrying
exactly four bytes. Each one-byte key is uniform over 256 values, so that conjunction
arrives about once in 400 000 inputs and has to coincide with a map that is otherwise
well formed. Measured: 0.00% of both files after a 300-second campaign that executed
439 049 inputs. A seed spells the conjunction once; mutation keeps whatever the
coverage signal rewards.

MuSig is deliberately not seeded. Subtypes 14 and 15 reach the musig sign modes, but a
musig policy is taproot, so key_expression_found comes from PSBT_IN_TAP_BIP32_DERIVATION
carrying the x-only *aggregate* musig key -- which psbt_model does not reproduce, so the
input stays external and preprocess_inputs.c:363 aborts exactly as before. Measured: two
such seeds moved musig_signing.c not at all (0/317 either way) and cost 1.35pp overall by
displacing fuzzing budget. Reaching it needs a third host binding for the aggregate key,
not a seed.

Only SIGN_PSBT is seeded, and that is a measured choice rather than an omission. From
a cold start with no seeds at all, register_wallet.c already reaches 84.7%,
get_wallet_address.c 61% and sign_message.c 40% -- random bytes find those lanes
unaided, so seeding them would be the fuzzer's work done by hand. Every file still at
0% is downstream of a valid PSBT input map.

Everything a seed writes is a tape byte, so every byte stays mutable and still means
what the builders say it means. The Absolution prefix is copied verbatim from the
generated fuzzer.seed via resolve_seed_prefix(): this file never authors a prefix byte
and knows nothing of the prefix layout, which is Absolution's alone.

Input layout (fuzz_defs.h):
    [ Absolution prefix ][ 4 ctrl ][ 16 app header ][ tail ]
    ctrl = lane selector, command index, P1, P2
    tail = slot 0 (64 B of scenario controls) followed by the tape
"""
import os
import re
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
        "ledger-secure-sdk", "fuzzing", "scripts",
    ),
)
from fuzz_seed_utils import resolve_prefix_size, resolve_seed_prefix  # noqa: E402

FUZZER_NAME = os.environ.get("FUZZER", "fuzz_app")

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOCK = os.path.join(_HERE, "..", "mock")
_SDK_INC = os.path.join(_HERE, "..", "..", "..", "ledger-secure-sdk", "fuzzing", "include")


def _c_const(name, *files):
    """Read a constant out of the C sources rather than duplicating its value.

    This file has to agree with psbt_model.c on the tape encoding and with mocks.h and
    fuzz_defs.h on the input layout. Duplicating those numbers here is what destroyed
    the previous generator: it accumulated 227 references to a slot layout the builders
    had stopped using, and every seed it wrote silently decoded as noise for months
    because nothing checks that a seed still means what it was written to mean.

    Matches both `#define NAME value` and an enum's `NAME = value,`. Raises rather than
    guessing, so a renamed constant fails the run instead of producing dead seeds.
    """
    pats = (
        re.compile(r"^\s*#define\s+" + re.escape(name) + r"\s+(\d+)", re.M),
        re.compile(r"^\s*" + re.escape(name) + r"\s*=\s*(\d+)\s*,", re.M),
    )
    for f in files:
        try:
            text = open(f, encoding="utf-8").read()
        except OSError:
            continue
        for pat in pats:
            m = pat.search(text)
            if m:
                return int(m.group(1))
    raise SystemExit(f"error: could not find {name} in {', '.join(files)}")


_PSBT = os.path.join(_MOCK, "psbt_model.c")
_MOCKS_H = os.path.join(_MOCK, "mocks.h")
_DEFS_H = os.path.join(_SDK_INC, "fuzz_defs.h")

# ── harness layout ────────────────────────────────────────────────────────────
CTRL_LEN = _c_const("FUZZ_CTRL_LEN", _DEFS_H)
APP_HEADER_LEN = _c_const("PSBT_ENTROPY_SIZE", _MOCKS_H)
SLOT_SIZE = _c_const("FUZZ_TAIL_SLOT_SIZE", _MOCKS_H)
# data[0] must be strictly greater than the threshold to select the structured lane.
STRUCTURED_LANE_MIN = _c_const("FUZZ_STRUCTURED_LANE_THRESHOLD", _DEFS_H) + 1

# slot 0 offsets read directly by pm_build_scenario
S0_TX_VERSION = _c_const("PM_SLOT0_TX_VERSION_OFF", _PSBT)
S0_LOCKTIME = _c_const("PM_SLOT0_LOCKTIME_OFF", _PSBT)
S0_N_INPUTS = _c_const("PM_SLOT0_N_INPUTS_OFF", _PSBT)
S0_N_OUTPUTS = _c_const("PM_SLOT0_N_OUTPUTS_OFF", _PSBT)
S0_SUBTYPE = _c_const("PM_SLOT0_SUBTYPE_OFF", _PSBT)
S0_DESCRIPTOR = _c_const("PM_SLOT0_DESCRIPTOR_OFF", _PSBT)

# fuzz_commands[] is a positional table, so this one is counted rather than defined.
N_SIGN_PSBT_SLOTS = len(re.findall(
    r"\.ins\s*=\s*SIGN_PSBT",
    open(os.path.join(_HERE, "..", "harness", "fuzz_dispatcher.c"), encoding="utf-8").read()))
if N_SIGN_PSBT_SLOTS == 0:
    raise SystemExit("error: no SIGN_PSBT entries found in fuzz_commands[]")

# ── tape encoding (pm_map_from_tape) ──────────────────────────────────────────
TAPE_MAP_MAX = _c_const("PM_TAPE_MAP_MAX", _PSBT)
TAPE_KV_MAX = _c_const("PM_TAPE_KV_MAX", _PSBT)
TAPE_VAL_SHORT = _c_const("PM_TAPE_VAL_SHORT", _PSBT)

# PSBT key types (src/common/psbt.h)
IN_NON_WITNESS_UTXO = 0x00
IN_WITNESS_UTXO = 0x01
IN_SIGHASH_TYPE = 0x03
IN_REDEEM_SCRIPT = 0x04
IN_WITNESS_SCRIPT = 0x05
IN_BIP32_DERIVATION = 0x06
IN_PREVIOUS_TXID = 0x0E
IN_OUTPUT_INDEX = 0x0F
IN_SEQUENCE = 0x10
IN_TAP_BIP32_DERIVATION = 0x16
OUT_BIP32_DERIVATION = 0x02
OUT_AMOUNT = 0x03
OUT_SCRIPT = 0x04


def tape_entry(key, val):
    """One map entry: key-length control, value-length control, then the bytes."""
    out = bytearray()

    if len(key) <= 4:
        out.append((len(key) - 1) % 4)       # kl = 1 + (b % 4)
        out.append(0x00)                     # long-key flag clear (set is b & 0x0F == 0x0F)
    else:
        out.append(0x00)
        out.append(0x0F)
        out.append(len(key) % TAPE_KV_MAX)

    if len(val) < TAPE_VAL_SHORT:
        out.append(len(val))                 # vl = b % TAPE_VAL_SHORT
        out.append(0x00)                     # long-value flag clear (set is b & 0x07 == 0x07)
    else:
        out.append(0x00)
        out.append(0x07)
        out.append(len(val) % TAPE_KV_MAX)

    return bytes(out) + key + val


def tape_map(entries, bind_txid=True, declared=None):
    """A whole map: entry count, the entries, then the two trailing control bytes."""
    out = bytearray()
    out.append((len(entries) - 1) % TAPE_MAP_MAX)    # n = 1 + (b % TAPE_MAP_MAX)
    for key, val in entries:
        out += tape_entry(key, val)
    out.append(0x00 if bind_txid else 0x0F)          # bind unless b & 0x0F == 0x0F
    if declared is None:
        out.append(0x00)                             # declared = actual entry count
    else:
        out.append(0x0F)
        out.append(declared & 0xFF)
    return bytes(out)


# ── bitcoin bytes the app parses ──────────────────────────────────────────────
def p2wpkh_spk(fill=0x11):
    return bytes([0x00, 0x14]) + bytes([fill]) * 20


def raw_legacy_tx(n_out=1, value=1000, fill=0x11):
    """A minimal legacy (non-segwit) transaction: the shape psbt_parse_rawtx walks."""
    tx = bytearray()
    tx += (1).to_bytes(4, "little")          # version
    tx.append(1)                             # input count
    tx += bytes(32)                          # prevout txid
    tx += (0).to_bytes(4, "little")          # prevout index
    tx.append(0)                             # scriptSig length
    tx += b"\xff" * 4                        # sequence
    tx.append(n_out)                         # output count
    for i in range(n_out):
        tx += (value + i).to_bytes(8, "little")
        spk = p2wpkh_spk(fill)
        tx.append(len(spk))
        tx += spk
    tx += (0).to_bytes(4, "little")          # locktime
    return bytes(tx)


def witness_utxo(value=1000, fill=0x11):
    spk = p2wpkh_spk(fill)
    return value.to_bytes(8, "little") + bytes([len(spk)]) + spk


def bip32_derivation():
    """Master fingerprint then the full derivation path, 4 + 5*4 = 24 bytes.

    build_wallet_policy writes key_info as "[00000000/purpose\'/coin\'/account\']", so
    the fingerprint is zero and the path continues .../0/0. psbt_model rewrites both
    this value and the 33-byte pubkey in the key to whatever the policy actually
    derives -- extract_bip32_derivation compares against a hash of the wallet's own
    xpub, which no mutation can reach. The shape has to be right here so there is an
    entry of the correct length for it to rewrite.
    """
    hardened = [0x80000000 | v for v in (84, 1, 0)]
    return bytes(4) + b"".join(
        v.to_bytes(4, "little") for v in hardened + [0, 0]
    )


# ── input assembly ────────────────────────────────────────────────────────────
def make_input(prefix, cmd_slot, tape, subtype=0, n_inputs=1, n_outputs=1,
               descriptor=0, p2=0, tx_version=2, locktime=0):
    slot0 = bytearray(SLOT_SIZE)
    slot0[S0_TX_VERSION:S0_TX_VERSION + 4] = tx_version.to_bytes(4, "little")
    slot0[S0_LOCKTIME:S0_LOCKTIME + 4] = locktime.to_bytes(4, "little")
    # pm_build_scenario computes 1 + (b % PM_MAX_INPUTS), so subtract one here.
    slot0[S0_N_INPUTS] = (n_inputs - 1) & 0xFF
    slot0[S0_N_OUTPUTS] = (n_outputs - 1) & 0xFF
    slot0[S0_SUBTYPE] = subtype
    slot0[S0_DESCRIPTOR] = descriptor

    ctrl = bytes([STRUCTURED_LANE_MIN, cmd_slot, 0x00, p2])
    return prefix + ctrl + bytes(APP_HEADER_LEN) + bytes(slot0) + tape


def output_map():
    return tape_map([
        (bytes([OUT_AMOUNT]), (5000).to_bytes(8, "little")),
        (bytes([OUT_SCRIPT]), p2wpkh_spk(0x22)),
        (bytes([OUT_BIP32_DERIVATION]) + bytes([0x02]) + bytes([0x33]) * 32,
         bip32_derivation()),
    ])


def psbt_cases():
    """(name, input-map entries, make_input kwargs, tape_map kwargs)."""
    pk33 = bytes([0x02]) + bytes([0x33]) * 32
    xonly32 = bytes([0x44]) * 32
    idx0 = (0).to_bytes(4, "little")
    txid_slot = bytes(32)
    cases = []

    # The legacy path: non-witness utxo present, witness utxo absent. This is the only
    # route into psbt_parse_rawtx.c, via amount_from_psbt.c:60.
    for tag, tx in (("1out", raw_legacy_tx(1)),
                    ("2out", raw_legacy_tx(2)),
                    ("bigval", raw_legacy_tx(1, value=0xFFFFFFFFFF))):
        cases.append((f"nonwitness-{tag}", [
            (bytes([IN_NON_WITNESS_UTXO]), tx),
            (bytes([IN_PREVIOUS_TXID]), txid_slot),
            (bytes([IN_OUTPUT_INDEX]), idx0),
        ], {}, {}))

    # Same shape with the txid binding left as written, so the mismatch rejection at
    # amount_from_psbt.c:73 stays reachable.
    cases.append(("nonwitness-badtxid", [
        (bytes([IN_NON_WITNESS_UTXO]), raw_legacy_tx(1)),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), idx0),
    ], {}, {"bind_txid": False}))

    # An output index past the end of the parsed transaction.
    cases.append(("nonwitness-oob-index", [
        (bytes([IN_NON_WITNESS_UTXO]), raw_legacy_tx(1)),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), (7).to_bytes(4, "little")),
    ], {}, {}))

    # The segwit path.
    cases.append(("witness", [
        (bytes([IN_WITNESS_UTXO]), witness_utxo()),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), idx0),
        (bytes([IN_BIP32_DERIVATION]) + pk33, bip32_derivation()),
    ], {}, {}))

    # Both utxo kinds present: the gate at preprocess_inputs.c:158 passes either way
    # and the two downstream branches disagree about which to trust.
    cases.append(("both-utxo", [
        (bytes([IN_NON_WITNESS_UTXO]), raw_legacy_tx(1)),
        (bytes([IN_WITNESS_UTXO]), witness_utxo()),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), idx0),
    ], {}, {}))

    # extract_bip32_derivation.c only runs for a key of exactly 1+33 or 1+32 bytes.
    cases.append(("bip32-p2tr", [
        (bytes([IN_WITNESS_UTXO]), witness_utxo()),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), idx0),
        (bytes([IN_TAP_BIP32_DERIVATION]) + xonly32,
         bytes([0x00]) + bip32_derivation()),
    ], {"subtype": 1, "descriptor": 1}, {}))

    # Scripts, and the fields that gate the sighash and locktime arithmetic.
    cases.append(("scripts", [
        (bytes([IN_WITNESS_UTXO]), witness_utxo()),
        (bytes([IN_SIGHASH_TYPE]), (1).to_bytes(4, "little")),
        (bytes([IN_REDEEM_SCRIPT]), p2wpkh_spk(0x33)),
        (bytes([IN_WITNESS_SCRIPT]), bytes([0x51])),
        (bytes([IN_PREVIOUS_TXID]), txid_slot),
        (bytes([IN_OUTPUT_INDEX]), idx0),
        (bytes([IN_SEQUENCE]), b"\xfe\xff\xff\xff"),
    ], {}, {}))

    return cases


def build_seeds(prefix):
    seeds = {}

    # The tape is consumed as n_inputs input maps followed by n_outputs output maps
    # (pm_build_inputs_tree then pm_build_outputs_tree), so a scenario's tape is just
    # those maps concatenated.
    for name, entries, kw, mapkw in psbt_cases():
        # Spread over the SIGN_PSBT command slots and the sign-mode subtypes, so a
        # seed is not pinned to one conversation shape.
        for slot, subtype in ((0, 0), (1, 6), (2, 10)):
            kwargs = dict(kw)
            kwargs.setdefault("subtype", subtype)
            seeds[f"psbt-{name}-s{slot}"] = make_input(
                prefix, slot % N_SIGN_PSBT_SLOTS,
                tape_map(entries, **mapkw) + output_map(), **kwargs
            )

    common = [
        (bytes([IN_WITNESS_UTXO]), witness_utxo()),
        (bytes([IN_PREVIOUS_TXID]), bytes(32)),
        (bytes([IN_OUTPUT_INDEX]), (0).to_bytes(4, "little")),
    ]

    # Two inputs, so preprocess_inputs iterates and per-input state must hold across
    # the loop; both must pass the utxo gate for preprocess_outputs to run at all.
    seeds["psbt-two-inputs"] = make_input(
        prefix, 0, tape_map(common) * 2 + output_map(), n_inputs=2
    )
    seeds["psbt-two-in-two-out"] = make_input(
        prefix, 0, tape_map(common) * 2 + output_map() * 2,
        n_inputs=2, n_outputs=2,
    )

    # A declared entry count that disagrees with the leaves actually served.
    seeds["psbt-count-mismatch"] = make_input(
        prefix, 0, tape_map(common, declared=9) + output_map()
    )

    return seeds


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)

    prefix_size = resolve_prefix_size(FUZZER_NAME)
    prefix = resolve_seed_prefix(prefix_size, FUZZER_NAME)

    seeds = build_seeds(prefix)
    for name, data in sorted(seeds.items()):
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)

    payloads = [len(d) - prefix_size for d in seeds.values()]
    print(f"  seeds: wrote {len(seeds)} file(s) to {out_dir} "
          f"(prefix {prefix_size} B, payload {min(payloads)}..{max(payloads)} B)")


if __name__ == "__main__":
    main()
