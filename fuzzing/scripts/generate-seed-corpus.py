#!/usr/bin/env python3
"""Generate valid seed corpus entries for the current app's fuzzer.

Each output file is a binary blob: prefix (current globals snapshot, when a
built fuzzer seed is available) + tail.
The mock builders in mocks.c generate continuation protocol responses based on
psbt_entropy and mock_continuation_data at the offsets declared in
scenario_layout.h.

Routing contract after the Bitcoin Lane Simplification pass:
  - psbt_entropy[0]   lane gate (>= 0xE0 picks the structured lane) and
                      descriptor-family / rawtx-toggle bits for the PSBT
                      builder
  - psbt_entropy[1]   structured-lane command slot in bits 0-3 (see
                      fuzz_commands[] in harness/fuzz_dispatcher.c); bits
                      4-7 carry I/O counts for the PSBT builder
  - psbt_entropy[2]   SIGN_PSBT subtype slot in bits 0-3 (see
                      pm_build_scenario in mock/psbt_model.c)
  - psbt_entropy[3..] model-specific entropy (paths, amounts, wallet flags,
                      message builder toggles)

Sabotage is driven entirely from the libFuzzer tail (structured lane only):
  - fuzz_tail[0..N_SLOTS*64-1]:  dense 64-byte builder slots.
  - fuzz_tail[len-4..len-1]:    fault knobs (kind, target, param0, param1).
See mocks.h and scenario_layout.h for the full contract.

This generator creates corpus entries for:
  - Structured SIGN_PSBT variants (default / registered / rawtx / musig r1/r2)
  - Structured GET_WALLET_ADDRESS / REGISTER_WALLET / SIGN_MESSAGE / swap
  - Raw GET_EXTENDED_PUBKEY and GET_MASTER_FINGERPRINT
  - A small stratum of sabotage-activating seeds so libFuzzer sees at least
    one example of every builder contradiction kind and every continuation
    sabotage kind.

Continuation-based commands stay structured-only, so this script intentionally
avoids raw seeds for REGISTER_WALLET, GET_WALLET_ADDRESS, SIGN_MESSAGE, and
SIGN_PSBT.
"""

import hashlib
import os
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SCRIPT_DIR)

bolos_sdk = os.environ.get("BOLOS_SDK")
if not bolos_sdk:
    raise SystemExit("error: BOLOS_SDK must be set")

SDK_SCRIPTS_DIR = os.path.join(bolos_sdk, "fuzzing", "scripts")
sys.path.insert(0, SDK_SCRIPTS_DIR)

from fuzz_seed_utils import (
    parse_layout_header,
    resolve_prefix_size as _resolve_prefix_size_shared,
    resolve_seed_prefix as _resolve_seed_prefix_shared,
    validate_prefix_size,
    get_layout_header_path,
)

LAYOUT_HEADER = get_layout_header_path()
_LAYOUT_DEFS = parse_layout_header(LAYOUT_HEADER)

ENTROPY_OFF = _LAYOUT_DEFS.get("SCEN_ENTROPY_OFF", 121)
ENTROPY_LEN = _LAYOUT_DEFS.get("SCEN_ENTROPY_LEN", 16)

TAIL_SLOT_SIZE = _LAYOUT_DEFS.get("SCEN_TAIL_SLOT_SIZE", 64)
TAIL_N_SLOTS = _LAYOUT_DEFS.get("SCEN_TAIL_N_SLOTS", 16)
TAIL_FAULT_SIZE = _LAYOUT_DEFS.get("SCEN_TAIL_FAULT_SIZE", 4)

G_SWAP_OFF = _LAYOUT_DEFS.get("SCEN_G_SWAP_OFF")
UI_APPROVE_OFF = _LAYOUT_DEFS.get("SCEN_UI_APPROVE_OFF")

# swap_globals_t struct field offsets (from swap_globals.h).
_SWAP_AMOUNT_REL = 0            # uint64_t  (8 bytes)
_SWAP_FEES_REL = 8              # uint64_t  (8 bytes)
_SWAP_DEST_ADDR_REL = 16        # char[65]
_SWAP_CALLED_FROM_SWAP_REL = 81 # unsigned char
_SWAP_SHOULD_EXIT_REL = 82      # unsigned char
_SWAP_MODE_REL = 83             # unsigned char
_SWAP_PAYIN_EXTRA_ID_REL = 84   # uint8_t[33]

SWAP_MODE_STANDARD = 0
SWAP_MODE_CROSSCHAIN = 1
SWAP_MODE_ERROR = 0xFF

# Command slots — must stay aligned with fuzz_commands[] in fuzz_dispatcher.c.
# Low nibble of psbt_entropy[1] selects the slot in the structured lane.
CMD_SLOT_SIGN_PSBT_BASE       = 0   # slots 0..7  (50% of structured lane)
CMD_SLOT_REGISTER_WALLET_BASE = 8   # slots 8..9
CMD_SLOT_GET_WALLET_ADDR_BASE = 10  # slots 10..11
CMD_SLOT_SIGN_MESSAGE_BASE    = 12  # slots 12..13
CMD_SLOT_SWAP_CHECK           = 14
CMD_SLOT_SWAP_HELPERS         = 15

# Sign subtype slots — must stay aligned with pm_build_scenario's subtype
# decoder.  Low nibble of psbt_entropy[2] selects the slot.
SIGN_SUBTYPE_DEFAULT_BASE    = 0   # slots 0..5  (37.5%)
SIGN_SUBTYPE_REGISTERED_BASE = 6   # slots 6..9  (25%)
SIGN_SUBTYPE_RAWTX_BASE      = 10  # slots 10..13 (25%)
SIGN_SUBTYPE_MUSIG_R1        = 14  # 6.25%
SIGN_SUBTYPE_MUSIG_R2        = 15  # 6.25%

# Fault knobs — must stay aligned with BTC_FAULT_* in mocks.h.  The
# fuzzer reads fuzz_tail[0] & 0x03 to pick one family per iteration.
# Fault kinds (must stay aligned with BTC_FAULT_* in mocks.h).
FAULT_CLEAN          = 0
FAULT_WRONG_HMAC     = 1
FAULT_SIGHASH_OVR    = 2
FAULT_AMOUNT_XOR     = 3
FAULT_SEQ_LOCK       = 4
FAULT_OUTPUT_AMT     = 5
FAULT_CONT_TRUNCATE  = 6
FAULT_CONT_FLIP      = 7

# Continuation sabotage kinds (btc_handle_ccmd in harness/fuzz_dispatcher.c).
# Legacy aliases for seed generation (mapped to FAULT_CONT_* knobs)
CONT_SAB_HOST_WRONG_REPLY = 0
CONT_SAB_TRUNCATE         = 1
CONT_SAB_FLIP             = 2
CONT_SAB_HEADER_REPLACE   = 3

REGISTER_WALLET_TEMPLATE_COUNT = 15  # keep in sync with wallet_model.c
FUZZER_NAME = os.environ.get("FUZZER", "fuzz_app")

PREFIX_SIZE = _resolve_prefix_size_shared(FUZZER_NAME)
validate_prefix_size(PREFIX_SIZE, _LAYOUT_DEFS)

if ENTROPY_OFF + ENTROPY_LEN > PREFIX_SIZE:
    raise SystemExit(
        f"error: semantic layout exceeds prefix size "
        f"({ENTROPY_OFF + ENTROPY_LEN} > {PREFIX_SIZE})"
    )


BASE_PREFIX = _resolve_seed_prefix_shared(PREFIX_SIZE, FUZZER_NAME)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _set_global(buf, off, val):
    if off is not None and val is not None:
        buf[off] = val & 0xFF


def _set_swap_field(buf, rel_off, val):
    """Write a single byte to a G_swap_state struct field."""
    if G_SWAP_OFF is not None and val is not None:
        buf[G_SWAP_OFF + rel_off] = val & 0xFF


def make_prefix(entropy_bytes,
                ui_approve=None,
                swap_called_from_swap=None, swap_mode=None):
    buf = bytearray(BASE_PREFIX)
    buf[ENTROPY_OFF:ENTROPY_OFF + ENTROPY_LEN] = entropy_bytes[:ENTROPY_LEN]
    _set_global(buf, UI_APPROVE_OFF, ui_approve)
    _set_swap_field(buf, _SWAP_CALLED_FROM_SWAP_REL, swap_called_from_swap)
    _set_swap_field(buf, _SWAP_MODE_REL, swap_mode)
    return bytes(buf)


def make_raw_prefix(entropy_bytes):
    """Build a prefix for raw mode (lane byte <=102).

    In raw mode the APDU comes from the tail, so the prefix only carries
    Absolution-driven global state.  No per-byte overrides are needed.
    """
    buf = bytearray(BASE_PREFIX)
    buf[ENTROPY_OFF:ENTROPY_OFF + ENTROPY_LEN] = entropy_bytes[:ENTROPY_LEN]
    return bytes(buf)


def encode_entropy1(command_slot, n_inputs=1, n_outputs=1):
    """Pack psbt_entropy[1]: low nibble = structured command slot, high
    nibble = I/O counts (read by pm_build_scenario).

    Bits 0-1 of the command slot also double as tx_version / locktime
    toggles for the PSBT builder — this is intentional: the structured
    lane slot 0 (plain SIGN_PSBT) corresponds to clean toggles, while
    slots 1-3 flip individual toggles inside the SIGN_PSBT family.  Non-
    PSBT commands don't consume those bits, so slot 8 (REGISTER_WALLET)
    etc. simply set bit 3 with no side effects.
    """
    n_inputs = max(1, min(n_inputs, 4))
    n_outputs = max(1, min(n_outputs, 4))
    ctrl = command_slot & 0x0F
    ctrl |= ((n_inputs - 1) & 0x03) << 4
    ctrl |= ((n_outputs - 1) & 0x03) << 6
    return ctrl


def structured_lane_byte(descriptor_idx=0):
    return 0xE0 | (descriptor_idx & 0x0F)


def musig_lane_byte(descriptor_variant=0, round2=False):
    """Pick a structured-lane byte that selects a specific MuSig descriptor
    family.  Round selection is now handled by psbt_entropy[2], not bit
    0x10 of the lane byte, so this helper only needs to drive descriptor
    choice — the round2 flag is kept for signature-compatibility with
    call sites that pass both pieces together.
    """
    (_,) = (round2,)  # retained for API compatibility; selection happens via psbt_entropy[2]
    target_mod = descriptor_variant % 3
    for candidate in range(192, 256):
        if candidate % 3 == target_mod:
            return candidate
    raise ValueError("could not encode musig lane byte")


def make_entropy(command_slot, sign_subtype_slot=None,
                 n_inputs=1, n_outputs=1,
                 lane_byte=None, entropy8=0, fault_byte=0):
    """Build psbt_entropy for the structured lane.

    command_slot is mandatory so seeds always land on their intended
    command in fuzz_commands[].  sign_subtype_slot is required for
    SIGN_PSBT seeds; other structured commands ignore it.

    fault_byte controls pm_inject_typed_fault: values >= 64 disable all
    fault injection.  MuSig seeds need clean HMAC to survive init, so
    they should use fault_byte=0xFF.
    """
    ent = bytearray(ENTROPY_LEN)
    ent[0] = 0xFF if lane_byte is None else (lane_byte & 0xFF)
    ent[1] = encode_entropy1(command_slot, n_inputs=n_inputs, n_outputs=n_outputs)
    if sign_subtype_slot is not None:
        ent[2] = sign_subtype_slot & 0x0F
    ent[8] = entropy8 & 0xFF
    ent[15] = fault_byte & 0xFF
    return bytes(ent)


def raw_entropy():
    ent = bytearray(ENTROPY_LEN)
    ent[0] = 10  # raw mode (<=102)
    return ent


def make_cont_slot(seed_byte=0x42):
    slot = bytearray(TAIL_SLOT_SIZE)
    for i in range(TAIL_SLOT_SIZE):
        slot[i] = (seed_byte + i * 7) & 0xFF
    return bytes(slot)


def make_tail(size=2000, seed=0x55):
    tail = bytearray(size)
    for i in range(size):
        tail[i] = (seed + i * 13) & 0xFF
    return bytes(tail)


def make_slot_tail(slots, fault_kind=FAULT_CLEAN, fault_target=0,
                   fault_params=(0, 0), extra_tail_size=2000, extra_seed=0x55):
    """Build a tail: [packed slots] + [extra bytes] + [4-byte fault knobs]."""
    slot_data = bytearray()
    for s in slots:
        padded = bytearray(TAIL_SLOT_SIZE)
        n = min(len(s), TAIL_SLOT_SIZE)
        padded[:n] = s[:n]
        slot_data += padded
    extra = bytearray(extra_tail_size)
    for i in range(extra_tail_size):
        extra[i] = (extra_seed + i * 13) & 0xFF
    fault = bytearray(TAIL_FAULT_SIZE)
    fault[0] = fault_kind & 0x07
    fault[1] = fault_target & 0xFF
    fault[2] = fault_params[0] & 0xFF
    fault[3] = fault_params[1] & 0xFF
    return bytes(slot_data) + bytes(extra) + bytes(fault)


def make_fault_tail(size, seed, fault_kind=FAULT_CLEAN, fault_target=0,
                    fault_params=None):
    """Build a tail with specific fault knobs at the end.

    The body is filled deterministically from `seed`; the last 4 bytes
    carry the fault knobs (kind, target, param0, param1).
    """
    if fault_params is None:
        fault_params = []
    body_size = max(size - TAIL_FAULT_SIZE, 0)
    body = bytearray(body_size)
    for i in range(body_size):
        body[i] = (seed + i * 13) & 0xFF
    fault = bytearray(TAIL_FAULT_SIZE)
    fault[0] = fault_kind & 0x07
    fault[1] = fault_target & 0xFF
    if len(fault_params) > 0:
        fault[2] = fault_params[0] & 0xFF
    if len(fault_params) > 1:
        fault[3] = fault_params[1] & 0xFF
    return bytes(body) + bytes(fault)


def stable_seed_byte(label):
    return hashlib.sha256(label.encode("utf-8")).digest()[0]


def make_raw_get_pubkey_corpus(path, corpus_name, display=0, declared_len=None):
    """Build a raw GET_EXTENDED_PUBKEY APDU payload."""
    ent = raw_entropy()
    prefix = make_raw_prefix(ent)
    payload = bytearray()
    payload.append(display & 0xFF)
    payload.append((len(path) if declared_len is None else declared_len) & 0xFF)
    for step in path:
        payload.extend(struct.pack('>I', step))
    tail = bytes(payload) + make_tail(200, seed=stable_seed_byte(corpus_name))
    return (corpus_name, bytes(prefix) + tail)


def make_psbt_slot(seed_byte=0x42, amount=10000, addr_index=0, output_index=0,
                   force_op_return=False, sequence=0xFFFFFFFD, sighash=0x01,
                   bip32_change=0, is_input=True):
    """Shape a dense 64-byte tail slot for the PSBT builder.

    Dense byte map (matches psbt_model.c):
      Input slots:
        [0..31]  prev_txid       (32 bytes, raw)
        [32]     output_index    (1 byte)
        [33..40] amount          (uint64 LE)
        [41..44] sequence        (uint32 LE)
        [45]     sighash_type    (1 byte)
        [46]     bip32_change    (bit 0)
        [47..48] bip32_addr_index (uint16 LE)
        [50]     rawtx n_outputs hint
        [51..54] rawtx version
        [55..58] rawtx locktime
      Output slots:
        [0..7]   amount          (uint64 LE)
        [8..11]  bip32_addr_index (uint32 LE)
        [12]     script family hint
        [13]     is_change       (bit 0)
    """
    slot = bytearray(TAIL_SLOT_SIZE)
    for i in range(TAIL_SLOT_SIZE):
        slot[i] = (seed_byte + i * 7) & 0xFF
    if is_input:
        struct.pack_into('<Q', slot, 33, amount)
        slot[32] = output_index & 0xFF
        struct.pack_into('<I', slot, 41, sequence)
        slot[45] = sighash & 0xFF
        slot[46] = bip32_change & 0x01
        struct.pack_into('<H', slot, 47, addr_index & 0xFFFF)
        slot[50] = max(1, (output_index % 8) + 1)
        struct.pack_into('<I', slot, 51, 2)
        struct.pack_into('<I', slot, 55, 0)
    else:
        struct.pack_into('<Q', slot, 0, amount)
        struct.pack_into('<I', slot, 8, addr_index & 0xFFFFFFFF)
        slot[12] = 4 if force_op_return else 5
        slot[13] = 0x00
    return bytes(slot)


def make_psbt_slots(seed_byte=0x42, n_inputs=1, n_outputs=1, include_opreturn=False):
    slots = []
    for i in range(TAIL_N_SLOTS):
        is_input = i < n_inputs
        output_idx = i - n_inputs
        force_op_return = include_opreturn and n_outputs > 1 and output_idx == 0
        slots.append(make_psbt_slot(
            seed_byte=seed_byte + i * 5,
            amount=10000 + i * 333,
            addr_index=i % 20,
            output_index=i,
            force_op_return=force_op_return,
            sequence=0xFFFFFFFD,
            sighash=0x01,
            bip32_change=0,
            is_input=is_input,
        ))
    return slots


def configure_psbt_scenario_slots(slots, *, sign_subtype_slot, descriptor_idx,
                                  n_inputs, n_outputs, tx_version=2,
                                  locktime=0):
    slot0 = bytearray(slots[0])
    struct.pack_into('<I', slot0, 52, tx_version & 0xFFFFFFFF)
    struct.pack_into('<I', slot0, 56, locktime & 0xFFFFFFFF)
    slot0[60] = (max(1, min(n_inputs, 8)) - 1) & 0xFF
    slot0[61] = (max(1, min(n_outputs, 8)) - 1) & 0xFF
    slot0[62] = sign_subtype_slot & 0x0F
    slot0[63] = descriptor_idx & 0xFF
    slots[0] = bytes(slot0)
    return slots


def make_wallet_slots(seed_byte, template_idx, *, version=1, registered=False,
                      corrupt_key=False, name=None, display=0, is_change=0,
                      address_index=0, flip_hmac=False, fault_byte=0xFF):
    slots = [bytearray(make_cont_slot(seed_byte + i + template_idx)) for i in range(16)]
    struct.pack_into('<H', slots[0], 16, template_idx & 0xFFFF)
    flags = 0
    if version == 2:
        flags |= 0x01
    if registered:
        flags |= 0x02
    if corrupt_key:
        flags |= 0x04
    if name is not None:
        flags |= 0x08
        raw_name = name[:16]
        slots[0][1] = len(raw_name)
        slots[0][2:2 + len(raw_name)] = raw_name
    slots[0][18] = flags
    slots[0][19] = 0
    slots[0][32] = display & 1
    slots[0][33] = is_change & 1
    struct.pack_into('<I', slots[0], 34, address_index & 0xFFFFFFFF)
    slots[0][38] = 1 if registered else 0
    slots[0][39] = 1 if flip_hmac else 0
    slots[1][10] = fault_byte & 0xFF
    return [bytes(s) for s in slots]


def make_message_slots(seed_byte, *, message_length, printable=True,
                       purpose_idx=0, include_change=False, change=0,
                       address_index=0):
    slots = []
    for i in range(16):
        slot = bytearray(TAIL_SLOT_SIZE)
        for j in range(TAIL_SLOT_SIZE):
            slot[j] = (seed_byte + (j % 26) + i * 3) & 0xFF
        slots.append(slot)

    slots[0][0] = (purpose_idx & 0x03) | (0x04 if include_change else 0x00)
    slots[0][1] = change & 0x01
    struct.pack_into('<I', slots[0], 2, address_index & 0xFFFFFFFF)
    struct.pack_into('<H', slots[0], 6, message_length & 0xFFFF)
    slots[0][8] = 0 if printable else 1
    return [bytes(s) for s in slots]


def make_structured_sign_corpus(corpus_name, sign_subtype_slot, descriptor_idx,
                                command_slot=None,
                                n_inputs=1, n_outputs=1,
                                cont_seed=0x42, tail_size=4000,
                                sighash_seed=0, ui_approve=True,
                                swap_from_swap=False, swap_mode_val=SWAP_MODE_STANDARD,
                                include_opreturn=False,
                                tx_version=2, locktime=0,
                                fault_byte=None,
                                tail=None):
    """Build a structured SIGN_PSBT seed.

    By default the tail fault knobs are set to FAULT_CLEAN so the canonical
    scaffold is always reachable from this seed.  libFuzzer discovers that
    mutating the last 4 bytes activates different fault paths.
    """
    is_musig = sign_subtype_slot in (SIGN_SUBTYPE_MUSIG_R1, SIGN_SUBTYPE_MUSIG_R2)
    if is_musig:
        lane_byte = musig_lane_byte(descriptor_idx)
    else:
        lane_byte = structured_lane_byte(descriptor_idx)

    if fault_byte is None:
        fault_byte = 0xFF if is_musig else 0

    slot = CMD_SLOT_SIGN_PSBT_BASE if command_slot is None else command_slot

    ent = make_entropy(
        command_slot=slot,
        sign_subtype_slot=sign_subtype_slot,
        n_inputs=n_inputs,
        n_outputs=n_outputs,
        lane_byte=lane_byte,
        entropy8=sighash_seed,
        fault_byte=fault_byte,
    )
    prefix = make_prefix(
        ent,
        ui_approve=0 if ui_approve else 1,
        swap_called_from_swap=1 if swap_from_swap else 0,
        swap_mode=swap_mode_val,
    )
    if tail is None:
        psbt_slots = make_psbt_slots(
            cont_seed,
            n_inputs=n_inputs,
            n_outputs=n_outputs,
            include_opreturn=include_opreturn,
        )
        psbt_slots = configure_psbt_scenario_slots(
            psbt_slots,
            sign_subtype_slot=sign_subtype_slot,
            descriptor_idx=descriptor_idx,
            n_inputs=n_inputs,
            n_outputs=n_outputs,
            tx_version=tx_version,
            locktime=locktime,
        )
        tail = make_slot_tail(
            psbt_slots,
            fault_kind=FAULT_CLEAN,
            extra_tail_size=tail_size,
            extra_seed=stable_seed_byte(corpus_name),
        )
    return (corpus_name, prefix + tail)


# ── Seed generation ─────────────────────────────────────────────────────────

def generate_seeds(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    seeds = []

    # ═══════════════════════════════════════════════════════════════════════
    # SIGN_PSBT variants (subtype encoded in psbt_entropy[2])
    # ═══════════════════════════════════════════════════════════════════════

    # SIGN_DEFAULT base seeds (WPKH family, coherent I/O counts)
    for n_in in [1, 2]:
        for n_out in [1, 2]:
            seeds.append(make_structured_sign_corpus(
                f"sign_default_i{n_in}_o{n_out}",
                SIGN_SUBTYPE_DEFAULT_BASE,
                descriptor_idx=0,
                n_inputs=n_in,
                n_outputs=n_out,
                cont_seed=0x10 + n_in * 8 + n_out,
                sighash_seed=((n_in - 1) * 2 + (n_out - 1)),
            ))

    # SIGN_REGISTERED base seeds (multi and sortedmulti families)
    for desc_idx, label in [(2, "multi"), (4, "sortedmulti")]:
        for n_in in [1, 2]:
            seeds.append(make_structured_sign_corpus(
                f"sign_registered_{label}_i{n_in}",
                SIGN_SUBTYPE_REGISTERED_BASE,
                descriptor_idx=desc_idx,
                n_inputs=n_in,
                n_outputs=1,
                cont_seed=0x20 + desc_idx * 3 + n_in,
                sighash_seed=0x80 + desc_idx + n_in,
            ))

    # SIGN_RAWTX base seeds (SH-WPKH and TR families).
    rawtx_cases = [
        ("sign_rawtx_sh_wpkh", 3, 2),
        ("sign_rawtx_tr",      1, 1),
    ]
    for corpus_name, desc_idx, tx_version in rawtx_cases:
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            SIGN_SUBTYPE_RAWTX_BASE,
            descriptor_idx=desc_idx,
            n_inputs=1,
            n_outputs=1,
            cont_seed=0x30 + desc_idx,
            sighash_seed=0x20 + desc_idx,
            tx_version=tx_version,
        ))

    # SIGN_MUSIG base seeds: explicit round1/round2 slots.
    base_musig_cases = [
        ("sign_musig_i1_o1", 0, 1, 1, SIGN_SUBTYPE_MUSIG_R1, 0x00),
        ("sign_musig_i1_o2", 1, 1, 2, SIGN_SUBTYPE_MUSIG_R1, 0x82),
        ("sign_musig_i2_o1", 2, 2, 1, SIGN_SUBTYPE_MUSIG_R2, 0x83),
        ("sign_musig_i2_o2", 0, 2, 2, SIGN_SUBTYPE_MUSIG_R2, 0x01),
    ]
    for corpus_name, desc_idx, n_in, n_out, subtype_slot, sighash_seed in base_musig_cases:
        is_r2 = subtype_slot == SIGN_SUBTYPE_MUSIG_R2
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            subtype_slot,
            descriptor_idx=desc_idx,
            n_inputs=n_in,
            n_outputs=n_out,
            cont_seed=0x40 + desc_idx * 0x10 + (0x08 if is_r2 else 0),
            tail_size=6000,
            sighash_seed=sighash_seed,
            include_opreturn=(is_r2 and n_out > 1),
        ))

    # Descriptor diversity (hit each descriptor family, rotate sighash patterns,
    # mix tx-version / locktime toggles via the command_slot low bits).
    sign_descriptor_scenarios = [
        # (label, subtype_slot, desc_idx, n_in, n_out, sighash, slot_low_bits)
        ("sign_desc_default_wpkh",              SIGN_SUBTYPE_DEFAULT_BASE,    0, 1, 1, 0x00, 0x0),
        ("sign_desc_default_tr",                SIGN_SUBTYPE_DEFAULT_BASE,    1, 1, 2, 0x03, 0x1),
        ("sign_desc_registered_wsh_multi",      SIGN_SUBTYPE_REGISTERED_BASE, 2, 2, 2, 0x81, 0x3),
        ("sign_desc_default_sh_wpkh",           SIGN_SUBTYPE_DEFAULT_BASE,    3, 2, 1, 0x82, 0x2),
        ("sign_desc_registered_wsh_sortedmulti",SIGN_SUBTYPE_REGISTERED_BASE, 4, 2, 2, 0x83, 0x3),
        ("sign_desc_default_tr_pk",             SIGN_SUBTYPE_DEFAULT_BASE,    5, 1, 2, 0x01, 0x0),
        ("sign_desc_registered_wsh_and_v",      SIGN_SUBTYPE_REGISTERED_BASE, 6, 2, 2, 0x02, 0x3),
        ("sign_desc_registered_wsh_or_b",       SIGN_SUBTYPE_REGISTERED_BASE, 7, 2, 1, 0x03, 0x2),
    ]
    for corpus_name, subtype_slot, desc_idx, n_in, n_out, sighash_seed, slot_low in sign_descriptor_scenarios:
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            subtype_slot,
            descriptor_idx=desc_idx,
            command_slot=CMD_SLOT_SIGN_PSBT_BASE | slot_low,
            n_inputs=n_in,
            n_outputs=n_out,
            cont_seed=0x60 + desc_idx * 7 + subtype_slot,
            sighash_seed=sighash_seed,
        ))

    # High-input sighash mixers.
    seeds.append(make_structured_sign_corpus(
        "sign_sighash_mix_sh_wpkh_i4_o2",
        SIGN_SUBTYPE_DEFAULT_BASE,
        descriptor_idx=3,
        command_slot=CMD_SLOT_SIGN_PSBT_BASE | 0x3,
        n_inputs=4,
        n_outputs=2,
        cont_seed=0x96,
        tail_size=8000,
        sighash_seed=0xE4,
        include_opreturn=True,
    ))
    seeds.append(make_structured_sign_corpus(
        "sign_sighash_mix_wsh_sortedmulti_i4_o2",
        SIGN_SUBTYPE_REGISTERED_BASE,
        descriptor_idx=4,
        command_slot=CMD_SLOT_SIGN_PSBT_BASE | 0x3,
        n_inputs=4,
        n_outputs=2,
        cont_seed=0xA4,
        tail_size=8000,
        sighash_seed=0xAD,
        include_opreturn=True,
    ))

    # Focused MuSig unlock set: explicit round1/round2 coverage per descriptor family.
    musig_focus_cases = [
        ("sign_musig_r1_2of2_i1_o1",       0, 1, 1, SIGN_SUBTYPE_MUSIG_R1, 0x00),
        ("sign_musig_r1_script_leaf_i2_o1",1, 2, 1, SIGN_SUBTYPE_MUSIG_R1, 0x82),
        ("sign_musig_r1_3of3_i2_o2",       2, 2, 2, SIGN_SUBTYPE_MUSIG_R1, 0x83),
        ("sign_musig_r2_2of2_i1_o1",       0, 1, 1, SIGN_SUBTYPE_MUSIG_R2, 0x01),
        ("sign_musig_r2_script_leaf_i2_o2",1, 2, 2, SIGN_SUBTYPE_MUSIG_R2, 0x81),
        ("sign_musig_r2_3of3_i2_o2",       2, 2, 2, SIGN_SUBTYPE_MUSIG_R2, 0x03),
    ]
    for corpus_name, desc_idx, n_in, n_out, subtype_slot, sighash_seed in musig_focus_cases:
        is_r2 = subtype_slot == SIGN_SUBTYPE_MUSIG_R2
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            subtype_slot,
            descriptor_idx=desc_idx,
            n_inputs=n_in,
            n_outputs=n_out,
            cont_seed=0xB0 + desc_idx * 9 + (0x04 if is_r2 else 0),
            tail_size=8000,
            sighash_seed=sighash_seed,
            include_opreturn=(n_out > 1),
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # GET_WALLET_ADDRESS (command_slot 10..11 — structured lane only)
    # ═══════════════════════════════════════════════════════════════════════

    family_names = [
        "wpkh", "pkh", "sh_wpkh", "tr", "wsh_multi", "wsh_sortedmulti",
        "tr_pk", "sh_multi", "wsh_and_v", "wsh_or_b", "wsh_or_i",
    ]
    for tmpl_idx, fname in enumerate(family_names):
        slots = make_wallet_slots(
            0x10,
            tmpl_idx,
            version=1,
            registered=False,
            display=0,
            is_change=0,
            address_index=tmpl_idx * 17,
        )
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_GET_WALLET_ADDR_BASE))
        seeds.append((f"addr_valid_{fname}",
                      prefix + make_slot_tail(slots, extra_seed=0x40 + tmpl_idx)))

        slots2 = make_wallet_slots(
            0x30,
            tmpl_idx,
            version=1,
            registered=True,
            display=1,
            is_change=1,
            address_index=0x100 + tmpl_idx,
        )
        prefix2 = make_prefix(make_entropy(command_slot=CMD_SLOT_GET_WALLET_ADDR_BASE | 0x1))
        seeds.append((f"addr_registered_{fname}",
                      prefix2 + make_slot_tail(slots2, extra_seed=0x50 + tmpl_idx)))

        slots3 = make_wallet_slots(
            0x50,
            tmpl_idx,
            version=1,
            registered=False,
            corrupt_key=True,
            address_index=0x200 + tmpl_idx,
        )
        prefix3 = make_prefix(make_entropy(command_slot=CMD_SLOT_GET_WALLET_ADDR_BASE))
        seeds.append((f"addr_invalid_{fname}",
                      prefix3 + make_slot_tail(slots3, extra_seed=0x60 + tmpl_idx)))

    slots = make_wallet_slots(0x60, 3, version=1, address_index=0x1234)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_GET_WALLET_ADDR_BASE))
    seeds.append(("get_addr_taproot",
                  prefix + make_slot_tail(slots, extra_seed=0xB0)))

    # ═══════════════════════════════════════════════════════════════════════
    # REGISTER_WALLET (command_slot 8..9 — structured lane only)
    # ═══════════════════════════════════════════════════════════════════════

    for template_idx in range(REGISTER_WALLET_TEMPLATE_COUNT):
        slots = make_wallet_slots(0x90, template_idx, version=1)
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_REGISTER_WALLET_BASE))
        seeds.append((f"struct_regwallet_tmpl{template_idx}",
                      prefix + make_slot_tail(slots,
                                              extra_seed=0xA0 + template_idx)))

    for template_idx in range(REGISTER_WALLET_TEMPLATE_COUNT):
        slots = make_wallet_slots(0xF0, template_idx, version=2)
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_REGISTER_WALLET_BASE | 0x1))
        seeds.append((f"struct_regwallet_v2_tmpl{template_idx}",
                      prefix + make_slot_tail(slots,
                                              extra_seed=0xC0 + template_idx)))

    for template_idx in [0, 4]:
        slots = make_wallet_slots(0xD0, template_idx, version=1, corrupt_key=True)
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_REGISTER_WALLET_BASE))
        seeds.append((f"struct_regwallet_corrupt_tmpl{template_idx}",
                      prefix + make_slot_tail(slots,
                                              extra_seed=0xD0 + template_idx)))

    slots = make_wallet_slots(0xE0, 0, version=1, registered=True)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_REGISTER_WALLET_BASE))
    seeds.append(("struct_regwallet_named",
                  prefix + make_slot_tail(slots, extra_seed=0xE5)))

    name_variants = [
        ("struct_regwallet_name_ascii16",       b"Policy-Depth-001", 0),
        ("struct_regwallet_name_leading_space", b" badname",         0),
        ("struct_regwallet_name_trailing_space",b"badname ",         0),
    ]
    for corpus_name, raw_name, template_idx in name_variants:
        slots = make_wallet_slots(0x88, template_idx, version=1, name=raw_name)
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_REGISTER_WALLET_BASE))
        seeds.append((corpus_name,
                      prefix + make_slot_tail(slots,
                                              extra_seed=stable_seed_byte(corpus_name))))

    # ═══════════════════════════════════════════════════════════════════════
    # SIGN_MESSAGE (command_slot 12..13 — structured lane only)
    # ═══════════════════════════════════════════════════════════════════════

    # Short printable message (single chunk, <64 bytes) — two seeds with
    # different command slots so corpus exercises both SIGN_MESSAGE slots.
    for slot_lsb in [0, 1]:
        slots = make_message_slots(0x41, message_length=11, printable=True)
        prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE | slot_lsb))
        seeds.append((f"struct_sign_message_short_s{slot_lsb}",
                      prefix + make_slot_tail(slots, extra_seed=0xB0 + slot_lsb)))

    slots = make_message_slots(0xA0, message_length=200, printable=True)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE))
    seeds.append(("struct_sign_message_multi_chunk",
                  prefix + make_slot_tail(slots, extra_seed=0xBC)))

    slots = make_message_slots(0xB0, message_length=200, printable=False,
                               purpose_idx=3)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE))
    seeds.append(("struct_sign_message_long",
                  prefix + make_slot_tail(slots, extra_seed=0xBD)))

    slots = make_message_slots(0x01, message_length=32, printable=False)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE))
    seeds.append(("struct_sign_message_binary",
                  prefix + make_slot_tail(slots, extra_seed=0xBE)))

    slots = make_message_slots(0xC0, message_length=64, printable=True)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE), ui_approve=1)
    seeds.append(("struct_sign_message_reject",
                  prefix + make_slot_tail(slots, extra_seed=0xBF)))

    slots = make_message_slots(0xD0, message_length=64, printable=True)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE))
    seeds.append(("struct_sign_message_boundary_64",
                  prefix + make_slot_tail(slots, extra_seed=0xC1)))

    slots = make_message_slots(0xE0, message_length=641, printable=True,
                               purpose_idx=2)
    prefix = make_prefix(make_entropy(command_slot=CMD_SLOT_SIGN_MESSAGE_BASE))
    seeds.append(("struct_sign_message_boundary_641",
                  prefix + make_slot_tail(slots, extra_seed=0xC2)))

    # ═══════════════════════════════════════════════════════════════════════
    # SWAP_CHECK / SWAP_HELPERS (command_slot 14 / 15 — structured lane only)
    # ═══════════════════════════════════════════════════════════════════════

    for sm_idx, sm_val in enumerate([SWAP_MODE_STANDARD, SWAP_MODE_CROSSCHAIN, SWAP_MODE_ERROR]):
        ent = make_entropy(command_slot=CMD_SLOT_SWAP_CHECK)
        prefix = make_prefix(ent, swap_called_from_swap=1, swap_mode=sm_val)
        slots = [make_cont_slot(0x70 + i) for i in range(16)]
        seeds.append((f"swap_check_mode{sm_idx}",
                      prefix + make_slot_tail(slots, extra_tail_size=1000, extra_seed=0xC0 + sm_idx)))

    for sm_idx, sm_val in enumerate([SWAP_MODE_STANDARD, SWAP_MODE_CROSSCHAIN, SWAP_MODE_ERROR]):
        ent = make_entropy(command_slot=CMD_SLOT_SWAP_HELPERS)
        prefix = make_prefix(ent, swap_called_from_swap=1, swap_mode=sm_val)
        slots = [make_cont_slot(0x80 + i) for i in range(16)]
        seeds.append((f"swap_helpers_mode{sm_idx}",
                      prefix + make_slot_tail(slots, extra_tail_size=1000, extra_seed=0xD0 + sm_idx)))

    # ═══════════════════════════════════════════════════════════════════════
    # SIGN_PSBT × swap / UI-reject / deep-tail variants
    # ═══════════════════════════════════════════════════════════════════════

    variant_sets = [
        # (label prefix, kwargs_overrides for the three subtype_slot variants)
        ("sign_swap",      {"swap_from_swap": True}),
        ("sign_noapprove", {"ui_approve":     False}),
    ]
    subtypes = [
        ("default",    SIGN_SUBTYPE_DEFAULT_BASE,    0),
        ("registered", SIGN_SUBTYPE_REGISTERED_BASE, 2),
        ("musig_r1",   SIGN_SUBTYPE_MUSIG_R1,        0),
    ]
    for label_prefix, extra in variant_sets:
        for subtype_label, subtype_slot, desc_idx in subtypes:
            corpus_name = f"{label_prefix}_{subtype_label}"
            seeds.append(make_structured_sign_corpus(
                corpus_name,
                subtype_slot,
                descriptor_idx=desc_idx,
                n_inputs=1,
                n_outputs=1,
                cont_seed=0xA0 + subtype_slot,
                tail_size=4000,
                **extra,
            ))

    # Deep tail variants for each family
    for subtype_label, subtype_slot, desc_idx in subtypes:
        seeds.append(make_structured_sign_corpus(
            f"sign_deep_{subtype_label}_i2o2",
            subtype_slot,
            descriptor_idx=desc_idx + (1 if subtype_slot == SIGN_SUBTYPE_MUSIG_R1 else 2),
            n_inputs=2,
            n_outputs=2,
            cont_seed=0xC0 + subtype_slot * 3,
            tail_size=20000,
            sighash_seed=0x93 + subtype_slot,
            include_opreturn=True,
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # RAW MODE: GET_EXTENDED_PUBKEY
    #
    # The current harness dispatches raw GET_EXTENDED_PUBKEY and
    # GET_MASTER_FINGERPRINT only.  Continuation-based commands stay
    # structured-only; keep the raw corpus focused on these two handlers.
    # ═══════════════════════════════════════════════════════════════════════

    bip32_paths = [
        ([0x80000054, 0x80000001, 0x80000000], "raw_get_pubkey_m_84h_1h_0h", 0),
        ([0x80000031, 0x80000001, 0x80000000], "raw_get_pubkey_m_49h_1h_0h", 0),
        ([0x80000056, 0x80000001, 0x80000000], "raw_get_pubkey_m_86h_1h_0h", 0),
        ([0x8000002C, 0x80000001, 0x80000000], "raw_get_pubkey_m_44h_1h_0h", 0),
        ([0x80000030, 0x80000001, 0x80000000], "raw_get_pubkey_m_48h_1h_0h", 0),
        ([0x80000054, 0x80000001, 0x80000000, 0, 0], "raw_get_pubkey_m_84h_1h_0h_0_0", 0),
        ([4541509 ^ 0x80000000, 1112098098 ^ 0x80000000], "raw_get_pubkey_electrum_whitelist", 0),
        ([0x8000002D, 0x80000001, 0x80000000], "raw_get_pubkey_m_45h_1h_0h", 0),
        ([0x80000030, 0x80000001, 0x80000000, 0x80000001], "raw_get_pubkey_m_48h_1h_0h_1h", 0),
        ([0x80000030, 0x80000001, 0x80000000, 0x80000002], "raw_get_pubkey_m_48h_1h_0h_2h", 0),
        ([0x80000054, 0x80000001, 0x80000064, 1, 50000], "raw_get_pubkey_m_84h_1h_100h_1_50000", 0),
        ([0x80000054, 0x80000001, 0x80000000, 0, 1, 2, 3, 4], "raw_get_pubkey_depth8_safe", 0),
        ([], "raw_get_pubkey_master_display", 1),
        ([0x80000054, 0x80000000, 0x80000000], "raw_get_pubkey_bad_coin_type", 0),
        ([0x80000054, 0x80000001, 0x80000065], "raw_get_pubkey_bad_account", 0),
        ([84, 0x80000001, 0x80000000], "raw_get_pubkey_bad_unhardened_prefix", 0),
        ([0x80000054, 0x80000001, 0x80000000, 0x80000000, 0], "raw_get_pubkey_bad_hardened_suffix", 0),
        ([0x80000030, 0x80000001, 0x80000000, 0x80000003], "raw_get_pubkey_bad_bip48_script", 0),
        ([0x80000054, 0x80000000, 0x80000000], "raw_get_pubkey_bad_coin_type_display", 1),
    ]

    for path, corpus_name, display in bip32_paths:
        seeds.append(make_raw_get_pubkey_corpus(path, corpus_name, display=display))

    seeds.append(make_raw_get_pubkey_corpus(
        [0x80000054, 0x80000001, 0x80000000, 0, 1, 2, 3, 4],
        "raw_get_pubkey_declared_len9",
        display=0,
        declared_len=9,
    ))

    # ═══════════════════════════════════════════════════════════════════════
    # RAW MODE: GET_MASTER_FINGERPRINT
    # ═══════════════════════════════════════════════════════════════════════

    ent = raw_entropy()
    prefix = make_raw_prefix(ent)
    seeds.append(("raw_get_master_fp", bytes(prefix) + make_tail(100, seed=0xDD)))

    # ═══════════════════════════════════════════════════════════════════════
    # DEEP-SIGN STARTERS: one coherent seed per descriptor family that
    # should be able to reach compute_tx_hashes.
    # ═══════════════════════════════════════════════════════════════════════

    deep_sign_families = [
        # (label, subtype_slot, desc_idx, n_in, n_out, cont_seed)
        ("deep_wpkh",            SIGN_SUBTYPE_DEFAULT_BASE,    0, 2, 2, 0x01),
        ("deep_tr",              SIGN_SUBTYPE_DEFAULT_BASE,    1, 2, 2, 0x02),
        ("deep_sh_wpkh",         SIGN_SUBTYPE_DEFAULT_BASE,    3, 2, 2, 0x03),
        ("deep_wsh_multi",       SIGN_SUBTYPE_REGISTERED_BASE, 2, 2, 2, 0x04),
        ("deep_wsh_sortedmulti", SIGN_SUBTYPE_REGISTERED_BASE, 4, 2, 2, 0x05),
        ("deep_tr_pk",           SIGN_SUBTYPE_REGISTERED_BASE, 5, 2, 2, 0x06),
        ("deep_wsh_and_v",       SIGN_SUBTYPE_REGISTERED_BASE, 6, 1, 2, 0x07),
        ("deep_wsh_or_b",        SIGN_SUBTYPE_REGISTERED_BASE, 7, 1, 2, 0x08),
        ("deep_musig_2of2",      SIGN_SUBTYPE_MUSIG_R1,        0, 1, 2, 0x09),
        ("deep_musig_3of3",      SIGN_SUBTYPE_MUSIG_R1,        2, 1, 2, 0x0A),
    ]
    for label, subtype_slot, desc_idx, n_in, n_out, cs in deep_sign_families:
        seeds.append(make_structured_sign_corpus(
            label,
            subtype_slot,
            descriptor_idx=desc_idx,
            n_inputs=n_in,
            n_outputs=n_out,
            cont_seed=cs,
            tail_size=8000,
            sighash_seed=0x00,
            ui_approve=True,
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # SABOTAGE STRATUM: one seed per builder contradiction kind and per
    # continuation sabotage kind so libFuzzer starts with a concrete
    # example of every fault site.  Every other seed in the corpus pins
    # fault_kind to FAULT_CLEAN, which is why this section exists at all.
    # ═══════════════════════════════════════════════════════════════════════

    builder_fault_seeds = [
        ("sign_fault_sighash",   FAULT_SIGHASH_OVR, 0, [0x42, 0]),
        ("sign_fault_amtxor",    FAULT_AMOUNT_XOR,  0, [0x10, 0x01]),
        ("sign_fault_seqlock",   FAULT_SEQ_LOCK,    0, [0, 0]),
        ("sign_fault_outamt",    FAULT_OUTPUT_AMT,   0, [0, 0]),
        ("sign_fault_hmac",      FAULT_WRONG_HMAC,  0, [0xAA, 0]),
    ]
    for corpus_name, fk, ft, fp in builder_fault_seeds:
        subtype = (SIGN_SUBTYPE_REGISTERED_BASE
                   if fk == FAULT_WRONG_HMAC else SIGN_SUBTYPE_DEFAULT_BASE)
        tail = make_fault_tail(
            4000,
            seed=stable_seed_byte(corpus_name),
            fault_kind=fk,
            fault_target=ft,
            fault_params=fp,
        )
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            subtype,
            descriptor_idx=0 if subtype == SIGN_SUBTYPE_DEFAULT_BASE else 2,
            n_inputs=1,
            n_outputs=1,
            cont_seed=0xD0 + fk,
            tail=tail,
        ))

    cont_fault_seeds = [
        ("sign_fault_cont_trunc",       1, FAULT_CONT_TRUNCATE, [0x04, 0]),
        ("sign_fault_cont_flip",        2, FAULT_CONT_FLIP,     [0x02, 0x10]),
        ("sign_fault_cont_late_trunc",  9, FAULT_CONT_TRUNCATE, [0x20, 0]),
        ("sign_fault_cont_late_flip",   9, FAULT_CONT_FLIP,     [0x01, 0x40]),
    ]
    for corpus_name, tgt_round, fk, fp in cont_fault_seeds:
        tail = make_fault_tail(
            4000,
            seed=stable_seed_byte(corpus_name),
            fault_kind=fk,
            fault_target=tgt_round,
            fault_params=fp,
        )
        seeds.append(make_structured_sign_corpus(
            corpus_name,
            SIGN_SUBTYPE_DEFAULT_BASE,
            descriptor_idx=0,
            n_inputs=1,
            n_outputs=1,
            cont_seed=0xE0 + tgt_round,
            tail=tail,
        ))

    # ═══════════════════════════════════════════════════════════════════════
    # DIVERSE CONTINUATION DATA PATTERNS
    # ═══════════════════════════════════════════════════════════════════════

    diverse_cases = [
        ("default",    SIGN_SUBTYPE_DEFAULT_BASE,    3),
        ("registered", SIGN_SUBTYPE_REGISTERED_BASE, 2),
        ("rawtx",      SIGN_SUBTYPE_RAWTX_BASE,      3),
        ("musig_r2",   SIGN_SUBTYPE_MUSIG_R2,        1),
    ]
    for label, subtype_slot, desc_idx in diverse_cases:
        is_musig = subtype_slot in (SIGN_SUBTYPE_MUSIG_R1, SIGN_SUBTYPE_MUSIG_R2)
        lane_byte = musig_lane_byte(desc_idx) if is_musig else structured_lane_byte(desc_idx)
        ent = make_entropy(
            command_slot=CMD_SLOT_SIGN_PSBT_BASE,
            sign_subtype_slot=subtype_slot,
            n_inputs=1,
            n_outputs=1,
            lane_byte=lane_byte,
            fault_byte=0xFF if is_musig else 0,
        )
        slots = []
        for i in range(16):
            slot = bytearray(TAIL_SLOT_SIZE)
            if i % 3 == 0:
                pass
            elif i % 3 == 1:
                for j in range(TAIL_SLOT_SIZE):
                    slot[j] = (0x42 * (i + 1) + j * 11) & 0xFF
            else:
                for j in range(TAIL_SLOT_SIZE):
                    slot[j] = 0xFF
            slots.append(bytes(slot))
        prefix = make_prefix(ent)
        seeds.append((f"sign_diverse_cont_{label}",
                      prefix + make_slot_tail(slots, extra_tail_size=4000,
                                              extra_seed=0x22 + subtype_slot)))

    # ═══════════════════════════════════════════════════════════════════════
    # Write all seeds
    # ═══════════════════════════════════════════════════════════════════════

    written = 0
    for name, blob in seeds:
        path = os.path.join(output_dir, name)
        with open(path, "wb") as f:
            f.write(blob)
        written += 1

    print(f"Generated {written} seed corpus files in {output_dir} (prefix size {PREFIX_SIZE})")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "base-corpus"
    generate_seeds(out)
