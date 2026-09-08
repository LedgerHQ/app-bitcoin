#!/usr/bin/env python3
"""Generate the C unit-test vector array from the pinned BIP-322 test vectors.

Input:
    specs/bip322/basic-test-vectors.json  -- verbatim copy of bip-0322/basic-test-vectors.json

Output (overwritten):
    unit-tests/bip322_vectors.inc.c       -- static C array of the tx_hashes vectors

Only the "tx_hashes" table is consumed: for each (message, address) pair it gives the
BIP0322-signed-message tagged hash of the message and the txids of the to_spend and
to_sign virtual transactions. Every hash is recomputed here and compared with the JSON
before emitting anything, so that a byte-order or encoding misreading of the file cannot
silently turn into a wrong expected value.

Run this script manually after replacing the JSON and commit the result. Pass --check
(e.g. in CI) to verify the committed output is up to date instead of regenerating it.
"""

from __future__ import annotations

import argparse
import difflib
import json
import struct
import sys
from hashlib import sha256
from pathlib import Path

SPECS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPECS_DIR.parents[1]
VECTORS_FILE = SPECS_DIR / "basic-test-vectors.json"
VECTORS_OUT = REPO_ROOT / "unit-tests" / "bip322_vectors.inc.c"

BIP0322_TAG = b"BIP0322-signed-message"


# ---------------------------------------------------------------------------
# bech32 / bech32m (BIP-173 / BIP-350) address decoding
# ---------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in bech32 data")
    return ret


def address_to_script(address: str) -> bytes:
    """Decodes a segwit (bech32/bech32m) address into its scriptPubKey."""
    if address.lower() != address and address.upper() != address:
        raise ValueError(f"mixed-case address: {address}")
    address = address.lower()
    hrp, sep, data_part = address.rpartition("1")
    if not sep or hrp not in ("bc", "tb", "bcrt"):
        raise ValueError(f"unsupported address (only segwit addresses are handled): {address}")
    data = [_CHARSET.find(c) for c in data_part]
    if -1 in data:
        raise ValueError(f"invalid bech32 character in {address}")
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    witness_version = data[0]
    program = bytes(_convertbits(data[1:-6], 5, 8))
    expected_const = _BECH32_CONST if witness_version == 0 else _BECH32M_CONST
    if const != expected_const:
        raise ValueError(f"bad checksum for {address}")
    if not 2 <= len(program) <= 40:
        raise ValueError(f"bad witness program length for {address}")
    op = 0 if witness_version == 0 else 0x50 + witness_version
    return bytes([op, len(program)]) + program


# ---------------------------------------------------------------------------
# BIP-322 virtual transactions (independent reimplementation, used to
# cross-check the JSON before emitting it)
# ---------------------------------------------------------------------------

def tagged_hash(tag: bytes, message: bytes) -> bytes:
    tag_hash = sha256(tag).digest()
    return sha256(tag_hash + tag_hash + message).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


def to_spend_tx(message_hash: bytes, challenge_script: bytes) -> bytes:
    return b"".join([
        struct.pack("<i", 0),                       # nVersion
        b"\x01",                                    # 1 input
        b"\x00" * 32, struct.pack("<I", 0xFFFFFFFF),  # null outpoint
        b"\x22\x00\x20" + message_hash,             # scriptSig: OP_0 PUSH32(message_hash)
        struct.pack("<I", 0),                       # nSequence
        b"\x01",                                    # 1 output
        struct.pack("<q", 0),                       # value
        bytes([len(challenge_script)]) + challenge_script,
        struct.pack("<I", 0),                       # nLockTime
    ])


def to_sign_tx(to_spend_txid: bytes) -> bytes:
    return b"".join([
        struct.pack("<i", 0),                       # nVersion
        b"\x01",                                    # 1 input
        to_spend_txid, struct.pack("<I", 0),        # spends to_spend:0
        b"\x00",                                    # empty scriptSig
        struct.pack("<I", 0),                       # nSequence
        b"\x01",                                    # 1 output
        struct.pack("<q", 0),                       # value
        b"\x01\x6a",                                # OP_RETURN
        struct.pack("<I", 0),                       # nLockTime
    ])


# ---------------------------------------------------------------------------
# Loading and cross-checking
# ---------------------------------------------------------------------------

def load_tx_hashes_vectors() -> list[dict]:
    """Returns the tx_hashes vectors, with all byte fields decoded into bytes objects
    (txids in the internal byte order used in transaction serializations and in
    PSBT_IN_PREVIOUS_TXID), after checking them against an independent computation."""
    doc = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    vectors = []
    for i, entry in enumerate(doc["tx_hashes"]):
        message = entry["message"].encode("utf-8")
        script = address_to_script(entry["address"])
        message_hash = bytes.fromhex(entry["message_hash"])
        # txids are displayed in reverse byte order
        to_spend_txid = bytes.fromhex(entry["to_spend_tx_hash"])[::-1]
        to_sign_txid = bytes.fromhex(entry["to_sign_tx_hash"])[::-1]

        computed_message_hash = tagged_hash(BIP0322_TAG, message)
        if computed_message_hash != message_hash:
            raise SystemExit(f"tx_hashes[{i}]: message_hash does not match the tagged hash")
        computed_to_spend_txid = sha256d(to_spend_tx(message_hash, script))
        if computed_to_spend_txid != to_spend_txid:
            raise SystemExit(f"tx_hashes[{i}]: to_spend_tx_hash does not match")
        if sha256d(to_sign_tx(to_spend_txid)) != to_sign_txid:
            raise SystemExit(f"tx_hashes[{i}]: to_sign_tx_hash does not match")

        vectors.append({
            "message": message,
            "address": entry["address"],
            "script": script,
            "message_hash": message_hash,
            "to_spend_txid": to_spend_txid,
            "to_sign_txid": to_sign_txid,
        })
    return vectors


# ---------------------------------------------------------------------------
# C emission
# ---------------------------------------------------------------------------

def c_bytes(data: bytes, indent: str = "    ") -> str:
    if not data:
        return indent + "0"  # placeholder; the length field is what matters
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        lines.append(indent + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return "\n".join(lines)


def c_string(data: bytes) -> str:
    """A C string literal for the (UTF-8) message, escaping everything outside printable
    ASCII as octal escapes (which cannot swallow the following characters, unlike \\x)."""
    out = []
    for b in data:
        if b == 0x22:
            out.append('\\"')
        elif b == 0x5C:
            out.append("\\\\")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03o}")
    return '"' + "".join(out) + '"'


def emit_vectors(vectors: list[dict]) -> str:
    out = [
        "// Generated by specs/bip322/gen.py. DO NOT EDIT.",
        "// Source: specs/bip322/basic-test-vectors.json (the \"tx_hashes\" table), a pinned",
        "// copy of bip-0322/basic-test-vectors.json from the bips repository.",
        "// clang-format off",
        "",
        "typedef struct {",
        "    const char *message_str;  // the message, as a C string literal (for test output)",
        "    const uint8_t *message;   // the UTF-8 encoded message",
        "    size_t message_len;",
        "    const char *address;",
        "    const uint8_t *challenge_script;  // scriptPubKey of address",
        "    size_t challenge_script_len;",
        "    uint8_t message_hash[32];   // BIP0322-signed-message tagged hash of message",
        "    uint8_t to_spend_txid[32];  // txid of to_spend, in internal byte order",
        "    uint8_t to_sign_txid[32];   // txid of to_sign, in internal byte order",
        "} bip322_tx_hashes_vector_t;",
        "",
    ]
    for i, v in enumerate(vectors):
        out.append(f"static const uint8_t vec_{i:03d}_message[] = {{")
        out.append(c_bytes(v["message"]))
        out.append("};")
        out.append(f"static const uint8_t vec_{i:03d}_script[] = {{")
        out.append(c_bytes(v["script"]))
        out.append("};")
        out.append("")

    out.append("static const bip322_tx_hashes_vector_t BIP322_TX_HASHES_VECTORS[] = {")
    for i, v in enumerate(vectors):
        out.append("    {")
        out.append(f"        .message_str = {c_string(v['message'])},")
        out.append(f"        .message = vec_{i:03d}_message,")
        out.append(f"        .message_len = {len(v['message'])},")
        out.append(f"        .address = \"{v['address']}\",")
        out.append(f"        .challenge_script = vec_{i:03d}_script,")
        out.append(f"        .challenge_script_len = {len(v['script'])},")
        for field in ("message_hash", "to_spend_txid", "to_sign_txid"):
            out.append(f"        .{field} = {{")
            out.append(c_bytes(v[field], indent="            "))
            out.append("        },")
        out.append("    },")
    out.append("};")
    out.append("")
    out.append("#define BIP322_TX_HASHES_VECTORS_COUNT "
               "(sizeof(BIP322_TX_HASHES_VECTORS) / sizeof(BIP322_TX_HASHES_VECTORS[0]))")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def generate_outputs() -> list[tuple[Path, str]]:
    return [(VECTORS_OUT, emit_vectors(load_tx_hashes_vectors()) + "\n")]


def write_outputs(outputs: list[tuple[Path, str]]) -> int:
    for path, content in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"wrote {path.relative_to(REPO_ROOT)}")
    return 0


def check_outputs(outputs: list[tuple[Path, str]]) -> int:
    stale: list[Path] = []
    for path, content in outputs:
        rel = path.relative_to(REPO_ROOT)
        current = path.read_text() if path.exists() else None
        if current == content:
            print(f"ok       {rel}")
            continue
        stale.append(rel)
        if current is None:
            print(f"MISSING  {rel}  (file does not exist)")
            continue
        print(f"DRIFT    {rel}")
        sys.stdout.writelines(difflib.unified_diff(
            current.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"{rel} (committed)",
            tofile=f"{rel} (generated)",
        ))
    if stale:
        print()
        print(f"error: {len(stale)} generated file(s) are out of date; regenerate with:")
        print("    python3 specs/bip322/gen.py")
        return 1
    print("All generated files are up to date.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gen.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "-c", "--check", action="store_true",
        help="don't write anything; verify the committed file matches what this script "
        "would generate and exit non-zero on any drift.",
    )
    args = parser.parse_args(argv)
    outputs = generate_outputs()
    if args.check:
        return check_outputs(outputs)
    return write_outputs(outputs)


if __name__ == "__main__":
    sys.exit(main())
