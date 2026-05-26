#!/usr/bin/env python3
"""Generate the C cleartext spec tables and unit-test vector arrays from the
BIP388 cleartext TOML files.

Inputs:
    specs/bip388/cleartext.toml        -- spec for the cleartext encoder
    specs/bip388/test_vectors.toml     -- test vectors

Outputs:
    src/common/cleartext_specs.h       -- enums + extern decls (overwritten)
    src/common/cleartext_specs.c       -- spec tables and string pool (overwritten)
    unit-tests/cleartext_vectors.inc.c -- static C array of test vectors (overwritten)

Run this script manually after changing the TOML files. The output is committed.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


REPO_ROOT = Path(__file__).resolve().parents[2]
SPECS_DIR = REPO_ROOT / "specs" / "bip388"
SPEC_FILE = SPECS_DIR / "cleartext.toml"
VECTORS_FILE = SPECS_DIR / "test_vectors.toml"
HEADER_OUT = REPO_ROOT / "src" / "common" / "cleartext_specs.h"
SOURCE_OUT = REPO_ROOT / "src" / "common" / "cleartext_specs.c"
VECTORS_OUT = REPO_ROOT / "unit-tests" / "cleartext_vectors.inc.c"


# Mirrors `binding_name_kind` in the Rust build.rs: strip trailing digits,
# then map to a kind.
_BINDING_KIND = {
    "key": "KEY",
    "internal_key": "KEY",
    "keys": "KEYS",
    "threshold": "THRESHOLD",
    "timelock": "TIMELOCK",
    "sub": "SUB",
}


def binding_kind(name: str) -> str | None:
    base = name.rstrip("0123456789")
    kind = _BINDING_KIND.get(base)
    if kind is None and base == "leaves":
        # `$leaves` is structural and never appears in cleartext output.
        return "LEAVES"
    return kind


def part_kind_c(kind: str) -> str:
    return f"CT_PART_{kind}"


# Pattern parsing -----------------------------------------------------------

_BINDING_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*|\$[A-Za-z_][A-Za-z0-9_]*|[(),]")


def pattern_bindings(pattern: str) -> list[tuple[str, str]]:
    """Return the list of (binding_name, kind) in the order they appear in
    the pattern string. Excludes structural bindings (LEAVES)."""
    bindings: list[tuple[str, str]] = []
    seen = set()
    for m in _BINDING_RE.finditer(pattern):
        name = m.group(1)
        if name in seen:
            raise ValueError(f"binding {name!r} appears twice in pattern {pattern!r}")
        seen.add(name)
        kind = binding_kind(name)
        if kind is None:
            raise ValueError(f"unknown binding name {name!r} in pattern {pattern!r}")
        bindings.append((name, kind))
    return bindings


def is_musig_pattern(pattern: str) -> bool:
    """A pattern is a 'musig pattern' when it uses musig(...) as a key
    expression. Such patterns require the round-trip check
    `threshold == n_keys` at scoring time."""
    return "musig(" in pattern


# String pool ---------------------------------------------------------------


class StringPool:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._offsets: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s in self._offsets:
            return self._offsets[s]
        off = len(self._buf)
        self._offsets[s] = off
        self._buf.extend(s.encode("utf-8"))
        self._buf.append(0)
        return off

    def as_bytes(self) -> bytes:
        return bytes(self._buf)


# Spec emission -------------------------------------------------------------


def parse_spec_file() -> dict[str, Any]:
    with open(SPEC_FILE, "rb") as f:
        return tomllib.load(f)


def parse_vectors_file() -> dict[str, Any]:
    with open(VECTORS_FILE, "rb") as f:
        return tomllib.load(f)


def build_parts(
    entry: dict[str, Any], pool: StringPool
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    """Return (parts, bindings).

    Each part is one of:
        ("LITERAL", text, "")    -- a literal string (placed in pool)
        ("KEY"|"KEYS"|...,        -- a dynamic placeholder, binding name
         binding_name, "")

    Bindings are the ordered list of (name, kind) extracted from the first
    pattern (assumed identical across all patterns of an entry).
    """
    patterns: list[str] = entry["patterns"]
    cleartext: list[str] = entry["cleartext"]

    if not patterns:
        raise ValueError(f"entry {entry.get('name')!r} has no patterns")
    bindings = pattern_bindings(patterns[0])

    # Every pattern within a single entry must share the same bindings
    # (modulo musig wrapping). We only require that the kinds match by name.
    binding_kinds = {n: k for n, k in bindings}
    for p in patterns[1:]:
        for n, k in pattern_bindings(p):
            if n not in binding_kinds:
                # Allow musig patterns to introduce $threshold/$keys when the
                # non-musig pattern already has them; otherwise reject.
                raise ValueError(
                    f"binding {n!r} in pattern {p!r} not in canonical pattern "
                    f"{patterns[0]!r}"
                )
            if binding_kinds[n] != k:
                raise ValueError(f"binding {n!r} kind mismatch")

    parts: list[tuple[str, str, str]] = []
    for s in cleartext:
        if s.startswith("$"):
            name = s[1:]
            if name not in binding_kinds:
                raise ValueError(
                    f"cleartext refers to unknown binding {name!r} in "
                    f"entry {entry.get('name')!r}"
                )
            parts.append((binding_kinds[name], name, ""))
        else:
            parts.append(("LITERAL", "", s))
            pool.add(s)

    return parts, bindings


def emit_header(spec: dict[str, Any]) -> str:
    top_level = spec.get("top_level", [])
    tapleaf = spec.get("tapleaf", [])

    out: list[str] = []
    out.append("// Generated by dev-tools/gen_cleartext/gen.py. DO NOT EDIT.")
    out.append("// clang-format off")
    out.append("")
    out.append("#pragma once")
    out.append("")
    out.append("#include <stdbool.h>")
    out.append("#include <stddef.h>")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("// A part of a cleartext template. Literals reference ct_string_pool")
    out.append("// at `lit_off`; dynamic placeholders refer to the binding at index")
    out.append("// `binding_idx` in the matcher's bindings array.")
    out.append("typedef enum {")
    out.append("    CT_PART_LITERAL = 0,")
    out.append("    CT_PART_KEY,")
    out.append("    CT_PART_KEYS,")
    out.append("    CT_PART_THRESHOLD,")
    out.append("    CT_PART_SUB,")
    out.append("    CT_PART_TIMELOCK,")
    out.append("} cleartext_part_kind_e;")
    out.append("")
    out.append("typedef struct {")
    out.append("    uint8_t  kind;         // cleartext_part_kind_e")
    out.append("    uint8_t  binding_idx;  // ignored for CT_PART_LITERAL")
    out.append("    uint16_t lit_off;      // valid only for CT_PART_LITERAL")
    out.append("} cleartext_part_t;")
    out.append("")
    out.append("typedef struct {")
    out.append("    uint8_t n_patterns;        // total patterns for the class")
    out.append("    uint8_t n_musig_patterns;  // patterns whose admittance requires")
    out.append("                               //   threshold == n_keys")
    out.append("    uint8_t n_parts;")
    out.append("    const cleartext_part_t *parts;")
    out.append("} cleartext_spec_t;")
    out.append("")

    # Top-level enum
    out.append("typedef enum {")
    for e in top_level:
        out.append(f"    DC_{snake_upper(e['name'])},")
    out.append("    DC_OTHER,")
    out.append(f"    DC__COUNT = DC_OTHER,")
    out.append("} descriptor_class_e;")
    out.append("")

    # Tapleaf enum
    out.append("typedef enum {")
    for e in tapleaf:
        out.append(f"    TC_{snake_upper(e['name'])},")
    out.append("    TC_OTHER,")
    out.append(f"    TC__COUNT = TC_OTHER,")
    out.append("} tapleaf_class_e;")
    out.append("")

    out.append("extern const char ct_string_pool[];")
    out.append("extern const cleartext_spec_t CT_TOP_LEVEL_SPECS[DC__COUNT];")
    out.append("extern const cleartext_spec_t CT_TAPLEAF_SPECS[TC__COUNT];")
    out.append("")
    return "\n".join(out)


def snake_upper(camel: str) -> str:
    """Convert CamelCase / PascalCase to UPPER_SNAKE_CASE."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", camel)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).upper()


def emit_source(spec: dict[str, Any]) -> str:
    top_level = spec.get("top_level", [])
    tapleaf = spec.get("tapleaf", [])
    pool = StringPool()

    # Build the parts of every entry first so that all literals are pooled.
    top_parts: list[tuple[str, list[tuple[str, str, str]], list[tuple[str, str]]]] = []
    for e in top_level:
        parts, bindings = build_parts(e, pool)
        top_parts.append((e["name"], parts, bindings))

    leaf_parts: list[tuple[str, list[tuple[str, str, str]], list[tuple[str, str]]]] = []
    for e in tapleaf:
        parts, bindings = build_parts(e, pool)
        leaf_parts.append((e["name"], parts, bindings))

    out: list[str] = []
    out.append("// Generated by dev-tools/gen_cleartext/gen.py. DO NOT EDIT.")
    out.append("// clang-format off")
    out.append("")
    out.append('#include "common/cleartext_specs.h"')
    out.append("")
    out.append("const char ct_string_pool[] = {")
    pool_bytes = pool.as_bytes()
    line: list[str] = []
    for b in pool_bytes:
        line.append(f"0x{b:02x}")
        if len(line) == 16:
            out.append("    " + ", ".join(line) + ",")
            line = []
    if line:
        out.append("    " + ", ".join(line) + ",")
    out.append("};")
    out.append("")

    def emit_entry_parts(prefix: str, name: str, parts: list[tuple[str, str, str]],
                          bindings: list[tuple[str, str]]) -> None:
        binding_index = {b[0]: i for i, b in enumerate(bindings)}
        out.append(f"static const cleartext_part_t {prefix}_{snake_upper(name)}_PARTS[] = {{")
        for kind, bname, lit in parts:
            kind_str = part_kind_c(kind)
            if kind == "LITERAL":
                off = pool._offsets[lit]
                out.append(f'    {{ {kind_str:<19s}, 0, {off:4d} }},  // {lit!r}')
            else:
                idx = binding_index[bname]
                out.append(f'    {{ {kind_str:<19s}, {idx}, {0:4d} }},  // ${bname}')
        out.append("};")
        out.append("")

    for name, parts, bindings in top_parts:
        emit_entry_parts("TOP", name, parts, bindings)
    for name, parts, bindings in leaf_parts:
        emit_entry_parts("LEAF", name, parts, bindings)

    out.append("const cleartext_spec_t CT_TOP_LEVEL_SPECS[DC__COUNT] = {")
    for entry, (name, parts, _) in zip(top_level, top_parts):
        n_patterns = len(entry["patterns"])
        n_musig = sum(1 for p in entry["patterns"] if is_musig_pattern(p))
        out.append(
            f"    [DC_{snake_upper(name)}] = {{ "
            f"{n_patterns}, {n_musig}, "
            f"{len(parts)}, TOP_{snake_upper(name)}_PARTS }},"
        )
    out.append("};")
    out.append("")

    out.append("const cleartext_spec_t CT_TAPLEAF_SPECS[TC__COUNT] = {")
    for entry, (name, parts, _) in zip(tapleaf, leaf_parts):
        n_patterns = len(entry["patterns"])
        n_musig = sum(1 for p in entry["patterns"] if is_musig_pattern(p))
        out.append(
            f"    [TC_{snake_upper(name)}] = {{ "
            f"{n_patterns}, {n_musig}, "
            f"{len(parts)}, LEAF_{snake_upper(name)}_PARTS }},"
        )
    out.append("};")
    out.append("")

    return "\n".join(out)


def emit_vectors(vectors_doc: dict[str, Any]) -> str:
    vectors = vectors_doc.get("vector", [])
    out: list[str] = []
    out.append("// Generated by dev-tools/gen_cleartext/gen.py. DO NOT EDIT.")
    out.append("// clang-format off")
    out.append("")

    # Per-vector cleartext arrays
    for i, v in enumerate(vectors):
        if "cleartext" in v:
            arr_name = f"vec_{i:03d}_ct"
            out.append(f"static const char *const {arr_name}[] = {{")
            for s in v["cleartext"]:
                out.append(f"    {c_string_literal(s)},")
            out.append("};")
    out.append("")

    out.append("static const ct_vector_t CT_VECTORS[] = {")
    for i, v in enumerate(vectors):
        has_score = "confusion_score" in v
        has_ct = "cleartext" in v
        has_flag = "has_cleartext" in v
        template = v["template"]
        score = v.get("confusion_score", 0)
        flag = "true" if v.get("has_cleartext", False) else "false"
        if has_ct:
            ct_n = len(v["cleartext"])
            ct_ptr = f"vec_{i:03d}_ct"
        else:
            ct_n = 0
            ct_ptr = "NULL"
        out.append(
            "    { "
            f".template_str = {c_string_literal(template)},"
            f" .has_confusion_score = {'true' if has_score else 'false'},"
            f" .confusion_score = {score}ULL,"
            f" .has_cleartext_array = {'true' if has_ct else 'false'},"
            f" .cleartext_n = {ct_n}, .cleartext = {ct_ptr},"
            f" .has_has_cleartext = {'true' if has_flag else 'false'},"
            f" .cleartext_flag = {flag} }},"
        )
    out.append("};")
    out.append(f"static const size_t CT_VECTORS_N = sizeof(CT_VECTORS) / sizeof(CT_VECTORS[0]);")
    out.append("")
    return "\n".join(out)


def c_string_literal(s: str) -> str:
    """Format a Python string as a C string literal, escaping where needed."""
    result = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '\\':
            result.append("\\\\")
        elif ch == '"':
            result.append('\\"')
        elif ch == '\n':
            result.append("\\n")
        elif ch == '\r':
            result.append("\\r")
        elif ch == '\t':
            result.append("\\t")
        elif 0x20 <= o < 0x7F:
            result.append(ch)
        else:
            # Encode as UTF-8 byte escapes
            for b in ch.encode("utf-8"):
                result.append(f"\\x{b:02x}")
        result.append("")
    result.append('"')
    return "".join(result)


def main() -> int:
    spec_doc = parse_spec_file()
    vectors_doc = parse_vectors_file()

    HEADER_OUT.parent.mkdir(parents=True, exist_ok=True)
    SOURCE_OUT.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_OUT.parent.mkdir(parents=True, exist_ok=True)

    HEADER_OUT.write_text(emit_header(spec_doc) + "\n")
    SOURCE_OUT.write_text(emit_source(spec_doc) + "\n")
    VECTORS_OUT.write_text(emit_vectors(vectors_doc) + "\n")

    print(f"wrote {HEADER_OUT.relative_to(REPO_ROOT)}")
    print(f"wrote {SOURCE_OUT.relative_to(REPO_ROOT)}")
    print(f"wrote {VECTORS_OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
