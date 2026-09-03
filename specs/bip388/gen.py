#!/usr/bin/env python3
"""Generate the C cleartext spec tables and unit-test vector arrays from the
BIP388 cleartext TOML files.

Inputs:
    specs/bip388/cleartext.toml        -- spec for the cleartext encoder
    specs/bip388/test_vectors.toml     -- test vectors

Outputs (all overwritten):
    src/common/cleartext_specs.h       -- enums + extern decls
    src/common/cleartext_specs.c       -- spec tables and string pool
    src/common/cleartext_match.c       -- generated AST classifiers
    unit-tests/cleartext_vectors.inc.c -- static C array of test vectors

Run this script manually after changing the TOML files and commit the result.
Pass --check (e.g. in CI) to verify the committed output is up to date instead
of regenerating it.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path
from string import digits as _DIGITS
from typing import Any

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


# Type aliases for the tuple shapes threaded through spec emission.
Binding = tuple[str, str]    # (name, kind)
Part = tuple[str, str, str]  # (kind, binding_name, literal_text)
# One entry's built parts: (name, parts, parts_all, bindings). parts_all is None
# unless the entry declares an n-of-n `cleartext_all` form.
EntryParts = tuple[str, list[Part], list[Part] | None, list[Binding]]


# This script lives alongside the TOML specs it reads, in specs/bip388/.
SPECS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPECS_DIR.parents[1]
SPEC_FILE = SPECS_DIR / "cleartext.toml"
VECTORS_FILE = SPECS_DIR / "test_vectors.toml"
HEADER_OUT = REPO_ROOT / "src" / "common" / "cleartext_specs.h"
SOURCE_OUT = REPO_ROOT / "src" / "common" / "cleartext_specs.c"
MATCH_OUT = REPO_ROOT / "src" / "common" / "cleartext_match.c"
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
    "leaves": "LEAVES",  # structural; never appears in cleartext output
}


def binding_kind(name: str) -> str | None:
    return _BINDING_KIND.get(name.rstrip(_DIGITS))


# Must match CT_MAX_BINDINGS in src/common/cleartext_match.h: the fixed length
# of the per-match bindings array the generated classifier writes into. A guard
# in _emit_match_fn rejects any entry that would overflow it.
CT_MAX_BINDINGS = 3


# --- Small helpers for rendering Python values as C source ------------------


def part_kind_c(kind: str) -> str:
    return f"CT_PART_{kind}"


def cbool(b: bool) -> str:
    """Render a Python bool as a C boolean literal."""
    return "true" if b else "false"


def snake_upper(camel: str) -> str:
    """Convert CamelCase / PascalCase to UPPER_SNAKE_CASE."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", camel)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).upper()


_C_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def c_string_literal(s: str) -> str:
    """Format a Python string as a C string literal, escaping where needed.

    A `\\xNN` byte escape has no fixed length: the compiler keeps consuming hex
    digits. So when a non-ASCII byte escape is immediately followed by an ASCII
    hex-digit character we split the literal (`"\\xc3" "a"`) so the digit can't be
    folded into the escape. Pure-ASCII input never triggers a split, so its
    output is unchanged."""
    result = ['"']
    prev_was_hex = False
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            result.append("\\\\")
            prev_was_hex = False
        elif ch == '"':
            result.append('\\"')
            prev_was_hex = False
        elif ch == "\n":
            result.append("\\n")
            prev_was_hex = False
        elif ch == "\r":
            result.append("\\r")
            prev_was_hex = False
        elif ch == "\t":
            result.append("\\t")
            prev_was_hex = False
        elif 0x20 <= o < 0x7F:
            if prev_was_hex and ch in _C_HEX_DIGITS:
                result.append('" "')  # break the string so the escape ends here
            result.append(ch)
            prev_was_hex = False
        else:
            # Encode as UTF-8 byte escapes
            for b in ch.encode("utf-8"):
                result.append(f"\\x{b:02x}")
            prev_was_hex = True
    result.append('"')
    return "".join(result)


def c_pool_entry(s: str) -> str:
    """A C string literal for one pooled string, with its NUL separator baked in
    (`"foo\\0"`). Concatenated adjacently in the pool array, these reproduce the
    NUL-separated byte layout that the `lit_off` offsets index into."""
    inner = c_string_literal(s)  # e.g. '"foo"'
    return inner[:-1] + '\\0"'   # -> '"foo\0"'


# Pattern parsing -----------------------------------------------------------

_BINDING_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
# A musig key argument: `musig($keys)`. musig is n-of-n, so the threshold is
# implied by the key count and is not written explicitly.
_MUSIG_KEYS_RE = re.compile(r"musig\(\$([A-Za-z_][A-Za-z0-9_]*)\)")


def synthesize_threshold_name(keys: str) -> str:
    """Mirror `synthesize_threshold_name` in the Rust build.rs: swap the "keys"
    base for "threshold", preserving any trailing digit suffix so it stays
    consistent with a sibling pattern's explicit `$threshold` (e.g.
    `keys` -> `threshold`, `keys1` -> `threshold1`)."""
    base = keys.rstrip(_DIGITS)
    return "threshold" + keys[len(base):]


def pattern_bindings(pattern: str) -> list[Binding]:
    """Return the list of (binding_name, kind) in the order they appear in
    the pattern string.

    `musig($keys)` is n-of-n: it carries no explicit threshold, so (as in the
    Rust build.rs) we synthesize a `$threshold` binding right before its `$keys`.
    Its value is the key count at match time, and the shared cleartext can still
    reference `$threshold`."""
    musig_keys = {m.group(1) for m in _MUSIG_KEYS_RE.finditer(pattern)}
    bindings: list[Binding] = []
    seen = set()
    for m in _BINDING_RE.finditer(pattern):
        name = m.group(1)
        if name in seen:
            raise ValueError(f"binding {name!r} appears twice in pattern {pattern!r}")
        seen.add(name)
        kind = binding_kind(name)
        if kind is None:
            raise ValueError(f"unknown binding name {name!r} in pattern {pattern!r}")
        if name in musig_keys:
            tname = synthesize_threshold_name(name)
            if tname not in seen:
                seen.add(tname)
                bindings.append((tname, "THRESHOLD"))
        bindings.append((name, kind))
    return bindings


def binding_index(bindings: list[Binding]) -> dict[str, int]:
    """Map each binding name to its positional index in the bindings list."""
    return {name: i for i, (name, _) in enumerate(bindings)}


def is_musig_pattern(pattern: str) -> bool:
    """A pattern is a 'musig pattern' when it uses musig(...) as a key
    expression. Such patterns require the round-trip check
    `threshold == n_keys` at scoring time."""
    return "musig(" in pattern


def entry_recurses(entry: dict[str, Any]) -> bool:
    """True iff the entry binds a `$leaves` taptree (i.e. classification
    recurses into a tr(...) tree). Mirrors `ProcessedEntry::recurses` in the
    Rust build.rs; drives per-leaf rendering and the taptree score factor."""
    for p in entry["patterns"]:
        for _, kind in pattern_bindings(p):
            if kind == "LEAVES":
                return True
    return False


# ===========================================================================
# Classifier codegen (port of build.rs `classify` / `classify_as_tapleaf`).
#
# build.rs lowers each `pattern` to a nested `if let` chain over the Rust
# `DescriptorTemplate` AST. Here we emit the equivalent C: one `do { ... }
# while (0)` block per pattern that walks the `policy_node_t` AST, `break`s on
# any mismatch, and on a full match fills the bindings + class and `return`s.
# ===========================================================================

# keyword -> (PolicyNodeType, C struct type, [positional arg kinds]).
# Arg kinds: KEY (a keyexpr), NUM (a threshold), KEYLIST (a key array),
#            SUB (a child policy_node), TREE (the tr(...) taptree).
_KEYWORD_INFO: dict[str, tuple[str, str, list[str]]] = {
    "pkh":           ("TOKEN_PKH",           "policy_node_with_key_t",     ["KEY"]),
    "wpkh":          ("TOKEN_WPKH",          "policy_node_with_key_t",     ["KEY"]),
    "pk":            ("TOKEN_PK",            "policy_node_with_key_t",     ["KEY"]),
    "pk_k":          ("TOKEN_PK_K",          "policy_node_with_key_t",     ["KEY"]),
    "pk_h":          ("TOKEN_PK_H",          "policy_node_with_key_t",     ["KEY"]),
    "multi":         ("TOKEN_MULTI",         "policy_node_multisig_t",     ["NUM", "KEYLIST"]),
    "multi_a":       ("TOKEN_MULTI_A",       "policy_node_multisig_t",     ["NUM", "KEYLIST"]),
    "sortedmulti":   ("TOKEN_SORTEDMULTI",   "policy_node_multisig_t",     ["NUM", "KEYLIST"]),
    "sortedmulti_a": ("TOKEN_SORTEDMULTI_A", "policy_node_multisig_t",     ["NUM", "KEYLIST"]),
    "tr":            ("TOKEN_TR",            "policy_node_tr_t",           ["KEY", "TREE"]),
    "older":         ("TOKEN_OLDER",         "policy_node_with_uint32_t",  ["NUM"]),
    "after":         ("TOKEN_AFTER",         "policy_node_with_uint32_t",  ["NUM"]),
    "sh":            ("TOKEN_SH",            "policy_node_with_script_t",  ["SUB"]),
    "wsh":           ("TOKEN_WSH",           "policy_node_with_script_t",  ["SUB"]),
    "and_v":         ("TOKEN_AND_V",         "policy_node_with_script2_t", ["SUB", "SUB"]),
    "and_b":         ("TOKEN_AND_B",         "policy_node_with_script2_t", ["SUB", "SUB"]),
    "and_n":         ("TOKEN_AND_N",         "policy_node_with_script2_t", ["SUB", "SUB"]),
    "or_b":          ("TOKEN_OR_B",          "policy_node_with_script2_t", ["SUB", "SUB"]),
    "or_c":          ("TOKEN_OR_C",          "policy_node_with_script2_t", ["SUB", "SUB"]),
    "or_d":          ("TOKEN_OR_D",          "policy_node_with_script2_t", ["SUB", "SUB"]),
    "or_i":          ("TOKEN_OR_I",          "policy_node_with_script2_t", ["SUB", "SUB"]),
    "andor":         ("TOKEN_ANDOR",         "policy_node_with_script3_t", ["SUB", "SUB", "SUB"]),
}

# Miniscript wrapper char -> PolicyNodeType. All wrappers are single-script
# nodes (policy_node_with_script_t).
_WRAPPER_TOKEN = {
    "a": "TOKEN_A", "s": "TOKEN_S", "c": "TOKEN_C", "t": "TOKEN_T", "d": "TOKEN_D",
    "v": "TOKEN_V", "j": "TOKEN_J", "n": "TOKEN_N", "l": "TOKEN_L", "u": "TOKEN_U",
}

# Allowed (binding-kind, positional-arg-kind) pairs.
_KIND_POSITION_OK = {
    ("KEY", "KEY"),
    ("KEYS", "KEYLIST"),
    ("THRESHOLD", "NUM"),
    ("LEAVES", "TREE"),
    ("SUB", "SUB"),
    ("TIMELOCK", "SUB"),
}


class Pattern:
    def __init__(self, keyword: str, args: list[Any]) -> None:
        self.keyword = keyword
        self.args = args  # list of PatternArg (tuples, see _PatternParser.parse_arg)


class _PatternParser:
    """Recursive-descent parser for the spec pattern language. Mirrors
    `PatternParser` in build.rs. Produces a `Pattern` AST whose args are tuples:
        ("binding", name, kind)            -- bare `$name`
        ("musig", threshold_name, keys)    -- musig($keys)
        ("sub", wrappers, inner_Pattern)   -- (wrappers:)? nested pattern
        ("subref", wrappers, name)         -- (wrappers:)? $subpolicy
    """

    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0

    def skip_ws(self) -> None:
        while self.pos < len(self.src) and self.src[self.pos].isspace():
            self.pos += 1

    def peek(self) -> str | None:
        return self.src[self.pos] if self.pos < len(self.src) else None

    def bump(self, c: str) -> None:
        self.skip_ws()
        if self.peek() == c:
            self.pos += 1
        else:
            raise ValueError(f"expected {c!r} at byte {self.pos} in {self.src!r}")

    def try_bump(self, c: str) -> bool:
        self.skip_ws()
        if self.peek() == c:
            self.pos += 1
            return True
        return False

    def try_parse_ident(self) -> str | None:
        self.skip_ws()
        start = self.pos
        while self.pos < len(self.src) and (self.src[self.pos].isalnum() or self.src[self.pos] == "_"):
            self.pos += 1
        return self.src[start:self.pos] if self.pos > start else None

    def parse_ident(self) -> str:
        ident = self.try_parse_ident()
        if ident is None:
            raise ValueError(f"expected identifier at byte {self.pos} in {self.src!r}")
        return ident

    def parse_binding_name(self) -> str:
        self.bump("$")
        return self.parse_ident()

    def parse_pattern(self) -> Pattern:
        kw = self.parse_ident()
        if kw not in _KEYWORD_INFO:
            raise ValueError(f"unknown descriptor keyword {kw!r} in {self.src!r}")
        if not self.try_bump("("):
            return Pattern(kw, [])
        arg_kinds = _KEYWORD_INFO[kw][2]
        args: list[Any] = []
        if not self.try_bump(")"):
            while True:
                expected = arg_kinds[len(args)] if len(args) < len(arg_kinds) else "SUB"
                args.append(self.parse_arg(expected))
                self.skip_ws()
                if self.try_bump(")"):
                    break
                self.bump(",")
        return Pattern(kw, args)

    def parse_arg(self, expected: str) -> Any:
        self.skip_ws()
        if self.peek() == "$":
            name = self.parse_binding_name()
            kind = binding_kind(name)
            if kind is None:
                raise ValueError(f"unknown binding name ${name!r} in {self.src!r}")
            _check_kind_position(name, kind, expected)
            return ("binding", name, kind)
        saved = self.pos
        ident = self.try_parse_ident()
        if ident is not None:
            if ident == "musig":
                if expected != "KEY":
                    raise ValueError(f"musig(...) only allowed in a Key position in {self.src!r}")
                self.bump("(")
                keys = self.parse_binding_name()
                if binding_kind(keys) != "KEYS":
                    raise ValueError(f"musig(...) arg must be a $keys binding in {self.src!r}")
                self.bump(")")
                return ("musig", synthesize_threshold_name(keys), keys)
            self.pos = saved  # rewind: it's a keyword for a (wrapped) sub-pattern
        wrappers: list[str] = []
        while True:
            snap = self.pos
            idd = self.try_parse_ident()
            self.skip_ws()
            if idd is not None and self.peek() == ":":
                for ch in idd:
                    if ch not in _WRAPPER_TOKEN:
                        raise ValueError(f"unknown wrapper char {ch!r} in {self.src!r}")
                    wrappers.append(ch)
                self.pos += 1  # consume ':'
                continue
            self.pos = snap
            break
        if expected != "SUB" and wrappers:
            raise ValueError(f"wrappers only allowed in Sub positions in {self.src!r}")
        if self.peek() == "$":
            snap = self.pos
            name = self.parse_binding_name()
            if binding_kind(name) == "SUB":
                _check_kind_position(name, "SUB", expected)
                return ("subref", wrappers, name)
            self.pos = snap  # not a subpolicy binding; fall through to pattern
        inner = self.parse_pattern()
        return ("sub", wrappers, inner)


def _check_kind_position(name: str, kind: str, expected: str) -> None:
    if (kind, expected) not in _KIND_POSITION_OK:
        raise ValueError(f"binding ${name!r} (kind {kind}) not valid in a {expected} position")


def parse_pattern_full(src: str) -> Pattern:
    p = _PatternParser(src)
    pat = p.parse_pattern()
    p.skip_ws()
    if p.pos != len(src):
        raise ValueError(f"trailing input at byte {p.pos} in pattern {src!r}")
    return pat


# --- C emission for one matcher function -----------------------------------


class _Ctx:
    def __init__(self, bidx: dict[str, int], combinators: list[str]) -> None:
        self.body: list[str] = []
        self.binds: list[str] = []
        self.ctr = 0
        self.bidx = bidx
        self.combinators = combinators

    def fresh(self, base: str) -> str:
        # `ct_`-prefixed (not `__`-prefixed) to avoid C reserved identifiers.
        self.ctr += 1
        return f"ct_{base}{self.ctr}"


def _sub_child_expr(struct: str, t: str, i: int) -> str:
    if struct == "policy_node_with_script_t":
        return f"{t}->script"
    return f"{t}->scripts[{i}]"  # script2 / script3


def _classify_sub(ctx: _Ctx, node_var: str, name: str) -> None:
    sm = ctx.fresh("sub")
    ctx.body.append(f"ct_leaf_match_t {sm};")
    ctx.body.append(f"if (!match_tapleaf({node_var}, &{sm})) break;")
    rejects = [f"{sm}.cls == TC_OTHER"] + [f"{sm}.cls == {cc}" for cc in ctx.combinators]
    ctx.body.append(f"if ({' || '.join(rejects)}) break;")
    slot = ctx.bidx[name]
    ctx.binds.append(f"set_binding_sub(&out->bindings, {slot}, {node_var});")


def _peel_wrappers(ctx: _Ctx, node_var: str, wrappers: list[str]) -> str:
    for ch in wrappers:
        wt = _WRAPPER_TOKEN[ch]
        ctx.body.append(f"if ({node_var} == NULL || {node_var}->type != {wt}) break;")
        w = ctx.fresh("w")
        ctx.body.append(f"const policy_node_with_script_t *{w} = (const policy_node_with_script_t *) {node_var};")
        c2 = ctx.fresh("c")
        ctx.body.append(f"const policy_node_t *{c2} = {w}->script;")
        node_var = c2
    return node_var


def _handle_key_arg(ctx: _Ctx, arg: Any, t: str) -> None:
    key_expr = f"{t}->key"
    if arg[0] == "binding" and arg[2] == "KEY":
        k = ctx.fresh("k")
        ctx.body.append(f"const policy_node_keyexpr_t *{k} = {key_expr};")
        ctx.body.append(f"if ({k}->type != KEY_EXPRESSION_NORMAL) break;")
        slot = ctx.bidx[arg[1]]
        ctx.binds.append(f"set_binding_key(&out->bindings, {slot}, {k});")
    elif arg[0] == "musig":
        k = ctx.fresh("k")
        ctx.body.append(f"const policy_node_keyexpr_t *{k} = {key_expr};")
        ctx.body.append(f"if ({k}->type != KEY_EXPRESSION_MUSIG) break;")
        mi = ctx.fresh("mi")
        ctx.body.append(f"const musig_aggr_key_info_t *{mi} = {k}->m.musig_info;")
        ts, ks = ctx.bidx[arg[1]], ctx.bidx[arg[2]]
        ctx.binds.append(f"set_binding_number(&out->bindings, {ts}, {mi}->n);")
        ctx.binds.append(f"set_binding_keys(&out->bindings, {ks}, {k}, 1);")
    else:
        raise ValueError(f"unexpected arg {arg!r} in Key position")


def _handle_arg(ctx: _Ctx, arg: Any, ak: str, struct: str, t: str, i: int) -> None:
    if ak == "KEY":
        _handle_key_arg(ctx, arg, t)
    elif ak == "NUM":
        # The only NUM args reached here are multisig thresholds (->k);
        # older/after thresholds are consumed by match_lock_value, not as args.
        if not (arg[0] == "binding" and arg[2] == "THRESHOLD"):
            raise ValueError(f"unexpected arg {arg!r} in Num position")
        slot = ctx.bidx[arg[1]]
        ctx.binds.append(f"set_binding_number(&out->bindings, {slot}, {t}->k);")
    elif ak == "KEYLIST":
        if not (arg[0] == "binding" and arg[2] == "KEYS"):
            raise ValueError(f"unexpected arg {arg!r} in KeyList position")
        ka = ctx.fresh("ka")
        ctx.body.append(f"const policy_node_keyexpr_t *{ka} = {t}->keys;")
        slot = ctx.bidx[arg[1]]
        ctx.binds.append(f"set_binding_keys(&out->bindings, {slot}, {ka}, {t}->n);")
    elif ak == "SUB":
        child = _sub_child_expr(struct, t, i)
        c = ctx.fresh("c")
        ctx.body.append(f"const policy_node_t *{c} = {child};")
        if arg[0] == "binding" and arg[2] == "TIMELOCK":
            tl = ctx.fresh("tl")
            ctx.body.append(f"ct_timelock_t {tl};")
            ctx.body.append(f"if (!match_lock_value({c}, &{tl})) break;")
            slot = ctx.bidx[arg[1]]
            ctx.binds.append(f"set_binding_timelock(&out->bindings, {slot}, {tl});")
        elif arg[0] == "binding" and arg[2] == "SUB":
            _classify_sub(ctx, c, arg[1])
        elif arg[0] == "subref":
            c = _peel_wrappers(ctx, c, arg[1])
            _classify_sub(ctx, c, arg[2])
        elif arg[0] == "sub":
            c = _peel_wrappers(ctx, c, arg[1])
            _lower(ctx, arg[2], c)
        else:
            raise ValueError(f"unexpected arg {arg!r} in Sub position")
    else:
        raise ValueError(f"unexpected arg kind {ak!r}")


def _lower(ctx: _Ctx, pat: Pattern, node_expr: str) -> None:
    token, struct, arg_kinds = _KEYWORD_INFO[pat.keyword]
    ctx.body.append(f"if ({node_expr} == NULL || {node_expr}->type != {token}) break;")
    t = ctx.fresh("n")
    ctx.body.append(f"const {struct} *{t} = (const {struct} *) {node_expr};")

    if pat.keyword == "tr":
        # tr's first arg is a Key (plain or musig); the optional second arg is
        # the $leaves taptree. A 1-arg tr matches only a leaf-less taproot.
        _handle_key_arg(ctx, pat.args[0], t)
        if len(pat.args) == 1:
            ctx.body.append(f"if ({t}->tree != NULL) break;")
        else:
            ctx.body.append(f"if ({t}->tree == NULL) break;")
            ctx.binds.append(f"out->taptree = {t}->tree;")
        return

    for i, arg in enumerate(pat.args):
        ak = arg_kinds[i] if i < len(arg_kinds) else "SUB"
        _handle_arg(ctx, arg, ak, struct, t, i)


def _emit_match_fn(
    fn_name: str,
    out_type: str,
    prefix: str,
    entries: list[dict[str, Any]],
    root_var: str,
    combinators: list[str],
    is_top: bool,
) -> str:
    lines: list[str] = []
    lines.append(f"bool {fn_name}(const policy_node_t *{root_var}, {out_type} *out) {{")
    if is_top:
        lines.append("    out->cls = DC_OTHER;")
        lines.append("    out->bindings.n = 0;")
        lines.append("    out->taptree = NULL;")
    else:
        lines.append("    out->cls = TC_OTHER;")
        lines.append("    out->bindings.n = 0;")
        lines.append(f"    out->leaf_script = {root_var};")
    lines.append(f"    if ({root_var} == NULL) return false;")
    lines.append("")
    for e in entries:
        name = e["name"]
        cls = f"{prefix}_{snake_upper(name)}"
        bindings = pattern_bindings(e["patterns"][0])
        bidx = binding_index(bindings)
        n_nonleaves = sum(1 for _, k in bindings if k != "LEAVES")
        if n_nonleaves > CT_MAX_BINDINGS:
            raise ValueError(
                f"entry {name!r} has {n_nonleaves} non-leaf bindings, which "
                f"exceeds CT_MAX_BINDINGS ({CT_MAX_BINDINGS}); raise it in "
                f"src/common/cleartext_match.h and here"
            )
        for src in e["patterns"]:
            ctx = _Ctx(bidx, combinators)
            _lower(ctx, parse_pattern_full(src), root_var)
            lines.append(f"    // {name}: {src}")
            lines.append("    do {")
            for stmt in ctx.body:
                lines.append("        " + stmt)
            for stmt in ctx.binds:
                lines.append("        " + stmt)
            lines.append(f"        out->bindings.n = {n_nonleaves};")
            lines.append(f"        out->cls = {cls};")
            lines.append("        return true;")
            lines.append("    } while (0);")
        lines.append("")
    lines.append("    return false;")
    lines.append("}")
    return "\n".join(lines)


def emit_match(spec: dict[str, Any]) -> str:
    top_level = spec.get("top_level", [])
    tapleaf = spec.get("tapleaf", [])

    # Combinator tapleaf classes: those that bind a $sub. They are rejected as
    # sub-policies (no nesting), matching build.rs's `combinator_variants`.
    combinators: list[str] = []
    for e in tapleaf:
        binds = pattern_bindings(e["patterns"][0])
        if any(k == "SUB" for _, k in binds):
            combinators.append("TC_" + snake_upper(e["name"]))

    out: list[str] = []
    out.append("// Generated by specs/bip388/gen.py. DO NOT EDIT.")
    out.append("// clang-format off")
    out.append("")
    out.append('#include "common/cleartext_match.h"')
    out.append("")
    out.append("// Classifier for the root descriptor template. Mirrors the `[[top_level]]`")
    out.append("// patterns of specs/bip388/cleartext.toml, tried in order.")
    out.append(_emit_match_fn("match_top_level", "ct_top_match_t", "DC", top_level, "root",
                              combinators, is_top=True))
    out.append("")
    out.append("// Classifier for a single tap-leaf script. Mirrors the `[[tapleaf]]`")
    out.append("// patterns of specs/bip388/cleartext.toml, tried in order.")
    out.append(_emit_match_fn("match_tapleaf", "ct_leaf_match_t", "TC", tapleaf, "leaf_script",
                              combinators, is_top=False))
    out.append("")
    return "\n".join(out)


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

    def offset(self, s: str) -> int:
        """Return the offset of an already-added string."""
        return self._offsets[s]

    def items(self) -> list[tuple[str, int]]:
        """The pooled strings with their byte offsets, in insertion order."""
        return list(self._offsets.items())


# Spec emission -------------------------------------------------------------


def load_toml(path: Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _cleartext_to_parts(
    cleartext: list[str],
    binding_kinds: dict[str, str],
    entry_name: Any,
    pool: StringPool,
) -> list[Part]:
    """Convert a cleartext template (list of literals and `$field` references)
    into a list of Parts (kind, binding_name, literal_text). Each part is one of:
        ("LITERAL", "", text)             -- a literal string (also placed in pool)
        (binding_kind, binding_name, "")  -- a dynamic placeholder
    """
    parts: list[Part] = []
    for s in cleartext:
        if s.startswith("$"):
            name = s[1:]
            if name not in binding_kinds:
                raise ValueError(
                    f"cleartext refers to unknown binding {name!r} in "
                    f"entry {entry_name!r}"
                )
            parts.append((binding_kinds[name], name, ""))
        else:
            parts.append(("LITERAL", "", s))
            pool.add(s)
    return parts


def build_parts(
    entry: dict[str, Any], pool: StringPool
) -> tuple[list[Part], list[Part] | None, list[Binding]]:
    """Return (parts, parts_all, bindings).

    `parts` is built from the entry's `cleartext`. `parts_all` is built from the
    optional `cleartext_all` -- the n-of-n rendering used when
    `threshold == number of keys` -- or None when the entry has no such form.
    A `cleartext_all` template must omit `$threshold` (implied by the key count,
    re-synthesized on decode) and reference the `$keys` list it is derived from.

    Bindings are the ordered list of (name, kind) extracted from the first
    pattern (assumed identical across all patterns of an entry).
    """
    patterns: list[str] = entry["patterns"]
    cleartext: list[str] = entry["cleartext"]

    if not patterns:
        raise ValueError(f"entry {entry.get('name')!r} has no patterns")
    bindings = pattern_bindings(patterns[0])

    # Every pattern within a single entry must share the same bindings
    # (modulo musig wrapping): a later pattern may only use bindings the
    # canonical (first) pattern already declares, and their kinds must agree by
    # name. The musig pattern (e.g. tr(musig($keys))) passes because the
    # canonical multisig pattern declares $threshold/$keys, which
    # pattern_bindings() re-synthesizes for musig.
    binding_kinds = dict(bindings)
    for p in patterns[1:]:
        for n, k in pattern_bindings(p):
            if n not in binding_kinds:
                raise ValueError(
                    f"binding {n!r} in pattern {p!r} not in canonical pattern "
                    f"{patterns[0]!r}"
                )
            if binding_kinds[n] != k:
                raise ValueError(f"binding {n!r} kind mismatch")

    parts = _cleartext_to_parts(cleartext, binding_kinds, entry.get("name"), pool)

    parts_all: list[Part] | None = None
    cleartext_all = entry.get("cleartext_all")
    if cleartext_all is not None:
        # Validate the n-of-n form, mirroring `parse_cleartext_all` in build.rs.
        refs = {s[1:] for s in cleartext_all if s.startswith("$")}
        threshold_names = {n for n, k in bindings if k == "THRESHOLD"}
        keys_names = {n for n, k in bindings if k == "KEYS"}
        if not keys_names:
            raise ValueError(
                f"entry {entry.get('name')!r}: cleartext_all requires a $keys binding"
            )
        if refs & threshold_names:
            raise ValueError(
                f"entry {entry.get('name')!r}: cleartext_all must omit $threshold "
                f"(it is implied by the key count)"
            )
        if not (refs & keys_names):
            raise ValueError(
                f"entry {entry.get('name')!r}: cleartext_all must reference $keys "
                f"(threshold is synthesized from it on decode)"
            )
        parts_all = _cleartext_to_parts(cleartext_all, binding_kinds, entry.get("name"), pool)

    return parts, parts_all, bindings


def build_all_parts(
    entries: list[dict[str, Any]], pool: StringPool
) -> list[EntryParts]:
    """Build the parts of every entry (pooling their literals as a side effect)."""
    result: list[EntryParts] = []
    for e in entries:
        parts, parts_all, bindings = build_parts(e, pool)
        result.append((e["name"], parts, parts_all, bindings))
    return result


# Static skeleton of cleartext_specs.h. The two enum bodies are the only
# dynamic parts; they are spliced in by emit_header() over these markers.
# Substituted with str.replace (not str.format), so the C source's `{`/`}` and
# the literal `$leaves` in the comments need no escaping.
_HEADER_TEMPLATE = """\
// Generated by specs/bip388/gen.py. DO NOT EDIT.
// clang-format off

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// A part of a cleartext template. Literals reference ct_string_pool
// at `lit_off`; dynamic placeholders refer to the binding at index
// `binding_idx` in the matcher's bindings array.
typedef enum {
    CT_PART_LITERAL = 0,
    CT_PART_KEY,
    CT_PART_KEYS,
    CT_PART_THRESHOLD,
    CT_PART_SUB,
    CT_PART_TIMELOCK,
} cleartext_part_kind_e;

typedef struct {
    uint8_t  kind;         // cleartext_part_kind_e
    uint8_t  binding_idx;  // ignored for CT_PART_LITERAL
    uint16_t lit_off;      // valid only for CT_PART_LITERAL
} cleartext_part_t;

typedef struct {
    uint8_t n_patterns;        // total patterns for the class
    uint8_t n_musig_patterns;  // patterns whose admittance requires
                               //   threshold == n_keys
    uint8_t n_parts;
    const cleartext_part_t *parts;
    uint8_t n_parts_all;               // 0 if the class has no n-of-n form
    const cleartext_part_t *parts_all; // alternate template used when
                                       //   threshold == n_keys; NULL if absent
    uint8_t recurses;                  // 1 iff the class binds a $leaves
                                       //   taptree (drives per-leaf
                                       //   rendering and the taptree score)
} cleartext_spec_t;

// Classes of the *root* of a wallet-policy descriptor template. Each named
// value (the sentinels aside) is one shape the cleartext encoder recognizes,
// listed in the same order as the `[[top_level]]` entries of
// specs/bip388/cleartext.toml (the single source of truth for their meaning).
// match_top_level() in cleartext.c yields one of these, and it indexes
// CT_TOP_LEVEL_SPECS[] to select that shape's cleartext rendering.
//   DC_OTHER  - matches no known shape: no cleartext form, so the UX falls
//               back to showing the raw descriptor template.
//   DC__COUNT - number of recognized classes (== DC_OTHER); sizes
//               CT_TOP_LEVEL_SPECS[], which has no entry for DC_OTHER.
typedef enum {
@TOP_LEVEL_ENUM@
    DC_OTHER,
    DC__COUNT = DC_OTHER,
} descriptor_class_e;

// Classes of a single leaf script of a taproot tree. Each named value (the
// sentinels aside) is one leaf shape the cleartext encoder recognizes, listed
// in the same order as the `[[tapleaf]]` entries of
// specs/bip388/cleartext.toml (the single source of truth for their meaning).
// match_tapleaf() in cleartext.c yields one of these, and it indexes
// CT_TAPLEAF_SPECS[] to select that leaf's cleartext rendering.
//   TC_OTHER  - matches no known shape: no cleartext form, so the leaf is
//               rendered as the fixed "(unknown)" marker.
//   TC__COUNT - number of recognized classes (== TC_OTHER); sizes
//               CT_TAPLEAF_SPECS[], which has no entry for TC_OTHER.
typedef enum {
@TAPLEAF_ENUM@
    TC_OTHER,
    TC__COUNT = TC_OTHER,
} tapleaf_class_e;

extern const char ct_string_pool[];
extern const cleartext_spec_t CT_TOP_LEVEL_SPECS[DC__COUNT];
extern const cleartext_spec_t CT_TAPLEAF_SPECS[TC__COUNT];
"""


def emit_header(spec: dict[str, Any]) -> str:
    top_level = spec.get("top_level", [])
    tapleaf = spec.get("tapleaf", [])
    top_enum = "\n".join(f"    DC_{snake_upper(e['name'])}," for e in top_level)
    tapleaf_enum = "\n".join(f"    TC_{snake_upper(e['name'])}," for e in tapleaf)
    return (
        _HEADER_TEMPLATE
        .replace("@TOP_LEVEL_ENUM@", top_enum)
        .replace("@TAPLEAF_ENUM@", tapleaf_enum)
    )


def emit_source(spec: dict[str, Any]) -> str:
    top_level = spec.get("top_level", [])
    tapleaf = spec.get("tapleaf", [])
    pool = StringPool()

    # Build the parts of every entry first so that all literals are pooled.
    top_parts = build_all_parts(top_level, pool)
    leaf_parts = build_all_parts(tapleaf, pool)

    out: list[str] = []
    out.append("// Generated by specs/bip388/gen.py. DO NOT EDIT.")
    out.append("// clang-format off")
    out.append("")
    out.append('#include "common/cleartext_specs.h"')
    out.append("")
    # Every literal used by the specs below, NUL-separated. Each line is
    # annotated with its byte offset -- the `lit_off` value a CT_PART_LITERAL
    # part stores to locate its string here.
    out.append("const char ct_string_pool[] =")
    pool_items = pool.items()
    if not pool_items:
        out.append('    "";')
    else:
        for s, off in pool_items:
            if off > 0xFFFF:
                raise ValueError(
                    f"string pool offset {off} for {s!r} does not fit the "
                    f"uint16_t lit_off field"
                )
            out.append(f"    /* {off:5d} */ {c_pool_entry(s)}")
        out[-1] += ";"  # terminate the initializer on the last literal
    out.append("")

    def emit_parts_array(arr_name: str, parts: list[Part],
                         bidx: dict[str, int]) -> None:
        out.append(f"static const cleartext_part_t {arr_name}[] = {{")
        for kind, bname, lit in parts:
            kind_str = part_kind_c(kind)
            if kind == "LITERAL":
                off = pool.offset(lit)
                out.append(f'    {{ {kind_str:<19s}, 0, {off:4d} }},  // {c_string_literal(lit)}')
            else:
                idx = bidx[bname]
                out.append(f'    {{ {kind_str:<19s}, {idx}, {0:4d} }},  // ${bname}')
        out.append("};")
        out.append("")

    def emit_entry_parts(prefix: str, name: str, parts: list[Part],
                          parts_all: list[Part] | None,
                          bindings: list[Binding]) -> None:
        bidx = binding_index(bindings)
        base = f"{prefix}_{snake_upper(name)}"
        emit_parts_array(f"{base}_PARTS", parts, bidx)
        if parts_all is not None:
            emit_parts_array(f"{base}_PARTS_ALL", parts_all, bidx)

    for name, parts, parts_all, bindings in top_parts:
        emit_entry_parts("TOP", name, parts, parts_all, bindings)
    for name, parts, parts_all, bindings in leaf_parts:
        emit_entry_parts("LEAF", name, parts, parts_all, bindings)

    def spec_initializer(prefix: str, name: str, n_patterns: int, n_musig: int,
                         parts: list[Part], parts_all: list[Part] | None,
                         recurses: bool) -> str:
        base = f"{prefix}_{snake_upper(name)}"
        if parts_all is not None:
            all_fields = f"{len(parts_all)}, {base}_PARTS_ALL"
        else:
            all_fields = "0, NULL"
        return (
            f"{{ {n_patterns}, {n_musig}, "
            f"{len(parts)}, {base}_PARTS, {all_fields}, {1 if recurses else 0} }}"
        )

    def emit_specs_array(decl: str, enum_prefix: str, part_prefix: str,
                         entries: list[dict[str, Any]],
                         parts_list: list[EntryParts]) -> None:
        out.append(f"const cleartext_spec_t {decl} = {{")
        for entry, (name, parts, parts_all, _) in zip(entries, parts_list):
            n_patterns = len(entry["patterns"])
            n_musig = sum(1 for p in entry["patterns"] if is_musig_pattern(p))
            out.append(
                f"    [{enum_prefix}_{snake_upper(name)}] = "
                + spec_initializer(part_prefix, name, n_patterns, n_musig, parts,
                                   parts_all, entry_recurses(entry))
                + ","
            )
        out.append("};")
        out.append("")

    emit_specs_array("CT_TOP_LEVEL_SPECS[DC__COUNT]", "DC", "TOP", top_level, top_parts)
    emit_specs_array("CT_TAPLEAF_SPECS[TC__COUNT]", "TC", "LEAF", tapleaf, leaf_parts)

    return "\n".join(out)


def emit_vectors(vectors_doc: dict[str, Any]) -> str:
    vectors = vectors_doc.get("vector", [])
    out: list[str] = []
    out.append("// Generated by specs/bip388/gen.py. DO NOT EDIT.")
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
        flag = cbool(v.get("has_cleartext", False))
        if has_ct:
            ct_n = len(v["cleartext"])
            ct_ptr = f"vec_{i:03d}_ct"
        else:
            ct_n = 0
            ct_ptr = "NULL"
        out.append(
            "    { "
            f".template_str = {c_string_literal(template)},"
            f" .has_confusion_score = {cbool(has_score)},"
            f" .confusion_score = {score}ULL,"
            f" .has_cleartext_array = {cbool(has_ct)},"
            f" .cleartext_n = {ct_n}, .cleartext = {ct_ptr},"
            f" .has_has_cleartext = {cbool(has_flag)},"
            f" .cleartext_flag = {flag} }},"
        )
    out.append("};")
    out.append("static const size_t CT_VECTORS_N = sizeof(CT_VECTORS) / sizeof(CT_VECTORS[0]);")
    out.append("")
    return "\n".join(out)


def generate_outputs() -> list[tuple[Path, str]]:
    """Render every generated file in memory, returning (path, content) pairs.

    This is the single source of truth shared by both write and --check modes,
    so the two can never disagree about what "correct" output is.
    """
    spec_doc = load_toml(SPEC_FILE)
    vectors_doc = load_toml(VECTORS_FILE)
    return [
        (HEADER_OUT, emit_header(spec_doc) + "\n"),
        (SOURCE_OUT, emit_source(spec_doc) + "\n"),
        (MATCH_OUT, emit_match(spec_doc) + "\n"),
        (VECTORS_OUT, emit_vectors(vectors_doc) + "\n"),
    ]


def write_outputs(outputs: list[tuple[Path, str]]) -> int:
    """Write each generated file to disk, creating parent dirs as needed."""
    for path, content in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"wrote {path.relative_to(REPO_ROOT)}")
    return 0


def check_outputs(outputs: list[tuple[Path, str]]) -> int:
    """Compare each generated file against what is already on disk without
    modifying anything. Return 0 if everything is up to date, 1 otherwise.

    Prints a unified diff for any file that drifted, so CI logs show exactly
    what regenerating would change.
    """
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
        diff = difflib.unified_diff(
            current.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"{rel} (committed)",
            tofile=f"{rel} (generated)",
        )
        sys.stdout.writelines(diff)

    if stale:
        print()
        print(f"error: {len(stale)} generated file(s) are out of date:")
        for rel in stale:
            print(f"  - {rel}")
        print()
        print("Regenerate them by running:")
        print("    python3 specs/bip388/gen.py")
        print("and commit the result.")
        return 1

    print()
    print("All generated files are up to date.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gen.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        "-c",
        "--check",
        action="store_true",
        help="don't write anything; verify the committed files match what this "
        "script would generate and exit non-zero on any drift. Use this in "
        "CI to catch generated files that were not regenerated after the "
        "TOML spec changed.",
    )
    args = parser.parse_args(argv)

    outputs = generate_outputs()
    if args.check:
        return check_outputs(outputs)
    return write_outputs(outputs)


if __name__ == "__main__":
    sys.exit(main())
