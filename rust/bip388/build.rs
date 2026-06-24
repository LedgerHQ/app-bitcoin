//! Build script: generates the cleartext support files from `src/cleartext/specs/cleartext.toml`.
//!
//! Emits two files into `OUT_DIR`:
//!
//! * `cleartext_generated.rs` — always compiled. Contains class/pattern enums, the
//!   spec tables, the `classify*` and `cleartext_pattern` methods, and the score
//!   helpers used by the encoder/confusion-score paths.
//! * `cleartext_decode_generated.rs` — included only when `cleartext-decode` (or
//!   `cfg(test)`) is active. Contains the `from_cleartext_pattern` impls and the
//!   `top_level_variants` / `tapleaf_to_descriptors` reverse-construction
//!   functions.
//!
//! # TOML schema
//!
//! The spec file has two array-of-table sections — `[[top_level]]` (matched
//! against the root `DescriptorTemplate`) and `[[tapleaf]]` (matched against
//! each leaf of a `tr(...)` tap-tree). Both share the same per-entry schema:
//!
//! ```toml
//! [[top_level]]      # or [[tapleaf]]
//! name = "..."       # variant name in the generated DescriptorClass /
//!                    # TapleafClass. Must be a valid Rust identifier and
//!                    # unique within its section.
//! patterns = [       # one or more pattern strings; the classifier tries each
//!     "...",         # in order. The score for the entry equals the number of
//! ]                  # patterns whose round-trip check applies.
//! cleartext = [      # rendered cleartext template: literal strings interleaved
//!     "...",         # with `$binding` references to fields captured by the
//!     "$binding",    # patterns. Subject to the invariants below.
//! ]
//! ```
//!
//! ## Pattern grammar
//!
//! ```text
//! Pattern    := Keyword '(' Args? ')' | Keyword
//! Args       := Arg (',' Arg)*
//! Arg        := '$' Name                                   // binding
//!             | 'musig' '(' '$' Name ')'                   // only in Key positions
//!             | (WrapperChars ':')? Pattern                // nested sub-template
//! Keyword      := one of the descriptor fragments in `keyword_to_variant`
//! WrapperChars := any non-empty run of:  a s c t d v j n l u
//! ```
//!
//! ## Binding names
//!
//! The base name (with any trailing digits stripped) determines the binding's
//! kind. `$key`, `$key1`, `$key2` all resolve to single-key placeholders; the
//! digit only disambiguates two occurrences within one pattern.
//!
//! | base name             | kind       | host type            | notes                     |
//! |-----------------------|------------|----------------------|---------------------------|
//! | `key`, `internal_key` | Key        | `KeyExpression`      | plain key                 |
//! | `keys`                | KeyList    | `Vec<KeyExpression>` | —                         |
//! | `threshold`           | Threshold  | `u32`                | —                         |
//! | `timelock`            | Timelock   | `Timelock`           | matches `older`/`after`   |
//! | `sub`                 | Subpolicy  | `Box<TapleafClass>`  | classified non-combinator |
//! | `leaves`              | Leaves     | `Vec<TapleafClass>`  | `tr(...)` only            |
//!
//! A `$timelock` binding is special: the same binding matches both `older($N)`
//! (relative) and `after($N)` (absolute), and the classifier emits a validity
//! guard (`is_valid_relative_locktime` / `is_valid_absolute_locktime`) together
//! with the matching `Timelock::{Relative,Absolute}` wrapper, chosen by the
//! enclosing keyword. The four display forms (blocks / duration / block height /
//! date) are produced from the `Timelock` value at format time.
//!
//! # Invariants enforced at build time
//!
//! The runtime parser depends on these properties; the build fails with a
//! clear message if any is violated:
//!
//! * Each entry has at least one pattern, and each pattern string is fully
//!   consumed by the grammar above.
//! * Bindings shared between patterns of the same entry have a consistent
//!   kind (`class_fields_for_entry`).
//! * Cleartext references only bindings that the entry's patterns capture, and
//!   never `$leaves` (which is structural — recursed into, not rendered).
//! * Cleartext literals are non-empty, contain no `@`, and do not start or end
//!   with a digit — needed for unambiguous reverse parsing of numeric and
//!   key fields adjacent to a literal.
//! * No two `$binding` tokens appear adjacent in a cleartext template
//!   (`parse_cleartext`). This is the invariant the runtime
//!   `debug_assert!` in `parse_with_spec` (decode.rs) relies on.
//! * Within each section, no two entries collapse to the same cleartext
//!   "shape" — literal sequence with every dynamic field replaced by a
//!   sentinel (`check_cleartext_uniqueness`).
//! * Within each section, every `name` is unique (`check_entry_names_unique`).

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Spec deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Spec {
    #[serde(default)]
    top_level: Vec<Entry>,
    #[serde(default)]
    tapleaf: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    patterns: Vec<String>,
    cleartext: Vec<String>,
    /// Optional alternate template used when `threshold == number of keys`
    /// (n-of-n). It omits `$threshold` (implied by the key count) and renders
    /// e.g. "each of <keys> ...". See `parse_cleartext` / `emit_cleartext_pattern`.
    #[serde(default)]
    cleartext_all: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Pattern AST
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Pattern {
    keyword: String,
    args: Vec<PatternArg>,
}

#[derive(Clone, Debug)]
enum PatternArg {
    /// `$name` — a normal binding.
    Binding { name: String, kind: BindingKind },
    /// `musig($keys)` — only valid in a Key position. musig is n-of-n, so the
    /// threshold is implied by the key count; `threshold` is a synthesized
    /// Threshold binding name (see `synthesize_threshold_name`) whose value is
    /// set to `keys.len()` during lowering. `keys` is a KeyList binding.
    Musig { threshold: String, keys: String },
    /// A nested pattern, optionally preceded by miniscript wrappers (e.g. `v:`).
    Sub {
        wrappers: Vec<String>,
        inner: Box<Pattern>,
    },
    /// `(wrappers:)?$name` where `$name` is a `Subpolicy` binding.
    /// The wrappers are unwrapped in the AST before the sub-expression is
    /// classified as a `TapleafClass`.
    SubpolicyRef { wrappers: Vec<String>, name: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingKind {
    Key,
    KeyList,
    Threshold,
    /// A spending timelock: a `$timelock` binding matches both `older(...)`
    /// (relative) and `after(...)` (absolute). Host type is the runtime
    /// `Timelock` enum; the enclosing keyword selects the variant and the
    /// validity guard emitted by the classifier.
    Timelock,
    /// Bound to the `Option<TapTree>` of a `tr(...)` and lowered to
    /// `Vec<TapleafClass>` after classification.
    Leaves,
    /// Bound to a sub-expression that is classified as a `TapleafClass`.
    /// Host type is `Box<TapleafClass>`.
    Subpolicy,
}

/// Static metadata for a binding kind: the host-language type, the matching
/// `CleartextPart` / `CleartextValue` variant name, and the cursor method that
/// pops a value of this kind.
struct KindInfo {
    rust_type: &'static str,
    cleartext_variant: Option<&'static str>,
    cursor_method: Option<&'static str>,
}

impl BindingKind {
    fn info(self) -> KindInfo {
        match self {
            BindingKind::Key => KindInfo {
                rust_type: "KeyExpression",
                cleartext_variant: Some("KeyIndex"),
                cursor_method: Some("key_index"),
            },
            BindingKind::KeyList => KindInfo {
                rust_type: "Vec<KeyExpression>",
                cleartext_variant: Some("KeyIndices"),
                cursor_method: Some("key_indices"),
            },
            BindingKind::Threshold => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("Threshold"),
                cursor_method: Some("threshold"),
            },
            BindingKind::Timelock => KindInfo {
                rust_type: "Timelock",
                cleartext_variant: Some("Timelock"),
                cursor_method: Some("timelock"),
            },
            BindingKind::Leaves => KindInfo {
                rust_type: "Vec<TapleafClass>",
                cleartext_variant: None,
                cursor_method: None,
            },
            BindingKind::Subpolicy => KindInfo {
                rust_type: "alloc::boxed::Box<TapleafClass>",
                cleartext_variant: Some("Subpolicy"),
                cursor_method: Some("subpolicy"),
            },
        }
    }
}

/// Map a binding name to its kind. Trailing digits are stripped so `$key`,
/// `$key1`, `$key2` all share kind Key.
fn binding_name_kind(name: &str) -> Option<BindingKind> {
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    Some(match base {
        "key" | "internal_key" => BindingKind::Key,
        "keys" => BindingKind::KeyList,
        "threshold" => BindingKind::Threshold,
        "timelock" => BindingKind::Timelock,
        "leaves" => BindingKind::Leaves,
        "sub" => BindingKind::Subpolicy,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Descriptor-AST tables (mirror of the runtime AST in `bip388::mod`).
// ---------------------------------------------------------------------------

fn keyword_to_variant(kw: &str) -> Option<&'static str> {
    Some(match kw {
        "sh" => "Sh",
        "wsh" => "Wsh",
        "pkh" => "Pkh",
        "wpkh" => "Wpkh",
        "sortedmulti" => "Sortedmulti",
        "sortedmulti_a" => "Sortedmulti_a",
        "tr" => "Tr",
        "pk" => "Pk",
        "pk_k" => "Pk_k",
        "pk_h" => "Pk_h",
        "older" => "Older",
        "after" => "After",
        "andor" => "Andor",
        "and_v" => "And_v",
        "and_b" => "And_b",
        "and_n" => "And_n",
        "or_b" => "Or_b",
        "or_c" => "Or_c",
        "or_d" => "Or_d",
        "or_i" => "Or_i",
        "thresh" => "Thresh",
        "multi" => "Multi",
        "multi_a" => "Multi_a",
        _ => return None,
    })
}

fn wrapper_to_variant(c: char) -> Option<&'static str> {
    Some(match c {
        'a' => "A",
        's' => "S",
        'c' => "C",
        't' => "T",
        'd' => "D",
        'v' => "V",
        'j' => "J",
        'n' => "N",
        'l' => "L",
        'u' => "U",
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgKind {
    Key,
    Num,
    KeyList,
    Sub,
    /// Special: the second argument of `tr(...)` — `Option<TapTree>` lowered
    /// to a `Vec<TapleafClass>`.
    Tree,
}

fn variant_arg_kinds(variant: &str) -> &'static [ArgKind] {
    use ArgKind::*;
    match variant {
        "Pk" | "Pk_k" | "Pk_h" | "Pkh" | "Wpkh" => &[Key],
        "Older" | "After" => &[Num],
        "Multi" | "Multi_a" | "Sortedmulti" | "Sortedmulti_a" => &[Num, KeyList],
        "Tr" => &[Key, Tree],
        "And_v" | "And_b" | "And_n" | "Or_b" | "Or_c" | "Or_d" | "Or_i" => &[Sub, Sub],
        "Andor" => &[Sub, Sub, Sub],
        "Sh" | "Wsh" | "A" | "S" | "C" | "T" | "D" | "V" | "J" | "N" | "L" | "U" => &[Sub],
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Pattern parser (recursive descent over the spec-language pattern syntax).
//
// Grammar:
//
//   Pattern    := Ident '(' Args? ')' | Ident
//   Args       := Arg (',' Arg)*
//   Arg        := '$' Name                                   // binding
//               | 'musig' '(' '$' Name ')'                   // only in Key
//               | (WrapperChars ':')? Pattern                // sub
//   Name       := [a-z_][a-z0-9_]*
// ---------------------------------------------------------------------------

struct PatternParser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> PatternParser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn bump(&mut self, c: u8) -> Result<(), String> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected '{}' at byte {} in {:?}",
                c as char, self.pos, self.src
            ))
        }
    }

    fn try_bump(&mut self, c: u8) -> bool {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            Err(format!(
                "expected identifier at byte {} in {:?}",
                self.pos, self.src
            ))
        } else {
            Ok(self.src[start..self.pos].to_string())
        }
    }

    fn parse_binding_name(&mut self) -> Result<String, String> {
        self.bump(b'$')?;
        self.parse_ident()
    }

    fn parse_pattern(&mut self) -> Result<Pattern, String> {
        let kw = self.parse_ident()?;
        let variant = keyword_to_variant(&kw)
            .ok_or_else(|| format!("unknown descriptor keyword '{}'", kw))?;

        if !self.try_bump(b'(') {
            return Ok(Pattern {
                keyword: kw,
                args: Vec::new(),
            });
        }

        let arg_kinds = variant_arg_kinds(variant);
        let mut args = Vec::new();
        if !self.try_bump(b')') {
            loop {
                let kind = arg_kinds.get(args.len()).copied().unwrap_or(ArgKind::Sub);
                args.push(self.parse_arg(kind)?);
                self.skip_ws();
                if self.try_bump(b')') {
                    break;
                }
                self.bump(b',')?;
            }
        }
        Ok(Pattern { keyword: kw, args })
    }

    fn parse_arg(&mut self, expected: ArgKind) -> Result<PatternArg, String> {
        self.skip_ws();
        // Binding starts with '$'.
        if self.peek() == Some(b'$') {
            let name = self.parse_binding_name()?;
            let kind = binding_name_kind(&name)
                .ok_or_else(|| format!("unknown binding name '${}'", name))?;
            check_kind_matches(&name, kind, expected)?;
            return Ok(PatternArg::Binding { name, kind });
        }
        // `musig(...)` is only valid in a Key position; it's spelled like a
        // keyword so we have to peek.
        let saved = self.pos;
        if let Ok(ident) = self.parse_ident() {
            if ident == "musig" {
                if expected != ArgKind::Key {
                    return Err(format!(
                        "musig(...) is only allowed in a Key position; got {:?}",
                        expected
                    ));
                }
                self.bump(b'(')?;
                let keys = self.parse_binding_name()?;
                if binding_name_kind(&keys) != Some(BindingKind::KeyList) {
                    return Err(format!(
                        "the arg of musig(...) must be a $keys binding, got '${}'",
                        keys
                    ));
                }
                self.bump(b')')?;
                // musig is n-of-n: the threshold is implied by the number of keys
                // (there is no `musig(2, @0, @1, @2)`). We synthesize a Threshold
                // binding -- named like the keys binding with the "keys" base
                // swapped for "threshold" -- so the shared cleartext can still
                // reference `$threshold` (its value is set to `keys.len()` in
                // `lower`).
                let threshold = synthesize_threshold_name(&keys);
                return Ok(PatternArg::Musig { threshold, keys });
            }
            // Otherwise rewind: it's a keyword for a (possibly wrapped) sub-pattern.
            self.pos = saved;
        }
        // Optional wrappers + nested pattern.
        let mut wrappers = Vec::new();
        loop {
            let snap = self.pos;
            let id = self.parse_ident().ok();
            self.skip_ws();
            if let Some(name) = id {
                if self.peek() == Some(b':') {
                    for c in name.chars() {
                        let v = wrapper_to_variant(c).ok_or_else(|| {
                            format!("unknown wrapper character '{}' in '{}'", c, name)
                        })?;
                        wrappers.push(v.to_string());
                    }
                    self.pos += 1;
                    continue;
                }
            }
            self.pos = snap;
            break;
        }
        if expected != ArgKind::Sub && !wrappers.is_empty() {
            return Err(format!(
                "wrappers are only allowed in Sub positions; got {:?}",
                expected
            ));
        }
        // If the next token is `$name` where name resolves to Subpolicy, this
        // is a wrapped subpolicy reference rather than a nested pattern.
        if self.peek() == Some(b'$') {
            let snap = self.pos;
            if let Ok(name) = self.parse_binding_name() {
                if binding_name_kind(&name) == Some(BindingKind::Subpolicy) {
                    check_kind_matches(&name, BindingKind::Subpolicy, expected)?;
                    return Ok(PatternArg::SubpolicyRef { wrappers, name });
                }
            }
            // Not a Subpolicy binding — rewind and fall through to pattern parsing.
            self.pos = snap;
        }
        let inner = self.parse_pattern()?;
        Ok(PatternArg::Sub {
            wrappers,
            inner: Box::new(inner),
        })
    }
}

/// Synthesize the Threshold binding name paired with a musig `$keys` binding.
/// The "keys" base is swapped for "threshold", preserving any trailing digit
/// suffix so it stays consistent with a sibling pattern's explicit `$threshold`
/// (e.g. `keys` -> `threshold`, `keys1` -> `threshold1`).
fn synthesize_threshold_name(keys: &str) -> String {
    let base_len = keys.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    format!("threshold{}", &keys[base_len..])
}

fn check_kind_matches(name: &str, binding: BindingKind, positional: ArgKind) -> Result<(), String> {
    match (binding, positional) {
        (BindingKind::Key, ArgKind::Key)
        | (BindingKind::KeyList, ArgKind::KeyList)
        | (BindingKind::Threshold, ArgKind::Num)
        | (BindingKind::Leaves, ArgKind::Tree)
        | (BindingKind::Subpolicy | BindingKind::Timelock, ArgKind::Sub) => Ok(()),
        _ => Err(format!(
            "binding '${}' (kind {:?}) doesn't match the AST position kind {:?}",
            name, binding, positional
        )),
    }
}

// ---------------------------------------------------------------------------
// Per-entry analysis: class fields, cleartext template, etc.
// ---------------------------------------------------------------------------

/// Walk a pattern, collecting (binding name, kind) pairs in source order.
/// Each `musig(...)` primitive contributes its `threshold` and `keys` bindings
/// (kinds Threshold and KeyList).
fn pattern_bindings(p: &Pattern) -> Vec<(String, BindingKind)> {
    fn walk(p: &Pattern, out: &mut Vec<(String, BindingKind)>) {
        for arg in &p.args {
            match arg {
                PatternArg::Binding { name, kind } => out.push((name.clone(), *kind)),
                PatternArg::Musig { threshold, keys } => {
                    out.push((threshold.clone(), BindingKind::Threshold));
                    out.push((keys.clone(), BindingKind::KeyList));
                }
                PatternArg::Sub { inner, .. } => walk(inner, out),
                PatternArg::SubpolicyRef { name, .. } => {
                    out.push((name.clone(), BindingKind::Subpolicy))
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(p, &mut out);
    out
}

fn pattern_uses_musig(p: &Pattern) -> bool {
    p.args.iter().any(|a| match a {
        PatternArg::Musig { .. } => true,
        PatternArg::Sub { inner, .. } => pattern_uses_musig(inner),
        PatternArg::Binding { .. } | PatternArg::SubpolicyRef { .. } => false,
    })
}

/// Class field definitions for a spec entry: the union of bindings across all
/// patterns. Within an entry, all patterns must agree on (name, kind).
struct ClassFields {
    /// Field declaration order: first occurrence across patterns.
    order: Vec<String>,
    kinds: BTreeMap<String, BindingKind>,
}

fn class_fields_for_entry(entry: &Entry, patterns: &[Pattern]) -> Result<ClassFields, String> {
    let mut order = Vec::new();
    let mut kinds: BTreeMap<String, BindingKind> = BTreeMap::new();
    for p in patterns {
        for (name, kind) in pattern_bindings(p) {
            match kinds.get(&name) {
                Some(prev) if *prev != kind => {
                    return Err(format!(
                        "entry '{}': binding '${}' has inconsistent kinds across patterns: {:?} vs {:?}",
                        entry.name, name, prev, kind
                    ));
                }
                Some(_) => {}
                None => {
                    order.push(name.clone());
                    kinds.insert(name, kind);
                }
            }
        }
    }
    Ok(ClassFields { order, kinds })
}

#[derive(Clone, Debug)]
enum CleartextToken {
    Literal(String),
    Field { name: String, kind: BindingKind },
}

/// Lower the `cleartext = [...]` array of an entry. Also enforces the
/// invariants the runtime reverse parser depends on (see the module-level
/// "Invariants enforced at build time" section).
fn parse_cleartext(items: &[String], fields: &ClassFields) -> Result<Vec<CleartextToken>, String> {
    if items.is_empty() {
        return Err("cleartext template is empty".to_string());
    }
    let mut out = Vec::new();
    for item in items {
        if let Some(rest) = item.strip_prefix('$') {
            let kind = *fields
                .kinds
                .get(rest)
                .ok_or_else(|| format!("cleartext references unknown field '${}'", rest))?;
            if kind == BindingKind::Leaves {
                return Err(format!(
                    "cleartext cannot reference '${}' (Leaves are recursed into, not rendered)",
                    rest
                ));
            }
            out.push(CleartextToken::Field {
                name: rest.to_string(),
                kind,
            });
        } else {
            let bytes = item.as_bytes();
            if bytes.is_empty() {
                return Err("cleartext literal is empty".to_string());
            }
            if bytes[0].is_ascii_digit() {
                return Err(format!("cleartext literal {:?} starts with a digit", item));
            }
            if bytes[bytes.len() - 1].is_ascii_digit() {
                return Err(format!("cleartext literal {:?} ends with a digit", item));
            }
            if item.contains('@') {
                return Err(format!("cleartext literal {:?} contains '@'", item));
            }
            out.push(CleartextToken::Literal(item.clone()));
        }
    }
    for w in out.windows(2) {
        if let (CleartextToken::Field { .. }, CleartextToken::Field { .. }) = (&w[0], &w[1]) {
            return Err(
                "cleartext template has two adjacent dynamic fields without a literal separator"
                    .to_string(),
            );
        }
    }
    Ok(out)
}

/// The (first) field name of a given kind in an entry, if any.
fn field_of_kind(fields: &ClassFields, want: BindingKind) -> Option<String> {
    fields
        .order
        .iter()
        .find(|n| fields.kinds[n.as_str()] == want)
        .cloned()
}

/// Lower the optional `cleartext_all = [...]` array: the n-of-n rendering used
/// when `threshold == keys.len()`. It is parsed like `cleartext` but must omit
/// `$threshold` (which is implied by the key count and re-synthesized on decode)
/// while still referencing the `$keys` binding it is derived from. The entry must
/// bind both a Threshold and a KeyList for this to make sense.
fn parse_cleartext_all(
    items: &[String],
    fields: &ClassFields,
) -> Result<Vec<CleartextToken>, String> {
    let tokens = parse_cleartext(items, fields)?;
    let threshold = field_of_kind(fields, BindingKind::Threshold).ok_or_else(|| {
        "cleartext_all requires the entry to bind a $threshold (it is the n-of-n form)".to_string()
    })?;
    let keys = field_of_kind(fields, BindingKind::KeyList)
        .ok_or_else(|| "cleartext_all requires the entry to bind a $keys list".to_string())?;
    let references = |field: &str| {
        tokens
            .iter()
            .any(|t| matches!(t, CleartextToken::Field { name, .. } if name == field))
    };
    if references(&threshold) {
        return Err(format!(
            "cleartext_all must omit '${}' (it is implied by the key count)",
            threshold
        ));
    }
    if !references(&keys) {
        return Err(format!(
            "cleartext_all must reference '${}' (threshold is synthesized from it on decode)",
            keys
        ));
    }
    Ok(tokens)
}

struct ProcessedEntry {
    name: String,
    patterns: Vec<Pattern>,
    fields: ClassFields,
    cleartext: Vec<CleartextToken>,
    /// Alternate n-of-n template (used when `threshold == keys.len()`), parsed
    /// from the entry's `cleartext_all`. When present it omits `$threshold`, and
    /// a synthetic `<Name>All` pattern-kind variant carries it in the spec table.
    cleartext_all: Option<Vec<CleartextToken>>,
    /// True iff the class has a `$leaves` field — i.e., classification recurses
    /// into a tap-tree.
    recurses: bool,
}

fn process_entries(entries: &[Entry]) -> Result<Vec<ProcessedEntry>, String> {
    let mut processed = Vec::new();
    for entry in entries {
        let mut patterns = Vec::new();
        for src in &entry.patterns {
            let mut p = PatternParser::new(src);
            let pat = p
                .parse_pattern()
                .map_err(|e| format!("entry '{}': pattern {:?}: {}", entry.name, src, e))?;
            p.skip_ws();
            if p.pos != src.len() {
                return Err(format!(
                    "entry '{}': pattern {:?}: trailing input at byte {}",
                    entry.name, src, p.pos
                ));
            }
            patterns.push(pat);
        }
        if patterns.is_empty() {
            return Err(format!("entry '{}': no patterns", entry.name));
        }
        let fields = class_fields_for_entry(entry, &patterns)?;
        let cleartext = parse_cleartext(&entry.cleartext, &fields)
            .map_err(|e| format!("entry '{}': {}", entry.name, e))?;
        let cleartext_all = match &entry.cleartext_all {
            None => None,
            Some(items) => Some(
                parse_cleartext_all(items, &fields)
                    .map_err(|e| format!("entry '{}': cleartext_all: {}", entry.name, e))?,
            ),
        };
        let recurses = fields.kinds.values().any(|k| *k == BindingKind::Leaves);
        processed.push(ProcessedEntry {
            name: entry.name.clone(),
            patterns,
            fields,
            cleartext,
            cleartext_all,
            recurses,
        });
    }
    Ok(processed)
}

/// Reject duplicate `name` fields within a section. Without this check a
/// repeated name would emit two enum variants with the same identifier and
/// fail downstream Rust compilation with an opaque error.
fn check_entry_names_unique(entries: &[Entry], scope: &str) -> Result<(), String> {
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for e in entries {
        if seen.insert(e.name.as_str(), ()).is_some() {
            return Err(format!(
                "{} entry name '{}' is declared more than once",
                scope, e.name
            ));
        }
    }
    Ok(())
}

/// Inter-entry uniqueness: each entry's literal-sequence (the concatenation
/// of its `Literal` tokens, with dynamic fields replaced by a sentinel) must
/// be unique. This is the invariant on which the runtime parser relies for
/// unambiguous reverse parsing. Literals are lower-cased because the reverse
/// parser decodes on lower-cased input, so two entries differing only in letter
/// case would be ambiguous when decoding.
fn check_cleartext_uniqueness(entries: &[ProcessedEntry], scope: &str) -> Result<(), String> {
    fn signature(tokens: &[CleartextToken]) -> String {
        let mut sig = String::new();
        for tok in tokens {
            match tok {
                CleartextToken::Literal(s) => sig.push_str(&s.to_ascii_lowercase()),
                CleartextToken::Field { .. } => sig.push('\u{1}'),
            }
        }
        sig
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    // Each rendered form gets its own signature: the primary `cleartext` and, when
    // present, the n-of-n `cleartext_all` (which the reverse parser must also be
    // able to tell apart from every other form).
    let mut forms: Vec<(String, &[CleartextToken])> = Vec::new();
    for e in entries {
        forms.push((e.name.clone(), e.cleartext.as_slice()));
        if let Some(all) = &e.cleartext_all {
            forms.push((format!("{}All", e.name), all.as_slice()));
        }
    }
    for (label, tokens) in &forms {
        if let Some(prev) = seen.insert(signature(tokens), label.clone()) {
            return Err(format!(
                "{} forms '{}' and '{}' produce indistinguishable cleartext literal sequences",
                scope, prev, label
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Code emission
// ---------------------------------------------------------------------------
//
// The emitted file (~1100 lines of Rust) is built as one big `TokenStream`
// using `quote!` and then pretty-printed with `prettyplease`. Each section is
// produced by a small `emit_*` helper that returns its own `TokenStream`.

#[derive(Clone, Copy)]
struct ClassKind {
    class_enum: &'static str,
    pattern_enum: &'static str,
    /// True for `TapleafClass::Other(String)`; false for `DescriptorClass::Other`.
    other_has_string: bool,
}

const TOP_LEVEL: ClassKind = ClassKind {
    class_enum: "DescriptorClass",
    pattern_enum: "TopLevelPattern",
    other_has_string: false,
};

const TAPLEAF: ClassKind = ClassKind {
    class_enum: "TapleafClass",
    pattern_enum: "TapleafPattern",
    other_has_string: true,
};

impl ClassKind {
    fn class(self) -> Ident {
        format_ident!("{}", self.class_enum)
    }
    fn pattern(self) -> Ident {
        format_ident!("{}", self.pattern_enum)
    }
    fn other_pat(self) -> TokenStream {
        let c = self.class();
        if self.other_has_string {
            quote!(#c::Other(_))
        } else {
            quote!(#c::Other)
        }
    }
    fn other_ctor(self) -> TokenStream {
        let c = self.class();
        if self.other_has_string {
            quote!(#c::Other(<Self as alloc::string::ToString>::to_string(self)))
        } else {
            quote!(#c::Other)
        }
    }
}

fn id(s: &str) -> Ident {
    format_ident!("{}", s)
}

fn ts(s: &str) -> TokenStream {
    s.parse().expect("valid Rust tokens")
}

fn rust_type(k: BindingKind) -> TokenStream {
    ts(k.info().rust_type)
}

fn cleartext_variant(k: BindingKind) -> Ident {
    id(k.info().cleartext_variant.expect("renderable"))
}

fn cursor_method(k: BindingKind) -> Ident {
    id(k.info().cursor_method.expect("renderable"))
}

// ---------------------------------------------------------------------------
// classify / classify_as_tapleaf  — lower a pattern to a nested `if let` chain
// ---------------------------------------------------------------------------
//
// Each pattern lowers to a chain of nested `if let` / `if` blocks. On a
// successful match the innermost block does:
//
//     <preamble lets>
//     break '<label> <ClassEnum>::<Variant> { <field>: <expr>, ... };
//
// The chain is built bottom-up by `fold_steps`.

enum MatchStep {
    /// `if let DescriptorTemplate::<variant>(<temps>...) = <matchee>`.
    Variant {
        matchee: TokenStream,
        variant: Ident,
        temps: Vec<Ident>,
    },
    /// `if <expr>.is_plain()`.
    PlainKey { expr: Ident },
    /// `if <expr>.iter().all(|k| k.is_plain())`.
    PlainKeyList { expr: Ident },
    /// `if <expr>.is_musig() { let <temp> = <expr>; ... }`.
    MusigKey { expr: Ident, temp: Ident },
    /// Match the whole `older(...)`/`after(...)` node bound to a `$timelock`
    /// Sub-position binding into a `Timelock` (rejecting out-of-range or
    /// non-lock nodes). `bound` holds the resulting `Timelock`.
    ClassifyTimelock { expr: TokenStream, bound: Ident },
    /// Classify `<expr>.classify_as_tapleaf()` into `<classified>`;
    /// fail the match if it is `Other` or any combinator variant.
    /// `combinator_variants` is the list of TapleafClass variant names that
    /// have Subpolicy fields (used to prevent nesting).
    ClassifySubpolicy {
        expr: TokenStream,
        classified: Ident,
        combinator_variants: Vec<Ident>,
    },
}

struct Counter(usize);
impl Counter {
    fn next(&mut self) -> Ident {
        let s = format_ident!("__t{}", self.0);
        self.0 += 1;
        s
    }
}

struct Lowered {
    steps: Vec<MatchStep>,
    /// Statements emitted inside the innermost block before the `break`.
    preamble: Vec<TokenStream>,
    /// User-binding-name → expression used to build the class-enum field.
    bindings: BTreeMap<String, TokenStream>,
}

fn lower_pattern(pat: &Pattern, combinator_variants: &[Ident]) -> Lowered {
    let mut counter = Counter(0);
    let mut l = Lowered {
        steps: Vec::new(),
        preamble: Vec::new(),
        bindings: BTreeMap::new(),
    };
    lower(pat, quote!(__m), &mut counter, &mut l, combinator_variants);
    l
}

fn lower(
    pat: &Pattern,
    matchee: TokenStream,
    c: &mut Counter,
    l: &mut Lowered,
    combinator_variants: &[Ident],
) {
    let variant_str = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let variant = id(variant_str);
    let arg_kinds = variant_arg_kinds(variant_str);

    let temps: Vec<Ident> = pat.args.iter().map(|_| c.next()).collect();
    l.steps.push(MatchStep::Variant {
        matchee,
        variant,
        temps: temps.clone(),
    });

    for (i, (arg, tv)) in pat.args.iter().zip(temps.iter()).enumerate() {
        let kind = arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub);
        match arg {
            PatternArg::Binding { name, kind: bkind } => match kind {
                ArgKind::Key => {
                    l.steps.push(MatchStep::PlainKey { expr: tv.clone() });
                    l.bindings.insert(name.clone(), quote!(#tv));
                }
                ArgKind::Num => {
                    l.bindings.insert(name.clone(), quote!(*#tv));
                }
                ArgKind::KeyList => {
                    l.steps.push(MatchStep::PlainKeyList { expr: tv.clone() });
                    l.bindings.insert(name.clone(), quote!(#tv));
                }
                // A Subpolicy binding in a Sub position with no wrappers:
                // classify the expression directly (same as SubpolicyRef with empty wrappers).
                ArgKind::Sub if *bkind == BindingKind::Subpolicy => {
                    let classify_expr = quote!(#tv.as_ref());
                    let classified = format_ident!("__cls_{}", name);
                    l.steps.push(MatchStep::ClassifySubpolicy {
                        expr: classify_expr,
                        classified: classified.clone(),
                        combinator_variants: combinator_variants.to_vec(),
                    });
                    l.bindings.insert(name.clone(), quote!(#classified));
                }
                // A Timelock binding in a Sub position matches the whole
                // `older(...)`/`after(...)` node; `ClassifyTimelock` captures the
                // resulting `Timelock` value (or fails the match).
                ArgKind::Sub if *bkind == BindingKind::Timelock => {
                    let bound = format_ident!("__tl_{}", name);
                    l.steps.push(MatchStep::ClassifyTimelock {
                        expr: quote!(#tv.as_ref()),
                        bound: bound.clone(),
                    });
                    l.bindings.insert(name.clone(), quote!(#bound));
                }
                ArgKind::Sub | ArgKind::Tree => {
                    l.bindings.insert(name.clone(), quote!(#tv));
                }
            },
            PatternArg::Musig { threshold, keys } => {
                debug_assert_eq!(kind, ArgKind::Key);
                let m = c.next();
                l.steps.push(MatchStep::MusigKey {
                    expr: tv.clone(),
                    temp: m.clone(),
                });
                let kv = c.next();
                let kt = c.next();
                // Propagate the musig's shared (num1, num2) onto each plain key.
                l.preamble.push(quote! {
                    let #kv: alloc::vec::Vec<KeyExpression> = #m.musig_key_indices()
                        .expect("is_musig checked")
                        .iter()
                        .map(|&__i| KeyExpression::plain(__i, #m.num1, #m.num2))
                        .collect();
                });
                l.preamble.push(quote!(let #kt: u32 = #kv.len() as u32;));
                l.bindings.insert(threshold.clone(), quote!(#kt));
                l.bindings.insert(keys.clone(), quote!(#kv));
            }
            PatternArg::Sub { wrappers, inner } => {
                let mut current: TokenStream = quote!(#tv);
                let mut current_boxed = matches!(kind, ArgKind::Sub);
                for w in wrappers {
                    let wv = id(w);
                    let wt = c.next();
                    let m: TokenStream = if current_boxed {
                        quote!(#current.as_ref())
                    } else {
                        current.clone()
                    };
                    l.steps.push(MatchStep::Variant {
                        matchee: m,
                        variant: wv,
                        temps: vec![wt.clone()],
                    });
                    current = quote!(#wt);
                    current_boxed = true;
                }
                let next_matchee: TokenStream = if current_boxed {
                    quote!(#current.as_ref())
                } else {
                    current
                };
                lower(inner, next_matchee, c, l, combinator_variants);
            }
            PatternArg::SubpolicyRef { wrappers, name } => {
                // Unwrap through each wrapper in the AST (e.g. `v:` → V node).
                let mut current: TokenStream = quote!(#tv);
                for w in wrappers {
                    let wv = id(w);
                    let wt = c.next();
                    l.steps.push(MatchStep::Variant {
                        matchee: quote!(#current.as_ref()),
                        variant: wv,
                        temps: vec![wt.clone()],
                    });
                    current = quote!(#wt);
                }
                // After unwrapping wrappers, `current` is a temp Ident holding a
                // `Box<DescriptorTemplate>`. We classify `current.as_ref()`.
                let classify_expr = quote!(#current.as_ref());
                let classified = format_ident!("__cls_{}", name);
                l.steps.push(MatchStep::ClassifySubpolicy {
                    expr: classify_expr,
                    classified: classified.clone(),
                    combinator_variants: combinator_variants.to_vec(),
                });
                // The binding holds the classified TapleafClass value; build_innermost
                // wraps it in Box::new() for the Subpolicy field.
                l.bindings.insert(name.clone(), quote!(#classified));
            }
        }
    }
}

fn fold_steps(steps: &[MatchStep], inner: TokenStream) -> TokenStream {
    let mut code = inner;
    for step in steps.iter().rev() {
        code = match step {
            MatchStep::Variant {
                matchee,
                variant,
                temps,
            } => {
                if temps.is_empty() {
                    quote!(if let DescriptorTemplate::#variant = #matchee { #code })
                } else if variant == "Tr" && temps.len() == 1 {
                    // A `tr($key)` pattern (no tree arg) matches only a leaf-less
                    // taproot: `Tr(key, None)`.
                    let key = &temps[0];
                    quote!(if let DescriptorTemplate::Tr(#key, None) = #matchee { #code })
                } else {
                    quote!(if let DescriptorTemplate::#variant(#(#temps),*) = #matchee { #code })
                }
            }
            MatchStep::PlainKey { expr } => quote!(if #expr.is_plain() { #code }),
            MatchStep::PlainKeyList { expr } => {
                quote!(if #expr.iter().all(|__k| __k.is_plain()) { #code })
            }
            MatchStep::MusigKey { expr, temp } => quote! {
                if #expr.is_musig() {
                    let #temp = #expr;
                    #code
                }
            },
            MatchStep::ClassifyTimelock { expr, bound } => quote! {
                let __tl = match #expr {
                    DescriptorTemplate::Older(__n) if is_valid_relative_locktime(*__n) => {
                        Some(Timelock::Relative(*__n))
                    }
                    DescriptorTemplate::After(__n) if is_valid_absolute_locktime(*__n) => {
                        Some(Timelock::Absolute(*__n))
                    }
                    _ => None,
                };
                if let Some(#bound) = __tl { #code }
            },
            MatchStep::ClassifySubpolicy {
                expr,
                classified,
                combinator_variants,
            } => {
                // Reject Other and all combinator variants (no nesting).
                let reject_pat = if combinator_variants.is_empty() {
                    quote!(TapleafClass::Other(_))
                } else {
                    quote!(TapleafClass::Other(_) #(| TapleafClass::#combinator_variants { .. })*)
                };
                quote! {
                    let #classified = #expr.classify_as_tapleaf();
                    if !matches!(#classified, #reject_pat) { #code }
                }
            }
        };
    }
    code
}

fn build_innermost(
    l: &Lowered,
    fields: &ClassFields,
    ck: ClassKind,
    variant: &Ident,
    label: &TokenStream,
) -> TokenStream {
    let class = ck.class();
    let preamble = &l.preamble;
    let break_expr = if fields.order.is_empty() {
        quote!(break #label #class::#variant;)
    } else {
        let assigns = fields.order.iter().map(|fname| {
            let kind = fields.kinds[fname];
            let bound = l.bindings.get(fname).expect("binding present");
            let f = id(fname);
            let value = match kind {
                BindingKind::Key | BindingKind::KeyList => quote!(#bound.clone()),
                BindingKind::Threshold | BindingKind::Timelock => quote!(#bound),
                BindingKind::Leaves => {
                    quote!(#bound.as_ref().map(tree_to_leaves).unwrap_or_default())
                }
                BindingKind::Subpolicy => quote!(alloc::boxed::Box::new(#bound)),
            };
            quote!(#f: #value)
        });
        quote!(break #label #class::#variant { #(#assigns),* };)
    };
    quote! {
        #(#preamble)*
        #break_expr
    }
}

fn emit_classify(entries: &[ProcessedEntry], ck: ClassKind, fn_name: &str) -> TokenStream {
    let fn_id = id(fn_name);
    let class = ck.class();
    let label: TokenStream = format!("'{fn_name}").parse().unwrap();
    let other = ck.other_ctor();

    // Collect all TapleafClass variant names that contain Subpolicy fields.
    // These are excluded from sub-policy classification to prevent nesting.
    let combinator_variants: Vec<Ident> = entries
        .iter()
        .filter(|e| {
            e.fields
                .kinds
                .values()
                .any(|k| *k == BindingKind::Subpolicy)
        })
        .map(|e| id(&e.name))
        .collect();

    let blocks: Vec<TokenStream> = entries
        .iter()
        .flat_map(|entry| {
            entry.patterns.iter().map(|pat| {
                let l = lower_pattern(pat, &combinator_variants);
                let variant = id(&entry.name);
                let inner = build_innermost(&l, &entry.fields, ck, &variant, &label);
                fold_steps(&l.steps, inner)
            })
        })
        .collect();

    quote! {
        fn #fn_id(&self) -> #class {
            #label: {
                let __m: &DescriptorTemplate = self;
                #(#blocks)*
                #other
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enums and constants
// ---------------------------------------------------------------------------

/// The synthetic pattern-kind variant name carrying an entry's n-of-n
/// (`cleartext_all`) form, e.g. `Multisig` -> `MultisigAll`.
fn all_variant_name(entry: &ProcessedEntry) -> String {
    format!("{}All", entry.name)
}

fn emit_pattern_kind_enum(name: &str, entries: &[ProcessedEntry]) -> TokenStream {
    let ident = id(name);
    // One variant per entry, plus a synthetic `<Name>All` variant for each entry
    // that declares an n-of-n (`cleartext_all`) rendering. These extra variants
    // are spec-table tags only; they map back to the *base* class variant.
    let variants: Vec<Ident> = entries
        .iter()
        .flat_map(|e| {
            let mut v = vec![id(&e.name)];
            if e.cleartext_all.is_some() {
                v.push(id(&all_variant_name(e)));
            }
            v
        })
        .collect();
    quote! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum #ident {
            #(#variants,)*
        }
    }
}

fn emit_class_enum(ck: ClassKind, entries: &[ProcessedEntry]) -> TokenStream {
    let ident = ck.class();
    let variants: Vec<TokenStream> = entries
        .iter()
        .map(|e| {
            let v = id(&e.name);
            if e.fields.order.is_empty() {
                quote!(#v)
            } else {
                let fields = e.fields.order.iter().map(|fname| {
                    let f = id(fname);
                    let ty = rust_type(e.fields.kinds[fname]);
                    quote!(#f: #ty)
                });
                quote!(#v { #(#fields),* })
            }
        })
        .collect();
    let other = if ck.other_has_string {
        quote!(Other(String))
    } else {
        quote!(Other)
    };
    quote! {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) enum #ident {
            #(#variants,)*
            #other,
        }
    }
}

fn emit_specs_const(name: &str, ck: ClassKind, entries: &[ProcessedEntry]) -> TokenStream {
    let const_name = id(name);
    let pattern = ck.pattern();
    let spec = |kind: Ident, tokens: &[CleartextToken]| -> TokenStream {
        let parts = tokens.iter().map(|t| match t {
            CleartextToken::Literal(s) => quote!(CleartextPart::Literal(#s)),
            CleartextToken::Field { kind, .. } => {
                let v = cleartext_variant(*kind);
                quote!(CleartextPart::#v)
            }
        });
        quote! {
            CleartextSpec {
                kind: #pattern::#kind,
                parts: &[#(#parts),*],
            }
        }
    };
    let items: Vec<TokenStream> = entries
        .iter()
        .flat_map(|e| {
            let mut specs = vec![spec(id(&e.name), &e.cleartext)];
            if let Some(all) = &e.cleartext_all {
                specs.push(spec(id(&all_variant_name(e)), all));
            }
            specs
        })
        .collect();
    quote! {
        pub(super) const #const_name: &[CleartextSpec<#pattern>] = &[#(#items),*];
    }
}

// ---------------------------------------------------------------------------
// cleartext_pattern (forward: class -> (PatternKind, Vec<CleartextValue>))
// ---------------------------------------------------------------------------

/// The `CleartextValue::*` constructors for a token list, in order — the encode
/// side of `parse_cleartext_value`.
fn cleartext_values(tokens: &[CleartextToken]) -> Vec<TokenStream> {
    tokens
        .iter()
        .filter_map(|t| match t {
            CleartextToken::Field { name, kind } => {
                let ctor = cleartext_variant(*kind);
                let n = id(name);
                let arg: TokenStream = match kind {
                    BindingKind::Key | BindingKind::KeyList | BindingKind::Subpolicy => {
                        quote!(#n.clone())
                    }
                    _ => quote!(*#n),
                };
                Some(quote!(CleartextValue::#ctor(#arg)))
            }
            _ => None,
        })
        .collect()
}

fn emit_cleartext_pattern(entries: &[ProcessedEntry], ck: ClassKind) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    let other_pat = ck.other_pat();

    let arms: Vec<TokenStream> = entries
        .iter()
        .map(|e| {
            let variant = id(&e.name);
            match &e.cleartext_all {
                // No n-of-n form: a single arm rendering the only template.
                None => {
                    let referenced: Vec<Ident> = e
                        .cleartext
                        .iter()
                        .filter_map(|t| match t {
                            CleartextToken::Field { name, .. } => Some(id(name)),
                            _ => None,
                        })
                        .collect();
                    let destructure: TokenStream =
                        match (e.fields.order.is_empty(), referenced.is_empty()) {
                            (true, _) => quote!(),
                            (false, true) => quote!({ .. }),
                            (false, false) => quote!({ #(#referenced),*, .. }),
                        };
                    let values = cleartext_values(&e.cleartext);
                    quote! {
                        #class::#variant #destructure => {
                            Some((#pattern::#variant, alloc::vec![#(#values),*]))
                        }
                    }
                }
                // Has an n-of-n form: pick it when `threshold == keys.len()`,
                // otherwise the primary form (same idiom as `emit_score_arm`).
                Some(all_tokens) => {
                    let variant_all = id(&all_variant_name(e));
                    let thr = id(&field_of_kind(&e.fields, BindingKind::Threshold)
                        .expect("cleartext_all validated to require a Threshold field"));
                    let keys = id(&field_of_kind(&e.fields, BindingKind::KeyList)
                        .expect("cleartext_all validated to require a KeyList field"));
                    // Bind the union of fields referenced by either form, plus the
                    // threshold/keys the condition needs. Dedup, preserving none of
                    // the order (irrelevant in a struct destructure).
                    let mut names: BTreeMap<String, ()> = BTreeMap::new();
                    for t in e.cleartext.iter().chain(all_tokens.iter()) {
                        if let CleartextToken::Field { name, .. } = t {
                            names.insert(name.clone(), ());
                        }
                    }
                    names.insert(thr.to_string(), ());
                    names.insert(keys.to_string(), ());
                    let bound: Vec<Ident> = names.keys().map(|n| id(n)).collect();
                    let any_values = cleartext_values(&e.cleartext);
                    let all_values = cleartext_values(all_tokens);
                    quote! {
                        #class::#variant { #(#bound),*, .. } => {
                            if *#thr as usize == #keys.len() {
                                Some((#pattern::#variant_all, alloc::vec![#(#all_values),*]))
                            } else {
                                Some((#pattern::#variant, alloc::vec![#(#any_values),*]))
                            }
                        }
                    }
                }
            }
        })
        .collect();

    quote! {
        impl #class {
            fn cleartext_pattern(&self) -> Option<(#pattern, alloc::vec::Vec<CleartextValue>)> {
                match self {
                    #(#arms,)*
                    #other_pat => None,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TapleafClass::{order,per_leaf_score} + DescriptorClass::outer_score
// ---------------------------------------------------------------------------

fn emit_tapleaf_helpers(tapleaf: &[ProcessedEntry]) -> TokenStream {
    let order_arms = tapleaf.iter().enumerate().map(|(i, e)| {
        let v = id(&e.name);
        let pat: TokenStream = if e.fields.order.is_empty() {
            quote!()
        } else {
            quote!({ .. })
        };
        let idx = i as u32;
        quote!(TapleafClass::#v #pat => #idx)
    });
    let last = tapleaf.len() as u32;
    let score_arms = tapleaf.iter().map(|e| emit_score_arm(e, "TapleafClass"));

    quote! {
        impl TapleafClass {
            fn order(&self) -> u32 {
                match self {
                    #(#order_arms,)*
                    TapleafClass::Other(_) => #last,
                }
            }

            fn per_leaf_score(&self) -> u64 {
                match self {
                    #(#score_arms)*
                    TapleafClass::Other(_) => 1,
                }
            }
        }
    }
}

fn emit_outer_score(top_level: &[ProcessedEntry]) -> TokenStream {
    let arms = top_level
        .iter()
        .map(|e| emit_score_arm(e, "DescriptorClass"));
    quote! {
        impl DescriptorClass {
            fn outer_score(&self) -> u64 {
                match self {
                    #(#arms)*
                    DescriptorClass::Other => 1,
                }
            }
        }
    }
}

/// One match arm of `per_leaf_score()` / `outer_score()`. Score equals the
/// number of patterns whose round-trip applies: non-musig patterns always do,
/// musig patterns require `threshold == len(keys)` (keys are guaranteed plain
/// by classification).
///
/// For entries with Subpolicy fields the score is the product of the
/// sub-policies' individual per-leaf scores.
fn emit_score_arm(entry: &ProcessedEntry, class_enum: &str) -> TokenStream {
    let class = id(class_enum);
    let variant = id(&entry.name);

    let subpolicy_names: Vec<&str> = entry
        .fields
        .order
        .iter()
        .filter(|n| entry.fields.kinds[*n] == BindingKind::Subpolicy)
        .map(String::as_str)
        .collect();

    if !subpolicy_names.is_empty() {
        let sub_idents: Vec<Ident> = subpolicy_names.iter().map(|n| id(n)).collect();
        let destructure = quote!({ #(#sub_idents),*, .. });
        let product = sub_idents.iter().fold(
            quote!(1u64),
            |acc, n| quote!(#acc.saturating_mul(#n.per_leaf_score())),
        );
        return quote!(#class::#variant #destructure => #product,);
    }

    let plain: u64 = entry
        .patterns
        .iter()
        .filter(|p| !pattern_uses_musig(p))
        .count() as u64;
    let musig: u64 = entry
        .patterns
        .iter()
        .filter(|p| pattern_uses_musig(p))
        .count() as u64;

    let destructure: TokenStream = if entry.fields.order.is_empty() {
        quote!()
    } else if musig > 0 {
        quote!({ threshold, keys, .. })
    } else {
        quote!({ .. })
    };

    let body: TokenStream = if musig == 0 {
        quote!(#plain)
    } else if musig == 1 {
        quote!(#plain + if *threshold as usize == keys.len() { 1 } else { 0 })
    } else {
        quote!(#plain + if *threshold as usize == keys.len() { #musig } else { 0 })
    };

    quote!(#class::#variant #destructure => #body,)
}

// ---------------------------------------------------------------------------
// from_cleartext_pattern (reverse: (PatternKind, Vec<CleartextValue>) -> class)
// ---------------------------------------------------------------------------

fn emit_from_cleartext_pattern(entries: &[ProcessedEntry], ck: ClassKind) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    // One arm per pattern-kind variant: the base form, plus the synthetic
    // `<Name>All` form (which reconstructs the same base class variant).
    let arms: Vec<TokenStream> = entries
        .iter()
        .flat_map(|e| {
            let mut arms = vec![emit_from_cleartext_arm(e, ck, &id(&e.name), &e.cleartext)];
            if let Some(all) = &e.cleartext_all {
                arms.push(emit_from_cleartext_arm(
                    e,
                    ck,
                    &id(&all_variant_name(e)),
                    all,
                ));
            }
            arms
        })
        .collect();
    quote! {
        impl #class {
            fn from_cleartext_pattern(
                kind: #pattern,
                values: alloc::vec::Vec<CleartextValue>,
            ) -> Option<Self> {
                let mut __cur = CleartextValueCursor::new(values);
                let __res = match kind {
                    #(#arms)*
                };
                __cur.finish()?;
                __res
            }
        }
    }
}

/// Emit one `from_cleartext_pattern` match arm. `src_variant` is the pattern-kind
/// being matched (the base entry name, or its synthetic `<Name>All`); `tokens` is
/// the corresponding template. The arm always reconstructs the *base* class
/// variant (`entry.name`). A class field absent from `tokens` is filled in:
///   - `$leaves` -> empty Vec (the caller fills it via the per-leaf product);
///   - `$threshold` -> `keys.len()` (n-of-n forms that omit the count; the value
///     is bound up front so struct-field order can't move `keys` before the read).
fn emit_from_cleartext_arm(
    entry: &ProcessedEntry,
    ck: ClassKind,
    src_variant: &Ident,
    tokens: &[CleartextToken],
) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    let variant = id(&entry.name);

    let mut available: BTreeMap<String, ()> = BTreeMap::new();
    let pops: Vec<TokenStream> = tokens
        .iter()
        .filter_map(|t| match t {
            CleartextToken::Field { name, kind } => {
                let m = cursor_method(*kind);
                let n = id(name);
                available.insert(name.clone(), ());
                Some(quote!(let #n = __cur.#m()?;))
            }
            _ => None,
        })
        .collect();

    // Synthesize a missing Threshold from its paired KeyList. Emitted as a binding
    // (not inline in the struct) so it reads `keys` before the struct moves it.
    let mut synth: Vec<TokenStream> = Vec::new();
    for name in &entry.fields.order {
        if available.contains_key(name) {
            continue;
        }
        if entry.fields.kinds[name.as_str()] == BindingKind::Threshold {
            let keys = field_of_kind(&entry.fields, BindingKind::KeyList).unwrap_or_else(|| {
                panic!(
                    "entry '{}': template omits '${}' but has no $keys to synthesize it from",
                    entry.name, name
                )
            });
            assert!(
                available.contains_key(&keys),
                "entry '{}': cannot synthesize '${}' because '${}' is not in the template",
                entry.name,
                name,
                keys
            );
            let n = id(name);
            let k = id(&keys);
            synth.push(quote!(let #n = #k.len() as u32;));
            available.insert(name.clone(), ());
        }
    }

    let body = if entry.fields.order.is_empty() {
        quote!(Some(#class::#variant))
    } else {
        let fields = entry.fields.order.iter().map(|name| {
            let n = id(name);
            if available.contains_key(name) {
                quote!(#n)
            } else {
                // The only remaining unfilled field is `$leaves`; it's filled in
                // by the caller (`parse_top_level_candidates`) via Cartesian
                // product over per-leaf candidates, so initialize it empty.
                debug_assert_eq!(entry.fields.kinds[name.as_str()], BindingKind::Leaves);
                quote!(#n: alloc::vec::Vec::new())
            }
        });
        quote!(Some(#class::#variant { #(#fields),* }))
    };

    quote! {
        #pattern::#src_variant => {
            #(#pops)*
            #(#synth)*
            #body
        },
    }
}

// ---------------------------------------------------------------------------
// top_level_variants + tapleaf_to_descriptors (reverse construction)
// ---------------------------------------------------------------------------

fn emit_top_level_variants(top_level: &[ProcessedEntry]) -> TokenStream {
    let arms: Vec<TokenStream> = top_level.iter().map(emit_top_level_variants_arm).collect();
    quote! {
        fn top_level_variants(
            class: DescriptorClass,
        ) -> Result<alloc::boxed::Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextDecodeError>
        {
            match class {
                #(#arms)*
                DescriptorClass::Other => Err(CleartextDecodeError::UnrecognizedPattern),
            }
        }
    }
}

fn emit_top_level_variants_arm(entry: &ProcessedEntry) -> TokenStream {
    let variant = id(&entry.name);

    // Destructure only fields the body references. For recursing entries we
    // always need `leaves`; non-musig recursing entries also need `internal_key`;
    // musig recursing entries need `keys`. Non-recursing entries reference all
    // fields by name (small classes; each name is used in at least one pattern).
    let destructure: TokenStream = if entry.fields.order.is_empty() {
        quote!()
    } else if entry.recurses {
        let key_field = if entry.fields.kinds.contains_key("internal_key") {
            id("internal_key")
        } else {
            id("keys")
        };
        let leaves = id("leaves");
        quote!({ #leaves, #key_field, .. })
    } else {
        let used: Vec<Ident> = entry.fields.order.iter().map(|s| id(s)).collect();
        quote!({ #(#used),* })
    };

    let body: TokenStream = if entry.recurses {
        let key_local = emit_internal_key_local(entry);
        quote! {
            let mut __per_leaf_variants: alloc::vec::Vec<alloc::vec::Vec<DescriptorTemplate>> =
                alloc::vec::Vec::new();
            for __leaf in &leaves {
                __per_leaf_variants.push(tapleaf_to_descriptors(__leaf)?);
            }
            #key_local
            if leaves.is_empty() {
                return Ok(alloc::boxed::Box::new(core::iter::once(
                    DescriptorTemplate::Tr(__internal_key, None),
                )));
            }
            let __trees = enumerate_taptrees(__per_leaf_variants);
            Ok(alloc::boxed::Box::new(__trees.map(move |__t| {
                let mut __dt = DescriptorTemplate::Tr(__internal_key.clone(), Some(__t));
                canonicalize_derivations(&mut __dt);
                __dt
            })))
        }
    } else {
        let block = emit_pattern_construction_block(entry, /*owned=*/ true);
        quote! {
            #block
            Ok(alloc::boxed::Box::new(__out.into_iter()))
        }
    };

    quote! {
        DescriptorClass::#variant #destructure => { #body },
    }
}

/// Build the body of a `tapleaf_to_descriptors` arm for an entry that has
/// Subpolicy fields. Generates a Cartesian product over the descriptor-template
/// sets for each sub-policy, wrapping them as required by the single pattern.
///
/// Assumes `subpolicy_names` is non-empty and `entry.patterns` has exactly one
/// pattern (all current combinator entries have one).
fn emit_subpolicy_construction_block(
    entry: &ProcessedEntry,
    subpolicy_names: &[&str],
) -> TokenStream {
    // For each sub-policy field, emit a `let <name>_descs = tapleaf_to_descriptors(&**<name>)?;`.
    // The `&**` is needed because the match arm binds sub-policy fields as
    // `&Box<TapleafClass>` (when matching on `leaf: &TapleafClass`), whereas
    // `tapleaf_to_descriptors` expects `&TapleafClass`.
    let desc_lets: Vec<TokenStream> = subpolicy_names
        .iter()
        .map(|n| {
            let n_ident = id(n);
            let d_ident = format_ident!("{}_descs", n);
            quote!(let #d_ident = tapleaf_to_descriptors(&**#n_ident)?;)
        })
        .collect();

    assert!(
        entry.patterns.len() == 1,
        "entry '{}' has Subpolicy fields but {} patterns; expected exactly 1",
        entry.name,
        entry.patterns.len()
    );

    // Build the single pattern's construction expression, substituting each
    // sub-policy binding with its loop variable.
    // We derive the construction expression from `entry.patterns[0]`.
    let pat = &entry.patterns[0];
    let sub_loop_vars: Vec<(String, Ident)> = subpolicy_names
        .iter()
        .map(|n| (n.to_string(), format_ident!("__s_{}", n)))
        .collect();

    let construction_expr = build_subpolicy_construction_expr(pat, &sub_loop_vars);

    // Nested for-loops over each sub-policy's descriptor set.
    let loop_vars: Vec<Ident> = sub_loop_vars.iter().map(|(_, v)| v.clone()).collect();
    let desc_idents: Vec<Ident> = subpolicy_names
        .iter()
        .map(|n| format_ident!("{}_descs", n))
        .collect();

    // Build nested loops (last sub-policy is the innermost).
    let push_stmt = quote!(__out.push(#construction_expr););
    let loops = desc_idents.iter().zip(loop_vars.iter()).rev().fold(
        push_stmt,
        |body, (desc, var)| quote!(for #var in &#desc { #body }),
    );

    quote! {
        let mut __out: alloc::vec::Vec<DescriptorTemplate> = alloc::vec::Vec::new();
        #(#desc_lets)*
        #loops
        Ok(__out)
    }
}

/// Build a `DescriptorTemplate` construction expression for a pattern that
/// contains `SubpolicyRef` args. Each sub-policy arg is replaced by its
/// corresponding loop variable (a `&DescriptorTemplate`), cloned and optionally
/// wrapped.
fn build_subpolicy_construction_expr(pat: &Pattern, sub_vars: &[(String, Ident)]) -> TokenStream {
    let variant_str = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let variant = id(variant_str);
    let arg_kinds = variant_arg_kinds(variant_str);
    if pat.args.is_empty() {
        return quote!(DescriptorTemplate::#variant);
    }
    let args = pat.args.iter().enumerate().map(|(i, a)| {
        build_subpolicy_arg_expr(
            a,
            arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub),
            sub_vars,
        )
    });
    quote!(DescriptorTemplate::#variant(#(#args),*))
}

fn build_subpolicy_arg_expr(
    arg: &PatternArg,
    kind: ArgKind,
    sub_vars: &[(String, Ident)],
) -> TokenStream {
    // Both `SubpolicyRef { wrappers, name }` and `Binding { kind: Subpolicy, name }`
    // represent sub-policy arguments and are handled identically here.
    let (wrappers, name): (&[String], &str) = match arg {
        PatternArg::SubpolicyRef { wrappers, name } => (wrappers.as_slice(), name.as_str()),
        PatternArg::Binding {
            name,
            kind: BindingKind::Subpolicy,
        } => (&[], name.as_str()),
        // Non-subpolicy args delegate to the standard builder.
        _ => return build_arg_expr(arg, kind, /*owned=*/ false),
    };
    // Find the loop variable for this sub-policy.
    let var = sub_vars
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
        .expect("sub-policy var present");
    // Start with the cloned descriptor template from the loop variable.
    let mut expr = quote!((*#var).clone());
    // Apply wrappers from innermost to outermost.
    for w in wrappers.iter().rev() {
        let wv = id(w);
        expr = quote!(DescriptorTemplate::#wv(alloc::boxed::Box::new(#expr)));
    }
    // The arg is in a Sub position → box it.
    quote!(alloc::boxed::Box::new(#expr))
}

fn emit_tapleaf_to_descriptors(tapleaf: &[ProcessedEntry]) -> TokenStream {
    let arms: Vec<TokenStream> = tapleaf
        .iter()
        .map(|e| {
            let variant = id(&e.name);
            let destructure: TokenStream = if e.fields.order.is_empty() {
                quote!()
            } else {
                let fields: Vec<Ident> = e.fields.order.iter().map(|s| id(s)).collect();
                quote!({ #(#fields),* })
            };

            // For entries with Subpolicy fields, emit a Cartesian product over
            // the descriptor-template sets for each sub-policy.
            let subpolicy_names: Vec<&str> = e
                .fields
                .order
                .iter()
                .filter(|n| e.fields.kinds[*n] == BindingKind::Subpolicy)
                .map(String::as_str)
                .collect();

            let block = if !subpolicy_names.is_empty() {
                emit_subpolicy_construction_block(e, &subpolicy_names)
            } else {
                let b = emit_pattern_construction_block(e, /*owned=*/ false);
                quote!(#b Ok(__out))
            };

            quote! {
                TapleafClass::#variant #destructure => { #block },
            }
        })
        .collect();
    quote! {
        fn tapleaf_to_descriptors(
            leaf: &TapleafClass,
        ) -> Result<alloc::vec::Vec<DescriptorTemplate>, CleartextDecodeError> {
            match leaf {
                #(#arms)*
                TapleafClass::Other(__s) => {
                    let dt = <DescriptorTemplate as core::str::FromStr>::from_str(__s)
                        .map_err(|e| {
                            CleartextDecodeError::InvalidDescriptor(alloc::format!("{:?}", e))
                        })?;
                    Ok(alloc::vec![dt])
                },
            }
        }
    }
}

/// Materialize `__internal_key` for a recursing entry. Taproot has the field
/// `internal_key` directly; TaprootMusig reconstructs it from `(threshold, keys)`.
fn emit_internal_key_local(entry: &ProcessedEntry) -> TokenStream {
    if entry.fields.kinds.contains_key("internal_key") {
        quote!(let __internal_key = internal_key;)
    } else {
        debug_assert!(entry.fields.kinds.contains_key("keys"));
        quote! {
            let __key_indices: alloc::vec::Vec<u32> = keys
                .iter()
                .map(|__k| __k.plain_key_index().expect("plain key"))
                .collect();
            let __num1 = keys.first().map(|__k| __k.num1).unwrap_or(0);
            let __num2 = keys.first().map(|__k| __k.num2).unwrap_or(1);
            let __internal_key = KeyExpression::musig(__key_indices, __num1, __num2);
        }
    }
}

/// Body of a non-recursing arm: build a `__out: Vec<DescriptorTemplate>` with
/// one entry per applicable pattern. `owned` controls whether numeric fields
/// are bound by value (`u32`) or by reference (`&u32`).
fn emit_pattern_construction_block(entry: &ProcessedEntry, owned: bool) -> TokenStream {
    let pushes = entry.patterns.iter().map(|pat| {
        let expr = build_construction_expr(pat, owned);
        if pattern_uses_musig(pat) {
            let t: TokenStream = if owned {
                quote!(threshold)
            } else {
                quote!(*threshold)
            };
            quote! {
                if #t as usize == keys.len() && keys.iter().all(|__k| __k.is_plain()) {
                    __out.push(#expr);
                }
            }
        } else {
            quote!(__out.push(#expr);)
        }
    });
    quote! {
        let mut __out: alloc::vec::Vec<DescriptorTemplate> = alloc::vec::Vec::new();
        #(#pushes)*
    }
}

fn build_construction_expr(pat: &Pattern, owned: bool) -> TokenStream {
    let variant_str = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let variant = id(variant_str);
    let arg_kinds = variant_arg_kinds(variant_str);
    if pat.args.is_empty() {
        return quote!(DescriptorTemplate::#variant);
    }
    let args: Vec<TokenStream> = pat
        .args
        .iter()
        .enumerate()
        .map(|(i, a)| build_arg_expr(a, arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub), owned))
        .collect();
    // A `tr($key)` pattern (no tree arg) reconstructs a leaf-less taproot, whose
    // runtime AST still carries the `Option<TapTree>` field as `None`.
    if variant_str == "Tr" && pat.args.len() == 1 {
        return quote!(DescriptorTemplate::Tr(#(#args),*, None));
    }
    quote!(DescriptorTemplate::#variant(#(#args),*))
}

fn build_arg_expr(arg: &PatternArg, kind: ArgKind, owned: bool) -> TokenStream {
    match arg {
        PatternArg::SubpolicyRef { .. } => {
            panic!("SubpolicyRef must be handled by build_subpolicy_arg_expr, not build_arg_expr")
        }
        PatternArg::Binding { name, kind: bkind } => {
            let n = id(name);
            match kind {
                ArgKind::Key | ArgKind::KeyList => quote!(#n.clone()),
                ArgKind::Num => {
                    if owned {
                        quote!(#n)
                    } else {
                        quote!(*#n)
                    }
                }
                // A `$timelock` Sub-position binding reconstructs to the
                // `older(...)`/`after(...)` node it matched.
                ArgKind::Sub if *bkind == BindingKind::Timelock => {
                    quote!(alloc::boxed::Box::new(#n.to_descriptor()))
                }
                ArgKind::Sub => quote!(#n),
                ArgKind::Tree => quote!(None),
            }
        }
        PatternArg::Musig { keys, .. } => {
            let k = id(keys);
            quote! {
                KeyExpression::musig(
                    #k.iter().map(|__k| __k.plain_key_index().expect("plain key")).collect(),
                    #k.first().map(|__k| __k.num1).unwrap_or(0),
                    #k.first().map(|__k| __k.num2).unwrap_or(1),
                )
            }
        }
        PatternArg::Sub { wrappers, inner } => {
            let mut expr = build_construction_expr(inner, owned);
            for w in wrappers.iter().rev() {
                let wv = id(w);
                expr = quote!(DescriptorTemplate::#wv(alloc::boxed::Box::new(#expr)));
            }
            match kind {
                ArgKind::Sub => quote!(alloc::boxed::Box::new(#expr)),
                _ => expr,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level emit: assemble the file and pretty-print
// ---------------------------------------------------------------------------

/// Render a `TokenStream` to a pretty-printed Rust source string with a leading
/// "do not edit" banner.
///
/// On `syn::parse_file` failure (which indicates a codegen bug, not a spec
/// problem), panic with the syn error *and* a numbered excerpt of the
/// offending source so the maintainer can locate the broken emit site.
fn pretty_file(file: TokenStream) -> String {
    let source = file.to_string();
    let parsed = syn::parse_file(&source).unwrap_or_else(|err| {
        let mut numbered = String::new();
        for (i, line) in source.lines().take(200).enumerate() {
            use std::fmt::Write as _;
            let _ = writeln!(numbered, "{:>4} | {}", i + 1, line);
        }
        panic!(
            "build.rs: generated code failed to parse as Rust.\n\
             This indicates a bug in the build script's codegen, not in the spec.\n\
             syn error: {err}\n\
             --- first 200 lines of generated source ---\n{numbered}"
        )
    });
    let body = prettyplease::unparse(&parsed);
    format!(
        "// AUTO-GENERATED by build.rs from src/cleartext/specs/cleartext.toml. Do not edit.\n\
         // To regenerate: edit the spec and rebuild.\n\n{body}"
    )
}

/// Code that is part of every build: class/pattern enums, spec tables, forward
/// classification, encode-side `cleartext_pattern`, and the score helpers used
/// by `confusion_score`.
fn emit_common(top_level: &[ProcessedEntry], tapleaf: &[ProcessedEntry]) -> String {
    let pat_kind_top = emit_pattern_kind_enum("TopLevelPattern", top_level);
    let pat_kind_tap = emit_pattern_kind_enum("TapleafPattern", tapleaf);
    let class_top = emit_class_enum(TOP_LEVEL, top_level);
    let class_tap = emit_class_enum(TAPLEAF, tapleaf);
    let specs_top = emit_specs_const("TOP_LEVEL_SPECS", TOP_LEVEL, top_level);
    let specs_tap = emit_specs_const("TAPLEAF_SPECS", TAPLEAF, tapleaf);
    let classify_top = emit_classify(top_level, TOP_LEVEL, "classify");
    let classify_tap = emit_classify(tapleaf, TAPLEAF, "classify_as_tapleaf");
    let cleartext_top = emit_cleartext_pattern(top_level, TOP_LEVEL);
    let cleartext_tap = emit_cleartext_pattern(tapleaf, TAPLEAF);
    let tap_helpers = emit_tapleaf_helpers(tapleaf);
    let outer = emit_outer_score(top_level);

    pretty_file(quote! {
        #pat_kind_top
        #pat_kind_tap
        #class_top
        #class_tap
        #specs_top
        #specs_tap

        impl DescriptorTemplate {
            #classify_top
            #classify_tap
        }

        #cleartext_top
        #cleartext_tap
        #tap_helpers
        #outer
    })
}

/// Code only needed when reverse-parsing cleartext (the `cleartext-decode`
/// feature, or `cfg(test)`): `from_cleartext_pattern` for both class enums,
/// plus `top_level_variants` and `tapleaf_to_descriptors`. This file is
/// included from a feature-gated submodule, so no `#[cfg]` attributes are
/// emitted here.
fn emit_decode(top_level: &[ProcessedEntry], tapleaf: &[ProcessedEntry]) -> String {
    let from_top = emit_from_cleartext_pattern(top_level, TOP_LEVEL);
    let from_tap = emit_from_cleartext_pattern(tapleaf, TAPLEAF);
    let top_variants = emit_top_level_variants(top_level);
    let tap_to_desc = emit_tapleaf_to_descriptors(tapleaf);

    pretty_file(quote! {
        #from_top
        #from_tap
        #top_variants
        #tap_to_desc
    })
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let spec_path = PathBuf::from(&manifest_dir).join("src/cleartext/specs/cleartext.toml");
    println!("cargo:rerun-if-changed={}", spec_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let raw = fs::read_to_string(&spec_path)?;
    let spec: Spec = toml::from_str(&raw)?;

    check_entry_names_unique(&spec.top_level, "top_level")?;
    check_entry_names_unique(&spec.tapleaf, "tapleaf")?;

    let top_level = process_entries(&spec.top_level).map_err(|e| format!("top_level: {}", e))?;
    let tapleaf = process_entries(&spec.tapleaf).map_err(|e| format!("tapleaf: {}", e))?;

    check_cleartext_uniqueness(&top_level, "top_level")?;
    check_cleartext_uniqueness(&tapleaf, "tapleaf")?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        out_dir.join("cleartext_generated.rs"),
        emit_common(&top_level, &tapleaf),
    )?;
    fs::write(
        out_dir.join("cleartext_decode_generated.rs"),
        emit_decode(&top_level, &tapleaf),
    )?;
    Ok(())
}
