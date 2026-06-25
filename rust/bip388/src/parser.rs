//! Hand-rolled recursive-descent parser for BIP-388 descriptor *templates*.
//!
//! The parser builds directly into an [`ArenaStore`], returning arena ids, so
//! the *same* parser serves both the `alloc` (`VecArena`) and the future
//! no-alloc (`SliceArena`) backings. No `Box`/`Vec`/`String` is used here.

use crate::arena::{ArenaFull, ArenaStore, KeyExprRec, ListBuilder, Node, NodeId, NodeTag, NONE};
use crate::{
    ParseContext, ParseError, HARDENED_INDEX, MAX_KEYS_MULTI_A, MAX_OLDER_AFTER, MAX_PARSE_DEPTH,
};

/// Return type for all hand-rolled parser functions: (remaining_input, parsed_value)
pub(crate) type ParseResult<'a, T> = Result<(&'a str, T), ParseError>;

#[inline]
fn full(_: ArenaFull) -> ParseError {
    ParseError::ArenaFull
}

/// Decode exactly `N` bytes from a `2*N`-char lowercase/uppercase hex string.
/// Allocation-free replacement for `hex::FromHex` (so the parser needs no `hex`
/// dependency in the minimal build).
fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (nibble(bytes[2 * i])? << 4) | nibble(bytes[2 * i + 1])?;
    }
    Some(out)
}

// ── Pure (allocation-free) scalar helpers ──────────────────────────────────

/// Parses a decimal u32 (no leading zeros unless "0"), value <= max.
pub(crate) fn parse_number_up_to(input: &str, max: u32) -> ParseResult<'_, u32> {
    if input.is_empty() || !input.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ParseError::InvalidSyntax);
    }
    // reject leading zeros on multi-digit numbers
    if input.starts_with('0') && input.len() > 1 && input.as_bytes()[1].is_ascii_digit() {
        return Err(ParseError::NumberOutOfRange);
    }
    let end = input
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(input.len());
    let num: u32 = input[..end]
        .parse()
        .map_err(|_| ParseError::NumberOutOfRange)?;
    if num > max {
        return Err(ParseError::NumberOutOfRange);
    }
    Ok((&input[end..], num))
}

/// Parses a derivation-step number like "44" or "44'".
pub(crate) fn parse_derivation_step_number(input: &str) -> ParseResult<'_, u32> {
    let (rest, num) = parse_number_up_to(input, HARDENED_INDEX - 1)?;
    if rest.starts_with('\'') {
        Ok((&rest[1..], num + HARDENED_INDEX))
    } else {
        Ok((rest, num))
    }
}

/// Parses the derivation suffix: /** or /<num1;num2>/*
pub(crate) fn parse_derivation_suffix(input: &str) -> ParseResult<'_, (u32, u32)> {
    if !input.starts_with('/') {
        return Err(ParseError::InvalidSyntax);
    }
    let rest = &input[1..];

    if rest.starts_with("**") {
        Ok((&rest[2..], (0u32, 1u32)))
    } else if rest.starts_with('<') {
        let rest = &rest[1..];
        let (rest, num1) = parse_derivation_step_number(rest)?;
        if !rest.starts_with(';') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, num2) = parse_derivation_step_number(&rest[1..])?;
        if !rest.starts_with(">/*") {
            return Err(ParseError::InvalidSyntax);
        }
        Ok((&rest[3..], (num1, num2)))
    } else {
        Err(ParseError::InvalidSyntax)
    }
}

// ── Key expressions ────────────────────────────────────────────────────────

/// Parses a key expression `@N/...` or (in taproot context) `musig(@N1,@N2,...)/...`,
/// allocating a [`KeyExprRec`] in the arena and returning its [`crate::arena::KeyId`].
pub(crate) fn parse_key_expression<'a, A: ArenaStore>(
    input: &'a str,
    ctx: ParseContext,
    arena: &mut A,
) -> ParseResult<'a, crate::arena::KeyId> {
    if input.starts_with("musig(") {
        if !ctx.musig_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_musig_key_expression(input, arena);
    }
    if !input.starts_with('@') {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, key_index) = parse_number_up_to(&input[1..], u32::MAX)?;
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;
    let id = arena
        .push_key(KeyExprRec::plain(key_index, num1, num2))
        .map_err(full)?;
    Ok((rest, id))
}

fn musig_previous_members_contains(mut previous: &str, idx: u32) -> Result<bool, ParseError> {
    while !previous.is_empty() {
        if !previous.starts_with('@') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, prev_idx) = parse_number_up_to(&previous[1..], u32::MAX)?;
        if prev_idx == idx {
            return Ok(true);
        }
        if rest.is_empty() {
            return Ok(false);
        }
        if !rest.starts_with(',') {
            return Err(ParseError::InvalidSyntax);
        }
        previous = &rest[1..];
    }
    Ok(false)
}

/// Parses `musig(@N1,@N2,...)/...`. Members are stored as a contiguous span in
/// the `members` pool (no nested allocations interleave during the member loop).
/// Per BIP-388, all participant key indices must be distinct.
fn parse_musig_key_expression<'a, A: ArenaStore>(
    input: &'a str,
    arena: &mut A,
) -> ParseResult<'a, crate::arena::KeyId> {
    let members_input = &input[6..]; // skip "musig("
    let mut rest = members_input;
    let start = arena.members_begin();
    let mut count = 0u32;
    loop {
        if !rest.starts_with('@') {
            return Err(ParseError::InvalidSyntax);
        }
        let (r, idx) = parse_number_up_to(&rest[1..], u32::MAX)?;
        let previous_len = members_input.len() - rest.len();
        if musig_previous_members_contains(&members_input[..previous_len], idx)? {
            return Err(ParseError::InvalidKey);
        }
        arena.members_push(idx).map_err(full)?;
        count += 1;
        rest = r;
        if rest.starts_with(',') {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    if count < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    rest = &rest[1..]; // skip ')'
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;
    let span = arena.members_end(start);
    let id = arena
        .push_key(KeyExprRec::musig(span, num1, num2))
        .map_err(full)?;
    Ok((rest, id))
}

// ── Descriptor fragments ───────────────────────────────────────────────────

/// Entry point: parse a complete descriptor template string.
pub(crate) fn parse_descriptor_template<A: ArenaStore>(
    input: &str,
    arena: &mut A,
) -> Result<NodeId, ParseError> {
    let (rest, root) = parse_descriptor(input, ParseContext::TopLevel, 0, arena)?;
    if rest.is_empty() {
        Ok(root)
    } else {
        Err(ParseError::TrailingInput)
    }
}

/// Parses a descriptor, optionally preceded by a wrapper prefix like "asc:".
pub(crate) fn parse_descriptor<'a, A: ArenaStore>(
    input: &'a str,
    ctx: ParseContext,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;

    // A wrapper prefix is a run of ASCII alphabetic chars followed by ':'.
    let alpha_end = input
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(input.len());
    let (input, wrappers) = if alpha_end > 0 && input.as_bytes().get(alpha_end) == Some(&b':') {
        let wrappers = &input[..alpha_end];
        (&input[alpha_end + 1..], wrappers)
    } else {
        (input, "")
    };

    let (input, inner) = parse_inner_descriptor(input, ctx, depth, arena)?;

    // Apply wrappers in reverse character order (rightmost char = outermost wrapper)
    let mut result = inner;
    for wrapper in wrappers.chars().rev() {
        let tag = match wrapper {
            'a' => NodeTag::A,
            's' => NodeTag::S,
            'c' => NodeTag::C,
            't' => NodeTag::T,
            'd' => NodeTag::D,
            'v' => NodeTag::V,
            'j' => NodeTag::J,
            'n' => NodeTag::N,
            'l' => NodeTag::L,
            'u' => NodeTag::U,
            _ => return Err(ParseError::InvalidSyntax),
        };
        result = arena.push_node(Node::with_a(tag, result.0)).map_err(full)?;
    }
    Ok((input, result))
}

fn parse_inner_descriptor<'a, A: ArenaStore>(
    input: &'a str,
    ctx: ParseContext,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    // Longer names checked before shorter to avoid premature prefix matches.
    if input.starts_with("sortedmulti_a(") {
        return parse_threshold_kp_fragment(
            input,
            "sortedmulti_a",
            NodeTag::SortedmultiA,
            ctx,
            MAX_KEYS_MULTI_A,
            arena,
        );
    }
    if input.starts_with("sortedmulti(") {
        return parse_threshold_kp_fragment(
            input,
            "sortedmulti",
            NodeTag::Sortedmulti,
            ctx,
            crate::MAX_KEYS_MULTI,
            arena,
        );
    }
    if input.starts_with("multi_a(") {
        return parse_threshold_kp_fragment(
            input,
            "multi_a",
            NodeTag::MultiA,
            ctx,
            MAX_KEYS_MULTI_A,
            arena,
        );
    }
    if input.starts_with("multi(") {
        return parse_threshold_kp_fragment(
            input,
            "multi",
            NodeTag::Multi,
            ctx,
            crate::MAX_KEYS_MULTI,
            arena,
        );
    }
    if input.starts_with("thresh(") {
        return parse_thresh(input, ctx, depth, arena);
    }
    if input.starts_with("wsh(") {
        if !ctx.wsh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let inner_ctx = match ctx {
            ParseContext::TopLevel => ParseContext::Segwit,
            ParseContext::Legacy => ParseContext::WrappedSegwit,
            _ => return Err(ParseError::InvalidScriptContext),
        };
        let (rest, [script]) = parse_n_subscripts::<1, A>(&input[4..], inner_ctx, depth, arena)?;
        let id = arena
            .push_node(Node::with_a(NodeTag::Wsh, script.0))
            .map_err(full)?;
        return Ok((rest, id));
    }
    if input.starts_with("sh(") {
        if !ctx.sh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let (rest, [script]) =
            parse_n_subscripts::<1, A>(&input[3..], ParseContext::Legacy, depth, arena)?;
        let id = arena
            .push_node(Node::with_a(NodeTag::Sh, script.0))
            .map_err(full)?;
        return Ok((rest, id));
    }
    if input.starts_with("wpkh(") {
        if !ctx.wpkh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_kp_fragment(input, "wpkh", NodeTag::Wpkh, ctx, arena);
    }
    if input.starts_with("pkh(") {
        return parse_kp_fragment(input, "pkh", NodeTag::Pkh, ctx, arena);
    }
    if input.starts_with("tr(") {
        if !ctx.tr_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_tr(input, depth, arena);
    }
    if input.starts_with("pk_k(") {
        return parse_kp_fragment(input, "pk_k", NodeTag::PkK, ctx, arena);
    }
    if input.starts_with("pk_h(") {
        return parse_kp_fragment(input, "pk_h", NodeTag::PkH, ctx, arena);
    }
    if input.starts_with("pk(") {
        return parse_kp_fragment(input, "pk", NodeTag::Pk, ctx, arena);
    }
    if input.starts_with("older(") {
        return parse_num_fragment(input, "older", MAX_OLDER_AFTER, NodeTag::Older, arena);
    }
    if input.starts_with("after(") {
        return parse_num_fragment(input, "after", MAX_OLDER_AFTER, NodeTag::After, arena);
    }
    if input.starts_with("sha256(") {
        return parse_hex32_fragment(input, "sha256", NodeTag::Sha256, arena);
    }
    if input.starts_with("hash256(") {
        return parse_hex32_fragment(input, "hash256", NodeTag::Hash256, arena);
    }
    if input.starts_with("ripemd160(") {
        return parse_hex20_fragment(input, "ripemd160", NodeTag::Ripemd160, arena);
    }
    if input.starts_with("hash160(") {
        return parse_hex20_fragment(input, "hash160", NodeTag::Hash160, arena);
    }
    if input.starts_with("andor(") {
        let (rest, [x, y, z]) = parse_n_subscripts::<3, A>(&input[6..], ctx, depth, arena)?;
        let mut node = Node::new(NodeTag::Andor);
        node.a = x.0;
        node.b = y.0;
        node.c = z.0;
        let id = arena.push_node(node).map_err(full)?;
        return Ok((rest, id));
    }
    if input.starts_with("and_b(") {
        return parse_binary(&input[6..], NodeTag::AndB, ctx, depth, arena);
    }
    if input.starts_with("and_v(") {
        return parse_binary(&input[6..], NodeTag::AndV, ctx, depth, arena);
    }
    if input.starts_with("and_n(") {
        return parse_binary(&input[6..], NodeTag::AndN, ctx, depth, arena);
    }
    if input.starts_with("or_b(") {
        return parse_binary(&input[5..], NodeTag::OrB, ctx, depth, arena);
    }
    if input.starts_with("or_c(") {
        return parse_binary(&input[5..], NodeTag::OrC, ctx, depth, arena);
    }
    if input.starts_with("or_d(") {
        return parse_binary(&input[5..], NodeTag::OrD, ctx, depth, arena);
    }
    if input.starts_with("or_i(") {
        return parse_binary(&input[5..], NodeTag::OrI, ctx, depth, arena);
    }
    // Simple terminals: bare "0" and "1"
    if input.starts_with('0') {
        let id = arena.push_node(Node::new(NodeTag::Zero)).map_err(full)?;
        return Ok((&input[1..], id));
    }
    if input.starts_with('1') {
        let id = arena.push_node(Node::new(NodeTag::One)).map_err(full)?;
        return Ok((&input[1..], id));
    }
    Err(ParseError::UnrecognizedFragment)
}

/// Parses two comma-separated sub-scripts (the opening `(` already consumed by
/// the caller) and builds a binary combinator node `(a, b)`.
fn parse_binary<'a, A: ArenaStore>(
    input: &'a str,
    tag: NodeTag,
    ctx: ParseContext,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let (rest, [x, y]) = parse_n_subscripts::<2, A>(input, ctx, depth, arena)?;
    let mut node = Node::new(tag);
    node.a = x.0;
    node.b = y.0;
    let id = arena.push_node(node).map_err(full)?;
    Ok((rest, id))
}

/// Parses a named fragment that wraps a single key expression: name(@...)
fn parse_kp_fragment<'a, A: ArenaStore>(
    input: &'a str,
    name: &str,
    tag: NodeTag,
    ctx: ParseContext,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, kp) = parse_key_expression(&rest[1..], ctx, arena)?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let id = arena.push_node(Node::with_a(tag, kp.0)).map_err(full)?;
    Ok((&rest[1..], id))
}

/// Parses "name(n)" where n is a number <= max.
fn parse_num_fragment<'a, A: ArenaStore>(
    input: &'a str,
    name: &str,
    max: u32,
    tag: NodeTag,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, num) = parse_number_up_to(&rest[1..], max)?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let id = arena.push_node(Node::with_a(tag, num)).map_err(full)?;
    Ok((&rest[1..], id))
}

/// Parses "name(<40 hex chars>)".
fn parse_hex20_fragment<'a, A: ArenaStore>(
    input: &'a str,
    name: &str,
    tag: NodeTag,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 40 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = decode_hex::<20>(&rest[..40]).ok_or(ParseError::InvalidHex)?;
    let rest = &rest[40..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let span = arena.push_bytes(&bytes).map_err(full)?;
    let id = arena.push_node(hash_node(tag, span)).map_err(full)?;
    Ok((&rest[1..], id))
}

/// Parses "name(<64 hex chars>)".
fn parse_hex32_fragment<'a, A: ArenaStore>(
    input: &'a str,
    name: &str,
    tag: NodeTag,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 64 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = decode_hex::<32>(&rest[..64]).ok_or(ParseError::InvalidHex)?;
    let rest = &rest[64..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let span = arena.push_bytes(&bytes).map_err(full)?;
    let id = arena.push_node(hash_node(tag, span)).map_err(full)?;
    Ok((&rest[1..], id))
}

fn hash_node(tag: NodeTag, span: crate::arena::Span) -> Node {
    let mut node = Node::new(tag);
    node.a = span.start;
    node.b = span.len;
    node
}

/// Parses "name(threshold,<key1>,<key2>,...)", building a `Multi*` node whose
/// key list is an in-order cons list of [`crate::arena::KeyId`]s.
pub(crate) fn parse_threshold_kp_fragment<'a, A: ArenaStore>(
    input: &'a str,
    name: &str,
    tag: NodeTag,
    ctx: ParseContext,
    max_keys: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    let (mut rest, threshold) = parse_number_up_to(rest, u32::MAX)?;
    let mut list = ListBuilder::new();
    let mut n_keys = 0usize;
    loop {
        if !rest.starts_with(',') {
            break;
        }
        if n_keys >= max_keys {
            return Err(ParseError::TooManyKeys);
        }
        match parse_key_expression(&rest[1..], ctx, arena) {
            Ok((r, kp)) => {
                list.push(arena, kp.0).map_err(full)?;
                n_keys += 1;
                rest = r;
            }
            Err(ParseError::InvalidScriptContext) => return Err(ParseError::InvalidScriptContext),
            Err(_) => break,
        }
    }
    if n_keys < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if threshold == 0 || (threshold as usize) > n_keys {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let mut node = Node::new(tag);
    node.a = threshold;
    node.b = list.head();
    node.c = list.count();
    let id = arena.push_node(node).map_err(full)?;
    Ok((&rest[1..], id))
}

/// Parses exactly `N` comma-separated sub-descriptors followed by ')'.
pub(crate) fn parse_n_subscripts<'a, const N: usize, A: ArenaStore>(
    input: &'a str,
    ctx: ParseContext,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, [NodeId; N]> {
    let mut rest = input;
    let mut ids = [NodeId(0); N];
    for (i, slot) in ids.iter_mut().enumerate() {
        let (r, id) = parse_descriptor(rest, ctx, depth, arena)?;
        *slot = id;
        rest = r;
        if i + 1 < N {
            if !rest.starts_with(',') {
                return Err(ParseError::InvalidSyntax);
            }
            rest = &rest[1..];
        }
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], ids))
}

pub(crate) fn parse_thresh<'a, A: ArenaStore>(
    input: &'a str,
    ctx: ParseContext,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    // input starts with "thresh("
    let (rest, k) = parse_number_up_to(&input[7..], u32::MAX)?;
    if !rest.starts_with(',') {
        return Err(ParseError::InvalidSyntax);
    }
    // parse first script (mandatory)
    let (rest, first) = parse_descriptor(&rest[1..], ctx, depth, arena)?;
    let mut list = ListBuilder::new();
    list.push(arena, first.0).map_err(full)?;
    let mut count = 1usize;
    let mut rest = rest;
    loop {
        if !rest.starts_with(',') {
            break;
        }
        match parse_descriptor(&rest[1..], ctx, depth, arena) {
            Ok((r, desc)) => {
                list.push(arena, desc.0).map_err(full)?;
                count += 1;
                rest = r;
            }
            Err(ParseError::NestingTooDeep) => return Err(ParseError::NestingTooDeep),
            Err(_) => break,
        }
    }
    if k == 0 {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if (k as usize) > count {
        return Err(ParseError::ThreshExceedsScripts);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let mut node = Node::new(NodeTag::Thresh);
    node.a = k;
    node.b = list.head();
    node.c = list.count();
    let id = arena.push_node(node).map_err(full)?;
    Ok((&rest[1..], id))
}

pub(crate) fn parse_tr<'a, A: ArenaStore>(
    input: &'a str,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    // input starts with "tr("
    let (rest, key) = parse_key_expression(&input[3..], ParseContext::Taproot, arena)?;
    let (rest, tree) = if rest.starts_with(',') {
        let (rest, t) = parse_tap_tree(&rest[1..], depth, arena)?;
        (rest, t.0)
    } else {
        (rest, NONE)
    };
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let mut node = Node::new(NodeTag::Tr);
    node.a = key.0;
    node.d = tree;
    let id = arena.push_node(node).map_err(full)?;
    Ok((&rest[1..], id))
}

fn parse_tap_tree<'a, A: ArenaStore>(
    input: &'a str,
    depth: usize,
    arena: &mut A,
) -> ParseResult<'a, NodeId> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;
    if input.starts_with('{') {
        let (rest, left) = parse_tap_tree(&input[1..], depth, arena)?;
        if !rest.starts_with(',') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, right) = parse_tap_tree(&rest[1..], depth, arena)?;
        if !rest.starts_with('}') {
            return Err(ParseError::InvalidSyntax);
        }
        let mut node = Node::new(NodeTag::TapBranch);
        node.a = left.0;
        node.b = right.0;
        let id = arena.push_node(node).map_err(full)?;
        Ok((&rest[1..], id))
    } else {
        let (rest, desc) = parse_descriptor(input, ParseContext::Taproot, depth, arena)?;
        let id = arena
            .push_node(Node::with_a(NodeTag::TapLeaf, desc.0))
            .map_err(full)?;
        Ok((rest, id))
    }
}
