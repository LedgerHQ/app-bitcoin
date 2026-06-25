//! Arena / index-based storage for BIP-388 descriptor templates.
//!
//! The descriptor AST is stored in a small set of flat, pointer-free pools and
//! addressed by `u32` ids. This lets the *same* parser, classifier and renderer
//! run against two backings:
//!
//! * [`VecArena`] — growable `Vec`-backed pools, used by the default `alloc`
//!   build (behaves like the historical `Box`/`Vec` AST, but flat).
//! * a future `SliceArena` — bump cursors over a caller-provided `&mut [u8]`,
//!   used by the no-alloc / C build (no global allocator, no `Vec`/`Box`).
//!
//! All node records are fixed-size and `Copy`, and all cross-references are
//! `u32` indices, so the layout is portable and there is no recursion through
//! owned pointers.
//!
//! Computation is written once against borrowed [`Cursor`]s (see [`Cursor::view`]
//! / [`DescriptorNode`]), so it is backing-agnostic.
//!
//! NOTE: this module is wired into the rest of the crate incrementally across
//! the migration phases; until then several items are intentionally unused.
#![allow(dead_code, unused_imports)]

use core::cmp::Ordering;
use core::fmt;

/// Sentinel for "no node" / "no link" in a `u32` reference.
pub const NONE: u32 = u32::MAX;

/// Maximum tap-tree / traversal depth (mirrors `MAX_PARSE_DEPTH` in `lib.rs`).
pub const MAX_TREE_DEPTH: usize = 64;

/// Index into the arena's `nodes` pool (descriptor *and* tap-tree nodes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NodeId(pub u32);

/// Index into the arena's `keys` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct KeyId(pub u32);

/// A contiguous `[start, start+len)` span into a typed pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub start: u32,
    pub len: u32,
}

impl Span {
    pub const EMPTY: Span = Span { start: 0, len: 0 };
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Discriminant for a [`Node`]. `repr(u8)` keeps the record compact and stable.
///
/// Covers every `DescriptorTemplate` variant plus the two tap-tree node kinds
/// (`TapLeaf` / `TapBranch`), which share the `nodes` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NodeTag {
    // top-level / script-context wrappers around a single child (a = child NodeId)
    Sh,
    Wsh,
    // single-letter miniscript wrappers (a = child NodeId)
    A,
    S,
    C,
    T,
    D,
    V,
    J,
    N,
    L,
    U,
    // key fragments (a = KeyId)
    Pkh,
    Wpkh,
    Pk,
    PkK,
    PkH,
    // taproot top level (a = KeyId, d = tap-tree root NodeId | NONE)
    Tr,
    // constants
    Zero,
    One,
    // numeric locktimes (a = value)
    Older,
    After,
    // hash fragments ((a,b) = bytes Span; len 32)
    Sha256,
    Hash256,
    // hash fragments ((a,b) = bytes Span; len 20)
    Ripemd160,
    Hash160,
    // combinators (a,b,c = child NodeIds)
    Andor,
    AndV,
    AndB,
    AndN,
    OrB,
    OrC,
    OrD,
    OrI,
    // threshold over sub-scripts (a = k, b = head link, c = child count)
    Thresh,
    // multisig over keys (a = k, b = head link, c = key count)
    Multi,
    MultiA,
    Sortedmulti,
    SortedmultiA,
    // tap-tree nodes
    TapLeaf,   // a = script NodeId
    TapBranch, // a = left NodeId, b = right NodeId
}

/// A fixed-size, `Copy` descriptor or tap-tree node. Fields `a..d` are
/// interpreted per [`NodeTag`] (see the tag docs above).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Node {
    pub tag: NodeTag,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

impl Node {
    pub fn new(tag: NodeTag) -> Node {
        Node {
            tag,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        }
    }
    pub fn with_a(tag: NodeTag, a: u32) -> Node {
        Node {
            tag,
            a,
            b: 0,
            c: 0,
            d: 0,
        }
    }
}

/// Plain vs. musig key expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyKind {
    Plain = 0,
    Musig = 1,
}

/// A `Copy`, pointer-free key expression. For a plain key, `plain_index` is the
/// key-information index and `musig_members` is empty; for a musig key,
/// `musig_members` is a span of member indices in the `members` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyExprRec {
    pub num1: u32,
    pub num2: u32,
    pub kind: KeyKind,
    pub plain_index: u32,
    pub musig_members: Span,
}

impl KeyExprRec {
    pub fn plain(plain_index: u32, num1: u32, num2: u32) -> KeyExprRec {
        KeyExprRec {
            num1,
            num2,
            kind: KeyKind::Plain,
            plain_index,
            musig_members: Span::EMPTY,
        }
    }
    pub fn musig(musig_members: Span, num1: u32, num2: u32) -> KeyExprRec {
        KeyExprRec {
            num1,
            num2,
            kind: KeyKind::Musig,
            plain_index: 0,
            musig_members,
        }
    }
}

/// A cons cell for the singly-linked lists used by `Thresh` (NodeIds) and
/// `Multi*` (KeyIds). Cons cells make list building robust against the
/// allocation interleaving that happens while parsing nested sub-fragments
/// (e.g. a musig key inside a `multi_a`, or a `thresh` inside a `thresh`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link {
    pub val: u32,
    pub next: u32,
}

/// Returned by allocation methods when a fixed-capacity backing is exhausted
/// (or when a `u32` id space would overflow).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArenaFull;

// ---------------------------------------------------------------------------
// Read / build abstractions
// ---------------------------------------------------------------------------

/// Read-only view of an arena. [`Cursor`]s are generic over this so traversal
/// code is written once for every backing.
pub trait ArenaRead {
    fn node(&self, id: NodeId) -> Node;
    fn key(&self, id: KeyId) -> KeyExprRec;
    fn link(&self, idx: u32) -> Link;
    fn members(&self, span: Span) -> &[u32];
    fn bytes(&self, span: Span) -> &[u8];
}

/// Append-only builder API shared by all backings, so the parser is generic
/// over it. Every method is fallible: `VecArena` only fails on `u32` overflow,
/// while a fixed-capacity backing fails when exhausted.
pub trait ArenaStore: ArenaRead {
    fn push_node(&mut self, node: Node) -> Result<NodeId, ArenaFull>;
    fn push_key(&mut self, key: KeyExprRec) -> Result<KeyId, ArenaFull>;
    fn push_link(&mut self, link: Link) -> Result<u32, ArenaFull>;
    /// Patch the `next` field of a previously pushed link (for in-order lists).
    fn set_link_next(&mut self, idx: u32, next: u32);

    /// Begin a contiguous span in the `members` pool. Returns the start index.
    fn members_begin(&self) -> u32;
    /// Append one value to the `members` pool (must not interleave with other
    /// `members` pushes — see the musig parsing path).
    fn members_push(&mut self, value: u32) -> Result<(), ArenaFull>;
    /// Finish a span started at `start` (the current `members` length is the end).
    fn members_end(&self, start: u32) -> Span;

    /// Append a byte run (hash fragment) and return its span.
    fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull>;

    /// Mutate a stored key's derivation indices in place (used by the decode
    /// path's canonicalization, addressed by id with no aliasing).
    fn set_key_derivation(&mut self, id: KeyId, num1: u32, num2: u32);
}

/// In-order cons-list builder. Holds the head and tail link indices and the
/// element count, so finished lists keep parse order with `O(1)` appends.
#[derive(Clone, Copy, Debug)]
pub struct ListBuilder {
    head: u32,
    tail: u32,
    count: u32,
}

impl ListBuilder {
    pub fn new() -> ListBuilder {
        ListBuilder {
            head: NONE,
            tail: NONE,
            count: 0,
        }
    }

    /// Append `val` (a NodeId or KeyId) to the list.
    pub fn push<A: ArenaStore>(&mut self, store: &mut A, val: u32) -> Result<(), ArenaFull> {
        let idx = store.push_link(Link { val, next: NONE })?;
        if self.head == NONE {
            self.head = idx;
        } else {
            store.set_link_next(self.tail, idx);
        }
        self.tail = idx;
        self.count += 1;
        Ok(())
    }

    pub fn head(&self) -> u32 {
        self.head
    }
    pub fn count(&self) -> u32 {
        self.count
    }
}

impl Default for ListBuilder {
    fn default() -> Self {
        ListBuilder::new()
    }
}

// ---------------------------------------------------------------------------
// VecArena (alloc-backed)
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
pub use vec_arena::VecArena;

#[cfg(feature = "alloc")]
mod vec_arena {
    use super::*;
    use alloc::vec::Vec;

    /// Growable, `Vec`-backed arena. Allocation only fails on `u32` overflow.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct VecArena {
        nodes: Vec<Node>,
        keys: Vec<KeyExprRec>,
        links: Vec<Link>,
        members: Vec<u32>,
        bytes: Vec<u8>,
    }

    impl VecArena {
        pub fn new() -> VecArena {
            VecArena::default()
        }

        pub fn node_count(&self) -> usize {
            self.nodes.len()
        }
    }

    impl ArenaRead for VecArena {
        fn node(&self, id: NodeId) -> Node {
            self.nodes[id.0 as usize]
        }
        fn key(&self, id: KeyId) -> KeyExprRec {
            self.keys[id.0 as usize]
        }
        fn link(&self, idx: u32) -> Link {
            self.links[idx as usize]
        }
        fn members(&self, span: Span) -> &[u32] {
            &self.members[span.start as usize..(span.start + span.len) as usize]
        }
        fn bytes(&self, span: Span) -> &[u8] {
            &self.bytes[span.start as usize..(span.start + span.len) as usize]
        }
    }

    impl ArenaStore for VecArena {
        fn push_node(&mut self, node: Node) -> Result<NodeId, ArenaFull> {
            let id = u32::try_from(self.nodes.len()).map_err(|_| ArenaFull)?;
            self.nodes.push(node);
            Ok(NodeId(id))
        }
        fn push_key(&mut self, key: KeyExprRec) -> Result<KeyId, ArenaFull> {
            let id = u32::try_from(self.keys.len()).map_err(|_| ArenaFull)?;
            self.keys.push(key);
            Ok(KeyId(id))
        }
        fn push_link(&mut self, link: Link) -> Result<u32, ArenaFull> {
            let idx = u32::try_from(self.links.len()).map_err(|_| ArenaFull)?;
            self.links.push(link);
            Ok(idx)
        }
        fn set_link_next(&mut self, idx: u32, next: u32) {
            self.links[idx as usize].next = next;
        }
        fn members_begin(&self) -> u32 {
            self.members.len() as u32
        }
        fn members_push(&mut self, value: u32) -> Result<(), ArenaFull> {
            if self.members.len() >= u32::MAX as usize {
                return Err(ArenaFull);
            }
            self.members.push(value);
            Ok(())
        }
        fn members_end(&self, start: u32) -> Span {
            Span {
                start,
                len: self.members.len() as u32 - start,
            }
        }
        fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull> {
            let start = u32::try_from(self.bytes.len()).map_err(|_| ArenaFull)?;
            let len = u32::try_from(bytes.len()).map_err(|_| ArenaFull)?;
            self.bytes.extend_from_slice(bytes);
            Ok(Span { start, len })
        }
        fn set_key_derivation(&mut self, id: KeyId, num1: u32, num2: u32) {
            let k = &mut self.keys[id.0 as usize];
            k.num1 = num1;
            k.num2 = num2;
        }
    }
}

// ---------------------------------------------------------------------------
// SliceArena (no-alloc, caller-provided slices)
// ---------------------------------------------------------------------------

/// Arena backed by caller-provided slices (one per pool), with bump cursors.
/// No allocation; `push_*` returns [`ArenaFull`] when a pool is exhausted. This
/// is the backing used by the no-alloc / C build.
pub struct SliceArena<'a> {
    nodes: &'a mut [Node],
    n_nodes: usize,
    keys: &'a mut [KeyExprRec],
    n_keys: usize,
    links: &'a mut [Link],
    n_links: usize,
    members: &'a mut [u32],
    n_members: usize,
    bytes: &'a mut [u8],
    n_bytes: usize,
}

impl<'a> SliceArena<'a> {
    pub fn new(
        nodes: &'a mut [Node],
        keys: &'a mut [KeyExprRec],
        links: &'a mut [Link],
        members: &'a mut [u32],
        bytes: &'a mut [u8],
    ) -> Self {
        SliceArena {
            nodes,
            n_nodes: 0,
            keys,
            n_keys: 0,
            links,
            n_links: 0,
            members,
            n_members: 0,
            bytes,
            n_bytes: 0,
        }
    }
}

impl<'a> ArenaRead for SliceArena<'a> {
    fn node(&self, id: NodeId) -> Node {
        self.nodes[id.0 as usize]
    }
    fn key(&self, id: KeyId) -> KeyExprRec {
        self.keys[id.0 as usize]
    }
    fn link(&self, idx: u32) -> Link {
        self.links[idx as usize]
    }
    fn members(&self, span: Span) -> &[u32] {
        &self.members[span.start as usize..(span.start + span.len) as usize]
    }
    fn bytes(&self, span: Span) -> &[u8] {
        &self.bytes[span.start as usize..(span.start + span.len) as usize]
    }
}

impl<'a> ArenaStore for SliceArena<'a> {
    fn push_node(&mut self, node: Node) -> Result<NodeId, ArenaFull> {
        if self.n_nodes >= self.nodes.len() {
            return Err(ArenaFull);
        }
        self.nodes[self.n_nodes] = node;
        self.n_nodes += 1;
        Ok(NodeId((self.n_nodes - 1) as u32))
    }
    fn push_key(&mut self, key: KeyExprRec) -> Result<KeyId, ArenaFull> {
        if self.n_keys >= self.keys.len() {
            return Err(ArenaFull);
        }
        self.keys[self.n_keys] = key;
        self.n_keys += 1;
        Ok(KeyId((self.n_keys - 1) as u32))
    }
    fn push_link(&mut self, link: Link) -> Result<u32, ArenaFull> {
        if self.n_links >= self.links.len() {
            return Err(ArenaFull);
        }
        self.links[self.n_links] = link;
        self.n_links += 1;
        Ok((self.n_links - 1) as u32)
    }
    fn set_link_next(&mut self, idx: u32, next: u32) {
        self.links[idx as usize].next = next;
    }
    fn members_begin(&self) -> u32 {
        self.n_members as u32
    }
    fn members_push(&mut self, value: u32) -> Result<(), ArenaFull> {
        if self.n_members >= self.members.len() {
            return Err(ArenaFull);
        }
        self.members[self.n_members] = value;
        self.n_members += 1;
        Ok(())
    }
    fn members_end(&self, start: u32) -> Span {
        Span {
            start,
            len: self.n_members as u32 - start,
        }
    }
    fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull> {
        let start = self.n_bytes;
        if start + bytes.len() > self.bytes.len() {
            return Err(ArenaFull);
        }
        self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        self.n_bytes += bytes.len();
        Ok(Span {
            start: start as u32,
            len: bytes.len() as u32,
        })
    }
    fn set_key_derivation(&mut self, id: KeyId, num1: u32, num2: u32) {
        let k = &mut self.keys[id.0 as usize];
        k.num1 = num1;
        k.num2 = num2;
    }
}

// ---------------------------------------------------------------------------
// Cursors / views (backing-agnostic traversal)
// ---------------------------------------------------------------------------

/// A borrowed reference to a descriptor node within an arena.
pub struct Cursor<'a, A: ArenaRead> {
    arena: &'a A,
    id: NodeId,
}

// Manual Clone/Copy so the cursor types stay `Copy` regardless of whether the
// backing arena `A` is `Copy` (it holds only a shared reference to `A`).
impl<'a, A: ArenaRead> Clone for Cursor<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for Cursor<'a, A> {}

impl<'a, A: ArenaRead> Cursor<'a, A> {
    pub fn new(arena: &'a A, id: NodeId) -> Self {
        Cursor { arena, id }
    }
    pub fn arena(&self) -> &'a A {
        self.arena
    }
    pub fn id(&self) -> NodeId {
        self.id
    }
    pub fn tag(&self) -> NodeTag {
        self.arena.node(self.id).tag
    }
    fn raw(&self) -> Node {
        self.arena.node(self.id)
    }
    fn child(&self, slot_field: u32) -> Cursor<'a, A> {
        Cursor::new(self.arena, NodeId(slot_field))
    }
    fn key_at(&self, id: u32) -> KeyView<'a, A> {
        KeyView {
            arena: self.arena,
            rec: self.arena.key(KeyId(id)),
        }
    }

    /// Resolve this node to a borrowed, matchable view.
    pub fn view(&self) -> DescriptorNode<'a, A> {
        let n = self.raw();
        use NodeTag::*;
        match n.tag {
            Sh => DescriptorNode::Sh(self.child(n.a)),
            Wsh => DescriptorNode::Wsh(self.child(n.a)),
            A => DescriptorNode::A(self.child(n.a)),
            S => DescriptorNode::S(self.child(n.a)),
            C => DescriptorNode::C(self.child(n.a)),
            T => DescriptorNode::T(self.child(n.a)),
            D => DescriptorNode::D(self.child(n.a)),
            V => DescriptorNode::V(self.child(n.a)),
            J => DescriptorNode::J(self.child(n.a)),
            N => DescriptorNode::N(self.child(n.a)),
            L => DescriptorNode::L(self.child(n.a)),
            U => DescriptorNode::U(self.child(n.a)),
            Pkh => DescriptorNode::Pkh(self.key_at(n.a)),
            Wpkh => DescriptorNode::Wpkh(self.key_at(n.a)),
            Pk => DescriptorNode::Pk(self.key_at(n.a)),
            PkK => DescriptorNode::PkK(self.key_at(n.a)),
            PkH => DescriptorNode::PkH(self.key_at(n.a)),
            Tr => {
                let tree = if n.d == NONE {
                    None
                } else {
                    Some(TapCursor::new(self.arena, NodeId(n.d)))
                };
                DescriptorNode::Tr(self.key_at(n.a), tree)
            }
            Zero => DescriptorNode::Zero,
            One => DescriptorNode::One,
            Older => DescriptorNode::Older(n.a),
            After => DescriptorNode::After(n.a),
            Sha256 => DescriptorNode::Sha256(self.arena.bytes(Span {
                start: n.a,
                len: n.b,
            })),
            Hash256 => DescriptorNode::Hash256(self.arena.bytes(Span {
                start: n.a,
                len: n.b,
            })),
            Ripemd160 => DescriptorNode::Ripemd160(self.arena.bytes(Span {
                start: n.a,
                len: n.b,
            })),
            Hash160 => DescriptorNode::Hash160(self.arena.bytes(Span {
                start: n.a,
                len: n.b,
            })),
            Andor => DescriptorNode::Andor(self.child(n.a), self.child(n.b), self.child(n.c)),
            AndV => DescriptorNode::AndV(self.child(n.a), self.child(n.b)),
            AndB => DescriptorNode::AndB(self.child(n.a), self.child(n.b)),
            AndN => DescriptorNode::AndN(self.child(n.a), self.child(n.b)),
            OrB => DescriptorNode::OrB(self.child(n.a), self.child(n.b)),
            OrC => DescriptorNode::OrC(self.child(n.a), self.child(n.b)),
            OrD => DescriptorNode::OrD(self.child(n.a), self.child(n.b)),
            OrI => DescriptorNode::OrI(self.child(n.a), self.child(n.b)),
            Thresh => DescriptorNode::Thresh(
                n.a,
                NodeList {
                    arena: self.arena,
                    cur: n.b,
                    count: n.c,
                },
            ),
            Multi => DescriptorNode::Multi(n.a, self.key_list(n.b, n.c)),
            MultiA => DescriptorNode::MultiA(n.a, self.key_list(n.b, n.c)),
            Sortedmulti => DescriptorNode::Sortedmulti(n.a, self.key_list(n.b, n.c)),
            SortedmultiA => DescriptorNode::SortedmultiA(n.a, self.key_list(n.b, n.c)),
            TapLeaf | TapBranch => DescriptorNode::TapNode(TapCursor::new(self.arena, self.id)),
        }
    }

    fn key_list(&self, head: u32, count: u32) -> KeyListView<'a, A> {
        KeyListView {
            arena: self.arena,
            head,
            count,
        }
    }
}

impl NodeTag {
    /// Whether this is a single-letter miniscript wrapper (`a:`…`u:`).
    pub fn is_wrapper(self) -> bool {
        use NodeTag::*;
        matches!(self, A | S | C | T | D | U | V | J | N | L)
    }

    /// The wrapper character for a wrapper tag, else `None`.
    pub fn wrapper_char(self) -> Option<char> {
        use NodeTag::*;
        Some(match self {
            A => 'a',
            S => 's',
            C => 'c',
            T => 't',
            D => 'd',
            V => 'v',
            J => 'j',
            N => 'n',
            L => 'l',
            U => 'u',
            _ => return None,
        })
    }
}

/// Writes `bytes` as lowercase hex into `w` (allocation-free; mirrors
/// `hex::encode` used by the owned `Display`).
fn write_hex(w: &mut dyn fmt::Write, bytes: &[u8]) -> fmt::Result {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        w.write_char(DIGITS[(byte >> 4) as usize] as char)?;
        w.write_char(DIGITS[(byte & 0x0f) as usize] as char)?;
    }
    Ok(())
}

/// Writes a key expression in descriptor-template syntax (mirrors the owned
/// `KeyExpression` `Display`): `@i/**`, `@i/<a;b>/*`, or `musig(@i,@j,…)/…`.
fn write_key<A: ArenaRead>(w: &mut dyn fmt::Write, kv: KeyView<'_, A>) -> fmt::Result {
    let (num1, num2) = (kv.num1(), kv.num2());
    if let Some(idx) = kv.plain_key_index() {
        if num1 == 0 && num2 == 1 {
            write!(w, "@{}/**", idx)
        } else {
            write!(w, "@{}/<{};{}>/*", idx, num1, num2)
        }
    } else {
        let members = kv.musig_key_indices().expect("musig key");
        w.write_str("musig(")?;
        for (i, idx) in members.iter().enumerate() {
            if i > 0 {
                w.write_char(',')?;
            }
            write!(w, "@{}", idx)?;
        }
        if num1 == 0 && num2 == 1 {
            write!(w, ")/**")
        } else {
            write!(w, ")/<{};{}>/*", num1, num2)
        }
    }
}

impl<'a, A: ArenaRead> Cursor<'a, A> {
    /// Renders this node as a descriptor-template string into `w`, byte-for-byte
    /// identical to the owned `DescriptorTemplate` `Display`.
    pub fn write_template(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        use DescriptorNode as DN;
        match self.view() {
            DN::Sh(c) => bracket(w, "sh(", c),
            DN::Wsh(c) => bracket(w, "wsh(", c),
            DN::Pkh(kv) => kp(w, "pkh(", kv),
            DN::Wpkh(kv) => kp(w, "wpkh(", kv),
            DN::Pk(kv) => kp(w, "pk(", kv),
            DN::PkK(kv) => kp(w, "pk_k(", kv),
            DN::PkH(kv) => kp(w, "pk_h(", kv),
            DN::Sortedmulti(k, keys) => multi(w, "sortedmulti(", k, keys),
            DN::SortedmultiA(k, keys) => multi(w, "sortedmulti_a(", k, keys),
            DN::Multi(k, keys) => multi(w, "multi(", k, keys),
            DN::MultiA(k, keys) => multi(w, "multi_a(", k, keys),
            DN::Tr(kv, None) => {
                w.write_str("tr(")?;
                write_key(w, kv)?;
                w.write_char(')')
            }
            DN::Tr(kv, Some(tree)) => {
                w.write_str("tr(")?;
                write_key(w, kv)?;
                w.write_char(',')?;
                tree.write_template(w)?;
                w.write_char(')')
            }
            DN::Zero => w.write_char('0'),
            DN::One => w.write_char('1'),
            DN::Older(n) => write!(w, "older({})", n),
            DN::After(n) => write!(w, "after({})", n),
            DN::Sha256(b) => hash(w, "sha256(", b),
            DN::Hash256(b) => hash(w, "hash256(", b),
            DN::Ripemd160(b) => hash(w, "ripemd160(", b),
            DN::Hash160(b) => hash(w, "hash160(", b),
            DN::Andor(x, y, z) => {
                w.write_str("andor(")?;
                x.write_template(w)?;
                w.write_char(',')?;
                y.write_template(w)?;
                w.write_char(',')?;
                z.write_template(w)?;
                w.write_char(')')
            }
            DN::AndV(x, y) => binary(w, "and_v(", x, y),
            DN::AndB(x, y) => binary(w, "and_b(", x, y),
            DN::AndN(x, y) => binary(w, "and_n(", x, y),
            DN::OrB(x, y) => binary(w, "or_b(", x, y),
            DN::OrC(x, y) => binary(w, "or_c(", x, y),
            DN::OrD(x, y) => binary(w, "or_d(", x, y),
            DN::OrI(x, y) => binary(w, "or_i(", x, y),
            DN::Thresh(k, list) => {
                write!(w, "thresh({}", k)?;
                for c in list.iter() {
                    w.write_char(',')?;
                    c.write_template(w)?;
                }
                w.write_char(')')
            }
            DN::A(c) => wrapper(w, 'a', c),
            DN::S(c) => wrapper(w, 's', c),
            DN::C(c) => wrapper(w, 'c', c),
            DN::T(c) => wrapper(w, 't', c),
            DN::D(c) => wrapper(w, 'd', c),
            DN::V(c) => wrapper(w, 'v', c),
            DN::J(c) => wrapper(w, 'j', c),
            DN::N(c) => wrapper(w, 'n', c),
            DN::L(c) => wrapper(w, 'l', c),
            DN::U(c) => wrapper(w, 'u', c),
            DN::TapNode(_) => unreachable!("tap-tree node reached via write_template"),
        }
    }
}

fn bracket<A: ArenaRead>(w: &mut dyn fmt::Write, open: &str, c: Cursor<'_, A>) -> fmt::Result {
    w.write_str(open)?;
    c.write_template(w)?;
    w.write_char(')')
}

fn kp<A: ArenaRead>(w: &mut dyn fmt::Write, open: &str, kv: KeyView<'_, A>) -> fmt::Result {
    w.write_str(open)?;
    write_key(w, kv)?;
    w.write_char(')')
}

fn multi<A: ArenaRead>(
    w: &mut dyn fmt::Write,
    open: &str,
    k: u32,
    keys: KeyListView<'_, A>,
) -> fmt::Result {
    write!(w, "{}{}", open, k)?;
    for kv in keys.iter() {
        w.write_char(',')?;
        write_key(w, kv)?;
    }
    w.write_char(')')
}

fn binary<A: ArenaRead>(
    w: &mut dyn fmt::Write,
    open: &str,
    x: Cursor<'_, A>,
    y: Cursor<'_, A>,
) -> fmt::Result {
    w.write_str(open)?;
    x.write_template(w)?;
    w.write_char(',')?;
    y.write_template(w)?;
    w.write_char(')')
}

fn hash(w: &mut dyn fmt::Write, open: &str, bytes: &[u8]) -> fmt::Result {
    w.write_str(open)?;
    write_hex(w, bytes)?;
    w.write_char(')')
}

fn wrapper<A: ArenaRead>(w: &mut dyn fmt::Write, ch: char, inner: Cursor<'_, A>) -> fmt::Result {
    w.write_char(ch)?;
    if !inner.tag().is_wrapper() {
        w.write_char(':')?;
    }
    inner.write_template(w)
}

impl<'a, A: ArenaRead> TapCursor<'a, A> {
    /// Renders this tap-tree node as `{left,right}` / leaf script, matching the
    /// owned `TapTree` `Display`.
    pub fn write_template(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        if let Some(script) = self.leaf_script() {
            script.write_template(w)
        } else {
            let (l, r) = self.branch().expect("tap node is leaf or branch");
            w.write_char('{')?;
            l.write_template(w)?;
            w.write_char(',')?;
            r.write_template(w)?;
            w.write_char('}')
        }
    }
}

/// Construct a [`KeyView`] for a key id (used when materializing an owned
/// `KeyExpression` from a parsed `KeyId`).
pub fn key_view<A: ArenaRead>(arena: &A, id: KeyId) -> KeyView<'_, A> {
    KeyView {
        arena,
        rec: arena.key(id),
    }
}

/// A borrowed key expression.
pub struct KeyView<'a, A: ArenaRead> {
    arena: &'a A,
    rec: KeyExprRec,
}
impl<'a, A: ArenaRead> Clone for KeyView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for KeyView<'a, A> {}

impl<'a, A: ArenaRead> KeyView<'a, A> {
    /// The underlying record (used by confusion-score grouping).
    pub fn record(&self) -> KeyExprRec {
        self.rec
    }
    pub fn num1(&self) -> u32 {
        self.rec.num1
    }
    pub fn num2(&self) -> u32 {
        self.rec.num2
    }
    pub fn is_plain(&self) -> bool {
        self.rec.kind == KeyKind::Plain
    }
    pub fn is_musig(&self) -> bool {
        self.rec.kind == KeyKind::Musig
    }
    pub fn plain_key_index(&self) -> Option<u32> {
        match self.rec.kind {
            KeyKind::Plain => Some(self.rec.plain_index),
            KeyKind::Musig => None,
        }
    }
    pub fn musig_key_indices(&self) -> Option<&'a [u32]> {
        match self.rec.kind {
            KeyKind::Musig => Some(self.arena.members(self.rec.musig_members)),
            KeyKind::Plain => None,
        }
    }
}

/// A borrowed list of key expressions (for `multi`/`sortedmulti`/`_a`).
pub struct KeyListView<'a, A: ArenaRead> {
    arena: &'a A,
    head: u32,
    count: u32,
}
impl<'a, A: ArenaRead> Clone for KeyListView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for KeyListView<'a, A> {}

impl<'a, A: ArenaRead> KeyListView<'a, A> {
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn iter(&self) -> KeyListIter<'a, A> {
        KeyListIter {
            arena: self.arena,
            cur: self.head,
        }
    }
}

pub struct KeyListIter<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
}

impl<'a, A: ArenaRead> Iterator for KeyListIter<'a, A> {
    type Item = KeyView<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == NONE {
            return None;
        }
        let link = self.arena.link(self.cur);
        self.cur = link.next;
        Some(KeyView {
            arena: self.arena,
            rec: self.arena.key(KeyId(link.val)),
        })
    }
}

/// The `keys` field of a classified `Multisig`/`TaprootMusig` class. It is
/// either an explicit `multi*`/`sortedmulti*` key list, or a single musig key
/// expanded into one synthetic plain key per member (mirroring how the owned
/// classifier expands `tr(musig($keys))` into `Multisig { keys: Vec<…> }`).
pub enum ClassKeyList<'a, A: ArenaRead> {
    Explicit(KeyListView<'a, A>),
    /// A musig key; yields one synthetic plain key per member, carrying the
    /// musig's shared `num1`/`num2`.
    MusigExpanded(KeyView<'a, A>),
}

impl<'a, A: ArenaRead> Clone for ClassKeyList<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for ClassKeyList<'a, A> {}

impl<'a, A: ArenaRead> ClassKeyList<'a, A> {
    pub fn len(&self) -> usize {
        match self {
            ClassKeyList::Explicit(l) => l.len(),
            ClassKeyList::MusigExpanded(kv) => kv.musig_key_indices().map(|m| m.len()).unwrap_or(0),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> ClassKeyIter<'a, A> {
        match self {
            ClassKeyList::Explicit(l) => ClassKeyIter::Explicit(l.iter()),
            ClassKeyList::MusigExpanded(kv) => ClassKeyIter::Musig {
                arena: kv.arena,
                members: kv.musig_key_indices().unwrap_or(&[]),
                pos: 0,
                num1: kv.num1(),
                num2: kv.num2(),
            },
        }
    }
}

pub enum ClassKeyIter<'a, A: ArenaRead> {
    Explicit(KeyListIter<'a, A>),
    Musig {
        arena: &'a A,
        members: &'a [u32],
        pos: usize,
        num1: u32,
        num2: u32,
    },
}

impl<'a, A: ArenaRead> Iterator for ClassKeyIter<'a, A> {
    type Item = KeyView<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ClassKeyIter::Explicit(it) => it.next(),
            ClassKeyIter::Musig {
                arena,
                members,
                pos,
                num1,
                num2,
            } => {
                let &idx = members.get(*pos)?;
                *pos += 1;
                Some(KeyView {
                    arena,
                    rec: KeyExprRec::plain(idx, *num1, *num2),
                })
            }
        }
    }
}

/// A borrowed list of sub-script nodes (for `thresh`).
pub struct NodeList<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
    count: u32,
}
impl<'a, A: ArenaRead> Clone for NodeList<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for NodeList<'a, A> {}

impl<'a, A: ArenaRead> NodeList<'a, A> {
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn iter(&self) -> NodeListIter<'a, A> {
        NodeListIter {
            arena: self.arena,
            cur: self.cur,
        }
    }
}

pub struct NodeListIter<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
}

impl<'a, A: ArenaRead> Iterator for NodeListIter<'a, A> {
    type Item = Cursor<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == NONE {
            return None;
        }
        let link = self.arena.link(self.cur);
        self.cur = link.next;
        Some(Cursor::new(self.arena, NodeId(link.val)))
    }
}

/// A borrowed reference to a tap-tree node.
pub struct TapCursor<'a, A: ArenaRead> {
    arena: &'a A,
    id: NodeId,
}
impl<'a, A: ArenaRead> Clone for TapCursor<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for TapCursor<'a, A> {}

impl<'a, A: ArenaRead> TapCursor<'a, A> {
    pub fn new(arena: &'a A, id: NodeId) -> Self {
        TapCursor { arena, id }
    }
    pub fn is_leaf(&self) -> bool {
        self.arena.node(self.id).tag == NodeTag::TapLeaf
    }
    /// For a `TapLeaf`, the leaf script cursor.
    pub fn leaf_script(&self) -> Option<Cursor<'a, A>> {
        let n = self.arena.node(self.id);
        if n.tag == NodeTag::TapLeaf {
            Some(Cursor::new(self.arena, NodeId(n.a)))
        } else {
            None
        }
    }
    /// For a `TapBranch`, the (left, right) child tap-cursors.
    pub fn branch(&self) -> Option<(TapCursor<'a, A>, TapCursor<'a, A>)> {
        let n = self.arena.node(self.id);
        if n.tag == NodeTag::TapBranch {
            Some((
                TapCursor::new(self.arena, NodeId(n.a)),
                TapCursor::new(self.arena, NodeId(n.b)),
            ))
        } else {
            None
        }
    }
    /// Iterate the leaf script cursors left-to-right (matching the historical
    /// `TapleavesIter`), using a fixed-capacity stack (no allocation).
    pub fn tapleaves(&self) -> TapleavesIter<'a, A> {
        let mut stack = [NodeId(0); MAX_TREE_DEPTH + 1];
        stack[0] = self.id;
        TapleavesIter {
            arena: self.arena,
            stack,
            depth: 1,
        }
    }
}

pub struct TapleavesIter<'a, A: ArenaRead> {
    arena: &'a A,
    stack: [NodeId; MAX_TREE_DEPTH + 1],
    depth: usize,
}

impl<'a, A: ArenaRead> Iterator for TapleavesIter<'a, A> {
    type Item = Cursor<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.depth > 0 {
            self.depth -= 1;
            let id = self.stack[self.depth];
            let n = self.arena.node(id);
            match n.tag {
                NodeTag::TapLeaf => return Some(Cursor::new(self.arena, NodeId(n.a))),
                NodeTag::TapBranch => {
                    // push right then left so left is popped first
                    if self.depth + 2 <= self.stack.len() {
                        self.stack[self.depth] = NodeId(n.b);
                        self.stack[self.depth + 1] = NodeId(n.a);
                        self.depth += 2;
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// A borrowed, matchable view of a descriptor node. Produced by [`Cursor::view`].
pub enum DescriptorNode<'a, A: ArenaRead> {
    Sh(Cursor<'a, A>),
    Wsh(Cursor<'a, A>),
    A(Cursor<'a, A>),
    S(Cursor<'a, A>),
    C(Cursor<'a, A>),
    T(Cursor<'a, A>),
    D(Cursor<'a, A>),
    V(Cursor<'a, A>),
    J(Cursor<'a, A>),
    N(Cursor<'a, A>),
    L(Cursor<'a, A>),
    U(Cursor<'a, A>),
    Pkh(KeyView<'a, A>),
    Wpkh(KeyView<'a, A>),
    Pk(KeyView<'a, A>),
    PkK(KeyView<'a, A>),
    PkH(KeyView<'a, A>),
    Tr(KeyView<'a, A>, Option<TapCursor<'a, A>>),
    Zero,
    One,
    Older(u32),
    After(u32),
    Sha256(&'a [u8]),
    Hash256(&'a [u8]),
    Ripemd160(&'a [u8]),
    Hash160(&'a [u8]),
    Andor(Cursor<'a, A>, Cursor<'a, A>, Cursor<'a, A>),
    AndV(Cursor<'a, A>, Cursor<'a, A>),
    AndB(Cursor<'a, A>, Cursor<'a, A>),
    AndN(Cursor<'a, A>, Cursor<'a, A>),
    OrB(Cursor<'a, A>, Cursor<'a, A>),
    OrC(Cursor<'a, A>, Cursor<'a, A>),
    OrD(Cursor<'a, A>, Cursor<'a, A>),
    OrI(Cursor<'a, A>, Cursor<'a, A>),
    Thresh(u32, NodeList<'a, A>),
    Multi(u32, KeyListView<'a, A>),
    MultiA(u32, KeyListView<'a, A>),
    Sortedmulti(u32, KeyListView<'a, A>),
    SortedmultiA(u32, KeyListView<'a, A>),
    /// A tap-tree node encountered directly (only when a `Cursor` is aimed at a
    /// `TapLeaf`/`TapBranch`); normal traversal reaches leaves via [`TapCursor`].
    TapNode(TapCursor<'a, A>),
}

// ---------------------------------------------------------------------------
// Cleartext output sink
// ---------------------------------------------------------------------------

/// A sink for cleartext output: a `core::fmt::Write` plus a line separator.
/// The encoder writes one logical description per "line" and calls
/// [`LineSink::flush_line`] between them.
pub trait LineSink: fmt::Write {
    /// Finish the current line and start a new one.
    fn flush_line(&mut self);
}

/// A `(offset, len)` slice of a cleartext line within a [`BufLineSink`]'s output
/// buffer. The C layer turns `offset` into a pointer into the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LineSpan {
    pub offset: u32,
    pub len: u32,
}

/// No-alloc [`LineSink`] writing line bytes into a caller `&mut [u8]` and
/// recording each line's `(offset, len)` into a caller `&mut [LineSpan]`.
/// `overflowed()` reports whether either buffer was exhausted. Used by the C
/// build.
pub struct BufLineSink<'a> {
    buf: &'a mut [u8],
    pos: usize,
    line_start: usize,
    lines: &'a mut [LineSpan],
    n_lines: usize,
    overflow: bool,
}

impl<'a> BufLineSink<'a> {
    pub fn new(buf: &'a mut [u8], lines: &'a mut [LineSpan]) -> Self {
        BufLineSink {
            buf,
            pos: 0,
            line_start: 0,
            lines,
            n_lines: 0,
            overflow: false,
        }
    }
    /// Number of completed lines.
    pub fn line_count(&self) -> usize {
        self.n_lines
    }
    /// The recorded line spans.
    pub fn lines(&self) -> &[LineSpan] {
        &self.lines[..self.n_lines]
    }
    /// Whether the output buffer or the line array was exhausted.
    pub fn overflowed(&self) -> bool {
        self.overflow
    }
}

impl<'a> fmt::Write for BufLineSink<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.pos < self.buf.len() {
                self.buf[self.pos] = b;
                self.pos += 1;
            } else {
                self.overflow = true;
            }
        }
        Ok(())
    }
}

impl<'a> LineSink for BufLineSink<'a> {
    fn flush_line(&mut self) {
        if self.n_lines < self.lines.len() {
            self.lines[self.n_lines] = LineSpan {
                offset: self.line_start as u32,
                len: (self.pos - self.line_start) as u32,
            };
            self.n_lines += 1;
        } else {
            self.overflow = true;
        }
        self.line_start = self.pos;
    }
}

/// A `fmt::Write` adapter that upper-cases the first ASCII-lowercase character
/// written through it, then passes everything else through unchanged. Used to
/// capitalize the first letter of each standalone cleartext line (composed
/// sub-policies, written after the first character, stay lowercase) — the
/// streaming equivalent of the owned `capitalize_first`.
pub struct CapWrite<'w> {
    inner: &'w mut dyn fmt::Write,
    done: bool,
}

impl<'w> CapWrite<'w> {
    pub fn new(inner: &'w mut dyn fmt::Write) -> Self {
        CapWrite { inner, done: false }
    }
}

impl<'w> fmt::Write for CapWrite<'w> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.done || s.is_empty() {
            return self.inner.write_str(s);
        }
        let first = s.chars().next().expect("non-empty");
        self.done = true;
        if first.is_ascii_lowercase() {
            let mut buf = [0u8; 4];
            self.inner
                .write_str(first.to_ascii_uppercase().encode_utf8(&mut buf))?;
            self.inner.write_str(&s[first.len_utf8()..])
        } else {
            self.inner.write_str(s)
        }
    }
}

/// A `fmt::Write` sink that captures up to `N` bytes into a fixed stack buffer
/// (excess is dropped). Used for the allocation-free lexicographic comparison of
/// two rendered "raw policy" tap leaves (a rare case), avoiding a heap `String`.
pub struct FixedBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    pub fn new() -> Self {
        FixedBuf {
            buf: [0u8; N],
            len: 0,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> Default for FixedBuf<N> {
    fn default() -> Self {
        FixedBuf::new()
    }
}

impl<const N: usize> fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len < N {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
pub use vec_sink::VecLineSink;

#[cfg(feature = "alloc")]
mod vec_sink {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Collects cleartext lines into `Vec<String>` (alloc build).
    #[derive(Default)]
    pub struct VecLineSink {
        lines: Vec<String>,
        cur: String,
    }

    impl VecLineSink {
        pub fn new() -> VecLineSink {
            VecLineSink::default()
        }
        /// Consume the sink, flushing any pending current line, into the lines.
        pub fn into_lines(mut self) -> Vec<String> {
            if !self.cur.is_empty() {
                self.lines.push(core::mem::take(&mut self.cur));
            }
            self.lines
        }
    }

    impl fmt::Write for VecLineSink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.cur.push_str(s);
            Ok(())
        }
    }

    impl LineSink for VecLineSink {
        fn flush_line(&mut self) {
            self.lines.push(core::mem::take(&mut self.cur));
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor-based traversals shared by both builds (no allocation)
// ---------------------------------------------------------------------------

impl<'a, A: ArenaRead> KeyView<'a, A> {
    /// Renders this key expression into `w` (mirrors `KeyExpression` `Display`).
    pub fn write_to(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write_key(w, *self)
    }
}

impl<'a, A: ArenaRead> Cursor<'a, A> {
    /// Determines the segwit version of a *top-level* descriptor node, matching
    /// the owned `WalletPolicy::get_segwit_version`.
    pub fn segwit_version(&self) -> Result<crate::SegwitVersion, crate::ParseError> {
        use crate::SegwitVersion as SV;
        use NodeTag::*;
        let n = self.arena.node(self.id);
        match n.tag {
            Tr => Ok(SV::Taproot),
            Pkh => Ok(SV::Legacy),
            Wpkh | Wsh => Ok(SV::SegwitV0),
            Sh => match self.arena.node(NodeId(n.a)).tag {
                Wpkh | Wsh => Ok(SV::SegwitV0),
                _ => Ok(SV::Legacy),
            },
            _ => Err(crate::ParseError::InvalidTopLevelPolicy),
        }
    }

    /// Visits every key placeholder in document order (left-to-right), passing
    /// the enclosing tap-leaf script cursor (or `None` outside a tap leaf / for
    /// the taproot internal key). Matches the order of the owned
    /// `DescriptorTemplate::placeholders` iterator. Recursion is bounded by the
    /// parser depth limit.
    pub fn for_each_placeholder<F>(&self, f: &mut F)
    where
        F: FnMut(KeyView<'a, A>, Option<Cursor<'a, A>>),
    {
        self.visit_placeholders(None, f);
    }

    fn visit_placeholders<F>(&self, leaf: Option<Cursor<'a, A>>, f: &mut F)
    where
        F: FnMut(KeyView<'a, A>, Option<Cursor<'a, A>>),
    {
        use DescriptorNode as DN;
        match self.view() {
            DN::Pkh(kv) | DN::Wpkh(kv) | DN::Pk(kv) | DN::PkK(kv) | DN::PkH(kv) => f(kv, leaf),
            DN::Multi(_, keys)
            | DN::MultiA(_, keys)
            | DN::Sortedmulti(_, keys)
            | DN::SortedmultiA(_, keys) => {
                for kv in keys.iter() {
                    f(kv, leaf);
                }
            }
            DN::Tr(kv, tree) => {
                f(kv, None);
                if let Some(t) = tree {
                    for leaf_script in t.tapleaves() {
                        leaf_script.visit_placeholders(Some(leaf_script), f);
                    }
                }
            }
            DN::Sh(c)
            | DN::Wsh(c)
            | DN::A(c)
            | DN::S(c)
            | DN::C(c)
            | DN::T(c)
            | DN::D(c)
            | DN::V(c)
            | DN::J(c)
            | DN::N(c)
            | DN::L(c)
            | DN::U(c) => c.visit_placeholders(leaf, f),
            DN::Andor(x, y, z) => {
                x.visit_placeholders(leaf, f);
                y.visit_placeholders(leaf, f);
                z.visit_placeholders(leaf, f);
            }
            DN::AndV(x, y)
            | DN::AndB(x, y)
            | DN::AndN(x, y)
            | DN::OrB(x, y)
            | DN::OrC(x, y)
            | DN::OrD(x, y)
            | DN::OrI(x, y) => {
                x.visit_placeholders(leaf, f);
                y.visit_placeholders(leaf, f);
            }
            DN::Thresh(_, list) => {
                for c in list.iter() {
                    c.visit_placeholders(leaf, f);
                }
            }
            DN::Zero
            | DN::One
            | DN::Older(_)
            | DN::After(_)
            | DN::Sha256(_)
            | DN::Hash256(_)
            | DN::Ripemd160(_)
            | DN::Hash160(_)
            | DN::TapNode(_) => {}
        }
    }
}

/// Total order over key *values* (derivation indices ignored), so equal key
/// expressions sort adjacently — matches the `KeyExpressionType` equality the
/// owned canonical check groups by.
fn cmp_key_value<A: ArenaRead>(arena: &A, a: &KeyExprRec, b: &KeyExprRec) -> Ordering {
    match (a.kind, b.kind) {
        (KeyKind::Plain, KeyKind::Plain) => a.plain_index.cmp(&b.plain_index),
        (KeyKind::Plain, KeyKind::Musig) => Ordering::Less,
        (KeyKind::Musig, KeyKind::Plain) => Ordering::Greater,
        (KeyKind::Musig, KeyKind::Musig) => arena
            .members(a.musig_members)
            .cmp(arena.members(b.musig_members)),
    }
}

impl<'a, A: ArenaRead> Cursor<'a, A> {
    /// Number of key placeholders (sizing for the canonical-check scratch).
    pub fn placeholder_count(&self) -> usize {
        let mut n = 0usize;
        self.for_each_placeholder(&mut |_, _| n += 1);
        n
    }

    /// Number of musig-expanded key-index occurrences (sizing for the
    /// orderings-count scratch).
    pub fn expanded_key_occurrences(&self) -> usize {
        let mut n = 0usize;
        self.for_each_placeholder(&mut |kv, _| {
            n += kv.musig_key_indices().map(|m| m.len()).unwrap_or(1);
        });
        n
    }

    /// Whether each distinct key expression's occurrences carry the canonical
    /// derivation pairs `(0,1),(2,3),…` (in some order). Mirrors the owned
    /// `are_key_derivations_canonical`. `scratch` must hold at least
    /// `placeholder_count()` records; if too small, returns `false`
    /// (conservatively falling back to the raw descriptor).
    pub fn are_key_derivations_canonical(&self, scratch: &mut [KeyExprRec]) -> bool {
        let mut n = 0usize;
        let mut overflow = false;
        self.for_each_placeholder(&mut |kv, _| {
            if n < scratch.len() {
                scratch[n] = kv.record();
            } else {
                overflow = true;
            }
            n += 1;
        });
        if overflow {
            return false;
        }
        let arena = self.arena;
        let s = &mut scratch[..n];
        s.sort_unstable_by(|a, b| {
            cmp_key_value(arena, a, b)
                .then(a.num1.cmp(&b.num1))
                .then(a.num2.cmp(&b.num2))
        });
        let mut i = 0;
        while i < s.len() {
            let mut j = i + 1;
            while j < s.len() && cmp_key_value(arena, &s[i], &s[j]) == Ordering::Equal {
                j += 1;
            }
            for (idx, e) in s[i..j].iter().enumerate() {
                if (e.num1, e.num2) != (2 * idx as u32, 2 * idx as u32 + 1) {
                    return false;
                }
            }
            i = j;
        }
        true
    }

    /// Upper bound on the number of canonical derivation-pair orderings across
    /// repeated keys: the product, over each key *index* (musig groups
    /// expanded), of `occurrences!`. Mirrors the owned
    /// `key_derivation_orderings_count`. `scratch` must hold at least
    /// `expanded_key_occurrences()` entries; if too small, returns `u64::MAX`
    /// (a safe over-count that only ever hides cleartext, never shows it).
    pub fn key_derivation_orderings_count(&self, scratch: &mut [u32]) -> u64 {
        let mut n = 0usize;
        let mut overflow = false;
        self.for_each_placeholder(&mut |kv, _| match kv.musig_key_indices() {
            Some(members) => {
                for &m in members {
                    if n < scratch.len() {
                        scratch[n] = m;
                    } else {
                        overflow = true;
                    }
                    n += 1;
                }
            }
            None => {
                let i = kv.plain_key_index().expect("plain or musig key");
                if n < scratch.len() {
                    scratch[n] = i;
                } else {
                    overflow = true;
                }
                n += 1;
            }
        });
        if overflow {
            return u64::MAX;
        }
        let s = &mut scratch[..n];
        s.sort_unstable();
        let mut product = 1u64;
        let mut i = 0;
        while i < s.len() {
            let mut j = i + 1;
            while j < s.len() && s[j] == s[i] {
                j += 1;
            }
            let mut f = 1u64;
            for k in 1..=(j - i) as u64 {
                f = f.saturating_mul(k);
            }
            product = product.saturating_mul(f);
            i = j;
        }
        product
    }
}

// ---------------------------------------------------------------------------
// Placeholder iterator (alloc-only pull-style traversal)
// ---------------------------------------------------------------------------
//
// The no-alloc computation paths use the recursive `for_each_placeholder`
// callback above. Consumers that need a pull-style iterator (the PSBT/signing
// handlers) use this `Vec`-backed iterator, which mirrors the owned
// `DescriptorTemplateIter` arm-for-arm (same traversal order), but yields
// `(KeyView, Option<Cursor>)` over the arena instead of borrowed owned nodes.

#[cfg(feature = "alloc")]
pub use placeholder_iter::PlaceholderIter;

#[cfg(feature = "alloc")]
mod placeholder_iter {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Pull-style iterator over a descriptor's key placeholders, in the same
    /// order as the historical owned `DescriptorTemplateIter`. Each item is the
    /// key expression and the enclosing tap-leaf script cursor (`None` outside a
    /// tap leaf / for the taproot internal key).
    pub struct PlaceholderIter<'a, A: ArenaRead> {
        fragments: Vec<(Cursor<'a, A>, Option<Cursor<'a, A>>)>,
        placeholders: Vec<(KeyView<'a, A>, Option<Cursor<'a, A>>)>,
    }

    impl<'a, A: ArenaRead> PlaceholderIter<'a, A> {
        pub fn new(root: Cursor<'a, A>) -> Self {
            PlaceholderIter {
                fragments: vec![(root, None)],
                placeholders: Vec::new(),
            }
        }
    }

    impl<'a, A: ArenaRead> Iterator for PlaceholderIter<'a, A> {
        type Item = (KeyView<'a, A>, Option<Cursor<'a, A>>);

        fn next(&mut self) -> Option<Self::Item> {
            use DescriptorNode as DN;
            while !self.placeholders.is_empty() || !self.fragments.is_empty() {
                // If there are pending placeholders, pop and return one.
                if let Some(item) = self.placeholders.pop() {
                    return Some(item);
                }

                let (frag, leaf) = self.fragments.pop()?;
                match frag.view() {
                    DN::Sh(c)
                    | DN::Wsh(c)
                    | DN::A(c)
                    | DN::S(c)
                    | DN::C(c)
                    | DN::T(c)
                    | DN::D(c)
                    | DN::V(c)
                    | DN::J(c)
                    | DN::N(c)
                    | DN::L(c)
                    | DN::U(c) => {
                        self.fragments.push((c, leaf));
                    }
                    DN::Andor(x, y, z) => {
                        self.fragments.push((z, leaf));
                        self.fragments.push((y, leaf));
                        self.fragments.push((x, leaf));
                    }
                    DN::OrB(x, y)
                    | DN::OrC(x, y)
                    | DN::OrD(x, y)
                    | DN::OrI(x, y)
                    | DN::AndV(x, y)
                    | DN::AndB(x, y)
                    | DN::AndN(x, y) => {
                        self.fragments.push((y, leaf));
                        self.fragments.push((x, leaf));
                    }
                    DN::Tr(key, tree) => {
                        self.placeholders.push((key, None));
                        if let Some(t) = tree {
                            let mut leaves: Vec<Cursor<'a, A>> = t.tapleaves().collect();
                            leaves.reverse();
                            for leaf_script in leaves {
                                self.fragments.push((leaf_script, Some(leaf_script)));
                            }
                        }
                    }
                    DN::Pkh(key) | DN::Wpkh(key) | DN::Pk(key) | DN::PkK(key) | DN::PkH(key) => {
                        return Some((key, leaf));
                    }
                    DN::Sortedmulti(_, keys)
                    | DN::SortedmultiA(_, keys)
                    | DN::Multi(_, keys)
                    | DN::MultiA(_, keys) => {
                        // Push keys in reverse so the first key is yielded first.
                        let kvs: Vec<KeyView<'a, A>> = keys.iter().collect();
                        for kv in kvs.into_iter().rev() {
                            self.placeholders.push((kv, leaf));
                        }
                    }
                    DN::Thresh(_, list) => {
                        let subs: Vec<Cursor<'a, A>> = list.iter().collect();
                        for c in subs.into_iter().rev() {
                            self.fragments.push((c, leaf));
                        }
                    }
                    DN::Zero
                    | DN::One
                    | DN::Older(_)
                    | DN::After(_)
                    | DN::Sha256(_)
                    | DN::Hash256(_)
                    | DN::Ripemd160(_)
                    | DN::Hash160(_)
                    | DN::TapNode(_) => {
                        // No placeholders for these.
                    }
                }
            }
            None
        }
    }

    impl<'a, A: ArenaRead> Cursor<'a, A> {
        /// Pull-style iterator over this node's key placeholders (see
        /// [`PlaceholderIter`]). Matches the owned `placeholders()` order.
        pub fn placeholders(&self) -> PlaceholderIter<'a, A> {
            PlaceholderIter::new(*self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    // Build `pkh(@0/**)` and read it back through a cursor.
    #[test]
    fn build_and_read_pkh() {
        let mut a = VecArena::new();
        let k = a.push_key(KeyExprRec::plain(0, 0, 1)).unwrap();
        let root = a.push_node(Node::with_a(NodeTag::Pkh, k.0)).unwrap();

        let cur = Cursor::new(&a, root);
        match cur.view() {
            DescriptorNode::Pkh(kv) => {
                assert!(kv.is_plain());
                assert_eq!(kv.plain_key_index(), Some(0));
                assert_eq!((kv.num1(), kv.num2()), (0, 1));
                assert_eq!(kv.musig_key_indices(), None);
            }
            _ => panic!("expected Pkh"),
        }
    }

    // Build `multi(2,@0,@1,@2)` via an in-order cons list.
    #[test]
    fn build_and_read_multi() {
        let mut a = VecArena::new();
        let mut list = ListBuilder::new();
        for i in 0..3u32 {
            let k = a.push_key(KeyExprRec::plain(i, 0, 1)).unwrap();
            list.push(&mut a, k.0).unwrap();
        }
        let mut node = Node::new(NodeTag::Multi);
        node.a = 2; // threshold
        node.b = list.head();
        node.c = list.count();
        let root = a.push_node(node).unwrap();

        match Cursor::new(&a, root).view() {
            DescriptorNode::Multi(k, keys) => {
                assert_eq!(k, 2);
                assert_eq!(keys.len(), 3);
                let indices: alloc::vec::Vec<u32> = keys
                    .iter()
                    .map(|kv| kv.plain_key_index().unwrap())
                    .collect();
                assert_eq!(indices, alloc::vec![0, 1, 2]);
            }
            _ => panic!("expected Multi"),
        }
    }

    // Build `musig(@3,@7)` and read its members as a contiguous slice.
    #[test]
    fn build_and_read_musig() {
        let mut a = VecArena::new();
        let start = a.members_begin();
        a.members_push(3).unwrap();
        a.members_push(7).unwrap();
        let span = a.members_end(start);
        let k = a.push_key(KeyExprRec::musig(span, 0, 1)).unwrap();
        let root = a.push_node(Node::with_a(NodeTag::Pk, k.0)).unwrap();

        match Cursor::new(&a, root).view() {
            DescriptorNode::Pk(kv) => {
                assert!(kv.is_musig());
                assert_eq!(kv.musig_key_indices(), Some(&[3u32, 7u32][..]));
                assert_eq!(kv.plain_key_index(), None);
            }
            _ => panic!("expected Pk(musig)"),
        }
    }

    #[test]
    fn class_key_list_explicit_and_musig_expanded() {
        let mut a = VecArena::new();

        // Explicit list: multi(_, @5, @6)
        let mut list = ListBuilder::new();
        for i in [5u32, 6] {
            let k = a.push_key(KeyExprRec::plain(i, 0, 1)).unwrap();
            list.push(&mut a, k.0).unwrap();
        }
        let explicit = KeyListView {
            arena: &a,
            head: list.head(),
            count: list.count(),
        };
        let ckl = ClassKeyList::Explicit(explicit);
        assert_eq!(ckl.len(), 2);
        let got: alloc::vec::Vec<(u32, u32, u32)> = ckl
            .iter()
            .map(|kv| (kv.plain_key_index().unwrap(), kv.num1(), kv.num2()))
            .collect();
        assert_eq!(got, alloc::vec![(5, 0, 1), (6, 0, 1)]);

        // Musig expanded: musig(@1,@2,@3)/<4;5> -> three synthetic plain keys
        // carrying the shared (4,5) derivation.
        let start = a.members_begin();
        for m in [1u32, 2, 3] {
            a.members_push(m).unwrap();
        }
        let span = a.members_end(start);
        let mk = a.push_key(KeyExprRec::musig(span, 4, 5)).unwrap();
        let kv = key_view(&a, mk);
        let ckl = ClassKeyList::MusigExpanded(kv);
        assert_eq!(ckl.len(), 3);
        let got: alloc::vec::Vec<(u32, u32, u32)> = ckl
            .iter()
            .map(|kv| (kv.plain_key_index().unwrap(), kv.num1(), kv.num2()))
            .collect();
        assert_eq!(got, alloc::vec![(1, 4, 5), (2, 4, 5), (3, 4, 5)]);
    }

    // Build a tap tree `{leaf(@0), {leaf(@1), leaf(@2)}}` and check left-to-right leaf order.
    #[test]
    fn build_and_iterate_tapleaves() {
        let mut a = VecArena::new();
        let mk_leaf = |a: &mut VecArena, idx: u32| {
            let k = a.push_key(KeyExprRec::plain(idx, 0, 1)).unwrap();
            let script = a.push_node(Node::with_a(NodeTag::Pk, k.0)).unwrap();
            a.push_node(Node::with_a(NodeTag::TapLeaf, script.0))
                .unwrap()
        };
        let l0 = mk_leaf(&mut a, 0);
        let l1 = mk_leaf(&mut a, 1);
        let l2 = mk_leaf(&mut a, 2);
        let mut inner = Node::new(NodeTag::TapBranch);
        inner.a = l1.0;
        inner.b = l2.0;
        let inner = a.push_node(inner).unwrap();
        let mut root = Node::new(NodeTag::TapBranch);
        root.a = l0.0;
        root.b = inner.0;
        let root = a.push_node(root).unwrap();

        let tc = TapCursor::new(&a, root);
        let order: alloc::vec::Vec<u32> = tc
            .tapleaves()
            .map(|leaf| match leaf.view() {
                DescriptorNode::Pk(kv) => kv.plain_key_index().unwrap(),
                _ => panic!("expected Pk leaf"),
            })
            .collect();
        assert_eq!(order, alloc::vec![0, 1, 2]);
    }

    #[test]
    fn line_sink_collects_lines() {
        let mut sink = VecLineSink::new();
        write!(sink, "first {}", 1).unwrap();
        sink.flush_line();
        write!(sink, "second").unwrap();
        let lines = sink.into_lines();
        assert_eq!(
            lines,
            alloc::vec!["first 1".to_string(), "second".to_string()]
        );
    }
}
