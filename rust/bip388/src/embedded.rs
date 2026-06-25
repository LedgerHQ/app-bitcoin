//! Public, allocation-free API for embedded / C consumers.
//!
//! Everything here works with caller-provided memory and never allocates, so it
//! is available in every build (including `--no-default-features`). The intended
//! flow is:
//!
//! 1. [`measure`] the template to get the per-pool record counts;
//! 2. carve caller memory into the typed pools and build a [`SliceArena`];
//! 3. [`parse`] the template into the arena to get the root [`NodeId`];
//! 4. build a [`Cursor`] and call [`Cursor::confusion_score`] /
//!    [`Cursor::to_cleartext`] (rendering into a [`BufLineSink`]).
//!
//! `bip388-c` is a thin `extern "C"` shim over exactly this.

use crate::arena::{ArenaFull, ArenaRead, ArenaStore, KeyId, NodeTag, Span};
use crate::ParseError;

pub use crate::arena::{BufLineSink, Cursor, KeyExprRec, LineSpan, Link, Node, NodeId, SliceArena};

/// Number of records each arena pool must hold to parse a given template.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArenaCounts {
    pub nodes: u32,
    pub keys: u32,
    pub links: u32,
    pub members: u32,
    pub bytes: u32,
}

/// An [`ArenaStore`] that records pool sizes without storing anything, used by
/// [`measure`]. Reads return harmless defaults; measurement only needs parser
/// validation and final pool counts.
struct CountingArena {
    counts: ArenaCounts,
}

impl ArenaRead for CountingArena {
    fn node(&self, _: NodeId) -> Node {
        Node::new(NodeTag::Zero)
    }
    fn key(&self, _: KeyId) -> KeyExprRec {
        KeyExprRec::plain(0, 0, 1)
    }
    fn link(&self, _: u32) -> Link {
        Link { val: 0, next: 0 }
    }
    fn members(&self, _: Span) -> &[u32] {
        &[]
    }
    fn bytes(&self, _: Span) -> &[u8] {
        &[]
    }
}

impl ArenaStore for CountingArena {
    fn push_node(&mut self, _: Node) -> Result<NodeId, ArenaFull> {
        let i = self.counts.nodes;
        self.counts.nodes += 1;
        Ok(NodeId(i))
    }
    fn push_key(&mut self, _: KeyExprRec) -> Result<KeyId, ArenaFull> {
        let i = self.counts.keys;
        self.counts.keys += 1;
        Ok(KeyId(i))
    }
    fn push_link(&mut self, _: Link) -> Result<u32, ArenaFull> {
        let i = self.counts.links;
        self.counts.links += 1;
        Ok(i)
    }
    fn set_link_next(&mut self, _: u32, _: u32) {}
    fn members_begin(&self) -> u32 {
        self.counts.members
    }
    fn members_push(&mut self, _: u32) -> Result<(), ArenaFull> {
        self.counts.members += 1;
        Ok(())
    }
    fn members_end(&self, start: u32) -> Span {
        Span {
            start,
            len: self.counts.members - start,
        }
    }
    fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull> {
        let start = self.counts.bytes;
        self.counts.bytes += bytes.len() as u32;
        Ok(Span {
            start,
            len: bytes.len() as u32,
        })
    }
    fn set_key_derivation(&mut self, _: KeyId, _: u32, _: u32) {}
}

/// Measure the per-pool record counts required to parse `template`. These are
/// an upper bound sufficient to size a [`SliceArena`] for a successful parse.
pub fn measure(template: &str) -> Result<ArenaCounts, ParseError> {
    let mut a = CountingArena {
        counts: ArenaCounts::default(),
    };
    crate::parser::parse_descriptor_template(template, &mut a)?;
    Ok(a.counts)
}

/// Parse `template` into `arena`, returning the root node id. Build a
/// [`Cursor`] with `Cursor::new(&arena, root)` afterwards to compute the
/// confusion score / cleartext.
pub fn parse<'a>(template: &str, arena: &mut SliceArena<'a>) -> Result<NodeId, ParseError> {
    crate::parser::parse_descriptor_template(template, arena)
}
