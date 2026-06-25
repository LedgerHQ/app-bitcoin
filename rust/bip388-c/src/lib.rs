//! C ABI for the bip388 cleartext / confusion-score API.
//!
//! Allocation-free: the caller supplies a scratch *arena* byte buffer (carved
//! internally into the bip388 record pools and working scratch) and, for
//! `to_cleartext`, an output byte buffer plus a `Bip388Line` array. Nothing
//! Rust-owned escapes; there is no global allocator.
#![no_std]
#![allow(clippy::missing_safety_doc)]

use core::marker::PhantomData;
use core::mem::{align_of, size_of};

use bip388::embedded::{
    measure, parse, ArenaCounts, BufLineSink, Cursor, KeyExprRec, LineSpan, Link, Node, SliceArena,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // The library is panic-free in normal operation; abort hard if reached.
    loop {}
}

/// Status codes returned by every entry point. `BIP388_OK` is 0; errors are
/// negative.
pub const BIP388_OK: i32 = 0;
pub const BIP388_NULL_ARG: i32 = -1;
pub const BIP388_INVALID_UTF8: i32 = -2;
pub const BIP388_PARSE_ERROR: i32 = -3;
pub const BIP388_ARENA_TOO_SMALL: i32 = -4;
pub const BIP388_BUFFER_TOO_SMALL: i32 = -5;
pub const BIP388_TOO_MANY_LINES: i32 = -6;

/// Threshold (inclusive upper bound) below which cleartext is considered
/// safe to show; mirrors `bip388::MAX_CONFUSION_SCORE`.
pub const BIP388_MAX_CONFUSION_SCORE: u64 = 100_000;

/// A rendered cleartext line: a pointer into the caller's output buffer and a
/// byte length (not NUL-terminated).
#[repr(C)]
pub struct Bip388Line {
    pub ptr: *const u8,
    pub len: usize,
}

// ---------------------------------------------------------------------------
// Bump carving of the caller arena into typed pools (no allocation)
// ---------------------------------------------------------------------------

/// Bump allocator over a caller-provided byte buffer. Hands out disjoint,
/// type-aligned, zero-initialized sub-slices that live as long as the buffer.
struct Bump<'a> {
    ptr: *mut u8,
    cap: usize,
    off: usize,
    _marker: PhantomData<&'a mut [u8]>,
}

impl<'a> Bump<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Bump {
            ptr: buf.as_mut_ptr(),
            cap: buf.len(),
            off: 0,
            _marker: PhantomData,
        }
    }

    fn take<T>(&mut self, n: usize) -> Option<&'a mut [T]> {
        let align = align_of::<T>();
        let start = (self.off.checked_add(align - 1)?) & !(align - 1);
        let size = size_of::<T>().checked_mul(n)?;
        let end = start.checked_add(size)?;
        if end > self.cap {
            return None;
        }
        // SAFETY: `start..end` is in-bounds and disjoint from every previously
        // handed-out region (`off` only grows). Zeroing makes the bytes a valid
        // `[T]` for every record type used here (all are valid when zeroed:
        // `NodeTag::Sh` / `KeyKind::Plain` have discriminant 0, others are
        // integers). The lifetime is tied to the original `&'a mut [u8]`.
        unsafe {
            let p = self.ptr.add(start);
            core::ptr::write_bytes(p, 0, size);
            self.off = end;
            Some(core::slice::from_raw_parts_mut(p as *mut T, n))
        }
    }
}

/// All pools and working scratch carved from one arena buffer.
struct Pools<'a> {
    nodes: &'a mut [Node],
    keys: &'a mut [KeyExprRec],
    links: &'a mut [Link],
    members: &'a mut [u32],
    bytes: &'a mut [u8],
    /// Scratch for `confusion_score` (musig-expanded key indices).
    orderings: &'a mut [u32],
    /// Scratch for the canonical-derivation check.
    canon: &'a mut [KeyExprRec],
    /// Scratch for the tap-leaf display sort.
    leaf: &'a mut [u32],
    /// Scratch for the rendered line spans.
    line_spans: &'a mut [LineSpan],
}

/// The number of bytes [`carve`] needs for the given counts. Must stay in lock
/// step with `carve`'s allocation sequence.
fn layout(c: &ArenaCounts) -> usize {
    fn bump(off: &mut usize, align: usize, size: usize) {
        *off = (*off + align - 1) & !(align - 1);
        *off += size;
    }
    let mut off = 0usize;
    bump(
        &mut off,
        align_of::<Node>(),
        size_of::<Node>() * c.nodes as usize,
    );
    bump(
        &mut off,
        align_of::<KeyExprRec>(),
        size_of::<KeyExprRec>() * c.keys as usize,
    );
    bump(
        &mut off,
        align_of::<Link>(),
        size_of::<Link>() * c.links as usize,
    );
    bump(
        &mut off,
        align_of::<u32>(),
        4 * (c.keys + c.members) as usize,
    ); // orderings
    bump(&mut off, align_of::<u32>(), 4 * c.members as usize); // members
    bump(
        &mut off,
        align_of::<KeyExprRec>(),
        size_of::<KeyExprRec>() * c.keys as usize,
    ); // canon
    bump(&mut off, align_of::<u32>(), 4 * c.nodes as usize); // leaf
    bump(&mut off, align_of::<u8>(), c.bytes as usize); // bytes
    bump(
        &mut off,
        align_of::<LineSpan>(),
        size_of::<LineSpan>() * (c.nodes as usize + 1),
    ); // line spans
    off
}

fn carve<'a>(buf: &'a mut [u8], c: &ArenaCounts) -> Option<Pools<'a>> {
    let mut b = Bump::new(buf);
    // Order must match `layout`.
    let nodes = b.take::<Node>(c.nodes as usize)?;
    let keys = b.take::<KeyExprRec>(c.keys as usize)?;
    let links = b.take::<Link>(c.links as usize)?;
    let orderings = b.take::<u32>((c.keys + c.members) as usize)?;
    let members = b.take::<u32>(c.members as usize)?;
    let canon = b.take::<KeyExprRec>(c.keys as usize)?;
    let leaf = b.take::<u32>(c.nodes as usize)?;
    let bytes = b.take::<u8>(c.bytes as usize)?;
    let line_spans = b.take::<LineSpan>(c.nodes as usize + 1)?;
    Some(Pools {
        nodes,
        keys,
        links,
        members,
        bytes,
        orderings,
        canon,
        leaf,
        line_spans,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate and convert a `(ptr, len)` pair into `&str`, or a status code.
unsafe fn template_str<'a>(tmpl: *const u8, tmpl_len: usize) -> Result<&'a str, i32> {
    if tmpl.is_null() {
        return Err(BIP388_NULL_ARG);
    }
    let bytes = core::slice::from_raw_parts(tmpl, tmpl_len);
    core::str::from_utf8(bytes).map_err(|_| BIP388_INVALID_UTF8)
}

// ---------------------------------------------------------------------------
// C ABI entry points
// ---------------------------------------------------------------------------

/// Minimum arena size (in bytes) needed by the other entry points for
/// `template`. Returns a status; on `BIP388_OK`, `*out_size` is set.
///
/// # Safety
/// `tmpl` must point to `tmpl_len` readable bytes; `out_size` must be writable.
#[no_mangle]
pub unsafe extern "C" fn bip388_min_arena_size(
    tmpl: *const u8,
    tmpl_len: usize,
    out_size: *mut usize,
) -> i32 {
    if out_size.is_null() {
        return BIP388_NULL_ARG;
    }
    let s = match template_str(tmpl, tmpl_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match measure(s) {
        Ok(c) => {
            *out_size = layout(&c);
            BIP388_OK
        }
        Err(_) => BIP388_PARSE_ERROR,
    }
}

/// Parse `template` and compute its confusion score into `*out_score`.
///
/// # Safety
/// All pointers must be valid for their given lengths; `out_score` writable.
#[no_mangle]
pub unsafe extern "C" fn bip388_confusion_score(
    tmpl: *const u8,
    tmpl_len: usize,
    arena: *mut u8,
    arena_len: usize,
    out_score: *mut u64,
) -> i32 {
    if arena.is_null() || out_score.is_null() {
        return BIP388_NULL_ARG;
    }
    let s = match template_str(tmpl, tmpl_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let counts = match measure(s) {
        Ok(c) => c,
        Err(_) => return BIP388_PARSE_ERROR,
    };
    let arena_buf = core::slice::from_raw_parts_mut(arena, arena_len);
    let pools = match carve(arena_buf, &counts) {
        Some(p) => p,
        None => return BIP388_ARENA_TOO_SMALL,
    };
    let mut sa = SliceArena::new(
        pools.nodes,
        pools.keys,
        pools.links,
        pools.members,
        pools.bytes,
    );
    let root = match parse(s, &mut sa) {
        Ok(r) => r,
        Err(_) => return BIP388_PARSE_ERROR,
    };
    let cur = Cursor::new(&sa, root);
    *out_score = cur.confusion_score(pools.orderings);
    BIP388_OK
}

/// Parse `template` and render its cleartext into `out`, recording one
/// `Bip388Line` (pointer into `out` + length) per description in `lines`.
///
/// On `BIP388_OK`: `*out_n_lines` is the number of lines written and
/// `*out_has_cleartext` is whether every part has a cleartext form; if a
/// score pointer is supplied it is set too.
///
/// # Safety
/// All pointers must be valid for their given lengths / sizes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bip388_to_cleartext(
    tmpl: *const u8,
    tmpl_len: usize,
    arena: *mut u8,
    arena_len: usize,
    out: *mut u8,
    out_len: usize,
    lines: *mut Bip388Line,
    max_lines: usize,
    out_n_lines: *mut usize,
    out_has_cleartext: *mut bool,
) -> i32 {
    if arena.is_null() || out.is_null() || lines.is_null() || out_n_lines.is_null() {
        return BIP388_NULL_ARG;
    }
    let s = match template_str(tmpl, tmpl_len) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let counts = match measure(s) {
        Ok(c) => c,
        Err(_) => return BIP388_PARSE_ERROR,
    };
    let arena_buf = core::slice::from_raw_parts_mut(arena, arena_len);
    let pools = match carve(arena_buf, &counts) {
        Some(p) => p,
        None => return BIP388_ARENA_TOO_SMALL,
    };
    let out_buf = core::slice::from_raw_parts_mut(out, out_len);

    let mut sa = SliceArena::new(
        pools.nodes,
        pools.keys,
        pools.links,
        pools.members,
        pools.bytes,
    );
    let root = match parse(s, &mut sa) {
        Ok(r) => r,
        Err(_) => return BIP388_PARSE_ERROR,
    };
    let cur = Cursor::new(&sa, root);

    let has_cleartext;
    let n_lines;
    {
        let mut sink = BufLineSink::new(out_buf, pools.line_spans);
        has_cleartext = cur.to_cleartext(&mut sink, pools.canon, pools.leaf);
        if sink.overflowed() {
            return BIP388_BUFFER_TOO_SMALL;
        }
        n_lines = sink.line_count();
        if n_lines > max_lines {
            return BIP388_TOO_MANY_LINES;
        }
        let out_lines = core::slice::from_raw_parts_mut(lines, max_lines);
        for (i, span) in sink.lines().iter().enumerate() {
            out_lines[i] = Bip388Line {
                ptr: out.add(span.offset as usize),
                len: span.len as usize,
            };
        }
    }
    *out_n_lines = n_lines;
    if !out_has_cleartext.is_null() {
        *out_has_cleartext = has_cleartext;
    }
    BIP388_OK
}
