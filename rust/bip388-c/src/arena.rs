//! Reclaiming global allocator backed by a caller-provided arena (freestanding
//! `no_std` build only).
//!
//! `bip388` and its `bitcoin` dependency unconditionally require an `alloc`
//! global allocator. Rather than depend on a C heap (`malloc`/`free`), the FFI
//! installs a scratch buffer supplied by the caller as the active heap for the
//! duration of a single call, then detaches it. Nothing Rust-owned ever escapes
//! the FFI boundary and the C side needs no persistent heap.
//!
//! Unlike a bump allocator, this reclaims freed memory (it wraps
//! [`linked_list_allocator::Heap`], the same allocator `embedded-alloc` uses),
//! so a transient `format!`/`Vec` temporary does not permanently consume arena
//! space. That keeps the peak working set close to the live set — small enough
//! that a 4-8 KiB arena holds realistic policies (see the sizing model in
//! `lib.rs`).
//!
//! The heap is reset to a fresh `Heap::empty()` at every [`install`], so the
//! once-only `init` contract of the underlying allocator is respected even
//! across many calls. Single-threaded only: one heap is shared process-wide via
//! a `static` accessed through an `UnsafeCell` (no locking). This matches the
//! embedded target (e.g. the Ledger app) and is documented in the generated
//! header.
//!
//! A peak-usage high-water mark is tracked so the FFI's *a priori* arena-fit
//! check (in `lib.rs`) can be validated against the real allocator, fragmentation
//! included.
//!
//! Under the `std` feature (host tests) this module is inert and the system
//! allocator is used instead.

#![cfg(not(feature = "std"))]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use linked_list_allocator::Heap;

struct LockedHeap(UnsafeCell<Heap>);

// SAFETY: single-threaded by contract (see module docs); the `UnsafeCell` is
// only ever touched from the FFI thread.
unsafe impl Sync for LockedHeap {}

#[global_allocator]
static HEAP: LockedHeap = LockedHeap(UnsafeCell::new(Heap::empty()));

/// High-water mark of the heap's used bytes since the last [`install`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = &mut *self.0.get();
        let p = heap
            .allocate_first_fit(layout)
            .map_or(ptr::null_mut(), |nn| nn.as_ptr());
        // Track peak live usage after each successful allocation.
        if !p.is_null() {
            PEAK.fetch_max(heap.used(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let heap = &mut *self.0.get();
        if let Some(nn) = ptr::NonNull::new(p) {
            heap.deallocate(nn, layout);
        }
    }
}

/// Installs `base[..len]` as the active heap (resetting any prior state) and
/// resets the peak counter.
///
/// # Safety
/// `base` must point to at least `len` writable bytes that stay valid until
/// [`clear`] is called, and no Rust allocation may be live from a prior arena.
pub unsafe fn install(base: *mut u8, len: usize) {
    let heap = &mut *HEAP.0.get();
    // Replace with a fresh, uninitialised heap so the following `init` is the
    // (required) first init on this instance, then point it at the arena.
    *heap = Heap::empty();
    heap.init(base, len);
    PEAK.store(0, Ordering::Relaxed);
}

/// Detaches the arena (resets the heap to empty) so no pointer into caller
/// memory remains and any stray allocation fails fast.
///
/// # Safety
/// No Rust allocation served from the arena may be live when this is called.
pub unsafe fn clear() {
    let heap = &mut *HEAP.0.get();
    *heap = Heap::empty();
}

/// Peak live bytes used since the last [`install`]. Used to validate the
/// arena-fit model against the real allocator.
pub fn peak_used() -> usize {
    PEAK.load(Ordering::Relaxed)
}
