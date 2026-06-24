//! Host tests for the C ABI. Run with `cargo test --features std` (the test
//! harness needs libstd; the system allocator stands in for the arena, but the
//! arena-fit / structural pre-checks still run on the supplied `arena_len`).

use super::*;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const ARENA_LEN: usize = BIP388_RECOMMENDED_ARENA_SIZE;

struct Rendered {
    status: Bip388Status,
    lines: Vec<String>,
    has_cleartext: bool,
    confusion_score: u64,
}

/// Calls `bip388_to_cleartext` with generously sized buffers and collects the
/// result into owned Rust values.
fn render(descriptor: &str) -> Rendered {
    render_full(descriptor, ARENA_LEN, 4096, 16)
}

/// Same, with explicit arena / `out` / `lines` capacities to exercise the
/// error paths.
fn render_full(descriptor: &str, arena_len: usize, out_len: usize, lines_cap: usize) -> Rendered {
    let mut arena = vec![0u8; arena_len.max(1)];
    let mut out = vec![0u8; out_len];
    let mut lines = vec![
        Bip388Line {
            ptr: core::ptr::null(),
            len: 0
        };
        lines_cap
    ];
    let mut n_lines = 0usize;
    let mut has_cleartext = false;
    let mut score = 0u64;

    let status = unsafe {
        bip388_to_cleartext(
            descriptor.as_ptr(),
            descriptor.len(),
            arena.as_mut_ptr(),
            arena_len,
            out.as_mut_ptr(),
            out.len(),
            lines.as_mut_ptr(),
            lines.len(),
            &mut n_lines,
            &mut has_cleartext,
            &mut score,
        )
    };

    let mut collected = Vec::new();
    if status == Bip388Status::Ok {
        for line in lines.iter().take(n_lines) {
            // SAFETY: on success each slice points into our `out` buffer.
            let bytes = unsafe { core::slice::from_raw_parts(line.ptr, line.len) };
            collected.push(String::from_utf8(bytes.to_vec()).unwrap());
        }
    }
    Rendered {
        status,
        lines: collected,
        has_cleartext,
        confusion_score: score,
    }
}

fn min_arena(descriptor: &str) -> (Bip388Status, usize) {
    let mut out = 0usize;
    let status =
        unsafe { bip388_min_arena_size(descriptor.as_ptr(), descriptor.len(), &mut out) };
    (status, out)
}

#[test]
fn single_sig_segwit() {
    let r = render("wpkh(@0/**)");
    assert_eq!(r.status, Bip388Status::Ok);
    assert_eq!(r.lines, vec!["Spendable by @0 alone (SegWit)".to_string()]);
    assert!(r.has_cleartext);
    assert_eq!(r.confusion_score, 2);
}

#[test]
fn single_sig_legacy_score() {
    let r = render("pkh(@0/**)");
    assert_eq!(r.status, Bip388Status::Ok);
    assert_eq!(r.lines, vec!["Spendable by @0 alone (Legacy)".to_string()]);
    assert_eq!(r.confusion_score, 1);
}

#[test]
fn taproot_multi_leaf() {
    let r = render("tr(@0/**,multi_a(3,@1/**,@2/**,@3/**))");
    assert_eq!(r.status, Bip388Status::Ok);
    assert_eq!(
        r.lines,
        vec![
            "Main path: spendable by @0".to_string(),
            "Each of @1, @2 and @3 must sign".to_string(),
        ]
    );
    assert!(r.has_cleartext);
    assert_eq!(r.confusion_score, 2);
}

#[test]
fn taproot_unrecognised_leaf_sets_has_cleartext_false() {
    let descriptor = "tr(@0/**,{t:or_c(pk(@2/**),and_v(v:pk(@3/**),or_c(pk(@4/**),v:ripemd160(907cd521fff981ce4063a4dc43c6f3fd28e08995)))),pk(@1/**)})";
    let r = render(descriptor);
    assert_eq!(r.status, Bip388Status::Ok);
    assert_eq!(r.lines.len(), 3);
    assert_eq!(r.lines[0], "Main path: spendable by @0");
    assert_eq!(r.lines[1], "@1 must sign");
    assert!(r.lines[2].starts_with("Raw policy: "));
    assert!(!r.has_cleartext);
}

#[test]
fn full_15_key_multisig_fits_4kib() {
    let d = "wsh(multi(15,@0/**,@1/**,@2/**,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**,@12/**,@13/**,@14/**))";
    // The headline guarantee: the largest plain multisig the Ledger app
    // supports fits a 4 KiB arena.
    let (s, req) = min_arena(d);
    assert_eq!(s, Bip388Status::Ok);
    assert!(req <= 4096, "15-key multisig needs {req} bytes, want <= 4096");
    let r = render_full(d, 4096, 4096, 16);
    assert_eq!(r.status, Bip388Status::Ok);
    assert_eq!(r.lines.len(), 1);
}

#[test]
fn confusion_score_entry_point() {
    let d = "wpkh(@0/**)";
    let mut arena = vec![0u8; ARENA_LEN];
    let mut score = 0u64;
    let status = unsafe {
        bip388_confusion_score(d.as_ptr(), d.len(), arena.as_mut_ptr(), arena.len(), &mut score)
    };
    assert_eq!(status, Bip388Status::Ok);
    assert_eq!(score, 2);
}

#[test]
fn invalid_descriptor_is_parse_error() {
    assert_eq!(
        render("this is not a descriptor").status,
        Bip388Status::ParseError
    );
}

#[test]
fn invalid_utf8_is_detected() {
    let bytes = [0xff, 0xfe, 0x00];
    let mut arena = vec![0u8; ARENA_LEN];
    let mut out = vec![0u8; 256];
    let mut lines = vec![
        Bip388Line {
            ptr: core::ptr::null(),
            len: 0
        };
        8
    ];
    let (mut n, mut hc, mut sc) = (0usize, false, 0u64);
    let status = unsafe {
        bip388_to_cleartext(
            bytes.as_ptr(),
            bytes.len(),
            arena.as_mut_ptr(),
            arena.len(),
            out.as_mut_ptr(),
            out.len(),
            lines.as_mut_ptr(),
            lines.len(),
            &mut n,
            &mut hc,
            &mut sc,
        )
    };
    assert_eq!(status, Bip388Status::InvalidUtf8);
}

#[test]
fn null_output_pointer_is_rejected() {
    let mut arena = vec![0u8; ARENA_LEN];
    let d = "wpkh(@0/**)";
    let mut lines = vec![
        Bip388Line {
            ptr: core::ptr::null(),
            len: 0
        };
        8
    ];
    let (mut n, mut hc, mut sc) = (0usize, false, 0u64);
    let status = unsafe {
        bip388_to_cleartext(
            d.as_ptr(),
            d.len(),
            arena.as_mut_ptr(),
            arena.len(),
            core::ptr::null_mut(),
            0,
            lines.as_mut_ptr(),
            lines.len(),
            &mut n,
            &mut hc,
            &mut sc,
        )
    };
    assert_eq!(status, Bip388Status::NullArg);
}

#[test]
fn out_buffer_too_small() {
    // "Spendable by @0 alone (SegWit)" needs 30 bytes; give 8.
    assert_eq!(
        render_full("wpkh(@0/**)", ARENA_LEN, 8, 16).status,
        Bip388Status::BufferTooSmall
    );
}

#[test]
fn too_many_lines() {
    // The taproot vector produces 2 lines; allow only 1.
    let r = render_full("tr(@0/**,multi_a(3,@1/**,@2/**,@3/**))", ARENA_LEN, 4096, 1);
    assert_eq!(r.status, Bip388Status::TooManyLines);
}

#[test]
fn arena_too_small_is_clean_error() {
    // A 15-key multisig needs ~3.9 KiB; a 1 KiB arena must be cleanly rejected
    // (before any allocation), never an abort.
    let d = "wsh(multi(15,@0/**,@1/**,@2/**,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**,@12/**,@13/**,@14/**))";
    let r = render_full(d, 1024, 4096, 16);
    assert_eq!(r.status, Bip388Status::OutOfArena);
}

#[test]
fn too_many_leaves_is_policy_too_complex() {
    // 9 single-sig leaves => 8 branch nodes => exceeds BIP388_MAX_TAPLEAVES.
    let d = "tr(@0/**,{{{pk(@1/**),pk(@2/**)},{pk(@3/**),pk(@4/**)}},{{pk(@5/**),pk(@6/**)},{{pk(@7/**),pk(@8/**)},pk(@9/**)}}})";
    let r = render_full(d, ARENA_LEN, 4096, 16);
    assert_eq!(r.status, Bip388Status::PolicyTooComplex);
}

#[test]
fn min_arena_size_matches_fit_check() {
    // A descriptor needs exactly min_arena_size; one byte less is rejected.
    let d = "wsh(sortedmulti(2,@0/**,@1/**))";
    let (s, req) = min_arena(d);
    assert_eq!(s, Bip388Status::Ok);
    assert_eq!(render_full(d, req, 4096, 16).status, Bip388Status::Ok);
    assert_eq!(
        render_full(d, req - 1, 4096, 16).status,
        Bip388Status::OutOfArena
    );
}
