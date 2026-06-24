/*
 * Smoke test / usage example for the bip388 C bindings.
 *
 * Demonstrates the caller-owns-everything memory model: a fixed-size arena, a
 * fixed output buffer, and a fixed array of line descriptors, all on the stack.
 * No malloc/free is needed. A policy that does not fit the arena returns a clean
 * status code (never an abort).
 *
 * Build (after `cargo build --release`):
 *   cc -I include examples/demo.c target/release/libbip388_c.a -o /tmp/demo
 */

#include <stdio.h>
#include <string.h>

#include "bip388.h"

/*
 * On a hosted target (e.g. x86_64-linux) the precompiled Rust `alloc` is built
 * with unwinding and references `rust_eh_personality`, even though this crate is
 * compiled with `panic = abort`. Provide a stub so the standalone demo links.
 * Embedded `*-none-*` targets are abort-by-default and do not need this.
 */
void rust_eh_personality(void) {}

/* A 4 KiB arena holds any plain multisig the Ledger app supports (up to 15
 * keys); taptrees with several leaves may need up to ~8 KiB. */
#define ARENA_SIZE 8192

static int run(const char *descriptor) {
    uint8_t arena[ARENA_SIZE];
    uint8_t out[512];
    Bip388Line lines[BIP388_MAX_TAPLEAVES + 1];
    uintptr_t n_lines = 0;
    bool has_cleartext = false;
    uint64_t confusion_score = 0;

    Bip388Status rc = bip388_to_cleartext(
        (const uint8_t *)descriptor, strlen(descriptor),
        arena, sizeof arena,
        out, sizeof out,
        lines, sizeof lines / sizeof lines[0],
        &n_lines, &has_cleartext, &confusion_score);

    printf("descriptor: %s\n", descriptor);
    if (rc != BIP388_STATUS_OK) {
        uintptr_t need = 0;
        bip388_min_arena_size((const uint8_t *)descriptor, strlen(descriptor), &need);
        printf("  status: %d (no cleartext; min arena = %zu)\n\n", (int)rc, (size_t)need);
        return rc;
    }

    printf("  confusion_score=%llu  has_cleartext=%d  shown=%d\n",
           (unsigned long long)confusion_score, (int)has_cleartext,
           confusion_score <= BIP388_MAX_CONFUSION_SCORE);
    for (uintptr_t i = 0; i < n_lines; i++) {
        /* Lines are UTF-8 and NOT NUL-terminated: print with an explicit length. */
        printf("  line[%zu]: %.*s\n", (size_t)i, (int)lines[i].len, lines[i].ptr);
    }
    printf("\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= run("wpkh(@0/**)");
    rc |= run("tr(@0/**,multi_a(3,@1/**,@2/**,@3/**))");
    rc |= run("wsh(sortedmulti(2,@0/**,@1/**))");
    rc |= run("wsh(multi(15,@0/**,@1/**,@2/**,@3/**,@4/**,@5/**,@6/**,@7/**,"
              "@8/**,@9/**,@10/**,@11/**,@12/**,@13/**,@14/**))");
    /* A parse failure is reported via the status code, not a crash. */
    run("not a descriptor");
    return rc;
}
