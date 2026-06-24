/*
 * Calibration / regression tool for the arena-fit model in `lib.rs`.
 *
 * For each descriptor read from stdin it asks the binding for the model's
 * `required` arena size, allocates EXACTLY that many bytes, runs the real
 * (reclaiming) allocator path, and prints `required`, the real peak usage, and
 * the status. The model is SAFE as long as every accepted descriptor returns a
 * non-abort status (rc != crash); `required >= peak` with margin confirms it is
 * not over-tight. A SIGABRT means the model under-provisioned and the
 * ARENA_* constants in `lib.rs` must grow.
 *
 * Re-run this whenever `bip388`'s parser or renderer changes:
 *   cargo build --release
 *   cc -I include examples/calibrate.c target/release/libbip388_c.a -o /tmp/calib
 *   printf 'wpkh(@0/**)\nwsh(multi(15,...))\n' | /tmp/calib
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip388.h"

void rust_eh_personality(void) {}

int main(void) {
    char line[2048];
    printf("%-8s %-8s %-4s  descriptor\n", "req", "peak", "rc");
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (n == 0) continue;

        uintptr_t required = 0;
        Bip388Status s = bip388_min_arena_size((const uint8_t *)line, n, &required);
        if (s != BIP388_STATUS_OK) {
            printf("%-8s %-8s %-4d  %s\n", "complex", "-", (int)s, line);
            continue;
        }

        uint8_t *arena = malloc(required);
        uint8_t out[16384];
        Bip388Line lines[BIP388_MAX_TAPLEAVES + 1];
        uintptr_t nl; bool hc; uint64_t cs;
        Bip388Status rc = bip388_to_cleartext((const uint8_t *)line, n, arena, required,
            out, sizeof out, lines, sizeof lines / sizeof lines[0], &nl, &hc, &cs);
        printf("%-8zu %-8zu %-4d  %s\n", (size_t)required,
               (size_t)bip388_debug_peak_used(), (int)rc, line);
        free(arena);
    }
    return 0;
}
