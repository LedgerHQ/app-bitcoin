#ifdef HAVE_CLEARTEXT

#include <string.h>

#include "cleartext.h"
#include "bip388.h"  // vendored binding (rust/bip388-c/include), via INCLUDES_PATH

// Keep the locally-mirrored constants in lock-step with the binding's contract.
_Static_assert(CLEARTEXT_MAX_CONFUSION_SCORE == BIP388_MAX_CONFUSION_SCORE,
               "CLEARTEXT_MAX_CONFUSION_SCORE out of sync with the binding");
_Static_assert(CT_MAX_LINES == BIP388_MAX_TAPLEAVES + 1,
               "CT_MAX_LINES must be BIP388_MAX_TAPLEAVES + 1");

#ifdef CLEARTEXT_HOST_BUILD
// On a hosted target (unit tests) the precompiled Rust `alloc` is built with
// unwinding and references rust_eh_personality even though this crate is
// panic=abort. Provide a stub so the test executables link. The freestanding
// device build (no_std, abort-by-default) never references it.
void rust_eh_personality(void) {}
#endif

// Scratch arena the binding bump-allocates from for the duration of one call.
// Kept in static storage rather than on the stack: BIP388_RECOMMENDED_ARENA_SIZE
// is 8 KiB, which is the entire stack budget on Nano X. Single-threaded use only
// (the binding is single-threaded and so is the app's command dispatch).
static uint8_t g_cleartext_arena[BIP388_RECOMMENDED_ARENA_SIZE];

int cleartext_encode(const char *descriptor,
                     size_t descriptor_len,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext,
                     uint64_t *out_confusion_score) {
    Bip388Line lines[CT_MAX_LINES];
    // Storage the binding copies the (non-NUL-terminated) line bytes into.
    uint8_t out[CT_MAX_LINES * (CT_MAX_LINE_LEN + 1)];
    size_t n_lines = 0;
    bool has_cleartext = false;
    uint64_t score = 0;

    Bip388Status rc = bip388_to_cleartext((const uint8_t *) descriptor,
                                          descriptor_len,
                                          g_cleartext_arena,
                                          sizeof g_cleartext_arena,
                                          out,
                                          sizeof out,
                                          lines,
                                          CT_MAX_LINES,
                                          &n_lines,
                                          &has_cleartext,
                                          &score);

    if (rc == BIP388_STATUS_PARSE_ERROR || rc == BIP388_STATUS_INVALID_UTF8) {
        // Not a renderable descriptor template: caller shows the raw template.
        return 0;
    }
    if (rc != BIP388_STATUS_OK || n_lines > CT_MAX_LINES) {
        // Capacity/structural error (out-of-arena, too-many-lines, ...): the
        // policy is within the app's limits, so this should not happen, but if
        // it does we fall back to the raw template rather than show nothing.
        return -1;
    }

    for (size_t i = 0; i < n_lines; i++) {
        if (lines[i].len > CT_MAX_LINE_LEN) {
            return -1;  // a rendered line did not fit our per-line buffer
        }
        memcpy(out_lines[i], lines[i].ptr, lines[i].len);
        out_lines[i][lines[i].len] = '\0';
    }

    *out_n_lines = n_lines;
    *out_has_cleartext = has_cleartext;
    *out_confusion_score = score;
    return 1;
}

#endif  // HAVE_CLEARTEXT
