#ifdef HAVE_CLEARTEXT

#include <string.h>

#include "cleartext.h"
#include "bip388.h"  // vendored binding (rust/bip388-c/include), via INCLUDES_PATH

// Keep the locally-mirrored threshold in lock-step with the binding's contract.
_Static_assert(CLEARTEXT_MAX_CONFUSION_SCORE == BIP388_MAX_CONFUSION_SCORE,
               "CLEARTEXT_MAX_CONFUSION_SCORE out of sync with the binding");

// Scratch arena the binding bump-allocates from for the duration of one call.
// Kept in static storage rather than on the stack (which is only 8 KiB on Nano
// X). Sized generously: realistic policies need well under 1.2 KiB (a 15-key
// multisig ~1 KiB, a depth-9 tap-tree ~1.1 KiB); a policy that does not fit
// makes the binding return BIP388_ARENA_TOO_SMALL and the wrapper falls back to
// the raw template. Single-threaded use only (so is the app's command
// dispatch).
#define CLEARTEXT_ARENA_SIZE 8192
static uint8_t g_cleartext_arena[CLEARTEXT_ARENA_SIZE];

int cleartext_encode(const char *descriptor,
                     size_t descriptor_len,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext,
                     uint64_t *out_confusion_score) {
    Bip388Line lines[CT_MAX_LINES];
    // Flat storage the binding renders into; it reports each line as a
    // (ptr,len) span into this buffer, which we copy out NUL-terminated below.
    uint8_t out[CT_MAX_LINES * (CT_MAX_LINE_LEN + 1)];
    size_t n_lines = 0;
    bool has_cleartext = false;

    int32_t rc = bip388_to_cleartext((const uint8_t *) descriptor,
                                     descriptor_len,
                                     g_cleartext_arena,
                                     sizeof g_cleartext_arena,
                                     out,
                                     sizeof out,
                                     lines,
                                     CT_MAX_LINES,
                                     &n_lines,
                                     &has_cleartext);

    if (rc == BIP388_PARSE_ERROR || rc == BIP388_INVALID_UTF8) {
        // Not a renderable descriptor template: caller shows the raw template.
        return 0;
    }
    if (rc != BIP388_OK || n_lines > CT_MAX_LINES) {
        // Capacity/structural error (arena too small, too many lines, a line
        // larger than our flat buffer, ...): the policy is within the app's
        // limits, so this should not happen, but if it does we fall back to the
        // raw template rather than show nothing.
        return -1;
    }

    for (size_t i = 0; i < n_lines; i++) {
        if (lines[i].len > CT_MAX_LINE_LEN) {
            return -1;  // a rendered line did not fit our per-line buffer
        }
        memcpy(out_lines[i], lines[i].ptr, lines[i].len);
        out_lines[i][lines[i].len] = '\0';
    }

    // The confusion score is a separate entry point; reuse the same arena.
    uint64_t score = 0;
    rc = bip388_confusion_score((const uint8_t *) descriptor,
                                descriptor_len,
                                g_cleartext_arena,
                                sizeof g_cleartext_arena,
                                &score);
    if (rc != BIP388_OK) {
        return -1;
    }

    *out_n_lines = n_lines;
    *out_has_cleartext = has_cleartext;
    *out_confusion_score = score;
    return 1;
}

#endif  // HAVE_CLEARTEXT
