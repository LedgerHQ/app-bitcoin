/*
 * C ABI for the bip388 cleartext / confusion-score API.
 *
 * Allocation-free and bitcoin-free: every entry point works entirely within
 * caller-provided memory and the library has no global allocator.
 *
 * Usage:
 *   1. Call bip388_min_arena_size() to size the scratch `arena` buffer.
 *   2. bip388_confusion_score() returns an upper bound on how many distinct
 *      descriptor templates map to the same cleartext. Show cleartext only when
 *      it is <= BIP388_MAX_CONFUSION_SCORE.
 *   3. bip388_to_cleartext() renders the human-readable descriptions into the
 *      caller's `out` buffer; each line is reported as a (ptr,len) into `out`.
 *
 * This header is maintained by hand; keep it in sync with src/lib.rs.
 */
#ifndef BIP388_H
#define BIP388_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. BIP388_OK is 0; errors are negative. */
#define BIP388_OK 0
#define BIP388_NULL_ARG (-1)
#define BIP388_INVALID_UTF8 (-2)
#define BIP388_PARSE_ERROR (-3)
#define BIP388_ARENA_TOO_SMALL (-4)
#define BIP388_BUFFER_TOO_SMALL (-5)
#define BIP388_TOO_MANY_LINES (-6)

/* Confusion-score display threshold (inclusive). */
#define BIP388_MAX_CONFUSION_SCORE ((uint64_t)100000)

/* A rendered cleartext line: a pointer into the caller's output buffer and a
 * byte length (not NUL-terminated). */
typedef struct Bip388Line {
  const uint8_t *ptr;
  size_t len;
} Bip388Line;

/* Minimum `arena` size (bytes) needed by the calls below for `template`.
 * On BIP388_OK, *out_size is set. */
int32_t bip388_min_arena_size(const uint8_t *tmpl, size_t tmpl_len,
                              size_t *out_size);

/* Parse `template` and write its confusion score to *out_score. */
int32_t bip388_confusion_score(const uint8_t *tmpl, size_t tmpl_len,
                               uint8_t *arena, size_t arena_len,
                               uint64_t *out_score);

/* Parse `template` and render its cleartext into `out`, recording one
 * Bip388Line per description in `lines` (capacity `max_lines`). On BIP388_OK,
 * *out_n_lines is the number of lines and *out_has_cleartext (if non-NULL) is
 * whether every part has a cleartext form. */
int32_t bip388_to_cleartext(const uint8_t *tmpl, size_t tmpl_len, uint8_t *arena,
                            size_t arena_len, uint8_t *out, size_t out_len,
                            Bip388Line *lines, size_t max_lines,
                            size_t *out_n_lines, bool *out_has_cleartext);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BIP388_H */
