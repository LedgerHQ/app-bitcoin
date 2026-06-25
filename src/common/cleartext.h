#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Human-readable ("cleartext") rendering of a BIP-388 wallet-policy descriptor
 * template, used by the register-wallet flow.
 *
 * This is a thin wrapper over the vendored Rust binding in rust/bip388-c (see
 * rust/README.md): the actual parsing, classification and rendering all happen
 * in the audited Rust reference. This header deliberately does not pull in the
 * binding's header (bip388.h); the constants below are mirrored from it and
 * checked for agreement with a _Static_assert in cleartext.c.
 */

// Maximum confusion score for which the cleartext description should be shown.
// Mirrors BIP388_MAX_CONFUSION_SCORE.
#define CLEARTEXT_MAX_CONFUSION_SCORE 100000ULL

// Maximum number of cleartext lines we render: one primary/key-path line plus
// up to 8 tapleaf lines. A taproot tree with more leaves than this is rendered
// by the binding as more lines than fit; the wrapper then falls back to showing
// the raw descriptor template.
#define CT_MAX_LINES 9

// Maximum length of one rendered cleartext line, not counting the NUL.
#define CT_MAX_LINE_LEN 160

/**
 * Renders a descriptor template into cleartext spending-path lines.
 *
 * For non-taproot shapes (and key-path-only taproot) a single line is produced;
 * for a taproot with a script tree the first line describes the key-path policy
 * and each following line describes one leaf (in canonical display order).
 *
 * @param descriptor the raw descriptor template string, e.g. a wsh(sortedmulti(...)) template.
 * @param descriptor_len its length in bytes (not counting any NUL).
 * @param out_lines caller-owned buffer; rendered lines are written as
 *        NUL-terminated UTF-8 strings.
 * @param out_n_lines receives the number of lines written.
 * @param out_has_cleartext receives true iff every part of the descriptor was
 *        rendered through the cleartext path (false if some part has no
 *        cleartext form).
 * @param out_confusion_score receives the confusion score (an upper bound on
 *        the number of templates sharing this cleartext).
 * @return 1 if at least one line was written (outputs valid);
 *         0 if the descriptor failed to parse (no cleartext; show raw template);
 *        -1 on a capacity/internal error (e.g. a line exceeded CT_MAX_LINE_LEN,
 *           or the policy is too complex for the scratch arena).
 *         For any return value <= 0 the caller should fall back to showing the
 *         raw descriptor template.
 */
int cleartext_encode(const char *descriptor,
                     size_t descriptor_len,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext,
                     uint64_t *out_confusion_score);
