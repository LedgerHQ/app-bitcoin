#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/wallet.h"
#include "common/cleartext_specs.h"

// Maximum confusion score below which the cleartext representation is shown.
#define CLEARTEXT_MAX_CONFUSION_SCORE 100000ULL

// Maximum number of cleartext lines we'll produce (1 primary spending path
// + up to CT_MAX_LINES-1 tapleaves).
#define CT_MAX_LINES 8

// Maximum length of one rendered cleartext line, not counting the NUL.
#define CT_MAX_LINE_LEN 160

/**
 * Computes the confusion score for a wallet policy descriptor.
 *
 * The confusion score is an upper bound on the number of structurally distinct
 * descriptor templates that share the same cleartext rendering. Uses
 * saturating-u64 arithmetic; returns UINT64_MAX on overflow.
 *
 * @param root pointer to the root of the parsed descriptor template
 * @return the confusion score
 */
uint64_t cleartext_confusion_score(const policy_node_t *root);

/**
 * Encodes a descriptor template into cleartext spending-path lines.
 *
 * For top-level shapes other than a taproot with a script tree (including a
 * leaf-less / key-path-only taproot), exactly one line is produced. For a
 * taproot with a tree, the first line is the key-path spending description
 * ("Main path: ..."), followed by one line per leaf (in canonical display
 * order). A leaf that has no cleartext form is rendered as the fixed
 * "(unknown)" marker — we don't have an unparser for descriptor templates,
 * so the leaf's own descriptor fragment cannot be printed — and
 * *out_has_cleartext is set to false. (Note: this differs from the reference
 * Rust implementation, whose unparser prints the raw leaf descriptor instead.)
 *
 * @param root pointer to the root of the parsed descriptor template
 * @param raw_template the original descriptor template string (used as
 *        fallback when classification fails or key derivations are
 *        non-canonical); may be NULL — in that case the function returns 0
 *        instead of writing a fallback line.
 * @param out_lines caller-owned buffer; rendered lines are written here as
 *        NUL-terminated strings.
 * @param out_n_lines receives the number of lines written.
 * @param out_has_cleartext receives true iff every part of the descriptor was
 *        rendered through the cleartext path.
 * @param out_class receives the matched top-level descriptor class when a
 *        cleartext rendering was produced, or DC_OTHER when the descriptor was
 *        unclassified or rendered via the raw-template fallback (non-canonical
 *        derivations). Must not be NULL.
 * @return 1 if at least one line was written; 0 if the descriptor classifies
 *         as Other and `raw_template` is NULL; -1 on internal error
 *         (e.g. a line did not fit in CT_MAX_LINE_LEN).
 */
int cleartext_encode(const policy_node_t *root,
                     const char *raw_template,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext,
                     descriptor_class_e *out_class);
