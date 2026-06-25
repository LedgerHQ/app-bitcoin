#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Local headers */
#include "constants.h"

/**
 * Classification result for a sighash type.
 */
typedef enum {
    SIGHASH_CLASS_SAFE,        // SIGHASH_ALL or SIGHASH_DEFAULT (for segwit v1+)
    SIGHASH_CLASS_NON_SAFE,    // Non-standard but recognized (NONE, SINGLE, ANYONECANPAY|*)
    SIGHASH_CLASS_UNSUPPORTED  // Completely unsupported sighash type
} sighash_class_t;

/**
 * Classify a sighash type according to the security model:
 *
 * SAFE:
 *   - SIGHASH_DEFAULT (0x00) when segwit_version > 0 (Taproot)
 *   - SIGHASH_ALL (0x01)
 *
 * NON_SAFE (requires user opt-in via settings):
 *   - SIGHASH_NONE (0x02)
 *   - SIGHASH_SINGLE (0x03)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_ALL (0x81)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_NONE (0x82)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_SINGLE (0x83)
 *
 * UNSUPPORTED: everything else
 *
 * @param sighash_type    The PSBT_IN_SIGHASH_TYPE value
 * @param segwit_version  The segwit version of the input (-1 for legacy)
 * @return                The classification of the sighash type
 */
static inline sighash_class_t classify_sighash(uint32_t sighash_type, int segwit_version) {
    // SIGHASH_DEFAULT is only valid for Taproot (segwit v1+)
    if (((segwit_version > 0) && (sighash_type == SIGHASH_DEFAULT)) ||
        (sighash_type == SIGHASH_ALL)) {
        return SIGHASH_CLASS_SAFE;
    }

    if ((segwit_version >= 0) &&
        ((sighash_type == SIGHASH_NONE) || (sighash_type == SIGHASH_SINGLE) ||
         (sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_ALL)) ||
         (sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_NONE)) ||
         (sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE)))) {
        return SIGHASH_CLASS_NON_SAFE;
    }

    return SIGHASH_CLASS_UNSUPPORTED;
}

// False iff ANYONECANPAY is set (then others can add inputs, so the total input
// amount, and the fee, is unknown). Only valid for accepted sighash types.
static inline bool sighash_commits_all_inputs(uint32_t sighash_type) {
    return (sighash_type & SIGHASH_ANYONECANPAY) == 0;
}

// True only for base-type ALL (ALL, or DEFAULT on taproot); NONE/SINGLE leave the
// outputs (and our change) free to change after signing.
static inline bool sighash_commits_all_outputs(uint32_t sighash_type) {
    uint32_t base = sighash_type & ~(uint32_t) SIGHASH_ANYONECANPAY;
    return base == SIGHASH_ALL || base == SIGHASH_DEFAULT;
}

// What the transaction review can show, given the aggregate sighash commitment over
// the signed inputs and whether the amounts are trustworthy.
typedef enum {
    TX_DISPLAY_FULL,         // outputs + fee (and total_spent)
    TX_DISPLAY_SPENT_ONLY,   // total_spent only; fee unknown
    TX_DISPLAY_UNAVAILABLE,  // nothing about amounts/fee is reliable
} tx_display_mode_t;

static inline tx_display_mode_t decide_tx_display_mode(bool commits_all_inputs,
                                                       bool commits_all_outputs,
                                                       bool amounts_trustworthy) {
    if (!amounts_trustworthy || !commits_all_outputs) {
        return TX_DISPLAY_UNAVAILABLE;
    }
    return commits_all_inputs ? TX_DISPLAY_FULL : TX_DISPLAY_SPENT_ONLY;
}
