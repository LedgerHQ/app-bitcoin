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

// Whether the input set is closed (no one can add inputs): true iff not ANYONECANPAY.
static inline bool sighash_input_set_closed(uint32_t sighash_type) {
    return (sighash_type & SIGHASH_ANYONECANPAY) == 0;
}

// Whether the output set is closed (no one can add/replace outputs): true only for base
// ALL/DEFAULT. Count-independent; feeds the "outputs open" flag (negative-fee check).
static inline bool sighash_output_set_closed(uint32_t sighash_type) {
    uint32_t base = sighash_type & ~(uint32_t) SIGHASH_ANYONECANPAY;
    return base == SIGHASH_ALL || base == SIGHASH_DEFAULT;
}

// Whether the signature commits to the outputs *present in this PSBT*: base ALL/DEFAULT
// always, or SINGLE with a single output. Unlocks SINGLE 1-in-1-out for NET_ONLY.
// Distinct from sighash_output_set_closed: with SINGLE + 1 output the output is committed,
// yet the set is still open (others can append outputs).
static inline bool sighash_commits_provided_outputs(uint32_t sighash_type,
                                                     unsigned int n_outputs) {
    uint32_t base = sighash_type & ~(uint32_t) SIGHASH_ANYONECANPAY;
    if (base == SIGHASH_ALL || base == SIGHASH_DEFAULT) {
        return true;
    }
    return base == SIGHASH_SINGLE && n_outputs == 1;
}

// What the transaction review can show, given the aggregate sighash commitment over
// the signed inputs and whether the amounts are trustworthy.
typedef enum {
    TX_DISPLAY_FULL,         // outputs + fee (and total_spent)
    TX_DISPLAY_NET_ONLY,   // total_spent only; fee unknown
    TX_DISPLAY_UNAVAILABLE,  // nothing about amounts/fee is reliable
} tx_display_mode_t;

// UNAVAILABLE if amounts untrusted or outputs not committed; FULL only if the fee is
// trustworthy too (whole input+output set fixed); else NET_ONLY (net exact, fee unknown).
static inline tx_display_mode_t decide_tx_display_mode(bool fee_trustworthy,
                                                       bool commits_all_outputs,
                                                       bool amounts_trustworthy) {
    if (!amounts_trustworthy || !commits_all_outputs) {
        return TX_DISPLAY_UNAVAILABLE;
    }
    return fee_trustworthy ? TX_DISPLAY_FULL : TX_DISPLAY_NET_ONLY;
}
