/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Local headers */
#include "constants.h"  // LOCKTIME_THRESHOLD

/**
 * BIP-0370 "Determining Lock Time".
 *
 * A PSBTv2 has no nLockTime field: the value is *derived* from PSBT_GLOBAL_FALLBACK_LOCKTIME
 * together with each input's PSBT_IN_REQUIRED_TIME_LOCKTIME (0x11) and
 * PSBT_IN_REQUIRED_HEIGHT_LOCKTIME (0x12), by these rules:
 *
 *  - If no input declares a required lock time, the fallback is used (0 when it is absent).
 *  - Otherwise the fallback is IGNORED ENTIRELY. It is not a lower bound and it is not folded
 *    into the maximum. This is the rule that is easiest to get wrong.
 *  - Of the two types, the one used is the type that *every* input can accept. An input that
 *    declares neither field accepts both; one that declares both also accepts both. Only an input
 *    declaring exactly one of the two constrains the choice.
 *  - The value is then the maximum, over the inputs that declare it, of the chosen type.
 *  - When both types are acceptable to every input (because every input that declares a lock time
 *    declares both), the height is chosen. Bitcoin's unit of time is the block height, so in a
 *    tie a height makes more sense; what matters most is that every signer agrees, since the
 *    signatures commit to the value.
 *  - If one input accepts only heights and another accepts only times, no nLockTime satisfies all
 *    of them and the PSBT is invalid.
 *
 * The rules are folded one input at a time into a locktime_acc_t, so that a caller can accumulate
 * during a pass it already makes over the inputs and then resolve once, without holding per-input
 * state (there can be up to MAX_N_INPUTS_CAN_SIGN of those).
 *
 * This header performs no I/O: it is the whole decision procedure and nothing else, so it can be
 * tested directly against the BIP-0370 test vectors. See unit-tests/test_locktime.c.
 */

typedef enum {
    LOCKTIME_OK = 0,
    /** A declared required lock time is outside the range BIP-0370 allows for its field. */
    LOCKTIME_ERR_RANGE,
    /** Some input accepts only a height lock time while another accepts only a time lock time. */
    LOCKTIME_ERR_UNDETERMINED,
} locktime_status_t;

/** What a single input declares. The value of a field that is not declared is unused. */
typedef struct {
    bool has_time_locktime;    // PSBT_IN_REQUIRED_TIME_LOCKTIME is present
    uint32_t time_locktime;    // its value; meaningful only if has_time_locktime
    bool has_height_locktime;  // PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is present
    uint32_t height_locktime;  // its value; meaningful only if has_height_locktime
} locktime_input_t;

/**
 * Running state of the determination. Zero-initialization (`locktime_acc_t acc = {0};`) is the
 * correct "no input seen yet" state, so there is no init function to forget to call.
 */
typedef struct {
    uint32_t max_height;    // largest height lock time declared; meaningful iff any_height
    uint32_t max_time;      // largest time lock time declared; meaningful iff any_time
    bool any_height;        // some input declares a height lock time
    bool any_time;          // some input declares a time lock time
    bool height_only_seen;  // some input declares a height lock time and no time lock time
    bool time_only_seen;    // some input declares a time lock time and no height lock time
} locktime_acc_t;

/** A valid PSBT_IN_REQUIRED_HEIGHT_LOCKTIME is greater than 0 and less than 500000000. */
static inline bool locktime_height_in_range(uint32_t height_locktime) {
    return height_locktime > 0 && height_locktime < LOCKTIME_THRESHOLD;
}

/** A valid PSBT_IN_REQUIRED_TIME_LOCKTIME is at least 500000000. */
static inline bool locktime_time_in_range(uint32_t time_locktime) {
    return time_locktime >= LOCKTIME_THRESHOLD;
}

/**
 * Folds one input into `acc`.
 *
 * Returns LOCKTIME_ERR_RANGE, leaving `acc` untouched, if a declared value is out of range for its
 * field. BIP-0370 requires a height in [1, 499999999] and a time of at least 500000000, and lists
 * a PSBT carrying a height of 0 among its invalid vectors. The reason to hold the line at both
 * ends is that consensus reads an nLockTime below 500000000 as a height and anything else as a
 * timestamp: a value on the wrong side of that boundary does not mean what the field it sits in
 * says it means, and the app signs the lock time without ever showing it.
 *
 * A 0 is the one out-of-range value that is not ambiguous -- it constrains nothing, and 0 is also
 * the identity of the maximum -- so rejecting it is a choice for the spec over leniency. A client
 * that means "this input requires no lock time" must omit the field rather than write 0. Note that
 * HWI, and hence bitcoin_client/ledger_bitcoin, instead treat 0 as absent, so the two disagree on
 * such a PSBT: the app rejects it where the Python client resolves it to the fallback.
 *
 * Returns LOCKTIME_OK otherwise.
 */
static inline locktime_status_t locktime_acc_add_input(locktime_acc_t *acc,
                                                       const locktime_input_t *in) {
    if (in->has_height_locktime && !locktime_height_in_range(in->height_locktime)) {
        return LOCKTIME_ERR_RANGE;
    }
    if (in->has_time_locktime && !locktime_time_in_range(in->time_locktime)) {
        return LOCKTIME_ERR_RANGE;
    }

    if (in->has_height_locktime) {
        if (!acc->any_height || in->height_locktime > acc->max_height) {
            acc->max_height = in->height_locktime;
        }
        acc->any_height = true;
    }
    if (in->has_time_locktime) {
        if (!acc->any_time || in->time_locktime > acc->max_time) {
            acc->max_time = in->time_locktime;
        }
        acc->any_time = true;
    }

    if (in->has_height_locktime && !in->has_time_locktime) {
        acc->height_only_seen = true;
    }
    if (in->has_time_locktime && !in->has_height_locktime) {
        acc->time_only_seen = true;
    }

    return LOCKTIME_OK;
}

/**
 * Computes the nLockTime to sign, from the accumulated inputs and PSBT_GLOBAL_FALLBACK_LOCKTIME
 * (pass 0 when that field is absent).
 *
 * Returns LOCKTIME_ERR_UNDETERMINED, without writing `*out`, if the inputs disagree on the type of
 * lock time. Otherwise LOCKTIME_OK and `*out` holds the lock time.
 *
 * Each branch that reads a maximum is guarded by the flag that guarantees it was written, so
 * there is no uninitialized read to reason about across branches.
 */
static inline locktime_status_t locktime_acc_resolve(const locktime_acc_t *acc,
                                                     uint32_t fallback_locktime,
                                                     uint32_t *out) {
    if (acc->height_only_seen && acc->time_only_seen) {
        // one input accepts heights only, another times only: nothing satisfies both
        return LOCKTIME_ERR_UNDETERMINED;
    }

    if (acc->any_height && !acc->time_only_seen) {
        // every input accepts a height, and heights win whenever both types are acceptable
        *out = acc->max_height;
    } else if (acc->any_time) {
        // reaching here implies time_only_seen: had no input been time-only, every time-declaring
        // input would also declare a height and the branch above would have been taken
        *out = acc->max_time;
    } else {
        // no input declares a required lock time at all - the only case where the fallback applies
        *out = fallback_locktime;
    }
    return LOCKTIME_OK;
}
