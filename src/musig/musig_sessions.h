#pragma once

#include <stdbool.h>

/* Local headers */
#include "musig.h"

/**
 * This module encapsulates the logic to manage the psbt-level MuSig2 sessions. See the
 * documentation in docs/musig.md for more information.
 */

// the maximum number of musig sessions that are stored in permanent memory
#define MAX_N_MUSIG_SESSIONS 8

// state of a musig_psbt_session. Members are private and must not be accessed directly by any
// code outside of musig_sessions.c.
typedef struct musig_psbt_session_s {
    uint8_t _id[32];
    uint8_t _rand_root[32];
} musig_psbt_session_t;

// volatile state for musig signing. Members are private and must not be accessed directly by any
// code outside of musig_sessions.c.
//
// WARNING: an instance of this struct MUST NOT outlive the signing flow that uses it, and therefore
// MUST NOT be a global or static variable. The whole guarantee that a MuSig2 nonce is never reused
// rests on `_round2` being popped from the persistent storage exactly once and then discarded with
// the flow that popped it: reusing the same `_rand_root` to sign two different transactions would
// let an attacker recover the private key. Note that the psbt_session_id no longer depends on the
// transaction, so an `_round2` surviving into another flow would be accepted by
// musigsession_round2_initialize() rather than rejected.
typedef struct musig_signing_state_s {
    // a session created during round 1; if signing completes (and in no other case), it is moved to
    // the persistent storage
    musig_psbt_session_t _round1;
    // a session that was removed from the persistent storage before any partial signature is
    // returned during round 2. It is deleted at the end of signing, and must _never_ be used again.
    musig_psbt_session_t _round2;
} musig_signing_state_t;

/**
 * Given a musig psbt session, computes the synthetic randomness for a given
 * (input_index, placeholder_index) pair.
 *
 * @param[in]  psbt_session
 *   Pointer to the musig psbt session.
 * @param[in]  input_index
 *   The index of the input.
 * @param[in]  placeholder_index
 *   The index of the key placeholder.
 * @param[out] out
 *   Pointer to receive the synthetic randomness.
 */
void compute_rand_i_j(const musig_psbt_session_t *psbt_session,
                      int input_index,
                      int placeholder_index,
                      uint8_t out[static 32]);

/**
 * Make sure that the musig signing state is initialized correctly.
 *
 * This method must be called before musigsession_round1_initialize or
 * musigsession_round2_initialize are called in the code.
 *
 * This allows the calling code to not make any assumption about how
 * the initialization of the musig signing state is done.
 *
 * @param[in]  musig_signing_state
 *   Pointer to the musig signing state.
 */
void musigsession_initialize_signing_state(musig_signing_state_t *musig_signing_state);

/**
 * Handles the creation of a new musig psbt session into the volatile memory, or its retrieval (if
 * the session already exists).
 * It must be called when starting MuSig2 round 1 for a fixed input/placeholder pair, during the
 * signing process.
 *
 * @param[in]  psbt_session_id
 *   Pointer to the musig psbt session id.
 * @param[in]  musig_signing_state
 *   Pointer to the musig signing state.
 *
 * @return a musig_psbt_session_t on success, NULL on failure.
 */
__attribute__((warn_unused_result)) const musig_psbt_session_t *musigsession_round1_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state);

/**
 * Handles the retrieval of a musig psbt session from volatile memory (if it exists already) or its
 * retrieval from the persistent memory otherwise. The session is guaranteed to be deleted from the
 * persistent memory prior to returning.
 * It must be called when starting MuSig2 round 2 for a fixed input/placeholder pair, during the
 * signing process.
 *
 * @param[in]  psbt_session_id
 *   Pointer to the musig psbt session id.
 * @param[in]  musig_signing_state
 *   Pointer to the musig signing state.
 *
 * @return a musig_psbt_session_t on success, NULL on failure.
 */
__attribute__((warn_unused_result)) const musig_psbt_session_t *musigsession_round2_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state);

/**
 * If a session produced in round 1 is active in volatile memory, it is stored in the persistent
 * memory. The signing state is then zeroed out, as the signing flow is over.
 * This must be called at the end of a successful signing flow, after all the public nonces have
 * been returned to the client. It must _not_ be called if any error occurs, or if the signing
 * process is aborted for any reason.
 *
 * @param[in]  musig_signing_state
 *   Pointer to the musig signing state.
 */
void musigsession_commit(musig_signing_state_t *musig_signing_state);
