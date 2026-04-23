/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025, 2026 Ledger SAS.
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

#include <stdint.h>

/* Local headers */
#include "dispatcher.h"
#include "musig.h"
#include "sign_psbt.h"
#include "wallet.h"

// Struct to hold the info computed for a given input in either of the two rounds
typedef struct {
    plain_pk_t keys[MAX_PUBKEYS_PER_MUSIG];
    serialized_extended_pubkey_t agg_key_tweaked;
    uint8_t psbt_session_id[32];
    uint8_t tweaks[3][32];  // 2 or three tweaks
    size_t n_tweaks;        // always 2 or 3 for supported BIP-388 wallet policies
    bool is_xonly[3];       // 2 or 3 elements
} musig_per_input_info_t;

/**
 * Computes the MuSig2 per-input, per-key-expression information.
 *
 * This function calculates the necessary information for each input in the MuSig protocol.
 * It is the shared logic that is common between both rounds of the MuSig2 protocol.
 *
 * Returns true if the computation is successful, false otherwise. In case of failure, it already
 * sends an error status word.
 */
bool compute_musig_per_input_info(dispatcher_context_t *dc,
                                  sign_psbt_state_t *st,
                                  signing_state_t *signing_state,
                                  const input_info_t *input,
                                  const keyexpr_info_t *keyexpr_info,
                                  musig_per_input_info_t *out);

/**
 * Computes and yields the pubnonce for the current input and placeholder, during Round 1 of the
 * MuSig2 protocol.
 *
 * Returns true if the computation is successful, false otherwise. In case of failure, it already
 * sends an error status word.
 */
bool produce_and_yield_pubnonce(dispatcher_context_t *dc,
                                sign_psbt_state_t *st,
                                signing_state_t *signing_state,
                                const keyexpr_info_t *keyexpr_info,
                                const input_info_t *input,
                                unsigned int cur_input_index);

/**
 * Computes and yields the partial signature for a certain sighash, during Round 2 of the MuSig2
 * protocol.
 *
 * Returns true if the computation is successful, false otherwise. In case of failure, it already
 * sends an error status word.
 */
bool sign_sighash_musig_and_yield(dispatcher_context_t *dc,
                                  sign_psbt_state_t *st,
                                  signing_state_t *signing_state,
                                  const keyexpr_info_t *keyexpr_info,
                                  const input_info_t *input,
                                  unsigned int cur_input_index,
                                  uint8_t sighash[static 32]);
