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

#include <stdbool.h>
#include <stdint.h>

#include "bitvector.h"
#include "buffer.h"
#include "constants.h"
#include "dispatcher.h"
#include "get_merkleized_map.h"
#include "sign_psbt.h"
#include "sign_psbt_cache.h"

typedef struct {
    sign_psbt_state_t *state;
    input_info_t *input;
} input_keys_callback_data_t;

/**
 * Callback invoked for each key in the current input map. It records the
 * presence of relevant fields (witness/non-witness UTXO, redeem script,
 * sighash type, MuSig2 pub nonces) and, for BIP32 derivation keys, attempts
 * to match the derivation to one of the internal key expressions.
 */
void input_keys_callback(dispatcher_context_t *dc,
                         void *callback_data_ptr,
                         const merkleized_map_commitment_t *map_commitment,
                         int index,
                         buffer_t *data);

/**
 * Goes through all the inputs:
 * - verifies the non-witness utxo (if any);
 * - computes the total amount spent;
 * - detects internal inputs that should be signed;
 * - flags warnings for external inputs and unusual sighash types.
 *
 * Marks internal inputs in the `internal_inputs` bitvector.
 */
bool preprocess_inputs(dispatcher_context_t *dc,
                       sign_psbt_state_t *st,
                       sign_psbt_cache_t *sign_psbt_cache,
                       uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]);
