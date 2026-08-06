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
#include "constants.h"
#include "dispatcher.h"
#include "sign_psbt.h"
#include "sign_psbt_cache.h"

typedef struct {
    sign_psbt_state_t *state;
    output_info_t *output;
} output_keys_callback_data_t;

/**
 * For each output, checks if it's a change address and validates that it is
 * acceptable. Also computes the total amount of all outputs. Marks internal
 * outputs in the `internal_outputs` bitvector.
 */
bool preprocess_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    sign_psbt_cache_t *sign_psbt_cache,
    uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]);
