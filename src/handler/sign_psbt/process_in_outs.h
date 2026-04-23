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

#include "buffer.h"
#include "constants.h"
#include "dispatcher.h"
#include "get_merkleized_map.h"
#include "sign_psbt.h"
#include "sign_psbt_cache.h"

/**
 * Helpers shared between input and output preprocessing (and signing).
 * These manipulate the BIP32 derivation fields of PSBT inputs and outputs and
 * test whether an input/output is internal to the wallet account being signed.
 */

typedef struct {
    uint32_t fingerprint;
    size_t derivation_len;
    uint32_t key_origin[MAX_BIP32_PATH_STEPS];
} derivation_info_t;

/**
 * Convenience function to share common logic when parsing the
 * PSBT_{IN|OUT}_{TAP}?_BIP32_DERIVATION fields from inputs or outputs.
 *
 * @return -1 only on errors (causing signing to abort);
 *          1 if a match that might match the wallet policy is found;
 *          0 otherwise (not a match, but continue the signing flow).
 */
int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index,
    derivation_info_t *derivation_info);

bool is_keyexpr_compatible_with_derivation_info(const keyexpr_info_t *keyexpr_info,
                                                const derivation_info_t *derivation_info);

/**
 * Verifies if a certain input/output is internal (that is, controlled by the
 * wallet being used for signing).
 *
 * @return 1 if the given input/output is internal; 0 if external; -1 on error.
 */
int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                       const sign_psbt_state_t *state,
                       sign_psbt_cache_t *sign_psbt_cache,
                       const in_out_info_t *in_out_info,
                       bool is_input);
