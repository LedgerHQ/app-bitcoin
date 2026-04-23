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

#include <stdint.h>
#include <string.h>

#include "process_in_outs.h"

/* Local headers */
#include "buffer.h"
#include "compare_wallet_script_at_path.h"
#include "constants.h"
#include "dispatcher.h"
#include "extract_bip32_derivation.h"
#include "psbt.h"

int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index,
    derivation_info_t *derivation_info) {
    uint8_t bip32_derivation_pubkey[33];

    bool is_tap = psbt_key_type == PSBT_IN_TAP_BIP32_DERIVATION ||
                  psbt_key_type == PSBT_OUT_TAP_BIP32_DERIVATION;
    int key_len = is_tap ? 32 : 33;

    if (!buffer_read_bytes(data,
                           bip32_derivation_pubkey,
                           key_len)  // read compressed pubkey or x-only pubkey
        || buffer_can_read(data, 1)  // ...but should not be able to read more
    ) {
        PRINTF("Unexpected pubkey length\n");
        return -1;
    }

    // get the corresponding value in the values Merkle tree,
    // then fetch the bip32 path from the field
    uint32_t fpt_der[1 + MAX_BIP32_PATH_STEPS];

    int der_len = extract_bip32_derivation(dc,
                                           psbt_key_type,
                                           map_commitment->values_root,
                                           map_commitment->size,
                                           index,
                                           fpt_der);
    if (der_len < 0) {
        PRINTF("Failed to read BIP32_DERIVATION\n");
        return -1;
    }

    if (der_len < 2 || der_len > MAX_BIP32_PATH_STEPS) {
        PRINTF("BIP32_DERIVATION path too long\n");
        return 0;
    }

    derivation_info->fingerprint = fpt_der[0];
    for (int i = 0; i < der_len; i++) {
        derivation_info->key_origin[i] = fpt_der[i + 1];
    }
    derivation_info->derivation_len = der_len;

    return 1;
}

bool is_keyexpr_compatible_with_derivation_info(const keyexpr_info_t *keyexpr_info,
                                                const derivation_info_t *derivation_info) {
    if (keyexpr_info->fingerprint != derivation_info->fingerprint) {
        return false;
    }
    if (keyexpr_info->psbt_root_key_derivation_length + 2 != derivation_info->derivation_len) {
        return false;
    }
    for (int i = 0; i < keyexpr_info->psbt_root_key_derivation_length; i++) {
        if (keyexpr_info->key_derivation[i] != derivation_info->key_origin[i]) {
            return false;
        }
    }
    uint32_t change_step = derivation_info->key_origin[derivation_info->derivation_len - 2];
    if (change_step != keyexpr_info->key_expression_ptr->num_first &&
        change_step != keyexpr_info->key_expression_ptr->num_second) {
        return false;
    }
    return true;
}

int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                       const sign_psbt_state_t *state,
                       sign_psbt_cache_t *sign_psbt_cache,
                       const in_out_info_t *in_out_info,
                       bool is_input) {
    // If we did not find any info about the pubkey associated to the key expression we're
    // considering, then it's external
    if (!in_out_info->key_expression_found) {
        return 0;
    }

    if (!is_input && in_out_info->is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         sign_psbt_cache,
                                         in_out_info->is_change,
                                         in_out_info->address_index,
                                         state->account.policy_map,
                                         state->account.wallet_header.version,
                                         state->account.wallet_header.keys_info_merkle_root,
                                         state->account.wallet_header.n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}
