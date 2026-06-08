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

#include "preprocess_outputs.h"

/* SDK headers */
#include "read.h"

/* Local headers */
#include "bitvector.h"
#include "buffer.h"
#include "constants.h"
#include "dispatcher.h"
#include "error_codes.h"
#include "get_merkleized_map.h"
#include "get_merkleized_map_value.h"
#include "process_in_outs.h"
#include "psbt.h"
#include "sign_psbt_cache.h"
#include "sw.h"

/**
 * Callback to process all the keys of the current output map.
 */
static void output_keys_callback(dispatcher_context_t *dc,
                                 output_keys_callback_data_t *callback_data,
                                 const merkleized_map_commitment_t *map_commitment,
                                 int index,
                                 buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if ((key_type == PSBT_OUT_BIP32_DERIVATION || key_type == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !callback_data->output->in_out.key_expression_found) {
            derivation_info_t derivation_info;
            int res = read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                       key_type,
                                                                       data,
                                                                       map_commitment,
                                                                       index,
                                                                       &derivation_info);
            if (res < 0) {
                // there was an error; we keep track of it so an error SW is sent later
                callback_data->output->in_out.unexpected_pubkey_error = true;
            } else if (res == 1) {
                in_out_info_t *in_out = &callback_data->output->in_out;
                for (size_t i = 0; i < callback_data->state->account.n_internal_key_expressions;
                     i++) {
                    const keyexpr_info_t *key_expr =
                        &callback_data->state->account.internal_key_expressions[i];
                    if (is_keyexpr_compatible_with_derivation_info(key_expr, &derivation_info)) {
                        bool is_change =
                            key_expr->key_expression_ptr->num_second ==
                            derivation_info.key_origin[derivation_info.derivation_len - 2];

                        in_out->key_expression_found = true;
                        in_out->is_change = is_change;
                        in_out->address_index =
                            derivation_info.key_origin[derivation_info.derivation_len - 1];
                        // unlike for inputs, where we want to keep track of all the key expressions
                        // we want to sign for, here we only care about finding the relevant info
                        // for this output. Therefore, we're done as soon as we have a match.
                        break;
                    }
                }
            }
        }
    }
}

bool __attribute__((noinline)) preprocess_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    sign_psbt_cache_t *sign_psbt_cache,
    uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's internal (that is, a change address).
     *  Also computes the total amount of change outputs, and the total of all outputs.
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(&st->outputs, 0, sizeof(st->outputs));

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        output_info_t output;
        memset(&output, 0, sizeof(output));

        output_keys_callback_data_t callback_data = {.output = &output, .state = st};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->outputs_root,
            st->n_outputs,
            cur_output_index,
            (merkle_tree_elements_callback_t) output_keys_callback,
            &output.in_out.map);

        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (output.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // Read output amount
        uint8_t raw_result[8];

        // Read the output's amount
        int result_len = call_get_merkleized_map_value(dc,
                                                       &output.in_out.map,
                                                       (uint8_t[]) {PSBT_OUT_AMOUNT},
                                                       1,
                                                       raw_result,
                                                       sizeof(raw_result));
        if (result_len != 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t value = read_u64_le(raw_result, 0);

        if (value > BITCOIN_TOTAL_SUPPLY) {
            // sanity check to avoid overflows in amounts
            PRINTF("Output amount exceed Bitcoin total supply!\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.value = value;
        st->outputs.total_amount += value;

        // Read the output's scriptPubKey
        result_len = call_get_merkleized_map_value(dc,
                                                   &output.in_out.map,
                                                   (uint8_t[]) {PSBT_OUT_SCRIPT},
                                                   1,
                                                   output.in_out.scriptPubKey,
                                                   sizeof(output.in_out.scriptPubKey));

        if (result_len < 0 || result_len > (int) sizeof(output.in_out.scriptPubKey)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.in_out.scriptPubKey_len = result_len;

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &output.in_out, false);

        if (is_internal < 0) {
            PRINTF("Error checking if output %d is internal\n", cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            // external output, user needs to validate
            bitvector_set(internal_outputs, cur_output_index, 0);

            // cache external output scripts
            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                st->outputs.output_script_lengths[external_outputs_count] =
                    output.in_out.scriptPubKey_len;
                memcpy(st->outputs.output_scripts[external_outputs_count],
                       output.in_out.scriptPubKey,
                       output.in_out.scriptPubKey_len);
                st->outputs.output_amounts[external_outputs_count] = value;
            }

            ++external_outputs_count;
        } else {
            // valid change address, nothing to show to the user

            bitvector_set(internal_outputs, cur_output_index, 1);

            st->outputs.change_total_amount += output.value;
            ++st->outputs.n_change;
        }
    }

    st->n_external_outputs = external_outputs_count;

    if (st->inputs_total_amount < st->outputs.total_amount) {
        PRINTF("Negative fee is invalid\n");
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->outputs.n_change > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many outputs
        // (possibly economically not worth spending).
        PRINTF("Too many change outputs: %d\n", st->outputs.n_change);
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS);
        return false;
    }

    return true;
}
