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

#include "transaction_display.h"

/* SDK headers */
#include "read.h"

/* Local headers */
#include "bitvector.h"
#include "constants.h"
#include "dispatcher.h"
#include "display.h"
#include "get_merkleized_map.h"
#include "get_merkleized_map_value.h"
#include "menu.h"
#include "psbt.h"
#include "script.h"
#include "sighash.h"
#include "sw.h"

static bool __attribute__((noinline)) display_output(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    int cur_output_index,
    int external_outputs_count,
    const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t out_scriptPubKey_len,
    uint64_t out_amount) {
    UNUSED(cur_output_index);

    // show this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(out_scriptPubKey, out_scriptPubKey_len, output_description)) {
        PRINTF("Invalid or unsupported script for output %d\n", cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    // Show address to the user
    if (!ui_transaction_streaming_validate_output(dc,
                                                  external_outputs_count,
                                                  st->n_external_outputs,
                                                  output_description,
                                                  out_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool get_output_script_and_amount(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    size_t output_index,
    uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t *out_scriptPubKey_len,
    uint64_t *out_amount) {
    if (out_scriptPubKey == NULL || out_amount == NULL) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    merkleized_map_commitment_t map;

    // TODO: This might be too slow, as it checks the integrity of the map;
    //       Refactor so that the map key ordering is checked all at the beginning of sign_psbt.
    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, output_index, &map);

    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read output amount
    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &map,
                                                   (uint8_t[]) {PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t value = read_u64_le(raw_result, 0);
    *out_amount = value;

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &map,
                                               (uint8_t[]) {PSBT_OUT_SCRIPT},
                                               1,
                                               out_scriptPubKey,
                                               MAX_OUTPUT_SCRIPTPUBKEY_LEN);

    if (result_len < 0 || result_len > MAX_OUTPUT_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    *out_scriptPubKey_len = result_len;

    return true;
}

static bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /**
     *  Display all the non-change outputs
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        if (!bitvector_get(internal_outputs, cur_output_index)) {
            // external output, user needs to validate
            uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            size_t out_scriptPubKey_len;
            uint64_t out_amount;

            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                // we have the output cached, no need to fetch it again
                out_scriptPubKey_len = st->outputs.output_script_lengths[external_outputs_count];
                memcpy(out_scriptPubKey,
                       st->outputs.output_scripts[external_outputs_count],
                       out_scriptPubKey_len);
                out_amount = st->outputs.output_amounts[external_outputs_count];
            } else if (!get_output_script_and_amount(dc,
                                                     st,
                                                     cur_output_index,
                                                     out_scriptPubKey,
                                                     &out_scriptPubKey_len,
                                                     &out_amount)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            ++external_outputs_count;

            // displays the output. It fails if the output is invalid or not supported
            if (!display_output(dc,
                                st,
                                cur_output_index,
                                external_outputs_count,
                                out_scriptPubKey,
                                out_scriptPubKey_len,
                                out_amount)) {
                return false;
            }
        }
    }

    return true;
}

static bool __attribute__((noinline)) display_warnings(dispatcher_context_t *dc,
                                                       sign_psbt_state_t *st) {
    // If any input has non-default sighash, we warn the user
    if (st->warnings.non_default_sighash && !ui_warn_nondefault_sighash(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If there are external inputs, it is unsafe to sign, therefore we warn the user
    if (st->warnings.external_inputs && !ui_warn_external_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If any segwitv0 input is missing the non-witness-utxo, we warn the user and ask for
    // confirmation
    if (st->warnings.missing_nonwitnessutxo && !ui_warn_unverified_segwit_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

bool __attribute__((noinline)) display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;
    int64_t total_spent =
        (int64_t) st->internal_inputs_total_amount - (int64_t) st->outputs.change_total_amount;

    // Default sighash => FULL. Non-default => show only what the signed inputs commit to.
    tx_display_mode_t mode = TX_DISPLAY_FULL;
    if (st->warnings.non_default_sighash) {
        if (st->sighash_mixed) {
            mode = TX_DISPLAY_UNAVAILABLE;  // signed inputs disagree: nothing coherent
        } else {
            // uniform non-default sighash never fixes the whole set => fee never trustworthy
            bool fee_trustworthy = false;
            bool outputs_committed =
                sighash_commits_provided_outputs(st->signed_sighash, st->n_outputs);
            bool amounts_trustworthy = !st->warnings.missing_nonwitnessutxo;
            mode =
                decide_tx_display_mode(fee_trustworthy, outputs_committed, amounts_trustworthy);
        }
    }

    tx_summary_t summary = {.mode = mode,
                            .fee = fee,
                            .total_spent = total_spent,
                            .signed_sighash = st->signed_sighash,
                            .sighash_mixed = st->sighash_mixed};

    // The account is the source (From) when net-spending, the destination (To) when
    // net-receiving, and neutral when the direction can't be trusted (UNAVAILABLE).
    account_role_t account_role = ACCOUNT_ROLE_FROM;
    if (mode == TX_DISPLAY_UNAVAILABLE) {
        account_role = ACCOUNT_ROLE_NEUTRAL;
    } else if (mode == TX_DISPLAY_SPENT_ONLY && total_spent < 0) {
        account_role = ACCOUNT_ROLE_TO;
    }

    /** INPUT VERIFICATION ALERTS
     *
     * Show warnings and allow users to abort in any of the following conditions:
     * - pre-taproot transaction with unverified inputs (missing non-witness-utxo)
     * - external inputs
     * - non-default sighash types
     */

    // high-fee warning only applies when we trust the fee
    st->warnings.high_fee = (mode == TX_DISPLAY_FULL) && (10 * fee >= st->inputs_total_amount &&
                                                          st->inputs_total_amount > 100000);

    // Display warnings/risks information before the transaction title
    // for the both classical and streaming cases.
    if (!display_warnings(dc, st)) {
        return false;
    }

    if (mode == TX_DISPLAY_UNAVAILABLE) {
        // Nothing reliable to show: no outputs/amounts, only a notice to confirm.
        ui_transaction_simplified_init(
            st->account.is_default ? NULL : st->account.wallet_header.name,
            0,
            st->warnings,
            account_role);
        ui_set_processing_screen_text(GA_SIGNING_TRANSACTION);
        if (!ui_transaction_simplified_show(dc, &summary)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
        return true;
    }

    if (st->n_external_outputs <= MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER) {
        // A simplified flow for most transactions: show it using the classical review if there is
        // exactly 0 (self-transfer) or <= MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER external outputs to show
        // to the user

        bool is_self_transfer = st->n_external_outputs == 0;

        // In SPENT_ONLY the account-level "You spend/receive" line already states the
        // amount; a "0 (self-transfer)" row would contradict a net-receive, so omit it.
        bool show_self_transfer_row = is_self_transfer && mode != TX_DISPLAY_SPENT_ONLY;

        /** TRANSACTION CONFIRMATION */
        /* Init*/
        ui_transaction_simplified_init(
            st->account.is_default ? NULL : st->account.wallet_header.name,
            is_self_transfer ? (show_self_transfer_row ? 1 : 0) : st->n_external_outputs,
            st->warnings,
            account_role);

        /* Adding outputs */
        if (!is_self_transfer) {
            for (unsigned int i = 0; i < st->n_external_outputs; i++) {
                char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];
                /* It is possible to return the following error in the middle of
                 * already shown screens of previous outputs
                 */
                if (!format_script(st->outputs.output_scripts[i],
                                   st->outputs.output_script_lengths[i],
                                   output_description)) {
                    PRINTF("Invalid or unsupported script for external output\n");
                    SEND_SW(dc, SW_NOT_SUPPORTED);
                    return false;
                }

                ui_transaction_simplified_add(st->outputs.output_amounts[i], output_description);
            }
        } else if (show_self_transfer_row) {
            ui_transaction_simplified_add(0, NULL);
        }

        /* Start the review */
        ui_set_processing_screen_text(GA_SIGNING_TRANSACTION);
        if (!ui_transaction_simplified_show(dc, &summary)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    } else {
        // Transactions with more than one external output; show one output per page,
        // using the streaming NBGL API.

        // If it's not a default wallet policy, let's save this info to ask the user for
        // confirmation
        ui_prepare_authorize_wallet_spend(
            !st->account.is_default ? st->account.wallet_header.name : NULL,
            account_role);

        // "Review transaction to send Bitcoin"
        if (!ui_transaction_streaming_prompt(dc)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }

        /** OUTPUTS CONFIRMATION
         *
         *  Display each non-change output, and transaction fees, and acquire user confirmation,
         */
        if (!display_external_outputs(dc, st, internal_outputs)) return false;

        /** TRANSACTION CONFIRMATION
         *
         *  Show summary info to the user (transaction fees), ask for final confirmation
         */
        // Show final user validation UI
        ui_set_processing_screen_text(GA_SIGNING_TRANSACTION);
        if (!ui_transaction_streaming_validate(dc, &summary, st->warnings, false)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }

    return true;
}
