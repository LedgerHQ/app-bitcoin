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

#ifdef HAVE_SWAP

#include <stdint.h>
#include <string.h>

#include "swap_checks.h"

/* SDK headers */
#include "cx.h"
#include "swap.h"

/* Local headers */
#include "constants.h"
#include "dispatcher.h"
#include "error_codes.h"
#include "handle_swap_sign_transaction.h"
#include "script.h"
#include "swap/swap_globals.h"
#include "sw.h"

bool __attribute__((noinline))
execute_swap_checks(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Swap feature: check that wallet policy is a default one
    if (!st->account.is_default) {
        PRINTF("Must be a default wallet policy for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY);
        finalize_exchange_sign_transaction(false);
    }

    // No external inputs allowed
    if (st->n_external_inputs > 0) {
        PRINTF("External inputs not allowed in swap transactions\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS);
        finalize_exchange_sign_transaction(false);
    }

    if (st->warnings.missing_nonwitnessutxo || st->warnings.non_default_sighash) {
        // Do not allow transactions with missing non-witness utxos or non-default sighash flags
        PRINTF(
            "Missing non-witness utxo or non-default sighash flags are not allowed during swaps\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    // The index of the swap destination address in the cache of external outputs.
    // NB: this is _not_ the output index in the transaction, as change outputs are skipped.
    int swap_dest_idx = -1;

    if (G_swap_state.mode == SWAP_MODE_STANDARD) {
        swap_dest_idx = 0;

        // There must be only one external output
        if (st->n_external_outputs != 1) {
            PRINTF("Standard swap transaction must have exactly 1 external output\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_CROSSCHAIN) {
        // There must be exactly 2 external outputs; the first is the OP_RETURN

        swap_dest_idx = 1;

        if (st->n_external_outputs != 2) {
            PRINTF("Cross-chain swap transaction must have exactly 2 external outputs\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t *opreturn_script = st->outputs.output_scripts[0];
        size_t opreturn_script_len = st->outputs.output_script_lengths[0];
        uint64_t opreturn_amount = st->outputs.output_amounts[0];
        if (opreturn_script_len < 4 || opreturn_script[0] != OP_RETURN) {
            PRINTF("The first output must be OP_RETURN <data> for a cross-chain swap\n");
            SEND_SW_EC(dc,
                       SW_FAIL_SWAP,
                       EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t second_byte = opreturn_script[1];
        size_t push_opcode_size = 0;  // the length of the push opcode (1 or 2 bytes)
        size_t data_size = 0;  // the length of the actual data embedded in the OP_RETURN output
        if (2 <= second_byte && second_byte <= 75) {
            push_opcode_size = 1;
            data_size = second_byte;
        } else if (second_byte == OP_PUSHDATA1) {
            // pushing more than 75 bytes requires using OP_PUSHDATA1 <len>
            // instead of a single-byte opcode
            push_opcode_size = 2;
            data_size = opreturn_script[2];
        } else {
            // there are other valid OP_RETURN Scripts that we never expect here,
            // so we don't bother parsing.
            PRINTF("Unsupported or invalid OP_RETURN Script in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure there is a single data push
        if (opreturn_script_len != 1 + push_opcode_size + data_size) {
            PRINTF("Invalid OP_RETURN Script length in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure the output's value is 0
        if (opreturn_amount != 0) {
            PRINTF("OP_RETURN with non-zero value during cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT);
            finalize_exchange_sign_transaction(false);
        }

        // verify the hash in the data payload is the expected one
        uint8_t expected_payin_hash[32];
        cx_hash_sha256(&opreturn_script[1 + push_opcode_size], data_size, expected_payin_hash, 32);
        if (memcmp(G_swap_state.payin_extra_id + 1,
                   expected_payin_hash,
                   sizeof(expected_payin_hash)) != 0) {
            PRINTF("Mismatching payin hash in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_ERROR) {
        // an error was detected in handle_swap_sign_transaction.c::copy_transaction_parameters
        // special case only to improve error reporting in debug mode
        PRINTF("Invalid parameters for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED);
        finalize_exchange_sign_transaction(false);
    } else {
        PRINTF("Unknown swap mode: %d\n", G_swap_state.mode);
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE);
        finalize_exchange_sign_transaction(false);
    }

    LEDGER_ASSERT(0 <= swap_dest_idx && swap_dest_idx < N_CACHED_EXTERNAL_OUTPUTS,
                  "External output index out of range for swap\n");

    // Check that total amount and fees are as expected
    if (fee != G_swap_state.fees) {
        PRINTF("Mismatching fee for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_FEES);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t spent_amount = st->outputs.total_amount - st->outputs.change_total_amount;
    if (spent_amount != G_swap_state.amount) {
        PRINTF("Mismatching spent amount for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_AMOUNT);
        finalize_exchange_sign_transaction(false);
    }

    // Compute this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(st->outputs.output_scripts[swap_dest_idx],
                       st->outputs.output_script_lengths[swap_dest_idx],
                       output_description)) {
        PRINTF("Invalid or unsupported script for external output\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT);
        finalize_exchange_sign_transaction(false);
    }

    size_t output_description_len = strlen(output_description);

    // Check that the external output's address matches the request from app-exchange
    size_t swap_addr_len = strlen(G_swap_state.destination_address);
    if (swap_addr_len != output_description_len ||
        0 !=
            strncmp(G_swap_state.destination_address, output_description, output_description_len)) {
        // address did not match
        PRINTF("Mismatching address for swap\n");
        PRINTF("Expected: ");
        for (size_t i = 0; i < swap_addr_len; i++) {
            PRINTF("%c", G_swap_state.destination_address[i]);
        }
        PRINTF("\n");
        PRINTF("Found: ");
        for (size_t i = 0; i < output_description_len; i++) {
            PRINTF("%c", output_description[i]);
        }
        PRINTF("\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_DESTINATION);
        finalize_exchange_sign_transaction(false);
    }

    return true;
}

#endif /* HAVE_SWAP */
