/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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
********************************************************************************/
#include "os.h"
#include "cx.h"
#include "format.h"
#include "read.h"
#include "write.h"
#include "bip32.h"
#include "swap.h"
#include "string.h"


#include "context.h"
#include "helpers.h"
#include "customizable_helpers.h"
#include "customizable_ui.h"
#include "extensions.h"
#include "display_utils.h"
#include "ux.h"
#include "display_variables.h"
#include "swap_lib_calls.h"
#include "handle_swap_sign_transaction.h"
#include "handle_get_printable_amount.h"
#include "handle_check_address.h"
#include "ui.h"
#include "be_operations.h"

#define OMNI_ASSETID 1
#define MAIDSAFE_ASSETID 3
#define USDT_ASSETID 31

static uint8_t check_fee_swap() {
    unsigned char fees[8];
    unsigned char borrow;

    borrow = transaction_amount_sub_be(
            fees, context.transactionContext.transactionAmount,
            context.totalOutputAmount);
    if ((borrow != 0) || (memcmp(fees, vars.swap_data.fees, 8) != 0))
        return 0;
    context.transactionContext.firstSigned = 0;

    if (context.usingSegwit &&  !context.segwitParsedOnce) {
        // This input cannot be signed when using segwit - just restart.
        context.segwitParsedOnce = 1;
        PRINTF("Segwit parsed once\n");
        context.transactionContext.transactionState =
        TRANSACTION_NONE;
    } else {
        context.transactionContext.transactionState =
        TRANSACTION_SIGN_READY;
    }
    context.sw = 0x9000;
    context.outLength = 0;
    G_io_apdu_buffer[context.outLength++] = 0x90;
    G_io_apdu_buffer[context.outLength++] = 0x00;

    return 1;
}

#define OMNI_ASSETID 1
#define MAIDSAFE_ASSETID 3
#define USDT_ASSETID 31

static void prepare_single_output(void) {
    // TODO : special display for OP_RETURN
    unsigned char amount[8];
    unsigned int offset = 0;
    char tmp[80] = {0};

    swap_bytes(amount, context.currentOutput + offset, 8);
    offset += 8;

    get_address_from_output_script(context.currentOutput + offset,  sizeof(context.currentOutput) - offset, tmp, sizeof(tmp));
    strncpy(vars.tmp.fullAddress, tmp, sizeof(vars.tmp.fullAddress) - 1);

    // Prepare amount

    // Handle Omni simple send
    if ((context.currentOutput[offset + 2] == 0x14) &&
        (memcmp(context.currentOutput + offset + 3, "omni", 4) == 0) &&
        (memcmp(context.currentOutput + offset + 3 + 4, "\0\0\0\0", 4) == 0)) {
            uint32_t omniAssetId = read_u32_be(context.currentOutput, offset + 3 + 4 + 4);
            switch(omniAssetId) {
                case OMNI_ASSETID:
                    strcpy(vars.tmp.fullAmount, "OMNI ");
                    break;
                case USDT_ASSETID:
                    strcpy(vars.tmp.fullAmount, "USDT ");
                    break;
                case MAIDSAFE_ASSETID:
                    strcpy(vars.tmp.fullAmount, "MAID ");
                    break;
                default:
                    snprintf(vars.tmp.fullAmount, sizeof(vars.tmp.fullAmount), "OMNI asset %d ", omniAssetId);
                    break;
            }
            format_sats_amount(vars.tmp.fullAmount,
                    (uint64_t) read_u64_be(context.currentOutput, offset + 3 + 4 + 4 + 4), // Cast prevents weird compilo bug
                    vars.tmp.fullAmount);
    }
    else {
        format_sats_amount(COIN_COINID_SHORT,
                (uint64_t)read_u64_be(amount, 0),  // Cast prevents weird compilo bug
                vars.tmp.fullAmount);
    }
}

static uint8_t prepare_message_signature(void) {
    uint8_t buffer[32];

    if (cx_hash_no_throw(&context.transactionHashAuthorization.header, CX_LAST,
            (uint8_t*)vars.tmp.fullAmount, 0, buffer, 32)) {
        return 0;
    }

    format_hex((const uint8_t*) buffer, sizeof(buffer), vars.tmp.fullAddress, sizeof(vars.tmp.fullAddress));

    return 1;
}


extern int handle_output_state(unsigned int* processed);
extern void hash_input_finalize_full_reset(void);

// Analog of confirm_single_output to work
// in silent mode, when called from SWAP app
unsigned int silent_confirm_single_output() {
    char tmp[80] = {0};
    unsigned char amount[8];
    while (true) {
        // in swap operation we can only have 1 "external" output
        if (vars.swap_data.was_address_checked) {
            PRINTF("Address was already checked\n");
            return 0;
        }
        vars.swap_data.was_address_checked = 1;
        // check amount
        swap_bytes(amount, context.currentOutput, 8);
        if (memcmp(amount, vars.swap_data.amount, 8) != 0) {
            PRINTF("Amount not matched\n");
            return 0;
        }
        get_address_from_output_script(context.currentOutput + 8, sizeof(context.currentOutput) - 8, tmp, sizeof(tmp));
        if (strcmp(tmp, vars.swap_data.destination_address) != 0) {
            PRINTF("Address not matched\n");
            return 0;
        }

        // Check if all inputs have been confirmed

        if (context.outputParsingState ==
            OUTPUT_PARSING_OUTPUT) {
            context.remainingOutputs--;
            if (context.remainingOutputs == 0)
                break;
        }

        memmove(context.currentOutput,
                    context.currentOutput +
                        context.discardSize,
                    context.currentOutputOffset -
                        context.discardSize);
        context.currentOutputOffset -= context.discardSize;
        unsigned int processed = true;
        while (processed == 1) {
            if (handle_output_state(&processed)) {
                PRINTF("Error in handle output state \n");
                return 0;
            }
        }

        if (processed != 2) {
            // Out of data to process, wait for the next call
            break;
        }
    }

    if ((context.outputParsingState == OUTPUT_PARSING_OUTPUT) &&
        (context.remainingOutputs == 0)) {
        context.outputParsingState = OUTPUT_FINALIZE_TX;
        // check fees
        unsigned char fees[8];

        if ((transaction_amount_sub_be(fees,
                                       context.transactionContext.transactionAmount,
                                       context.totalOutputAmount) != 0) ||
            (memcmp(fees, vars.swap_data.fees, 8) != 0)) {
            PRINTF("Fees is not matched\n");
            return 0;
        }
    }

    if (context.outputParsingState == OUTPUT_FINALIZE_TX) {
        context.transactionContext.firstSigned = 0;

        if (context.usingSegwit &&
            !context.segwitParsedOnce) {
            // This input cannot be signed when using segwit - just restart.
            context.segwitParsedOnce = 1;
            PRINTF("Segwit parsed once\n");
            context.transactionContext.transactionState =
                TRANSACTION_NONE;
        } else {
            context.transactionContext.transactionState =
                TRANSACTION_SIGN_READY;
        }
    }
    if (context.outputParsingState == OUTPUT_FINALIZE_TX) {
        // we've finished the processing of the input
        hash_input_finalize_full_reset();
    }

    return 1;
}

unsigned int confirm_single_output(void) {
    if (G_called_from_swap) {
        if (silent_confirm_single_output()) {
            return 2;
        }
        return 0;
    }
    prepare_single_output();

    ui_confirm_single_flow();
    return 1;
}

unsigned int finalize_tx(void) {
    if (G_called_from_swap) {
        if (check_fee_swap()) {
            return 2;
        }
    }

    if (!prepare_fees()) {
        return 0;
    }

    ui_finalize_flow();
    return 1;
}

void confirm_message_signature(void) {
    if (!prepare_message_signature()) {
        return;
    }

    ui_sign_message_flow();
}

uint8_t set_key_path_to_display(const unsigned char* keyPath) {
    format_path(keyPath, vars.tmp_warning.derivation_path, sizeof(vars.tmp_warning.derivation_path));
    return bip44_derivation_guard(keyPath, false);
}

void display_public_key(uint8_t is_derivation_path_unusual) {
    // append a white space at the end of the address to avoid glitch on nano S
    strlcat((char *)G_io_apdu_buffer + 200, " ", sizeof(G_io_apdu_buffer) - 200);

    if (is_derivation_path_unusual) {
        ui_display_public_with_warning_flow();
    }
    else {
        ui_display_public_flow();
    }
}

void display_token(void)
{
    ui_display_token_flow();
}

void request_pubkey_approval(void)
{
    ui_request_pubkey_approval_flow();
}

void request_change_path_approval(unsigned char* change_path)
{
    format_path(change_path, vars.tmp_warning.derivation_path, sizeof(vars.tmp_warning.derivation_path));
    ui_request_change_path_approval_flow();
}

void request_sign_path_approval(unsigned char* change_path)
{
    format_path(change_path, vars.tmp_warning.derivation_path, sizeof(vars.tmp_warning.derivation_path));
    ui_request_sign_path_approval_flow();
}

void request_segwit_input_approval(void)
{
    ui_request_segwit_input_approval_flow();
}


