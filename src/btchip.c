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

#include "string.h"

#include "internal.h"

#include "bagl_extensions.h"

#include "segwit_addr.h"
#include "cashaddr.h"

#include "ux.h"
#include "display_variables.h"
#include "swap_lib_calls.h"

#include "handle_swap_sign_transaction.h"
#include "handle_get_printable_amount.h"
#include "handle_check_address.h"
#include "ui.h"
#include "lib_standard_app/format.h"
#include "read.h"
#include "write.h"
#include "bip32.h"
#include "swap.h"

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

unsigned char io_event(unsigned char channel) {
    UNUSED(channel);
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
#ifdef HAVE_NBGL
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;
#endif  // HAVE_NBGL

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif // HAVE_BAGL
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
        __attribute__((fallthrough));
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
        UX_DISPLAYED_EVENT({});
#endif // HAVE_BAGL
#ifdef HAVE_NBGL
        UX_DEFAULT_EVENT();
#endif // HAVE_NBGL
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        // TODO: found less hacky way to exit library after sending response
        // this mechanism is used for Swap/Exchange functionality
        // when application is in silent mode, and should return to caller,
        // after responding some APDUs
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

uint8_t check_fee_swap() {
    unsigned char fees[8];
    unsigned char borrow;

    borrow = transaction_amount_sub_be(
            fees, context_D.transactionContext.transactionAmount,
            context_D.totalOutputAmount);
    if ((borrow != 0) || (memcmp(fees, vars.swap_data.fees, 8) != 0))
        return 0;
    context_D.transactionContext.firstSigned = 0;

    if (context_D.usingSegwit &&  !context_D.segwitParsedOnce) {
        // This input cannot be signed when using segwit - just restart.
        context_D.segwitParsedOnce = 1;
        PRINTF("Segwit parsed once\n");
        context_D.transactionContext.transactionState =
        TRANSACTION_NONE;
    } else {
        context_D.transactionContext.transactionState =
        TRANSACTION_SIGN_READY;
    }
    context_D.sw = 0x9000;
    context_D.outLength = 0;
    G_io_apdu_buffer[context_D.outLength++] = 0x90;
    G_io_apdu_buffer[context_D.outLength++] = 0x00;

    return 1;
}

uint8_t prepare_fees(void) {
    if (context_D.transactionContext.relaxed) {
        memmove(vars.tmp.feesAmount, "UNKNOWN", 7);
        vars.tmp.feesAmount[7] = '\0';
    } else {
        unsigned char fees[8];
        unsigned short textSize;
        unsigned char borrow;

        borrow = transaction_amount_sub_be(
                fees, context_D.transactionContext.transactionAmount,
                context_D.totalOutputAmount);
        if (borrow && COIN_KIND == COIN_KIND_KOMODO) {
            memmove(vars.tmp.feesAmount, "REWARD", 6);
            vars.tmp.feesAmount[6] = '\0';
        }
        else {
            if (borrow) {
                PRINTF("Error : Fees not consistent");
                goto error;
            }
            memmove(vars.tmp.feesAmount, COIN_COINID_SHORT,
                       strlen(COIN_COINID_SHORT));
            vars.tmp.feesAmount[strlen(COIN_COINID_SHORT)] = ' ';
            context_D.tmp =
                (unsigned char *)(vars.tmp.feesAmount +
                              strlen(COIN_COINID_SHORT) + 1);
            textSize = convert_hex_amount_to_displayable(fees);
            vars.tmp.feesAmount[textSize + strlen(COIN_COINID_SHORT) + 1] =
                '\0';
        }
    }
    return 1;
error:
    return 0;
}

#define OMNI_ASSETID 1
#define MAIDSAFE_ASSETID 3
#define USDT_ASSETID 31

void get_address_from_output_script(unsigned char* script, int script_size, char* out, int out_size) {
    if (output_script_is_op_return(script)) {
        strncpy(out, "OP_RETURN", out_size);
        return;
    }
    if ((COIN_KIND == COIN_KIND_HYDRA) &&
        output_script_is_op_create(script, script_size)) {
        strncpy(out, "OP_CREATE", out_size);
        return;
    }
    if ((COIN_KIND == COIN_KIND_HYDRA) &&
        output_script_is_op_call(script, script_size)) {
        strncpy(out, "OP_CALL", out_size);
        return;
    }
    if (output_script_is_native_witness(script)) {
        if (COIN_NATIVE_SEGWIT_PREFIX) {
            segwit_addr_encode(
                out, (char *)PIC(COIN_NATIVE_SEGWIT_PREFIX), 0,
                script + OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET,
                script[OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET - 1]);
        }
        return;
    }
    unsigned char versionSize;
    unsigned char address[22];
    unsigned short textSize;
    int addressOffset = 3;
    unsigned short version = COIN_P2SH_VERSION;

    if (output_script_is_regular(script)) {
        addressOffset = 4;
        version = COIN_P2PKH_VERSION;
    }

    if (version > 255) {
        versionSize = 2;
        address[0] = (version >> 8);
        address[1] = version;
    } else {
        versionSize = 1;
        address[0] = version;
    }
    memmove(address + versionSize, script + addressOffset, 20);

    // Prepare address
    if (context_D.usingCashAddr) {
        cashaddr_encode(
            address + versionSize, 20, (uint8_t *)out, out_size,
            (version == COIN_P2SH_VERSION
                    ? CASHADDR_P2SH
                    : CASHADDR_P2PKH));
    } else {
        textSize = public_key_to_encoded_base58(
            address, 20 + versionSize, (unsigned char *)out,
            out_size, version, 1);
        out[textSize] = '\0';
    }
}

uint8_t prepare_single_output(void) {
    // TODO : special display for OP_RETURN
    unsigned char amount[8];
    unsigned int offset = 0;
    unsigned short textSize;
    char tmp[80] = {0};

    swap_bytes(amount, context_D.currentOutput + offset, 8);
    offset += 8;

    get_address_from_output_script(context_D.currentOutput + offset,  sizeof(context_D.currentOutput) - offset, tmp, sizeof(tmp));
    strncpy(vars.tmp.fullAddress, tmp, sizeof(vars.tmp.fullAddress) - 1);

    // Prepare amount

    // Handle Omni simple send
    if ((context_D.currentOutput[offset + 2] == 0x14) &&
        (memcmp(context_D.currentOutput + offset + 3, "omni", 4) == 0) &&
        (memcmp(context_D.currentOutput + offset + 3 + 4, "\0\0\0\0", 4) == 0)) {
            uint8_t headerLength;
            uint32_t omniAssetId = read_u32_be(context_D.currentOutput, offset + 3 + 4 + 4);
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
            headerLength = strlen(vars.tmp.fullAmount);
            context_D.tmp = (uint8_t *)vars.tmp.fullAmount + headerLength;
            textSize = convert_hex_amount_to_displayable(context_D.currentOutput + offset + 3 + 4 + 4 + 4);
            vars.tmp.fullAmount[textSize + headerLength] = '\0';
    }
    else {
        memmove(vars.tmp.fullAmount, COIN_COINID_SHORT,
               strlen(COIN_COINID_SHORT));
        vars.tmp.fullAmount[strlen(COIN_COINID_SHORT)] = ' ';
        context_D.tmp =
            (unsigned char *)(vars.tmp.fullAmount +
                          strlen(COIN_COINID_SHORT) + 1);
        textSize = convert_hex_amount_to_displayable(amount);
        vars.tmp.fullAmount[textSize + strlen(COIN_COINID_SHORT) + 1] =
            '\0';
    }

    return 1;
}

uint8_t prepare_message_signature(void) {
    uint8_t buffer[32];

    if (cx_hash_no_throw(&context_D.transactionHashAuthorization.header, CX_LAST,
            (uint8_t*)vars.tmp.fullAmount, 0, buffer, 32)) {
        return 0;
    }

    format_hex((const uint8_t*) buffer, sizeof(buffer), vars.tmp.fullAddress, sizeof(vars.tmp.fullAddress));

    return 1;
}


extern bool handle_output_state(void);
extern void apdu_hash_input_finalize_full_reset(void);

// Analog of bagl_confirm_single_output to work
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
        swap_bytes(amount, context_D.currentOutput, 8);
        if (memcmp(amount, vars.swap_data.amount, 8) != 0) {
            PRINTF("Amount not matched\n");
            return 0;
        }
        get_address_from_output_script(context_D.currentOutput + 8, sizeof(context_D.currentOutput) - 8, tmp, sizeof(tmp));
        if (strcmp(tmp, vars.swap_data.destination_address) != 0) {
            PRINTF("Address not matched\n");
            return 0;
        }

        // Check if all inputs have been confirmed

        if (context_D.outputParsingState ==
            OUTPUT_PARSING_OUTPUT) {
            context_D.remainingOutputs--;
            if (context_D.remainingOutputs == 0)
                break;
        }

        memmove(context_D.currentOutput,
                    context_D.currentOutput +
                        context_D.discardSize,
                    context_D.currentOutputOffset -
                        context_D.discardSize);
        context_D.currentOutputOffset -= context_D.discardSize;
        context_D.io_flags &= ~IO_ASYNCH_REPLY;
        while (handle_output_state() &&
                (!(context_D.io_flags & IO_ASYNCH_REPLY)))
            ;
        if (!(context_D.io_flags & IO_ASYNCH_REPLY)) {
            // Out of data to process, wait for the next call
            break;
        }
    }

    if ((context_D.outputParsingState == OUTPUT_PARSING_OUTPUT) &&
        (context_D.remainingOutputs == 0)) {
        context_D.outputParsingState = OUTPUT_FINALIZE_TX;
        // check fees
        unsigned char fees[8];

        if ((transaction_amount_sub_be(fees,
                                       context_D.transactionContext.transactionAmount,
                                       context_D.totalOutputAmount) != 0) ||
            (memcmp(fees, vars.swap_data.fees, 8) != 0)) {
            PRINTF("Fees is not matched\n");
            return 0;
        }
    }

    if (context_D.outputParsingState == OUTPUT_FINALIZE_TX) {
        context_D.transactionContext.firstSigned = 0;

        if (context_D.usingSegwit &&
            !context_D.segwitParsedOnce) {
            // This input cannot be signed when using segwit - just restart.
            context_D.segwitParsedOnce = 1;
            PRINTF("Segwit parsed once\n");
            context_D.transactionContext.transactionState =
                TRANSACTION_NONE;
        } else {
            context_D.transactionContext.transactionState =
                TRANSACTION_SIGN_READY;
        }
    }
    if (context_D.outputParsingState == OUTPUT_FINALIZE_TX) {
        // we've finished the processing of the input
        apdu_hash_input_finalize_full_reset();
    }

    return 1;
}

unsigned int bagl_confirm_single_output(void) {
    if (G_called_from_swap) {
        return silent_confirm_single_output();
    }
    if (!prepare_single_output()) {
        return 0;
    }

    ui_confirm_single_flow();
    return 1;
}

unsigned int bagl_finalize_tx(void) {
    if (G_called_from_swap) {
        return check_fee_swap();
    }

    if (!prepare_fees()) {
        return 0;
    }

    ui_finalize_flow();
    return 1;
}

void bagl_confirm_message_signature(void) {
    if (!prepare_message_signature()) {
        return;
    }

    ui_sign_message_flow();
}

uint8_t set_key_path_to_display(unsigned char* keyPath) {
    bip32_print_path(keyPath, vars.tmp_warning.derivation_path, MAX_DERIV_PATH_ASCII_LENGTH);
    return bip44_derivation_guard(keyPath, false);
}

void bagl_display_public_key(uint8_t is_derivation_path_unusual) {
    // append a white space at the end of the address to avoid glitch on nano S
    strlcat((char *)G_io_apdu_buffer + 200, " ", sizeof(G_io_apdu_buffer) - 200);

    if (is_derivation_path_unusual) {
        ui_display_public_with_warning_flow();
    }
    else {
        ui_display_public_flow();
    }
}

void bagl_display_token(void)
{
    ui_display_token_flow();
}

void bagl_request_pubkey_approval(void)
{
    ui_request_pubkey_approval_flow();
}

void bagl_request_change_path_approval(unsigned char* change_path)
{

    bip32_print_path(change_path, vars.tmp_warning.derivation_path, sizeof(vars.tmp_warning.derivation_path));
    ui_request_change_path_approval_flow();
}

void bagl_request_sign_path_approval(unsigned char* change_path)
{
    bip32_print_path(change_path, vars.tmp_warning.derivation_path, sizeof(vars.tmp_warning.derivation_path));
    ui_request_sign_path_approval_flow();
}

void bagl_request_segwit_input_approval(void)
{
    ui_request_segwit_input_approval_flow();
}


#include "os.h"

#include "internal.h"

#include "os_io_seproxyhal.h"

#include "apdu_constants.h"
#include "display_variables.h"

#include "handle_swap_sign_transaction.h"

#define TECHNICAL_NOT_IMPLEMENTED 0x99

#define COMMON_CLA               0xB0

void app_dispatch(void) {
    unsigned char cla;
    unsigned char ins;
    unsigned char dispatched;

    // nothing to reply for now
    context_D.outLength = 0;
    context_D.io_flags = 0;

    cla = G_io_apdu_buffer[ISO_OFFSET_CLA];
    ins = G_io_apdu_buffer[ISO_OFFSET_INS];
    for (dispatched = 0; dispatched < DISPATCHER_APDUS; dispatched++) {
        if ((cla == DISPATCHER_CLA[dispatched]) &&
                (ins == DISPATCHER_INS[dispatched])) {
            break;
        }
    }
    if (dispatched == DISPATCHER_APDUS) {
        context_D.sw = SW_INS_NOT_SUPPORTED;
        goto sendSW;
    }
    if (DISPATCHER_DATA_IN[dispatched]) {
        if (G_io_apdu_buffer[ISO_OFFSET_LC] == 0x00 ||
                context_D.inLength - 5 == 0) {
            context_D.sw = SW_INCORRECT_LENGTH;
            goto sendSW;
        }
        // notify we need to receive data
        // io_exchange(CHANNEL_APDU | IO_RECEIVE_DATA, 0);
    }
    // call the apdu handler
    context_D.sw = ((apduProcessingFunction)PIC(
                DISPATCHER_FUNCTIONS[dispatched]))();

    // an APDU has been replied. request for power off time extension from the
    // common ux
#ifdef IO_APP_ACTIVITY
    IO_APP_ACTIVITY();
#endif // IO_APP_ACTIVITY

sendSW:
    if (G_called_from_swap) {
        context_D.io_flags &= ~IO_ASYNCH_REPLY;
        if(context_D.sw != SW_OK) {
            vars.swap_data.should_exit = 1;
        }
    }
    // prepare SW after replied data
    G_io_apdu_buffer[context_D.outLength] =
        (context_D.sw >> 8);
    G_io_apdu_buffer[context_D.outLength + 1] =
        (context_D.sw & 0xff);
    context_D.outLength += 2;
    return;
}

void app_main(void) {
    context_init();

    ui_idle_flow();

    memset(G_io_apdu_buffer, 0, 255); // paranoia

    // Process the incoming APDUs

    // first exchange, no out length :) only wait the apdu
    context_D.outLength = 0;
    context_D.io_flags = 0;
    for (;;) {

        // memset(G_io_apdu_buffer, 0, 255); // paranoia

        if (G_called_from_swap && vars.swap_data.should_exit) {
            context_D.io_flags |= IO_RETURN_AFTER_TX;
        }

        // receive the whole apdu using the 7 bytes headers (ledger transport)
        context_D.inLength =
            io_exchange(CHANNEL_APDU | context_D.io_flags,
                        // use the previous outlength as the reply
                        context_D.outLength);

        if (G_called_from_swap && vars.swap_data.should_exit) {
            swap_finalize_exchange_sign_transaction(context_D.sw == SW_OK);
        }

        PRINTF("New APDU received:\n%.*H\n", context_D.inLength, G_io_apdu_buffer);

        app_dispatch();

        // reply during reception of next apdu
    }

    PRINTF("End of main loop\n");

    // in case reached
    reset();
}
