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

    // If halted, then notify
    SB_CHECK(context_D.halted);
    if (SB_GET(context_D.halted)) {
        context_D.sw = SW_TECHNICAL_PROBLEM;
        goto sendSW;
    }

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
    if (context_D.called_from_swap) {
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
    memset(G_io_apdu_buffer, 0, 255); // paranoia

    // Process the incoming APDUs

    // first exchange, no out length :) only wait the apdu
    context_D.outLength = 0;
    context_D.io_flags = 0;
    for (;;) {

        // memset(G_io_apdu_buffer, 0, 255); // paranoia

        if (context_D.called_from_swap && vars.swap_data.should_exit) {
            context_D.io_flags |= IO_RETURN_AFTER_TX;
        }

        // receive the whole apdu using the 7 bytes headers (ledger transport)
        context_D.inLength =
            io_exchange(CHANNEL_APDU | context_D.io_flags,
                        // use the previous outlength as the reply
                        context_D.outLength);

        if (context_D.called_from_swap && vars.swap_data.should_exit) {
            finalize_exchange_sign_transaction(context_D.sw == SW_OK);
        }

        PRINTF("New APDU received:\n%.*H\n", context_D.inLength, G_io_apdu_buffer);

        app_dispatch();

        // reply during reception of next apdu
    }

    PRINTF("End of main loop\n");

    // in case reached
    reset();
}
