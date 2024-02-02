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
#include "lib_standard_app/read.h"
#include "lib_standard_app/write.h"
#include "io.h"

#include "context.h"
#include "filesystem.h"
#include "transaction.h"
#include "apdu_constants.h"

#define GET_TRUSTED_INPUT_P1_FIRST 0x00
#define GET_TRUSTED_INPUT_P1_NEXT 0x80

WEAK unsigned short handler_get_trusted_input(buffer_t* buffer, uint8_t p1, uint8_t p2) {
    unsigned char dataOffset = 0;

    if (p1 == GET_TRUSTED_INPUT_P1_FIRST) {
        // Initialize
        context_D.transactionTargetInput =
            read_u32_be(buffer->ptr, 0);
        context_D.transactionContext.transactionState =
            TRANSACTION_NONE;
        context_D.trustedInputProcessed = 0;
        context_D.transactionContext.consumeP2SH = 0;
        dataOffset = 4;
        context_D.transactionHashOption = TRANSACTION_HASH_FULL;
        context_D.usingSegwit = 0;
        context_D.usingOverwinter = 0;
    } else if (p1 != GET_TRUSTED_INPUT_P1_NEXT) {
        return io_send_sw(SW_INCORRECT_P1_P2);
    }

    if (p2 != 0x00) {
        return io_send_sw(SW_INCORRECT_P1_P2);
    }

    context_D.transactionBufferPointer = (uint8_t* ) buffer->ptr + dataOffset;
    context_D.transactionDataRemaining = buffer->size - dataOffset;

    transaction_parse(PARSE_MODE_TRUSTED_INPUT);

    if (context_D.transactionContext.transactionState ==
        TRANSACTION_PARSED) {

        context_D.transactionContext.transactionState =
            TRANSACTION_NONE;
        if (!context_D.trustedInputProcessed) {
            // Output was not found
            return io_send_sw(SW_INCORRECT_DATA);
        }

        if (cx_hash_no_throw(&context_D.transactionHashFull.sha256.header, CX_LAST,
                NULL, 0, G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32)) {
            return io_send_sw(SW_TECHNICAL_PROBLEM);
        }

        // Otherwise prepare
        cx_rng(G_io_apdu_buffer, 8);
        G_io_apdu_buffer[0] = MAGIC_TRUSTED_INPUT;
        G_io_apdu_buffer[1] = 0x00;
        cx_hash_sha256(G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32, G_io_apdu_buffer + 4, 32);

        write_u32_le(G_io_apdu_buffer, 4 + 32,
                            context_D.transactionTargetInput);
        memmove(G_io_apdu_buffer + 4 + 32 + 4,
                   context_D.transactionContext.transactionAmount, 8);

        cx_hmac_sha256((uint8_t *)N_btchip.bkp.trustedinput_key,
                       sizeof(N_btchip.bkp.trustedinput_key), G_io_apdu_buffer,
                       TRUSTED_INPUT_SIZE, G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32);
        context_D.outLength = TRUSTED_INPUT_TOTAL_SIZE;
    }
    return io_send_response_pointer(G_io_apdu_buffer, context_D.outLength, SW_OK);
}
