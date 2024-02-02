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

#include "io.h"

#include "context.h"
#include "transaction.h"
#include "apdu_constants.h"
#include "extensions.h"
#include "swap.h"

#define P1_FIRST 0x00
#define P1_NEXT 0x80
#define P2_NEW 0x00
#define P2_NEW_SEGWIT 0x02
#define P2_NEW_SEGWIT_CASHADDR 0x03
#define P2_NEW_SEGWIT_OVERWINTER 0x04
#define P2_NEW_SEGWIT_SAPLING 0x05
#define P2_CONTINUE 0x80

#define IS_INPUT()                                        \
    (buffer->size - 1 > 8                                 \
     && buffer->size - 1 <= TRUSTED_INPUT_TOTAL_SIZE + 2  \
     && buffer->ptr[0] <= 0x02)                           \

#define IS_INPUT_TRUSTED()                           \
    (buffer->ptr[0] == 0x01                          \
     && buffer->ptr[1] == TRUSTED_INPUT_TOTAL_SIZE   \
     && buffer->ptr[2] == MAGIC_TRUSTED_INPUT        \
     && buffer->ptr[3] == 0x00)

WEAK unsigned short handler_hash_input_start(buffer_t* buffer, uint8_t p1, uint8_t p2) {
    if (p1 == P1_FIRST) {
        // Initialize
        context.transactionContext.transactionState =
            TRANSACTION_NONE;
        context.transactionHashOption = TRANSACTION_HASH_BOTH;
    } else if (p1 != P1_NEXT) {
        return io_send_sw(SW_INCORRECT_P1_P2);
    }

    if ((p2 == P2_NEW) ||
        (p2 == P2_NEW_SEGWIT) ||
        (p2 == P2_NEW_SEGWIT_CASHADDR) ||
        (p2 == P2_NEW_SEGWIT_OVERWINTER) ||
        (p2 == P2_NEW_SEGWIT_SAPLING)) {
        if (p1 == P1_FIRST) {
            unsigned char usingSegwit =
                (p2 == P2_NEW_SEGWIT) ||
                (p2 == P2_NEW_SEGWIT_CASHADDR) ||
                (p2 == P2_NEW_SEGWIT_OVERWINTER) ||
                (p2 == P2_NEW_SEGWIT_SAPLING);
            // Master transaction reset
            context.transactionContext.firstSigned = 1;
            context.transactionContext.consumeP2SH = 0;
            context.transactionContext.relaxed = 0;
            context.usingSegwit = usingSegwit;

            if (COIN_KIND == COIN_KIND_BITCOIN_CASH) {
                unsigned char usingCashAddr = (p2 == P2_NEW_SEGWIT_CASHADDR);
                context.usingCashAddr = usingCashAddr;
            }
            else {
                context.usingCashAddr = 0;
            }

            context.usingOverwinter = 0;
            if ((COIN_KIND == COIN_KIND_ZCASH) || (COIN_KIND == COIN_KIND_KOMODO) || (COIN_KIND == COIN_KIND_ZCLASSIC) || (COIN_KIND == COIN_KIND_RESISTANCE)) {
                if (p2 == P2_NEW_SEGWIT_OVERWINTER) {
                    context.usingOverwinter = ZCASH_USING_OVERWINTER;
                }
                else
                if (p2 == P2_NEW_SEGWIT_SAPLING) {
                    context.usingOverwinter = ZCASH_USING_OVERWINTER_SAPLING;
                }
            }
            context.overwinterSignReady = 0;
            context.segwitParsedOnce = 0;
            // Initialize for screen pairing
            memset(&context.tmpCtx.output, 0,
                      sizeof(context.tmpCtx.output));
            context.tmpCtx.output.changeAccepted = 1;
            // Reset segwitWarningSeen flag to prevent displaying the warning for each
            // segwit input when coontinuing from a previous session (P2=0x80)
            context.segwitWarningSeen = 0;
        }
    } else if (p2 != P2_CONTINUE) {
        return io_send_sw(SW_INCORRECT_P1_P2);
    }

    // In segwit mode, warn user one time only to update its client wallet...
    if (context.usingSegwit
        && !context.segwitWarningSeen
        && (p1 == P1_NEXT)
        && (p2 != P2_CONTINUE)
        // ...if input is not passed as a TrustedInput
        && IS_INPUT()
        && !IS_INPUT_TRUSTED())
    {
        if(G_called_from_swap){
            /* There is no point in displaying a warning when the app is signing
            in silent mode, as its UI is hidden behind the exchange app*/
            return io_send_sw(SW_SWAP_WITHOUT_TRUSTED_INPUTS);
        }
        context.segwitWarningSeen = 1;
        request_segwit_input_approval();
        // Start parsing of the 1st chunk
        context.transactionBufferPointer = (uint8_t*) buffer->ptr;
        context.transactionDataRemaining = buffer->size;

        transaction_parse(PARSE_MODE_SIGNATURE);
        return 0;
    }

    // Start parsing of the 1st chunk
    context.transactionBufferPointer = (uint8_t*) buffer->ptr;
    context.transactionDataRemaining = buffer->size;

    transaction_parse(PARSE_MODE_SIGNATURE);

    return io_send_response_pointer(G_io_apdu_buffer, context.outLength, SW_OK);
}
