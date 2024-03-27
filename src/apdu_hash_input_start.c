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

#include "internal.h"
#include "apdu_constants.h"
#include "bagl_extensions.h"
#include "swap.h"

#define P1_FIRST 0x00
#define P1_NEXT 0x80
#define P2_NEW 0x00
#define P2_NEW_SEGWIT 0x02
#define P2_NEW_SEGWIT_CASHADDR 0x03
#define P2_NEW_SEGWIT_OVERWINTER 0x04
#define P2_NEW_SEGWIT_SAPLING 0x05
#define P2_CONTINUE 0x80

#define IS_INPUT()                                                          \
    (G_io_apdu_buffer[ISO_OFFSET_LC] - 1 > 8                                \
     && G_io_apdu_buffer[ISO_OFFSET_LC] - 1 <= TRUSTED_INPUT_TOTAL_SIZE + 2  \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA] <= 0x02)                         \

#define IS_INPUT_TRUSTED()                                                  \
    (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x01                             \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 1] == TRUSTED_INPUT_TOTAL_SIZE   \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 2] == MAGIC_TRUSTED_INPUT       \
     && G_io_apdu_buffer[ISO_OFFSET_CDATA + 3] == 0x00)

unsigned short apdu_hash_input_start() {
    unsigned char apduLength;
    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST) {
        // Initialize
        context_D.transactionContext.transactionState =
            TRANSACTION_NONE;
        context_D.transactionHashOption = TRANSACTION_HASH_BOTH;
    } else if (G_io_apdu_buffer[ISO_OFFSET_P1] != P1_NEXT) {
        return SW_INCORRECT_P1_P2;
    }

    if ((G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING)) {
        if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST) {
            unsigned char usingSegwit =
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) ||
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING);
            unsigned char usingCashAddr =
                (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_CASHADDR);
            // Master transaction reset
            context_D.transactionContext.firstSigned = 1;
            context_D.transactionContext.consumeP2SH = 0;
            context_D.transactionContext.relaxed = 0;
            context_D.usingSegwit = usingSegwit;
            context_D.usingCashAddr =
                (COIN_KIND == COIN_KIND_BITCOIN_CASH ? usingCashAddr
                                                               : 0);
            context_D.usingOverwinter = 0;
            if ((COIN_KIND == COIN_KIND_ZCASH) || (COIN_KIND == COIN_KIND_KOMODO) || (COIN_KIND == COIN_KIND_ZCLASSIC) || (COIN_KIND == COIN_KIND_RESISTANCE)) {
                if (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_OVERWINTER) {
                    context_D.usingOverwinter = ZCASH_USING_OVERWINTER;
                }
                else
                if (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW_SEGWIT_SAPLING) {
                    context_D.usingOverwinter = ZCASH_USING_OVERWINTER_SAPLING;
                }
            }
            context_D.overwinterSignReady = 0;
            context_D.segwitParsedOnce = 0;
            // Initialize for screen pairing
            memset(&context_D.tmpCtx.output, 0,
                      sizeof(context_D.tmpCtx.output));
            context_D.tmpCtx.output.changeAccepted = 1;
            // Reset segwitWarningSeen flag to prevent displaying the warning for each
            // segwit input when coontinuing from a previous session (P2=0x80)
            context_D.segwitWarningSeen = 0;
        }
    } else if (G_io_apdu_buffer[ISO_OFFSET_P2] != P2_CONTINUE) {
        return SW_INCORRECT_P1_P2;
    }

    // In segwit mode, warn user one time only to update its client wallet...
    if (context_D.usingSegwit
        && !context_D.segwitWarningSeen
        &&(G_io_apdu_buffer[ISO_OFFSET_P1] == P1_NEXT)
        && (G_io_apdu_buffer[ISO_OFFSET_P2] != P2_CONTINUE)
        // ...if input is not passed as a TrustedInput
        && IS_INPUT()
        && !IS_INPUT_TRUSTED())
    {
        if(G_called_from_swap){
            /* There is no point in displaying a warning when the app is signing
            in silent mode, as its UI is hidden behind the exchange app*/
            return SW_SWAP_WITHOUT_TRUSTED_INPUTS;
        }
        context_D.segwitWarningSeen = 1;
        context_D.io_flags |= IO_ASYNCH_REPLY;
        bagl_request_segwit_input_approval();
    }

    // Start parsing of the 1st chunk
    context_D.transactionBufferPointer =
        G_io_apdu_buffer + ISO_OFFSET_CDATA;
    context_D.transactionDataRemaining = apduLength;

    transaction_parse(PARSE_MODE_SIGNATURE);

    return SW_OK;
}
