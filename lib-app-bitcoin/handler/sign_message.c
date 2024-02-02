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

#include "context.h"
#include "helpers.h"
#include "apdu_constants.h"
#include "extensions.h"
#include "lib_standard_app/read.h"
#include "swap.h"
#include "io.h"

#define P1_PREPARE 0x00
#define P1_SIGN 0x80
#define P2_LEGACY 0x00
#define P2_FIRST 0x01
#define P2_OTHER 0x80

#define BITID_NONE 0
#define BITID_POWERCYCLE 1
#define BITID_MULTIPLE 2

unsigned char const SIGNMAGIC[] = {' ', 'S', 'i', 'g', 'n', 'e', 'd', ' ', 'M',
                                   'e', 's', 's', 'a', 'g', 'e', ':', '\n'};

// TODO : support longer messages
unsigned char message_check_bit_id(unsigned char *bip32Path) {
    unsigned char i;
    unsigned char bip32PathLength = bip32Path[0];
    bip32Path++;
    for (i = 0; i < bip32PathLength; i++) {
        unsigned short account = read_u32_be(bip32Path, 0);
        bip32Path += 4;

        if (account == BITID_DERIVE) {
            return BITID_POWERCYCLE;
        }
        if (account == BITID_DERIVE_MULTIPLE) {
            return BITID_MULTIPLE;
        }
    }
    return BITID_NONE;
}

unsigned short message_compute_hash(void) {
    unsigned char hash[32];
    unsigned short sw = SW_OK;

    context.outLength = 0;
    if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, CX_LAST, hash,
                0, hash, 32)) {
        goto discard;
    }
            
    if (cx_hash_sha256(hash, sizeof(hash), hash, 32) == 0) {
        goto discard;
    }

    size_t out_len = 100;
    sign_finalhash(
            context.transactionSummary.keyPath,
            sizeof(context.transactionSummary.keyPath),
            hash, sizeof(hash), // IN
            G_io_apdu_buffer, &out_len);                        // OUT
    context.outLength = G_io_apdu_buffer[1] + 2;
            memset(&context.transactionSummary, 0,
                      sizeof(transaction_summary_t));
    return sw;

    discard: 
            sw = SW_TECHNICAL_PROBLEM_2;
            return sw;
}


static unsigned short sign_message_internal(buffer_t* buffer, uint8_t p1, uint8_t p2) {
    unsigned short sw = SW_OK;
    unsigned char apduLength = buffer->size;
    unsigned short offset = 0;

    if ((p1 != P1_PREPARE) && (p1 != P1_SIGN)) {
        return io_send_sw(SW_INCORRECT_P1_P2);
    }
    if (p1 == P1_PREPARE) {
        if ((p2 != P2_FIRST) && (p2 != P2_OTHER) && (p2 != P2_LEGACY)) {
            return io_send_sw(SW_INCORRECT_P1_P2);
        }
    }

    if (p1 == P1_PREPARE) {
        if ((p2 == P2_FIRST) || (p2 == P2_LEGACY)) {
            unsigned char chunkLength;
            unsigned char messageLength[3];
            unsigned char messageLengthSize;
            memset(&context.transactionSummary, 0,
                    sizeof(transaction_summary_t));
            if (buffer->ptr[0] > MAX_BIP32_PATH) {
                PRINTF("Invalid path\n");
                sw = SW_INCORRECT_DATA;
                goto discard;
            }
            context.transactionSummary.payToAddressVersion = COIN_P2PKH_VERSION;
            context.transactionSummary.payToScriptHashVersion = COIN_P2SH_VERSION;
            memmove(
                    context.transactionSummary.keyPath,
                    buffer->ptr, MAX_BIP32_PATH_LENGTH);
            offset += (4 * buffer->ptr[0]) + 1;
            if (p2 == P2_LEGACY) {
                context.transactionSummary.messageLength =
                    buffer->ptr[offset];
                offset++;
            } else {
                context.transactionSummary.messageLength =
                    (buffer->ptr[offset] << 8) |
                    (buffer->ptr[offset + 1]);
                offset += 2;
            }
            if (context.transactionSummary.messageLength ==
                    0) {
                PRINTF("Null message length\n");
                sw = SW_INCORRECT_DATA;
                goto discard;
            }
            context.hashedMessageLength = 0;

            // Horizen signed message magic header is "Zcash"
            // See https://github.com/HorizenOfficial/zen/blob/v5.0.0/src/main.cpp#L122
            const char* magicHeader = (COIN_KIND != COIN_KIND_HORIZEN) ? COIN_COINID : "Zcash";

            cx_sha256_init_no_throw(&context.transactionHashFull.sha256);
            cx_sha256_init_no_throw(&context.transactionHashAuthorization);

            chunkLength =
                strlen(magicHeader) + sizeof(SIGNMAGIC);
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        &chunkLength, 1, NULL, 0)) {
                goto discard;
            }
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        (uint8_t *)magicHeader,
                        strlen(magicHeader), NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        (unsigned char *)SIGNMAGIC, sizeof(SIGNMAGIC), NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            if (context.transactionSummary.messageLength <
                    0xfd) {
                messageLength[0] =
                    context.transactionSummary.messageLength;
                messageLengthSize = 1;
            } else {
                messageLength[0] = 0xfd;
                messageLength[1] =
                    (context.transactionSummary.messageLength &
                     0xff);
                messageLength[2] = ((context.transactionSummary
                            .messageLength >>
                            8) &
                        0xff);
                messageLengthSize = 3;
            }
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        messageLength, messageLengthSize, NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            chunkLength = apduLength - offset;
            if ((context.hashedMessageLength + chunkLength) >
                    context.transactionSummary.messageLength) {
                PRINTF("Invalid data length\n");
                sw = SW_INCORRECT_DATA;
                goto discard;
            }
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        buffer->ptr + offset, chunkLength, NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            if (cx_hash_no_throw(
                        &context.transactionHashAuthorization.header,
                        0, buffer->ptr + offset, chunkLength, NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            context.hashedMessageLength += chunkLength;
            G_io_apdu_buffer[0] = 0x00;
            if (context.hashedMessageLength ==
                    context.transactionSummary.messageLength) {
                G_io_apdu_buffer[1] = 0x00;
                context.outLength = 2;
            } else {
                context.outLength = 1;
            }
        } else {
            if ((context.hashedMessageLength + apduLength) >
                    context.transactionSummary.messageLength) {
                PRINTF("Invalid data length\n");
                sw = SW_INCORRECT_DATA;
                goto discard;
            }
            if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                        buffer->ptr + offset, apduLength, NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            if (cx_hash_no_throw(
                        &context.transactionHashAuthorization.header,
                        0, buffer->ptr + offset, apduLength, NULL, 0)) {
                sw = SW_TECHNICAL_PROBLEM_2;
                goto discard;
            }
            context.hashedMessageLength += apduLength;
            G_io_apdu_buffer[0] = 0x00;
            if (context.hashedMessageLength ==
                    context.transactionSummary.messageLength) {
                G_io_apdu_buffer[1] = 0x00;
                context.outLength = 2;
            } else {
                context.outLength = 1;
            }
        }
    } else {
        if ((context.transactionSummary.messageLength == 0) ||
                (context.hashedMessageLength !=
                 context.transactionSummary.messageLength)) {
            PRINTF("Invalid length to sign\n");
            sw = SW_INCORRECT_DATA;
            goto discard;
        }
        if (message_check_bit_id(context.transactionSummary.keyPath) != BITID_NONE) {
            sw = message_compute_hash();
        } else {
            confirm_message_signature();
            return 0;
        }
    }
    return io_send_response_pointer(G_io_apdu_buffer, context.outLength, sw);

    discard : 
        memset(&context.transactionSummary, 0,
                  sizeof(transaction_summary_t));
        return io_send_sw(sw);
}

WEAK unsigned short handler_sign_message(buffer_t* buffer, uint8_t p1, uint8_t p2) {
    if (G_called_from_swap) {
        return io_send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return sign_message_internal(buffer, p1, p2);
}

int user_action_message_signing(unsigned char confirming) {
    unsigned short sw;
    if (confirming) {
        sw = message_compute_hash();
        return io_send_response_pointer(G_io_apdu_buffer, context.outLength, sw);
    } else {
        context.outLength = 0;
        return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
}
