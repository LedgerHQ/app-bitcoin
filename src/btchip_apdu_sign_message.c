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

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"

#define P1_PREPARE 0x00
#define P1_SIGN 0x80
#define P2_LEGACY 0x00
#define P2_FIRST 0x01
#define P2_OTHER 0x80

#define BITID_NONE 0
#define BITID_POWERCYCLE 1
#define BITID_MULTIPLE 2

//#define SLIP_13 0x8000000D

unsigned short btchip_compute_hash(void);

unsigned char checkBitId(unsigned char *bip32Path) {
    unsigned char i;
    unsigned char bip32PathLength = bip32Path[0];
    bip32Path++;
    /*
    if ((bip32PathLength != 0) && (btchip_read_u32(bip32Path, 1, 0) == SLIP_13))
    {
        return BITID_MULTIPLE;
    }
    */
    for (i = 0; i < bip32PathLength; i++) {
        unsigned short account = btchip_read_u32(bip32Path, 1, 0);
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

// TODO : support longer messages

unsigned short btchip_apdu_sign_message_internal() {
    unsigned short sw = BTCHIP_SW_OK;
    unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
    unsigned char p2 = G_io_apdu_buffer[ISO_OFFSET_P2];
    unsigned char apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];
    unsigned short offset = ISO_OFFSET_CDATA;

    if ((p1 != P1_PREPARE) && (p1 != P1_SIGN)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }
    if (p1 == P1_PREPARE) {
        if ((p2 != P2_FIRST) && (p2 != P2_OTHER) && (p2 != P2_LEGACY)) {
            return BTCHIP_SW_INCORRECT_P1_P2;
        }
    }

    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    if (p1 == P1_PREPARE) {
        if ((p2 == P2_FIRST) || (p2 == P2_LEGACY)) {
            unsigned char chunkLength;
            unsigned char messageLength[3];
            unsigned char messageLengthSize;
            memset(&btchip_context_D.transactionSummary, 0,
                    sizeof(btchip_transaction_summary_t));
            if (G_io_apdu_buffer[offset] > MAX_BIP32_PATH) {
                PRINTF("Invalid path\n");
                sw = BTCHIP_SW_INCORRECT_DATA;
                goto discard;
            }
            btchip_context_D.transactionSummary.payToAddressVersion =
                G_coin_config->p2pkh_version;
            btchip_context_D.transactionSummary.payToScriptHashVersion =
                G_coin_config->p2sh_version;
            memmove(
                    btchip_context_D.transactionSummary.keyPath,
                    G_io_apdu_buffer + offset, MAX_BIP32_PATH_LENGTH);
            offset += (4 * G_io_apdu_buffer[offset]) + 1;
            if (p2 == P2_LEGACY) {
                btchip_context_D.transactionSummary.messageLength =
                    G_io_apdu_buffer[offset];
                offset++;
            } else {
                btchip_context_D.transactionSummary.messageLength =
                    (G_io_apdu_buffer[offset] << 8) |
                    (G_io_apdu_buffer[offset + 1]);
                offset += 2;
            }
            if (btchip_context_D.transactionSummary.messageLength ==
                    0) {
                PRINTF("Null message length\n");
                sw = BTCHIP_SW_INCORRECT_DATA;
                goto discard;
            }
            btchip_context_D.hashedMessageLength = 0;
            if (cx_sha256_init_no_throw(&btchip_context_D.transactionHashFull.sha256)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            if (cx_sha256_init_no_throw(
                        &btchip_context_D.transactionHashAuthorization)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            // Horizen signed message magic header is "Zcash"
            // See https://github.com/HorizenOfficial/zen/blob/v5.0.0/src/main.cpp#L122
            const char* magicHeader = (G_coin_config->kind != COIN_KIND_HORIZEN) ? G_coin_config->coinid : "Zcash";
            chunkLength =
                strlen(magicHeader) + SIGNMAGIC_LENGTH;
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        &chunkLength, 1, NULL, 0)) {
                goto discard;
            }
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        (uint8_t *)magicHeader,
                        strlen(magicHeader), NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        (unsigned char *)SIGNMAGIC, SIGNMAGIC_LENGTH, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            if (btchip_context_D.transactionSummary.messageLength <
                    0xfd) {
                messageLength[0] =
                    btchip_context_D.transactionSummary.messageLength;
                messageLengthSize = 1;
            } else {
                messageLength[0] = 0xfd;
                messageLength[1] =
                    (btchip_context_D.transactionSummary.messageLength &
                     0xff);
                messageLength[2] = ((btchip_context_D.transactionSummary
                            .messageLength >>
                            8) &
                        0xff);
                messageLengthSize = 3;
            }
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        messageLength, messageLengthSize, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            chunkLength = apduLength - (offset - ISO_OFFSET_CDATA);
            if ((btchip_context_D.hashedMessageLength + chunkLength) >
                    btchip_context_D.transactionSummary.messageLength) {
                PRINTF("Invalid data length\n");
                sw = BTCHIP_SW_INCORRECT_DATA;
                goto discard;
            }
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        G_io_apdu_buffer + offset, chunkLength, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            if (cx_hash_no_throw(
                        &btchip_context_D.transactionHashAuthorization.header,
                        0, G_io_apdu_buffer + offset, chunkLength, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            btchip_context_D.hashedMessageLength += chunkLength;
            G_io_apdu_buffer[0] = 0x00;
            if (btchip_context_D.hashedMessageLength ==
                    btchip_context_D.transactionSummary.messageLength) {
                G_io_apdu_buffer[1] = 0x00;
                btchip_context_D.outLength = 2;
            } else {
                btchip_context_D.outLength = 1;
            }
        } else {
            if ((btchip_context_D.hashedMessageLength + apduLength) >
                    btchip_context_D.transactionSummary.messageLength) {
                PRINTF("Invalid data length\n");
                sw = BTCHIP_SW_INCORRECT_DATA;
                goto discard;
            }
            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                        G_io_apdu_buffer + offset, apduLength, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            if (cx_hash_no_throw(
                        &btchip_context_D.transactionHashAuthorization.header,
                        0, G_io_apdu_buffer + offset, apduLength, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discard;
            }
            btchip_context_D.hashedMessageLength += apduLength;
            G_io_apdu_buffer[0] = 0x00;
            if (btchip_context_D.hashedMessageLength ==
                    btchip_context_D.transactionSummary.messageLength) {
                G_io_apdu_buffer[1] = 0x00;
                btchip_context_D.outLength = 2;
            } else {
                btchip_context_D.outLength = 1;
            }
        }
    } else {
        if ((btchip_context_D.transactionSummary.messageLength == 0) ||
                (btchip_context_D.hashedMessageLength !=
                 btchip_context_D.transactionSummary.messageLength)) {
            PRINTF("Invalid length to sign\n");
            sw = BTCHIP_SW_INCORRECT_DATA;
            goto discard;
        }
        if (checkBitId(btchip_context_D.transactionSummary.keyPath) != BITID_NONE) {
            sw = btchip_compute_hash();
        } else {
            btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
            return BTCHIP_SW_OK;
        }
    }
    return sw;

    discard : 
        memset(&btchip_context_D.transactionSummary, 0,
                  sizeof(btchip_transaction_summary_t));
        return sw;
}

unsigned short btchip_apdu_sign_message() {
    if (btchip_context_D.called_from_swap) {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }
    unsigned short sw = btchip_apdu_sign_message_internal();
    if (btchip_context_D.io_flags & IO_ASYNCH_REPLY) {
        btchip_bagl_confirm_message_signature();
    }
    return sw;
}

unsigned short btchip_compute_hash() {
    unsigned char hash[32];
    unsigned short sw = BTCHIP_SW_OK;

    btchip_context_D.outLength = 0;
    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, CX_LAST, hash,
                0, hash, 32)) {
        goto discard;
    }
            
    if (cx_hash_sha256(hash, sizeof(hash), hash, 32) == 0) {
        goto discard;
    }

    size_t out_len = 100;
    btchip_sign_finalhash(
            btchip_context_D.transactionSummary.keyPath,
            sizeof(btchip_context_D.transactionSummary.keyPath),
            hash, sizeof(hash), // IN
            G_io_apdu_buffer, &out_len,                        // OUT
            ((N_btchip.bkp.config.options &
              BTCHIP_OPTION_DETERMINISTIC_SIGNATURE) != 0));
    btchip_context_D.outLength = G_io_apdu_buffer[1] + 2;
            memset(&btchip_context_D.transactionSummary, 0,
                      sizeof(btchip_transaction_summary_t));
    return sw;

    discard: 
            sw = SW_TECHNICAL_DETAILS(0x0F);
            return sw;
}

void btchip_bagl_user_action_message_signing(unsigned char confirming) {
    unsigned short sw;
    if (confirming) {
        sw = btchip_compute_hash();
    } else {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
}
