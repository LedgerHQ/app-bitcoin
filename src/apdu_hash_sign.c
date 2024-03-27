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
#include "display_variables.h"
#include "ui.h"
#include "ledger_assert.h"
#include "lib_standard_app/read.h"
#include "lib_standard_app/write.h"
#include "swap.h"

#define SIGHASH_ALL 0x01

#ifndef COIN_FORKID
#define COIN_FORKID 0
#endif 

unsigned short apdu_hash_sign() {
    unsigned long int lockTime;
    uint32_t sighashType;
    unsigned char dataBuffer[8];
    unsigned char authorizationLength;
    unsigned char *parameters = G_io_apdu_buffer + ISO_OFFSET_CDATA;
    unsigned short sw = SW_TECHNICAL_DETAILS(0xF);

    if ((G_io_apdu_buffer[ISO_OFFSET_P1] != 0) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] != 0)) {
        return SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < (1 + 1 + 4 + 1)) {
        return SW_INCORRECT_LENGTH;
    }

    // Zcash special - store parameters for later

    if ((context_D.usingOverwinter) &&
            (!context_D.overwinterSignReady) &&
            (context_D.segwitParsedOnce) &&
            (context_D.transactionContext.transactionState == TRANSACTION_NONE)) {
        unsigned long int expiryHeight;
        parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
        authorizationLength = *(parameters++);
        parameters += authorizationLength;
        lockTime = read_u32_be(parameters, 0);
        parameters += 4;
        sighashType = *(parameters++);
        expiryHeight = read_u32_be(parameters, 0);
        write_u32_le(context_D.nLockTime, 0, lockTime);
        write_u32_le(context_D.sigHashType, 0, sighashType);
        write_u32_le(context_D.nExpiryHeight, 0, expiryHeight);
        context_D.overwinterSignReady = 1;
        return SW_OK;
    }

    if (context_D.transactionContext.transactionState !=
            TRANSACTION_SIGN_READY) {
        PRINTF("Invalid transaction state %d\n", context_D.transactionContext.transactionState);
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
    }

    if (context_D.usingOverwinter && !context_D.overwinterSignReady) {
        PRINTF("Overwinter not ready to sign\n");
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
    }

    // Read parameters
    if (G_io_apdu_buffer[ISO_OFFSET_CDATA] > MAX_BIP32_PATH) {
        sw = SW_INCORRECT_DATA;
        goto discardTransaction;
    }
    memmove(context_D.transactionSummary.keyPath,
            G_io_apdu_buffer + ISO_OFFSET_CDATA,
            MAX_BIP32_PATH_LENGTH);
    parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
    authorizationLength = *(parameters++);
    parameters += authorizationLength;
    lockTime = read_u32_be(parameters, 0);
    parameters += 4;
    sighashType = *(parameters++);
    context_D.transactionSummary.sighashType = sighashType;

        // if bitcoin cash OR forkid is set, then use the fork id
    if (COIN_KIND == COIN_KIND_BITCOIN_CASH || (COIN_FORKID)) {
#define SIGHASH_FORKID 0x40
        if (sighashType != (SIGHASH_ALL | SIGHASH_FORKID)) {
            sw = SW_INCORRECT_DATA;
            goto discardTransaction;
        }
        sighashType |= (COIN_FORKID << 8);
    } else {
        if (sighashType != SIGHASH_ALL) {
            sw = SW_INCORRECT_DATA;
            goto discardTransaction;
        }
    }

    // Finalize the hash
    if (!context_D.usingOverwinter) {
        write_u32_le(dataBuffer, 0, lockTime);
        write_u32_le(dataBuffer, 4, sighashType);
        PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(dataBuffer), dataBuffer);
        if (cx_hash_no_throw(&context_D.transactionHashFull.sha256.header, 0,
                dataBuffer, sizeof(dataBuffer), NULL, 0)) {
            goto discardTransaction;
        }
    }

    // Check if the path needs to be enforced
    if (!enforce_bip44_coin_type(context_D.transactionSummary.keyPath, false)) {
        context_D.io_flags |= IO_ASYNCH_REPLY;
        bagl_request_sign_path_approval(context_D.transactionSummary.keyPath);
    }
    else {
        // Sign immediately
        bagl_user_action_signtx(1, 1);
    }
    sw = SW_OK;
    if (G_called_from_swap) {
        // if we signed all outputs we should exit,
        // but only after sending response, so lets raise the
        // vars.swap_data.should_exit flag and check it on timer later
        vars.swap_data.alreadySignedInputs++;
        if (vars.swap_data.alreadySignedInputs >= vars.swap_data.totalNumberOfInputs) {
            vars.swap_data.should_exit = 1;
        }
    }

    return sw;

    discardTransaction:
        context_D.transactionContext.transactionState = TRANSACTION_NONE;
        return sw;
}

void bagl_user_action_signtx(unsigned char confirming, unsigned char direct) {
    unsigned short sw = SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming) {
        unsigned char hash[32];
        if (context_D.usingOverwinter) {
            LEDGER_ASSERT(cx_hash_no_throw(&context_D.transactionHashFull.blake2b.header, CX_LAST, hash, 0, hash, 32) == CX_OK, "Hash Failed");
        }
        else {
            LEDGER_ASSERT(cx_hash_no_throw(&context_D.transactionHashFull.sha256.header, CX_LAST,
                hash, 0, hash, 32) == CX_OK, "Hash Failed");
            PRINTF("Hash1\n%.*H\n", sizeof(hash), hash);

            // Rehash
            cx_hash_sha256(hash, sizeof(hash), hash, 32);
        }
        PRINTF("Hash2\n%.*H\n", sizeof(hash), hash);
        // Sign
        size_t out_len = sizeof(G_io_apdu_buffer);
        sign_finalhash(
            context_D.transactionSummary.keyPath,
            sizeof(context_D.transactionSummary.keyPath),
            hash, sizeof(hash),
            G_io_apdu_buffer, &out_len,
            1);

        context_D.outLength = G_io_apdu_buffer[1] + 2;
        G_io_apdu_buffer[context_D.outLength++] = context_D.transactionSummary.sighashType;
        ui_transaction_finish();

    } else {
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        context_D.outLength = 0;
    }

    if (!direct) {
        G_io_apdu_buffer[context_D.outLength++] = sw >> 8;
        G_io_apdu_buffer[context_D.outLength++] = sw;

        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, context_D.outLength);
    }
}

