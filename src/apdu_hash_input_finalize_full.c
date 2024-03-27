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

// TODO Trustlet, BAGL : process each output separately.
// review nvm_write policy

#include "internal.h"
#include "apdu_constants.h"
#include "bagl_extensions.h"
#include "ui.h"
#include "lib_standard_app/crypto_helpers.h"

#define FINALIZE_P1_MORE 0x00
#define FINALIZE_P1_LAST 0x80
#define FINALIZE_P1_CHANGEINFO 0xFF

#define FINALIZE_P2_DEFAULT 0x00

#define FLAG_SIGNATURE 0x01
#define FLAG_CHANGE_VALIDATED 0x80

void apdu_hash_input_finalize_full_reset(void) {
    context_D.currentOutputOffset = 0;
    context_D.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
    memset(context_D.totalOutputAmount, 0,
              sizeof(context_D.totalOutputAmount));
    context_D.changeOutputFound = 0;
    set_check_internal_structure_integrity(1);
}

static bool check_output_displayable() {
    bool displayable = true;
    unsigned char amount[8], isOpReturn, isP2sh, isNativeSegwit, j,
        nullAmount = 1;
    unsigned char isOpCreate, isOpCall;

    for (j = 0; j < 8; j++) {
        if (context_D.currentOutput[j] != 0) {
            nullAmount = 0;
            break;
        }
    }
    if (!nullAmount) {
        swap_bytes(amount, context_D.currentOutput, 8);
        transaction_amount_add_be(context_D.totalOutputAmount,
                                  context_D.totalOutputAmount, amount);
    }
    isOpReturn =
        output_script_is_op_return(context_D.currentOutput + 8);
    isP2sh = output_script_is_p2sh(context_D.currentOutput + 8);
    isNativeSegwit = output_script_is_native_witness(
        context_D.currentOutput + 8);
    isOpCreate =
        output_script_is_op_create(context_D.currentOutput + 8,
          sizeof(context_D.currentOutput) - 8);
    isOpCall =
        output_script_is_op_call(context_D.currentOutput + 8,
          sizeof(context_D.currentOutput) - 8);
    if (((G_coin_config->kind == COIN_KIND_HYDRA) &&
         !output_script_is_regular(context_D.currentOutput + 8) &&
         !isP2sh && !(nullAmount && isOpReturn) && !isOpCreate && !isOpCall) ||
        (!(G_coin_config->kind == COIN_KIND_HYDRA) &&
         !output_script_is_regular(context_D.currentOutput + 8) &&
         !isP2sh && !(nullAmount && isOpReturn))) {
        PRINTF("Error : Unrecognized output script");
        THROW(EXCEPTION);
    }
    if (context_D.tmpCtx.output.changeInitialized && !isOpReturn) {
        bool changeFound = false;
        unsigned char addressOffset =
            (isNativeSegwit ? OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET
                            : isP2sh ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH
                                     : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
        if (!isP2sh &&
            memcmp(context_D.currentOutput + 8 + addressOffset,
                      context_D.tmpCtx.output.changeAddress,
                      20) == 0) {
            changeFound = true;
        } else if (isP2sh && context_D.usingSegwit) {
            unsigned char changeSegwit[22];
            changeSegwit[0] = 0x00;
            changeSegwit[1] = 0x14;
            memmove(changeSegwit + 2,
                       context_D.tmpCtx.output.changeAddress, 20);
            public_key_hash160(changeSegwit, 22, changeSegwit);
            if (memcmp(context_D.currentOutput + 8 + addressOffset,
                          changeSegwit, 20) == 0) {
                if (G_coin_config->flags & FLAG_SEGWIT_CHANGE_SUPPORT) {
                    changeFound = true;
                } else {
                    // Attempt to avoid fatal failures on Bitcoin Cash
                    PRINTF("Error : Non spendable Segwit change");
                    THROW(EXCEPTION);
                }
            }
        }
        if (changeFound) {
            if (context_D.changeOutputFound) {
                PRINTF("Error : Multiple change output found");
                THROW(EXCEPTION);
            }
            context_D.changeOutputFound = true;
            displayable = false;
        }
    }

    return displayable;
}

bool handle_output_state() {
    uint32_t discardSize = 0;
    context_D.discardSize = 0;
    bool processed = false;
    switch (context_D.outputParsingState) {
    case OUTPUT_PARSING_NUMBER_OUTPUTS: {
        context_D.totalOutputs = 0;
        if (context_D.currentOutputOffset < 1) {
            break;
        }
        if (context_D.currentOutput[0] < 0xFD) {
            context_D.totalOutputs = context_D.remainingOutputs =
                context_D.currentOutput[0];
            discardSize = 1;
            context_D.outputParsingState = OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        }
        if (context_D.currentOutput[0] == 0xFD) {
            if (context_D.currentOutputOffset < 3) {
                break;
            }
            context_D.totalOutputs = context_D.remainingOutputs =
                (context_D.currentOutput[2] << 8) |
                context_D.currentOutput[1];
            discardSize = 3;
            context_D.outputParsingState = OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        } else if (context_D.currentOutput[0] == 0xFE) {
            if (context_D.currentOutputOffset < 5) {
                break;
            }
            context_D.totalOutputs = context_D.remainingOutputs =
                read_u32(context_D.currentOutput + 1, 0, 0);
            discardSize = 5;
            context_D.outputParsingState = OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        } else {
            THROW(EXCEPTION);
        }
    } break;

    case OUTPUT_PARSING_OUTPUT: {
        unsigned int scriptSize;
        if (context_D.currentOutputOffset < 9) {
            break;
        }
        if (context_D.currentOutput[8] < 0xFD) {
            scriptSize = context_D.currentOutput[8];
            discardSize = 1;
        } else if (context_D.currentOutput[8] == 0xFD) {
            if (context_D.currentOutputOffset < 9 + 2) {
                break;
            }
            scriptSize =
                read_u32(context_D.currentOutput + 9, 0, 0);
            discardSize = 3;
        } else {
            // Unrealistically large script
            THROW(EXCEPTION);
        }
        if (context_D.currentOutputOffset <
            8 + discardSize + scriptSize) {
            discardSize = 0;
            break;
        }

        processed = true;

        discardSize += 8 + scriptSize;

        if (check_output_displayable()) {
            context_D.io_flags |= IO_ASYNCH_REPLY;

            // The output can be processed by the UI

            context_D.discardSize = discardSize;
            discardSize = 0;
        } else {
            context_D.remainingOutputs--;
        }
    } break;

    default:
        THROW(EXCEPTION);
    }

    if (discardSize != 0) {
        memmove(context_D.currentOutput,
                   context_D.currentOutput + discardSize,
                   context_D.currentOutputOffset - discardSize);
        context_D.currentOutputOffset -= discardSize;
    }

    return processed;
}

// out should be 32 bytes, even only 20 bytes is significant for output
int get_pubkey_hash160(unsigned char* keyPath, size_t keyPath_len, unsigned char* out) {
    cx_ecfp_public_key_t public_key;
    int keyLength;
    if (get_public_key(keyPath, keyPath_len, public_key.W, NULL)) {
        return -1;
    }
    if (((N_btchip.bkp.config.options &
            OPTION_UNCOMPRESSED_KEYS) != 0)) {
        keyLength = 65;
    } else {
        compress_public_key_value(public_key.W);
        keyLength = 33;
    }
    public_key_hash160(
        public_key.W,   // IN
        keyLength,      // INLEN
        out             // OUT
    );
    return 0;
}

unsigned short apdu_hash_input_finalize_full_internal(
    transaction_summary_t *transactionSummary) {
    unsigned char authorizationHash[32];
    unsigned char apduLength;
    unsigned short sw = SW_OK;
    unsigned char *target = G_io_apdu_buffer;
    unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
    unsigned char hashOffset = 0;

    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    if ((p1 != FINALIZE_P1_MORE) && (p1 != FINALIZE_P1_LAST) &&
        (p1 != FINALIZE_P1_CHANGEINFO)) {
        return SW_INCORRECT_P1_P2;
    }

    // See if there is a hashing offset
    if (context_D.usingSegwit &&
        (context_D.tmpCtx.output.multipleOutput == 0)) {
        unsigned char firstByte = G_io_apdu_buffer[ISO_OFFSET_CDATA];
        if (firstByte < 0xfd) {
            hashOffset = 1;
        } else if (firstByte == 0xfd) {
            hashOffset = 3;
        } else if (firstByte == 0xfe) {
            hashOffset = 5;
        }
    }

    // Check state
    set_check_internal_structure_integrity(0);
    if (context_D.transactionContext.transactionState !=
            TRANSACTION_PRESIGN_READY) {
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
    }

    if (p1 == FINALIZE_P1_CHANGEINFO) {
        if (!context_D.transactionContext.firstSigned) {
            // Already validated, should be prevented on the client side
return_OK:
            return SW_OK;
        }
        if (!context_D.tmpCtx.output.changeAccepted) {
            sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
            goto discardTransaction;
        }
        memset(transactionSummary, 0,
                sizeof(transaction_summary_t));
        if (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x00) {
            // Called with no change path, abort, should be prevented on
            // the client side
            goto return_OK;
        }
        memmove(transactionSummary->keyPath,
                G_io_apdu_buffer + ISO_OFFSET_CDATA,
                MAX_BIP32_PATH_LENGTH);

        if (get_pubkey_hash160(transactionSummary->keyPath, sizeof(transactionSummary->keyPath), context_D.tmpCtx.output.changeAddress)) {
            sw = SW_TECHNICAL_DETAILS(0x0F);
            goto discardTransaction;
        }
        PRINTF("Change address = %.*H\n", 20, context_D.tmpCtx.output.changeAddress);

        context_D.tmpCtx.output.changeInitialized = 1;
        context_D.tmpCtx.output.changeAccepted = 0;

        // if the bip44 change path provided is not canonical or its index are unsual, ask for user approval
        if(bip44_derivation_guard(transactionSummary->keyPath, true)) {
            if (context_D.called_from_swap) {
                PRINTF("In swap mode only standart path is allowed\n");
                sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }
            context_D.io_flags |= IO_ASYNCH_REPLY;
            context_D.outputParsingState = BIP44_CHANGE_PATH_VALIDATION;
            bagl_request_change_path_approval(transactionSummary->keyPath);
        }

        goto return_OK;
    }

    // Always update the transaction & authorization hashes with the
    // given data
    // For SegWit, this has been reset to hold hashOutputs
    if (!context_D.segwitParsedOnce) {
        if ((int)(apduLength - hashOffset) < 0) {
            sw = SW_INCORRECT_DATA;
            goto discardTransaction;
        }
        if (context_D.usingOverwinter) {
            if (cx_hash_no_throw(&context_D.transactionHashFull.blake2b.header, 0, G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset, apduLength - hashOffset, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discardTransaction;
            }
        }
        else {
            PRINTF("--- ADD TO HASH FULL:\n%.*H\n", apduLength - hashOffset, G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset);
            if (cx_hash_no_throw(&context_D.transactionHashFull.sha256.header, 0,
                        G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset,
                        apduLength - hashOffset, NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discardTransaction;
            }
        }
    }

    if (context_D.transactionContext.firstSigned) {
        if ((context_D.currentOutputOffset + apduLength) >
                sizeof(context_D.currentOutput)) {
            PRINTF("Output is too long to be checked\n");
            sw = SW_INCORRECT_DATA;
            goto discardTransaction;
        }
        memmove(context_D.currentOutput +
                context_D.currentOutputOffset,
                G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength);
        context_D.currentOutputOffset += apduLength;

        while (handle_output_state() &&
                (!(context_D.io_flags & IO_ASYNCH_REPLY)))
            ;

        // Finalize the TX if necessary

        if ((context_D.remainingOutputs == 0) &&
                (!(context_D.io_flags & IO_ASYNCH_REPLY))) {
            context_D.io_flags |= IO_ASYNCH_REPLY;
            context_D.outputParsingState =
                OUTPUT_FINALIZE_TX;
        }
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == FINALIZE_P1_MORE) {
        if (!context_D.usingSegwit) {
            PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", apduLength, G_io_apdu_buffer + ISO_OFFSET_CDATA);
            if (cx_hash_no_throw(
                        &context_D.transactionHashAuthorization.header,
                        0, G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength,
                        NULL, 0)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discardTransaction;
            }
        }
        G_io_apdu_buffer[0] = 0x00;
        context_D.outLength = 1;
        context_D.tmpCtx.output.multipleOutput = 1;
        goto return_OK;
    }

    if (!context_D.usingSegwit) {
        PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", apduLength, G_io_apdu_buffer + ISO_OFFSET_CDATA);
        if (cx_hash_no_throw(&context_D.transactionHashAuthorization.header,
                    CX_LAST, G_io_apdu_buffer + ISO_OFFSET_CDATA,
                    apduLength, authorizationHash, 32)) {
            sw = SW_TECHNICAL_DETAILS(0x0F);
            goto discardTransaction;
        }
    }

    if (context_D.usingSegwit) {
        if (!context_D.segwitParsedOnce) {
            if (context_D.usingOverwinter) {
                if (cx_hash_no_throw(&context_D.transactionHashFull.blake2b.header, CX_LAST, context_D.segwit.cache.hashedOutputs, 0, context_D.segwit.cache.hashedOutputs, 32)) {
                    sw = SW_TECHNICAL_DETAILS(0x0F);
                    goto discardTransaction;
                }
            }
            else {
                if (cx_hash_no_throw(&context_D.transactionHashFull.sha256.header,
                            CX_LAST,
                            context_D.segwit.cache.hashedOutputs, 0,
                            context_D.segwit.cache.hashedOutputs, 32)) {
                    sw = SW_TECHNICAL_DETAILS(0x0F);
                    goto discardTransaction;
                }
                if (cx_sha256_init_no_throw(&context_D.transactionHashFull.sha256)) {
                    sw = SW_TECHNICAL_DETAILS(0x0F);
                    goto discardTransaction;
                }
                if (cx_hash_no_throw(&context_D.transactionHashFull.sha256.header,
                            CX_LAST,
                            context_D.segwit.cache.hashedOutputs,
                            sizeof(context_D.segwit.cache.hashedOutputs),
                            context_D.segwit.cache.hashedOutputs, 32)) {
                    sw = SW_TECHNICAL_DETAILS(0x0F);
                    goto discardTransaction;
                }
            }
            PRINTF("hashOutputs\n%.*H\n",32,context_D.segwit.cache.hashedOutputs);
            if (cx_hash_no_throw(
                        &context_D.transactionHashAuthorization.header,
                        CX_LAST, G_io_apdu_buffer, 0, authorizationHash, 32)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discardTransaction;
            }
            PRINTF("Auth Hash:\n%.*H\n", 32, authorizationHash);
        } else {
            if (cx_hash_no_throw(
                        &context_D.transactionHashAuthorization.header,
                        CX_LAST,
                        (unsigned char *)&context_D.segwit.cache,
                        sizeof(context_D.segwit.cache),
                        authorizationHash, 32)) {
                sw = SW_TECHNICAL_DETAILS(0x0F);
                goto discardTransaction;
            }
            PRINTF("Auth Hash:\n%.*H\n", 32, authorizationHash);
        }
    }

    if (context_D.transactionContext.firstSigned) {
        if (!context_D.tmpCtx.output.changeInitialized) {
            memset(transactionSummary, 0,
                    sizeof(transaction_summary_t));
        }

        transactionSummary->payToAddressVersion =
            G_coin_config->p2pkh_version;
        transactionSummary->payToScriptHashVersion =
            G_coin_config->p2sh_version;

        // Generate new nonce

        cx_rng(transactionSummary->transactionNonce, 8);
    }

    G_io_apdu_buffer[0] = 0x00;
    target++;

    *target = 0x00;
    target++;

    context_D.outLength = (target - G_io_apdu_buffer);

    // Check that the input being signed is part of the same
    // transaction, otherwise abort
    // (this is done to keep the transaction counter limit per session
    // synchronized)
    if (context_D.transactionContext.firstSigned) {
        memmove(transactionSummary->authorizationHash,
                authorizationHash,
                sizeof(transactionSummary->authorizationHash));
        goto return_OK;
    } else {
        if (secure_memcmp(
                    authorizationHash,
                    transactionSummary->authorizationHash,
                    sizeof(transactionSummary->authorizationHash))) {
            PRINTF("Authorization hash not matching, aborting\n");
            sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
            goto discardTransaction;
        }

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
        sw = SW_OK;
    }
    apdu_hash_input_finalize_full_reset();
    return sw;

discardTransaction:
    apdu_hash_input_finalize_full_reset();
    ui_transaction_error();
    context_D.transactionContext.transactionState =
        TRANSACTION_NONE;
    context_D.outLength = 0;

    memmove(G_io_apdu_buffer, context_D.currentOutput,
            context_D.currentOutputOffset);
    context_D.outLength = context_D.currentOutputOffset;
    return sw;
}

unsigned short apdu_hash_input_finalize_full() {
    PRINTF("state=%d\n", context_D.outputParsingState);
    unsigned short sw = apdu_hash_input_finalize_full_internal(
        &context_D.transactionSummary);
    if (context_D.io_flags & IO_ASYNCH_REPLY) {
        // if the UI reject the processing of the request, then reply
        // immediately
        bool status;
        if(context_D.outputParsingState == BIP44_CHANGE_PATH_VALIDATION) {
            context_D.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
            return sw;
        }
        else if (context_D.outputParsingState == OUTPUT_FINALIZE_TX) {
            status = bagl_finalize_tx();
        }
        else {
            status = bagl_confirm_single_output();
        }
        if (!status) {
            ui_transaction_error();
            context_D.io_flags &= ~IO_ASYNCH_REPLY;
            context_D.transactionContext.transactionState =
                TRANSACTION_NONE;
            context_D.outLength = 0;
            sw = SW_INCORRECT_DATA;
        }
    }
    return sw;
}

unsigned char bagl_user_action(unsigned char confirming) {
    unsigned short sw = SW_OK;

    // confirm and finish the apdu exchange //spaghetti

    if (confirming) {
        // Check if all inputs have been confirmed

        if (context_D.outputParsingState ==
            OUTPUT_PARSING_OUTPUT) {
            context_D.remainingOutputs--;
        }

        while (context_D.remainingOutputs != 0) {
            memmove(context_D.currentOutput,
                       context_D.currentOutput +
                           context_D.discardSize,
                       context_D.currentOutputOffset -
                           context_D.discardSize);
            context_D.currentOutputOffset -=
                context_D.discardSize;
            context_D.io_flags &= ~IO_ASYNCH_REPLY;
            while (handle_output_state() &&
                   (!(context_D.io_flags & IO_ASYNCH_REPLY)))
                ;
            if (context_D.io_flags & IO_ASYNCH_REPLY) {
                if (!bagl_confirm_single_output()) {
                    context_D.transactionContext.transactionState =
                        TRANSACTION_NONE;
                    sw = SW_INCORRECT_DATA;
                    break;
                } else {
                    // Let the UI play
                    return 1;
                }
            } else {
                // Out of data to process, wait for the next call
                break;
            }
        }

        if ((context_D.outputParsingState ==
             OUTPUT_PARSING_OUTPUT) &&
            (context_D.remainingOutputs == 0)) {
            context_D.outputParsingState = OUTPUT_FINALIZE_TX;
            if (!bagl_finalize_tx()) {
                context_D.outputParsingState =
                    OUTPUT_PARSING_NONE;
                context_D.transactionContext.transactionState =
                    TRANSACTION_NONE;
                sw = SW_INCORRECT_DATA;
            } else {
                // Let the UI play
                return 1;
            }
        }

        if (context_D.outputParsingState ==
             OUTPUT_FINALIZE_TX) {
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
        context_D.outLength -=
            2; // status was already set by the last call
    } else {
        // Discard transaction
        context_D.transactionContext.transactionState =
            TRANSACTION_NONE;
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        context_D.outLength = 0;
    }
    G_io_apdu_buffer[context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[context_D.outLength++] = sw;

    if ((context_D.outputParsingState == OUTPUT_FINALIZE_TX) ||
        (sw != SW_OK)) {

        // we've finished the processing of the input
        apdu_hash_input_finalize_full_reset();
    }

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, context_D.outLength);

    return 0;
}
