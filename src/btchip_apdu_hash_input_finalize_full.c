/*******************************************************************************
*   Ledger Blue - Bitcoin Wallet
*   (c) 2016 Ledger
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

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"

#define FINALIZE_P1_MORE 0x00
#define FINALIZE_P1_LAST 0x80
#define FINALIZE_P1_CHANGEINFO 0xFF

#define FLAG_SIGNATURE 0x01
#define FLAG_CHANGE_VALIDATED 0x80

static void btchip_apdu_hash_input_finalize_full_reset(void) {
    btchip_context_D.currentOutputOffset = 0;
    btchip_set_check_internal_structure_integrity(1);
}

unsigned short btchip_apdu_hash_input_finalize_full_internal(
    btchip_transaction_summary_t *transactionSummary) {
    unsigned char authorizationHash[32];
    unsigned char apduLength;
    unsigned short sw = BTCHIP_SW_OK;
    unsigned char *target = G_io_apdu_buffer;
    unsigned char keycardActivated = 0;
    unsigned char screenPaired = 0;
    unsigned char deepControl = 0;
    unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
    unsigned char persistentCommit = 0;
    unsigned char hashOffset = 0;
    unsigned char numOutputs = 0;

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:

        break;
    case BTCHIP_MODE_RELAXED_WALLET:
        persistentCommit = 1;
        break;
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    /*
    if (G_io_apdu_buffer[ISO_OFFSET_P2] != 0) {
      return BTCHIP_SW_INCORRECT_P1_P2;
    }
    */

    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    if ((p1 != FINALIZE_P1_MORE) && (p1 != FINALIZE_P1_LAST) &&
        (p1 != FINALIZE_P1_CHANGEINFO)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    // See if there is a hashing offset
    if (btchip_context_D.usingSegwit &&
        (btchip_context_D.tmpCtx.output.multipleOutput == 0)) {
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
    BEGIN_TRY {
        TRY {
            btchip_set_check_internal_structure_integrity(0);
            if (btchip_context_D.transactionContext.transactionState !=
                BTCHIP_TRANSACTION_PRESIGN_READY) {
                sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }

            if (p1 == FINALIZE_P1_CHANGEINFO) {
                unsigned char keyLength;
                if (!btchip_context_D.transactionContext.firstSigned) {
                    // Already validated, should be prevented on the client side
                    return BTCHIP_SW_OK;
                }
                if (!btchip_context_D.tmpCtx.output.changeAccepted) {
                    sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                    goto discardTransaction;
                }
                os_memset(transactionSummary, 0,
                          sizeof(btchip_transaction_summary_t));
                if (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x00) {
                    // Called with no change path, abort, should be prevented on
                    // the client side
                    return BTCHIP_SW_OK;
                }
                os_memmove(transactionSummary->summarydata.keyPath,
                           G_io_apdu_buffer + ISO_OFFSET_CDATA,
                           MAX_BIP32_PATH_LENGTH);
                btchip_private_derive_keypair(
                    transactionSummary->summarydata.keyPath, 1, NULL);
                if (((N_btchip.bkp.config.options &
                      BTCHIP_OPTION_UNCOMPRESSED_KEYS) != 0)) {
                    keyLength = 65;
                } else {
                    btchip_compress_public_key_value(btchip_public_key_D.W);
                    keyLength = 33;
                }
                btchip_public_key_hash160(
                    btchip_public_key_D.W,                            // IN
                    keyLength,                                        // INLEN
                    transactionSummary->summarydata.changeAddress + 1 // OUT
                    );
                // Commit to persistent memory if necessary
                os_memmove(
                    btchip_context_D.tmpCtx.output.changeAddress,
                    transactionSummary->summarydata.changeAddress,
                    sizeof(transactionSummary->summarydata.changeAddress));
                btchip_context_D.tmpCtx.output.changeInitialized = 1;
                btchip_context_D.tmpCtx.output.changeAccepted = 0;
                return BTCHIP_SW_OK;
            }

            // Always update the transaction & authorization hashes with the
            // given data
            // For SegWit, this has been reset to hold hashOutputs
            if (!btchip_context_D.segwitParsedOnce) {
                cx_hash(&btchip_context_D.transactionHashFull.header, 0,
                        G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset,
                        apduLength - hashOffset, NULL);
            }
            if (screenPaired) {
                btchip_context_D.tmpCtx.output.outputCrc = cx_crc16_update(
                    btchip_context_D.tmpCtx.output.outputCrc,
                    G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength);
            }

            if ((btchip_context_D.currentOutputOffset + apduLength) >
                sizeof(btchip_context_D.currentOutput)) {
                L_DEBUG_APP(("Output is too long to be checked\n"));
                sw = BTCHIP_SW_INCORRECT_DATA;
                goto discardTransaction;
            }
            os_memmove(btchip_context_D.currentOutput +
                           btchip_context_D.currentOutputOffset,
                       G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength);
            btchip_context_D.currentOutputOffset += apduLength;

            if (G_io_apdu_buffer[ISO_OFFSET_P1] == FINALIZE_P1_MORE) {
                if (!btchip_context_D.usingSegwit) {
                    cx_hash(
                        &btchip_context_D.transactionHashAuthorization.header,
                        0, G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength,
                        NULL);
                }
                if (screenPaired) {
                } else {
                    G_io_apdu_buffer[0] = 0x00;
                    btchip_context_D.outLength = 1;
                }
                btchip_context_D.tmpCtx.output.multipleOutput = 1;
                return BTCHIP_SW_OK;
            }

            if (!btchip_context_D.usingSegwit) {
                cx_hash(&btchip_context_D.transactionHashAuthorization.header,
                        CX_LAST, G_io_apdu_buffer + ISO_OFFSET_CDATA,
                        apduLength, authorizationHash);
            }

            if (btchip_context_D.usingSegwit) {
                if (!btchip_context_D.segwitParsedOnce) {
                    cx_hash(&btchip_context_D.transactionHashFull.header,
                            CX_LAST,
                            btchip_context_D.segwit.cache.hashedOutputs, 0,
                            btchip_context_D.segwit.cache.hashedOutputs);
                    cx_sha256_init(&btchip_context_D.transactionHashFull);
                    cx_hash(&btchip_context_D.transactionHashFull.header,
                            CX_LAST,
                            btchip_context_D.segwit.cache.hashedOutputs,
                            sizeof(btchip_context_D.segwit.cache.hashedOutputs),
                            btchip_context_D.segwit.cache.hashedOutputs);
                    L_DEBUG_BUF(("hashOutputs\n",
                                 btchip_context_D.segwit.cache.hashedOutputs,
                                 32));
                    cx_hash(
                        &btchip_context_D.transactionHashAuthorization.header,
                        CX_LAST, G_io_apdu_buffer, 0, authorizationHash);
                } else {
                    cx_hash(
                        &btchip_context_D.transactionHashAuthorization.header,
                        CX_LAST,
                        (unsigned char WIDE *)&btchip_context_D.segwit.cache,
                        sizeof(btchip_context_D.segwit.cache),
                        authorizationHash);
                }
            }

            // On last output, generate the persistent transaction context if
            // necessary
            /*
            if (btchip_context_D.transactionContext.firstSigned) {
                os_memset(&transactionSummary, 0, sizeof(transactionSummary));
                transactionSummary.summarydata.relaxed =
            btchip_context_D.transactionContext.relaxed;
            }
            */

            /* seem a dup ?!
            if (G_io_apdu_buffer[ISO_OFFSET_P1] == FINALIZE_P1_LAST) {
              // On last output, generate the persistent transaction context if
            necessary
              if (btchip_context_D.transactionContext.firstSigned) {
                os_memset(&transactionSummary, 0, sizeof(transactionSummary));
                transactionSummary.summarydata.relaxed =
            btchip_context_D.transactionContext.relaxed;
              }
            }
            */

            if (btchip_context_D.transactionContext.firstSigned) {
                if (btchip_context_D.tmpCtx.output.changeInitialized) {
                } else {
                    os_memset(transactionSummary, 0,
                              sizeof(btchip_transaction_summary_t));
                }

                transactionSummary->payToAddressVersion =
                    btchip_context_D.payToAddressVersion;
                transactionSummary->payToScriptHashVersion =
                    btchip_context_D.payToScriptHashVersion;

                if (!deepControl &&
                    !(screenPaired &&
                      !btchip_context_D.tmpCtx.output.multipleOutput)) {
                    transactionSummary->summarydata.relaxed = 1;
                } else {
                    unsigned char offset = ISO_OFFSET_CDATA;
                    unsigned char i;
                    unsigned char changeFilled = 0;
                    unsigned char regularFilled = 0;
                    numOutputs = G_io_apdu_buffer[offset++];
                    // Too many outputs, deny
                    if (numOutputs > 3) {
                        L_DEBUG_APP(("Too many outputs\n"));
                        goto failControl;
                    }
                    for (i = 0; i < numOutputs; i++) {
                        unsigned char tmpVersion;
                        unsigned char address[20];
                        unsigned char *destinationAddress = NULL;
                        unsigned char *destinationAmount = NULL;
                        offset += 8;
                        if (btchip_output_script_is_regular(G_io_apdu_buffer +
                                                            offset)) {
                            tmpVersion =
                                transactionSummary->payToAddressVersion;
                            os_memmove(address,
                                       G_io_apdu_buffer + offset +
                                           OUTPUT_SCRIPT_REGULAR_PRE_LENGTH,
                                       20);
                            L_DEBUG_BUF(
                                ("Regular script, address\n", address, 20));
                        } else if (btchip_output_script_is_p2sh(
                                       G_io_apdu_buffer + offset)) {
                            tmpVersion =
                                transactionSummary->payToScriptHashVersion;
                            os_memmove(address,
                                       G_io_apdu_buffer + offset +
                                           OUTPUT_SCRIPT_P2SH_PRE_LENGTH,
                                       20);
                            L_DEBUG_BUF(
                                ("P2SH script, address\n", address, 20));
                        } else if (btchip_output_script_is_op_return(
                                       G_io_apdu_buffer + offset)) {
                            unsigned char j;
                            for (j = 0; j < 8; j++) {
                                if (G_io_apdu_buffer[offset - 8 + j]) {
                                    L_DEBUG_APP(
                                        ("Output amount is not null\n"));
                                    goto failControl;
                                }
                            }
                            goto nextOutput;
                        } else {
                            L_DEBUG_APP(("Unrecognized output script\n"));
                            goto failControl;
                        }
                        // If the address matches the registred change, use it
                        if (btchip_context_D.tmpCtx.output.changeInitialized) {
                            if (os_memcmp(address,
                                          btchip_context_D.tmpCtx.output
                                                  .changeAddress +
                                              1,
                                          20) == 0) {
                                if (changeFilled) {
                                    L_DEBUG_APP(("Change already filled\n"));
                                    goto failControl;
                                }
                                destinationAddress =
                                    transactionSummary->summarydata
                                        .changeAddress;
                                destinationAmount =
                                    transactionSummary->summarydata
                                        .changeAmount;
                                btchip_context_D.tmpCtx.output.changeChecked =
                                    1;
                                changeFilled = 1;
                            }
                        }
                        if (destinationAddress == NULL) {
                            if (changeFilled && regularFilled) {
                                L_DEBUG_APP(
                                    ("Both output addresses already filled\n"));
                                goto failControl;
                            }
                            if (!regularFilled) {
                                destinationAddress =
                                    transactionSummary->summarydata
                                        .outputAddress;
                                destinationAmount =
                                    transactionSummary->summarydata
                                        .outputAmount;
                                regularFilled = 1;
                            } else {
                                destinationAddress =
                                    transactionSummary->summarydata
                                        .changeAddress;
                                destinationAmount =
                                    transactionSummary->summarydata
                                        .changeAmount;
                                changeFilled = 1;
                            }
                        }
                        os_memmove(destinationAddress + 1, address, 20);
                        destinationAddress[0] = tmpVersion;
                        btchip_swap_bytes(destinationAmount,
                                          G_io_apdu_buffer + offset - 8, 8);
                    // Otherwise fit the next input
                    // Then move to the next input
                    nextOutput:
                        offset += G_io_apdu_buffer[offset] + 1;
                    }
                    goto endControl;
                failControl:
                    if (deepControl) {
                        sw = BTCHIP_SW_INCORRECT_DATA;
                        goto discardTransaction;
                    } else {
                        // Soft fail, clear validation since it is meaningless
                        btchip_context_D.tmpCtx.output.changeChecked = 0;
                    }
                endControl:
                    // Internal change is mandatory but wasn't used, deny if it
                    // cannot be validated
                    // (keycard mode without screen cannot verify it)
                    if (deepControl && changeFilled &&
                        !btchip_context_D.tmpCtx.output.changeChecked) {
                        if (((N_btchip.bkp.config.options &
                              BTCHIP_OPTION_ALLOW_ARBITRARY_CHANGE) == 0) ||
                            (keycardActivated && !screenPaired)) {
                            L_DEBUG_APP(
                                ("Mandatory change control not done\n"));
                            sw = BTCHIP_SW_INCORRECT_DATA;
                            goto discardTransaction;
                        } else {
                            transactionSummary->summarydata.arbitraryChange = 1;
                        }
                    }
                }

                if (deepControl) {
                    unsigned char workAmount[8];
                    L_DEBUG_BUF(("Output Amount\n",
                                 transactionSummary->summarydata.outputAmount,
                                 8));
                    L_DEBUG_BUF(("Change Amount\n",
                                 transactionSummary->summarydata.changeAmount,
                                 8));
                    L_DEBUG_BUF(
                        ("Transaction Amount\n",
                         btchip_context_D.transactionContext.transactionAmount,
                         8));
                    if (transaction_amount_add_be(
                            workAmount,
                            transactionSummary->summarydata.outputAmount,
                            transactionSummary->summarydata.changeAmount) ||
                        transaction_amount_sub_be(
                            transactionSummary->summarydata.fees,
                            btchip_context_D.transactionContext
                                .transactionAmount,
                            workAmount)) {
                        L_DEBUG_APP(("Failed computing fees\n"));
                        sw = BTCHIP_SW_INCORRECT_DATA;
                        goto discardTransaction;
                    }
                } else {
                    // Only used for relaxed mode
                    os_memmove(
                        transactionSummary->summarydata.outputAmount,
                        btchip_context_D.transactionContext.transactionAmount,
                        8);
                }

                // Generate new nonce

                cx_rng(transactionSummary->summarydata.transactionNonce, 8);
                transactionSummary->active =
                    !btchip_context_D.transactionContext.consumeP2SH &&
                    !keycardActivated;
            } else {
            }

            if (screenPaired) {
            } else {
                G_io_apdu_buffer[0] = 0x00;
                target++;
            }

            *target = 0x00;
            target++;

            btchip_context_D.outLength = (target - G_io_apdu_buffer);

            // Check that the input being signed is part of the same
            // transaction, otherwise abort
            // (this is done to keep the transaction counter limit per session
            // synchronized)
            if (btchip_context_D.transactionContext.firstSigned) {
                os_memmove(transactionSummary->authorizationHash,
                           authorizationHash,
                           sizeof(transactionSummary->authorizationHash));
                btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
                CLOSE_TRY;
                return BTCHIP_SW_OK;

            } else {
                if (btchip_secure_memcmp(
                        authorizationHash,
                        transactionSummary->authorizationHash,
                        sizeof(transactionSummary->authorizationHash))) {
                    L_DEBUG_APP(
                        ("Authorization hash not matching, aborting\n"));
                    sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                    goto discardTransaction;
                }
            }

            if (btchip_context_D.usingSegwit &&
                !btchip_context_D.segwitParsedOnce) {
                // This input cannot be signed when using segwit - just restart.
                btchip_context_D.segwitParsedOnce = 1;
                L_DEBUG_APP(("Segwit parsed once\n"));
                btchip_context_D.transactionContext.transactionState =
                    BTCHIP_TRANSACTION_NONE;
            } else {
                btchip_context_D.transactionContext.transactionState =
                    BTCHIP_TRANSACTION_SIGN_READY;
            }
            sw = BTCHIP_SW_OK;
        }
        CATCH_ALL {
            sw = SW_TECHNICAL_DETAILS(0x0F);
        discardTransaction:
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_context_D.outLength = 0;
        }
        FINALLY {
            btchip_apdu_hash_input_finalize_full_reset();
            return sw;
        }
    }
    END_TRY;
}

unsigned short btchip_apdu_hash_input_finalize_full() {
    unsigned short sw = btchip_apdu_hash_input_finalize_full_internal(
        &btchip_context_D.transactionSummary);
    if (btchip_context_D.io_flags & IO_ASYNCH_REPLY) {
        // if the UI reject the processing of the request, then reply
        // immediately
        if (!btchip_bagl_confirm_full_output()) {
            btchip_context_D.io_flags &= ~IO_ASYNCH_REPLY;
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_context_D.outLength = 0;
            sw = BTCHIP_SW_INCORRECT_DATA;
        }
    }
    return sw;
}

void btchip_bagl_user_action(unsigned char confirming) {
    unsigned short sw = BTCHIP_SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming) {
        btchip_context_D.transactionContext.firstSigned = 0;

        if (btchip_context_D.usingSegwit &&
            !btchip_context_D.segwitParsedOnce) {
            // This input cannot be signed when using segwit - just restart.
            btchip_context_D.segwitParsedOnce = 1;
            L_DEBUG_APP(("Segwit parsed once\n"));
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
        } else {
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_SIGN_READY;
        }
        btchip_context_D.outLength -=
            2; // status was already set by the last call

    } else {
        // Discard transaction
        btchip_context_D.transactionContext.transactionState =
            BTCHIP_TRANSACTION_NONE;
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    // we've finished the processing of the input
    btchip_apdu_hash_input_finalize_full_reset();

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
}
