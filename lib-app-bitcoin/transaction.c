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

#include "ledger_assert.h"
#include "lib_standard_app/read.h"
#include "lib_standard_app/write.h"
#include "swap.h"

#include "apdu_constants.h"
#include "display_variables.h"
#include "be_operations.h"
#include "transaction.h"
#include "context.h"
#include "filesystem.h"
#include "helpers.h"

#ifndef COIN_CONSENSUS_BRANCH_ID
#define COIN_CONSENSUS_BRANCH_ID 0
#endif 

#define CONSENSUS_BRANCH_ID_OVERWINTER 0x5ba81b19
#define CONSENSUS_BRANCH_ID_SAPLING 0x76b809bb
#define CONSENSUS_BRANCH_ID_ZCLASSIC 0x930b540d

unsigned char const OVERWINTER_PARAM_PREVOUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'P', 'r', 'e', 'v', 'o', 'u', 't', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SEQUENCE[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'e', 'q', 'u', 'e', 'n', 'c', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_OUTPUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'O', 'u', 't', 'p', 'u', 't', 's', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SIGHASH[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'i', 'g', 'H', 'a', 's', 'h', 0, 0, 0, 0 };
unsigned char const OVERWINTER_NO_JOINSPLITS[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

// Check if fOverwintered flag is set and if nVersion is >= 0x03
#define TRUSTED_INPUT_OVERWINTER ( (COIN_KIND == COIN_KIND_ZCASH || \
                                    COIN_KIND == COIN_KIND_ZCLASSIC || \
                                    COIN_KIND == COIN_KIND_KOMODO) && \
                                    (read_u32_le(context.transactionVersion, 0) & (1<<31)) && \
                                    (read_u32_le(context.transactionVersion, 0) ^ (1<<31)) >= 0x03 \
                                )

static void check_transaction_available(unsigned char x) {
    LEDGER_ASSERT(context.transactionDataRemaining >= x, "Check transaction available failed %d < %d\n", context.transactionDataRemaining, x);
}

#define OP_HASH160 0xA9
#define OP_EQUAL 0x87
#define OP_CHECKMULTISIG 0xAE

static void transaction_offset(unsigned char value) {
    if ((context.transactionHashOption & TRANSACTION_HASH_FULL) != 0) {
        PRINTF("--- ADD TO HASH FULL:\n%.*H\n", value, context.transactionBufferPointer);
        if (context.usingOverwinter) {
            LEDGER_ASSERT(cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.transactionBufferPointer, value, NULL, 0) == CX_OK, "Hash Failed");
        }
        else {
            LEDGER_ASSERT(cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                context.transactionBufferPointer, value, NULL, 0) == CX_OK, "Hash Failed");
        }
    }
    if ((context.transactionHashOption &
         TRANSACTION_HASH_AUTHORIZATION) != 0) {
        PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", value, context.transactionBufferPointer);
        LEDGER_ASSERT(cx_hash_no_throw(&context.transactionHashAuthorization.header, 0,
                context.transactionBufferPointer, value, NULL, 0) == CX_OK, "Hash Failed");
    }
}

static void transaction_offset_increase(unsigned char value) {
    transaction_offset(value);
    context.transactionBufferPointer += value;
    context.transactionDataRemaining -= value;
}

static unsigned long int transaction_get_varint(void) {
    unsigned char firstByte;
    check_transaction_available(1);
    firstByte = *context.transactionBufferPointer;
    if (firstByte < 0xFD) {
        transaction_offset_increase(1);
        return firstByte;
    } else if (firstByte == 0xFD) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(2);
        result =
            (unsigned long int)(*context.transactionBufferPointer) |
            ((unsigned long int)(*(context.transactionBufferPointer +
                                   1))
             << 8);
        transaction_offset_increase(2);
        return result;
    } else if (firstByte == 0xFE) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(4);
        result = read_u32_le(context.transactionBufferPointer, 0);
        transaction_offset_increase(4);
        return result;
    } else {
        LEDGER_ASSERT(false, "Varint parsing failed");
        __builtin_unreachable();
    }
}

void transaction_parse(unsigned char parseMode) {
            for (;;) {
                switch (context.transactionContext.transactionState) {
                case TRANSACTION_NONE: {
                    PRINTF("Init transaction parser\n");
                    // Reset transaction state
                    context.transactionContext
                        .transactionRemainingInputsOutputs = 0;
                    context.transactionContext
                        .transactionCurrentInputOutput = 0;
                    context.transactionContext.scriptRemaining = 0;
                    memset(
                        context.transactionContext.transactionAmount,
                        0, sizeof(context.transactionContext
                                      .transactionAmount));
                    // TODO : transactionControlFid
                    // Reset hashes
                    if (context.usingOverwinter) {
                        if (context.segwitParsedOnce) {
                            uint8_t parameters[16];
                            memmove(parameters, OVERWINTER_PARAM_SIGHASH, 16);
                            if (COIN_KIND == COIN_KIND_ZCLASSIC) {
                                write_u32_le(parameters, 12, CONSENSUS_BRANCH_ID_ZCLASSIC);
                            }
                            else {
                                write_u32_le(parameters, 12,
                                    context.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING ?
                                    (COIN_CONSENSUS_BRANCH_ID != 0 ? COIN_CONSENSUS_BRANCH_ID : CONSENSUS_BRANCH_ID_SAPLING) : CONSENSUS_BRANCH_ID_OVERWINTER);
                            }
                            if (cx_blake2b_init2_no_throw(&context.transactionHashFull.blake2b, 256, NULL, 0, parameters, 16)) {
                                goto fail;
                            }
                        }
                    }
                    else {
                        if (cx_sha256_init_no_throw(&context.transactionHashFull.sha256)) {
                            goto fail;
                        }
                    }
                    if (cx_sha256_init_no_throw(
                        &context.transactionHashAuthorization)) {
                        goto fail;
                    }
                    if (context.usingSegwit) {
                        context.transactionHashOption = 0;
                        if (!context.segwitParsedOnce) {
                            if (context.usingOverwinter) {
                                if (cx_blake2b_init2_no_throw(&context.segwit.hash.hashPrevouts.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_PREVOUTS, 16)) {
                                    goto fail;
                                }
                                if (cx_blake2b_init2_no_throw(&context.transactionHashFull.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_SEQUENCE, 16)) {
                                    goto fail;
                                }
                            }
                            else {
                                if (cx_sha256_init_no_throw(
                                    &context.segwit.hash.hashPrevouts.sha256)) {
                                    goto fail;
                                }
                            }
                        } else {
                            PRINTF("Resume SegWit hash\n");
                            PRINTF("SEGWIT Version\n%.*H\n",sizeof(context.transactionVersion),context.transactionVersion);
                            PRINTF("SEGWIT HashedPrevouts\n%.*H\n",sizeof(context.segwit.cache.hashedPrevouts),context.segwit.cache.hashedPrevouts);
                            PRINTF("SEGWIT HashedSequence\n%.*H\n",sizeof(context.segwit.cache.hashedSequence),context.segwit.cache.hashedSequence);
                            if (context.usingOverwinter) {
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.transactionVersion, sizeof(context.transactionVersion), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.nVersionGroupId, sizeof(context.nVersionGroupId), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.segwit.cache.hashedPrevouts, sizeof(context.segwit.cache.hashedPrevouts), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.segwit.cache.hashedSequence, sizeof(context.segwit.cache.hashedSequence), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.segwit.cache.hashedOutputs, sizeof(context.segwit.cache.hashedOutputs), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) {
                                    goto fail;
                                }
                                if (context.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                    if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) { // sapling hashShieldedSpend) 
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) { // sapling hashShieldedOutputs
                                        goto fail;
                                    }

                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.nLockTime, sizeof(context.nLockTime), NULL, 0)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.nExpiryHeight, sizeof(context.nExpiryHeight), NULL, 0)) {
                                    goto fail;
                                }
                                if (context.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                    unsigned char valueBalance[8];
                                    memset(valueBalance, 0, sizeof(valueBalance));
                                    if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, valueBalance, sizeof(valueBalance), NULL, 0)) { // sapling valueBalance
                                        goto fail;
                                    }
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.sigHashType, sizeof(context.sigHashType), NULL, 0)) {
                                        goto fail;
                                }
                            }
                            else {
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(context.transactionVersion), context.transactionVersion);
                                if (cx_hash_no_throw(
                                    &context.transactionHashFull.sha256.header, 0,
                                    context.transactionVersion,
                                    sizeof(context.transactionVersion),
                                    NULL, 0)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(context.segwit.cache.hashedPrevouts), context.segwit.cache.hashedPrevouts);
                                if (cx_hash_no_throw(
                                    &context.transactionHashFull.sha256.header, 0,
                                    context.segwit.cache.hashedPrevouts,
                                    sizeof(context.segwit.cache
                                           .hashedPrevouts),
                                    NULL, 0)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(context.segwit.cache.hashedSequence), context.segwit.cache.hashedSequence);
                                if (cx_hash_no_throw(
                                    &context.transactionHashFull.sha256.header, 0,
                                    context.segwit.cache.hashedSequence,
                                    sizeof(context.segwit.cache
                                           .hashedSequence),
                                    NULL, 0)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", sizeof(context.segwit.cache), (unsigned char *)&context.segwit.cache);
                                if (cx_hash_no_throw(&context
                                         .transactionHashAuthorization.header,
                                    0,
                                    (unsigned char *)&context
                                        .segwit.cache,
                                    sizeof(context.segwit.cache),
                                    NULL, 0)) {
                                    goto fail;
                                }
                            }
                        }
                    }
                    // Parse the beginning of the transaction
                    // Version
                    check_transaction_available(4);
                    memmove(context.transactionVersion,
                               context.transactionBufferPointer, 4);
                    transaction_offset_increase(4);

                    if (context.usingOverwinter ||
                        TRUSTED_INPUT_OVERWINTER) {
                        // nVersionGroupId
                        check_transaction_available(4);
                        memmove(context.nVersionGroupId,
                               context.transactionBufferPointer, 4);
                        transaction_offset_increase(4);
                    }

                    if (COIN_FLAGS & FLAG_PEERCOIN_SUPPORT) {
                        if (((COIN_FAMILY ==
                            FAMILY_PEERCOIN &&
                            (context.transactionVersion[0] < 3))) ||
                            ((COIN_FAMILY == FAMILY_STEALTH) &&
                            (context.transactionVersion[0] < 2))) {
                            // Timestamp
                            check_transaction_available(4);
                            transaction_offset_increase(4);
                        }
                    }

                    // Number of inputs
                    context.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    PRINTF("Number of inputs : %d\n", context.transactionContext.transactionRemainingInputsOutputs);
                    if (G_called_from_swap && parseMode == PARSE_MODE_SIGNATURE) {
                        // remember number of inputs to know when to exit from library
                        // we will count number of already signed inputs and compare with this value
                        // As there are a lot of different states in which we can have different number of input
                        // (when for ex. we sign segregated witness)
                        if (vars.swap_data.totalNumberOfInputs == 0) {
                            vars.swap_data.totalNumberOfInputs =
                                context.transactionContext.transactionRemainingInputsOutputs;
                        }
                        // Reseting the flag, because we should check address ones for each input
                        vars.swap_data.was_address_checked = 0;
                    }
                    // Ready to proceed
                    context.transactionContext.transactionState =
                        TRANSACTION_DEFINED_WAIT_INPUT;

                    __attribute__((fallthrough));
                }

                case TRANSACTION_DEFINED_WAIT_INPUT: {
                    unsigned char trustedInputFlag = 1;
                    PRINTF("Process input\n");
                    if (context.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more inputs to hash, move forward
                        context.transactionContext.transactionState =
                            TRANSACTION_INPUT_HASHING_DONE;
                        continue;
                    }
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Proceed with the next input
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
                        check_transaction_available(
                            36); // prevout : 32 hash + 4 index
                        transaction_offset_increase(36);
                    }
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        unsigned char trustedInputLength;
                        unsigned char trustedInput[TRUSTED_INPUT_TOTAL_SIZE];
                        unsigned char amount[8];
                        unsigned char *savePointer;

                        // Expect the trusted input flag and trusted input length
                        check_transaction_available(2);
                        switch (*context.transactionBufferPointer) {
                        case 0:
                            if (context.usingSegwit) {
                                PRINTF("Non trusted input used in segwit mode\n");
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        case 1:
                            if (context.usingSegwit) {
                                // Segwit inputs can be passed as TrustedInput also
                                PRINTF("Trusted input used in segwit mode\n");
                            }
                            trustedInputFlag = 1;
                            break;
                        case 2:
                            if (!context.usingSegwit) {
                                PRINTF("Segwit input not used in segwit mode\n");
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        default:
                            PRINTF("Invalid trusted input flag\n");
                            goto fail;
                        }
                        // Check TrustedInput (TI) integrity, be it a non-segwit TI or a segwit TI
                        if (trustedInputFlag) {
                            trustedInputLength = *(
                                context.transactionBufferPointer + 1);
                            if ((trustedInputLength > sizeof(trustedInput)) ||
                                (trustedInputLength < 8)) {
                                PRINTF("Invalid trusted input size\n");
                                goto fail;
                            }

                            check_transaction_available(2 + trustedInputLength);
                            // Check TrustedInput Hmac
                            cx_hmac_sha256(
                                (uint8_t *)g_nvram_data.bkp.trustedinput_key,
                                sizeof(g_nvram_data.bkp.trustedinput_key),
                                context.transactionBufferPointer + 2,
                                trustedInputLength - 8, trustedInput, trustedInputLength);
                                PRINTF("====> Input HMAC:    %.*H\n", 8, context.transactionBufferPointer + 2 + trustedInputLength - 8);
                                PRINTF("====> Computed HMAC: %.*H\n", 8, trustedInput);

                            if (os_secure_memcmp(
                                    trustedInput,       // Contains computed Hmac for now
                                    context.transactionBufferPointer +
                                        2 + trustedInputLength - 8,
                                    8) != 0) {
                                PRINTF("Invalid signature\n");
                                goto fail;
                            }
                            // Hmac is valid. If TrustedInput contains a segwit input, update data pointer & length
                            // to fake the parser into believing a normal segwit input was received. Do not use
                            // transaction_offset_increase() here as it could update the hash being computed.
                            if (context.usingSegwit) {
                                // Overwrite the no longer needed HMAC's 1st byte w/ the input script length byte.
                                *(context.transactionBufferPointer + 1 + TRUSTED_INPUT_SIZE + 1) =
                                    *(context.transactionBufferPointer + 1 + TRUSTED_INPUT_TOTAL_SIZE + 1);
                                // Set tx data pointer on TI header's (i.e. 0x38||0x32||0x00||Nonce (2B)) last byte
                                // before prevout tx hash. Also remove HMAC size from remaining data length.
                                context.transactionBufferPointer += 5;
                                context.transactionDataRemaining -= (5+8);
                            }
                        }
                        // Handle pure segwit inputs, whether trusted or not (i.e. InputHashStart 1st APDU's P2==02
                        // & data[0]=={0x01, 0x02})
                        if (context.usingSegwit) {
                            transaction_offset_increase(1);     // Set tx pointer on 1st byte of hash
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            if (!context.segwitParsedOnce) {
                                if (context.usingOverwinter) {
                                    if (cx_hash_no_throw(&context.segwit.hash.hashPrevouts.blake2b.header, 0, context.transactionBufferPointer, 36, NULL, 0)) {
                                        goto fail;
                                    }
                                }
                                else {
                                    if (cx_hash_no_throw(
                                        &context.segwit.hash.hashPrevouts
                                         .sha256.header,
                                        0,
                                        context.transactionBufferPointer,
                                        36, NULL, 0)) {
                                        goto fail;
                                    }
                                }
                                transaction_offset_increase(36);
                                check_transaction_available(8); // update amount
                                swap_bytes(
                                    amount,
                                    context.transactionBufferPointer,
                                    8);
                                if (transaction_amount_add_be(
                                        context.transactionContext
                                            .transactionAmount,
                                        context.transactionContext
                                            .transactionAmount,
                                        amount)) {
                                    PRINTF("Overflow\n");
                                    goto fail;
                                }
                                PRINTF("Adding amount\n%.*H\n",8,context.transactionBufferPointer);
                                PRINTF("New amount\n%.*H\n",8,context.transactionContext.transactionAmount);
                                transaction_offset_increase(8);
                            } else {
                                context.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                                transaction_offset_increase(36);
                                context.transactionHashOption = 0;
                                check_transaction_available(8); // save amount
                                memmove(
                                    context.inputValue,
                                    context.transactionBufferPointer,
                                    8);
                                transaction_offset_increase(8);
                                context.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                            }
                        }
                        // Handle non-segwit inputs (i.e. InputHashStart 1st APDU's P2==00 && data[0]==0x00)
                        else if (!trustedInputFlag) {
                            PRINTF("Untrusted input not authorized\n");
                            goto fail;
                        }
                        // Handle non-segwit TrustedInput (i.e. InputHashStart 1st APDU's P2==00 & data[0]==0x01)
                        else if (trustedInputFlag && !context.usingSegwit) {
                            memmove(
                                trustedInput,
                                context.transactionBufferPointer + 2,
                                trustedInputLength - 8);
                            if (trustedInput[0] != MAGIC_TRUSTED_INPUT) {
                                PRINTF("Failed to verify trusted input signature\n");
                                goto fail;
                            }
                            // Update the hash with prevout data
                            savePointer =
                                context.transactionBufferPointer;
                            context.transactionBufferPointer =
                                trustedInput + 4;
                            PRINTF("Trusted input hash\n%.*H\n",36,context.transactionBufferPointer);
                            transaction_offset(36);

                            context.transactionBufferPointer =
                                savePointer + (2 + trustedInputLength);
                            context.transactionDataRemaining -=
                                (2 + trustedInputLength);

                            // Update the amount

                            swap_bytes(amount, trustedInput + 40, 8);
                            if (transaction_amount_add_be(
                                    context.transactionContext
                                        .transactionAmount,
                                    context.transactionContext
                                        .transactionAmount,
                                    amount)) {
                                PRINTF("Overflow\n");
                                goto fail;
                            }

                            PRINTF("Adding amount\n%.*H\n",8,(trustedInput + 40));
                            PRINTF("New amount\n%.*H\n",8,context.transactionContext.transactionAmount);
                        }

                        if (!context.usingSegwit) {
                            // Do not include the input script length + value in
                            // the authentication hash
                            context.transactionHashOption =
                                TRANSACTION_HASH_FULL;
                        }
                    }
                    // Read the script length
                    context.transactionContext.scriptRemaining =
                        transaction_get_varint();
                    PRINTF("Script to read %d\n", context.transactionContext.scriptRemaining);

                    if ((parseMode == PARSE_MODE_SIGNATURE) &&
                        !trustedInputFlag && !context.usingSegwit) {
                        // Only proceeds if this is not to be signed - so length
                        // should be null
                        if (context.transactionContext
                                .scriptRemaining != 0) {
                            PRINTF("Request to sign relaxed input\n");
                            goto fail;
                        }
                    }
                    // Move on
                    context.transactionContext.transactionState =
                        TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process input script, remaining %d\n", context.transactionContext.scriptRemaining);
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Scan for P2SH consumption - huge shortcut, but fine
                    // enough
                    // Also usable in SegWit mode
                    if (context.transactionContext.scriptRemaining ==
                        1) {
                        if (*context.transactionBufferPointer ==
                            OP_CHECKMULTISIG) {
                            PRINTF("Marking P2SH consumption\n");
                            context.transactionContext.consumeP2SH = 1;
                        } else {
                            // When using the P2SH shortcut, all inputs must use
                            // P2SH
                            PRINTF("Disabling P2SH consumption\n");
                            context.transactionContext.consumeP2SH = 0;
                        }
                        transaction_offset_increase(1);
                        context.transactionContext.scriptRemaining--;
                    }

                    if (context.transactionContext.scriptRemaining ==
                        0) {
                        if (parseMode == PARSE_MODE_SIGNATURE) {
                            if (!context.usingSegwit) {
                                // Restore dual hash for signature +
                                // authentication
                                context.transactionHashOption =
                                    TRANSACTION_HASH_BOTH;
                            } else {
                                if (context.segwitParsedOnce) {
                                    // Append the saved value
                                    PRINTF("SEGWIT Add value\n%.*H\n",8,context.inputValue);
                                    if (context.usingOverwinter) {
                                        if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.inputValue, 8, NULL, 0)) {
                                            goto fail;
                                        }
                                    }
                                    else {
                                        PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(context.inputValue), context.inputValue);
                                        if (cx_hash_no_throw(&context
                                                 .transactionHashFull.sha256.header,
                                            0, context.inputValue, 8,
                                            NULL, 0)) {
                                            goto fail;
                                        }
                                    }
                                }
                            }
                        }
                        // Sequence
                        check_transaction_available(4);
                        if (context.usingSegwit &&
                            !context.segwitParsedOnce) {
                            if (context.usingOverwinter) {
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0, context.transactionBufferPointer, 4, NULL, 0)) {
                                    goto fail;
                                }
                            }
                            else {
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", 4, context.transactionBufferPointer);
                                if (cx_hash_no_throw(&context.transactionHashFull
                                         .sha256.header,
                                    0,
                                    context.transactionBufferPointer,
                                    4, NULL, 0)) {
                                    goto fail;
                                }
                            }
                        }
                        transaction_offset_increase(4);
                        // Move to next input
                        context.transactionContext
                            .transactionRemainingInputsOutputs--;
                        context.transactionContext
                            .transactionCurrentInputOutput++;
                        context.transactionContext.transactionState =
                            TRANSACTION_DEFINED_WAIT_INPUT;
                        continue;
                    }
                    // Save the last script byte for the P2SH check
                    dataAvailable =
                        (context.transactionDataRemaining >
                                 context.transactionContext
                                         .scriptRemaining -
                                     1
                             ? context.transactionContext
                                       .scriptRemaining -
                                   1
                             : context.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    context.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case TRANSACTION_INPUT_HASHING_DONE: {
                    PRINTF("Input hashing done\n");
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        // inputs have been prepared, stop the parsing here
                        if (context.usingSegwit &&
                            !context.segwitParsedOnce) {
                            unsigned char hashedPrevouts[32];
                            unsigned char hashedSequence[32];
                            // Flush the cache
                            if (context.usingOverwinter) {
                                if (cx_hash_no_throw(&context.segwit.hash.hashPrevouts.blake2b.header, CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, CX_LAST, hashedSequence, 0, hashedSequence, 32)) {
                                    goto fail;
                                }
                            }
                            else {
                                if (cx_hash_no_throw(&context.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_sha256_init_no_throw(
                                    &context.segwit.hash.hashPrevouts.sha256)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts,
                                    sizeof(hashedPrevouts), hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&context.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence, 0, hashedSequence, 32)) {
                                    goto fail;
                                }
                                if (cx_sha256_init_no_throw(
                                    &context.transactionHashFull.sha256)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(hashedSequence), hashedSequence);
                                if (cx_hash_no_throw(&context.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence,
                                    sizeof(hashedSequence), hashedSequence, 32)) {
                                    goto fail;
                                }

                            }
                            memmove(
                                context.segwit.cache.hashedPrevouts,
                                hashedPrevouts, sizeof(hashedPrevouts));
                            memmove(
                                context.segwit.cache.hashedSequence,
                                hashedSequence, sizeof(hashedSequence));
                            PRINTF("hashPrevout\n%.*H\n",32,context.segwit.cache.hashedPrevouts);
                            PRINTF("hashSequence\n%.*H\n",32,context.segwit.cache.hashedSequence);
                        }
                        if (context.usingSegwit &&
                            context.segwitParsedOnce) {
                            if (!context.usingOverwinter) {
                                PRINTF("SEGWIT hashedOutputs\n%.*H\n",sizeof(context.segwit.cache.hashedOutputs),context.segwit.cache.hashedOutputs);
                                if (cx_hash_no_throw(
                                    &context.transactionHashFull.sha256.header, 0,
                                    context.segwit.cache.hashedOutputs,
                                    sizeof(context.segwit.cache
                                           .hashedOutputs),
                                    NULL, 0)) {
                                    goto fail;
                                }
                            }
                            context.transactionContext
                                .transactionState =
                                TRANSACTION_SIGN_READY;
                        } else {
                            context.transactionContext
                                .transactionState =
                                TRANSACTION_PRESIGN_READY;
                            if (context.usingOverwinter) {
                                if (cx_blake2b_init2_no_throw(&context.transactionHashFull.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_OUTPUTS, 16)) {
                                    goto fail;
                                }
                            }
                            else
                            if (context.usingSegwit) {
                                if (cx_sha256_init_no_throw(&context.transactionHashFull.sha256)) {
                                    goto fail;
                                }
                            }
                        }
                        continue;
                    }
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Number of outputs
                    context.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    context.transactionContext
                        .transactionCurrentInputOutput = 0;
                    PRINTF("Number of outputs : %d\n",
                        context.transactionContext.transactionRemainingInputsOutputs);
                    // Ready to proceed
                    context.transactionContext.transactionState =
                        TRANSACTION_DEFINED_WAIT_OUTPUT;

                    __attribute__((fallthrough));
                }
                case TRANSACTION_DEFINED_WAIT_OUTPUT: {
                    if (context.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more outputs to hash, move forward
                        context.transactionContext.transactionState =
                            TRANSACTION_OUTPUT_HASHING_DONE;
                        continue;
                    }
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Amount
                    check_transaction_available(8);
                    if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
                        (context.transactionContext
                             .transactionCurrentInputOutput ==
                         context.transactionTargetInput)) {
                        // Save the amount
                        memmove(context.transactionContext
                                       .transactionAmount,
                                   context.transactionBufferPointer,
                                   8);
                        context.trustedInputProcessed = 1;
                    }
                    transaction_offset_increase(8);
                    // Read the script length
                    context.transactionContext.scriptRemaining =
                        transaction_get_varint();

                    PRINTF("Script to read %d\n", context.transactionContext.scriptRemaining);
                    // Move on
                    context.transactionContext.transactionState =
                        TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process output script, remaining %d\n", context.transactionContext.scriptRemaining);
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    if (context.transactionContext.scriptRemaining ==
                        0) {
                        // Move to next output
                        context.transactionContext
                            .transactionRemainingInputsOutputs--;
                        context.transactionContext
                            .transactionCurrentInputOutput++;
                        context.transactionContext.transactionState =
                            TRANSACTION_DEFINED_WAIT_OUTPUT;
                        continue;
                    }
                    dataAvailable =
                        (context.transactionDataRemaining >
                                 context.transactionContext
                                     .scriptRemaining
                             ? context.transactionContext
                                   .scriptRemaining
                             : context.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    context.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case TRANSACTION_OUTPUT_HASHING_DONE: {
                    PRINTF("Output hashing done\n");
                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Locktime
                    check_transaction_available(4);
                    transaction_offset_increase(4);

                    if (context.transactionDataRemaining == 0) {
                        context.transactionContext.transactionState =
                            TRANSACTION_PARSED;
                        continue;
                    } else {
                        context.transactionHashOption = 0;
                        context.transactionContext.scriptRemaining =
                            transaction_get_varint();
                        context.transactionHashOption =
                            TRANSACTION_HASH_FULL;
                        context.transactionContext.transactionState =
                            TRANSACTION_PROCESS_EXTRA;
                        continue;
                    }
                }

                case TRANSACTION_PROCESS_EXTRA: {
                    unsigned char dataAvailable;

                    if (context.transactionContext.scriptRemaining ==
                        0) {
                        context.transactionContext.transactionState =
                            TRANSACTION_PARSED;
                        continue;
                    }

                    if (context.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    dataAvailable =
                        (context.transactionDataRemaining >
                                 context.transactionContext
                                     .scriptRemaining
                             ? context.transactionContext
                                   .scriptRemaining
                             : context.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable);
                    context.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }

                case TRANSACTION_PARSED: {
                    PRINTF("Transaction parsed\n");
                    goto ok;
                }

                case TRANSACTION_PRESIGN_READY: {
                    PRINTF("Presign ready\n");
                    goto ok;
                }

                case TRANSACTION_SIGN_READY: {
                    PRINTF("Sign ready\n");
                    goto ok;
                }
                }
            }

        fail:
            LEDGER_ASSERT(false, "Transaction parse - fail\n");
        ok: 
            return;

}
