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
#include "ledger_assert.h"
#include "macros.h"
#include "read.h"
#include "swap.h"
#include "write.h"

#include "apdu_constants.h"
#include "context.h"
#include "display_variables.h"
#include "extensions.h"
#include "helpers.h"
#include "ui.h"

#define SIGHASH_ALL 0x01

#ifndef COIN_FORKID
#define COIN_FORKID 0
#endif

/*
 * Function: handler_hash_sign
 * ----------------------------
 * Handles the signing process for hashing a transaction.
 * This function is defined as WEAK and can be overridden in the application own
 * sources.
 *
 * The function verifies parameters handles Zcash-specific scenarios, reads
 * transaction parameters, finalizes the hash, checks for path enforcement, and
 * initiates signing. It also handles specific cases for Bitcoin Cash and sets
 * the appropriate sighash type. After hashing and signing, it sends the
 * response. Parameters:
 *   - buffer: Pointer to the buffer containing transaction data.
 *   - p1: Instruction parameter 1.
 *   - p2: Instruction parameter 2.
 *
 */
WEAK unsigned short handler_hash_sign(buffer_t *buffer, uint8_t p1,
                                      uint8_t p2) {
  unsigned long int lockTime;
  uint32_t sighashType;
  unsigned char dataBuffer[8];
  unsigned char authorizationLength;
  unsigned char *parameters = (uint8_t *)buffer->ptr;

  if ((p1 != 0) || (p2 != 0)) {
    return io_send_sw(SW_INCORRECT_P1_P2);
  }

#define HASH_LENGTH 1 + 1 + 4 + 1
  if (buffer->size < HASH_LENGTH) {
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  // Zcash special - store parameters for later

  if ((context.usingOverwinter) && (!context.overwinterSignReady) &&
      (context.segwitParsedOnce) &&
      (context.transactionContext.transactionState == TRANSACTION_NONE)) {
    unsigned long int expiryHeight;
    parameters += (4 * buffer->ptr[0]) + 1;
    authorizationLength = *(parameters++);
    parameters += authorizationLength;
    lockTime = read_u32_be(parameters, 0);
    parameters += 4;
    sighashType = *(parameters++);
    expiryHeight = read_u32_be(parameters, 0);
    write_u32_le(context.nLockTime, 0, lockTime);
    write_u32_le(context.sigHashType, 0, sighashType);
    write_u32_le(context.nExpiryHeight, 0, expiryHeight);
    context.overwinterSignReady = 1;
    return io_send_sw(SW_OK);
  }

  if (context.transactionContext.transactionState != TRANSACTION_SIGN_READY) {
    PRINTF("Invalid transaction state %d\n",
           context.transactionContext.transactionState);
    context.transactionContext.transactionState = TRANSACTION_NONE;
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }

  if (context.usingOverwinter && !context.overwinterSignReady) {
    PRINTF("Overwinter not ready to sign\n");
    context.transactionContext.transactionState = TRANSACTION_NONE;
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }

  // Read parameters
  if (buffer->ptr[0] > MAX_BIP32_PATH) {
    context.transactionContext.transactionState = TRANSACTION_NONE;
    return io_send_sw(SW_INCORRECT_DATA);
  }
  memmove(context.transactionSummary.keyPath, buffer->ptr,
          MAX_BIP32_PATH_LENGTH);
  parameters += (4 * buffer->ptr[0]) + 1;
  authorizationLength = *(parameters++);
  parameters += authorizationLength;
  lockTime = read_u32_be(parameters, 0);
  parameters += 4;
  sighashType = *(parameters++);
  context.transactionSummary.sighashType = sighashType;

  // if bitcoin cash OR forkid is set, then use the fork id
  if ((COIN_KIND == COIN_KIND_BITCOIN_CASH) || (COIN_FORKID)) {
#define SIGHASH_FORKID 0x40
    if (sighashType != (SIGHASH_ALL | SIGHASH_FORKID)) {
      context.transactionContext.transactionState = TRANSACTION_NONE;
      return io_send_sw(SW_INCORRECT_DATA);
    }
    sighashType |= (COIN_FORKID << 8);

  } else {
    if (sighashType != SIGHASH_ALL) {
      context.transactionContext.transactionState = TRANSACTION_NONE;
      return io_send_sw(SW_INCORRECT_DATA);
    }
  }

  // Finalize the hash
  if (!context.usingOverwinter) {
    write_u32_le(dataBuffer, 0, lockTime);
    write_u32_le(dataBuffer, 4, sighashType);
    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(dataBuffer), dataBuffer);
    if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                         dataBuffer, sizeof(dataBuffer), NULL, 0)) {
      context.transactionContext.transactionState = TRANSACTION_NONE;
      return io_send_sw(SW_INCORRECT_DATA);
    }
  }

  // Check if the path needs to be enforced
  if (!enforce_bip44_coin_type(context.transactionSummary.keyPath, false)) {
    request_sign_path_approval(context.transactionSummary.keyPath);
  } else {
    // Sign immediately
    user_action_signtx(1, 0);
  }
  if (G_called_from_swap) {
    // if we signed all outputs we should exit,
    // but only after sending response, so lets raise the
    // vars.swap_data.should_exit flag and check it on timer later
    vars.swap_data.alreadySignedInputs++;
    if (vars.swap_data.alreadySignedInputs >=
        vars.swap_data.totalNumberOfInputs) {
      vars.swap_data.should_exit = 1;
    }
    return io_send_response_pointer(G_io_apdu_buffer, context.outLength, SW_OK);
  }
  return 0;
}

int user_action_signtx(unsigned char confirming, unsigned char direct) {
  // confirm and finish the apdu exchange //spaghetti
  if (confirming) {
    unsigned char hash[32];
    if (context.usingOverwinter) {
      LEDGER_ASSERT(
          cx_hash_no_throw(&context.transactionHashFull.blake2b.header, CX_LAST,
                           hash, 0, hash, 32) == CX_OK,
          "Hash Failed");
    } else {
      LEDGER_ASSERT(cx_hash_no_throw(&context.transactionHashFull.sha256.header,
                                     CX_LAST, hash, 0, hash, 32) == CX_OK,
                    "Hash Failed");
      PRINTF("Hash1\n%.*H\n", sizeof(hash), hash);

      // Rehash
      cx_hash_sha256(hash, sizeof(hash), hash, 32);
    }
    PRINTF("Hash2\n%.*H\n", sizeof(hash), hash);
    // Sign
    size_t out_len = sizeof(G_io_apdu_buffer);
    sign_finalhash(context.transactionSummary.keyPath,
                   sizeof(context.transactionSummary.keyPath), hash,
                   sizeof(hash), G_io_apdu_buffer, &out_len);

    context.outLength = G_io_apdu_buffer[1] + 2;
    G_io_apdu_buffer[context.outLength++] =
        context.transactionSummary.sighashType;
    ui_transaction_finish();

  } else {
    context.outLength = 0;
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }

  if (!direct) {
    return io_send_response_pointer(G_io_apdu_buffer, context.outLength, SW_OK);
  }
  return 0;
}
