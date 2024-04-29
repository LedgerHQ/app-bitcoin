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

#include "crypto_helpers.h"
#include "io.h"
#include "read.h"
#include "swap.h"

#include "apdu_constants.h"
#include "be_operations.h"
#include "context.h"
#include "customizable_helpers.h"
#include "extensions.h"
#include "helpers.h"
#include "ui.h"

#define FINALIZE_P1_MORE 0x00
#define FINALIZE_P1_LAST 0x80
#define FINALIZE_P1_CHANGEINFO 0xFF

#define FINALIZE_P2_DEFAULT 0x00

#define FLAG_SIGNATURE 0x01
#define FLAG_CHANGE_VALIDATED 0x80

void hash_input_finalize_full_reset(void) {
  context.currentOutputOffset = 0;
  context.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
  memset(context.totalOutputAmount, 0, sizeof(context.totalOutputAmount));
  context.changeOutputFound = 0;
}

static int check_output_displayable(bool *displayable) {
  *displayable = true;
  unsigned char amount[8], isOpReturn, isP2sh, isNativeSegwit, j,
      nullAmount = 1;

  for (j = 0; j < 8; j++) {
    if (context.currentOutput[j] != 0) {
      nullAmount = 0;
      break;
    }
  }
  if (!nullAmount) {
    swap_bytes(amount, context.currentOutput, 8);
    transaction_amount_add_be(context.totalOutputAmount,
                              context.totalOutputAmount, amount);
  }
  isOpReturn = output_script_is_op_return(context.currentOutput + 8);
  isP2sh = output_script_is_p2sh(context.currentOutput + 8);
  isNativeSegwit = output_script_is_native_witness(context.currentOutput + 8);
#ifndef __clang_analyzer__
  unsigned char isOpCreate = output_script_is_op_create(
      context.currentOutput + 8, sizeof(context.currentOutput) - 8);
  unsigned char isOpCall = output_script_is_op_call(
      context.currentOutput + 8, sizeof(context.currentOutput) - 8);
  if (((COIN_KIND == COIN_KIND_HYDRA) &&
       !output_script_is_regular(context.currentOutput + 8) && !isP2sh &&
       !(nullAmount && isOpReturn) && !isOpCreate && !isOpCall) ||
      (!(COIN_KIND == COIN_KIND_HYDRA) &&
       !output_script_is_regular(context.currentOutput + 8) && !isP2sh &&
       !(nullAmount && isOpReturn))) {
    PRINTF("Error : Unrecognized output script");
    return -1;
  }
#endif
  if (context.tmpCtx.output.changeInitialized && !isOpReturn) {
    bool changeFound = false;
    unsigned char addressOffset =
        (isNativeSegwit ? OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET
         : isP2sh       ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH
                        : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
    if (!isP2sh && memcmp(context.currentOutput + 8 + addressOffset,
                          context.tmpCtx.output.changeAddress, 20) == 0) {
      changeFound = true;
    } else if (isP2sh && context.usingSegwit) {
      unsigned char changeSegwit[22];
      changeSegwit[0] = 0x00;
      changeSegwit[1] = 0x14;
      memmove(changeSegwit + 2, context.tmpCtx.output.changeAddress, 20);
      public_key_hash160(changeSegwit, 22, changeSegwit);
      if (memcmp(context.currentOutput + 8 + addressOffset, changeSegwit, 20) ==
          0) {
        if (COIN_FLAGS & FLAG_SEGWIT_CHANGE_SUPPORT) {
          changeFound = true;
        } else {
          // Attempt to avoid fatal failures on Bitcoin Cash
          PRINTF("Error : Non spendable Segwit change");
          return -1;
        }
      }
    }
    if (changeFound) {
      if (context.changeOutputFound) {
        PRINTF("Error : Multiple change output found");
        return -1;
      }
      context.changeOutputFound = true;
      *displayable = false;
    }
  }
  return 0;
}

int handle_output_state(unsigned int *processed) {
  uint32_t discardSize = 0;
  context.discardSize = 0;
  *processed = 0;
  switch (context.outputParsingState) {
  case OUTPUT_PARSING_NUMBER_OUTPUTS: {
    context.totalOutputs = 0;
    if (context.currentOutputOffset < 1) {
      break;
    }
    if (context.currentOutput[0] < 0xFD) {
      context.totalOutputs = context.remainingOutputs =
          context.currentOutput[0];
      discardSize = 1;
      context.outputParsingState = OUTPUT_PARSING_OUTPUT;
      *processed = 1;
      break;
    }
    if (context.currentOutput[0] == 0xFD) {
      if (context.currentOutputOffset < 3) {
        break;
      }
      context.totalOutputs = context.remainingOutputs =
          (context.currentOutput[2] << 8) | context.currentOutput[1];
      discardSize = 3;
      context.outputParsingState = OUTPUT_PARSING_OUTPUT;
      *processed = 1;
      break;
    } else if (context.currentOutput[0] == 0xFE) {
      if (context.currentOutputOffset < 5) {
        break;
      }
      context.totalOutputs = context.remainingOutputs =
          read_u32_le(context.currentOutput, 1);
      discardSize = 5;
      context.outputParsingState = OUTPUT_PARSING_OUTPUT;
      *processed = 1;
      break;
    } else {
      return -1;
    }
  } break;

  case OUTPUT_PARSING_OUTPUT: {
    unsigned int scriptSize = 0;
    if (context.currentOutputOffset < 9) {
      break;
    }
    if (context.currentOutput[8] < 0xFD) {
      scriptSize = context.currentOutput[8];
      discardSize = 1;
    } else if (context.currentOutput[8] == 0xFD) {
      if (context.currentOutputOffset < 9 + 2) {
        break;
      }
      scriptSize = read_u32_le(context.currentOutput, 9);
      discardSize = 3;
    } else {
      // Unrealistically large script
      return -1;
    }
    if (context.currentOutputOffset < 8 + discardSize + scriptSize) {
      discardSize = 0;
      break;
    }

    *processed = 1;

    discardSize += 8 + scriptSize;

    bool displayable;
    if (check_output_displayable(&displayable)) {
      return -1;
    }

    if (displayable) {
      // The output can be processed by the UI

      context.discardSize = discardSize;
      discardSize = 0;
      *processed = 2;
    } else {
      context.remainingOutputs--;
    }
  } break;

  default:
    return -1;
  }

  if (discardSize != 0) {
    memmove(context.currentOutput, context.currentOutput + discardSize,
            context.currentOutputOffset - discardSize);
    context.currentOutputOffset -= discardSize;
  }

  return 0;
}

// out should be 32 bytes, even only 20 bytes is significant for output
int get_pubkey_hash160(unsigned char *keyPath, size_t keyPath_len,
                       unsigned char *out) {
  cx_ecfp_public_key_t public_key;
  if (get_public_key(keyPath, keyPath_len, public_key.W, NULL)) {
    return -1;
  }
  compress_public_key_value(public_key.W);

  public_key_hash160(public_key.W, // IN
                     33,           // INLEN
                     out           // OUT
  );
  return 0;
}

static unsigned short
hash_input_finalize_full_internal(transaction_summary_t *transactionSummary,
                                  buffer_t *buffer, uint8_t p1, uint8_t p2,
                                  bool *async) {
  unsigned char authorizationHash[32];
  unsigned short sw = SW_OK;
  unsigned char *target = G_io_apdu_buffer;
  unsigned char hashOffset = 0;

  (void)p2;

  if ((p1 != FINALIZE_P1_MORE) && (p1 != FINALIZE_P1_LAST) &&
      (p1 != FINALIZE_P1_CHANGEINFO)) {
    return SW_INCORRECT_P1_P2;
  }

  // See if there is a hashing offset
  if (context.usingSegwit && (context.tmpCtx.output.multipleOutput == 0)) {
    unsigned char firstByte = buffer->ptr[0];
    if (firstByte < 0xfd) {
      hashOffset = 1;
    } else if (firstByte == 0xfd) {
      hashOffset = 3;
    } else if (firstByte == 0xfe) {
      hashOffset = 5;
    }
  }

  // Check state
  if (context.transactionContext.transactionState !=
      TRANSACTION_PRESIGN_READY) {
    sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    goto discardTransaction;
  }

  if (p1 == FINALIZE_P1_CHANGEINFO) {
    if (!context.transactionContext.firstSigned) {
      // Already validated, should be prevented on the client side
      return SW_OK;
    }
    if (!context.tmpCtx.output.changeAccepted) {
      sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
      goto discardTransaction;
    }
    memset(transactionSummary, 0, sizeof(transaction_summary_t));
    if (buffer->ptr[0] == 0x00) {
      // Called with no change path, abort, should be prevented on
      // the client side
      return SW_OK;
    }
    memmove(transactionSummary->keyPath, buffer->ptr, MAX_BIP32_PATH_LENGTH);

    if (get_pubkey_hash160(transactionSummary->keyPath,
                           sizeof(transactionSummary->keyPath),
                           context.tmpCtx.output.changeAddress)) {
      sw = SW_TECHNICAL_PROBLEM_2;
      goto discardTransaction;
    }
    PRINTF("Change address = %.*H\n", 20, context.tmpCtx.output.changeAddress);

    context.tmpCtx.output.changeInitialized = 1;
    context.tmpCtx.output.changeAccepted = 0;

    // if the bip44 change path provided is not canonical or its index are
    // unsual, ask for user approval
    if (bip44_derivation_guard(transactionSummary->keyPath, true)) {
      if (G_called_from_swap) {
        PRINTF("In swap mode only standart path is allowed\n");
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
      }
      *async = true;
      context.outputParsingState = BIP44_CHANGE_PATH_VALIDATION;
      request_change_path_approval(transactionSummary->keyPath);
    }

    return SW_OK;
  }

  // Always update the transaction & authorization hashes with the
  // given data
  // For SegWit, this has been reset to hold hashOutputs
  if (!context.segwitParsedOnce) {
    if ((int)(buffer->size - hashOffset) < 0) {
      sw = SW_INCORRECT_DATA;
      goto discardTransaction;
    }
    if (context.usingOverwinter) {
      if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header, 0,
                           buffer->ptr + hashOffset, buffer->size - hashOffset,
                           NULL, 0)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
    } else {
      PRINTF("--- ADD TO HASH FULL:\n%.*H\n", buffer->size - hashOffset,
             buffer->ptr + hashOffset);
      if (cx_hash_no_throw(&context.transactionHashFull.sha256.header, 0,
                           buffer->ptr + hashOffset, buffer->size - hashOffset,
                           NULL, 0)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
    }
  }

  if (context.transactionContext.firstSigned) {
    if ((context.currentOutputOffset + buffer->size) >
        sizeof(context.currentOutput)) {
      PRINTF("Output is too long to be checked\n");
      sw = SW_INCORRECT_DATA;
      goto discardTransaction;
    }
    memmove(context.currentOutput + context.currentOutputOffset, buffer->ptr,
            buffer->size);
    context.currentOutputOffset += buffer->size;

    unsigned int processed = 1;
    while (processed == 1) {
      if (handle_output_state(&processed)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
    }

    if (processed == 2) {
      *async = true;
    }
    // Finalize the TX if necessary

    if ((context.remainingOutputs == 0) && (!*async)) {
      *async = true;
      context.outputParsingState = OUTPUT_FINALIZE_TX;
    }
  }

  if (p1 == FINALIZE_P1_MORE) {
    if (!context.usingSegwit) {
      PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", buffer->size, buffer->ptr);
      if (cx_hash_no_throw(&context.transactionHashAuthorization.header, 0,
                           buffer->ptr, buffer->size, NULL, 0)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
    }
    G_io_apdu_buffer[0] = 0x00;
    context.outLength = 1;
    context.tmpCtx.output.multipleOutput = 1;
    return SW_OK;
  }

  if (!context.usingSegwit) {
    PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", buffer->size, buffer->ptr);
    if (cx_hash_no_throw(&context.transactionHashAuthorization.header, CX_LAST,
                         buffer->ptr, buffer->size, authorizationHash, 32)) {
      sw = SW_TECHNICAL_PROBLEM_2;
      goto discardTransaction;
    }
  }

  if (context.usingSegwit) {
    if (!context.segwitParsedOnce) {
      if (context.usingOverwinter) {
        if (cx_hash_no_throw(&context.transactionHashFull.blake2b.header,
                             CX_LAST, context.segwit.cache.hashedOutputs, 0,
                             context.segwit.cache.hashedOutputs, 32)) {
          sw = SW_TECHNICAL_PROBLEM_2;
          goto discardTransaction;
        }
      } else {
        if (cx_hash_no_throw(&context.transactionHashFull.sha256.header,
                             CX_LAST, context.segwit.cache.hashedOutputs, 0,
                             context.segwit.cache.hashedOutputs, 32)) {
          sw = SW_TECHNICAL_PROBLEM_2;
          goto discardTransaction;
        }
        if (cx_sha256_init_no_throw(&context.transactionHashFull.sha256)) {
          sw = SW_TECHNICAL_PROBLEM_2;
          goto discardTransaction;
        }
        if (cx_hash_no_throw(&context.transactionHashFull.sha256.header,
                             CX_LAST, context.segwit.cache.hashedOutputs,
                             sizeof(context.segwit.cache.hashedOutputs),
                             context.segwit.cache.hashedOutputs, 32)) {
          sw = SW_TECHNICAL_PROBLEM_2;
          goto discardTransaction;
        }
      }
      PRINTF("hashOutputs\n%.*H\n", 32, context.segwit.cache.hashedOutputs);
      if (cx_hash_no_throw(&context.transactionHashAuthorization.header,
                           CX_LAST, G_io_apdu_buffer, 0, authorizationHash,
                           32)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
      PRINTF("Auth Hash:\n%.*H\n", 32, authorizationHash);
    } else {
      if (cx_hash_no_throw(&context.transactionHashAuthorization.header,
                           CX_LAST, (unsigned char *)&context.segwit.cache,
                           sizeof(context.segwit.cache), authorizationHash,
                           32)) {
        sw = SW_TECHNICAL_PROBLEM_2;
        goto discardTransaction;
      }
      PRINTF("Auth Hash:\n%.*H\n", 32, authorizationHash);
    }
  }

  if (context.transactionContext.firstSigned) {
    if (!context.tmpCtx.output.changeInitialized) {
      memset(transactionSummary, 0, sizeof(transaction_summary_t));
    }

    transactionSummary->payToAddressVersion = COIN_P2PKH_VERSION;
    transactionSummary->payToScriptHashVersion = COIN_P2SH_VERSION;

    // Generate new nonce

    cx_rng(transactionSummary->transactionNonce, 8);
  }

  G_io_apdu_buffer[0] = 0x00;
  target++;

  *target = 0x00;
  target++;

  context.outLength = (target - G_io_apdu_buffer);

  // Check that the input being signed is part of the same
  // transaction, otherwise abort
  // (this is done to keep the transaction counter limit per session
  // synchronized)
  if (context.transactionContext.firstSigned) {
    memmove(transactionSummary->authorizationHash, authorizationHash,
            sizeof(transactionSummary->authorizationHash));
    return SW_OK;
  } else {
    if (os_secure_memcmp(authorizationHash,
                         transactionSummary->authorizationHash,
                         sizeof(transactionSummary->authorizationHash))) {
      PRINTF("Authorization hash not matching, aborting\n");
      sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
      goto discardTransaction;
    }

    if (context.usingSegwit && !context.segwitParsedOnce) {
      // This input cannot be signed when using segwit - just restart.
      context.segwitParsedOnce = 1;
      PRINTF("Segwit parsed once\n");
      context.transactionContext.transactionState = TRANSACTION_NONE;
    } else {
      context.transactionContext.transactionState = TRANSACTION_SIGN_READY;
    }
    hash_input_finalize_full_reset();
    return SW_OK;
  }

discardTransaction:
  hash_input_finalize_full_reset();
  ui_transaction_error();
  context.transactionContext.transactionState = TRANSACTION_NONE;
  context.outLength = 0;

  memmove(G_io_apdu_buffer, context.currentOutput, context.currentOutputOffset);
  context.outLength = context.currentOutputOffset;
  return sw;
}

unsigned short handler_hash_input_finalize_full(buffer_t *buffer, uint8_t p1,
                                                uint8_t p2) {
  bool is_async = false;
  PRINTF("state=%d\n", context.outputParsingState);
  unsigned short sw = hash_input_finalize_full_internal(
      &context.transactionSummary, buffer, p1, p2, &is_async);

  if (is_async) {
    // if the UI reject the processing of the request, then reply
    // immediately
    int status;
    if (context.outputParsingState == BIP44_CHANGE_PATH_VALIDATION) {
      context.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
      return 0;
    } else if (context.outputParsingState == OUTPUT_FINALIZE_TX) {
      status = finalize_tx();
    } else {
      status = confirm_single_output();
    }
    if (status == 0) {
      ui_transaction_error();
      context.transactionContext.transactionState = TRANSACTION_NONE;
      context.outLength = 0;
      sw = SW_INCORRECT_DATA;
      return io_send_sw(sw);
    } else if (status == 2) {
      return io_send_response_pointer(G_io_apdu_buffer, context.outLength,
                                      SW_OK);
    }
    return 0;
  }
  return io_send_response_pointer(G_io_apdu_buffer, context.outLength, sw);
}

unsigned char user_action(unsigned char confirming) {
  unsigned short sw = SW_OK;

  // confirm and finish the apdu exchange //spaghetti

  if (confirming) {
    // Check if all inputs have been confirmed

    if (context.outputParsingState == OUTPUT_PARSING_OUTPUT) {
      context.remainingOutputs--;
    }

    while (context.remainingOutputs != 0) {
      memmove(context.currentOutput,
              context.currentOutput + context.discardSize,
              context.currentOutputOffset - context.discardSize);
      context.currentOutputOffset -= context.discardSize;
      unsigned int processed = 1;
      while (processed == 1) {
        if (handle_output_state(&processed)) {
          context.transactionContext.transactionState = TRANSACTION_NONE;
          sw = SW_INCORRECT_DATA;
          break;
        }
      }

      if (processed == 2) {
        if (!confirm_single_output()) {
          context.transactionContext.transactionState = TRANSACTION_NONE;
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

    if ((context.outputParsingState == OUTPUT_PARSING_OUTPUT) &&
        (context.remainingOutputs == 0)) {
      context.outputParsingState = OUTPUT_FINALIZE_TX;
      if (!finalize_tx()) {
        context.outputParsingState = OUTPUT_PARSING_NONE;
        context.transactionContext.transactionState = TRANSACTION_NONE;
        sw = SW_INCORRECT_DATA;
      } else {
        // Let the UI play
        return 1;
      }
    }

    if (context.outputParsingState == OUTPUT_FINALIZE_TX) {
      context.transactionContext.firstSigned = 0;

      if (context.usingSegwit && !context.segwitParsedOnce) {
        // This input cannot be signed when using segwit - just restart.
        context.segwitParsedOnce = 1;
        PRINTF("Segwit parsed once\n");
        context.transactionContext.transactionState = TRANSACTION_NONE;
      } else {
        context.transactionContext.transactionState = TRANSACTION_SIGN_READY;
      }
    }
  } else {
    // Discard transaction
    context.transactionContext.transactionState = TRANSACTION_NONE;
    sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    context.outLength = 0;
  }

  if ((context.outputParsingState == OUTPUT_FINALIZE_TX) || (sw != SW_OK)) {

    // we've finished the processing of the input
    hash_input_finalize_full_reset();
  }
  return io_send_response_pointer(G_io_apdu_buffer, context.outLength, sw);
}
