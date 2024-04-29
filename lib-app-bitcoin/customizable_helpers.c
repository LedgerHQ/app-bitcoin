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
#include "macros.h"

#include "context.h"
#include "customizable_helpers.h"

const unsigned char TRANSACTION_OUTPUT_SCRIPT_PRE[] = {
    0x19, 0x76, 0xA9,
    0x14}; // script length, OP_DUP, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_POST[] = {
    0x88, 0xAC}; // OP_EQUALVERIFY, OP_CHECKSIG

const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
    0x17, 0xA9, 0x14}; // script length, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {0x87}; // OP_EQUAL

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
    0x3D, 0xA9, 0x14}; // script length, OP_HASH160, address length

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {
    0x87, // OP_EQUAL
    0x20, 0x9E, 0xC9, 0x84, 0x5A, 0xCB, 0x02, 0xFA, 0XB2, 0X4E, 0x1C, 0x03,
    0x68, 0xB3, 0xB5, 0x17, 0xC1, 0xA4, 0x48, 0x8F, 0xBA, 0x97, 0xF0, 0xE3,
    0x45, 0x9A, 0xC0, 0x53, 0xEA, 0x01, 0x00, 0x00, 0x00, // ParamHash
    0x03, // Push 3 bytes to stack to make ParamHeight line up properly
    0xC0, 0x1F, 0x02, // ParamHeight (139200) -> hex -> endianness swapped
    0xB4};            // OP_CHECKBLOCKATHEIGHT

const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE[] = {0x16, 0x00, 0x14};
const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE[] = {0x22, 0x00, 0x20};

const unsigned char ZEN_OUTPUT_SCRIPT_PRE[] = {
    0x3F, 0x76, 0xA9,
    0x14}; // script length, OP_DUP, OP_HASH160, address length
const unsigned char ZEN_OUTPUT_SCRIPT_POST[] = {
    0x88, 0xAC, // OP_EQUALVERIFY, OP_CHECKSIG
    0x20, 0x9e, 0xc9, 0x84, 0x5a, 0xcb, 0x02, 0xfa, 0xb2, 0x4e, 0x1c, 0x03,
    0x68, 0xb3, 0xb5, 0x17, 0xc1, 0xa4, 0x48, 0x8f, 0xba, 0x97, 0xf0, 0xe3,
    0x45, 0x9a, 0xc0, 0x53, 0xea, 0x01, 0x00, 0x00, 0x00, // ParamHash
    0x03, // Push 3 bytes to stack to make ParamHeight line up properly
    0xc0, 0x1f, 0x02, // ParamHeight (139200) -> hex -> endianness swapped
    0xb4              // OP_CHECKBLOCKATHEIGHT
};                    // BIP0115 Replay Protection

/*
 * Function: output_script_is_regular
 * -----------------------------------
 * Checks if the given output script is a regular script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *
 * Returns:
 *   - 1 if the output script is regular
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_regular(unsigned char *buffer) {
  if (COIN_NATIVE_SEGWIT_PREFIX) {
    if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE,
                sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE)) == 0) ||
        (memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE,
                sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE)) == 0)) {
      return 1;
    }
  }
  if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_PRE,
              sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE)) == 0) &&
      (memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE) + 20,
              TRANSACTION_OUTPUT_SCRIPT_POST,
              sizeof(TRANSACTION_OUTPUT_SCRIPT_POST)) == 0)) {
    return 1;
  }
  if (COIN_KIND == COIN_KIND_HORIZEN) {
    if ((memcmp(buffer, ZEN_OUTPUT_SCRIPT_PRE, sizeof(ZEN_OUTPUT_SCRIPT_PRE)) ==
         0) &&
        (memcmp(buffer + sizeof(ZEN_OUTPUT_SCRIPT_PRE) + 20,
                ZEN_OUTPUT_SCRIPT_POST, sizeof(ZEN_OUTPUT_SCRIPT_POST)) == 0)) {
      return 1;
    }
  }

  return 0;
}

/*
 * Function: output_script_is_p2sh
 * --------------------------------
 * Checks if the given output script is a pay-to-script-hash (P2SH) script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *
 * Returns:
 *   - 1 if the output script is a P2SH script.
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_p2sh(unsigned char *buffer) {
  if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
              sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
      (memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
              TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
              sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
    return 1;
  }
  if (COIN_KIND == COIN_KIND_HORIZEN) {
    if ((memcmp(buffer, ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
                sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
        (memcmp(buffer + sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
                ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
                sizeof(ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
      return 1;
    }
  }
  return 0;
}

/*
 * Function: output_script_is_native_witness
 * ------------------------------------------
 * Checks if the given output script is a native witness script (P2WPKH or
 * P2WSH).
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *
 * Returns:
 *   - 1 if the output script is a native witness script.
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_native_witness(unsigned char *buffer) {
  if (COIN_NATIVE_SEGWIT_PREFIX) {
    if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE,
                sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE)) == 0) ||
        (memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE,
                sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE)) == 0)) {
      return 1;
    }
  }
  return 0;
}

/*
 * Function: output_script_is_op_return
 * -------------------------------------
 * Checks if the given output script is an OP_RETURN script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *
 * Returns:
 *   - 1 if the output script is an OP_RETURN script.
 *   - 0 otherwise.
 *
 */
WEAK unsigned char output_script_is_op_return(unsigned char *buffer) {
  if (COIN_KIND == COIN_KIND_BITCOIN_CASH) {
    return ((buffer[1] == 0x6A) ||
            ((buffer[1] == 0x00) && (buffer[2] == 0x6A)));
  } else {
    return (buffer[1] == 0x6A);
  }
}

/*
 * Function: output_script_is_op_create_or_call
 * ---------------------------------------------
 * Checks if the given output script is an OP_CREATE or OP_CALL script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *   - size: Size of the output script.
 *   - value: Value to match against the last byte of the script.
 *
 * Returns:
 *   - 1 if the output script is an OP_CREATE or OP_CALL script.
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_op_create_or_call(unsigned char *buffer,
                                                      size_t size,
                                                      unsigned char value) {
  return (!output_script_is_regular(buffer) && !output_script_is_p2sh(buffer) &&
          !output_script_is_op_return(buffer) && (buffer[0] <= 0xEA) &&
          (buffer[0] < size) && (buffer[buffer[0]] == value));
}

/*
 * Function: output_script_is_op_create
 * -------------------------------------
 * Checks if the given output script is an OP_CREATE script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *   - size: Size of the output script.
 *
 * Returns:
 *   - 1 if the output script is an OP_CREATE script.
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_op_create(unsigned char *buffer,
                                              size_t size) {
  return output_script_is_op_create_or_call(buffer, size, 0xC1);
}

/*
 * Function: output_script_is_op_call
 * -----------------------------------
 * Checks if the given output script is an OP_CALL script.
 *
 * Parameters:
 *   - buffer: Pointer to the output script buffer.
 *   - size: Size of the output script.
 *
 * Returns:
 *   - 1 if the output script is an OP_CALL script.
 *   - 0 otherwise.
 */
WEAK unsigned char output_script_is_op_call(unsigned char *buffer,
                                            size_t size) {
  return output_script_is_op_create_or_call(buffer, size, 0xC2);
}
