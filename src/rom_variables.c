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

unsigned char const SIGNMAGIC[] = {' ', 'S', 'i', 'g', 'n', 'e', 'd', ' ', 'M',
                                   'e', 's', 's', 'a', 'g', 'e', ':', '\n'};

unsigned char const OVERWINTER_PARAM_PREVOUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'P', 'r', 'e', 'v', 'o', 'u', 't', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SEQUENCE[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'e', 'q', 'u', 'e', 'n', 'c', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_OUTPUTS[16] = { 'Z', 'c', 'a', 's', 'h', 'O', 'u', 't', 'p', 'u', 't', 's', 'H', 'a', 's', 'h' };
unsigned char const OVERWINTER_PARAM_SIGHASH[16] = { 'Z', 'c', 'a', 's', 'h', 'S', 'i', 'g', 'H', 'a', 's', 'h', 0, 0, 0, 0 };
unsigned char const OVERWINTER_NO_JOINSPLITS[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

unsigned char const DISPATCHER_CLA[] = {
    CLA, // apdu_get_wallet_public_key,
    CLA, // apdu_get_trusted_input,
    CLA, // apdu_hash_input_start,
    CLA, // apdu_hash_sign,
    CLA, // apdu_hash_input_finalize_full,
    CLA, // apdu_sign_message,
    CLA, // apdu_get_firmware_version,
    CLA, // apdu_get_coin_version
};

unsigned char const DISPATCHER_INS[] = {
    INS_GET_WALLET_PUBLIC_KEY,    // apdu_get_wallet_public_key,
    INS_GET_TRUSTED_INPUT,        // apdu_get_trusted_input,
    INS_HASH_INPUT_START,         // apdu_hash_input_start,
    INS_HASH_SIGN,                // apdu_hash_sign,
    INS_HASH_INPUT_FINALIZE_FULL, // apdu_hash_input_finalize_full,
    INS_SIGN_MESSAGE,             // apdu_sign_message,
    INS_GET_FIRMWARE_VERSION,     // apdu_get_firmware_version,
    INS_GET_COIN_VER,           // apdu_get_coin_version
};

unsigned char const DISPATCHER_DATA_IN[] = {
    1, // apdu_get_wallet_public_key,
    1, // apdu_get_trusted_input,
    1, // apdu_hash_input_start,
    1, // apdu_hash_sign,
    1, // apdu_hash_input_finalize_full,
    1, // apdu_sign_message,
    0, // apdu_get_firmware_version,
    0, // apdu_get_coin_version
};

apduProcessingFunction const DISPATCHER_FUNCTIONS[] = {
    apdu_get_wallet_public_key,
    apdu_get_trusted_input,
    apdu_hash_input_start,
    apdu_hash_sign,
    apdu_hash_input_finalize_full,
    apdu_sign_message,
    apdu_get_firmware_version,
    apdu_get_coin_version,
};
