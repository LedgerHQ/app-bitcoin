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
#pragma once

#include "os.h"
#include "buffer.h"
#include "macros.h"

#define CLA 0xE0

#define INS_GET_WALLET_PUBLIC_KEY 0x40
#define INS_GET_TRUSTED_INPUT 0x42
#define INS_HASH_INPUT_START 0x44
#define INS_HASH_SIGN 0x48
#define INS_HASH_INPUT_FINALIZE_FULL 0x4A
#define INS_SIGN_MESSAGE 0x4E
#define INS_GET_FIRMWARE_VERSION 0xC4
#define INS_GET_COIN_VER 0x16

#define SW_INCORRECT_LENGTH 0x6700
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define SW_CONDITIONS_OF_USE_NOT_SATISFIED 0x6985
#define SW_INCORRECT_DATA 0x6A80
#define SW_SWAP_WITHOUT_TRUSTED_INPUTS 0x6A8A
#define SW_INCORRECT_P1_P2 0x6B00
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_TECHNICAL_PROBLEM 0x6F00
#define SW_TECHNICAL_PROBLEM_2 0x6F0F
#define SW_OK 0x9000

#define BITID_DERIVE 0xB11D
#define BITID_DERIVE_MULTIPLE 0xB11E

#define ZCASH_USING_OVERWINTER 0x01
#define ZCASH_USING_OVERWINTER_SAPLING 0x02

unsigned short handler_sign_message(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_hash_sign(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_hash_input_start(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_hash_input_finalize_full(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_get_wallet_public_key(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_get_trusted_input(buffer_t* buffer, uint8_t p1, uint8_t p2);
unsigned short handler_get_firmware_version(void);
unsigned short handler_get_coin_version(void);

