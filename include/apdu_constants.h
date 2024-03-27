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

#ifndef APDU_CONSTANTS_H

#define APDU_CONSTANTS_H

#define CLA 0xE0
#define ADM_CLA 0xD0
#define NFCPAYMENT_CLA 0xF0

#define INS_SETUP 0x20
#define INS_VERIFY_PIN 0x22
#define INS_GET_OPERATION_MODE 0x24
#define INS_SET_OPERATION_MODE 0x26
#define INS_SET_KEYBOARD_CFG 0x28
#define INS_GET_WALLET_PUBLIC_KEY 0x40
#define INS_GET_TRUSTED_INPUT 0x42
#define INS_HASH_INPUT_START 0x44
#define INS_HASH_INPUT_FINALIZE 0x46
#define INS_HASH_SIGN 0x48
#define INS_HASH_INPUT_FINALIZE_FULL 0x4A
#define INS_GET_INTERNAL_CHAIN_INDEX 0x4C
#define INS_SIGN_MESSAGE 0x4E
#define INS_GET_TRANSACTION_LIMIT 0xA0
#define INS_SET_TRANSACTION_LIMIT 0xA2
#define INS_IMPORT_PRIVATE_KEY 0xB0
#define INS_GET_PUBLIC_KEY 0xB2
#define INS_DERIVE_BIP32_KEY 0xB4
#define INS_SIGNVERIFY_IMMEDIATE 0xB6
#define INS_GET_RANDOM 0xC0
#define INS_GET_ATTESTATION 0xC2
#define INS_GET_FIRMWARE_VERSION 0xC4
#define INS_COMPOSE_MOFN_ADDRESS 0xC6
#define INS_GET_POS_SEED 0xCA
#define INS_DEBUG 0xD0

#define INS_ADM_INIT_KEYS 0x20
#define INS_ADM_INIT_ATTESTATION 0x22
#define INS_ADM_GET_UPDATE_ID 0x24
#define INS_ADM_SET_KEYCARD_SEED 0x26
#define INS_ADM_FIRMWARE_UPDATE 0x42

#define INS_SET_USER_KEYCARD 0x10
#define INS_SETUP_SECURE_SCREEN 0x12
#define INS_SET_ALTERNATE_COIN_VER 0x14
#define INS_GET_COIN_VER 0x16

#define INS_STORE_TRUST_ROOT_BIP70 0x30
#define INS_CREATE_CERTIFICATE_BIP70 0x32
#define INS_CREATE_PAYMENT_REQ_BIP70 0x34
#define INS_PROCESS_CERTIFICATE_BIP70 0x36
#define INS_PARSE_PAYMENT_REQ_BIP70 0x38
#define INS_HASH_INPUT_FINALIZE_BIP70 0x3A
#define INS_ADM_SET_ROOT_BIP70 0x28
#define INS_ADM_SET_BIP39_SHUFFLE 0x2A

#define INS_NFCPAYMENT_SET_CONFIG 0x20
#define INS_NFCPAYMENT_GET_CONFIG 0x22
#define INS_NFCPAYMENT_STORE_UTXO 0x40
#define INS_NFCPAYMENT_STORE_SCRIPT 0x42
#define INS_NFCPAYMENT_GET_UTXO 0x44
#define INS_NFCPAYMENT_DELETE_UTXO 0x46
#define INS_NFCPAYMENT_GET_PAYMENT_TX 0x50
#define INS_NFCPAYMENT_GET_LAST_TX 0x52
#define INS_NFCPAYMENT_CONFIRM_TX 0x54
#define INS_NFCPAYMENT_CONFIRM_CHANGE 0x56
#define INS_NFCPAYMENT_GET_LAST_STAT 0x58
#define INS_NFCPAYMENT_GET_DATA 0xC0

#define SW_PIN_REMAINING_ATTEMPTS 0x63C0
#define SW_INCORRECT_LENGTH 0x6700
#define SW_COMMAND_INCOMPATIBLE_FILE_STRUCTURE 0x6981
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define SW_CONDITIONS_OF_USE_NOT_SATISFIED 0x6985
#define SW_INCORRECT_DATA 0x6A80
#define SW_NOT_ENOUGH_MEMORY_SPACE 0x6A84
#define SW_REFERENCED_DATA_NOT_FOUND 0x6A88
#define SW_FILE_ALREADY_EXISTS 0x6A89
#define SW_SWAP_WITHOUT_TRUSTED_INPUTS 0x6A8A
#define SW_INCORRECT_P1_P2 0x6B00
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_TECHNICAL_PROBLEM 0x6F00
#define SW_OK 0x9000
#define SW_MEMORY_PROBLEM 0x9240
#define SW_NO_EF_SELECTED 0x9400
#define SW_INVALID_OFFSET 0x9402
#define SW_FILE_NOT_FOUND 0x9404
#define SW_INCONSISTENT_FILE 0x9408
#define SW_ALGORITHM_NOT_SUPPORTED 0x9484
#define SW_INVALID_KCV 0x9485
#define SW_CODE_NOT_INITIALIZED 0x9802
#define SW_ACCESS_CONDITION_NOT_FULFILLED 0x9804
#define SW_CONTRADICTION_SECRET_CODE_STATUS 0x9808
#define SW_CONTRADICTION_INVALIDATION 0x9810
#define SW_CODE_BLOCKED 0x9840
#define SW_MAX_VALUE_REACHED 0x9850
#define SW_GP_AUTH_FAILED 0x6300
#define SW_LICENSING 0x6F42
#define SW_HALTED 0x6FAA
#define SW_APP_HALTED SW_CONDITIONS_OF_USE_NOT_SATISFIED

#define ISO_OFFSET_CLA 0x00
#define ISO_OFFSET_INS 0x01
#define ISO_OFFSET_P1 0x02
#define ISO_OFFSET_P2 0x03
#define ISO_OFFSET_LC 0x04
#define ISO_OFFSET_CDATA 0x05

#define BITID_DERIVE 0xB11D
#define BITID_DERIVE_MULTIPLE 0xB11E

#include "os.h"
#include "secure_value.h"

void commit_operation_mode(secu8 operationMode);

unsigned short apdu_get_wallet_public_key(void);
unsigned short apdu_get_trusted_input(void);
unsigned short apdu_hash_input_start(void);
unsigned short apdu_hash_input_finalize(void);
unsigned short apdu_hash_sign(void);
unsigned short apdu_hash_input_finalize_full(void);
unsigned short apdu_sign_message(void);

unsigned short apdu_get_firmware_version(void);

unsigned short apdu_get_coin_version(void);

#endif
