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

#include "cx.h"
#include "filesystem_tx.h"
#include "os.h"
#include "stdbool.h"

#define OUTPUT_SCRIPT_REGULAR_PRE_LENGTH 4
#define OUTPUT_SCRIPT_REGULAR_POST_LENGTH 2
#define OUTPUT_SCRIPT_P2SH_PRE_LENGTH 3
#define OUTPUT_SCRIPT_P2SH_POST_LENGTH 1

#define OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET 3

typedef struct bip32_path {
  unsigned char length;
  unsigned int path[MAX_BIP32_PATH];
} bip32_path_t;

void public_key_hash160(unsigned char *in, unsigned short inlen,
                        unsigned char out[static CX_RIPEMD160_SIZE]);
unsigned short public_key_to_encoded_base58(
    unsigned char *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version, unsigned char alreadyHashed);

unsigned char bip44_derivation_guard(const unsigned char *bip32Path,
                                     bool is_change_path);
unsigned char enforce_bip44_coin_type(const unsigned char *bip32Path,
                                      bool for_pubkey);

void swap_bytes(unsigned char *target, unsigned char *source,
                unsigned char size);

int sign_finalhash(unsigned char *path, size_t path_len, unsigned char *in,
                   unsigned short inlen, unsigned char *out, size_t *outlen);

int get_public_key(const unsigned char *keyPath, size_t keyPath_len,
                   uint8_t raw_pubkey[static 65], unsigned char *chainCode);

void compress_public_key_value(unsigned char *value);

bool parse_serialized_path(bip32_path_t *path,
                           const unsigned char *serialized_path,
                           unsigned char serialized_path_length);
