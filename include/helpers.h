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

#ifndef HELPERS_H

#define HELPERS_H

#include "os.h"
#include "cx.h"
#include "stdbool.h"

#define OUTPUT_SCRIPT_REGULAR_PRE_LENGTH 4
#define OUTPUT_SCRIPT_REGULAR_POST_LENGTH 2
#define OUTPUT_SCRIPT_P2SH_PRE_LENGTH 3
#define OUTPUT_SCRIPT_P2SH_POST_LENGTH 1

#define OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET 3

unsigned char output_script_is_regular(unsigned char *buffer);
unsigned char output_script_is_p2sh(unsigned char *buffer);
unsigned char output_script_is_op_return(unsigned char *buffer);
unsigned char output_script_is_native_witness(unsigned char *buffer);

unsigned char output_script_is_op_create(unsigned char *buffer,
                                                size_t size);
unsigned char output_script_is_op_call(unsigned char *buffer,
                                                size_t size);

void public_key_hash160(unsigned char *in, unsigned short inlen,
                               unsigned char *out);
unsigned short public_key_to_encoded_base58(
    unsigned char *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version, unsigned char alreadyHashed);

unsigned char bip44_derivation_guard(unsigned char *bip32Path, bool is_change_path);
unsigned char enforce_bip44_coin_type(unsigned char *bip32Path, bool for_pubkey);
unsigned char bip32_print_path(unsigned char *bip32Path, char* out, unsigned char max_out_len);

void swap_bytes(unsigned char *target, unsigned char *source,
                       unsigned char size);

int sign_finalhash(unsigned char *path, size_t path_len,
                           unsigned char *in, unsigned short inlen,
                           unsigned char *out, size_t* outlen,
                           unsigned char rfc6979);

void transaction_add_output(unsigned char *hash160Address,
                                   unsigned char *amount, unsigned char p2sh);
int get_public_key(unsigned char* keyPath, size_t keyPath_len, uint8_t raw_pubkey[static 65], unsigned char* chainCode);

#endif
