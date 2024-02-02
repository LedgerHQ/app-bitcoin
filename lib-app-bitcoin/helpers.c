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

#include "lib_standard_app/crypto_helpers.h"
#include "lib_standard_app/bip32.h"
#include "ledger_assert.h"
#include "io.h"
#include "base58.h"
#include "read.h"

#include "context.h"
#include "helpers.h"

void public_key_hash160(unsigned char *in, unsigned short inlen,
                               unsigned char out[static CX_RIPEMD160_SIZE]) {
    unsigned char buffer[CX_SHA256_SIZE];
    cx_hash_sha256(in, inlen, buffer, sizeof(buffer));
    cx_ripemd160_hash(buffer, sizeof(buffer), out);
}

static void compute_checksum(unsigned char *in, unsigned short inlen,
                             unsigned char output[static 4]) {
    unsigned char checksumBuffer[32];
    cx_hash_sha256(in, inlen, checksumBuffer, 32);
    cx_hash_sha256(checksumBuffer, 32, checksumBuffer, 32);

    PRINTF("Checksum\n%.*H\n",4,checksumBuffer);
    memmove(output, checksumBuffer, 4);
}

unsigned short public_key_to_encoded_base58(
    unsigned char *in, unsigned short inlen, unsigned char *out,
    unsigned short outlen, unsigned short version,
    unsigned char alreadyHashed) {
    unsigned char tmpBuffer[34];

    unsigned char versionSize = (version > 255 ? 2 : 1);
    short outputLen;

    if (!alreadyHashed) {
        PRINTF("To hash\n%.*H\n",inlen,in);
        public_key_hash160(in, inlen, tmpBuffer + versionSize);
        PRINTF("Hash160\n%.*H\n",20,(tmpBuffer + versionSize));
        if (version > 255) {
            tmpBuffer[0] = (version >> 8);
            tmpBuffer[1] = version;
        } else {
            tmpBuffer[0] = version;
        }
    } else {
        memmove(tmpBuffer, in, 20 + versionSize);
    }

    compute_checksum(tmpBuffer, 20 + versionSize, tmpBuffer + 20 + versionSize);

    outputLen = base58_encode(tmpBuffer, 24 + versionSize, (char *)out, outlen);
    LEDGER_ASSERT(outputLen >= 0, "Error encoding public key");

    return outputLen;
}

void swap_bytes(unsigned char *target, unsigned char *source,
                       unsigned char size) {
    unsigned char i;
    for (i = 0; i < size; i++) {
        target[i] = source[size - 1 - i];
    }
}

/*
Checks if the values of a derivation path are within "normal" (arbitrary) ranges:
Account < 100, change == 1 or 0, address index < 50000
Returns 1 if the path is unusual, or not compliant with BIP44*/
unsigned char bip44_derivation_guard(const unsigned char *bip32Path, bool is_change_path) {
    unsigned char path_len;
    bip32_path_t bip32PathInt;

    path_len = bip32Path[0];
    if (!parse_serialized_path(&bip32PathInt, bip32Path, MAX_BIP32_PATH_LENGTH)) {
        return 1;
    }

    // If the path length is not compliant with BIP44 or if the purpose don't match regular usage, return a warning
    if(path_len != BIP44_PATH_LEN ||
       ((bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) != 44 &&
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) != 49 &&
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) != 84)) {
        return 1;
    }

    // If the coin type doesn't match, return a warning
    if ((BIP44_COIN_TYPE != 0) &&
        (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) != BIP44_COIN_TYPE) &&
          ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) != BIP44_COIN_TYPE_2))) {
        return 1;
    }

    // If the account or address index is very high or if the change isn't 1, return a warning
    if((bip32PathInt.path[BIP44_ACCOUNT_OFFSET]^0x80000000) > MAX_BIP44_ACCOUNT_RECOMMENDED ||
       bip32PathInt.path[BIP44_CHANGE_OFFSET] != is_change_path?1:0 ||
       bip32PathInt.path[BIP44_ADDRESS_INDEX_OFFSET] > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED) {
        return 1;
    }

    return 0;
}

/*
Only enforce the structure or coin type for consumed UTXOs or a public address
Returns 0 if the path is non compliant, or 1 if compliant
*/
unsigned char enforce_bip44_coin_type(const unsigned char *bip32Path, bool for_pubkey) {
    bip32_path_t bip32PathInt;
    // No enforcement required
    if (BIP44_COIN_TYPE == 0) {
        return 1;
    }
    // Path is too short - always require a user validation if signing
    if (bip32Path[0] < 2) {
        return for_pubkey;
    }

    if (!parse_serialized_path(&bip32PathInt, bip32Path, MAX_BIP32_PATH_LENGTH)) {
        return 1;
    }

    // Path is not compliant with BIP 44 or derivatives - valid if not signing
    if (!(((bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) == 44 ||
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) == 49 ||
       (bip32PathInt.path[BIP44_PURPOSE_OFFSET]^0x80000000) == 84))) {
        return for_pubkey;
    }

    if  (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) == BIP44_COIN_TYPE) ||
        ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) == BIP44_COIN_TYPE_2)) {
        // Valid BIP 44 path
        return 1;
    }
    // Everything else needs a user validation
    return 0;
}

int sign_finalhash(unsigned char* path, size_t path_len, unsigned char *in, unsigned short inlen,
                                 unsigned char *out, size_t* outlen) {

    unsigned int info = 0;

    io_seproxyhal_io_heartbeat();
    
    bip32_path_t bip32Path;
    bip32Path.length = path[0];

    if (!parse_serialized_path(&bip32Path, path, path_len)) {
        return -1;
    }

    if (bip32_derive_ecdsa_sign_hash_256(
            CX_CURVE_SECP256K1,
            bip32Path.path, 
            bip32Path.length,
            CX_LAST | CX_RND_RFC6979,
            CX_SHA256,
            in, 
            inlen, 
            out, 
            outlen,
            &info) != CX_OK) {
        return -1;
    }

    // Store information about the parity of the 'y' coordinate
    if (info & CX_ECCINFO_PARITY_ODD) {
        out[0] |= 0x01;
    }

    io_seproxyhal_io_heartbeat();
    return 0;
}

int get_public_key(const unsigned char* keyPath, size_t keyPath_len, uint8_t raw_pubkey[static 65], unsigned char* chainCode) {

    bip32_path_t bip32Path;

    if (!parse_serialized_path(&bip32Path, keyPath, keyPath_len)) {
        return -1;
    }

    if (bip32_derive_get_pubkey_256(
        CX_CURVE_SECP256K1,
        bip32Path.path, 
        bip32Path.length,
        raw_pubkey,
        chainCode,
        CX_SHA512) != CX_OK) 
    {
        return -1;
    }

    return 0;
}

void compress_public_key_value(unsigned char *value) {
    bool odd = (value[64] & 1);
    value[0] = odd ? 0x03 : 0x02;
}

bool parse_serialized_path(bip32_path_t* path, const unsigned char* serialized_path, unsigned char serialized_path_length) {
    if (serialized_path_length < 1 ||
        serialized_path[0] > MAX_BIP32_PATH ||
        serialized_path[0] * 4 + 1 > serialized_path_length)
        return false;
    path->length = serialized_path[0];
    serialized_path++;
    for (int i = 0; i < path->length; i += 1, serialized_path += 4) {
        path->path[i] = read_u32_be(serialized_path, 0);
    }
    return true;
}
