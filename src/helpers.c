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
#include "lib_standard_app/crypto_helpers.h"
#include "bip32_path.h"
#include "ledger_assert.h"

const unsigned char TRANSACTION_OUTPUT_SCRIPT_PRE[] = {
    0x19, 0x76, 0xA9,
    0x14}; // script length, OP_DUP, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_POST[] = {
    0x88, 0xAC}; // OP_EQUALVERIFY, OP_CHECKSIG

const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
    0x17, 0xA9, 0x14}; // script length, OP_HASH160, address length
const unsigned char TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {0x87}; // OP_EQUAL

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE[] = {
        0x3D, 0xA9,
        0x14}; // script length, OP_HASH160, address length

const unsigned char ZEN_TRANSACTION_OUTPUT_SCRIPT_P2SH_POST[] = {
        0x87, // OP_EQUAL
        0x20, 0x9E, 0xC9, 0x84, 0x5A, 0xCB, 0x02, 0xFA, 0XB2, 0X4E,
        0x1C, 0x03, 0x68, 0xB3, 0xB5, 0x17, 0xC1, 0xA4, 0x48, 0x8F,
        0xBA, 0x97, 0xF0, 0xE3, 0x45, 0x9A, 0xC0, 0x53, 0xEA, 0x01,
        0x00, 0x00, 0x00, // ParamHash
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

unsigned char output_script_is_regular(unsigned char *buffer) {
    if (G_coin_config->native_segwit_prefix) {
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
    if (G_coin_config->kind == COIN_KIND_HORIZEN) {
        if ((memcmp(buffer, ZEN_OUTPUT_SCRIPT_PRE,
                       sizeof(ZEN_OUTPUT_SCRIPT_PRE)) == 0) &&
            (memcmp(buffer + sizeof(ZEN_OUTPUT_SCRIPT_PRE) + 20,
                       ZEN_OUTPUT_SCRIPT_POST,
                       sizeof(ZEN_OUTPUT_SCRIPT_POST)) == 0)) {
            return 1;
        }
    }

    return 0;
}

unsigned char output_script_is_p2sh(unsigned char *buffer) {
    if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
                    sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
        (memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
                    TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
                    sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
        return 1;
    }
    if (G_coin_config->kind == COIN_KIND_HORIZEN) {
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

unsigned char output_script_is_native_witness(unsigned char *buffer) {
    if (G_coin_config->native_segwit_prefix) {
        if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WPKH_PRE)) == 0) ||
            (memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2WSH_PRE)) == 0)) {
            return 1;
        }
    }
    return 0;
}

unsigned char output_script_is_op_return(unsigned char *buffer) {
    if (G_coin_config->kind == COIN_KIND_BITCOIN_CASH) {
        return ((buffer[1] == 0x6A) || ((buffer[1] == 0x00) && (buffer[2] == 0x6A)));
    }
    else {
        return (buffer[1] == 0x6A);
    }
}

static unsigned char output_script_is_op_create_or_call(unsigned char *buffer,
                                                        size_t size,
                                                        unsigned char value) {
    return (!output_script_is_regular(buffer) &&
            !output_script_is_p2sh(buffer) &&
            !output_script_is_op_return(buffer) && (buffer[0] <= 0xEA) &&
            (buffer[0] < size) &&
            (buffer[buffer[0]] == value));
}

unsigned char output_script_is_op_create(unsigned char *buffer,
                                                size_t size) {
    return output_script_is_op_create_or_call(buffer, size, 0xC1);
}

unsigned char output_script_is_op_call(unsigned char *buffer,
                                              size_t size) {
    return output_script_is_op_create_or_call(buffer, size, 0xC2);
}

unsigned char rng_u8_modulo(unsigned char modulo) {
    unsigned int rng_max = 256 % modulo;
    unsigned int rng_limit = 256 - rng_max;
    unsigned char candidate;
    while ((candidate = cx_rng_u8()) > rng_limit)
        ;
    return (candidate % modulo);
}

unsigned char secure_memcmp(const void *buf1, const void *buf2,
                                   unsigned short length) {
    unsigned char error = 0;
    while (length--) {
        error |= ((unsigned char *)buf1)[length] ^
                 ((unsigned char *)buf2)[length];
    }
    if (length != 0xffff) {
        return 1;
    }
    return error;
}

unsigned long int read_u32(unsigned char *buffer, unsigned char be,
                                  unsigned char skipSign) {
    unsigned char i;
    unsigned long int result = 0;
    unsigned char shiftValue = (be ? 24 : 0);
    for (i = 0; i < 4; i++) {
        unsigned char x = (unsigned char)buffer[i];
        if ((i == 0) && skipSign) {
            x &= 0x7f;
        }
        result += ((unsigned long int)x) << shiftValue;
        if (be) {
            shiftValue -= 8;
        } else {
            shiftValue += 8;
        }
    }
    return result;
}

void write_u32_be(unsigned char *buffer, unsigned long int value) {
    buffer[0] = ((value >> 24) & 0xff);
    buffer[1] = ((value >> 16) & 0xff);
    buffer[2] = ((value >> 8) & 0xff);
    buffer[3] = (value & 0xff);
}

void write_u32_le(unsigned char *buffer, unsigned long int value) {
    buffer[0] = (value & 0xff);
    buffer[1] = ((value >> 8) & 0xff);
    buffer[2] = ((value >> 16) & 0xff);
    buffer[3] = ((value >> 24) & 0xff);
}



void public_key_hash160(unsigned char *in, unsigned short inlen,
                               unsigned char *out) {
    cx_ripemd160_t riprip;
    unsigned char buffer[32];
    cx_hash_sha256(in, inlen, buffer, 32);
    cx_ripemd160_init(&riprip);
    LEDGER_ASSERT(cx_hash_no_throw(&riprip.header, CX_LAST, buffer, 32, out, 20) == CX_OK, "hash160");
}

void compute_checksum(unsigned char* in, unsigned short inlen, unsigned char * output) {
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
    size_t outputLen;

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

    outputLen = outlen;
    if (encode_base58(tmpBuffer, 24 + versionSize, out, &outputLen) < 0) {
        THROW(EXCEPTION);
    }
    return outputLen;
}

void swap_bytes(unsigned char *target, unsigned char *source,
                       unsigned char size) {
    unsigned char i;
    for (i = 0; i < size; i++) {
        target[i] = source[size - 1 - i];
    }
}

unsigned short decode_base58_address(unsigned char *in,
                                            unsigned short inlen,
                                            unsigned char *out,
                                            unsigned short outlen) {
    unsigned char hashBuffer[32];
    size_t outputLen = outlen;
    if (decode_base58((char *)in, inlen, out, &outputLen) < 0) {
        THROW(EXCEPTION);
    }
    outlen = outputLen;

    // Compute hash to verify address
    cx_hash_sha256(out, outlen - 4, hashBuffer, 32);

    cx_hash_sha256(hashBuffer, 32, hashBuffer, 32);

    if (memcmp(out + outlen - 4, hashBuffer, 4)) {
        PRINTF("Hash checksum mismatch\n%.*H\n",sizeof(hashBuffer),hashBuffer);
        THROW(INVALID_CHECKSUM);
    }

    return outlen;
}

/*
Checks if the values of a derivation path are within "normal" (arbitrary) ranges:
Account < 100, change == 1 or 0, address index < 50000
Returns 1 if the path is unusual, or not compliant with BIP44*/
unsigned char bip44_derivation_guard(unsigned char *bip32Path, bool is_change_path) {

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
    if ((G_coin_config->bip44_coin_type != 0) &&
        (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) != G_coin_config->bip44_coin_type) &&
          ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) != G_coin_config->bip44_coin_type2))) {
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
unsigned char enforce_bip44_coin_type(unsigned char *bip32Path, bool for_pubkey) {
    bip32_path_t bip32PathInt;
    // No enforcement required
    if (G_coin_config->bip44_coin_type == 0) {
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

    if  (((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) == G_coin_config->bip44_coin_type) ||
        ((bip32PathInt.path[BIP44_COIN_TYPE_OFFSET]^0x80000000) == G_coin_config->bip44_coin_type2)) {
        // Valid BIP 44 path
        return 1;
    }
    // Everything else needs a user validation
    return 0;
}

// Print a BIP32 path as an ascii string to display on the device screen
// On the Ledger Blue, if the string is longer than 30 char, the string will be split in multiple lines
unsigned char bip32_print_path(unsigned char *bip32Path, char* out, unsigned char max_out_len) {

    unsigned char bip32PathLength;
    unsigned char i, offset;
    unsigned int current_level;
    bool hardened;

    bip32PathLength = bip32Path[0];
    if (bip32PathLength > MAX_BIP32_PATH) {
        THROW(INVALID_PARAMETER);
    }
    bip32Path++;
    out[0] = ' ';
    offset=1;
    for (i = 0; i < bip32PathLength; i++) {
        current_level = read_u32(bip32Path, 1, 0);
        hardened = (bool)(current_level & 0x80000000);
        if(hardened) {
            //remove hardening flag
            current_level ^= 0x80000000;
        }
        bip32Path += 4;
        snprintf(out+offset, max_out_len-offset, "%u", current_level);
        offset = strnlen(out, max_out_len);
        if(offset >= max_out_len - 2) THROW(EXCEPTION_OVERFLOW);
        if(hardened) out[offset++] = '\'';

        out[offset++] = '/';
        out[offset] = '\0';
    }
    // remove last '/'
    out[offset-1] = '\0';

    return offset -1;
}

void transaction_add_output(unsigned char *hash160Address,
                                   unsigned char *amount, unsigned char p2sh) {
    const unsigned char *pre = (p2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE
                                     : TRANSACTION_OUTPUT_SCRIPT_PRE);
    const unsigned char *post = (p2sh ? TRANSACTION_OUTPUT_SCRIPT_P2SH_POST
                                      : TRANSACTION_OUTPUT_SCRIPT_POST);
    unsigned char sizePre = (p2sh ? sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)
                                  : sizeof(TRANSACTION_OUTPUT_SCRIPT_PRE));
    unsigned char sizePost = (p2sh ? sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)
                                   : sizeof(TRANSACTION_OUTPUT_SCRIPT_POST));
    if (amount != NULL) {
        swap_bytes(context_D.tmp, amount, 8);
        context_D.tmp += 8;
    }
    memmove(context_D.tmp, (void *)pre, sizePre);
    context_D.tmp += sizePre;
    memmove(context_D.tmp, hash160Address, 20);
    context_D.tmp += 20;
    memmove(context_D.tmp, (void *)post, sizePost);
    context_D.tmp += sizePost;
}


int sign_finalhash(unsigned char* path, size_t path_len, unsigned char *in, unsigned short inlen,
                                 unsigned char *out, size_t* outlen,
                                 unsigned char rfc6979) {

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
            CX_LAST | (rfc6979 ? CX_RND_RFC6979 : CX_RND_TRNG), 
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

int get_public_key(unsigned char* keyPath, size_t keyPath_len, uint8_t raw_pubkey[static 65], unsigned char* chainCode) {

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
