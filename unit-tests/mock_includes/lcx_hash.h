
/*******************************************************************************
*   Ledger Nano S - Secure firmware
*   (c) 2019 Ledger
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

#ifndef LCX_HASH_H
#define LCX_HASH_H

#include <stdint.h>

/* Defines from os.h */
#ifndef SYSCALL
#define SYSCALL
#endif

#ifndef PLENGTH
#define PLENGTH(...)
#endif

#define WIDE  // const // don't !!

/** Message Digest algorithm identifiers. */
enum cx_md_e {
    /** NONE Digest */
    CX_NONE,
    /** RIPEMD160 Digest */
    CX_RIPEMD160,  // 20 bytes
    /** SHA224 Digest */
    CX_SHA224,  // 28 bytes
    /** SHA256 Digest */
    CX_SHA256,  // 32 bytes
    /** SHA384 Digest */
    CX_SHA384,  // 48 bytes
    /** SHA512 Digest */
    CX_SHA512,  // 64 bytes
    /** Keccak (pre-SHA3) Digest */
    CX_KECCAK,  // 28,32,48,64 bytes
    /** SHA3 Digest */
    CX_SHA3,  // 28,32,48,64 bytes
    /** Groestl Digest */
    CX_GROESTL,
    /** Blake Digest */
    CX_BLAKE2B,
    /** SHAKE-128 Digest */
    CX_SHAKE128,  // any bytes
    /** SHAKE-128 Digest */
    CX_SHAKE256,  // any bytes
};
/** Convenience type. See #cx_md_e. */
typedef enum cx_md_e cx_md_t;

/**
 * @internal
 * Maximum size of message for any digest. The size is given in block,
 */
#define CX_HASH_MAX_BLOCK_COUNT 65535

/**
 * Common Message Digest context, used as abstract type.
 */
struct cx_hash_header_s {
    /** Message digest identifier, See cx_md_e. */
    cx_md_t algo;
    /** Number of block already processed */
    unsigned int counter;
};
/** Convenience type. See #cx_hash_header_s. */
typedef struct cx_hash_header_s cx_hash_t;

/**
 * Add more data to hash.
 *
 * @param  [in/out] hash
 *   Univers Continuation Blob.
 *   The hash context pointer shall point to a well-defined hash struct
 * cx_ripemd160_t, cx_sha256_t, .... The hash context shall be inited with
 * 'cx_xxx_init' The hash context shall be in RAM The function should be called
 * with a nice cast.
 *
 * @param  [in] mode
 *   Supported flags: CX_LAST
 *   If CX_LAST is set,
 *     - The struct is left not modified after finishing
 *     - if out is provided, hash is copied in out
 *     - context is NOT automatically re-inited.
 *
 * @param  [in] in
 *   Input data to add to current hash
 *
 * @param  [in] len
 *   Length of input to data.
 *
 * @param [out] out
 *   Either:
 *     - NULL (ignored) if CX_LAST is NOT set
 *     - produced hash  if CX_LAST is set
 *
 * @param [out] out_len
 *   Either:
 *     - O, if out is NULL
 *     - out buffer size, if buffer is too small to store the hash a exception
 * is thrown
 *
 */
CXCALL int cx_hash(cx_hash_t *hash PLENGTH(scc__cx_scc_struct_size_hash__hash),
                   int mode,
                   const unsigned char WIDE *in PLENGTH(len),
                   unsigned int len,
                   unsigned char *out PLENGTH(out_len),
                   unsigned int out_len);

/**
 * cx_hash_no_throw - same as cx_hash but returns error code instead of throwing.
 * In unit tests we use this as the primary implementation.
 */
int cx_hash_no_throw(cx_hash_t *hash,
                     int mode,
                     const unsigned char *in,
                     unsigned int in_len,
                     unsigned char *out,
                     unsigned int out_len);

/**
 * I/O vector for cx_sha256_hash_iovec.
 */
typedef struct {
    const uint8_t *iov_base;
    size_t iov_len;
} cx_iovec_t;

#endif
