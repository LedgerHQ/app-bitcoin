
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

#ifndef LCX_SHA256_H
#define LCX_SHA256_H

/** SHA224 message digest size */
#define CX_SHA224_SIZE 28
/** SHA256 message digest size */
#define CX_SHA256_SIZE 32

/**
 * SHA-224 and SHA-256 context
 */
struct cx_sha256_s {
    /** @copydoc cx_ripemd160_s::header */
    struct cx_hash_header_s header;
    /** @internal @copydoc cx_ripemd160_s::blen */
    unsigned int blen;
    /** @internal @copydoc cx_ripemd160_s::block */
    unsigned char block[64];
    /** @copydoc cx_ripemd160_s::acc */
    unsigned char acc[8 * 4];
};
/** Convenience type. See #cx_sha256_s. */
typedef struct cx_sha256_s cx_sha256_t;

/**
 * Initialize a SHA-224 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return algorithm identifier
 */
CXCALL int cx_sha224_init(cx_sha256_t *hash PLENGTH(sizeof(cx_sha256_t)));

/**
 * Initialize a SHA-256 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return algorithm identifier
 */
CXCALL int cx_sha256_init(cx_sha256_t *hash PLENGTH(sizeof(cx_sha256_t)));

/**
 * One shot SHA-256 digest
 *
 * @param  [in] in
 *   Input data to compute the hash
 *
 * @param  [in] len
 *   Length of input data.
 *
 * @param [out] out
 *   'out' length is implicit
 *
 */
CXCALL int cx_hash_sha256(const unsigned char WIDE *in PLENGTH(len),
                          unsigned int len,
                          unsigned char *out PLENGTH(out_len),
                          unsigned int out_len);

/**
 * Compute SHA-256 over an I/O vector.
 */
int cx_sha256_hash_iovec(const cx_iovec_t *iovec, size_t iovec_count, uint8_t out[32]);

#endif
