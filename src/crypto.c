/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
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
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "os.h"
#include "cx.h"
#include "cx_stubs.h"
#include "cx_ecfp.h"
#include "ox_ec.h"
#include "cx_ram.h"
#include "lcx_ripemd160.h"
#include "cx_ripemd160.h"
#include "lib_standard_app/crypto_helpers.h"

#include "common/base58.h"
#include "common/bip32.h"
#include "common/format.h"
#include "common/read.h"
#include "common/write.h"

#include "cxram_stash.h"
#include "debug-helpers/debug.h"

#include "crypto.h"

/**
 * Generator for secp256k1, value 'g' defined in "Standards for Efficient Cryptography"
 * (SEC2) 2.7.1.
 */
// clang-format off
static const uint8_t secp256k1_generator[] = {
    0x04,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
// clang-format on

/**
 * Modulo for secp256k1
 */
static const uint8_t secp256k1_p[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};

/**
 * Curve order for secp256k1
 */
static const uint8_t secp256k1_n[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

/**
 * (p + 1)/4, used to calculate square roots in secp256k1
 */
static const uint8_t secp256k1_sqr_exponent[] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c};

/* BIP0341 tags for computing the tagged hashes when tweaking public keys */
static const uint8_t BIP0341_taptweak_tag[] = {'T', 'a', 'p', 'T', 'w', 'e', 'a', 'k'};
static const uint8_t BIP0341_tapbranch_tag[] = {'T', 'a', 'p', 'B', 'r', 'a', 'n', 'c', 'h'};
static const uint8_t BIP0341_tapleaf_tag[] = {'T', 'a', 'p', 'L', 'e', 'a', 'f'};

/**
 * Gets the point on the SECP256K1 that corresponds to kG, where G is the curve's generator point.
 * Returns -1 if point is Infinity or any error occurs; 0 otherwise.
 */
static int secp256k1_point(const uint8_t k[static 32], uint8_t out[static 65]) {
    memcpy(out, secp256k1_generator, 65);
    if (CX_OK != cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, out, k, 32)) return -1;
    return 0;
}

int bip32_CKDpub(const serialized_extended_pubkey_t *parent,
                 uint32_t index,
                 serialized_extended_pubkey_t *child) {
    PRINT_STACK_POINTER();

    if (index >= BIP32_FIRST_HARDENED_CHILD) {
        return -1;  // can only derive unhardened children
    }

    if (parent->depth == 255) {
        return -1;  // maximum derivation depth reached
    }

    uint8_t I[64];

    {  // make sure that heavy memory allocations are freed as soon as possible

        uint8_t tmp[33 + 4];
        memcpy(tmp, parent->compressed_pubkey, 33);
        write_u32_be(tmp, 33, index);

        cx_hmac_sha512(parent->chain_code, 32, tmp, sizeof(tmp), I, 64);
    }

    uint8_t *I_L = &I[0];
    uint8_t *I_R = &I[32];

    // fail if I_L is not smaller than the group order n, but the probability is < 1/2^128
    int diff;
    if (CX_OK != cx_math_cmp_no_throw(I_L, secp256k1_n, 32, &diff) || diff >= 0) {
        return -1;
    }

    uint8_t child_uncompressed_pubkey[65];

    {  // make sure that heavy memory allocations are freed as soon as possible
        // compute point(I_L)
        uint8_t P[65];
        if (0 > secp256k1_point(I_L, P)) return -1;

        uint8_t K_par[65];
        if (0 > crypto_get_uncompressed_pubkey(parent->compressed_pubkey, K_par)) return -1;

        // add K_par
        if (CX_OK !=
            cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1, child_uncompressed_pubkey, P, K_par)) {
            return -1;  // the point at infinity is not a valid child pubkey (should never happen in
                        // practice)
        }
    }

    memmove(child->version, parent->version, 4);
    child->depth = parent->depth + 1;

    uint32_t parent_fingerprint = crypto_get_key_fingerprint(parent->compressed_pubkey);

    write_u32_be(child->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(child->child_number, 0, index);

    memcpy(child->chain_code, I_R, 32);

    crypto_get_compressed_pubkey(child_uncompressed_pubkey, child->compressed_pubkey);

    return 0;
}

void crypto_ripemd160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    int res = cx_ripemd160_hash(in, inlen, out);
    LEDGER_ASSERT(res == CX_OK, "Unexpected error in ripemd160 computation. Returned: %d", res);
}

void crypto_hash160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    PRINT_STACK_POINTER();

    uint8_t buffer[32];
    int res = cx_hash_sha256(in, inlen, buffer, 32);
    LEDGER_ASSERT(res == CX_SHA256_SIZE,
                  "Unexpected error in sha256 computation. Returned: %d",
                  res);
    crypto_ripemd160(buffer, 32, out);
}

int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[static 65],
                                 uint8_t out[static 33]) {
    PRINT_STACK_POINTER();

    if (uncompressed_key[0] != 0x04) {
        return -1;
    }
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32);  // copy x
    return 0;
}

int crypto_get_uncompressed_pubkey(const uint8_t compressed_key[static 33],
                                   uint8_t out[static 65]) {
    PRINT_STACK_POINTER();

    uint8_t prefix = compressed_key[0];
    if (prefix != 0x02 && prefix != 0x03) {
        return -1;
    }

    uint8_t *x = &out[1], *y = &out[1 + 32];

    memmove(x, compressed_key + 1, 32);  // copy x

    // we use y for intermediate results, in order to save memory

    uint8_t e = 3;
    if (CX_OK != cx_math_powm_no_throw(y, x, &e, 1, secp256k1_p, 32))
        return -1;  // tmp = x^3 (mod p)
    uint8_t scalar[32] = {0};
    scalar[31] = 7;
    if (CX_OK != cx_math_addm_no_throw(y, y, scalar, secp256k1_p, 32))
        return -1;  // tmp = x^3 + 7 (mod p)
    if (CX_OK != cx_math_powm_no_throw(y, y, secp256k1_sqr_exponent, 32, secp256k1_p, 32))
        return -1;  // tmp = sqrt(x^3 + 7) (mod p)

    // if the prefix and y don't have the same parity, take the opposite root (mod p)
    if (((prefix ^ y[31]) & 1) != 0) {
        if (CX_OK != cx_math_sub_no_throw(y, secp256k1_p, y, 32)) return -1;
    }

    out[0] = 0x04;
    return 0;
}

// TODO: missing unit tests
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    size_t res;
    res = cx_hash_sha256(in, in_len, buffer, 32);
    LEDGER_ASSERT(res == CX_SHA256_SIZE,
                  "Unexpected error in sha256 computation. Returned: %d",
                  res);
    res = cx_hash_sha256(buffer, 32, buffer, 32);
    LEDGER_ASSERT(res == CX_SHA256_SIZE,
                  "Unexpected error in sha256 computation. Returned: %d",
                  res);
    memmove(out, buffer, 4);
}

bool crypto_get_compressed_pubkey_at_path(const uint32_t bip32_path[],
                                          uint8_t bip32_path_len,
                                          uint8_t pubkey[static 33],
                                          uint8_t chain_code[]) {
    uint8_t raw_public_key[65];

    if (bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    bip32_path,
                                    bip32_path_len,
                                    raw_public_key,
                                    chain_code,
                                    CX_SHA512) != CX_OK) {
        return false;
    }

    if (crypto_get_compressed_pubkey(raw_public_key, pubkey) < 0) {
        return false;
    }

    return true;
}

uint32_t crypto_get_key_fingerprint(const uint8_t pub_key[static 33]) {
    uint8_t key_rip[20];
    crypto_hash160(pub_key, 33, key_rip);

    return read_u32_be(key_rip, 0);
}

uint32_t crypto_get_master_key_fingerprint() {
    uint8_t master_pub_key[33];
    uint32_t bip32_path[] = {};
    crypto_get_compressed_pubkey_at_path(bip32_path, 0, master_pub_key, NULL);
    return crypto_get_key_fingerprint(master_pub_key);
}

bool crypto_derive_symmetric_key(const char *label, size_t label_len, uint8_t key[static 32]) {
    // The label is a byte string in SLIP-0021, but os_derive_bip32_with_seed_no_throw
    // accesses the `path` argument as an array of uint32_t, causing a device freeze if memory
    // is not aligned.
    // As a workaround, we copy the label into a local buffer aligned to 4 bytes.

    uint8_t label_copy[32] __attribute__((aligned(4)));

    // Fail if the length of the buffer is longer than the local buffer
    if (label_len > sizeof(label_copy)) {
        return false;
    }

    memcpy(label_copy, label, label_len);

    // The SDK function below requires the output key array to be 64 bytes long
    uint8_t tmp_key[64] = {0};
    cx_err_t ret = os_derive_bip32_with_seed_no_throw(HDW_SLIP21,
                                                      CX_CURVE_SECP256K1,
                                                      (uint32_t *) label_copy,
                                                      label_len,
                                                      tmp_key,
                                                      NULL,
                                                      NULL,
                                                      0);
    if (ret == CX_OK) {
        // Only the first 32 bytes are used for SLIP21
        memcpy(key, tmp_key, 32);
    }
    explicit_bzero(tmp_key, sizeof(tmp_key));

    return ret == CX_OK;
}

int get_extended_pubkey_at_path(const uint32_t bip32_path[],
                                uint8_t bip32_path_len,
                                uint32_t bip32_pubkey_version,
                                serialized_extended_pubkey_t *out_pubkey) {
    // find parent key's fingerprint and child number
    uint32_t parent_fingerprint = 0;
    uint32_t child_number = 0;
    if (bip32_path_len > 0) {
        // here we reuse the storage for the parent keys that we will later use
        // for the response, in order to save memory

        uint8_t parent_pubkey[33];
        if (!crypto_get_compressed_pubkey_at_path(bip32_path,
                                                  bip32_path_len - 1,
                                                  parent_pubkey,
                                                  NULL)) {
            return -1;
        }

        parent_fingerprint = crypto_get_key_fingerprint(parent_pubkey);
        child_number = bip32_path[bip32_path_len - 1];
    }

    write_u32_be(out_pubkey->version, 0, bip32_pubkey_version);
    out_pubkey->depth = bip32_path_len;
    write_u32_be(out_pubkey->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(out_pubkey->child_number, 0, child_number);

    if (!crypto_get_compressed_pubkey_at_path(bip32_path,
                                              bip32_path_len,
                                              out_pubkey->compressed_pubkey,
                                              out_pubkey->chain_code)) {
        return -1;
    }

    return 0;
}

int base58_encode_address(const uint8_t in[20], uint32_t version, char *out, size_t out_len) {
    uint8_t tmp[4 + 20 + 4];  // version + max_in_len + checksum

    uint8_t version_len;
    if (version < 256) {
        tmp[0] = (uint8_t) version;
        version_len = 1;
    } else if (version < 65536) {
        write_u16_be(tmp, 0, (uint16_t) version);
        version_len = 2;
    } else {
        write_u32_be(tmp, 0, version);
        version_len = 4;
    }

    memcpy(tmp + version_len, in, 20);
    crypto_get_checksum(tmp, version_len + 20, tmp + version_len + 20);
    return base58_encode(tmp, version_len + 20 + 4, out, out_len);
}

int crypto_ecdsa_sign_sha256_hash_with_key(const uint32_t bip32_path[],
                                           uint8_t bip32_path_len,
                                           const uint8_t hash[static 32],
                                           uint8_t *pubkey,
                                           uint8_t out[static MAX_DER_SIG_LEN],
                                           uint32_t *info) {
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;
    uint32_t info_internal = 0;

    size_t sig_len = MAX_DER_SIG_LEN;
    bool error = true;

    if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                      bip32_path,
                                      bip32_path_len,
                                      &private_key,
                                      NULL) != CX_OK) {
        goto end;
    }

    if (cx_ecdsa_sign_no_throw(&private_key,
                               CX_RND_RFC6979,
                               CX_SHA256,
                               hash,
                               32,
                               out,
                               &sig_len,
                               &info_internal) != CX_OK) {
        goto end;
    }

    if (pubkey != NULL) {
        // Generate associated pubkey
        if (cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &public_key, &private_key, true) !=
            CX_OK) {
            goto end;
        }

        // compute compressed public key
        if (crypto_get_compressed_pubkey(public_key.W, pubkey) < 0) {
            goto end;
        }
    }

    error = false;

end:
    explicit_bzero(&private_key, sizeof(private_key));

    if (error) {
        // unexpected error when signing
        explicit_bzero(out, MAX_DER_SIG_LEN);  // never produce a valid signature on errors
        return -1;
    }

    if (info != NULL) {
        *info = info_internal;
    }

    return sig_len;
}

void crypto_tr_tagged_hash_init(cx_sha256_t *hash_context, const uint8_t *tag, uint16_t tag_len) {
    int res;
    // we recycle the input to save memory (will reinit later)
    cx_sha256_init(hash_context);

    uint8_t hashtag[32];
    res = crypto_hash_update(&hash_context->header, tag, tag_len);
    LEDGER_ASSERT(res == CX_OK, "Unexpected error in sha256 computation. Returned: %d", res);
    res = crypto_hash_digest(&hash_context->header, hashtag, sizeof(hashtag));
    LEDGER_ASSERT(res == CX_OK, "Unexpected error in sha256 computation. Returned: %d", res);

    cx_sha256_init(hash_context);
    res = crypto_hash_update(&hash_context->header, hashtag, sizeof(hashtag));
    LEDGER_ASSERT(res == CX_OK, "Unexpected error in sha256 computation. Returned: %d", res);
    res = crypto_hash_update(&hash_context->header, hashtag, sizeof(hashtag));
    LEDGER_ASSERT(res == CX_OK, "Unexpected error in sha256 computation. Returned: %d", res);
}

void crypto_tr_tapleaf_hash_init(cx_sha256_t *hash_context) {
    crypto_tr_tagged_hash_init(hash_context, BIP0341_tapleaf_tag, sizeof(BIP0341_tapleaf_tag));
}

static int crypto_tr_lift_x(const uint8_t x[static 32], uint8_t out[static 65]) {
    // save memory by reusing output buffer for intermediate results
    uint8_t *y = out + 1 + 32;
    // we use the memory for the x-coordinate of the output as a temporary variable
    uint8_t *c = out + 1;

    uint8_t e = 3;
    if (CX_OK != cx_math_powm_no_throw(c, x, &e, 1, secp256k1_p, 32)) return -1;  // c = x^3 (mod p)
    uint8_t scalar[32] = {0};
    scalar[31] = 7;
    if (CX_OK != cx_math_addm_no_throw(c, c, scalar, secp256k1_p, 32))
        return -1;  // c = x^3 + 7 (mod p)

    if (CX_OK != cx_math_powm_no_throw(y, c, secp256k1_sqr_exponent, 32, secp256k1_p, 32))
        return -1;  // y = sqrt(x^3 + 7) (mod p)

    // sanity check: fail if y * y % p != x^3 + 7
    uint8_t y_2[32];
    e = 2;
    if (CX_OK != cx_math_powm_no_throw(y_2, y, &e, 1, secp256k1_p, 32)) return -1;  // y^2 (mod p)
    int diff;
    if (CX_OK != cx_math_cmp_no_throw(y_2, c, 32, &diff) || diff != 0) {
        return -1;
    }

    if (y[31] & 1) {
        // y must be even: take the negation
        if (CX_OK != cx_math_sub_no_throw(out + 1 + 32, secp256k1_p, y, 32)) return -1;
    }

    // add the 0x04 prefix; copy x verbatim
    out[0] = 0x04;
    memcpy(out + 1, x, 32);

    return 0;
}

// Computes a tagged hash according to BIP-340.
// If data2_len > 0, then data2 must be non-NULL and the `data` and `data2` arrays are concatenated.
static void crypto_tr_tagged_hash(const uint8_t *tag,
                                  uint16_t tag_len,
                                  const uint8_t *data,
                                  uint16_t data_len,
                                  const uint8_t *data2,
                                  uint16_t data2_len,
                                  uint8_t out[static CX_SHA256_SIZE]) {
    // First compute hashtag, reuse out buffer for that
    cx_sha256_hash(tag, tag_len, out);

    cx_iovec_t iovec[4] = {{.iov_base = out, .iov_len = CX_SHA256_SIZE},
                           {.iov_base = out, .iov_len = CX_SHA256_SIZE},
                           {.iov_base = data, .iov_len = data_len},
                           {.iov_base = data2, .iov_len = data2_len}};
    if (data2_len > 0) {
        cx_sha256_hash_iovec(iovec, 4, out);
    } else {
        cx_sha256_hash_iovec(iovec, 3, out);
    }
}

void crypto_tr_combine_taptree_hashes(const uint8_t left_h[static 32],
                                      const uint8_t right_h[static 32],
                                      uint8_t out[static 32]) {
    if (memcmp(left_h, right_h, 32) < 0) {
        crypto_tr_tagged_hash(BIP0341_tapbranch_tag,
                              sizeof(BIP0341_tapbranch_tag),
                              left_h,
                              32,
                              right_h,
                              32,
                              out);
    } else {
        crypto_tr_tagged_hash(BIP0341_tapbranch_tag,
                              sizeof(BIP0341_tapbranch_tag),
                              right_h,
                              32,
                              left_h,
                              32,
                              out);
    }
}

// Like taproot_tweak_pubkey of BIP0341
int crypto_tr_tweak_pubkey(const uint8_t pubkey[static 32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[static 32]) {
    uint8_t t[32];

    crypto_tr_tagged_hash(BIP0341_taptweak_tag,
                          sizeof(BIP0341_taptweak_tag),
                          pubkey,
                          32,
                          h,
                          h_len,
                          t);

    // fail if t is not smaller than the curve order
    int diff;
    if (CX_OK != cx_math_cmp_no_throw(t, secp256k1_n, 32, &diff) || diff >= 0) {
        return -1;
    }

    uint8_t Q[65];

    uint8_t lifted_pubkey[65];
    if (crypto_tr_lift_x(pubkey, lifted_pubkey) < 0) {
        return -1;
    }

    if (0 > secp256k1_point(t, Q)) {
        // point at infinity, or error
        return -1;
    }

    if (CX_OK != cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1, Q, Q, lifted_pubkey)) {
        return -1;  // error, or point at Infinity
    }

    *y_parity = Q[64] & 1;
    memcpy(out, Q + 1, 32);
    return 0;
}

// Like taproot_tweak_seckey of BIP0341
int crypto_tr_tweak_seckey(const uint8_t seckey[static 32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t out[static 32]) {
    uint8_t P[65];

    int ret = -1;
    do {  // loop to break out in case of error
        if (0 > secp256k1_point(seckey, P)) break;

        memmove(out, seckey, 32);

        if (P[64] & 1) {
            // odd y, negate the secret key
            if (CX_OK != cx_math_sub_no_throw(out, secp256k1_n, out, 32)) break;
        }

        uint8_t t[32];
        crypto_tr_tagged_hash(BIP0341_taptweak_tag,
                              sizeof(BIP0341_taptweak_tag),
                              &P[1],  // P[1:33] is x(P)
                              32,
                              h,
                              h_len,
                              t);

        // fail if t is not smaller than the curve order
        int diff;
        if (CX_OK != cx_math_cmp_no_throw(t, secp256k1_n, 32, &diff) || diff >= 0) break;

        if (CX_OK != cx_math_addm_no_throw(out, out, t, secp256k1_n, 32)) break;

        ret = 0;
    } while (0);

    if (ret != 0) {
        // In case of error, make sure that the output buffer doesn't contain data related to seckey
        explicit_bzero(out, 32);
    }

    explicit_bzero(&P, sizeof(P));

    return ret;
}
