/**
 * Real crypto implementations for unit tests using libsecp256k1 and OpenSSL.
 *
 * This provides real secp256k1 elliptic curve operations and hash functions
 * needed by bip32_CKDpub, crypto_hash160, crypto_tr_tweak_pubkey, etc.
 * It allows unit-testing get_wallet_script and get_script_address end-to-end.
 */

#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "/usr/include/secp256k1.h"
#include "/usr/include/secp256k1_extrakeys.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "cx.h"
#include "write.h"
#include "read.h"

#ifndef CX_OK
#define CX_OK 0x00000000
#endif
#ifndef CX_INTERNAL_ERROR
#define CX_INTERNAL_ERROR 0xFFFFFF85
#endif

/* cx_ecpoint_t stub - not used in our real implementations */
typedef struct { int dummy; } cx_ecpoint_t;

/* Provided by sha-256.c in libs/ */
#include "sha-256.h"

/* Import the app's types */
#include "crypto.h"
#include "secp256k1.h"

/* We need a global secp256k1 context */
static secp256k1_context *g_ctx = NULL;

static secp256k1_context *get_secp256k1_ctx(void) {
    if (g_ctx == NULL) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    }
    return g_ctx;
}

/* ========================================================================= */
/* HMAC-SHA512 using OpenSSL                                                  */
/* ========================================================================= */

void cx_hmac_sha512(const uint8_t *key,
                    size_t key_len,
                    const uint8_t *data,
                    size_t data_len,
                    uint8_t *out,
                    size_t out_len) {
    unsigned int len = 64;
    uint8_t buf[64];
    HMAC(EVP_sha512(), key, (int) key_len, data, data_len, buf, &len);
    size_t copy_len = out_len < 64 ? out_len : 64;
    memcpy(out, buf, copy_len);
}

/* ========================================================================= */
/* cx_math_cmp_no_throw                                                       */
/* ========================================================================= */

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t len, int *diff) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) {
            *diff = -1;
            return CX_OK;
        }
        if (a[i] > b[i]) {
            *diff = 1;
            return CX_OK;
        }
    }
    *diff = 0;
    return CX_OK;
}

/* ========================================================================= */
/* cx_math_sub_no_throw                                                       */
/* ========================================================================= */

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    int borrow = 0;
    for (int i = (int) len - 1; i >= 0; i--) {
        int tmp = (int) a[i] - (int) b[i] - borrow;
        if (tmp < 0) {
            tmp += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        r[i] = (uint8_t) tmp;
    }
    return CX_OK;
}

/* ========================================================================= */
/* cx_math_addm_no_throw (a + b) mod m                                        */
/* ========================================================================= */

cx_err_t cx_math_addm_no_throw(uint8_t *r,
                                const uint8_t *a,
                                const uint8_t *b,
                                const uint8_t *m,
                                size_t len) {
    /* Simple: r = a + b, then if r >= m, r -= m */
    int carry = 0;
    uint8_t sum[64];
    assert(len <= 64);
    for (int i = (int) len - 1; i >= 0; i--) {
        int tmp = (int) a[i] + (int) b[i] + carry;
        sum[i] = (uint8_t) (tmp & 0xFF);
        carry = tmp >> 8;
    }
    int diff;
    cx_math_cmp_no_throw(sum, m, len, &diff);
    if (diff >= 0 || carry) {
        cx_math_sub_no_throw(r, sum, m, len);
    } else {
        memcpy(r, sum, len);
    }
    return CX_OK;
}

/* ========================================================================= */
/* cx_math_powm_no_throw  - big-number modular exponentiation                 */
/* We only use this for point decompression, implement via OpenSSL BIGNUM     */
/* ========================================================================= */

#include <openssl/bn.h>

cx_err_t cx_math_powm_no_throw(uint8_t *r,
                                const uint8_t *a,
                                const uint8_t *e,
                                size_t e_len,
                                const uint8_t *m,
                                size_t m_len) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, (int) m_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e, (int) e_len, NULL);
    BIGNUM *bn_m = BN_bin2bn(m, (int) m_len, NULL);
    BIGNUM *bn_r = BN_new();

    BN_mod_exp(bn_r, bn_a, bn_e, bn_m, ctx);

    /* Pad output to m_len bytes */
    int r_bytes = BN_num_bytes(bn_r);
    memset(r, 0, m_len);
    BN_bn2bin(bn_r, r + (m_len - r_bytes));

    BN_free(bn_a);
    BN_free(bn_e);
    BN_free(bn_m);
    BN_free(bn_r);
    BN_CTX_free(ctx);
    return CX_OK;
}

/* ========================================================================= */
/* EC point operations using libsecp256k1                                     */
/* ========================================================================= */

cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve,
                                     uint8_t *R,
                                     const uint8_t *P,
                                     const uint8_t *Q) {
    (void) curve;
    secp256k1_context *ctx = get_secp256k1_ctx();

    secp256k1_pubkey pk_P, pk_Q;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk_P, P, 65)) return CX_INTERNAL_ERROR;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk_Q, Q, 65)) return CX_INTERNAL_ERROR;

    const secp256k1_pubkey *pks[2] = {&pk_P, &pk_Q};
    secp256k1_pubkey pk_result;
    if (!secp256k1_ec_pubkey_combine(ctx, &pk_result, pks, 2)) return CX_INTERNAL_ERROR;

    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, R, &out_len, &pk_result, SECP256K1_EC_UNCOMPRESSED);
    return CX_OK;
}

/* Scalar multiplication: R = k * P (where P is a point in uncompressed form) */
/* For unit tests, we only need the case where P = G (the generator) */
static cx_err_t ecfp_scalar_mult(uint8_t *P, const uint8_t *k, size_t k_len) {
    secp256k1_context *ctx = get_secp256k1_ctx();

    /* Check if P is the generator */
    secp256k1_pubkey pk;

    /* Create a pubkey from the scalar (effectively computing k*G) */
    uint8_t scalar[32];
    memset(scalar, 0, 32);
    if (k_len <= 32) {
        memcpy(scalar + (32 - k_len), k, k_len);
    }

    /* We check if P is the generator. If so, we compute k*G directly. */
    /* Otherwise, we use the tweak approach. */
    if (memcmp(P, secp256k1_generator, 65) == 0) {
        /* P is G, compute k*G */
        if (!secp256k1_ec_pubkey_create(ctx, &pk, scalar)) return CX_INTERNAL_ERROR;
    } else {
        /* P is not G, use P and multiply by scalar */
        /* secp256k1 doesn't have a direct scalar_mult_point.
         * We can use the following trick:
         * Parse P as pubkey, negate it to get -P, then compute k*G + (something)?
         * Actually, the cleaner approach is:
         * P' = P (parsed), then tweak with (k-1) */
        /* Actually libsecp256k1 doesn't expose arbitrary point multiplication.
         * We'll use a different approach for point decompression.
         * Since the only non-generator usage in our code is for bip32 where P=G,
         * and in crypto_tr_tweak_pubkey where P=G, this case shouldn't happen
         * in practice. But let's handle it safely. */

        /* The only case we hit this for is secp256k1_point_unsafe which always
         * passes the generator. Assert this for safety. */
        return CX_INTERNAL_ERROR;
    }

    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, P, &out_len, &pk, SECP256K1_EC_UNCOMPRESSED);
    return CX_OK;
}

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve,
                                       uint8_t *P,
                                       const uint8_t *k,
                                       size_t k_len) {
    (void) curve;
    return ecfp_scalar_mult(P, k, k_len);
}

/* ========================================================================= */
/* cx_ecdomain_parameters_length, cx_bn_lock/unlock, cx_ecpoint_*            */
/* These are used by cx_ecfp_scalar_mult_unsafe in crypto.c                  */
/* We provide stubs; the _unsafe variant calls these but we override it.     */
/* ========================================================================= */

cx_err_t cx_ecdomain_parameters_length(cx_curve_t curve, size_t *length) {
    (void) curve;
    *length = 32;
    return CX_OK;
}

cx_err_t cx_bn_lock(size_t word_nbytes, uint32_t flags) {
    (void) word_nbytes;
    (void) flags;
    return CX_OK;
}

void cx_bn_unlock(void) {}

cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *p, cx_curve_t curve) {
    (void) p;
    (void) curve;
    return CX_OK;
}

cx_err_t cx_ecpoint_init(cx_ecpoint_t *p,
                          const uint8_t *x,
                          size_t x_len,
                          const uint8_t *y,
                          size_t y_len) {
    (void) p;
    (void) x;
    (void) x_len;
    (void) y;
    (void) y_len;
    return CX_OK;
}

cx_err_t cx_ecpoint_scalarmul(cx_ecpoint_t *p, const uint8_t *k, size_t k_len) {
    (void) p;
    (void) k;
    (void) k_len;
    /* Not actually called since we override the callers */
    return CX_INTERNAL_ERROR;
}

cx_err_t cx_ecpoint_export(const cx_ecpoint_t *p,
                            uint8_t *x,
                            size_t x_len,
                            uint8_t *y,
                            size_t y_len) {
    (void) p;
    (void) x;
    (void) x_len;
    (void) y;
    (void) y_len;
    return CX_INTERNAL_ERROR;
}

/* ========================================================================= */
/* RIPEMD-160 using OpenSSL                                                   */
/* ========================================================================= */

cx_err_t cx_ripemd160_hash(const uint8_t *in, size_t in_len, uint8_t *out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_ripemd160();
    unsigned int md_len = 20;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, in, in_len);
    EVP_DigestFinal_ex(mdctx, out, &md_len);
    EVP_MD_CTX_free(mdctx);
    return CX_OK;
}

/* ========================================================================= */
/* crypto_hash160, crypto_ripemd160, crypto_get_key_fingerprint              */
/* These are app-level functions from crypto.c that we re-implement here.    */
/* ========================================================================= */

void crypto_ripemd160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    cx_ripemd160_hash(in, inlen, out);
}

void crypto_hash160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    uint8_t sha_buf[32];
    calc_sha_256(sha_buf, in, inlen);
    crypto_ripemd160(sha_buf, 32, out);
}

uint32_t crypto_get_key_fingerprint(const uint8_t pub_key[static 33]) {
    uint8_t key_rip[20];
    crypto_hash160(pub_key, 33, key_rip);
    return read_u32_be(key_rip, 0);
}

/* ========================================================================= */
/* crypto_get_compressed_pubkey / crypto_get_uncompressed_pubkey              */
/* ========================================================================= */

int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[static 65],
                                 uint8_t out[static 33]) {
    if (uncompressed_key[0] != 0x04) return -1;
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32);
    return 0;
}

int crypto_get_uncompressed_pubkey(const uint8_t compressed_key[static 33],
                                   uint8_t out[static 65]) {
    secp256k1_context *ctx = get_secp256k1_ctx();
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, compressed_key, 33)) return -1;
    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk, SECP256K1_EC_UNCOMPRESSED);
    return 0;
}

/* ========================================================================= */
/* bip32_CKDpub                                                               */
/* ========================================================================= */

int bip32_CKDpub(const serialized_extended_pubkey_t *parent,
                 uint32_t index,
                 serialized_extended_pubkey_t *child,
                 uint8_t *tweak) {
    if (index >= BIP32_FIRST_HARDENED_CHILD) return -1;
    if (parent->depth == 255) return -1;

    uint8_t I[64];
    {
        uint8_t tmp[33 + 4];
        memcpy(tmp, parent->compressed_pubkey, 33);
        write_u32_be(tmp, 33, index);
        cx_hmac_sha512(parent->chain_code, 32, tmp, sizeof(tmp), I, 64);
    }

    uint8_t *I_L = &I[0];
    uint8_t *I_R = &I[32];

    if (tweak != NULL) {
        memcpy(tweak, I_L, 32);
    }

    /* Check I_L < n */
    int diff;
    cx_math_cmp_no_throw(I_L, secp256k1_n, 32, &diff);
    if (diff >= 0) return -1;

    /* Compute child pubkey = point(I_L) + parent_pubkey */
    secp256k1_context *ctx = get_secp256k1_ctx();

    /* Parse parent compressed pubkey */
    secp256k1_pubkey parent_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &parent_pk, parent->compressed_pubkey, 33)) return -1;

    /* Compute point(I_L) by creating a pubkey from I_L as secret key */
    secp256k1_pubkey il_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &il_pk, I_L)) return -1;

    /* Add: child = point(I_L) + parent */
    const secp256k1_pubkey *pks[2] = {&il_pk, &parent_pk};
    secp256k1_pubkey child_pk;
    if (!secp256k1_ec_pubkey_combine(ctx, &child_pk, pks, 2)) return -1;

    /* Serialize compressed */
    size_t out_len = 33;
    uint8_t child_compressed[33];
    secp256k1_ec_pubkey_serialize(ctx, child_compressed, &out_len, &child_pk,
                                  SECP256K1_EC_COMPRESSED);

    memmove(child->version, parent->version, 4);
    child->depth = parent->depth + 1;

    uint32_t parent_fp = crypto_get_key_fingerprint(parent->compressed_pubkey);
    write_u32_be(child->parent_fingerprint, 0, parent_fp);
    write_u32_be(child->child_number, 0, index);
    memcpy(child->chain_code, I_R, 32);
    memcpy(child->compressed_pubkey, child_compressed, 33);

    return 0;
}

/* ========================================================================= */
/* Taproot functions                                                           */
/* ========================================================================= */

/* Tagged hash per BIP-340 */
void crypto_tr_tagged_hash(const uint8_t *tag,
                           uint16_t tag_len,
                           const uint8_t *data,
                           uint16_t data_len,
                           const uint8_t *data2,
                           uint16_t data2_len,
                           uint8_t out[static CX_SHA256_SIZE]) {
    /* Compute SHA256(tag) */
    uint8_t tag_hash[32];
    calc_sha_256(tag_hash, tag, tag_len);

    /* Compute SHA256(tag_hash || tag_hash || data || data2) */
    struct Sha_256 ctx;
    uint8_t hash_buf[32];
    sha_256_init(&ctx, hash_buf);
    sha_256_write(&ctx, tag_hash, 32);
    sha_256_write(&ctx, tag_hash, 32);
    sha_256_write(&ctx, data, data_len);
    if (data2_len > 0 && data2 != NULL) {
        sha_256_write(&ctx, data2, data2_len);
    }
    sha_256_close(&ctx);
    memcpy(out, hash_buf, 32);
}

void crypto_tr_tagged_hash_init(cx_sha256_t *hash_context, const uint8_t *tag, uint16_t tag_len) {
    /* Compute SHA256(tag) */
    uint8_t tag_hash[32];
    calc_sha_256(tag_hash, tag, tag_len);

    /* Init the hash context with tag_hash || tag_hash prefix */
    cx_sha256_init(hash_context);
    cx_hash_no_throw(&hash_context->header, 0, tag_hash, 32, NULL, 0);
    cx_hash_no_throw(&hash_context->header, 0, tag_hash, 32, NULL, 0);
}

static const uint8_t BIP0341_tapleaf_tag_local[] = {'T', 'a', 'p', 'L', 'e', 'a', 'f'};
static const uint8_t BIP0341_tapbranch_tag_local[] = {'T', 'a', 'p', 'B', 'r', 'a', 'n', 'c', 'h'};

void crypto_tr_tapleaf_hash_init(cx_sha256_t *hash_context) {
    crypto_tr_tagged_hash_init(hash_context, BIP0341_tapleaf_tag_local,
                               sizeof(BIP0341_tapleaf_tag_local));
}

void crypto_tr_combine_taptree_hashes(const uint8_t left_h[static 32],
                                      const uint8_t right_h[static 32],
                                      uint8_t out[static 32]) {
    if (memcmp(left_h, right_h, 32) < 0) {
        crypto_tr_tagged_hash(BIP0341_tapbranch_tag_local,
                              sizeof(BIP0341_tapbranch_tag_local),
                              left_h, 32, right_h, 32, out);
    } else {
        crypto_tr_tagged_hash(BIP0341_tapbranch_tag_local,
                              sizeof(BIP0341_tapbranch_tag_local),
                              right_h, 32, left_h, 32, out);
    }
}

int crypto_tr_lift_x(const uint8_t x[static 32], uint8_t out[static 65]) {
    secp256k1_context *ctx = get_secp256k1_ctx();

    /* Create an x-only pubkey and convert to full pubkey */
    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, x)) return -1;

    secp256k1_pubkey pk;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &pk, &xonly_pk, (const unsigned char[32]){0})) {
        /* Fallback: just parse and serialize */
        /* secp256k1_xonly_pubkey_tweak_add with zero tweak should give us the point with even y */
    }

    /* Actually, a simpler approach: construct a compressed key with 0x02 prefix and decompress */
    uint8_t compressed[33];
    compressed[0] = 0x02;  /* even y */
    memcpy(compressed + 1, x, 32);

    secp256k1_pubkey pk2;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk2, compressed, 33)) return -1;

    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk2, SECP256K1_EC_UNCOMPRESSED);
    return 0;
}

int crypto_tr_tweak_pubkey(const uint8_t pubkey[static 32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[static 32]) {
    static const uint8_t taptweak_tag[] = {'T', 'a', 'p', 'T', 'w', 'e', 'a', 'k'};

    uint8_t t[32];
    crypto_tr_tagged_hash(taptweak_tag, sizeof(taptweak_tag),
                          pubkey, 32, h, (uint16_t) h_len, t);

    /* Check t < n */
    int diff;
    cx_math_cmp_no_throw(t, secp256k1_n, 32, &diff);
    if (diff >= 0) return -1;

    /* Use libsecp256k1's xonly tweak API */
    secp256k1_context *ctx = get_secp256k1_ctx();

    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, pubkey)) return -1;

    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pk, &xonly_pk, t)) return -1;

    /* Extract x-only and parity */
    secp256k1_xonly_pubkey result_xonly;
    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &result_xonly, &parity, &tweaked_pk)) return -1;

    *y_parity = (uint8_t) parity;
    secp256k1_xonly_pubkey_serialize(ctx, out, &result_xonly);
    return 0;
}

/* ========================================================================= */
/* base58_encode_address (from crypto.c)                                      */
/* ========================================================================= */

/* crypto_get_checksum is already available from crypto_mocks, but we provide
 * it here too since we're using this library instead. */
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    calc_sha_256(buffer, in, in_len);
    calc_sha_256(buffer, buffer, 32);
    memmove(out, buffer, 4);
}

int base58_encode_address(const uint8_t in[20], uint32_t version, char *out, size_t out_len) {
    uint8_t tmp[4 + 20 + 4];

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

/* ========================================================================= */
/* cx_sha256_hash - inline in SDK, needed as a symbol here                    */
/* ========================================================================= */

cx_err_t cx_sha256_hash(const uint8_t *in, size_t in_len, uint8_t digest[static 32]) {
    calc_sha_256(digest, in, in_len);
    return CX_OK;
}
