#include <stdbool.h>

#include "musig.h"

/* SDK headers */
#include "cx_errors.h"

/* Local headers */
#include "crypto.h"
#include "secp256k1.h"

static const uint8_t BIP0327_keyagg_coeff_tag[] =
    {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'c', 'o', 'e', 'f', 'f', 'i', 'c', 'i', 'e', 'n', 't'};
static const uint8_t BIP0327_keyagg_list_tag[] =
    {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'l', 'i', 's', 't'};
static const uint8_t BIP0327_nonce_tag[] = {'M', 'u', 'S', 'i', 'g', '/', 'n', 'o', 'n', 'c', 'e'};
static const uint8_t BIP0327_noncecoef_tag[] =
    {'M', 'u', 'S', 'i', 'g', '/', 'n', 'o', 'n', 'c', 'e', 'c', 'o', 'e', 'f'};

static const uint8_t BIP0340_challenge_tag[] =
    {'B', 'I', 'P', '0', '3', '4', '0', '/', 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e'};

static inline bool is_point_infinite(const point_t *P) {
    return P->prefix == 0;
}

static inline void set_point_infinite(point_t *P) {
    memset(P->raw, 0, sizeof(point_t));
}

#define G ((const point_t *) secp256k1_generator)

static cx_err_t point_add(const point_t *P1, const point_t *P2, point_t *out) {
    if (is_point_infinite(P1)) {
        memmove(out->raw, P2->raw, sizeof(point_t));
        return CX_OK;
    }
    if (is_point_infinite(P2)) {
        memmove(out->raw, P1->raw, sizeof(point_t));
        return CX_OK;
    }
    if (memcmp(P1->x, P2->x, 32) == 0 && memcmp(P1->y, P2->y, 32) != 0) {
        memset(out->raw, 0, sizeof(point_t));
        return CX_OK;
    }

    cx_err_t res = cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1, out->raw, P1->raw, P2->raw);
    if (res == CX_EC_INFINITE_POINT) {
        set_point_infinite(out);
        return CX_OK;
    }

    return res;
}

static cx_err_t point_mul(const point_t *P, const uint8_t scalar[static 32], point_t *out) {
    if (is_point_infinite(P)) {
        set_point_infinite(out);
        return CX_OK;
    }
    point_t Q;  // result
    memcpy(&Q, P, sizeof(point_t));
    cx_err_t res = cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, Q.raw, scalar, 32);
    if (res == CX_EC_INFINITE_POINT) {
        set_point_infinite(out);
        return CX_OK;
    }
    memcpy(out, &Q, sizeof(point_t));
    return res;
}

// out can be equal to P
static int point_negate(const point_t *P, point_t *out) {
    if (is_point_infinite(P)) {
        set_point_infinite(out);
        return 0;
    }
    memmove(out->x, P->x, sizeof(out->x));

    if (CX_OK != cx_math_sub_no_throw(out->y, secp256k1_p, P->y, sizeof(out->y))) return -1;

    out->prefix = 4;
    return 0;
}

static bool has_even_y(const point_t *P) {
    LEDGER_ASSERT(!is_point_infinite(P), "has_even_y called with an infinite point");

    return P->y[31] % 2 == 0;
}

static int cpoint(const uint8_t x[33], point_t *out) {
    if (0 > crypto_tr_lift_x(&x[1], out->raw)) {
        PRINTF("Invalid compressed point: not on curve\n");
        return -1;
    }
    if (is_point_infinite(out)) {
        PRINTF("Invalid compressed point\n");
        return -1;
    }
    if (x[0] == 2) {
        return 0;
    } else if (x[0] == 3) {
        if (0 > point_negate(out, out)) {
            return -1;
        }
        return 0;
    } else {
        PRINTF("Invalid compressed point: invalid prefix\n");
        return -1;
    }
}

static int cpoint_ext(const uint8_t x[static sizeof(plain_pk_t)], point_t *out) {
    // Check if the point is at infinity (all bytes zero)
    if (is_array_all_zeros(x, sizeof(plain_pk_t))) {
        set_point_infinite(out);
        return 0;
    }

    // Otherwise, handle as a regular compressed point
    return cpoint(x, out);
}

static void musig_get_second_key(const plain_pk_t pubkeys[], size_t n_keys, plain_pk_t out) {
    for (size_t i = 0; i < n_keys; i++) {
        if (memcmp(pubkeys[0], pubkeys[i], sizeof(plain_pk_t)) != 0) {
            memcpy(out, pubkeys[i], sizeof(plain_pk_t));
            return;
        }
    }
    memset(out, 0, sizeof(plain_pk_t));
}

static void musig_hash_keys(const plain_pk_t pubkeys[],
                            size_t n_keys,
                            uint8_t out[static CX_SHA256_SIZE]) {
    cx_sha256_t hash_context;
    crypto_tr_tagged_hash_init(&hash_context,
                               BIP0327_keyagg_list_tag,
                               sizeof(BIP0327_keyagg_list_tag));
    for (size_t i = 0; i < n_keys; i++) {
        crypto_hash_update(&hash_context.header, pubkeys[i], sizeof(plain_pk_t));
    }
    crypto_hash_digest(&hash_context.header, out, CX_SHA256_SIZE);
}

static void musig_key_agg_coeff_internal(const plain_pk_t pubkeys[],
                                         size_t n_keys,
                                         const plain_pk_t pk_,
                                         const plain_pk_t pk2,
                                         uint8_t out[static CX_SHA256_SIZE]) {
    uint8_t L[CX_SHA256_SIZE];
    musig_hash_keys(pubkeys, n_keys, L);
    if (memcmp(pk_, pk2, sizeof(plain_pk_t)) == 0) {
        memset(out, 0, CX_SHA256_SIZE);
        out[31] = 1;
    } else {
        crypto_tr_tagged_hash(BIP0327_keyagg_coeff_tag,
                              sizeof(BIP0327_keyagg_coeff_tag),
                              L,
                              sizeof(L),
                              pk_,
                              sizeof(plain_pk_t),
                              out);

        // result modulo secp256k1_n
        int res = cx_math_modm_no_throw(out, CX_SHA256_SIZE, secp256k1_n, sizeof(secp256k1_n));

        LEDGER_ASSERT(res == CX_OK, "Modular reduction failed");
    }
}

static void musig_key_agg_coeff(const plain_pk_t pubkeys[],
                                size_t n_keys,
                                const plain_pk_t pk_,
                                uint8_t out[static CX_SHA256_SIZE]) {
    plain_pk_t pk2;
    musig_get_second_key(pubkeys, n_keys, pk2);

    musig_key_agg_coeff_internal(pubkeys, n_keys, pk_, pk2, out);
}

int musig_key_agg(const plain_pk_t pubkeys[], size_t n_keys, musig_keyagg_context_t *ctx) {
    plain_pk_t pk2;
    musig_get_second_key(pubkeys, n_keys, pk2);

    set_point_infinite(&ctx->Q);
    for (size_t i = 0; i < n_keys; i++) {
        point_t P;

        // set P := P_i
        if (0 > cpoint(pubkeys[i], &P)) {
            PRINTF("Invalid pubkey in musig_key_agg\n");
            return -1;
        }

        uint8_t a_i[32];
        musig_key_agg_coeff_internal(pubkeys, n_keys, pubkeys[i], pk2, a_i);

        // set P := a_i * P_i
        if (CX_OK != point_mul(&P, a_i, &P)) {
            PRINTF("Scalar multiplication failed in musig_key_agg\n");
            return -1;
        }

        point_add(&ctx->Q, &P, &ctx->Q);
    }

    if (is_point_infinite(&ctx->Q)) {
        PRINTF("Musig key aggregation resulted in an infinite point\n");
        return -1;
    }

    memset(ctx->tacc, 0, sizeof(ctx->tacc));
    memset(ctx->gacc, 0, sizeof(ctx->gacc));
    ctx->gacc[31] = 1;
    return 0;
}

static void musig_nonce_hash(const uint8_t *rand,
                             size_t rand_len,
                             const plain_pk_t pk,
                             const xonly_pk_t aggpk,
                             uint8_t i,
                             const uint8_t *msg_prefixed,
                             size_t msg_prefixed_len,
                             const uint8_t *extra_in,
                             size_t extra_in_len,
                             uint8_t out[static CX_SHA256_SIZE]) {
    cx_sha256_t hash_context;
    crypto_tr_tagged_hash_init(&hash_context, BIP0327_nonce_tag, sizeof(BIP0327_nonce_tag));

    // rand
    crypto_hash_update(&hash_context.header, rand, rand_len);

    // len(pk) + pk
    crypto_hash_update_u8(&hash_context.header, sizeof(plain_pk_t));
    crypto_hash_update(&hash_context.header, pk, sizeof(plain_pk_t));

    // len(aggpk) + aggpk
    crypto_hash_update_u8(&hash_context.header, sizeof(xonly_pk_t));
    crypto_hash_update(&hash_context.header, aggpk, sizeof(xonly_pk_t));

    // msg_prefixed
    crypto_hash_update(&hash_context.header, msg_prefixed, msg_prefixed_len);

    // len(extra_in) (4 bytes) + extra_in
    crypto_hash_update_u32(&hash_context.header, extra_in_len);
    if (extra_in_len > 0) {
        crypto_hash_update(&hash_context.header, extra_in, extra_in_len);
    }

    crypto_hash_update_u8(&hash_context.header, i);

    crypto_hash_digest(&hash_context.header, out, CX_SHA256_SIZE);
}

// same as nonce_gen_internal from the reference, removing the optional arguments sk, msg and
// extra_in, and making aggpk compulsory
int musig_nonce_gen(const uint8_t *rand,
                    size_t rand_len,
                    const plain_pk_t pk,
                    const xonly_pk_t aggpk,
                    musig_secnonce_t *secnonce,
                    musig_pubnonce_t *pubnonce) {
    uint8_t msg[] = {0x00};

    musig_nonce_hash(rand, rand_len, pk, aggpk, 0, msg, 1, NULL, 0, secnonce->k_1);
    if (CX_OK != cx_math_modm_no_throw(secnonce->k_1, 32, secp256k1_n, 32)) goto nonce_gen_fail;
    musig_nonce_hash(rand, rand_len, pk, aggpk, 1, msg, 1, NULL, 0, secnonce->k_2);
    if (CX_OK != cx_math_modm_no_throw(secnonce->k_2, 32, secp256k1_n, 32)) goto nonce_gen_fail;

    if (is_array_all_zeros(secnonce->k_1, sizeof(secnonce->k_1)) ||
        is_array_all_zeros(secnonce->k_2, sizeof(secnonce->k_2))) {
        // this can only happen with negligible probability
        goto nonce_gen_fail;
    }

    memcpy(secnonce->pk, pk, sizeof(secnonce->pk));

    point_t R_s1, R_s2;

    if (CX_OK != point_mul(G, secnonce->k_1, &R_s1)) goto nonce_gen_fail;
    if (CX_OK != point_mul(G, secnonce->k_2, &R_s2)) goto nonce_gen_fail;

    if (0 > crypto_get_compressed_pubkey(R_s1.raw, pubnonce->R_s1)) goto nonce_gen_fail;
    if (0 > crypto_get_compressed_pubkey(R_s2.raw, pubnonce->R_s2)) goto nonce_gen_fail;

    return 0;

nonce_gen_fail:
    explicit_bzero(secnonce->k_1, sizeof(secnonce->k_1));
    explicit_bzero(secnonce->k_2, sizeof(secnonce->k_2));
    return -1;
}

int musig_nonce_agg(const musig_pubnonce_t pubnonces[], size_t n_keys, musig_pubnonce_t *out) {
    for (size_t j = 1; j <= 2; j++) {
        point_t R_j;
        set_point_infinite(&R_j);
        for (size_t i = 0; i < n_keys; i++) {
            point_t R_ij;
            if (0 > cpoint(&pubnonces[i].raw[(j - 1) * sizeof(plain_pk_t)], &R_ij)) {
                PRINTF("Musig2 nonce aggregation: invalid contribution from cosigner %d\n", i);
                return -i - 1;
            }
            point_add(&R_j, &R_ij, &R_j);
        }

        if (is_point_infinite(&R_j)) {
            memset(&out->raw[(j - 1) * sizeof(plain_pk_t)], 0, sizeof(plain_pk_t));
        } else {
            crypto_get_compressed_pubkey(R_j.raw, &out->raw[(j - 1) * sizeof(plain_pk_t)]);
        }
    }
    return 0;
}

static int apply_tweak(musig_keyagg_context_t *ctx, const uint8_t tweak[static 32], bool is_xonly) {
    if (tweak == NULL || ctx == NULL) {
        return -1;
    }

    uint8_t g[32];
    memset(g, 0, 31);
    g[31] = 1;  // g = 1

    if (is_xonly && !has_even_y(&ctx->Q)) {
        // g = n - 1
        if (CX_OK != cx_math_sub_no_throw(g, secp256k1_n, g, 32)) {
            return -1;
        };
    }

    int diff;
    if (CX_OK != cx_math_cmp_no_throw(tweak, secp256k1_n, 32, &diff)) {
        return -1;
    }
    if (diff >= 0) {
        PRINTF("The tweak must be less than n\n");
        return -1;
    }

    // compute Q * g (in place)

    if (point_mul(&ctx->Q, g, &ctx->Q) != CX_OK) {
        return -1;
    }

    point_t T;  // compute T = tweak * G
    if (point_mul(G, tweak, &T) != CX_OK) {
        return -1;
    }

    // compute the resulting tweaked point g * Q + tweak * G
    point_add(&ctx->Q, &T, &ctx->Q);
    if (is_point_infinite(&ctx->Q)) {
        PRINTF("The result of tweaking cannot be infinity\n");
        return -1;
    }

    // gacc := g * gacc % n
    if (CX_OK != cx_math_multm_no_throw(ctx->gacc, g, ctx->gacc, secp256k1_n, 32)) {
        return -1;
    }

    // tacc := (g * tacc + t) % n
    if (CX_OK != cx_math_multm_no_throw(ctx->tacc, g, ctx->tacc, secp256k1_n, 32)) {
        return -1;
    }
    if (CX_OK != cx_math_addm_no_throw(ctx->tacc, ctx->tacc, tweak, secp256k1_n, 32)) {
        return -1;
    }

    return 0;
}

static int musig_get_session_values(const musig_session_context_t *session_ctx,
                                    point_t *Q,
                                    uint8_t gacc[static 32],
                                    uint8_t tacc[static 32],
                                    uint8_t b[static CX_SHA256_SIZE],
                                    point_t *R,
                                    uint8_t e[static CX_SHA256_SIZE]) {
    cx_sha256_t hash_context;

    // Perform key aggregation and tweaking
    musig_keyagg_context_t keyagg_ctx;

    if (0 > musig_key_agg(session_ctx->pubkeys, session_ctx->n_keys, &keyagg_ctx)) {
        return -1;
    }

    for (size_t i = 0; i < session_ctx->n_tweaks; i++) {
        if (0 > apply_tweak(&keyagg_ctx, session_ctx->tweaks[i], session_ctx->is_xonly[i])) {
            return -1;
        };
    }

    // Copy Q, gacc, tacc from keyagg_ctx
    memcpy(Q, &keyagg_ctx.Q, sizeof(point_t));
    memcpy(gacc, keyagg_ctx.gacc, 32);
    memcpy(tacc, keyagg_ctx.tacc, 32);

    // Calculate b
    crypto_tr_tagged_hash_init(&hash_context, BIP0327_noncecoef_tag, sizeof(BIP0327_noncecoef_tag));
    crypto_hash_update(&hash_context.header,
                       session_ctx->aggnonce->raw,
                       sizeof(session_ctx->aggnonce->raw));
    crypto_hash_update(&hash_context.header, Q->x, sizeof(Q->x));
    crypto_hash_update(&hash_context.header, session_ctx->msg, session_ctx->msg_len);
    crypto_hash_digest(&hash_context.header, b, CX_SHA256_SIZE);

    // Calculate R
    point_t R_1, R_2;
    if (0 > cpoint_ext(session_ctx->aggnonce->R_s1, &R_1)) {
        return -1;
    };
    if (0 > cpoint_ext(session_ctx->aggnonce->R_s2, &R_2)) {
        return -1;
    };

    // R2 := b*R2
    if (point_mul(&R_2, b, &R_2) != CX_OK) {
        return -1;
    }

    if (CX_OK != point_add(&R_1, &R_2, R)) {
        return -1;
    };
    if (is_point_infinite(R)) {
        memcpy(R->raw, G, sizeof(point_t));
    }

    // Calculate e
    crypto_tr_tagged_hash_init(&hash_context, BIP0340_challenge_tag, sizeof(BIP0340_challenge_tag));
    crypto_hash_update(&hash_context.header, R->x, sizeof(R->x));
    crypto_hash_update(&hash_context.header, Q->x, sizeof(Q->x));
    crypto_hash_update(&hash_context.header, session_ctx->msg, session_ctx->msg_len);
    crypto_hash_digest(&hash_context.header, e, CX_SHA256_SIZE);
    return 0;
}

int musig_get_session_key_agg_coeff(const musig_session_context_t *session_ctx,
                                    const point_t *P,
                                    uint8_t out[static 32]) {
    // Convert point to compressed public key
    plain_pk_t pk;
    crypto_get_compressed_pubkey(P->raw, pk);

    // Check if pk is in pubkeys
    bool found = false;
    for (size_t i = 0; i < session_ctx->n_keys; i++) {
        if (memcmp(pk, session_ctx->pubkeys[i], sizeof(plain_pk_t)) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        return -1;  // Public key not found in the list of pubkeys
    }

    musig_key_agg_coeff(session_ctx->pubkeys, session_ctx->n_keys, pk, out);
    return 0;
}

int musig_sign(musig_secnonce_t *secnonce,
               const uint8_t sk[static 32],
               const musig_session_context_t *session_ctx,
               uint8_t psig[static 32]) {
    point_t Q;
    uint8_t gacc[32];
    uint8_t tacc[32];
    uint8_t b[CX_SHA256_SIZE];
    point_t R;
    uint8_t e[CX_SHA256_SIZE];

    int diff;

    if (0 > musig_get_session_values(session_ctx, &Q, gacc, tacc, b, &R, e)) {
        return -1;
    }

    uint8_t k_1[32];
    uint8_t k_2[32];
    memcpy(k_1, secnonce->k_1, sizeof(k_1));
    memcpy(k_2, secnonce->k_2, sizeof(k_2));

    // paranoia: since reusing nonces is catastrophic, we make sure that they are zeroed out and
    // work with a local copy instead
    explicit_bzero(secnonce->k_1, sizeof(secnonce->k_1));
    explicit_bzero(secnonce->k_2, sizeof(secnonce->k_2));

    bool err = false;
    uint8_t bk_2[32];

    if (CX_OK != cx_math_cmp_no_throw(k_1, secp256k1_n, 32, &diff)) {
        err = true;
        goto cleanup;
    }
    if (is_array_all_zeros(k_1, sizeof(k_1)) || diff >= 0) {
        PRINTF("first secnonce value is out of range\n");
        err = true;
        goto cleanup;
    }
    if (CX_OK != cx_math_cmp_no_throw(k_2, secp256k1_n, 32, &diff)) {
        err = true;
        goto cleanup;
    }
    if (is_array_all_zeros(k_2, sizeof(k_2)) || diff >= 0) {
        PRINTF("second secnonce value is out of range\n");
        err = true;
        goto cleanup;
    }

    if (!has_even_y(&R)) {
        if (CX_OK != cx_math_sub_no_throw(k_1, secp256k1_n, k_1, 32)) {
            err = true;
            goto cleanup;
        };
        if (CX_OK != cx_math_sub_no_throw(k_2, secp256k1_n, k_2, 32)) {
            err = true;
            goto cleanup;
        };
    }

    if (CX_OK != cx_math_cmp_no_throw(sk, secp256k1_n, 32, &diff)) {
        err = true;
        goto cleanup;
    }
    if (is_array_all_zeros(sk, 32) || diff >= 0) {
        PRINTF("secret key value is out of range\n");
        err = true;
        goto cleanup;
    }

    // Put together all the variables that we want to always zero out before returning.
    // As an excess of safety, we put here any variable that is (directly or indirectly) derived
    // from the secret during the computation of the signature
    struct {
        uint8_t d[32];
        point_t P;
        uint8_t ead[32];
        uint8_t s[32];
    } secrets;

    do {  // executed only once, to allow for an easy way to break out of the block
        // P = d_ * G
        if (point_mul(G, sk, &secrets.P) != CX_OK) {
            err = true;
            break;
        }

        plain_pk_t pk;
        crypto_get_compressed_pubkey(secrets.P.raw, pk);

        if (memcmp(pk, secnonce->pk, sizeof(pk)) != 0) {
            err = true;
            PRINTF("Public key does not match nonce_gen argument\n");
            break;
        }

        uint8_t a[32];
        if (0 > musig_get_session_key_agg_coeff(session_ctx, &secrets.P, a)) {
            err = true;
            break;
        }

        // g = 1 if has_even_y(Q) else n - 1
        uint8_t g[32];
        memset(g, 0, 31);
        g[31] = 1;  // g = 1
        if (!has_even_y(&Q)) {
            // g = n - 1
            if (CX_OK != cx_math_sub_no_throw(g, secp256k1_n, g, 32)) {
                err = true;
                break;
            };
        }

        // d_ in the reference implementation is just sk
        // d = g * gacc % n
        if (CX_OK != cx_math_multm_no_throw(secrets.d, g, gacc, secp256k1_n, 32)) {
            err = true;
            break;
        }
        // d = g * gacc * d_ % n
        if (CX_OK != cx_math_multm_no_throw(secrets.d, secrets.d, sk, secp256k1_n, 32)) {
            err = true;
            break;
        }

        // bk_2 = b * k_2
        if (CX_OK != cx_math_multm_no_throw(bk_2, b, k_2, secp256k1_n, 32)) {
            err = true;
            break;
        }

        // e * a * d
        if (CX_OK != cx_math_multm_no_throw(secrets.ead, e, a, secp256k1_n, 32)) {
            err = true;
            break;
        }
        if (CX_OK != cx_math_multm_no_throw(secrets.ead, secrets.ead, secrets.d, secp256k1_n, 32)) {
            err = true;
            break;
        }

        // s = k_1 + b * k_2 + e * a * d
        memcpy(secrets.s, k_1, 32);
        if (CX_OK != cx_math_addm_no_throw(secrets.s, secrets.s, bk_2, secp256k1_n, 32)) {
            err = true;
            break;
        }
        if (CX_OK != cx_math_addm_no_throw(secrets.s, secrets.s, secrets.ead, secp256k1_n, 32)) {
            err = true;
            break;
        }

        memcpy(psig, secrets.s, 32);
    } while (false);

    // make sure to zero out any variable derived from secrets before returning
    explicit_bzero(&secrets, sizeof(secrets));

cleanup:
    explicit_bzero(k_1, sizeof(k_1));
    explicit_bzero(k_2, sizeof(k_2));
    explicit_bzero(bk_2, sizeof(bk_2));

    if (err) {
        return -1;
    }

    return 0;
}
