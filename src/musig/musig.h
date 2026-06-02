#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MUSIG_PUBNONCE_SIZE 66

static uint8_t BIP_328_CHAINCODE[32] = {
    0x86, 0x80, 0x87, 0xCA, 0x02, 0xA6, 0xF9, 0x74, 0xC4, 0x59, 0x89, 0x24, 0xC3, 0x6B, 0x57, 0x76,
    0x2D, 0x32, 0xCB, 0x45, 0x71, 0x71, 0x67, 0xE3, 0x00, 0x62, 0x2C, 0x71, 0x67, 0xE3, 0x89, 0x65};

typedef uint8_t plain_pk_t[33];
typedef uint8_t xonly_pk_t[32];

// An uncompressed pubkey, encoded as 04||x||y, where x and y are 32-byte big-endian coordinates.
// If the first byte (prefix) is 0, encodes the point at infinity.
typedef union {
    uint8_t raw[65];
    struct {
        uint8_t prefix;  // 0 for the point at infinity, otherwise 4.
        uint8_t x[32];
        uint8_t y[32];
    } __attribute__((packed));
} point_t;

typedef struct musig_keyagg_context_s {
    point_t Q;
    uint8_t gacc[32];
    uint8_t tacc[32];
} musig_keyagg_context_t;

typedef struct musig_secnonce_s {
    uint8_t k_1[32];
    uint8_t k_2[32];
    uint8_t pk[33];
} musig_secnonce_t;

typedef union {
    struct {
        uint8_t R_s1[33];
        uint8_t R_s2[33];
    } __attribute__((packed));
    uint8_t raw[66];
} musig_pubnonce_t;

typedef struct musig_session_context_s {
    musig_pubnonce_t *aggnonce;
    size_t n_keys;
    plain_pk_t *pubkeys;
    size_t n_tweaks;
    uint8_t **tweaks;
    bool *is_xonly;
    uint8_t *msg;
    size_t msg_len;
} musig_session_context_t;

// Comparator for 33-byte compressed public key, in order to sort according to the KeySort
// algorithm of BIP-327.
static inline int compare_plain_pk(const void *a, const void *b) {
    return memcmp(a, b, sizeof(plain_pk_t));
}

/**
 * Computes the KeyAgg Context per BIP-0327.
 *
 * @param[in]  pubkeys
 *   Pointer to a list of pubkeys.
 * @param[in]  n_keys
 *   Number of pubkeys.
 * @param[out]  ctx
 *   Pointer to receive the musig KeyAgg Context.
 *
 * @return 0 on success, a negative number in case of error.
 */
int musig_key_agg(const plain_pk_t pubkeys[], size_t n_keys, musig_keyagg_context_t *ctx);

/**
 * Generates secret and public nonces (round 1 of MuSig per BIP-0327).
 *
 * @param[in]  rand
 *   The randomness to use.
 * @param[in]  rand_len
 *  The length of the randomness.
 * @param[in]  pk
 *   The 33-byte public key of the signer.
 * @param[in]  aggpk
 *   The 32-byte x-only aggregate public key.
 * @param[out] secnonce
 *   Pointer to receive the secret nonce.
 * @param[out] pubnonce
 *   Pointer to receive the public nonce.
 *
 * @return 0 on success, a negative number in case of error.
 */
int musig_nonce_gen(const uint8_t *rand,
                    size_t rand_len,
                    const plain_pk_t pk,
                    const xonly_pk_t aggpk,
                    musig_secnonce_t *secnonce,
                    musig_pubnonce_t *pubnonce);

/**
 * Generates the aggregate nonce (nonce_agg in the reference implementation).
 *
 * @param[in]  pubnonces
 *   A list of musig_pubnonce_t, the pubnonces of all the participants.
 * @param[in]  n_keys
 *   Number of pubkeys.
 * @param[out] out
 *   Pointer to receive the aggregate nonce.
 *
 * @return 0 on success, a negative number in case of error. On error, `-i - 1` is returned if the
 * nonce provided by the cosigner with index `i` is invalid, in order to allow blaming for a
 * disruptive signer.
 */
int musig_nonce_agg(const musig_pubnonce_t pubnonces[], size_t n_keys, musig_pubnonce_t *out);

/**
 * Computes the partial signature (round 2 of MuSig per BIP-0327).
 *
 * @param[in]  secnonce
 *   The secret nonce.
 * @param[in]  sk
 *   The secret key.
 * @param[in]  session_ctx
 *   The session context.
 * @param[out] psig
 *   Pointer to receive the partial signature.
 *
 * @return 0 on success, a negative number in case of error.
 */
int musig_sign(musig_secnonce_t *secnonce,
               const uint8_t sk[static 32],
               const musig_session_context_t *session_ctx,
               uint8_t psig[static 32]);
