/**
 * Speculos bridge: SDK-name → speculos-name forwarders, and host-side
 * implementations of the lib_cxng high-level wrappers that the
 * application uses.
 *
 * The application is written against the Ledger SDK API (cx_bn_lock,
 * cx_ecpoint_alloc, cx_hmac_sha512, cx_ecfp_add_point_no_throw, ...).
 *
 * Speculos provides the *pure-C* implementation of the underlying
 * primitives, but under sys_-prefixed symbol names because on the
 * device they're reached through an SVC dispatcher.
 *
 * Functions not used by code-under-test are stubbed with explicit
 * aborts, in order to keep the linker happy but fail loudly if
 * called. Stubs can be replaced with real implementations as needed.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include "speculos_bridge.h"

/* Pull in the speculos type/prototype definitions. We use the speculos
 * header chain rather than the SDK one to avoid double-defining
 * cx_bn_t / cx_ecpoint_t. */
#define _SDK_2_0_
#include "bolos/cxlib.h"

/* ------------------------------------------------------------------
 * Forwarders: SDK name -> sys_cx_* implementation
 * ------------------------------------------------------------------ */

cx_err_t cx_bn_lock(size_t word_nbytes, uint32_t flags) {
    return sys_cx_bn_lock(word_nbytes, flags);
}

uint32_t cx_bn_unlock(void) {
    return sys_cx_bn_unlock();
}

cx_err_t cx_bn_alloc(cx_bn_t *bn_x, size_t size) {
    return sys_cx_bn_alloc(bn_x, size);
}

cx_err_t cx_bn_alloc_init(cx_bn_t *bn_x, size_t size, const uint8_t *bytes, size_t nbytes) {
    return sys_cx_bn_alloc_init(bn_x, size, bytes, nbytes);
}

cx_err_t cx_bn_destroy(cx_bn_t *bn_x) {
    return sys_cx_bn_destroy(bn_x);
}

cx_err_t cx_bn_cmp(const cx_bn_t a, const cx_bn_t b, int *diff) {
    return sys_cx_bn_cmp(a, b, diff);
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t curve, size_t *length) {
    return sys_cx_ecdomain_parameters_length(curve, length);
}

cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv) {
    return sys_cx_ecpoint_alloc(P, cv);
}

cx_err_t cx_ecpoint_destroy(cx_ecpoint_t *P) {
    return sys_cx_ecpoint_destroy(P);
}

cx_err_t cx_ecpoint_init(cx_ecpoint_t *p,
                         const uint8_t *x,
                         size_t x_len,
                         const uint8_t *y,
                         size_t y_len) {
    return sys_cx_ecpoint_init(p, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_export(const cx_ecpoint_t *p,
                           uint8_t *x,
                           size_t x_len,
                           uint8_t *y,
                           size_t y_len) {
    return sys_cx_ecpoint_export(p, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_add(cx_ecpoint_t *r, const cx_ecpoint_t *p, const cx_ecpoint_t *q) {
    return sys_cx_ecpoint_add(r, p, q);
}

cx_err_t cx_ecpoint_scalarmul(cx_ecpoint_t *p, const uint8_t *k, size_t k_len) {
    return sys_cx_ecpoint_scalarmul(p, k, k_len);
}

cx_err_t cx_ecpoint_rnd_scalarmul(cx_ecpoint_t *p, const uint8_t *k, size_t k_len) {
    return sys_cx_ecpoint_rnd_scalarmul(p, k, k_len);
}

/* ------------------------------------------------------------------
 * High-level lib_cxng wrappers, re-implemented here for the host.
 *
 * These are literal copies of the SDK source (lib_cxng/src/cx_math.c
 * and cx_ecfp.c). We re-implement instead of compiling the SDK file
 * because the SDK source pulls in a large set of headers that conflict
 * with the unit-test mock environment.
 * ------------------------------------------------------------------ */

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t length, int *diff) {
    cx_err_t error;
    cx_bn_t bn_a, bn_b;

    if ((error = sys_cx_bn_lock(length, 0))) return error;
    if ((error = sys_cx_bn_alloc_init(&bn_a, length, a, length))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_b, length, b, length))) goto end;
    error = sys_cx_bn_cmp(bn_a, bn_b, diff);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve,
                                      uint8_t *P,
                                      const uint8_t *k,
                                      size_t k_len) {
    size_t size;
    cx_ecpoint_t ecP;
    cx_err_t error;

    if ((error = sys_cx_ecdomain_parameters_length(curve, &size))) return error;
    if ((error = sys_cx_bn_lock(size, 0))) return error;

    if ((error = sys_cx_ecpoint_alloc(&ecP, curve))) goto end;
    if ((error = sys_cx_ecpoint_init(&ecP, P + 1, size, P + 1 + size, size))) goto end;
    if ((error = sys_cx_ecpoint_rnd_scalarmul(&ecP, k, k_len))) goto end;
    P[0] = 0x04;
    error = sys_cx_ecpoint_export(&ecP, &P[1], size, &P[1 + size], size);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve,
                                    unsigned char *R,
                                    const unsigned char *P,
                                    const unsigned char *Q) {
    size_t size;
    cx_ecpoint_t ecR, ecP, ecQ;
    cx_err_t error;

    if ((error = sys_cx_ecdomain_parameters_length(curve, &size))) return error;
    if ((error = sys_cx_bn_lock(size, 0))) return error;

    if ((error = sys_cx_ecpoint_alloc(&ecP, curve))) goto end;
    if ((error = sys_cx_ecpoint_alloc(&ecQ, curve))) goto end;
    if ((error = sys_cx_ecpoint_alloc(&ecR, curve))) goto end;
    if ((error = sys_cx_ecpoint_init(&ecP, P + 1, size, P + 1 + size, size))) goto end;
    if ((error = sys_cx_ecpoint_init(&ecQ, Q + 1, size, Q + 1 + size, size))) goto end;
    if ((error = sys_cx_ecpoint_add(&ecR, &ecP, &ecQ))) goto end;
    R[0] = 0x04;
    error = sys_cx_ecpoint_export(&ecR, &R[1], size, &R[1 + size], size);
end:
    sys_cx_bn_unlock();
    return error;
}

/* HMAC-SHA512 is implemented directly by speculos under a spec_ prefix. */
extern int spec_cx_hmac_sha512(const unsigned char *key,
                               unsigned int key_len,
                               const unsigned char *in,
                               unsigned int len,
                               unsigned char *out,
                               unsigned int out_len);

size_t cx_hmac_sha512(const uint8_t *key,
                      size_t key_len,
                      const uint8_t *in,
                      size_t len,
                      uint8_t *out,
                      size_t out_len) {
    return (size_t) spec_cx_hmac_sha512(key,
                                        (unsigned int) key_len,
                                        in,
                                        (unsigned int) len,
                                        out,
                                        (unsigned int) out_len);
}

/* SHA-256 one-shot. */
extern int sys_cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len);

int cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    return sys_cx_hash_sha256(in, len, out, out_len);
}

/* RIPEMD-160 one-shot, forwarded as iovec wrapper. */
extern int sys_cx_hash_ripemd160(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

typedef struct {
    const uint8_t *iov_base;
    size_t iov_len;
} cx_iovec_t_local;

cx_err_t cx_ripemd160_hash_iovec(const cx_iovec_t_local *iovec,
                                 size_t iovec_count,
                                 uint8_t digest[20]) {
    /* The app currently uses a single-iovec call. Concatenate if needed. */
    if (iovec_count == 1) {
        return (sys_cx_hash_ripemd160(iovec[0].iov_base, iovec[0].iov_len, digest, 20) == 20)
                   ? 0
                   : 0xFFFFFF85;
    }

    size_t total = 0;
    for (size_t i = 0; i < iovec_count; i++) total += iovec[i].iov_len;
    uint8_t *buf = malloc(total);
    if (!buf) return 0xFFFFFF8B; /* CX_MEMORY_FULL */
    size_t off = 0;
    for (size_t i = 0; i < iovec_count; i++) {
        memcpy(buf + off, iovec[i].iov_base, iovec[i].iov_len);
        off += iovec[i].iov_len;
    }
    int rc = sys_cx_hash_ripemd160(buf, total, digest, 20);
    free(buf);
    return (rc == 20) ? 0 : 0xFFFFFF85;
}

/* ------------------------------------------------------------------
 * Stubs for syscalls referenced by other parts of crypto.c that this
 * test target never exercises. Calling any of them is a programming
 * error in the test, so we abort loudly.
 * ------------------------------------------------------------------ */

#define STUB_ABORT(name)                                                  \
    fprintf(stderr,                                                       \
            "speculos_bridge: %s called but not implemented in this test" \
            " harness.\n",                                                \
            name);                                                        \
    abort()

cx_err_t cx_hash_no_throw(void *hash,
                          int mode,
                          const unsigned char *in,
                          size_t len,
                          unsigned char *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) len;
    (void) out;
    (void) out_len;
    STUB_ABORT("cx_hash_no_throw");
}

cx_err_t cx_sha256_init_no_throw(void *hash) {
    (void) hash;
    STUB_ABORT("cx_sha256_init_no_throw");
}

cx_err_t cx_sha256_hash_iovec(const void *iovec, size_t iovec_count, uint8_t *out) {
    (void) iovec;
    (void) iovec_count;
    (void) out;
    STUB_ABORT("cx_sha256_hash_iovec");
}

cx_err_t cx_math_addm_no_throw(uint8_t *r,
                               const uint8_t *a,
                               const uint8_t *b,
                               const uint8_t *m,
                               size_t len) {
    cx_bn_t bn_r, bn_a, bn_b, bn_m;
    cx_err_t error;
    if ((error = sys_cx_bn_lock(len, 0))) return error;
    if ((error = sys_cx_bn_alloc(&bn_r, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_a, len, a, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_b, len, b, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_m, len, m, len))) goto end;
    if ((error = sys_cx_bn_mod_add(bn_r, bn_a, bn_b, bn_m))) goto end;
    error = sys_cx_bn_export(bn_r, r, len);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_math_powm_no_throw(uint8_t *r,
                               const uint8_t *a,
                               const uint8_t *e,
                               size_t len_e,
                               const uint8_t *m,
                               size_t len) {
    cx_bn_t bn_r, bn_a, bn_m;
    cx_err_t error;
    if ((error = sys_cx_bn_lock(len, 0))) return error;
    if ((error = sys_cx_bn_alloc(&bn_r, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_a, len, a, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_m, len, m, len))) goto end;
    if ((error = sys_cx_bn_mod_pow(bn_r, bn_a, e, (uint32_t) len_e, bn_m))) goto end;
    error = sys_cx_bn_export(bn_r, r, len);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    cx_bn_t bn_r, bn_a, bn_b;
    cx_err_t error;
    if ((error = sys_cx_bn_lock(len, 0))) return error;
    if ((error = sys_cx_bn_alloc(&bn_r, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_a, len, a, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_b, len, b, len))) goto end;
    /* CX_CARRY is expected for sub when a < b; treat as ok. */
    error = sys_cx_bn_sub(bn_r, bn_a, bn_b);
    if (error && error != 0xFFFFFF21) goto end;
    error = sys_cx_bn_export(bn_r, r, len);
end:
    sys_cx_bn_unlock();
    return error;
}

/* sys_cx_ecdsa_sign / sys_cx_ecdsa_verify are declared by speculos's
 * cx_ec.h, pulled in transitively via bolos/cxlib.h above. They use
 * unsigned int for the signature length (speculos returns the written
 * length via the function's return value), while the SDK's _no_throw
 * wrappers use size_t* in-out. Bridge the calling convention here. */

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                uint32_t mode,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t *sig_len,
                                uint32_t *info) {
    unsigned int info_local = 0;
    int n = sys_cx_ecdsa_sign(pvkey,
                              (int) mode,
                              hashID,
                              hash,
                              (unsigned int) hash_len,
                              sig,
                              (unsigned int) *sig_len,
                              &info_local);
    if (n < 0) return 0xFFFFFF85; /* CX_INTERNAL_ERROR */
    *sig_len = (size_t) n;
    if (info != NULL) *info = info_local;
    return 0; /* CX_OK */
}

bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *pukey,
                              const uint8_t *hash,
                              size_t hash_len,
                              const uint8_t *sig,
                              size_t sig_len) {
    return sys_cx_ecdsa_verify(pukey,
                               0,
                               CX_SHA256,
                               hash,
                               (unsigned int) hash_len,
                               sig,
                               (unsigned int) sig_len) == 1;
}

/* ------------------------------------------------------------------
 * BIP32 seed derivation — forwarders to speculos's os_bip32.c.
 *
 * Speculos exposes:
 *   sys_os_perso_derive_node_with_seed_key(mode, curve, path, len,
 *                                          privkey, chain, seed_key, seed_key_len)
 *   sys_os_perso_get_master_key_identifier(identifier, length)
 *   sys_cx_ecfp_init_private_key(curve, raw_key, key_len, privkey)
 *   sys_cx_ecfp_generate_pair(curve, pubkey, privkey, keep_private)
 *
 * The seed itself is read by os_bip32.c through env_get_seed(); we
 * provide a deterministic stub for env_get_seed below.
 * ------------------------------------------------------------------ */

/* sys_cx_ecfp_init_private_key and sys_cx_ecfp_generate_pair are
 * already declared by speculos's cx_ec.h, pulled in transitively via
 * bolos/cxlib.h above. Declare here only what isn't exposed in a
 * speculos public header. */
extern unsigned long sys_os_perso_derive_node_with_seed_key(unsigned int mode,
                                                            cx_curve_t curve,
                                                            const unsigned int *path,
                                                            unsigned int path_len,
                                                            unsigned char *privkey,
                                                            unsigned char *chain,
                                                            unsigned char *seed_key,
                                                            unsigned int seed_key_len);
extern unsigned long sys_os_perso_get_master_key_identifier(uint8_t *identifier,
                                                            size_t identifier_length);

unsigned long os_perso_derive_node_with_seed_key(unsigned int mode,
                                                 cx_curve_t curve,
                                                 const unsigned int *path,
                                                 unsigned int path_len,
                                                 unsigned char *privkey,
                                                 unsigned char *chain,
                                                 unsigned char *seed_key,
                                                 unsigned int seed_key_len) {
    return sys_os_perso_derive_node_with_seed_key(mode,
                                                  curve,
                                                  path,
                                                  path_len,
                                                  privkey,
                                                  chain,
                                                  seed_key,
                                                  seed_key_len);
}

cx_err_t os_derive_bip32_with_seed_no_throw(unsigned int mode,
                                            cx_curve_t curve,
                                            const uint32_t *path,
                                            size_t path_len,
                                            unsigned char *privkey,
                                            unsigned char *chain,
                                            unsigned char *seed_key,
                                            size_t seed_key_len) {
    sys_os_perso_derive_node_with_seed_key(mode,
                                           curve,
                                           path,
                                           (unsigned int) path_len,
                                           privkey,
                                           chain,
                                           seed_key,
                                           (unsigned int) seed_key_len);
    return 0; /* CX_OK; THROW path is fatal in our test harness. */
}

unsigned long os_perso_get_master_key_identifier(uint8_t *id, size_t id_len) {
    return sys_os_perso_get_master_key_identifier(id, id_len);
}

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        int keepprivate) {
    int rc = sys_cx_ecfp_generate_pair(curve, pubkey, privkey, keepprivate);
    return rc == 0 ? 0 : 0xFFFFFF85;
}

cx_err_t cx_ecfp_generate_pair2_no_throw(cx_curve_t curve,
                                         cx_ecfp_public_key_t *pubkey,
                                         cx_ecfp_private_key_t *privkey,
                                         int keepprivate,
                                         cx_md_t hashID) {
    /* hashID only affects ed25519 derivation; for secp256k1 it is ignored. */
    (void) hashID;
    return cx_ecfp_generate_pair_no_throw(curve, pubkey, privkey, keepprivate);
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *raw,
                                           size_t raw_len,
                                           cx_ecfp_private_key_t *privkey) {
    int rc = sys_cx_ecfp_init_private_key(curve, raw, (unsigned int) raw_len, privkey);
    return rc >= 0 ? 0 : 0xFFFFFF85;
}

/* SDK helpers, reimplemented inline. Equivalent to
 * lib_standard_app/crypto_helpers.c — but rewritten here because that
 * file pulls in the full SDK header chain (incompatible with the
 * unit-test mock environment). */

cx_err_t bip32_derive_with_seed_init_privkey_256(unsigned int derivation_mode,
                                                 cx_curve_t curve,
                                                 const uint32_t *path,
                                                 size_t path_len,
                                                 cx_ecfp_private_key_t *privkey,
                                                 uint8_t *chain_code,
                                                 unsigned char *seed,
                                                 size_t seed_len) {
    uint8_t raw[64] = {0};
    cx_err_t err = os_derive_bip32_with_seed_no_throw(derivation_mode,
                                                      curve,
                                                      path,
                                                      path_len,
                                                      raw,
                                                      chain_code,
                                                      seed,
                                                      seed_len);
    if (err != 0) return err;
    return cx_ecfp_init_private_key_no_throw(curve, raw, 32, privkey);
}

cx_err_t bip32_derive_with_seed_get_pubkey_256(unsigned int derivation_mode,
                                               cx_curve_t curve,
                                               const uint32_t *path,
                                               size_t path_len,
                                               uint8_t raw_pubkey[65],
                                               uint8_t *chain_code,
                                               cx_md_t hashID,
                                               unsigned char *seed,
                                               size_t seed_len) {
    cx_ecfp_private_key_t privkey = {0};
    cx_ecfp_public_key_t pubkey = {0};

    cx_err_t err = bip32_derive_with_seed_init_privkey_256(derivation_mode,
                                                           curve,
                                                           path,
                                                           path_len,
                                                           &privkey,
                                                           chain_code,
                                                           seed,
                                                           seed_len);
    if (err != 0) return err;

    err = cx_ecfp_generate_pair2_no_throw(curve, &pubkey, &privkey, 1, hashID);
    if (err != 0) return err;
    if (pubkey.W_len != 65) return 0xFFFFFFA3; /* CX_EC_INVALID_CURVE */
    memcpy(raw_pubkey, pubkey.W, 65);
    return 0;
}

/* ------------------------------------------------------------------
 * Speculos environment globals.
 *
 * os_bip32.c reads the BIP32 master seed via env_get_seed(), references
 * the app_flags global, and consults get_app_derivation_path() to check
 * whether the requested derivation path is allowed. None of those
 * concepts apply to the host test harness, so we provide trivial
 * fixtures: a fixed 64-byte test seed, no flag restrictions, no
 * derivation-path restriction.
 * ------------------------------------------------------------------ */

// NOTE: the app does not have this flag, but allowing any derivation simplifies unit test
// by allowing the use of any BIP32 test vector.
/* 0x10 = APPLICATION_FLAG_DERIVE_MASTER — required by speculos's
 * os_bip32 to allow non-hardened derivation paths from the master. */
uint64_t app_flags = 0x10u;

unsigned long get_app_derivation_path(uint8_t **derivationPath) {
    (void) derivationPath;
    return 0; /* no restriction */
}

/* The same 64-byte test seed speculos uses when no SPECULOS_SEED env
 * variable is set. Matches the mnemonic
 *   "glory promote mansion idle axis finger extra february uncover one
 *    trip resource lawn turtle enact monster seven myth punch hobby
 *    comfort wild raise skin".
 * Tests use this fixed seed to assert against known BIP32 derivations. */
static const uint8_t speculos_bridge_seed[64] = {
    0xb1, 0x19, 0x97, 0xfa, 0xff, 0x42, 0x0a, 0x33, 0x1b, 0xb4, 0xa4, 0xff, 0xdc, 0x8b, 0xdc, 0x8b,
    0xa7, 0xc0, 0x17, 0x32, 0xa9, 0x9a, 0x30, 0xd8, 0x3d, 0xbb, 0xeb, 0xd4, 0x69, 0x66, 0x6c, 0x84,
    0xb4, 0x7d, 0x09, 0xd3, 0xf5, 0xf4, 0x72, 0xb3, 0xb9, 0x38, 0x4a, 0xc6, 0x34, 0xbe, 0xba, 0x2a,
    0x44, 0x0b, 0xa3, 0x6e, 0xc7, 0x66, 0x11, 0x44, 0x13, 0x2f, 0x35, 0xe2, 0x06, 0x87, 0x35, 0x64,
};

size_t env_get_seed(uint8_t *seed, size_t max_size) {
    size_t n = sizeof(speculos_bridge_seed);
    if (n > max_size) n = max_size;
    memcpy(seed, speculos_bridge_seed, n);
    return n;
}

/* ------------------------------------------------------------------
 * BOLOS runtime stubs
 * ------------------------------------------------------------------ */

/* Custom setjmp/longjmp are ARM-asm in speculos. On the host we don't
 * need an exception mechanism: any THROW path is treated as a fatal
 * test failure. */
void os_longjmp(unsigned int exception) {
    fprintf(stderr, "os_longjmp(%u) — BOLOS exception in host test.\n", exception);
    abort();
}

/* sys_try_context_get is referenced by os_longjmp inside speculos's
 * exception.c, but on the host we redefine os_longjmp above, so this
 * is dead code. Provide a stub anyway. */
void *sys_try_context_set(void *ctx) {
    (void) ctx;
    return NULL;
}
void *sys_try_context_get(void) {
    return NULL;
}

void __attribute__((noreturn)) assert_exit(bool confirm) {
    (void) confirm;
    fprintf(stderr, "assert_exit fired in host test\n");
    abort();
}

/* sys_cx_rng is referenced by speculos's cxlib.c (sys_cx_get_random_bytes
 * forwards to it). On the device it pulls from the TRNG; on the host we
 * route to OpenSSL. */
unsigned long sys_cx_rng(uint8_t *buffer, unsigned int length) {
    if (RAND_bytes(buffer, (int) length) != 1) abort();
    return (unsigned long) buffer;
}

/* ED25519 entry points from libcrypto are not directly available on
 * modern OpenSSL; speculos references them from libsodium. Our test
 * target does not exercise ED25519, so stubbing keeps the linker happy. */
int ED25519_public_from_private(uint8_t out_pub[32], const uint8_t priv[32]) {
    (void) out_pub;
    (void) priv;
    STUB_ABORT("ED25519_public_from_private");
}
int ED25519_sign(uint8_t *out_sig,
                 const uint8_t *msg,
                 size_t msg_len,
                 const uint8_t pub[32],
                 const uint8_t priv[32]) {
    (void) out_sig;
    (void) msg;
    (void) msg_len;
    (void) pub;
    (void) priv;
    STUB_ABORT("ED25519_sign");
}
int ED25519_verify(const uint8_t *msg,
                   size_t msg_len,
                   const uint8_t sig[64],
                   const uint8_t pub[32]) {
    (void) msg;
    (void) msg_len;
    (void) sig;
    (void) pub;
    STUB_ABORT("ED25519_verify");
}

/* The application code references `try_context_get` / `try_context_set`
 * via the SDK header. On the device these are the BOLOS exception-stack
 * primitives. On the host we redirect THROW to abort, so these never
 * fire; provide trivial forwarders. */
void *try_context_set(void *ctx) {
    return sys_try_context_set(ctx);
}
void *try_context_get(void) {
    return sys_try_context_get();
}

void speculos_bridge_init(void) {
    /* Deterministic OpenSSL RNG seed for reproducible test runs. */
    static const uint8_t seed[32] = {
        0x73, 0x70, 0x65, 0x63, 0x75, 0x6c, 0x6f, 0x73, 0x2d, 0x62, 0x72,
        0x69, 0x64, 0x67, 0x65, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x66,
        0x6f, 0x72, 0x2d, 0x75, 0x6e, 0x69, 0x74, 0x74, 0x65, 0x73,
    };
    RAND_seed(seed, sizeof(seed));
}
