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

cx_err_t cx_bn_alloc_init(cx_bn_t *bn_x, size_t size,
                          const uint8_t *bytes, size_t nbytes) {
    return sys_cx_bn_alloc_init(bn_x, size, bytes, nbytes);
}

cx_err_t cx_bn_destroy(cx_bn_t *bn_x) { return sys_cx_bn_destroy(bn_x); }

cx_err_t cx_bn_cmp(const cx_bn_t a, const cx_bn_t b, int *diff) {
    return sys_cx_bn_cmp(a, b, diff);
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t curve, size_t *length) {
    return sys_cx_ecdomain_parameters_length(curve, length);
}

cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv) {
    return sys_cx_ecpoint_alloc(P, cv);
}

cx_err_t cx_ecpoint_destroy(cx_ecpoint_t *P) { return sys_cx_ecpoint_destroy(P); }

cx_err_t cx_ecpoint_init(cx_ecpoint_t *p, const uint8_t *x, size_t x_len,
                         const uint8_t *y, size_t y_len) {
    return sys_cx_ecpoint_init(p, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_export(const cx_ecpoint_t *p, uint8_t *x, size_t x_len,
                           uint8_t *y, size_t y_len) {
    return sys_cx_ecpoint_export(p, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_add(cx_ecpoint_t *r, const cx_ecpoint_t *p,
                        const cx_ecpoint_t *q) {
    return sys_cx_ecpoint_add(r, p, q);
}

cx_err_t cx_ecpoint_scalarmul(cx_ecpoint_t *p, const uint8_t *k, size_t k_len) {
    return sys_cx_ecpoint_scalarmul(p, k, k_len);
}

cx_err_t cx_ecpoint_rnd_scalarmul(cx_ecpoint_t *p, const uint8_t *k,
                                  size_t k_len) {
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

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b,
                              size_t length, int *diff) {
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

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve, uint8_t *P,
                                      const uint8_t *k, size_t k_len) {
    size_t size;
    cx_ecpoint_t ecP;
    cx_err_t error;

    if ((error = sys_cx_ecdomain_parameters_length(curve, &size))) return error;
    if ((error = sys_cx_bn_lock(size, 0))) return error;

    if ((error = sys_cx_ecpoint_alloc(&ecP, curve))) goto end;
    if ((error = sys_cx_ecpoint_init(&ecP, P + 1, size, P + 1 + size, size)))
        goto end;
    if ((error = sys_cx_ecpoint_rnd_scalarmul(&ecP, k, k_len))) goto end;
    P[0] = 0x04;
    error = sys_cx_ecpoint_export(&ecP, &P[1], size, &P[1 + size], size);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve, unsigned char *R,
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
    if ((error = sys_cx_ecpoint_init(&ecP, P + 1, size, P + 1 + size, size)))
        goto end;
    if ((error = sys_cx_ecpoint_init(&ecQ, Q + 1, size, Q + 1 + size, size)))
        goto end;
    if ((error = sys_cx_ecpoint_add(&ecR, &ecP, &ecQ))) goto end;
    R[0] = 0x04;
    error = sys_cx_ecpoint_export(&ecR, &R[1], size, &R[1 + size], size);
end:
    sys_cx_bn_unlock();
    return error;
}

/* HMAC-SHA512 is implemented directly by speculos under a spec_ prefix. */
extern int spec_cx_hmac_sha512(const unsigned char *key, unsigned int key_len,
                               const unsigned char *in, unsigned int len,
                               unsigned char *out, unsigned int out_len);

size_t cx_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *in,
                      size_t len, uint8_t *out, size_t out_len) {
    return (size_t) spec_cx_hmac_sha512(key, (unsigned int) key_len, in,
                                        (unsigned int) len, out,
                                        (unsigned int) out_len);
}

/* SHA-256 one-shot. */
extern int sys_cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out,
                              size_t out_len);

int cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out,
                   size_t out_len) {
    return sys_cx_hash_sha256(in, len, out, out_len);
}

/* RIPEMD-160 one-shot, forwarded as iovec wrapper. */
extern int sys_cx_hash_ripemd160(const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t out_len);

typedef struct {
    const uint8_t *iov_base;
    size_t iov_len;
} cx_iovec_t_local;

cx_err_t cx_ripemd160_hash_iovec(const cx_iovec_t_local *iovec,
                                 size_t iovec_count, uint8_t digest[20]) {
    /* The app currently uses a single-iovec call. Concatenate if needed. */
    if (iovec_count == 1) {
        return (sys_cx_hash_ripemd160(iovec[0].iov_base, iovec[0].iov_len,
                                      digest, 20) == 20) ? 0 : 0xFFFFFF85;
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

#define STUB_ABORT(name)                                                    \
    fprintf(stderr,                                                         \
            "speculos_bridge: %s called but not implemented in this test"   \
            " harness.\n",                                                  \
            name);                                                          \
    abort()

cx_err_t cx_hash_no_throw(void *hash, int mode, const unsigned char *in,
                          size_t len, unsigned char *out, size_t out_len) {
    (void) hash; (void) mode; (void) in; (void) len; (void) out; (void) out_len;
    STUB_ABORT("cx_hash_no_throw");
}

cx_err_t cx_sha256_init_no_throw(void *hash) {
    (void) hash; STUB_ABORT("cx_sha256_init_no_throw");
}

cx_err_t cx_sha256_hash_iovec(const void *iovec, size_t iovec_count,
                              uint8_t *out) {
    (void) iovec; (void) iovec_count; (void) out;
    STUB_ABORT("cx_sha256_hash_iovec");
}

cx_err_t cx_math_addm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                               const uint8_t *m, size_t len) {
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

cx_err_t cx_math_powm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *e,
                               size_t len_e, const uint8_t *m, size_t len) {
    cx_bn_t bn_r, bn_a, bn_m;
    cx_err_t error;
    if ((error = sys_cx_bn_lock(len, 0))) return error;
    if ((error = sys_cx_bn_alloc(&bn_r, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_a, len, a, len))) goto end;
    if ((error = sys_cx_bn_alloc_init(&bn_m, len, m, len))) goto end;
    if ((error = sys_cx_bn_mod_pow(bn_r, bn_a, e, (uint32_t) len_e, bn_m)))
        goto end;
    error = sys_cx_bn_export(bn_r, r, len);
end:
    sys_cx_bn_unlock();
    return error;
}

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                              size_t len) {
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

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve, void *pubkey,
                                        void *privkey, int keepprivate) {
    (void) curve; (void) pubkey; (void) privkey; (void) keepprivate;
    STUB_ABORT("cx_ecfp_generate_pair_no_throw");
}

cx_err_t cx_ecdsa_sign_no_throw(const void *pvkey, uint32_t mode,
                                uint32_t hashID, const uint8_t *hash,
                                size_t hash_len, uint8_t *sig,
                                size_t *sig_len, uint32_t *info) {
    (void) pvkey; (void) mode; (void) hashID; (void) hash; (void) hash_len;
    (void) sig; (void) sig_len; (void) info;
    STUB_ABORT("cx_ecdsa_sign_no_throw");
}

cx_err_t bip32_derive_with_seed_init_privkey_256(unsigned int derivation_mode,
                                                 cx_curve_t curve,
                                                 const uint32_t *path,
                                                 size_t path_len,
                                                 void *privkey,
                                                 uint8_t *chain_code,
                                                 unsigned char *seed,
                                                 size_t seed_len) {
    (void) derivation_mode; (void) curve; (void) path; (void) path_len;
    (void) privkey; (void) chain_code; (void) seed; (void) seed_len;
    STUB_ABORT("bip32_derive_with_seed_init_privkey_256");
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
    (void) derivation_mode; (void) curve; (void) path; (void) path_len;
    (void) raw_pubkey; (void) chain_code; (void) hashID; (void) seed; (void) seed_len;
    STUB_ABORT("bip32_derive_with_seed_get_pubkey_256");
}

unsigned long os_perso_derive_node_with_seed_key(unsigned int mode,
                                                 cx_curve_t curve,
                                                 const unsigned int *path,
                                                 unsigned int path_len,
                                                 unsigned char *privkey,
                                                 unsigned char *chain,
                                                 unsigned char *seed_key,
                                                 unsigned int seed_key_len) {
    (void) mode; (void) curve; (void) path; (void) path_len; (void) privkey;
    (void) chain; (void) seed_key; (void) seed_key_len;
    STUB_ABORT("os_perso_derive_node_with_seed_key");
}

unsigned long os_perso_get_master_key_identifier(uint8_t *id, size_t id_len) {
    (void) id; (void) id_len;
    STUB_ABORT("os_perso_get_master_key_identifier");
}

/* ------------------------------------------------------------------
 * BOLOS runtime stubs
 * ------------------------------------------------------------------ */

/* Custom setjmp/longjmp are ARM-asm in speculos. On the host we don't
 * need an exception mechanism: any THROW path is treated as a fatal
 * test failure. */
void os_longjmp(unsigned int exception) {
    fprintf(stderr, "os_longjmp(%u) — BOLOS exception in host test.\n",
            exception);
    abort();
}

/* sys_try_context_get is referenced by os_longjmp inside speculos's
 * exception.c, but on the host we redefine os_longjmp above, so this
 * is dead code. Provide a stub anyway. */
void *sys_try_context_set(void *ctx) { (void) ctx; return NULL; }
void *sys_try_context_get(void) { return NULL; }

void assert_exit(bool confirm, const char *file, unsigned int line) {
    (void) confirm; (void) file; (void) line;
    fprintf(stderr, "assert_exit fired in host test at %s:%u\n", file, line);
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
    (void) out_pub; (void) priv; STUB_ABORT("ED25519_public_from_private");
}
int ED25519_sign(uint8_t *out_sig, const uint8_t *msg, size_t msg_len,
                 const uint8_t pub[32], const uint8_t priv[32]) {
    (void) out_sig; (void) msg; (void) msg_len; (void) pub; (void) priv;
    STUB_ABORT("ED25519_sign");
}
int ED25519_verify(const uint8_t *msg, size_t msg_len,
                   const uint8_t sig[64], const uint8_t pub[32]) {
    (void) msg; (void) msg_len; (void) sig; (void) pub;
    STUB_ABORT("ED25519_verify");
}

/* The application code references `try_context_get` / `try_context_set`
 * via the SDK header. On the device these are the BOLOS exception-stack
 * primitives. On the host we redirect THROW to abort, so these never
 * fire; provide trivial forwarders. */
void *try_context_set(void *ctx) { return sys_try_context_set(ctx); }
void *try_context_get(void) { return sys_try_context_get(); }

void speculos_bridge_init(void) {
    /* Deterministic OpenSSL RNG seed for reproducible test runs. */
    static const uint8_t seed[32] = {
        0x73, 0x70, 0x65, 0x63, 0x75, 0x6c, 0x6f, 0x73,
        0x2d, 0x62, 0x72, 0x69, 0x64, 0x67, 0x65, 0x2d,
        0x73, 0x65, 0x65, 0x64, 0x2d, 0x66, 0x6f, 0x72,
        0x2d, 0x75, 0x6e, 0x69, 0x74, 0x74, 0x65, 0x73,
    };
    RAND_seed(seed, sizeof(seed));
}
