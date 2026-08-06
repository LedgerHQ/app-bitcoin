/**
 * Speculos bridge: bind the SDK symbol names called by the application
 * to speculos's sys_cx_* / spec_cx_* primitives.
 *
 * The application is written against the Ledger SDK API (cx_bn_lock,
 * cx_ecpoint_alloc, cx_hmac_sha512, cx_ecfp_add_point_no_throw, ...).
 * Speculos provides a pure-C implementation of the underlying syscalls,
 * but under sys_-prefixed symbol names because on the device they're
 * reached through an SVC dispatcher.
 *
 * This file is mostly thin forwarders: the SDK name calls into the
 * corresponding sys_cx_* / spec_cx_*, with a calling-convention adapter
 * where the signatures diverge. Two higher-level wrappers
 * (cx_ecfp_scalar_mult_no_throw, cx_ecfp_add_point_no_throw) are
 * reimplemented because speculos's flat variants drop semantics the
 * app relies on. The SDK's bip32_derive_with_seed_* helpers come from
 * compiling lib_standard_app/crypto_helpers.c directly into app_crypto
 * via CMakeLists.txt — they are NOT reimplemented here.
 *
 * Functions not used by code-under-test are stubbed with explicit
 * aborts: they keep the linker happy and fail loudly if called.
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
 * cx_bn_t / cx_ecpoint_t. cxlib.h itself defines _SDK_2_0_ before
 * pulling in cx.h, so no pre-define is needed here. */
#include "bolos/cxlib.h"

/* SDK header that defines cx_iovec_t. Speculos does NOT define this
 * type, so we can pull the SDK definition in unconditionally; it has
 * no other shared symbols to clash with the speculos headers above. */
#include "lcx_common.h"

/* Loudly abort from a stub for a syscall the test target doesn't
 * exercise. Wrapped as a do/while(0) so the macro is statement-safe in
 * any context. */
#define STUB_ABORT(name)                                                      \
    do {                                                                      \
        fprintf(stderr,                                                       \
                "speculos_bridge: %s called but not implemented in this test" \
                " harness.\n",                                                \
                name);                                                        \
        abort();                                                              \
    } while (0)

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
 * cx_ecfp_scalar_mult_no_throw and cx_ecfp_add_point_no_throw are
 * literal copies of the SDK source (lib_cxng/src/cx_ecfp.c) — the
 * speculos sys_cx_ecfp_* variants either errx-abort on SECP256K1 input
 * (add_point) or fail to surface CX_EC_INFINITE_POINT to the caller
 * (scalar_mult), so we keep the bn-based composition for those.
 * ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------
 * One-shot hash & HMAC wrappers
 * ------------------------------------------------------------------ */

/* HMAC-SHA256 / HMAC-SHA512 are implemented directly by speculos under
 * a spec_ prefix. */
size_t cx_hmac_sha256(const uint8_t *key,
                      size_t key_len,
                      const uint8_t *in,
                      size_t len,
                      uint8_t *out,
                      size_t out_len) {
    return (size_t) spec_cx_hmac_sha256(key,
                                        (unsigned int) key_len,
                                        in,
                                        (unsigned int) len,
                                        out,
                                        (unsigned int) out_len);
}

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
int cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    return sys_cx_hash_sha256(in, len, out, out_len);
}

/* RIPEMD-160 one-shot, forwarded as iovec wrapper. Concatenates first
 * since speculos only exposes a flat (in, len) entry point. */
cx_err_t cx_ripemd160_hash_iovec(const cx_iovec_t *iovec, size_t iovec_count, uint8_t digest[20]) {
    size_t total = 0;
    for (size_t i = 0; i < iovec_count; i++) total += iovec[i].iov_len;
    if (total == 0) {
        uint8_t dummy = 0;
        int rc = sys_cx_hash_ripemd160(&dummy, 0, digest, 20);
        return (rc == 20) ? CX_OK : CX_INTERNAL_ERROR;
    }
    uint8_t *buf = malloc(total);
    if (!buf) return CX_MEMORY_FULL;
    size_t off = 0;
    for (size_t i = 0; i < iovec_count; i++) {
        memcpy(buf + off, iovec[i].iov_base, iovec[i].iov_len);
        off += iovec[i].iov_len;
    }
    int rc = sys_cx_hash_ripemd160(buf, total, digest, 20);
    free(buf);
    return (rc == 20) ? CX_OK : CX_INTERNAL_ERROR;
}

/* ------------------------------------------------------------------
 * Streaming-hash wrappers (cx_hash / cx_sha256)
 * ------------------------------------------------------------------ */

/* sys_cx_hash isn't declared in any speculos public header. */
extern unsigned long sys_cx_hash(cx_hash_t *hash,
                                 int mode,
                                 const uint8_t *in,
                                 size_t len,
                                 uint8_t *out,
                                 size_t out_len);

cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          int mode,
                          const unsigned char *in,
                          size_t len,
                          unsigned char *out,
                          size_t out_len) {
    /* speculos's sys_cx_hash returns digest_len on CX_LAST success and 0
     * otherwise; the SDK function returns CX_OK on success regardless.
     * speculos THROWs on any error (mapped to abort by the bridge), so
     * if we get here at all, treat it as success. */
    (void) sys_cx_hash(hash, mode, in, len, out, out_len);
    return CX_OK;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    /* Per the SDK header, this function always returns CX_OK. */
    cx_sha256_init(hash);
    return CX_OK;
}

cx_err_t cx_sha256_hash_iovec(const cx_iovec_t *iovec, size_t iovec_count, uint8_t *out) {
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);
    for (size_t i = 0; i < iovec_count; i++) {
        if (iovec[i].iov_len > 0) {
            sys_cx_hash(&ctx.header, 0, iovec[i].iov_base, iovec[i].iov_len, NULL, 0);
        }
    }
    sys_cx_hash(&ctx.header, CX_LAST, NULL, 0, out, 32);
    return CX_OK;
}

/* ------------------------------------------------------------------
 * Math wrappers
 *
 * The sys_cx_math_* primitives have useless return values (some return
 * 0xdeadbeef, some return 0 unconditionally — see the speculos source).
 * Treat any path through them as success; failure in speculos is
 * signaled by an errx(1, ...) that aborts the process.
 * ------------------------------------------------------------------ */

cx_err_t cx_math_addm_no_throw(uint8_t *r,
                               const uint8_t *a,
                               const uint8_t *b,
                               const uint8_t *m,
                               size_t len) {
    (void) sys_cx_math_addm(r, a, b, m, (unsigned int) len);
    return CX_OK;
}

cx_err_t cx_math_powm_no_throw(uint8_t *r,
                               const uint8_t *a,
                               const uint8_t *e,
                               size_t len_e,
                               const uint8_t *m,
                               size_t len) {
    (void) sys_cx_math_powm(r, a, e, len_e, m, len);
    return CX_OK;
}

cx_err_t cx_math_multm_no_throw(uint8_t *r,
                                const uint8_t *a,
                                const uint8_t *b,
                                const uint8_t *m,
                                size_t len) {
    (void) sys_cx_math_multm(r, a, b, m, (unsigned int) len);
    return CX_OK;
}

cx_err_t cx_math_modm_no_throw(uint8_t *v, size_t len_v, const uint8_t *m, size_t len_m) {
    (void) sys_cx_math_modm(v, (unsigned int) len_v, m, (unsigned int) len_m);
    return CX_OK;
}

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    (void) sys_cx_math_sub(r, a, b, len);
    return CX_OK;
}

/* sys_cx_math_cmp returns the int comparison result; the SDK wrapper
 * passes it through a diff out-param. */
cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t length, int *diff) {
    *diff = sys_cx_math_cmp(a, b, (unsigned int) length);
    return CX_OK;
}

/* ------------------------------------------------------------------
 * Misc utilities
 * ------------------------------------------------------------------ */

/* Constant-time memcmp, matching the SDK char convention (0 on equal,
 * nonzero otherwise). XOR-accumulate every byte pair so the loop's data
 * access pattern and branch behavior don't depend on where the first
 * mismatch occurs. */
char os_secure_memcmp(const void *src1, const void *src2, size_t length) {
    const uint8_t *a = (const uint8_t *) src1;
    const uint8_t *b = (const uint8_t *) src2;
    uint8_t diff = 0;
    for (size_t i = 0; i < length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------
 * ECDSA wrappers
 *
 * sys_cx_ecdsa_sign / sys_cx_ecdsa_verify use unsigned int for the
 * signature length (speculos returns the written length via the
 * function's return value), while the SDK's _no_throw wrappers use
 * size_t* in-out. We bridge the calling convention here.
 * ------------------------------------------------------------------ */

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
    if (n < 0) return CX_INTERNAL_ERROR;
    *sig_len = (size_t) n;
    if (info != NULL) *info = info_local;
    return CX_OK;
}

bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *pukey,
                              const uint8_t *hash,
                              size_t hash_len,
                              const uint8_t *sig,
                              size_t sig_len) {
    /* sys_cx_ecdsa_verify ignores its hashID and mode parameters; we
     * pass CX_SHA256 / 0 only to satisfy the signature. */
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
 * The seed itself is read by os_bip32.c through env_get_seed(); we
 * provide a deterministic stub for env_get_seed below.
 *
 * sys_os_perso_* aren't exposed by any speculos public header, so
 * declare them here.
 * ------------------------------------------------------------------ */

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
    return CX_OK; /* THROW path is fatal in our test harness. */
}

unsigned long os_perso_get_master_key_identifier(uint8_t *id, size_t id_len) {
    return sys_os_perso_get_master_key_identifier(id, id_len);
}

/* ------------------------------------------------------------------
 * EC key init / generation
 * ------------------------------------------------------------------ */

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        int keepprivate) {
    int rc = sys_cx_ecfp_generate_pair(curve, pubkey, privkey, keepprivate);
    return rc == 0 ? CX_OK : CX_INTERNAL_ERROR;
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
    return rc >= 0 ? CX_OK : CX_INTERNAL_ERROR;
}

/* ------------------------------------------------------------------
 * Stubs for unused crypto_helpers.c entry points.
 *
 * bip32_derive_with_seed_* are provided by compiling
 * lib_standard_app/crypto_helpers.c directly into app_crypto (see
 * CMakeLists.txt). The signing-helper variants in that file
 * (ecdsa_sign_rs / eddsa_sign) reference syscalls the app doesn't
 * exercise; these stubs keep the linker happy and abort loudly if a
 * test ever reaches them.
 * ------------------------------------------------------------------ */

cx_err_t cx_ecdsa_sign_rs_no_throw(const cx_ecfp_private_key_t *key,
                                   uint32_t mode,
                                   cx_md_t hashID,
                                   const uint8_t *hash,
                                   size_t hash_len,
                                   size_t rs_len,
                                   uint8_t *sig_r,
                                   uint8_t *sig_s,
                                   uint32_t *info) {
    (void) key;
    (void) mode;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) rs_len;
    (void) sig_r;
    (void) sig_s;
    (void) info;
    STUB_ABORT("cx_ecdsa_sign_rs_no_throw");
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len) {
    (void) pvkey;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    STUB_ABORT("cx_eddsa_sign_no_throw");
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

/* 0x10 = APPLICATION_FLAG_DERIVE_MASTER. Required by speculos's
 * os_bip32 to allow non-hardened derivation from the master key.
 * The real app does not set this flag — we enable it here so unit
 * tests can use any BIP32 test vector, hardened or not. */
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
 * BOLOS runtime: host-side glue and stubs
 *
 * On-device, these entry points are BOLOS primitives (exception stack,
 * RNG, PIC relocation, ...). On the host we either short-circuit them
 * (THROW → abort) or wire them to a host-equivalent (TRNG → OpenSSL).
 * ------------------------------------------------------------------ */

/* Custom setjmp/longjmp are ARM-asm in speculos. On the host we don't
 * need an exception mechanism: any THROW path is treated as a fatal
 * test failure. */
void os_longjmp(unsigned int exception) {
    fprintf(stderr, "os_longjmp(%u) — BOLOS exception in host test.\n", exception);
    abort();
}

/* sys_try_context_* are referenced by os_longjmp inside speculos's
 * exception.c, but on the host we redefine os_longjmp above, so they
 * are dead code. The application code calls the non-sys_ names via the
 * SDK header; we forward them so a THROW-free path stays inert. */
void *sys_try_context_set(void *ctx) {
    (void) ctx;
    return NULL;
}
void *sys_try_context_get(void) {
    return NULL;
}
void *try_context_set(void *ctx) {
    return sys_try_context_set(ctx);
}
void *try_context_get(void) {
    return sys_try_context_get();
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

/* The SDK's PIC() macro forwards to a `pic()` function that on the device
 * translates a link-time address into the runtime address used after the
 * loader has applied the application's relocations. On the host we run a
 * normal ELF so addresses don't change; the identity function suffices. */
void *pic(void *link_address) {
    return link_address;
}

/* mock_dispatcher.c resets cx_hash_mock's pool counter on every init. When
 * the dispatcher is wired to the speculos-backed cx_ primitives instead,
 * this global is never actually consulted — but it still has to be defined
 * for the linker. */
int g_sha256_pool_next = 0;

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

/* ------------------------------------------------------------------
 * Bridge init
 * ------------------------------------------------------------------ */

void speculos_bridge_init(void) {
    /* Deterministic OpenSSL RNG seed for reproducible test runs. */
    static const uint8_t seed[32] = {
        0x73, 0x70, 0x65, 0x63, 0x75, 0x6c, 0x6f, 0x73, 0x2d, 0x62, 0x72,
        0x69, 0x64, 0x67, 0x65, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x66,
        0x6f, 0x72, 0x2d, 0x75, 0x6e, 0x69, 0x74, 0x74, 0x65, 0x73,
    };
    RAND_seed(seed, sizeof(seed));
}
