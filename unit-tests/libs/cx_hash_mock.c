/**
 * Mock implementation of Ledger SDK cx_hash / cx_sha256 functions,
 * wrapping the reference SHA-256 library (sha-256.c).
 *
 * Since `struct Sha_256` does not fit inside `cx_sha256_t`, we use a
 * static pool of contexts and store the pool index in `cx_sha256_t.blen`.
 */

#include <string.h>
#include <assert.h>

#include "cx_hash_mock.h"
#include "sha-256.h"

/* Pool of streaming SHA-256 contexts for the mock */
#define MAX_HASH_CONTEXTS 32
static struct Sha_256 g_sha256_pool[MAX_HASH_CONTEXTS];
static uint8_t g_sha256_hash_out[MAX_HASH_CONTEXTS][32];
int g_sha256_pool_next = 0;

/**
 * Map a cx_sha256_t to its pool index.  We store the index in `blen`.
 */
static struct Sha_256 *get_sha256_ctx(cx_sha256_t *hash) {
    unsigned int idx = hash->blen;
    assert(idx < MAX_HASH_CONTEXTS);
    return &g_sha256_pool[idx];
}

int cx_sha256_init(cx_sha256_t *hash) {
    memset(hash, 0, sizeof(cx_sha256_t));
    hash->header.algo = CX_SHA256;
    hash->header.counter = 0;

    /* Allocate a pool slot */
    assert(g_sha256_pool_next < MAX_HASH_CONTEXTS);
    int idx = g_sha256_pool_next++;
    hash->blen = (unsigned int) idx;

    sha_256_init(&g_sha256_pool[idx], g_sha256_hash_out[idx]);
    return CX_SHA256;
}

int cx_hash_no_throw(cx_hash_t *hash,
                     int mode,
                     const unsigned char *in,
                     unsigned int in_len,
                     unsigned char *out,
                     unsigned int out_len) {
    /* We only support SHA-256 in this mock */
    assert(hash->algo == CX_SHA256);

    cx_sha256_t *sha = (cx_sha256_t *) hash;
    struct Sha_256 *ctx = get_sha256_ctx(sha);

    if (in != NULL && in_len > 0) {
        sha_256_write(ctx, in, in_len);
    }

    if (mode & CX_LAST) {
        uint8_t *result = sha_256_close(ctx);
        if (out != NULL && out_len >= 32) {
            memcpy(out, result, 32);
        }
    }

    return 0;
}

int cx_hash_sha256(const unsigned char *in,
                   unsigned int in_len,
                   unsigned char *out,
                   unsigned int out_len) {
    (void) out_len;
    calc_sha_256(out, in, in_len);
    return CX_SHA256_SIZE;
}

int cx_sha256_hash_iovec(const cx_iovec_t *iovec, size_t iovec_count, uint8_t out[32]) {
    /* Use a temporary streaming context */
    struct Sha_256 ctx;
    uint8_t hash_buf[32];
    sha_256_init(&ctx, hash_buf);

    for (size_t i = 0; i < iovec_count; i++) {
        if (iovec[i].iov_base != NULL && iovec[i].iov_len > 0) {
            sha_256_write(&ctx, iovec[i].iov_base, iovec[i].iov_len);
        }
    }

    sha_256_close(&ctx);
    memcpy(out, hash_buf, 32);
    return 0;
}
