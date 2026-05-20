#include "fuzz_sha256.h"
#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e, f, g)  (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(a)       (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22))
#define EP1(e)       (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25))
#define SIG0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static inline uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8)
           | (uint32_t) p[3];
}

static inline void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static void fuzz_sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        W[i] = read_be32(block + i * 4);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h           = g;
        g           = f;
        f           = e;
        e           = d + t1;
        d           = c;
        c           = b;
        b           = a;
        a           = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void fuzz_sha256_init(fuzz_sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count    = 0;
    ctx->buf_len  = 0;
}

void fuzz_sha256_update(fuzz_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t space = 64 - ctx->buf_len;
        size_t chunk = len < space ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk;
        data += chunk;
        len -= chunk;
        ctx->count += chunk;
        if (ctx->buf_len == 64) {
            fuzz_sha256_transform(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void fuzz_sha256_final(fuzz_sha256_ctx *ctx, uint8_t digest[32])
{
    uint64_t bits = ctx->count * 8;
    uint8_t  pad  = 0x80;
    fuzz_sha256_update(ctx, &pad, 1);
    pad = 0x00;
    while (ctx->buf_len != 56) {
        fuzz_sha256_update(ctx, &pad, 1);
    }

    uint8_t len_be[8];
    for (int i = 7; i >= 0; i--) {
        len_be[i] = (uint8_t) (bits & 0xFF);
        bits >>= 8;
    }
    fuzz_sha256_update(ctx, len_be, 8);

    for (int i = 0; i < 8; i++) {
        write_be32(digest + i * 4, ctx->state[i]);
    }
}

void fuzz_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    fuzz_sha256_ctx ctx;
    fuzz_sha256_init(&ctx);
    fuzz_sha256_update(&ctx, data, len);
    fuzz_sha256_final(&ctx, digest);
}
