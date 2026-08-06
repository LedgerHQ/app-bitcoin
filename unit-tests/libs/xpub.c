#include <string.h>

#include "xpub.h"
#include "base58.h"

#define XPUB_BIN_LEN  78
#define XPUB_FULL_LEN 82 /* 78 payload bytes + 4 checksum bytes */

static void double_sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
    cx_hash_sha256(in, len, out, 32);
    cx_hash_sha256(out, 32, out, 32);
}

bool xpub_from_base58(const char *str, serialized_extended_pubkey_t *out) {
    uint8_t buf[XPUB_FULL_LEN];

    int n = base58_decode(str, strlen(str), buf, sizeof(buf));
    if (n != XPUB_FULL_LEN) return false;

    uint8_t check[32];
    double_sha256(buf, XPUB_BIN_LEN, check);
    if (memcmp(check, buf + XPUB_BIN_LEN, 4) != 0) return false;

    memcpy(out, buf, XPUB_BIN_LEN);
    return true;
}

int xpub_to_base58(const serialized_extended_pubkey_t *in, char *out,
                   size_t out_len) {
    uint8_t buf[XPUB_FULL_LEN];

    memcpy(buf, in, XPUB_BIN_LEN);

    uint8_t check[32];
    double_sha256(buf, XPUB_BIN_LEN, check);
    memcpy(buf + XPUB_BIN_LEN, check, 4);

    return base58_encode(buf, XPUB_FULL_LEN, out, out_len);
}
