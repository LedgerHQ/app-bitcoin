/**
 * Stubs for functions referenced by policy.c and other modules
 * that are not needed for the get_wallet_address unit tests.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* policy.c calls these but we don't need them for script derivation */
int get_extended_pubkey_at_path(const uint32_t *bip32_path,
                                uint8_t bip32_path_len,
                                uint32_t bip32_pubkey_version,
                                void *out) {
    (void) bip32_path;
    (void) bip32_path_len;
    (void) bip32_pubkey_version;
    (void) out;
    return -1;
}

int crypto_get_master_key_fingerprint(uint32_t *out) {
    (void) out;
    *out = 0;
    return 0;
}

int crypto_derive_symmetric_key(const char *label, size_t label_len, uint8_t *key) {
    (void) label;
    (void) label_len;
    memset(key, 0, 32);
    return 0;
}

int os_secure_memcmp(const void *src1, const void *src2, size_t length) {
    const uint8_t *s1 = src1;
    const uint8_t *s2 = src2;
    uint8_t result = 0;
    for (size_t i = 0; i < length; i++) {
        result |= s1[i] ^ s2[i];
    }
    return result;
}

/* cx_hmac_sha256 stub - used in policy.c for HMAC verification */
typedef uint32_t cx_err_t;
cx_err_t cx_hmac_sha256(const uint8_t *key,
                        size_t key_len,
                        const uint8_t *data,
                        size_t data_len,
                        uint8_t *mac,
                        size_t mac_len) {
    (void) key;
    (void) key_len;
    (void) data;
    (void) data_len;
    memset(mac, 0, mac_len);
    return 0;
}
