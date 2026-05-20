/**
 * Unit tests for the functions defined in src/crypto.c.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "speculos_bridge.h"
#include "crypto.h"
#include "xpub.h"

/* Helper: decode an xpub string, abort the test on any decoding error. */
static serialized_extended_pubkey_t decode_xpub(const char *str) {
    serialized_extended_pubkey_t out;
    assert_true(xpub_from_base58(str, &out));
    return out;
}

/* ---------------------------------------------------------------- */
/* bip32_CKDpub                                                     */
/*                                                                  */
/* Test vectors come from BIP32 Test Vector 2 (m and m/0).          */
/*   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki */
/* ---------------------------------------------------------------- */

// clang-format off
static const char tv2_m_xpub[] = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";

static const char tv2_m_0_xpub[] = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
// clang-format on

static void test_bip32_CKDpub_tv2_m_to_m0(void **state) {
    (void) state;

    serialized_extended_pubkey_t parent = decode_xpub(tv2_m_xpub);
    serialized_extended_pubkey_t expected = decode_xpub(tv2_m_0_xpub);

    serialized_extended_pubkey_t child = {0};
    uint8_t tweak[32];

    int ret = bip32_CKDpub(&parent, 0, &child, tweak);
    assert_int_equal(ret, 0);
    assert_memory_equal(&child, &expected, sizeof(child));
}

static void test_bip32_CKDpub_in_place(void **state) {
    (void) state;

    /* child == parent must be allowed per the docstring. */
    serialized_extended_pubkey_t buf = decode_xpub(tv2_m_xpub);
    serialized_extended_pubkey_t expected = decode_xpub(tv2_m_0_xpub);

    int ret = bip32_CKDpub(&buf, 0, &buf, NULL);
    assert_int_equal(ret, 0);
    assert_memory_equal(&buf, &expected, sizeof(buf));
}

static void test_bip32_CKDpub_rejects_hardened(void **state) {
    (void) state;

    serialized_extended_pubkey_t parent = decode_xpub(tv2_m_xpub);
    serialized_extended_pubkey_t child = {0};
    /* 0x80000000 is the first hardened index. */
    int ret = bip32_CKDpub(&parent, 0x80000000u, &child, NULL);
    assert_int_equal(ret, -1);
}

static void test_bip32_CKDpub_rejects_max_depth(void **state) {
    (void) state;

    serialized_extended_pubkey_t parent = decode_xpub(tv2_m_xpub);
    parent.depth = 255;
    serialized_extended_pubkey_t child = {0};

    int ret = bip32_CKDpub(&parent, 0, &child, NULL);
    assert_int_equal(ret, -1);
}

/* ---------------------------------------------------------------- */
/* crypto_ripemd160                                                 */
/* ---------------------------------------------------------------- */

static void test_crypto_ripemd160_empty(void **state) {
    (void) state;
    /* Standard RIPEMD-160 test vector for the empty input. */
    static const uint8_t expected[20] = {
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
    };
    uint8_t out[20];
    crypto_ripemd160((const uint8_t *) "", 0, out);
    assert_memory_equal(out, expected, 20);
}

static void test_crypto_ripemd160_abc(void **state) {
    (void) state;
    /* RIPEMD-160 of "abc". */
    static const uint8_t expected[20] = {
        0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
        0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
    };
    uint8_t out[20];
    crypto_ripemd160((const uint8_t *) "abc", 3, out);
    assert_memory_equal(out, expected, 20);
}

static void test_crypto_ripemd160_1000_a(void **state) {
    (void) state;
    /* RIPEMD-160 of 1000 repetitions of 'a' — exercises multi-block input. */
    static const uint8_t expected[20] = {
        0xaa, 0x69, 0xde, 0xee, 0x9a, 0x89, 0x22, 0xe9, 0x2f, 0x81,
        0x05, 0xe0, 0x07, 0xf7, 0x61, 0x10, 0xf3, 0x81, 0xe9, 0xcf,
    };
    uint8_t input[1000];
    memset(input, 'a', sizeof(input));
    uint8_t out[20];
    crypto_ripemd160(input, sizeof(input), out);
    assert_memory_equal(out, expected, 20);
}

/* ---------------------------------------------------------------- */
/* crypto_hash160                                                   */
/* ---------------------------------------------------------------- */

static void test_crypto_hash160_empty(void **state) {
    (void) state;
    /* RIPEMD160(SHA256("")) */
    static const uint8_t expected[20] = {
        0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
        0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb,
    };
    uint8_t out[20];
    crypto_hash160((const uint8_t *) "", 0, out);
    assert_memory_equal(out, expected, 20);
}

static void test_crypto_hash160_abc(void **state) {
    (void) state;
    /* RIPEMD160(SHA256("abc")) */
    static const uint8_t expected[20] = {
        0xbb, 0x1b, 0xe9, 0x8c, 0x14, 0x24, 0x44, 0xd7, 0xa5, 0x6a,
        0xa3, 0x98, 0x1c, 0x39, 0x42, 0xa9, 0x78, 0xe4, 0xdc, 0x33,
    };
    uint8_t out[20];
    crypto_hash160((const uint8_t *) "abc", 3, out);
    assert_memory_equal(out, expected, 20);
}

static void test_crypto_hash160_secp256k1_generator(void **state) {
    (void) state;
    /* HASH160 of the uncompressed secp256k1 generator point (04 || Gx || Gy).
     * Sanity check that bitcoin-style HASH160 of a pubkey works as expected. */
    static const uint8_t G_uncompressed[65] = {
        0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
        0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59,
        0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3,
        0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4,
        0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
    };
    static const uint8_t expected[20] = {
        0x91, 0xb2, 0x4b, 0xf9, 0xf5, 0x28, 0x85, 0x32, 0x96, 0x0a,
        0xc6, 0x87, 0xab, 0xb0, 0x35, 0x12, 0x7b, 0x1d, 0x28, 0xa5,
    };
    uint8_t out[20];
    crypto_hash160(G_uncompressed, sizeof(G_uncompressed), out);
    assert_memory_equal(out, expected, 20);
}

/* ---------------------------------------------------------------- */
/* crypto_get_compressed_pubkey                                     */
/* ---------------------------------------------------------------- */

// clang-format off
static const uint8_t uncompressed_key_02[] = {
    0x04,
    0xee,0x86,0x08,0x20,0x7e,0x21,0x02,0x84,0x26,0xf6,0x9e,0x76,0x44,0x7d,0x7e,0x3d,
    0x5e,0x07,0x70,0x49,0xf5,0xe6,0x83,0xc3,0x13,0x6c,0x23,0x14,0x76,0x2a,0x47,0x18,
    0xb4,0x5f,0x52,0x24,0xb0,0x5e,0xbb,0xad,0x09,0xf4,0x35,0x94,0xb7,0xbd,0x8d,0xc0,
    0xef,0xf4,0x51,0x9a,0x07,0xcb,0xab,0x37,0xec,0xc6,0x6e,0x00,0x01,0xab,0x95,0x9a  // even
};
static const uint8_t compressed_key_02[] = {
    0x02,
    0xee,0x86,0x08,0x20,0x7e,0x21,0x02,0x84,0x26,0xf6,0x9e,0x76,0x44,0x7d,0x7e,0x3d,
    0x5e,0x07,0x70,0x49,0xf5,0xe6,0x83,0xc3,0x13,0x6c,0x23,0x14,0x76,0x2a,0x47,0x18
};

static const uint8_t uncompressed_key_03[] = {
    0x04,
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13,
    0x1d,0x5e,0x56,0x4f,0xc5,0x1b,0x4f,0xb9,0x1a,0x83,0x67,0x73,0x3b,0x97,0xc7,0x6a,
    0x5c,0x99,0x70,0x5d,0x7e,0x99,0x12,0x59,0xb7,0x9d,0x8c,0xa3,0x65,0x35,0x09,0xcb // odd
};
static const uint8_t compressed_key_03[] = {
    0x03,
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13
};

static const uint8_t uncompressed_key_invalid[] = {
    0x05, // does not start with 0x04; invalid
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13,
    0x1d,0x5e,0x56,0x4f,0xc5,0x1b,0x4f,0xb9,0x1a,0x83,0x67,0x73,0x3b,0x97,0xc7,0x6a,
    0x5c,0x99,0x70,0x5d,0x7e,0x99,0x12,0x59,0xb7,0x9d,0x8c,0xa3,0x65,0x35,0x09,0xcb // odd
};
// clang-format on

static void test_crypto_get_compressed_pubkey_02(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_02, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_out, compressed_key_02, 33);
    assert_memory_equal(key_in, uncompressed_key_02, 65);
}

static void test_crypto_get_compressed_pubkey_03(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_03, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_out, compressed_key_03, 33);
    assert_memory_equal(key_in, uncompressed_key_03, 65);
}

// Test that it also works if key_out == key_in
static void test_crypto_get_compressed_pubkey_in_place(void **state) {
    (void) state;

    uint8_t key_in_out[65];
    memcpy(key_in_out, uncompressed_key_02, 65);
    int ret = crypto_get_compressed_pubkey(key_in_out, key_in_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_in_out, compressed_key_02, 33);
}

static void test_crypto_get_compressed_pubkey_invalid(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_invalid, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, -1);
}

/* ---------------------------------------------------------------- */
/* crypto_get_checksum                                              */
/* ---------------------------------------------------------------- */

static void test_crypto_get_checksum_empty(void **state) {
    (void) state;
    /* First 4 bytes of SHA256(SHA256("")). */
    static const uint8_t expected[4] = {0x5d, 0xf6, 0xe0, 0xe2};
    uint8_t out[4];
    crypto_get_checksum((const uint8_t *) "", 0, out);
    assert_memory_equal(out, expected, 4);
}

static void test_crypto_get_checksum_hello(void **state) {
    (void) state;
    /* First 4 bytes of SHA256(SHA256("hello")). */
    static const uint8_t expected[4] = {0x95, 0x95, 0xc9, 0xdf};
    uint8_t out[4];
    crypto_get_checksum((const uint8_t *) "hello", 5, out);
    assert_memory_equal(out, expected, 4);
}

/* ---------------------------------------------------------------- */
/* crypto_get_compressed_pubkey_at_path                             */
/*                                                                  */
/* Expected xpubs are precomputed from the BIP32 master seed used   */
/* by speculos when no SPECULOS_SEED override is set (the speculos  */
/* default test seed, mirrored in libs/speculos_bridge.c).          */
/* ---------------------------------------------------------------- */

#define BIP32_HARDENED 0x80000000u

/* Decode the expected xpub and assert that the speculos-backed
 * derivation produces the same compressed pubkey and chain code. */
static void check_pubkey_at_path(const uint32_t *path,
                                 size_t path_len,
                                 const char *expected_xpub,
                                 bool with_chain_code) {
    serialized_extended_pubkey_t expected = decode_xpub(expected_xpub);

    uint8_t pubkey[33];
    uint8_t chain[32];
    cx_err_t err = crypto_get_compressed_pubkey_at_path(path,
                                                        path_len,
                                                        pubkey,
                                                        with_chain_code ? chain : NULL);

    assert_int_equal(err, CX_OK);
    assert_memory_equal(pubkey, expected.compressed_pubkey, 33);
    if (with_chain_code) {
        assert_memory_equal(chain, expected.chain_code, 32);
    }
}

static void test_crypto_get_compressed_pubkey_at_path_master(void **state) {
    (void) state;
    /* m — passes a non-NULL but empty path. speculos rejects NULL path
     * with an exception regardless of length; this matches what real
     * app callers do. */
    static const uint32_t path[1] = {0};
    // clang-format off
    static const char xpub[] = "xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12";
    // clang-format on
    check_pubkey_at_path(path, 0, xpub, true);
}

static void test_crypto_get_compressed_pubkey_at_path_unhardened(void **state) {
    (void) state;
    /* m/0 */
    static const uint32_t path[] = {0};
    // clang-format off
    static const char xpub[] = "xpub69hEPYcyraCnMhNKGGNy4tgCorxg8HhVkCfMHjf7N769AzVqu94hakMtZGuNANFda6qLfHNZ9mLQewRg9zbp2S9QRyyPkHSht1Ua8dKZzJQ";
    // clang-format on
    check_pubkey_at_path(path, 1, xpub, true);
}

static void test_crypto_get_compressed_pubkey_at_path_bip44_account(void **state) {
    (void) state;
    /* m/44'/0'/0' — BIP44 Bitcoin mainnet account 0 */
    static const uint32_t path[] = {BIP32_HARDENED | 44, BIP32_HARDENED | 0, BIP32_HARDENED | 0};
    // clang-format off
    static const char xpub[] = "xpub6Cak8u8nU1evR4eMoz5UX12bU9Ws5RjEgq2Kq1RKZrsEQF6Cvecoyr19ZYRikWoJo16SXeft5fhkzbXcmuPfCzQKKB9RDPWT8XnUM62ieB9";
    // clang-format on
    check_pubkey_at_path(path, 3, xpub, false);
}

static void test_crypto_get_compressed_pubkey_at_path_bip44_first_address(void **state) {
    (void) state;
    /* m/44'/0'/0'/0/0 — first receive address of the first BIP44 account.
     * Also exercises chain_code == NULL. */
    static const uint32_t path[] = {BIP32_HARDENED | 44,
                                    BIP32_HARDENED | 0,
                                    BIP32_HARDENED | 0,
                                    0,
                                    0};
    // clang-format off
    static const char xpub[] = "xpub6GnNWkuKTn5pBczcx8fvSS37i42kfZkoTZo9y7gZeEmv1JZYH1DLmmYL36oJDSnJwcPaGX1Y7ZW2gtR1VPkLG6ce6XizxeSq3iV6vyw6p7X";
    // clang-format on
    check_pubkey_at_path(path, 5, xpub, false);
}

int main(void) {
    speculos_bridge_init();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bip32_CKDpub_tv2_m_to_m0),
        cmocka_unit_test(test_bip32_CKDpub_in_place),
        cmocka_unit_test(test_bip32_CKDpub_rejects_hardened),
        cmocka_unit_test(test_bip32_CKDpub_rejects_max_depth),
        cmocka_unit_test(test_crypto_ripemd160_empty),
        cmocka_unit_test(test_crypto_ripemd160_abc),
        cmocka_unit_test(test_crypto_ripemd160_1000_a),
        cmocka_unit_test(test_crypto_hash160_empty),
        cmocka_unit_test(test_crypto_hash160_abc),
        cmocka_unit_test(test_crypto_hash160_secp256k1_generator),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_02),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_03),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_in_place),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_invalid),
        cmocka_unit_test(test_crypto_get_checksum_empty),
        cmocka_unit_test(test_crypto_get_checksum_hello),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_at_path_master),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_at_path_unhardened),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_at_path_bip44_account),
        cmocka_unit_test(test_crypto_get_compressed_pubkey_at_path_bip44_first_address),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
