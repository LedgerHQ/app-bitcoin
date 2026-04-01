/**
 * Unit tests for call_get_preimage using the mock dispatcher.
 *
 * Tests verify that the C implementation of call_get_preimage correctly
 * handles the client command protocol (GET_PREIMAGE / GET_MORE_ELEMENTS)
 * and validates the SHA-256 hash of the received data.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

/* SDK mock stubs */
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}
#undef PIC
#define PIC(x) (x)

#include "mock_dispatcher.h"
#include "cx_hash_mock.h"
#include "sha-256.h"

#include "handler/lib/get_preimage.h"

/* ---------- Helpers ---------- */

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    calc_sha_256(out, data, len);
}

/* ---------- Test cases ---------- */

/**
 * Happy path: small preimage (fits entirely in the first response, no
 * GET_MORE_ELEMENTS needed).
 */
static void test_get_preimage_small(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* A small preimage: 50 bytes */
    uint8_t preimage[50];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(&mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[256];
    memset(out, 0xAA, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Happy path: large preimage that requires GET_MORE_ELEMENTS to transfer
 * all the bytes.
 */
static void test_get_preimage_large(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* A larger preimage: 300 bytes */
    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    mock_dispatcher_add_preimage(&mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Error: requesting preimage of an unknown hash should return a negative value.
 */
static void test_get_preimage_unknown_hash(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Don't register any preimage; just call with a random hash */
    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t out[256];

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* process_interruption returns -1 → call_get_preimage returns -1 */
    assert_true(result < 0);
}

/**
 * Error: output buffer too small for the preimage.
 * call_get_preimage should return -10.
 */
static void test_get_preimage_buffer_too_small(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t preimage[100];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) i;
    }

    mock_dispatcher_add_preimage(&mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[50]; /* Too small! */

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -10);
}

/**
 * Edge case: minimal preimage of exactly 1 byte.
 */
static void test_get_preimage_one_byte(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t preimage[1] = {0x42};
    mock_dispatcher_add_preimage(&mock, preimage, 1);

    uint8_t hash[32];
    compute_sha256(preimage, 1, hash);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, 1);
    assert_int_equal(out[0], 0x42);
}

/**
 * Edge case: preimage that exactly fills the max first-response payload.
 *
 * For a preimage of length L, the varint encoding takes:
 *   1 byte if L < 253, 3 bytes if L < 65536, etc.
 * Max payload = 255 - varint_len - 1.
 * For varint_len=1: max_payload = 253.
 * So a 253-byte preimage should fit exactly with no GET_MORE_ELEMENTS.
 */
static void test_get_preimage_exact_fit(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t preimage[253];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i ^ 0xA5);
    }

    mock_dispatcher_add_preimage(&mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Edge case: preimage of length 254 (one byte over the exact-fit boundary,
 * so a few bytes go through GET_MORE_ELEMENTS).
 */
static void test_get_preimage_one_byte_overflow(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Varint encodings above 253 bytes (and less than 65536) take 3 bytes,
     * therefore max_payload = 255 - 3 - 1 = 251.
     * Hence, for length 254, 3 bytes go through GET_MORE_ELEMENTS.
     */
    uint8_t preimage[254];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i * 3);
    }

    mock_dispatcher_add_preimage(&mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_preimage_small),
        cmocka_unit_test(test_get_preimage_large),
        cmocka_unit_test(test_get_preimage_unknown_hash),
        cmocka_unit_test(test_get_preimage_buffer_too_small),
        cmocka_unit_test(test_get_preimage_one_byte),
        cmocka_unit_test(test_get_preimage_exact_fit),
        cmocka_unit_test(test_get_preimage_one_byte_overflow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
