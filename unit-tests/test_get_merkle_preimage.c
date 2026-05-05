/**
 * Unit tests for call_get_merkle_preimage using the mock dispatcher.
 *
 * call_get_merkle_preimage behaves like call_get_preimage, but strips the
 * leading 0x00 Merkle leaf prefix byte from the output.  The hash is
 * verified over the full preimage (including the prefix).
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

#include "client_commands.h"
#include "handler/lib/get_merkle_preimage.h"

/* ---------- Helpers ---------- */

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    calc_sha_256(out, data, len);
}

/**
 * Register a Merkle leaf preimage: the stored preimage is (0x00 || element),
 * and the hash is SHA256(0x00 || element).
 * Fills `hash_out` with the hash if non-NULL.
 */
static void add_merkle_preimage(mock_dispatcher_t *mock,
                                const uint8_t *element,
                                size_t element_len,
                                uint8_t hash_out[32]) {
    uint8_t prefixed[513];
    prefixed[0] = 0x00;
    memcpy(prefixed + 1, element, element_len);

    mock_dispatcher_add_preimage(mock, prefixed, 1 + element_len);

    if (hash_out) {
        compute_sha256(prefixed, 1 + element_len, hash_out);
    }
}

/* ---------- Test cases ---------- */

/**
 * Happy path: small element (fits entirely in the first response, no
 * GET_MORE_ELEMENTS needed).
 */
static void test_get_merkle_preimage_small(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[256];
    memset(out, 0xAA, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* Returns element length (preimage_len - 1, stripping 0x00 prefix) */
    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Happy path: large element that requires GET_MORE_ELEMENTS to transfer
 * all the bytes.
 */
static void test_get_merkle_preimage_large(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Element of 250 bytes; with the 0x00 prefix the preimage is 251 bytes,
     * which might not fully fit in the first response chunk. */
    uint8_t element[250];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Error: requesting preimage of an unknown hash should return a negative value.
 */
static void test_get_merkle_preimage_unknown_hash(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Don't register any preimage; just call with a random hash */
    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t out[256];

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* process_interruption returns -1 → call_get_merkle_preimage returns -1 */
    assert_true(result < 0);
}

/**
 * Error: output buffer too small for the element (preimage_len - 1 > out_ptr_len).
 * call_get_merkle_preimage should return -4.
 */
static void test_get_merkle_preimage_buffer_too_small(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[100];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[50]; /* Too small for 100-byte element */

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -4);
}

/**
 * Edge case: minimal element of exactly 1 byte.
 * Preimage is (0x00 || 0x42) = 2 bytes, output should be just 0x42.
 */
static void test_get_merkle_preimage_one_byte(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[1] = {0x42};

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, 1, hash);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, 1);
    assert_int_equal(out[0], 0x42);
}

/**
 * Edge case: element that, with the 0x00 prefix, exactly fills the max
 * first-response payload (no GET_MORE_ELEMENTS needed).
 *
 * For a preimage of length L, the varint encoding takes 1 byte if L < 253.
 * Max payload = 255 - varint_len(1) - partial_data_len_byte(1) = 253.
 * So a preimage of 253 bytes fits in one chunk → element of 252 bytes.
 */
static void test_get_merkle_preimage_exact_fit(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[252];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i ^ 0xA5);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Edge case: element whose preimage (0x00 || element) is one byte over the
 * exact-fit boundary, so a few bytes go through GET_MORE_ELEMENTS.
 *
 * For preimage length 254: varint takes 3 bytes (>= 253),
 * max_payload = 255 - 3 - 1 = 251.  So 3 bytes spill to GET_MORE_ELEMENTS.
 * Element length = 253.
 */
static void test_get_merkle_preimage_one_byte_overflow(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[253];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Edge case: output buffer exactly matches element length (no spare room).
 */
static void test_get_merkle_preimage_exact_buffer(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[64];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i + 0x10);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    uint8_t out[64]; /* Exactly the element size */
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client returns valid structure but corrupted data bytes,
 * causing a SHA-256 hash mismatch on the leaf preimage.
 */
static int tamper_corrupt_data(uint8_t *response_buf,
                               size_t *response_len,
                               uint8_t cmd,
                               int call_count,
                               void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len > 3) {
        response_buf[3] ^= 0xFF;
    }
    return 0;
}

static void test_get_merkle_preimage_corrupted_data(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_corrupt_data, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* Must detect hash mismatch */
    assert_true(result < 0);
}

/**
 * Adversarial: client corrupts the continuation data for a large preimage.
 */
static int tamper_corrupt_continuation(uint8_t *response_buf,
                                       size_t *response_len,
                                       uint8_t cmd,
                                       int call_count,
                                       void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len > 2) {
        response_buf[2] ^= 0xFF;
    }
    return 0;
}

static void test_get_merkle_preimage_corrupted_continuation(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Element large enough to require continuation (preimage = 0x00 || element) */
    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 7);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_corrupt_continuation, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* Must detect the corruption (hash mismatch or protocol error) */
    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_merkle_preimage_small),
        cmocka_unit_test(test_get_merkle_preimage_large),
        cmocka_unit_test(test_get_merkle_preimage_unknown_hash),
        cmocka_unit_test(test_get_merkle_preimage_buffer_too_small),
        cmocka_unit_test(test_get_merkle_preimage_one_byte),
        cmocka_unit_test(test_get_merkle_preimage_exact_fit),
        cmocka_unit_test(test_get_merkle_preimage_one_byte_overflow),
        cmocka_unit_test(test_get_merkle_preimage_exact_buffer),
        cmocka_unit_test(test_get_merkle_preimage_corrupted_data),
        cmocka_unit_test(test_get_merkle_preimage_corrupted_continuation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
