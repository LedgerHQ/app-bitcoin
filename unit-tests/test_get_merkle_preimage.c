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
    mock_dispatcher_t *mock = *state;

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[256];
    memset(out, 0xAA, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    /* Element of 250 bytes; with the 0x00 prefix the preimage is 251 bytes,
     * which might not fully fit in the first response chunk. */
    uint8_t element[250];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Error: requesting preimage of an unknown hash should return a negative value.
 */
static void test_get_merkle_preimage_unknown_hash(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Don't register any preimage; just call with a random hash */
    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t out[256];

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* process_interruption returns -1 → call_get_merkle_preimage returns -1 */
    assert_true(result < 0);
}

/**
 * Error: output buffer too small for the element (preimage_len - 1 > out_ptr_len).
 * call_get_merkle_preimage should return -4.
 */
static void test_get_merkle_preimage_buffer_too_small(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[100];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[50]; /* Too small for 100-byte element */

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -4);
}

/**
 * Edge case: minimal element of exactly 1 byte.
 * Preimage is (0x00 || 0x42) = 2 bytes, output should be just 0x42.
 */
static void test_get_merkle_preimage_one_byte(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[1] = {0x42};

    uint8_t hash[32];
    add_merkle_preimage(mock, element, 1, hash);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[252];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i ^ 0xA5);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[253];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(element));
    assert_memory_equal(out, element, sizeof(element));
}

/**
 * Edge case: output buffer exactly matches element length (no spare room).
 */
static void test_get_merkle_preimage_exact_buffer(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[64];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i + 0x10);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    uint8_t out[64]; /* Exactly the element size */
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_data, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    /* Element large enough to require continuation (preimage = 0x00 || element) */
    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 7);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_continuation, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    /* Must detect the corruption (hash mismatch or protocol error) */
    assert_true(result < 0);
}

/**
 * Adversarial: truncated response — buffer reads fail. Must return -2.
 */
static int tamper_truncate(uint8_t *response_buf,
                           size_t *response_len,
                           uint8_t cmd,
                           int call_count,
                           void *user_data) {
    (void) response_buf;
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        *response_len = 0;
    }
    return 0;
}

static void test_get_merkle_preimage_truncated(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[10];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_truncate, NULL);

    uint8_t out[64];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -2);
}

/**
 * Adversarial: preimage_len = 0 or partial_data_len = 0 — must return -3.
 */
static int tamper_zero_len(uint8_t *response_buf,
                           size_t *response_len,
                           uint8_t cmd,
                           int call_count,
                           void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        response_buf[0] = 0x00;
        response_buf[1] = 0x00;
        *response_len = 2;
    }
    return 0;
}

static void test_get_merkle_preimage_zero_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[5] = {1, 2, 3, 4, 5};
    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_zero_len, NULL);

    uint8_t out[64];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -3);
}

/**
 * Adversarial: partial_data_len > preimage_len with padded buffer.
 * Must return -5.
 */
static int tamper_partial_len_over(uint8_t *response_buf,
                                   size_t *response_len,
                                   uint8_t cmd,
                                   int call_count,
                                   void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len >= 2) {
        uint8_t preimage_len = response_buf[0];
        response_buf[1] = preimage_len + 1;
        response_buf[*response_len] = 0xCC;
        (*response_len)++;
    }
    return 0;
}

static void test_get_merkle_preimage_partial_len_over(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[5] = {1, 2, 3, 4, 5};
    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_partial_len_over, NULL);

    uint8_t out[64];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -5);
}

/**
 * Adversarial: second-call communication failure during GET_MORE_ELEMENTS.
 * Must return -6.
 */
static int tamper_fail_second(uint8_t *response_buf,
                              size_t *response_len,
                              uint8_t cmd,
                              int call_count,
                              void *user_data) {
    (void) response_buf;
    (void) response_len;
    (void) cmd;
    (void) user_data;

    if (call_count >= 1) {
        return -1;
    }
    return 0;
}

static void test_get_merkle_preimage_comm_failure(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_fail_second, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -6);
}

/**
 * Adversarial: truncated GET_MORE_ELEMENTS response — must return -7.
 */
static int tamper_truncate_more(uint8_t *response_buf,
                                size_t *response_len,
                                uint8_t cmd,
                                int call_count,
                                void *user_data) {
    (void) response_buf;
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS) {
        *response_len = 0;
    }
    return 0;
}

static void test_get_merkle_preimage_truncated_more(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_truncate_more, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -7);
}

/**
 * Adversarial: GET_MORE_ELEMENTS with elements_len != 1 — must return -8.
 */
static int tamper_more_bad_size(uint8_t *response_buf,
                                size_t *response_len,
                                uint8_t cmd,
                                int call_count,
                                void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[0] = 0;
        response_buf[1] = 4;
    }
    return 0;
}

static void test_get_merkle_preimage_bad_element_size(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_bad_size, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -8);
}

/**
 * Adversarial: GET_MORE_ELEMENTS with n_bytes > bytes_remaining (padded buffer).
 * Must return -9.
 */
static int tamper_more_bytes(uint8_t *response_buf,
                             size_t *response_len,
                             uint8_t cmd,
                             int call_count,
                             void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        uint8_t orig_n = response_buf[0];
        response_buf[0] = orig_n + 1;
        response_buf[*response_len] = 0xAB;
        (*response_len)++;
    }
    return 0;
}

static void test_get_merkle_preimage_more_bytes(void **state) {
    mock_dispatcher_t *mock = *state;

    /* element 253 → preimage 254 → spill 3 bytes */
    uint8_t element[253];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 7);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_bytes, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -9);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_get_merkle_preimage_small),
        T(test_get_merkle_preimage_large),
        T(test_get_merkle_preimage_unknown_hash),
        T(test_get_merkle_preimage_buffer_too_small),
        T(test_get_merkle_preimage_one_byte),
        T(test_get_merkle_preimage_exact_fit),
        T(test_get_merkle_preimage_one_byte_overflow),
        T(test_get_merkle_preimage_exact_buffer),
        T(test_get_merkle_preimage_corrupted_data),
        T(test_get_merkle_preimage_corrupted_continuation),
        T(test_get_merkle_preimage_truncated),
        T(test_get_merkle_preimage_zero_len),
        T(test_get_merkle_preimage_partial_len_over),
        T(test_get_merkle_preimage_comm_failure),
        T(test_get_merkle_preimage_truncated_more),
        T(test_get_merkle_preimage_bad_element_size),
        T(test_get_merkle_preimage_more_bytes),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
