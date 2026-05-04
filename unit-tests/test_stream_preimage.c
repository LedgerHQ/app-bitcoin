/**
 * Unit tests for call_stream_preimage using the mock dispatcher.
 *
 * call_stream_preimage behaves like call_get_merkle_preimage, but instead of
 * writing to an output buffer it streams data via callbacks.  The len_callback
 * is invoked once with the total element length (excluding the 0x00 prefix),
 * then the data callback is invoked one or more times with buffer_t chunks.
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

#include "handler/lib/stream_preimage.h"

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
    uint8_t prefixed[512];
    prefixed[0] = 0x00;
    memcpy(prefixed + 1, element, element_len);

    mock_dispatcher_add_preimage(mock, prefixed, 1 + element_len);

    if (hash_out) {
        compute_sha256(prefixed, 1 + element_len, hash_out);
    }
}

/* Accumulator for streaming callbacks */
typedef struct {
    uint8_t buf[1024];
    size_t offset;
    size_t total_len; /* set by len_callback */
    bool len_called;
} stream_accumulator_t;

static void acc_len_callback(size_t len, void *state) {
    stream_accumulator_t *acc = (stream_accumulator_t *) state;
    acc->total_len = len;
    acc->len_called = true;
}

static void acc_data_callback(buffer_t *data, void *state) {
    stream_accumulator_t *acc = (stream_accumulator_t *) state;
    size_t n = data->size - data->offset;
    memcpy(acc->buf + acc->offset, data->ptr + data->offset, n);
    acc->offset += n;
}

/* ---------- Test cases ---------- */

/**
 * Happy path: small element (fits entirely in the first response, no
 * GET_MORE_ELEMENTS needed).
 */
static void test_stream_preimage_small(void **state) {
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

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(element));
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/**
 * Happy path: large element that requires GET_MORE_ELEMENTS to transfer
 * all the bytes.
 */
static void test_stream_preimage_large(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(element));
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/**
 * Error: requesting preimage of an unknown hash should return a negative value.
 */
static void test_stream_preimage_unknown_hash(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_true(result < 0);
}

/**
 * Edge case: minimal element of exactly 1 byte.
 * Preimage is (0x00 || 0x42) = 2 bytes, streamed output should be just 0x42.
 */
static void test_stream_preimage_one_byte(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[1] = {0x42};

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, 1, hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, 1);
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, 1);
    assert_int_equal(acc.offset, 1);
    assert_int_equal(acc.buf[0], 0x42);
}

/**
 * Happy path: NULL len_callback should work (len_callback is optional).
 */
static void test_stream_preimage_null_len_callback(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t element[30];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, NULL, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_false(acc.len_called);
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/**
 * Edge case: element that, with the 0x00 prefix, exactly fills the max
 * first-response payload (no GET_MORE_ELEMENTS needed).
 *
 * For a preimage of length L, the varint encoding takes 1 byte if L < 253.
 * Max payload = 255 - varint_len(1) - partial_data_len_byte(1) = 253.
 * A preimage of 253 bytes means element of 252 bytes (253 - 1 for 0x00 prefix).
 */
static void test_stream_preimage_exact_fit(void **state) {
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

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(element));
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/**
 * Edge case: element one byte over the exact-fit boundary, so a few bytes
 * go through GET_MORE_ELEMENTS.
 */
static void test_stream_preimage_one_byte_overflow(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Preimage length = 254 (element 253 + prefix 1).
     * Varint for 254 takes 3 bytes, so max_payload = 255 - 3 - 1 = 251.
     * 254 - 251 = 3 bytes via GET_MORE_ELEMENTS.
     */
    uint8_t element[253];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(&mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(element));
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_stream_preimage_small),
        cmocka_unit_test(test_stream_preimage_large),
        cmocka_unit_test(test_stream_preimage_unknown_hash),
        cmocka_unit_test(test_stream_preimage_one_byte),
        cmocka_unit_test(test_stream_preimage_null_len_callback),
        cmocka_unit_test(test_stream_preimage_exact_fit),
        cmocka_unit_test(test_stream_preimage_one_byte_overflow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
