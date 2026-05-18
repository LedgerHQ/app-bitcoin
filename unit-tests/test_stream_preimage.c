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

#include "client_commands.h"
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_true(result < 0);
}

/**
 * Edge case: minimal element of exactly 1 byte.
 * Preimage is (0x00 || 0x42) = 2 bytes, streamed output should be just 0x42.
 */
static void test_stream_preimage_one_byte(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[1] = {0x42};

    uint8_t hash[32];
    add_merkle_preimage(mock, element, 1, hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[30];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    uint8_t element[252];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i ^ 0xA5);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
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
    mock_dispatcher_t *mock = *state;

    /* Preimage length = 254 (element 253 + prefix 1).
     * Varint for 254 takes 3 bytes, so max_payload = 255 - 3 - 1 = 251.
     * 254 - 251 = 3 bytes via GET_MORE_ELEMENTS.
     */
    uint8_t element[253];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(element));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(element));
    assert_int_equal(acc.offset, sizeof(element));
    assert_memory_equal(acc.buf, element, sizeof(element));
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client returns corrupted data in the initial chunk.
 * Hash verification must detect the mismatch.
 */
static int tamper_corrupt_stream_data(uint8_t *response_buf,
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

static void test_stream_preimage_corrupted_data(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[50];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i & 0xFF);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_stream_data, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_true(result < 0);
}

/**
 * Adversarial: client corrupts continuation data during streaming.
 */
static int tamper_corrupt_stream_continuation(uint8_t *response_buf,
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

static void test_stream_preimage_corrupted_continuation(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 7);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_stream_continuation, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_true(result < 0);
}

/**
 * Adversarial: response is truncated so buffer_read_varint already fails — must
 * return -2.
 */
static int tamper_truncate_response(uint8_t *response_buf,
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

static void test_stream_preimage_truncated_response(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[20];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_truncate_response, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -2);
}

/**
 * Adversarial: client returns preimage_len > UINT32_MAX (9-byte varint).
 * call_stream_preimage must reject with -10.
 */
static int tamper_overflow_len(uint8_t *response_buf,
                               size_t *response_len,
                               uint8_t cmd,
                               int call_count,
                               void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        response_buf[0] = 0xFF; /* 9-byte varint */
        response_buf[1] = 0x00;
        response_buf[2] = 0x00;
        response_buf[3] = 0x00;
        response_buf[4] = 0x00;
        response_buf[5] = 0x01; /* 2^32 */
        response_buf[6] = 0x00;
        response_buf[7] = 0x00;
        response_buf[8] = 0x00;
        response_buf[9] = 0x00; /* partial_data_len */
        *response_len = 10;
    }
    return 0;
}

static void test_stream_preimage_overflow_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[5] = {1, 2, 3, 4, 5};
    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_overflow_len, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -10);
}

/**
 * Adversarial: client returns preimage_len = 0 — must return -3.
 */
static int tamper_zero_preimage_len(uint8_t *response_buf,
                                    size_t *response_len,
                                    uint8_t cmd,
                                    int call_count,
                                    void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        response_buf[0] = 0x00; /* preimage_len = 0 */
        response_buf[1] = 0x00; /* partial_data_len = 0 */
        *response_len = 2;
    }
    return 0;
}

static void test_stream_preimage_zero_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[5] = {1, 2, 3, 4, 5};
    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_zero_preimage_len, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -3);
}

/**
 * Adversarial: client claims partial_data_len > preimage_len while padding the
 * buffer so buffer_can_read(partial_data_len) passes — must return -4.
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

static void test_stream_preimage_partial_len_over(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[5] = {1, 2, 3, 4, 5};
    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_partial_len_over, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -4);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, response is truncated so buffer_read_u8
 * fails on n_bytes — must return -6.
 */
static int tamper_truncate_more_elements(uint8_t *response_buf,
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

static void test_stream_preimage_truncated_more_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_truncate_more_elements, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -6);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, set n_bytes=0 (so buffer_can_read(0)
 * trivially passes) and elements_len != 1 — must return -7.
 */
static int tamper_more_elements_bad_size(uint8_t *response_buf,
                                         size_t *response_len,
                                         uint8_t cmd,
                                         int call_count,
                                         void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[0] = 0;
        response_buf[1] = 4; /* elements_len != 1 */
    }
    return 0;
}

static void test_stream_preimage_bad_element_size(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) i;
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_elements_bad_size, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -7);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, claim n_bytes > bytes_remaining with
 * the buffer extended so buffer_can_read still passes — must return -8.
 */
static int tamper_more_bytes_with_padding(uint8_t *response_buf,
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

static void test_stream_preimage_more_bytes_than_remaining(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[253]; /* spill = 3 bytes */
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 7);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_bytes_with_padding, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, -8);
}

/**
 * Adversarial: communication failure mid-stream (second interruption fails).
 */
static int tamper_fail_on_second(uint8_t *response_buf,
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

static void test_stream_preimage_communication_failure(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t element[300];
    for (size_t i = 0; i < sizeof(element); i++) {
        element[i] = (uint8_t) (i * 3);
    }

    uint8_t hash[32];
    add_merkle_preimage(mock, element, sizeof(element), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_fail_on_second, NULL);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_preimage(dc, hash, acc_len_callback, acc_data_callback, &acc);

    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_stream_preimage_small),
        T(test_stream_preimage_large),
        T(test_stream_preimage_unknown_hash),
        T(test_stream_preimage_one_byte),
        T(test_stream_preimage_null_len_callback),
        T(test_stream_preimage_exact_fit),
        T(test_stream_preimage_one_byte_overflow),
        T(test_stream_preimage_corrupted_data),
        T(test_stream_preimage_corrupted_continuation),
        T(test_stream_preimage_truncated_response),
        T(test_stream_preimage_overflow_len),
        T(test_stream_preimage_zero_len),
        T(test_stream_preimage_partial_len_over),
        T(test_stream_preimage_truncated_more_elements),
        T(test_stream_preimage_bad_element_size),
        T(test_stream_preimage_more_bytes_than_remaining),
        T(test_stream_preimage_communication_failure),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
