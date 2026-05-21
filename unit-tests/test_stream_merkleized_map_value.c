/**
 * Unit tests for call_stream_merkleized_map_value using the mock dispatcher.
 *
 * call_stream_merkleized_map_value looks up a key in a merkleized key-value
 * map (by finding its index via Merkle leaf index), then streams the
 * corresponding value via callbacks.
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

#include "handler/lib/stream_merkleized_map_value.h"

/* ---------- Helpers ---------- */

/* Accumulator for streaming callbacks */
typedef struct {
    uint8_t buf[1024];
    size_t offset;
    size_t total_len;
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
 * Happy path: single key-value pair, look up by key and stream the value.
 */
static void test_stream_map_value_single(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01, 0x02};
    const uint8_t value[] = {0xAA, 0xBB, 0xCC};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkleized_map_value(dc,
                                                  &commitment,
                                                  key,
                                                  sizeof(key),
                                                  acc_len_callback,
                                                  acc_data_callback,
                                                  &acc);

    assert_int_equal(result, (int) sizeof(value));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(value));
    assert_int_equal(acc.offset, sizeof(value));
    assert_memory_equal(acc.buf, value, sizeof(value));
}

/**
 * Happy path: three key-value pairs, look up each by key.
 * Keys must be in sorted order for the Merkle map to work.
 */
static void test_stream_map_value_three_pairs(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Keys are sorted lexicographically by mock_dispatcher_add_map */
    const uint8_t k0[] = {0x01};
    const uint8_t k1[] = {0x02};
    const uint8_t k2[] = {0x03};
    const uint8_t v0[] = {0x10, 0x11, 0x12};
    const uint8_t v1[] = {0x20, 0x21};
    const uint8_t v2[] = {0x30, 0x31, 0x32, 0x33};

    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 3, &commitment);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    /* Look up each key-value pair */
    const uint8_t *test_keys[] = {k0, k1, k2};
    const size_t test_key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *expected_values[] = {v0, v1, v2};
    const size_t expected_value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    for (size_t i = 0; i < 3; i++) {
        stream_accumulator_t acc;
        memset(&acc, 0, sizeof(acc));

        int result = call_stream_merkleized_map_value(dc,
                                                      &commitment,
                                                      test_keys[i],
                                                      test_key_lens[i],
                                                      acc_len_callback,
                                                      acc_data_callback,
                                                      &acc);

        assert_int_equal(result, (int) expected_value_lens[i]);
        assert_true(acc.len_called);
        assert_int_equal(acc.total_len, expected_value_lens[i]);
        assert_int_equal(acc.offset, expected_value_lens[i]);
        assert_memory_equal(acc.buf, expected_values[i], expected_value_lens[i]);
    }
}

/**
 * Error: key not found in the map.
 */
static void test_stream_map_value_key_not_found(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xAA};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    /* Look up a key that doesn't exist */
    const uint8_t missing_key[] = {0xFF};

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkleized_map_value(dc,
                                                  &commitment,
                                                  missing_key,
                                                  sizeof(missing_key),
                                                  acc_len_callback,
                                                  acc_data_callback,
                                                  &acc);

    assert_true(result < 0);
}

/**
 * Edge case: value of exactly 1 byte.
 */
static void test_stream_map_value_one_byte_value(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x42};
    const uint8_t value[] = {0x99};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkleized_map_value(dc,
                                                  &commitment,
                                                  key,
                                                  sizeof(key),
                                                  acc_len_callback,
                                                  acc_data_callback,
                                                  &acc);

    assert_int_equal(result, 1);
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, 1);
    assert_int_equal(acc.offset, 1);
    assert_int_equal(acc.buf[0], 0x99);
}

/**
 * Happy path: NULL len_callback should work (len_callback is optional).
 */
static void test_stream_map_value_null_len_callback(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x05};
    const uint8_t value[] = {0x10, 0x20, 0x30};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkleized_map_value(dc,
                                                  &commitment,
                                                  key,
                                                  sizeof(key),
                                                  NULL,
                                                  acc_data_callback,
                                                  &acc);

    assert_int_equal(result, (int) sizeof(value));
    assert_false(acc.len_called);
    assert_int_equal(acc.offset, sizeof(value));
    assert_memory_equal(acc.buf, value, sizeof(value));
}

/**
 * Happy path: keys provided in unsorted order (mock_dispatcher_add_map sorts them).
 */
static void test_stream_map_value_unsorted_keys(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Provide keys in reverse order; add_map will sort them */
    const uint8_t k0[] = {0x03};
    const uint8_t k1[] = {0x01};
    const uint8_t k2[] = {0x02};
    const uint8_t v0[] = {0x30};
    const uint8_t v1[] = {0x10};
    const uint8_t v2[] = {0x20};

    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 3, &commitment);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    /* Look up each original key and verify it retrieves the correct value */
    for (size_t i = 0; i < 3; i++) {
        stream_accumulator_t acc;
        memset(&acc, 0, sizeof(acc));

        int result = call_stream_merkleized_map_value(dc,
                                                      &commitment,
                                                      keys[i],
                                                      key_lens[i],
                                                      acc_len_callback,
                                                      acc_data_callback,
                                                      &acc);

        assert_int_equal(result, (int) value_lens[i]);
        assert_true(acc.len_called);
        assert_int_equal(acc.total_len, value_lens[i]);
        assert_int_equal(acc.offset, value_lens[i]);
        assert_memory_equal(acc.buf, values[i], value_lens[i]);
    }
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_stream_map_value_single),
        T(test_stream_map_value_three_pairs),
        T(test_stream_map_value_key_not_found),
        T(test_stream_map_value_one_byte_value),
        T(test_stream_map_value_null_len_callback),
        T(test_stream_map_value_unsorted_keys),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
