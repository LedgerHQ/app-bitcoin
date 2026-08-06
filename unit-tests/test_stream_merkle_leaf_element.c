/**
 * Unit tests for call_stream_merkle_leaf_element using the mock dispatcher.
 *
 * call_stream_merkle_leaf_element is the streaming counterpart of
 * call_get_merkle_leaf_element: instead of writing to an output buffer it
 * streams data via callbacks.
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

#include "handler/lib/stream_merkle_leaf_element.h"

/* ---------- Helpers ---------- */

/**
 * Build a Merkle tree from the given elements and copy the root hash.
 */
static void build_tree(mock_dispatcher_t *mock,
                       const uint8_t *const *elems,
                       const size_t *lens,
                       size_t n,
                       uint8_t root_out[32]) {
    mock_dispatcher_add_list(mock, elems, lens, n);
    memcpy(root_out, mock->trees[mock->n_trees - 1].root, 32);
}

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
 * Happy path: single element tree, retrieve the only leaf.
 */
static void test_stream_leaf_element_single(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result =
        call_stream_merkle_leaf_element(dc, root, 1, 0, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(elem));
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, sizeof(elem));
    assert_int_equal(acc.offset, sizeof(elem));
    assert_memory_equal(acc.buf, elem, sizeof(elem));
}

/**
 * Happy path: three-element tree, retrieve each leaf by index.
 */
static void test_stream_leaf_element_three_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "alpha",
                              (const uint8_t *) "beta",
                              (const uint8_t *) "gamma"};
    size_t lens[] = {5, 4, 5};

    uint8_t root[32];
    build_tree(mock, elems, lens, 3, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 3; i++) {
        stream_accumulator_t acc;
        memset(&acc, 0, sizeof(acc));

        int result = call_stream_merkle_leaf_element(dc,
                                                     root,
                                                     3,
                                                     (uint32_t) i,
                                                     acc_len_callback,
                                                     acc_data_callback,
                                                     &acc);

        assert_int_equal(result, (int) lens[i]);
        assert_true(acc.len_called);
        assert_int_equal(acc.total_len, lens[i]);
        assert_int_equal(acc.offset, lens[i]);
        assert_memory_equal(acc.buf, elems[i], lens[i]);
    }
}

/**
 * Happy path: power-of-two number of elements (4 elements, balanced tree).
 */
static void test_stream_leaf_element_four_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t e0[] = {0x00, 0x01, 0x02};
    uint8_t e1[] = {0x10, 0x11};
    uint8_t e2[] = {0x20};
    uint8_t e3[] = {0x30, 0x31, 0x32, 0x33};

    const uint8_t *elems[] = {e0, e1, e2, e3};
    size_t lens[] = {sizeof(e0), sizeof(e1), sizeof(e2), sizeof(e3)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 4, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 4; i++) {
        stream_accumulator_t acc;
        memset(&acc, 0, sizeof(acc));

        int result = call_stream_merkle_leaf_element(dc,
                                                     root,
                                                     4,
                                                     (uint32_t) i,
                                                     acc_len_callback,
                                                     acc_data_callback,
                                                     &acc);

        assert_int_equal(result, (int) lens[i]);
        assert_true(acc.len_called);
        assert_int_equal(acc.total_len, lens[i]);
        assert_int_equal(acc.offset, lens[i]);
        assert_memory_equal(acc.buf, elems[i], lens[i]);
    }
}

/**
 * Edge case: leaf element of exactly 1 byte.
 */
static void test_stream_leaf_element_one_byte(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0x42};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {1};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result =
        call_stream_merkle_leaf_element(dc, root, 1, 0, acc_len_callback, acc_data_callback, &acc);

    assert_int_equal(result, 1);
    assert_true(acc.len_called);
    assert_int_equal(acc.total_len, 1);
    assert_int_equal(acc.offset, 1);
    assert_int_equal(acc.buf[0], 0x42);
}

/**
 * Error: wrong Merkle root (no matching tree).
 */
static void test_stream_leaf_element_wrong_root(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0xAB, 0xCD};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    /* Corrupt the root */
    uint8_t bad_root[32];
    memset(bad_root, 0xFF, 32);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkle_leaf_element(dc,
                                                 bad_root,
                                                 1,
                                                 0,
                                                 acc_len_callback,
                                                 acc_data_callback,
                                                 &acc);

    assert_true(result < 0);
}

/**
 * Error: leaf index out of bounds (>= tree_size).
 */
static void test_stream_leaf_element_index_out_of_bounds(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "x", (const uint8_t *) "y"};
    size_t lens[] = {1, 1};

    uint8_t root[32];
    build_tree(mock, elems, lens, 2, root);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_stream_merkle_leaf_element(dc,
                                                 root,
                                                 2,
                                                 5,
                                                 acc_len_callback,
                                                 acc_data_callback,
                                                 &acc);

    assert_true(result < 0);
}

/**
 * Happy path: larger tree (8 elements) to exercise deeper proof paths.
 */
static void test_stream_leaf_element_eight_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t data[8][16];
    const uint8_t *elems[8];
    size_t lens[8];

    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 16; j++) {
            data[i][j] = (uint8_t) (i * 16 + j);
        }
        elems[i] = data[i];
        lens[i] = 16;
    }

    uint8_t root[32];
    build_tree(mock, elems, lens, 8, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 8; i++) {
        stream_accumulator_t acc;
        memset(&acc, 0, sizeof(acc));

        int result = call_stream_merkle_leaf_element(dc,
                                                     root,
                                                     8,
                                                     (uint32_t) i,
                                                     acc_len_callback,
                                                     acc_data_callback,
                                                     &acc);

        assert_int_equal(result, 16);
        assert_true(acc.len_called);
        assert_int_equal(acc.total_len, 16);
        assert_int_equal(acc.offset, 16);
        assert_memory_equal(acc.buf, data[i], 16);
    }
}

/**
 * Happy path: NULL len_callback should work (len_callback is optional).
 */
static void test_stream_leaf_element_null_len_callback(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    stream_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result =
        call_stream_merkle_leaf_element(dc, root, 1, 0, NULL, acc_data_callback, &acc);

    assert_int_equal(result, (int) sizeof(elem));
    assert_false(acc.len_called);
    assert_int_equal(acc.offset, sizeof(elem));
    assert_memory_equal(acc.buf, elem, sizeof(elem));
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_stream_leaf_element_single),
        T(test_stream_leaf_element_three_elements),
        T(test_stream_leaf_element_four_elements),
        T(test_stream_leaf_element_one_byte),
        T(test_stream_leaf_element_wrong_root),
        T(test_stream_leaf_element_index_out_of_bounds),
        T(test_stream_leaf_element_eight_elements),
        T(test_stream_leaf_element_null_len_callback),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
