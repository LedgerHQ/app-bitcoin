/**
 * Unit tests for call_get_merkle_leaf_element using the mock dispatcher.
 *
 * Tests verify that the function correctly retrieves the preimage of a
 * leaf in a Merkle tree identified by root and tree_size, combining
 * call_get_merkle_leaf_hash and call_get_merkle_preimage internally.
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
#include "test_assertions.h"

#include "client_commands.h"
#include "handler/lib/get_merkle_leaf_element.h"

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

/* ---------- Test cases ---------- */

/**
 * Happy path: single element tree, retrieve the only leaf.
 */
static void test_get_leaf_element_single(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    uint8_t out[256];
    memset(out, 0xAA, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 1, 0, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(elem));
    assert_memory_equal(out, elem, sizeof(elem));
}

/**
 * Happy path: three-element tree, retrieve each leaf by index.
 */
static void test_get_leaf_element_three_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "alpha",
                              (const uint8_t *) "beta",
                              (const uint8_t *) "gamma"};
    size_t lens[] = {5, 4, 5};

    uint8_t root[32];
    build_tree(mock, elems, lens, 3, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 3; i++) {
        uint8_t out[256];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_element(dc, root, 3, (uint32_t) i, out, sizeof(out));

        assert_int_equal(result, (int) lens[i]);
        assert_memory_equal(out, elems[i], lens[i]);
    }
}

/**
 * Happy path: power-of-two number of elements (4 elements, balanced tree).
 */
static void test_get_leaf_element_four_elements(void **state) {
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
        uint8_t out[256];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_element(dc, root, 4, (uint32_t) i, out, sizeof(out));

        assert_int_equal(result, (int) lens[i]);
        assert_memory_equal(out, elems[i], lens[i]);
    }
}

/**
 * Edge case: leaf element of exactly 1 byte.
 */
static void test_get_leaf_element_one_byte(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0x42};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {1};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 1, 0, out, sizeof(out));

    assert_int_equal(result, 1);
    assert_int_equal(out[0], 0x42);
}

/**
 * Error: output buffer too small for the leaf element.
 */
static void test_get_leaf_element_buffer_too_small(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t elem[100];
    for (size_t i = 0; i < sizeof(elem); i++) {
        elem[i] = (uint8_t) i;
    }
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    uint8_t out[10]; /* Too small */
    memset(out, 0xEE, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 1, 0, out, sizeof(out));

    assert_true(result < 0);
    assert_cleared(out, sizeof(out));
}

/**
 * Error: wrong Merkle root (no matching tree).
 */
static void test_get_leaf_element_wrong_root(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t elem[] = {0xAB, 0xCD};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    /* Corrupt the root */
    uint8_t bad_root[32];
    memset(bad_root, 0xFF, 32);

    uint8_t out[256];
    memset(out, 0xEE, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, bad_root, 1, 0, out, sizeof(out));

    assert_true(result < 0);
    assert_cleared(out, sizeof(out));
}

/**
 * Error: leaf index out of bounds (>= tree_size).
 */
static void test_get_leaf_element_index_out_of_bounds(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "x", (const uint8_t *) "y"};
    size_t lens[] = {1, 1};

    uint8_t root[32];
    build_tree(mock, elems, lens, 2, root);

    uint8_t out[256];
    memset(out, 0xEE, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 2, 5, out, sizeof(out));

    assert_true(result < 0);
    assert_cleared(out, sizeof(out));
}

/**
 * Happy path: larger tree (8 elements) to exercise deeper proof paths.
 */
static void test_get_leaf_element_eight_elements(void **state) {
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
        uint8_t out[256];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_element(dc, root, 8, (uint32_t) i, out, sizeof(out));

        assert_int_equal(result, 16);
        assert_memory_equal(out, data[i], 16);
    }
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client corrupts the leaf hash in the proof response so it
 * doesn't match the actual leaf.  call_get_merkle_leaf_hash will fail
 * (root mismatch), causing call_get_merkle_leaf_element to fail.
 */
static int tamper_corrupt_leaf_in_proof(uint8_t *response_buf,
                                        size_t *response_len,
                                        uint8_t cmd,
                                        int call_count,
                                        void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF && *response_len >= 32) {
        response_buf[5] ^= 0x01;
    }
    return 0;
}

static void test_get_leaf_element_corrupted_proof(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t e0[] = {0x01, 0x02, 0x03};
    uint8_t e1[] = {0x04, 0x05, 0x06};
    uint8_t e2[] = {0x07, 0x08, 0x09};
    uint8_t e3[] = {0x0A, 0x0B, 0x0C};

    const uint8_t *elems[] = {e0, e1, e2, e3};
    size_t lens[] = {sizeof(e0), sizeof(e1), sizeof(e2), sizeof(e3)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 4, root);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_leaf_in_proof, NULL);

    uint8_t out[256];
    memset(out, 0xEE, sizeof(out));
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 4, 0, out, sizeof(out));

    assert_true(result < 0);
    assert_cleared(out, sizeof(out));
}

/**
 * Adversarial: client corrupts the preimage data returned after the proof
 * verified.  The leaf hash was correct (proof passed), but the preimage
 * returned doesn't hash to it.
 */
static int tamper_corrupt_preimage_after_proof(uint8_t *response_buf,
                                               size_t *response_len,
                                               uint8_t cmd,
                                               int call_count,
                                               void *user_data) {
    (void) user_data;

    /* Only tamper the second interruption (first is the proof, second is preimage) */
    if (cmd == CCMD_GET_PREIMAGE && call_count == 1 && *response_len > 3) {
        response_buf[3] ^= 0xFF;
    }
    return 0;
}

static void test_get_leaf_element_corrupted_preimage(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t e0[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t *elems[] = {e0};
    size_t lens[] = {sizeof(e0)};

    uint8_t root[32];
    build_tree(mock, elems, lens, 1, root);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_preimage_after_proof, NULL);

    uint8_t out[256];
    memset(out, 0xEE, sizeof(out));
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkle_leaf_element(dc, root, 1, 0, out, sizeof(out));

    /* Preimage hash mismatch → must fail */
    assert_true(result < 0);
    assert_cleared(out, sizeof(out));
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_get_leaf_element_single),
        T(test_get_leaf_element_three_elements),
        T(test_get_leaf_element_four_elements),
        T(test_get_leaf_element_one_byte),
        T(test_get_leaf_element_buffer_too_small),
        T(test_get_leaf_element_wrong_root),
        T(test_get_leaf_element_index_out_of_bounds),
        T(test_get_leaf_element_eight_elements),
        T(test_get_leaf_element_corrupted_proof),
        T(test_get_leaf_element_corrupted_preimage),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
