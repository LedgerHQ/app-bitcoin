/**
 * Unit tests for call_get_merkle_leaf_index using the mock dispatcher.
 *
 * Tests verify that the function correctly finds the index of a leaf
 * by its hash in a Merkle tree, and validates the result by fetching
 * the leaf hash at the returned index and comparing.
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
#include "handler/lib/get_merkle_leaf_index.h"

/* ---------- Helpers ---------- */

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    calc_sha_256(out, data, len);
}

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

/**
 * Compute the expected leaf hash: SHA256(0x00 || element).
 */
static void compute_leaf_hash(const uint8_t *elem, size_t len, uint8_t out[32]) {
    uint8_t buf[257];
    buf[0] = 0x00;
    memcpy(buf + 1, elem, len);
    compute_sha256(buf, 1 + len, out);
}

/* ---------- Test cases ---------- */

/**
 * Happy path: single element tree, find the only leaf by its hash.
 */
static void test_get_leaf_index_single(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(elem, sizeof(elem), leaf_hash);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, root, leaf_hash);

    assert_int_equal(result, 0);
}

/**
 * Happy path: three-element tree, find each leaf index.
 */
static void test_get_leaf_index_three_elements(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t *elems[] = {(const uint8_t *) "alpha",
                              (const uint8_t *) "beta",
                              (const uint8_t *) "gamma"};
    size_t lens[] = {5, 4, 5};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 3, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

    for (size_t i = 0; i < 3; i++) {
        uint8_t leaf_hash[32];
        compute_leaf_hash(elems[i], lens[i], leaf_hash);

        int result = call_get_merkle_leaf_index(dc, 3, root, leaf_hash);

        assert_int_equal(result, (int) i);
    }
}

/**
 * Happy path: power-of-two number of elements (4 elements, balanced tree).
 */
static void test_get_leaf_index_four_elements(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0x00, 0x01, 0x02};
    uint8_t e1[] = {0x10, 0x11};
    uint8_t e2[] = {0x20};
    uint8_t e3[] = {0x30, 0x31, 0x32, 0x33};

    const uint8_t *elems[] = {e0, e1, e2, e3};
    size_t lens[] = {sizeof(e0), sizeof(e1), sizeof(e2), sizeof(e3)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 4, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

    for (size_t i = 0; i < 4; i++) {
        uint8_t leaf_hash[32];
        compute_leaf_hash(elems[i], lens[i], leaf_hash);

        int result = call_get_merkle_leaf_index(dc, 4, root, leaf_hash);

        assert_int_equal(result, (int) i);
    }
}

/**
 * Happy path: 5-element unbalanced tree.
 */
static void test_get_leaf_index_five_elements(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0xAA};
    uint8_t e1[] = {0xBB, 0xCC};
    uint8_t e2[] = {0xDD, 0xEE, 0xFF};
    uint8_t e3[] = {0x11, 0x22};
    uint8_t e4[] = {0x33};

    const uint8_t *elems[] = {e0, e1, e2, e3, e4};
    size_t lens[] = {sizeof(e0), sizeof(e1), sizeof(e2), sizeof(e3), sizeof(e4)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 5, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

    for (size_t i = 0; i < 5; i++) {
        uint8_t leaf_hash[32];
        compute_leaf_hash(elems[i], lens[i], leaf_hash);

        int result = call_get_merkle_leaf_index(dc, 5, root, leaf_hash);

        assert_int_equal(result, (int) i);
    }
}

/**
 * Error: unknown leaf hash (not in the tree).
 */
static void test_get_leaf_index_unknown_hash(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    /* Use a leaf hash that doesn't exist in the tree */
    uint8_t fake_hash[32];
    memset(fake_hash, 0xDE, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, root, fake_hash);

    assert_true(result < 0);
}

/**
 * Error: wrong Merkle root (no matching tree registered).
 */
static void test_get_leaf_index_wrong_root(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xDE, 0xAD};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(elem, sizeof(elem), leaf_hash);

    /* Corrupt the root */
    uint8_t bad_root[32];
    memset(bad_root, 0xFF, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, bad_root, leaf_hash);

    assert_true(result < 0);
}

/**
 * Happy path: two-element tree, find both leaves.
 */
static void test_get_leaf_index_two_elements(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t e0[] = {0x01, 0x02, 0x03};
    const uint8_t e1[] = {0x04, 0x05};
    const uint8_t *elems[] = {e0, e1};
    size_t lens[] = {sizeof(e0), sizeof(e1)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 2, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

    for (size_t i = 0; i < 2; i++) {
        uint8_t leaf_hash[32];
        compute_leaf_hash(elems[i], lens[i], leaf_hash);

        int result = call_get_merkle_leaf_index(dc, 2, root, leaf_hash);

        assert_int_equal(result, (int) i);
    }
}

/**
 * Happy path: 8-element balanced tree (depth 3).
 */
static void test_get_leaf_index_eight_elements(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t data[8][4];
    const uint8_t *elems[8];
    size_t lens[8];

    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 4; j++) {
            data[i][j] = (uint8_t) ((i * 4 + j) ^ 0x5A);
        }
        elems[i] = data[i];
        lens[i] = 4;
    }

    uint8_t root[32];
    build_tree(&mock, elems, lens, 8, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

    for (size_t i = 0; i < 8; i++) {
        uint8_t leaf_hash[32];
        compute_leaf_hash(elems[i], lens[i], leaf_hash);

        int result = call_get_merkle_leaf_index(dc, 8, root, leaf_hash);

        assert_int_equal(result, (int) i);
    }
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client claims a leaf is at a wrong index.  The device fetches
 * the leaf hash at the claimed index and compares — must detect mismatch.
 */
static int tamper_wrong_index(uint8_t *response_buf,
                              size_t *response_len,
                              uint8_t cmd,
                              int call_count,
                              void *user_data) {
    (void) user_data;

    if (cmd == CCMD_GET_MERKLE_LEAF_INDEX && call_count == 0) {
        if (*response_len >= 2) {
            response_buf[0] = 1; /* found */
            /* Swap: 0↔1 */
            response_buf[1] = (response_buf[1] == 0) ? 1 : 0;
        }
    }
    return 0;
}

static void test_get_leaf_index_wrong_index(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0x01, 0x02, 0x03};
    uint8_t e1[] = {0x04, 0x05, 0x06};

    const uint8_t *elems[] = {e0, e1};
    size_t lens[] = {sizeof(e0), sizeof(e1)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 2, root);

    /* Query for e1 (index 1), tamper will claim index 0 */
    uint8_t leaf_hash[32];
    compute_leaf_hash(e1, sizeof(e1), leaf_hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_wrong_index, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 2, root, leaf_hash);

    /* Verification fetch at wrong index → hash mismatch → must fail */
    assert_true(result < 0);
}

/**
 * Adversarial: client claims found=1 but returns an out-of-bounds index.
 */
static int tamper_oob_index(uint8_t *response_buf,
                            size_t *response_len,
                            uint8_t cmd,
                            int call_count,
                            void *user_data) {
    (void) user_data;

    if (cmd == CCMD_GET_MERKLE_LEAF_INDEX && call_count == 0) {
        if (*response_len >= 2) {
            response_buf[0] = 1; /* found */
            response_buf[1] = 2; /* out of bounds */
        }
    }
    return 0;
}

static void test_get_leaf_index_oob_index(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0xAA};
    uint8_t e1[] = {0xBB};

    const uint8_t *elems[] = {e0, e1};
    size_t lens[] = {1, 1};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 2, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(e0, sizeof(e0), leaf_hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_oob_index, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 2, root, leaf_hash);

    /* index >= size → must fail */
    assert_true(result < 0);
}

/**
 * Adversarial: process_interruption fails on the initial
 * CCMD_GET_MERKLE_LEAF_INDEX call — must return -3.
 */
static int tamper_fail_first(uint8_t *response_buf,
                             size_t *response_len,
                             uint8_t cmd,
                             int call_count,
                             void *user_data) {
    (void) response_buf;
    (void) response_len;
    (void) cmd;
    (void) user_data;
    (void) call_count;
    return -1;
}

static void test_get_leaf_index_initial_comm_failure(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(elem, sizeof(elem), leaf_hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_fail_first, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, root, leaf_hash);

    assert_int_equal(result, -3);
}

/**
 * Adversarial: client returns `found` byte that is neither 0 nor 1 — must
 * return -2.
 */
static int tamper_invalid_found(uint8_t *response_buf,
                                size_t *response_len,
                                uint8_t cmd,
                                int call_count,
                                void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_INDEX && *response_len >= 2) {
        response_buf[0] = 7; /* invalid */
        response_buf[1] = 0;
    }
    return 0;
}

static void test_get_leaf_index_invalid_found(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(elem, sizeof(elem), leaf_hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_invalid_found, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, root, leaf_hash);

    assert_int_equal(result, -2);
}

/**
 * Adversarial: after a valid CCMD_GET_MERKLE_LEAF_INDEX reply, the follow-up
 * CCMD_GET_MERKLE_LEAF_PROOF call (issued by call_get_merkle_leaf_hash) fails.
 * call_get_merkle_leaf_index must surface this as -4.
 */
static int tamper_fail_second_call(uint8_t *response_buf,
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

static void test_get_leaf_index_verify_comm_failure(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t leaf_hash[32];
    compute_leaf_hash(elem, sizeof(elem), leaf_hash);

    mock_dispatcher_set_tamper_hook(&mock, tamper_fail_second_call, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_index(dc, 1, root, leaf_hash);

    assert_int_equal(result, -4);
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_leaf_index_single),
        cmocka_unit_test(test_get_leaf_index_three_elements),
        cmocka_unit_test(test_get_leaf_index_four_elements),
        cmocka_unit_test(test_get_leaf_index_five_elements),
        cmocka_unit_test(test_get_leaf_index_unknown_hash),
        cmocka_unit_test(test_get_leaf_index_wrong_root),
        cmocka_unit_test(test_get_leaf_index_two_elements),
        cmocka_unit_test(test_get_leaf_index_eight_elements),
        cmocka_unit_test(test_get_leaf_index_wrong_index),
        cmocka_unit_test(test_get_leaf_index_oob_index),
        cmocka_unit_test(test_get_leaf_index_initial_comm_failure),
        cmocka_unit_test(test_get_leaf_index_invalid_found),
        cmocka_unit_test(test_get_leaf_index_verify_comm_failure),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
