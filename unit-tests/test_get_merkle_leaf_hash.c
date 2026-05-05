/**
 * Unit tests for call_get_merkle_leaf_hash using the mock dispatcher.
 *
 * Tests verify that the function correctly retrieves a leaf hash from a
 * Merkle tree and validates the proof against the root.
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
#include "handler/lib/get_merkle_leaf_hash.h"

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
 * Happy path: single element tree, retrieve the only leaf hash.
 */
static void test_get_leaf_hash_single(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xCA, 0xFE};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t expected_hash[32];
    compute_leaf_hash(elem, sizeof(elem), expected_hash);

    uint8_t out[32];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 1, 0, out);

    assert_int_equal(result, 0);
    assert_memory_equal(out, expected_hash, 32);
}

/**
 * Happy path: three-element tree, retrieve each leaf hash by index.
 */
static void test_get_leaf_hash_three_elements(void **state) {
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
        uint8_t expected_hash[32];
        compute_leaf_hash(elems[i], lens[i], expected_hash);

        uint8_t out[32];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_hash(dc, root, 3, (uint32_t) i, out);

        assert_int_equal(result, 0);
        assert_memory_equal(out, expected_hash, 32);
    }
}

/**
 * Happy path: power-of-two number of elements (4 elements, balanced tree).
 */
static void test_get_leaf_hash_four_elements(void **state) {
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
        uint8_t expected_hash[32];
        compute_leaf_hash(elems[i], lens[i], expected_hash);

        uint8_t out[32];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_hash(dc, root, 4, (uint32_t) i, out);

        assert_int_equal(result, 0);
        assert_memory_equal(out, expected_hash, 32);
    }
}

/**
 * Happy path: larger unbalanced tree (5 elements).
 */
static void test_get_leaf_hash_five_elements(void **state) {
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
        uint8_t expected_hash[32];
        compute_leaf_hash(elems[i], lens[i], expected_hash);

        uint8_t out[32];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_hash(dc, root, 5, (uint32_t) i, out);

        assert_int_equal(result, 0);
        assert_memory_equal(out, expected_hash, 32);
    }
}

/**
 * Happy path: 8-element balanced tree (depth 3).
 */
static void test_get_leaf_hash_eight_elements(void **state) {
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
        uint8_t expected_hash[32];
        compute_leaf_hash(elems[i], lens[i], expected_hash);

        uint8_t out[32];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_hash(dc, root, 8, (uint32_t) i, out);

        assert_int_equal(result, 0);
        assert_memory_equal(out, expected_hash, 32);
    }
}

/**
 * Edge case: leaf element of exactly 1 byte.
 */
static void test_get_leaf_hash_one_byte_element(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0x42};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {1};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    uint8_t expected_hash[32];
    compute_leaf_hash(elem, 1, expected_hash);

    uint8_t out[32];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 1, 0, out);

    assert_int_equal(result, 0);
    assert_memory_equal(out, expected_hash, 32);
}

/**
 * Error: wrong Merkle root (no matching tree registered).
 */
static void test_get_leaf_hash_wrong_root(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    const uint8_t elem[] = {0xDE, 0xAD};
    const uint8_t *elems[] = {elem};
    size_t lens[] = {sizeof(elem)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 1, root);

    /* Corrupt the root */
    uint8_t bad_root[32];
    memset(bad_root, 0xFF, 32);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, bad_root, 1, 0, out);

    assert_true(result < 0);
}

/**
 * Happy path: two-element tree, verify both leaves.
 */
static void test_get_leaf_hash_two_elements(void **state) {
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
        uint8_t expected_hash[32];
        compute_leaf_hash(elems[i], lens[i], expected_hash);

        uint8_t out[32];
        memset(out, 0, sizeof(out));

        int result = call_get_merkle_leaf_hash(dc, root, 2, (uint32_t) i, out);

        assert_int_equal(result, 0);
        assert_memory_equal(out, expected_hash, 32);
    }
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client returns a corrupted sibling hash in the Merkle proof.
 * The proof won't verify against the root.
 */
static int tamper_corrupt_proof_hash(uint8_t *response_buf,
                                     size_t *response_len,
                                     uint8_t cmd,
                                     int call_count,
                                     void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF && *response_len > 35) {
        /* Response: <leaf_hash:32> <proof_size:1> <n_proof_elements:1> <proof_hashes...>
         * Corrupt byte in first proof hash (starting at offset 34) */
        response_buf[35] ^= 0xFF;
    }
    return 0;
}

static void test_get_leaf_hash_corrupted_proof(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0x00, 0x01};
    uint8_t e1[] = {0x10, 0x11};
    uint8_t e2[] = {0x20, 0x21};
    uint8_t e3[] = {0x30, 0x31};

    const uint8_t *elems[] = {e0, e1, e2, e3};
    size_t lens[] = {sizeof(e0), sizeof(e1), sizeof(e2), sizeof(e3)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 4, root);

    mock_dispatcher_set_tamper_hook(&mock, tamper_corrupt_proof_hash, NULL);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 4, 0, out);

    assert_true(result < 0);
}

/**
 * Adversarial: client returns a corrupted leaf hash. The proof (built for the
 * real leaf) won't verify when starting from the wrong leaf hash.
 */
static int tamper_corrupt_leaf_hash(uint8_t *response_buf,
                                    size_t *response_len,
                                    uint8_t cmd,
                                    int call_count,
                                    void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF && *response_len >= 32) {
        response_buf[0] ^= 0xFF;
    }
    return 0;
}

static void test_get_leaf_hash_corrupted_leaf(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0xAA, 0xBB};
    uint8_t e1[] = {0xCC, 0xDD};

    const uint8_t *elems[] = {e0, e1};
    size_t lens[] = {sizeof(e0), sizeof(e1)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 2, root);

    mock_dispatcher_set_tamper_hook(&mock, tamper_corrupt_leaf_hash, NULL);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 2, 0, out);

    assert_true(result < 0);
}

/**
 * Adversarial: client claims n_proof_elements > proof_size.
 */
static int tamper_proof_elements_overflow(uint8_t *response_buf,
                                          size_t *response_len,
                                          uint8_t cmd,
                                          int call_count,
                                          void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF && *response_len >= 34) {
        uint8_t proof_size = response_buf[32];
        response_buf[33] = proof_size + 5;
    }
    return 0;
}

static void test_get_leaf_hash_proof_elements_overflow(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0xAA};
    uint8_t e1[] = {0xBB};

    const uint8_t *elems[] = {e0, e1};
    size_t lens[] = {sizeof(e0), sizeof(e1)};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 2, root);

    mock_dispatcher_set_tamper_hook(&mock, tamper_proof_elements_overflow, NULL);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 2, 0, out);

    assert_true(result < 0);
}

/**
 * Adversarial: client claims proof_size=0 for a multi-element tree.
 * The leaf hash alone won't match the root.
 */
static int tamper_zero_proof_size(uint8_t *response_buf,
                                  size_t *response_len,
                                  uint8_t cmd,
                                  int call_count,
                                  void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF && *response_len >= 34) {
        response_buf[32] = 0;
        response_buf[33] = 0;
        *response_len = 34;
    }
    return 0;
}

static void test_get_leaf_hash_zero_proof_size(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    uint8_t e0[] = {0xAA};
    uint8_t e1[] = {0xBB};
    uint8_t e2[] = {0xCC};

    const uint8_t *elems[] = {e0, e1, e2};
    size_t lens[] = {1, 1, 1};

    uint8_t root[32];
    build_tree(&mock, elems, lens, 3, root);

    mock_dispatcher_set_tamper_hook(&mock, tamper_zero_proof_size, NULL);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 3, 0, out);

    assert_true(result < 0);
}

/**
 * Adversarial: during proof continuation (GET_MORE_ELEMENTS), client sends
 * elements_len != 32.
 */
static int tamper_bad_proof_element_size(uint8_t *response_buf,
                                         size_t *response_len,
                                         uint8_t cmd,
                                         int call_count,
                                         void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[1] = 16; /* should be 32 */
    }
    return 0;
}

static void test_get_leaf_hash_bad_proof_element_size(void **state) {
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    /* Need a tree large enough that proof spills: 128 elements → depth 7,
     * first response fits 6 proof hashes → 1 goes via GET_MORE_ELEMENTS */
    uint8_t data[128][2];
    const uint8_t *elems[128];
    size_t lens[128];

    for (size_t i = 0; i < 128; i++) {
        data[i][0] = (uint8_t) (i >> 8);
        data[i][1] = (uint8_t) (i & 0xFF);
        elems[i] = data[i];
        lens[i] = 2;
    }

    uint8_t root[32];
    build_tree(&mock, elems, lens, 128, root);

    mock_dispatcher_set_tamper_hook(&mock, tamper_bad_proof_element_size, NULL);

    uint8_t out[32];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
    int result = call_get_merkle_leaf_hash(dc, root, 128, 0, out);

    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_leaf_hash_single),
        cmocka_unit_test(test_get_leaf_hash_three_elements),
        cmocka_unit_test(test_get_leaf_hash_four_elements),
        cmocka_unit_test(test_get_leaf_hash_five_elements),
        cmocka_unit_test(test_get_leaf_hash_eight_elements),
        cmocka_unit_test(test_get_leaf_hash_one_byte_element),
        cmocka_unit_test(test_get_leaf_hash_wrong_root),
        cmocka_unit_test(test_get_leaf_hash_two_elements),
        cmocka_unit_test(test_get_leaf_hash_corrupted_proof),
        cmocka_unit_test(test_get_leaf_hash_corrupted_leaf),
        cmocka_unit_test(test_get_leaf_hash_proof_elements_overflow),
        cmocka_unit_test(test_get_leaf_hash_zero_proof_size),
        cmocka_unit_test(test_get_leaf_hash_bad_proof_element_size),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
