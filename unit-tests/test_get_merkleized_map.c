/**
 * Unit tests for call_get_merkleized_map_with_callback (and the
 * call_get_merkleized_map convenience wrapper) using the mock dispatcher.
 *
 * Tests verify that the function correctly:
 *  - Fetches the index-th element of a tree of serialized map commitments,
 *    decodes it into a merkleized_map_commitment_t, and validates that the
 *    inner keys tree is sorted.
 *  - Invokes the optional element callback once per key when validating.
 *  - Propagates errors from the underlying merkle leaf retrieval, the
 *    deserialization of the commitment, and the sorted-keys check.
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

#include "buffer.h"
#include "varint.h"
#include "client_commands.h"
#include "common/merkle.h"
#include "handler/lib/get_merkleized_map.h"

/* ---------- Helpers ---------- */

/**
 * Serialize a merkleized map commitment to the canonical byte layout
 *   varint(size) || keys_root[32] || values_root[32]
 */
static size_t serialize_commitment(const merkleized_map_commitment_t *c, uint8_t *out) {
    int vlen = varint_write(out, 0, c->size);
    memcpy(out + vlen, c->keys_root, 32);
    memcpy(out + vlen + 32, c->values_root, 32);
    return (size_t) vlen + 64;
}

/* ---------- Callback tracking ---------- */

#define MAX_CALLBACK_CALLS 32

typedef struct {
    size_t n_calls;
    int indices[MAX_CALLBACK_CALLS];
    uint8_t elements[MAX_CALLBACK_CALLS][64];
    size_t element_lens[MAX_CALLBACK_CALLS];
    const merkleized_map_commitment_t *received_commitment;
} callback_tracker_t;

static void tracking_callback(dispatcher_context_t *dc,
                              void *state,
                              const merkleized_map_commitment_t *map_commitment,
                              int index,
                              buffer_t *buf) {
    (void) dc;

    callback_tracker_t *tracker = (callback_tracker_t *) state;
    assert_true(tracker->n_calls < MAX_CALLBACK_CALLS);

    tracker->received_commitment = map_commitment;
    size_t i = tracker->n_calls++;
    tracker->indices[i] = index;
    size_t len = buf->size - buf->offset;
    assert_true(len <= sizeof(tracker->elements[0]));
    memcpy(tracker->elements[i], buf->ptr + buf->offset, len);
    tracker->element_lens[i] = len;
}

/* ---------- Test cases ---------- */

/**
 * Happy path: a single map with one key-value pair, registered as the
 * only element of an outer "tree-of-maps".
 */
static void test_get_map_single_outer_single_inner(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xAA, 0xBB};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t inner;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &inner);

    /* Build the tree of (one) serialized commitment. */
    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);

    assert_int_equal(result, 0);
    assert_int_equal((int) got.size, 1);
    assert_memory_equal(got.keys_root, inner.keys_root, 32);
    assert_memory_equal(got.values_root, inner.values_root, 32);
}

/**
 * Happy path: a tree of three maps, fetch each by index and verify the
 * decoded commitment matches the inner map registered with the mock.
 */
static void test_get_map_multiple_outer(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Build three distinct inner maps. */
    merkleized_map_commitment_t inners[3];
    for (size_t i = 0; i < 3; i++) {
        uint8_t k[2] = {(uint8_t) i, 0x00};
        uint8_t v[2] = {(uint8_t) (0x10 + i), 0x01};
        const uint8_t *ks[] = {k};
        const size_t kls[] = {sizeof(k)};
        const uint8_t *vs[] = {v};
        const size_t vls[] = {sizeof(v)};
        mock_dispatcher_add_map(mock, ks, kls, vs, vls, 1, &inners[i]);
    }

    /* Serialize commitments and register them as the outer list. */
    uint8_t bufs[3][1 + 64];
    size_t lens[3];
    const uint8_t *ptrs[3];
    for (size_t i = 0; i < 3; i++) {
        lens[i] = serialize_commitment(&inners[i], bufs[i]);
        ptrs[i] = bufs[i];
    }
    mock_dispatcher_add_list(mock, ptrs, lens, 3);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 3; i++) {
        merkleized_map_commitment_t got;
        int result = call_get_merkleized_map(dc, outer_root, 3, (int) i, &got);
        assert_int_equal(result, 0);
        assert_int_equal((int) got.size, 1);
        assert_memory_equal(got.keys_root, inners[i].keys_root, 32);
        assert_memory_equal(got.values_root, inners[i].values_root, 32);
    }
}

/**
 * Happy path: an inner map with multiple sorted keys, fetched with a
 * callback. The callback must be invoked once per key, in order.
 */
static void test_get_map_with_callback(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t k0[] = {0x01};
    const uint8_t k1[] = {0x02};
    const uint8_t k2[] = {0x03};
    const uint8_t v0[] = {0xA0};
    const uint8_t v1[] = {0xB0};
    const uint8_t v2[] = {0xC0};

    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    merkleized_map_commitment_t inner;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 3, &inner);

    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map_with_callback(dc,
                                                       &tracker,
                                                       outer_root,
                                                       1,
                                                       0,
                                                       tracking_callback,
                                                       &got);

    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 3);
    /* The callback must receive a pointer to the out commitment */
    assert_ptr_equal(tracker.received_commitment, &got);
    /* Callback receives keys in sorted order */
    for (size_t i = 0; i < 3; i++) {
        assert_int_equal(tracker.indices[i], (int) i);
        assert_int_equal(tracker.element_lens[i], 1);
    }
    assert_int_equal(tracker.elements[0][0], 0x01);
    assert_int_equal(tracker.elements[1][0], 0x02);
    assert_int_equal(tracker.elements[2][0], 0x03);
}

/**
 * Happy path: a map with size = 0 (no keys). The sorted-keys check
 * trivially succeeds and the callback is never invoked.
 */
static void test_get_map_empty_inner(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Build an empty commitment manually: size=0, keys_root and values_root
     * are arbitrary (they are not consulted because size=0). */
    merkleized_map_commitment_t inner;
    inner.size = 0;
    memset(inner.keys_root, 0, 32);
    memset(inner.values_root, 0, 32);

    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map_with_callback(dc,
                                                       &tracker,
                                                       outer_root,
                                                       1,
                                                       0,
                                                       tracking_callback,
                                                       &got);

    assert_int_equal(result, 0);
    assert_int_equal((int) got.size, 0);
    assert_int_equal(tracker.n_calls, 0);
}

/**
 * Error: invalid outer index (out of range). The underlying
 * call_get_merkle_leaf_element fails and the error must be propagated.
 */
static void test_get_map_outer_index_out_of_range(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xAA};
    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t inner;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &inner);

    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    /* Index 5 is past the end of the 1-element outer tree. */
    int result = call_get_merkleized_map(dc, outer_root, 1, 5, &got);
    assert_true(result < 0);
}

/**
 * Error: the leaf element is too short to contain a valid serialized
 * commitment (varint + 32 + 32 bytes). The mock returns a known leaf, but
 * the test registers a leaf shorter than the minimum length, so the
 * varint/bytes reads must fail and call_get_merkleized_map returns -1.
 */
static void test_get_map_truncated_commitment(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Only 33 bytes: varint(=1) + 32 bytes of "keys_root" but no values_root. */
    uint8_t truncated[1 + 32];
    truncated[0] = 0x01;
    memset(truncated + 1, 0xAB, 32);

    const uint8_t *outer_elems[] = {truncated};
    const size_t outer_lens[] = {sizeof(truncated)};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);
    assert_true(result < 0);
}

/**
 * Error: the leaf element is empty (0 bytes), so buffer_read_varint fails
 * on the very first byte.
 */
static void test_get_map_empty_commitment(void **state) {
    mock_dispatcher_t *mock = *state;

    /* A single empty leaf element. */
    const uint8_t *outer_elems[] = {(const uint8_t *) ""};
    const size_t outer_lens[] = {0};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);
    assert_true(result < 0);
}

/**
 * Error: the leaf element contains a valid varint but no keys_root bytes.
 * buffer_read_bytes for keys_root fails.
 */
static void test_get_map_commitment_missing_keys_root(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Single byte 0x05: varint size = 5, then nothing more. */
    const uint8_t leaf[] = {0x05};
    const uint8_t *outer_elems[] = {leaf};
    const size_t outer_lens[] = {sizeof(leaf)};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);
    assert_true(result < 0);
}

/**
 * Error: the inner keys tree is not sorted. We craft a commitment whose
 * keys_root points to a tree we built manually with unsorted keys, so the
 * sorted-keys check at the end of call_get_merkleized_map_with_callback
 * must fail.
 */
static void test_get_map_inner_unsorted_keys(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Build a keys tree with keys in DESCENDING order. */
    const uint8_t k0[] = {0x03};
    const uint8_t k1[] = {0x02};
    const uint8_t k2[] = {0x01};
    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {1, 1, 1};
    mock_dispatcher_add_list(mock, keys, key_lens, 3);
    uint8_t keys_root[32];
    memcpy(keys_root, mock->trees[mock->n_trees - 1].root, 32);

    /* Build an unrelated values tree (its content is not checked). */
    const uint8_t v0[] = {0xA0};
    const uint8_t v1[] = {0xB0};
    const uint8_t v2[] = {0xC0};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {1, 1, 1};
    mock_dispatcher_add_list(mock, values, value_lens, 3);
    uint8_t values_root[32];
    memcpy(values_root, mock->trees[mock->n_trees - 1].root, 32);

    merkleized_map_commitment_t inner;
    inner.size = 3;
    memcpy(inner.keys_root, keys_root, 32);
    memcpy(inner.values_root, values_root, 32);

    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);
    assert_true(result < 0);
}

/**
 * Adversarial: client corrupts the leaf hash returned in the merkle proof
 * for the outer tree-of-maps. The merkle proof verification must fail
 * inside call_get_merkle_leaf_element, propagating an error.
 */
static int tamper_corrupt_outer_proof(uint8_t *response_buf,
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

static void test_get_map_corrupted_outer_proof(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xAA};
    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t inner;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &inner);

    uint8_t commitment_buf[1 + 64];
    size_t commitment_len = serialize_commitment(&inner, commitment_buf);
    const uint8_t *outer_elems[] = {commitment_buf};
    const size_t outer_lens[] = {commitment_len};
    mock_dispatcher_add_list(mock, outer_elems, outer_lens, 1);
    uint8_t outer_root[32];
    memcpy(outer_root, mock->trees[mock->n_trees - 1].root, 32);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_outer_proof, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    merkleized_map_commitment_t got;
    int result = call_get_merkleized_map(dc, outer_root, 1, 0, &got);
    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_get_map_single_outer_single_inner),
        T(test_get_map_multiple_outer),
        T(test_get_map_with_callback),
        T(test_get_map_empty_inner),
        T(test_get_map_outer_index_out_of_range),
        T(test_get_map_truncated_commitment),
        T(test_get_map_empty_commitment),
        T(test_get_map_commitment_missing_keys_root),
        T(test_get_map_inner_unsorted_keys),
        T(test_get_map_corrupted_outer_proof),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
