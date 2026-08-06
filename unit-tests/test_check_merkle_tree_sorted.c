/**
 * Unit tests for call_check_merkle_tree_sorted_with_callback using the mock dispatcher.
 *
 * Tests verify that the function correctly:
 *  - Accepts elements in strict lexicographic order.
 *  - Rejects elements that are not in strict lexicographic order.
 *  - Invokes the callback once per element in order.
 *  - Handles edge cases (single element, empty tree, duplicate elements).
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

#include "handler/lib/check_merkle_tree_sorted.h"

/* ---------- Callback tracking ---------- */

#define MAX_CALLBACK_CALLS 64

typedef struct {
    size_t n_calls;
    int indices[MAX_CALLBACK_CALLS];
    uint8_t elements[MAX_CALLBACK_CALLS][256];
    size_t element_lens[MAX_CALLBACK_CALLS];
} callback_tracker_t;

static void tracking_callback(dispatcher_context_t *dc,
                               void *state,
                               const merkleized_map_commitment_t *map_commitment,
                               int index,
                               buffer_t *buf) {
    (void) dc;
    (void) map_commitment;

    callback_tracker_t *tracker = (callback_tracker_t *) state;
    assert_true(tracker->n_calls < MAX_CALLBACK_CALLS);

    size_t i = tracker->n_calls++;
    tracker->indices[i] = index;
    size_t len = buf->size - buf->offset;
    assert_true(len <= 256);
    memcpy(tracker->elements[i], buf->ptr + buf->offset, len);
    tracker->element_lens[i] = len;
}

/* ---------- Test cases ---------- */

/**
 * Happy path: three elements in strict lexicographic order.
 */
static void test_sorted_three_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Elements in sorted order: "aaa" < "bbb" < "ccc" */
    const uint8_t *elems[] = {(const uint8_t *) "aaa",
                              (const uint8_t *) "bbb",
                              (const uint8_t *) "ccc"};
    size_t lens[] = {3, 3, 3};

    mock_dispatcher_add_list(mock, elems, lens, 3);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             3,
                                                             tracking_callback,
                                                             NULL);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 3);

    /* Verify callback received elements in order */
    assert_int_equal(tracker.indices[0], 0);
    assert_int_equal(tracker.indices[1], 1);
    assert_int_equal(tracker.indices[2], 2);
    assert_memory_equal(tracker.elements[0], "aaa", 3);
    assert_memory_equal(tracker.elements[1], "bbb", 3);
    assert_memory_equal(tracker.elements[2], "ccc", 3);
}

/**
 * Happy path: single element tree is always sorted.
 */
static void test_sorted_single_element(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "hello"};
    size_t lens[] = {5};

    mock_dispatcher_add_list(mock, elems, lens, 1);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             1,
                                                             tracking_callback,
                                                             NULL);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 1);
    assert_memory_equal(tracker.elements[0], "hello", 5);
}

/**
 * Happy path: NULL callback (no callback invoked, just order checking).
 */
static void test_sorted_null_callback(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "aa", (const uint8_t *) "bb"};
    size_t lens[] = {2, 2};

    mock_dispatcher_add_list(mock, elems, lens, 2);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             NULL,
                                                             root,
                                                             2,
                                                             NULL,
                                                             NULL);
    assert_int_equal(result, 0);
}

/**
 * Happy path: empty tree (size=0) should succeed immediately.
 */
static void test_sorted_empty_tree(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t root[32] = {0};

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             0,
                                                             tracking_callback,
                                                             NULL);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 0);
}

/**
 * Error: elements NOT in sorted order (descending).
 * The tree is built with the elements in descending order, so
 * call_check_merkle_tree_sorted_with_callback should detect the unsorted order.
 */
static void test_unsorted_descending(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Elements in reverse order: "ccc" > "bbb" > "aaa" */
    const uint8_t *elems[] = {(const uint8_t *) "ccc",
                              (const uint8_t *) "bbb",
                              (const uint8_t *) "aaa"};
    size_t lens[] = {3, 3, 3};

    mock_dispatcher_add_list(mock, elems, lens, 3);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             NULL,
                                                             root,
                                                             3,
                                                             NULL,
                                                             NULL);
    assert_true(result < 0);
}

/**
 * Error: duplicate elements (equal keys are not strictly sorted).
 */
static void test_unsorted_duplicates(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "aaa",
                              (const uint8_t *) "aaa",
                              (const uint8_t *) "bbb"};
    size_t lens[] = {3, 3, 3};

    mock_dispatcher_add_list(mock, elems, lens, 3);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             NULL,
                                                             root,
                                                             3,
                                                             NULL,
                                                             NULL);
    assert_true(result < 0);
}

/**
 * Happy path: elements of different lengths, sorted lexicographically.
 * "a" < "aa" < "b" in lexicographic order (shorter prefix comes first).
 */
static void test_sorted_different_lengths(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "a",
                              (const uint8_t *) "aa",
                              (const uint8_t *) "b"};
    size_t lens[] = {1, 2, 1};

    mock_dispatcher_add_list(mock, elems, lens, 3);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             3,
                                                             tracking_callback,
                                                             NULL);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 3);
    assert_int_equal(tracker.element_lens[0], 1);
    assert_int_equal(tracker.element_lens[1], 2);
    assert_int_equal(tracker.element_lens[2], 1);
}

/**
 * Error: unsorted with prefix relationship.
 * "aa" before "a" — the longer prefix comes first, violating order.
 */
static void test_unsorted_prefix(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "aa",
                              (const uint8_t *) "a"};
    size_t lens[] = {2, 1};

    mock_dispatcher_add_list(mock, elems, lens, 2);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             NULL,
                                                             root,
                                                             2,
                                                             NULL,
                                                             NULL);
    assert_true(result < 0);
}

/**
 * Happy path: many elements in sorted order.
 * Verifies correctness with a larger tree that exercises multiple levels of merkle proofs.
 */
static void test_sorted_many_elements(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Generate 10 sorted elements: "\x00", "\x01", ..., "\x09" */
    uint8_t raw[10][1];
    const uint8_t *elems[10];
    size_t lens[10];

    for (int i = 0; i < 10; i++) {
        raw[i][0] = (uint8_t) i;
        elems[i] = raw[i];
        lens[i] = 1;
    }

    mock_dispatcher_add_list(mock, elems, lens, 10);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    callback_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             10,
                                                             tracking_callback,
                                                             NULL);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 10);

    for (int i = 0; i < 10; i++) {
        assert_int_equal(tracker.indices[i], i);
        assert_int_equal(tracker.element_lens[i], 1);
        assert_int_equal(tracker.elements[i][0], (uint8_t) i);
    }
}

/**
 * Error: tree with size mismatch (wrong size passed to function).
 * call_get_merkle_leaf_element should fail because the mock tree has a
 * different number of elements.
 */
static void test_wrong_tree_size(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "a", (const uint8_t *) "b"};
    size_t lens[] = {1, 1};

    mock_dispatcher_add_list(mock, elems, lens, 2);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    /* Pass size=5 when actual tree has 2 elements */
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             NULL,
                                                             root,
                                                             5,
                                                             NULL,
                                                             NULL);
    assert_true(result < 0);
}

/**
 * Happy path: two elements, with the map_commitment parameter passed through.
 * Verifies that the callback receives the map_commitment pointer.
 */
typedef struct {
    size_t n_calls;
    const merkleized_map_commitment_t *received_commitment;
} commitment_tracker_t;

static void commitment_tracking_callback(dispatcher_context_t *dc,
                                          void *state,
                                          const merkleized_map_commitment_t *map_commitment,
                                          int index,
                                          buffer_t *buf) {
    (void) dc;
    (void) index;
    (void) buf;

    commitment_tracker_t *tracker = (commitment_tracker_t *) state;
    tracker->n_calls++;
    tracker->received_commitment = map_commitment;
}

static void test_map_commitment_passed(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t *elems[] = {(const uint8_t *) "x", (const uint8_t *) "y"};
    size_t lens[] = {1, 1};

    mock_dispatcher_add_list(mock, elems, lens, 2);
    uint8_t root[32];
    memcpy(root, mock->trees[mock->n_trees - 1].root, 32);

    merkleized_map_commitment_t dummy_commitment;
    memset(&dummy_commitment, 0xAB, sizeof(dummy_commitment));

    commitment_tracker_t tracker;
    memset(&tracker, 0, sizeof(tracker));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_check_merkle_tree_sorted_with_callback(dc,
                                                             &tracker,
                                                             root,
                                                             2,
                                                             commitment_tracking_callback,
                                                             &dummy_commitment);
    assert_int_equal(result, 0);
    assert_int_equal(tracker.n_calls, 2);
    assert_ptr_equal(tracker.received_commitment, &dummy_commitment);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_sorted_three_elements),
        T(test_sorted_single_element),
        T(test_sorted_null_callback),
        T(test_sorted_empty_tree),
        T(test_unsorted_descending),
        T(test_unsorted_duplicates),
        T(test_sorted_different_lengths),
        T(test_unsorted_prefix),
        T(test_sorted_many_elements),
        T(test_wrong_tree_size),
        T(test_map_commitment_passed),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
