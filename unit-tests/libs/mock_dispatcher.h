#pragma once

/**
 * Mock dispatcher_context_t for unit testing.
 *
 * This module implements a C equivalent of the Python ClientCommandInterpreter,
 * handling the following client commands entirely in-process:
 *   - CCMD_GET_PREIMAGE      (0x40)
 *   - CCMD_GET_MERKLE_LEAF_PROOF (0x41)
 *   - CCMD_GET_MERKLE_LEAF_INDEX (0x42)
 *   - CCMD_GET_MORE_ELEMENTS (0xA0)
 *   - CCMD_YIELD             (0x10)
 *
 * Usage:
 *   mock_dispatcher_t mock;
 *   mock_dispatcher_init(&mock);
 *   mock_dispatcher_add_preimage(&mock, data, len);
 *   dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
 *   int result = call_get_preimage(dc, hash, out, out_len);
 */

#include <stdint.h>
#include <stddef.h>

#include "dispatcher.h"

/* ---- Configuration ---- */
#define MOCK_MAX_PREIMAGES   1024
#define MOCK_MAX_TREES       16
#define MOCK_MAX_TREE_ELEMS  1024
#define MOCK_MAX_YIELDED     1024
#define MOCK_MAX_QUEUE_ELEMS 1024
#define MOCK_BUF_SIZE        2048
#define MOCK_MAX_YIELDED_LEN 1024

/* ---- Merkle tree storage ---- */
typedef struct {
    uint8_t root[32];

    /* element_hashes[i] = SHA256(0x00 || raw_elements[i]) */
    uint8_t element_hashes[MOCK_MAX_TREE_ELEMS][32];

    /* raw element bytes (without 0x00 prefix) */
    uint8_t raw_elements[MOCK_MAX_TREE_ELEMS][256];
    size_t raw_element_lens[MOCK_MAX_TREE_ELEMS];

    size_t n_elements;

    /* all_hashes: full binary tree node hashes for proof generation.
     * Indexed like a segment tree: node 1 = root, node 2i = left child, 2i+1 = right.
     * We store up to 2 * MOCK_MAX_TREE_ELEMS nodes. */
    uint8_t node_hashes[2 * MOCK_MAX_TREE_ELEMS][32];
} mock_merkle_tree_t;

/* ---- Queue for GET_MORE_ELEMENTS ---- */
typedef struct {
    uint8_t data[MOCK_MAX_QUEUE_ELEMS][32]; /* elements (up to 32 bytes each) */
    size_t element_size;                    /* size of each element */
    size_t count;                           /* total enqueued */
    size_t head;                            /* next to dequeue */
} mock_queue_t;

/* ---- Main mock state ---- */
typedef struct {
    dispatcher_context_t dc; /* MUST be first member (container_of pattern) */

    /* Request accumulation (from add_to_response calls) */
    uint8_t request_buf[MOCK_BUF_SIZE];
    size_t request_len;
    uint16_t last_sw;

    /* Client response buffer (backing for dc.read_buffer) */
    uint8_t response_buf[MOCK_BUF_SIZE];
    size_t response_len;

    /* Known preimages: sha256(data) -> data */
    struct {
        uint8_t hash[32];
        uint8_t data[MOCK_BUF_SIZE];
        size_t len;
    } preimages[MOCK_MAX_PREIMAGES];
    size_t n_preimages;

    /* Known Merkle trees */
    mock_merkle_tree_t trees[MOCK_MAX_TREES];
    size_t n_trees;

    /* GET_MORE_ELEMENTS queue */
    mock_queue_t queue;

    /* Yielded values */
    struct {
        uint8_t data[MOCK_MAX_YIELDED_LEN];
        size_t len;
    } yielded[MOCK_MAX_YIELDED];
    size_t n_yielded;
} mock_dispatcher_t;

/* ---- Public API ---- */

/**
 * Initialize a mock dispatcher. Zero-initializes all state and wires up
 * the function pointers in mock->dc.
 */
void mock_dispatcher_init(mock_dispatcher_t *mock);

/**
 * Register a known preimage. Computes sha256(data) and stores the mapping.
 * The mock will respond to CCMD_GET_PREIMAGE requests matching this hash.
 */
void mock_dispatcher_add_preimage(mock_dispatcher_t *mock, const uint8_t *data, size_t len);

/**
 * Build a Merkle tree from a list of elements and register it.
 * Also registers each leaf preimage (0x00 || element) as a known preimage.
 *
 * @param elements     Array of pointers to element data.
 * @param element_lens Array of element lengths.
 * @param n            Number of elements.
 */
void mock_dispatcher_add_list(mock_dispatcher_t *mock,
                              const uint8_t *const *elements,
                              const size_t *element_lens,
                              size_t n);

/**
 * Get the dispatcher_context_t pointer for use with app functions.
 */
static inline dispatcher_context_t *mock_dispatcher_get_dc(mock_dispatcher_t *mock) {
    return &mock->dc;
}

/**
 * Reset the hash context pool (call between independent tests to avoid
 * exhausting the fixed-size pool in cx_hash_mock).
 */
void mock_dispatcher_reset_hash_pool(void);
