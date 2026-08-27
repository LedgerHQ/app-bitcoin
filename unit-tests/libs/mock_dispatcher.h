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
 * Usage (manual):
 *   mock_dispatcher_t mock;
 *   mock_dispatcher_init(&mock);
 *   mock_dispatcher_add_preimage(&mock, data, len);
 *   dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
 *   int result = call_get_preimage(dc, hash, out, out_len);
 *
 * Usage (cmocka fixture):
 *   static void test_something(void **state) {
 *       mock_dispatcher_t *mock = *state;
 *       ...
 *   }
 *   ...
 *   cmocka_unit_test_setup_teardown(test_something,
 *                                   mock_dispatcher_setup,
 *                                   mock_dispatcher_teardown);
 */

#include <stdint.h>
#include <stddef.h>

#include "dispatcher.h"
#include "common/merkle.h"
#include "psbt_parse.h"

/* ---- Configuration ---- */
#define MOCK_MAX_PREIMAGES   1024
/* A PSBT scenario spends 1 (key-info) + 2 (global) + 1 (inputs list) + 2 per input
 * map + 1 (outputs list) + 2 per output map, i.e. 5 + 2*(n_in + n_out). At 16 that
 * caps n_in + n_out at 5 against declared maxima of 8 and 8, so 54 of 64 uniform
 * (n_in, n_out) pairs made the builder refuse and the iteration dispatch nothing --
 * 84.4% of SIGN_PSBT inputs. 40 lifts the cap to 17. */
#define MOCK_MAX_TREES       40
#define MOCK_MAX_TREE_ELEMS  1024
#define MOCK_MAX_YIELDED     1024
#define MOCK_MAX_QUEUE_ELEMS 2048
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

/**
 * Tamper hook signature.
 * Called after a response is built but before it's delivered to the caller.
 * Can modify response_buf/response_len to simulate malicious client behavior.
 * Return 0 to deliver the (possibly modified) response normally.
 * Return -1 to simulate a communication failure (process_interruption returns -1).
 *
 * @param response_buf   The response buffer (writable).
 * @param response_len   Pointer to the response length (readable/writable).
 * @param cmd            The client command that produced this response.
 * @param call_count     How many times this hook has been called (0-indexed).
 * @param user_data      Opaque pointer set by the test.
 */
typedef int (*mock_tamper_hook_t)(uint8_t *response_buf,
                                  size_t *response_len,
                                  uint8_t cmd,
                                  int call_count,
                                  void *user_data);

/**
 * Forge hook signature.
 * Called with the accumulated request *before* it reaches its handler, so a test can answer a
 * request that an honest client would refuse (an out-of-range leaf index, say). The tamper hook
 * cannot: it only ever sees a response that a handler already agreed to produce.
 *
 * Write the reply into response_buf/response_len and return 1 to deliver it; return 0 to leave the
 * request to the honest handler; return -1 to simulate a communication failure.
 *
 * @param request_buf    The request bytes, starting with the command byte.
 * @param request_len    Length of the request.
 * @param response_buf   The response buffer (writable, MOCK_BUF_SIZE bytes).
 * @param response_len   Out param for the response length; zeroed before the call.
 * @param user_data      Opaque pointer set by the test.
 */
typedef int (*mock_forge_hook_t)(const uint8_t *request_buf,
                                 size_t request_len,
                                 uint8_t *response_buf,
                                 size_t *response_len,
                                 void *user_data);

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

    /* Tamper hook (NULL = no tampering, behave honestly) */
    mock_tamper_hook_t tamper_hook;
    void *tamper_user_data;
    int tamper_call_count;

    /* Forge hook (NULL = every request goes to its honest handler) */
    mock_forge_hook_t forge_hook;
    void *forge_user_data;
} mock_dispatcher_t;

/* ---- Public API ---- */

/**
 * Initialize a mock dispatcher. Zero-initializes all state and wires up
 * the function pointers in mock->dc.
 */
void mock_dispatcher_init(mock_dispatcher_t *mock);

/**
 * Clear per-scenario state without re-zeroing the whole struct.
 *
 * mock_dispatcher_init() memsets several megabytes (the preimage store and the
 * Merkle trees dominate), which is fine once per test but not once per fuzzing
 * iteration. Only the counters gate what is readable, so resetting them is
 * enough; the dc callbacks and any tamper hook are left in place.
 */
void mock_dispatcher_reset(mock_dispatcher_t *mock);

/**
 * Answer one client command without going through dispatcher_context_t.
 *
 * Same handlers, same tamper hook as mock_process_interruption(); this entry
 * point exists for callers that already own the transport (a fuzzing harness
 * intercepting os_io_rx_evt(), for instance) and just need request bytes turned
 * into response bytes.
 *
 * @return 0 on success, -1 on a malformed request, an unknown command, an
 *         oversized response, or a tamper hook simulating a comms failure.
 */
int mock_dispatcher_handle_ccmd(mock_dispatcher_t *mock,
                                const uint8_t *request,
                                size_t request_len,
                                uint8_t *response,
                                size_t response_cap,
                                size_t *response_len);

/**
 * @name Incremental Merkle tree construction
 *
 * mock_dispatcher_add_list() needs every element up front. These build a tree
 * leaf by leaf, which is what a caller assembling elements in a loop wants.
 * Each leaf is registered as a preimage exactly as add_list() does.
 * @{
 */
/** @return tree index, or -1 if no tree slot is free. */
int mock_dispatcher_tree_begin(mock_dispatcher_t *mock);
/** @return 0, or -1 if the tree is full or the element too large. */
int mock_dispatcher_tree_add_leaf(mock_dispatcher_t *mock, int tree,
                                  const uint8_t *data, size_t len);
/** Add a leaf by its hash, for elements whose preimage is registered elsewhere. */
int mock_dispatcher_tree_add_leaf_hash(mock_dispatcher_t *mock, int tree,
                                       const uint8_t hash[32]);
/** Compute the root; @p out_root may be NULL. */
void mock_dispatcher_tree_end(mock_dispatcher_t *mock, int tree, uint8_t out_root[32]);
/** @} */

/**
 * cmocka setup fixture: allocates a mock_dispatcher_t on the heap, initializes
 * it, and stores the pointer in *state.
 */
int mock_dispatcher_setup(void **state);

/**
 * cmocka teardown fixture: frees the mock_dispatcher_t allocated by
 * mock_dispatcher_setup.
 */
int mock_dispatcher_teardown(void **state);

/**
 * Register a known preimage. Computes sha256(data) and stores the mapping.
 * The mock will respond to CCMD_GET_PREIMAGE requests matching this hash.
 */
int mock_dispatcher_add_preimage(mock_dispatcher_t *mock, const uint8_t *data, size_t len);

/**
 * Set a tamper hook to simulate malicious client behavior.
 * The hook is called after each response is built, before delivery.
 * Pass NULL to disable tampering.
 */
static inline void mock_dispatcher_set_tamper_hook(mock_dispatcher_t *mock,
                                                   mock_tamper_hook_t hook,
                                                   void *user_data) {
    mock->tamper_hook = hook;
    mock->tamper_user_data = user_data;
    mock->tamper_call_count = 0;
}

/**
 * Set a forge hook, to answer requests that no honest handler would.
 * The hook is called with each request before it is dispatched.
 * Pass NULL to disable forging.
 */
static inline void mock_dispatcher_set_forge_hook(mock_dispatcher_t *mock,
                                                  mock_forge_hook_t hook,
                                                  void *user_data) {
    mock->forge_hook = hook;
    mock->forge_user_data = user_data;
}

/**
 * Build a Merkle tree from a list of elements and register it.
 * Also registers each leaf preimage (0x00 || element) as a known preimage.
 *
 * @param elements     Array of pointers to element data.
 * @param element_lens Array of element lengths.
 * @param n            Number of elements.
 * @return 0, or -1 if a capacity or per-element limit would be exceeded. Nothing is
 *         registered on failure, so a tree's root always matches the leaves it serves.
 */
int mock_dispatcher_add_list(mock_dispatcher_t *mock,
                             const uint8_t *const *elements,
                             const size_t *element_lens,
                             size_t n);

/**
 * Register a key-value mapping (like a PSBT map) and its Merkle trees.
 * Sorts items by key, builds separate Merkle trees for keys and values,
 * registers preimages for all leaves, and fills in the commitment struct.
 *
 * This mirrors the Python ClientCommandInterpreter.add_known_mapping().
 *
 * @param keys          Array of pointers to key data.
 * @param key_lens      Array of key lengths.
 * @param values        Array of pointers to value data.
 * @param value_lens    Array of value lengths.
 * @param n             Number of key-value pairs.
 * @param out_commitment  Filled with the merkleized map commitment (size, keys_root, values_root).
 */
int mock_dispatcher_add_map(mock_dispatcher_t *mock,
                             const uint8_t *const *keys,
                             const size_t *key_lens,
                             const uint8_t *const *values,
                             const size_t *value_lens,
                             size_t n,
                             merkleized_map_commitment_t *out_commitment);

/** Result of mock_dispatcher_add_psbt. */
typedef struct {
    merkleized_map_commitment_t global_map;
    merkleized_map_commitment_t input_maps[PSBT_MAX_MAPS];
    size_t n_inputs;
    merkleized_map_commitment_t output_maps[PSBT_MAX_MAPS];
    size_t n_outputs;
} mock_psbt_t;

/**
 * Parse a PSBTv2 binary and register all its maps with the mock dispatcher.
 *
 * This mirrors the registration flow in the Python sign_psbt() method:
 *  1. Parses the PSBT into global/input/output maps.
 *  2. Registers each map (keys + values trees) with mock_dispatcher_add_map.
 *  3. Computes the merkleized map commitment for each input/output map.
 *  4. Registers the list of input commitments and output commitments.
 *
 * @param mock       The mock dispatcher state.
 * @param psbt       Raw PSBTv2 bytes (starting with "psbt\xff").
 * @param psbt_len   Length of the PSBT data.
 * @param n_inputs   Number of input maps in the PSBT.
 * @param n_outputs  Number of output maps in the PSBT.
 * @param out        Filled with parsed map commitments on success.
 * @return 0 on success, negative on error.
 */
int mock_dispatcher_add_psbt(mock_dispatcher_t *mock,
                             const uint8_t *psbt,
                             size_t psbt_len,
                             size_t n_inputs,
                             size_t n_outputs,
                             mock_psbt_t *out);

/**
 * Get the dispatcher_context_t pointer for use with app functions.
 */
static inline dispatcher_context_t *mock_dispatcher_get_dc(mock_dispatcher_t *mock) {
    return &mock->dc;
}

