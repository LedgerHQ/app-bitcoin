#pragma once

/* Local headers */
#include "dispatcher.h"
#include "merkle.h"
#include "wallet.h"

// this flow aborts if any element is larger than this size
// TODO: we might remove this limitation altogether with a more careful implementation.
// Here we make sure that we have enough space for control block of a taptree of the maximum
// supported depth
#define MAX_CHECK_MERKLE_TREE_SORTED_PREIMAGE_SIZE (34 + 32 * (MAX_TAPTREE_POLICY_DEPTH - 1))

typedef void (*merkle_tree_elements_callback_t)(struct dispatcher_context_s *,
                                                void *,
                                                const merkleized_map_commitment_t *,
                                                int,
                                                buffer_t *);

/**
 * Given a Merkle tree root and the size of the tree, it requests all the elements to the client
 * (verifying Merkle proofs) and verifies that the leaf preimages are in lexicographical order. If a
 * callback to a non-NULL function is given, it is called once for each of the elements of the
 * Merkle tree, in lexicographical order.
 *
 * Returns 0 on success, or a negative number on failure.
 */
int call_check_merkle_tree_sorted_with_callback(dispatcher_context_t *dispatcher_context,
                                                void *callback_state,
                                                const uint8_t root[static 32],
                                                size_t size,
                                                merkle_tree_elements_callback_t callback,
                                                const merkleized_map_commitment_t *map_commitment);

/**
 * Convenience function to call the get_merkle_tree_sorted flow, with a void callback.
 */
static inline int call_check_merkle_tree_sorted(dispatcher_context_t *dispatcher_context,
                                                const uint8_t root[static 32],
                                                size_t size) {
    return call_check_merkle_tree_sorted_with_callback(dispatcher_context,
                                                       NULL,
                                                       root,
                                                       size,
                                                       NULL,
                                                       NULL);
}

/**
 * Validates a merkleized map commitment whose fields were populated directly (rather than obtained
 * from call_get_merkleized_map): checks that its keys tree is lexicographically sorted, and on
 * success marks the commitment as validated so that its values can be read by key.
 *
 * This is the counterpart of call_get_merkleized_map for maps that are not fetched from an outer
 * Merkle tree of maps (e.g. the PSBT global map, whose commitment comes straight from the APDU).
 *
 * Returns 0 on success, or a negative number on failure.
 */
static inline int call_check_merkleized_map_sorted(dispatcher_context_t *dispatcher_context,
                                                   merkleized_map_commitment_t *map) {
    int ret = call_check_merkle_tree_sorted(dispatcher_context, map->keys_root, (size_t) map->size);
    if (ret >= 0) {
        map->_keys_are_sorted = true;
    }
    return ret;
}
