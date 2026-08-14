#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * The client asserts that no leaf with the given hash is in the tree.
 *
 * NOTE: this is not verified. The device requests no proof of absence, so this reports what the
 * client claims, not what the committed tree contains. See map_value_status.h for the implications.
 */
#define MERKLE_LEAF_NOT_FOUND (-1)

/**
 * The lookup failed: malformed client response, Merkle proof mismatch, or transport error.
 * Nothing may be concluded about whether the leaf is in the tree.
 */
#define MERKLE_LEAF_ERROR (-2)

/**
 * Retrieves the index of the leaf whose hash is `leaf_hash` in the Merkle tree identified by
 * `root` and `size`.
 *
 * Returns the leaf index on success, MERKLE_LEAF_NOT_FOUND if the client reports the leaf is not
 * in the tree, or MERKLE_LEAF_ERROR on failure. When the client reports the leaf as found, this
 * function validates the returned index by retrieving the leaf hash at that index and checking
 * that it matches `leaf_hash`.
 */
int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 32],
                               const uint8_t leaf_hash[static 32]);
