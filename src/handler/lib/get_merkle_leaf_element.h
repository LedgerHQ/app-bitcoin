#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * Retrieves the preimage of the leaf at `leaf_index` in the Merkle tree identified by
 * `merkle_root` and `tree_size`, and stores it in `out_ptr`.
 *
 * Returns the length of the preimage on success, or a negative number on failure; `out_ptr` is
 * then fully zeroed (see call_get_preimage).
 */
int call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                 const uint8_t merkle_root[static 32],
                                 uint32_t tree_size,
                                 uint32_t leaf_index,
                                 uint8_t *out_ptr,
                                 size_t out_ptr_len);
