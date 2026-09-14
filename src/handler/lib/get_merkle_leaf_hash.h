#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * Retrieves the hash of the leaf at `leaf_index` in the Merkle tree identified by `merkle_root`
 * and `tree_size`, and verifies the proof returned by the host against `merkle_root`.
 *
 * On success, writes the 32-byte leaf hash to `out` and returns 0. Returns a negative value on
 * failure; `out` is then fully zeroed, as the leaf hash is copied out before the proof is
 * verified (see call_get_preimage).
 */
int call_get_merkle_leaf_hash(dispatcher_context_t *dispatcher_context,
                              const uint8_t merkle_root[static 32],
                              uint32_t tree_size,
                              uint32_t leaf_index,
                              uint8_t out[static 32]);
