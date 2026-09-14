#pragma once

/* Local headers */
#include "dispatcher.h"
#include "map_value_status.h"
#include "merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element
 * corresponding to the key, then fetches the hash of the corresponding value stores it in the `out`
 * pointer. As the value is a Merkle tree preimage, it is always the hash of a string starting with
 * a 0x00 byte.
 *
 * Returns 0 on success, MAP_VALUE_ABSENT if the key is not in the map, or MAP_VALUE_ERROR if any
 * of the proofs failed. See map_value_status.h; in particular, callers must branch on
 * MAP_VALUE_ABSENT explicitly rather than on `res < 0` when a missing key is not an error.
 *
 * On any non-success return - MAP_VALUE_ABSENT included - `out` is fully zeroed; see
 * call_get_preimage.
 *
 * PRECONDITION: the map's keys must have already been verified to be lexicographically sorted;
 * this function asserts it (LEDGER_ASSERT on `map->_keys_are_sorted`).
 */
int call_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context,
                                       const merkleized_map_commitment_t *map,
                                       const uint8_t *key,
                                       size_t key_len,
                                       uint8_t out[static 32]);