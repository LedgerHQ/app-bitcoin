#pragma once

/* Local headers */
#include "dispatcher.h"
#include "merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element
 * corresponding to the key, then fetches the hash of the corresponding value stores it in the `out`
 * pointer. As the value is a Merkle tree preimage, it is always the hash of a string starting with
 * a 0x00 byte.
 *
 * Returns a negative number if the key is not found, or any of the proofs failed. Returns 0 on
 * success.
 *
 * PRECONDITION: the map's keys must have already been verified to be lexicographically sorted;
 * this function asserts it (LEDGER_ASSERT on `map->_keys_are_sorted`).
 */
int call_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context,
                                       const merkleized_map_commitment_t *map,
                                       const uint8_t *key,
                                       size_t key_len,
                                       uint8_t out[static 32]);