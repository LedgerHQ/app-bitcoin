#pragma once

/* Local headers */
#include "dispatcher.h"
#include "merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow find out the index of the
 * corresponding element, then it fetches it and it streams it back via the callback. If
 * len_callback is not NONE, it is called before the other callback with the length of the element.
 *
 * Returns a negative number on failure, or the preimage length on success.
 *
 * PRECONDITION: the map's keys must have already been verified to be lexicographically sorted;
 * this function asserts it (LEDGER_ASSERT on `map->_keys_are_sorted`).
 */
int call_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                     const merkleized_map_commitment_t *map,
                                     const uint8_t *key,
                                     size_t key_len,
                                     void (*len_callback)(size_t, void *),
                                     void (*callback)(buffer_t *, void *),
                                     void *callback_state);