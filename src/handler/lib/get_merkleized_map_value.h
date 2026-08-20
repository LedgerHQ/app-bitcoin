#pragma once

/* Local headers */
#include "dispatcher.h"
#include "map_value_status.h"
#include "merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element
 * corresponding to the key, then fetches the corresponding element and verifies that its hash and
 * Merkle proof matches. The value is then stored in the `out` pointer, which must be large enough
 * to contain the preimage.
 *
 * Returns the length of the preimage on success, MAP_VALUE_ABSENT if the key is not in the map, or
 * MAP_VALUE_ERROR if any of the proofs failed, the response was malformed, or the value is too
 * long to fit into the output buffer. See map_value_status.h; in particular, callers must branch
 * on MAP_VALUE_ABSENT explicitly rather than on `res < 0` when a missing key is not an error.
 *
 * On any non-success return - MAP_VALUE_ABSENT included - `out` is fully zeroed; see
 * call_get_preimage.
 *
 * PRECONDITION: the map's keys must have already been verified to be lexicographically sorted (and
 * therefore unique); this is what makes a by-key lookup unambiguous. A map is validated either by
 * `call_get_merkleized_map[_with_callback]` (which validates before returning) or by
 * `call_check_merkleized_map_sorted`. This function asserts that precondition (LEDGER_ASSERT on
 * `map->_keys_are_sorted`); it does NOT re-check the ordering itself.
 *
 * NOTE for callbacks fired during validation (via call_get_merkleized_map_with_callback): at that
 * point the map is not yet validated, so values must be read by index (on `values_root`) and never
 * by key through this function or its siblings.
 */
int call_get_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                  const merkleized_map_commitment_t *map,
                                  const uint8_t *key,
                                  size_t key_len,
                                  uint8_t *out,
                                  size_t out_len);
