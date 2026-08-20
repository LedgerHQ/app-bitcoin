#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * Like call_get_preimage, but strips the leading 0x00 Merkle leaf prefix from the output.
 * The hash is still verified over the full preimage (including the prefix byte).
 *
 * In this flow, the HWW sends a CCMD_GET_PREIMAGE command with a SHA256 hash.
 * The client must respond with the preimage, prefixed by its length.
 * The flow fails with SW_WRONG_DATA_LENGTH if the response is too short; it will fail with
 * SW_INCORRECT_DATA if the computed hash does not match.
 *
 * Returns the length of the preimage without the prefix on success, or a negative number in case
 * of failure.
 *
 * On any negative return `out_ptr` is fully zeroed; see call_get_preimage.
 */
int call_get_merkle_preimage(dispatcher_context_t *dispatcher_context,
                             const uint8_t hash[static 32],
                             uint8_t *out_ptr,
                             size_t out_ptr_len);
