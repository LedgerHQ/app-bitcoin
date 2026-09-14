#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * Given a sha256 hash, requests the corresponding pre-image to the host.
 *
 * Returns a negative number on error, or the preimage length on success. This function validates
 * that the SHA256 of the data provided by the host does indeed match the expected hash.
 *
 * On any negative return `out` is fully zeroed: the preimage is streamed in before its hash can be
 * verified, so a rejected read must not leave host-chosen bytes behind. This does not make the
 * contents meaningful - the status must still be checked.
 */
int call_get_preimage(dispatcher_context_t *dispatcher_context,
                      const uint8_t hash[static 32],
                      uint8_t *out,
                      size_t out_len);
