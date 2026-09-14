#include <string.h>
#include <limits.h>

#include "get_merkle_leaf_index.h"

/* Local headers */
#include "client_commands.h"
#include "get_merkle_leaf_hash.h"
#include "sw.h"

int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 32],
                               const uint8_t leaf_hash[static 32]) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    {  // free memory as soon as possible
        uint8_t request[1 + 32 + 32];
        request[0] = CCMD_GET_MERKLE_LEAF_INDEX;
        memcpy(request + 1, root, 32);
        memcpy(request + 1 + 32, leaf_hash, 32);

        SET_RESPONSE(dispatcher_context, request, sizeof(request), SW_INTERRUPTED_EXECUTION);
    }
    if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
        PRINTF("Interrupted execution failed.\n");
        return MERKLE_LEAF_ERROR;
    }

    uint8_t found;
    uint64_t index;

    if (!buffer_read_u8(&dispatcher_context->read_buffer, &found) ||
        !buffer_read_varint(&dispatcher_context->read_buffer, &index) || index > INT_MAX ||
        index >= (uint64_t) size) {
        PRINTF("Malformed response, or index out of range.\n");
        return MERKLE_LEAF_ERROR;
    }

    if (found != 0 && found != 1) {
        PRINTF("Invalid value for the 'found' flag.\n");
        return MERKLE_LEAF_ERROR;
    }

    if (!found) {
        // The client claims the leaf is not in the tree; this is not verified.
        return MERKLE_LEAF_NOT_FOUND;
    }

    // Ask the host for the leaf hash with that index
    uint8_t returned_merkle_leaf_hash[32];
    int res =
        call_get_merkle_leaf_hash(dispatcher_context, root, size, index, returned_merkle_leaf_hash);
    if (res < 0) {
        PRINTF("Failed to retrieve the leaf hash at the returned index.\n");
        return MERKLE_LEAF_ERROR;
    }

    if (memcmp(leaf_hash, returned_merkle_leaf_hash, 32) != 0) {
        PRINTF("Leaf hash at the returned index does not match.\n");
        return MERKLE_LEAF_ERROR;
    }

    return index;
}
