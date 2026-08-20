#include <string.h>

#include "get_merkle_leaf_element.h"

/* Local headers */
#include "get_merkle_leaf_hash.h"
#include "get_merkle_preimage.h"

int call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                 const uint8_t merkle_root[static 32],
                                 uint32_t tree_size,
                                 uint32_t leaf_index,
                                 uint8_t *out_ptr,
                                 size_t out_ptr_len) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t leaf_hash[32];

    int res = call_get_merkle_leaf_hash(dispatcher_context,
                                        merkle_root,
                                        tree_size,
                                        leaf_index,
                                        leaf_hash);
    if (res < 0) {
        // Nothing was written to `out_ptr` here, but clear it anyway to keep the postcondition
        // uniform; call_get_merkle_preimage covers the other failures.
        explicit_bzero(out_ptr, out_ptr_len);
        return res;
    }
    return call_get_merkle_preimage(dispatcher_context, leaf_hash, out_ptr, out_ptr_len);
}
