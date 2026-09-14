#include <string.h>

#include "get_merkleized_map.h"

/* SDK headers */
#include "buffer.h"

/* Local headers */
#include "check_merkle_tree_sorted.h"
#include "get_merkle_leaf_element.h"

int call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                          void *callback_state,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          merkle_tree_elements_callback_t callback,
                                          merkleized_map_commitment_t *out_ptr) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t raw_output[9 + 2 * 32];  // maximum size of serialized result (9 bytes for the varint,
                                     // and the 2 Merkle roots)

    // The map is not yet validated; explicitly mark it as such
    out_ptr->_keys_are_sorted = false;

    int el_len = call_get_merkle_leaf_element(dispatcher_context,
                                              root,
                                              size,
                                              index,
                                              raw_output,
                                              sizeof(raw_output));
    if (el_len < 0) {
        return -1;
    }

    buffer_t buf = buffer_create(raw_output, el_len);
    if (!buffer_read_varint(&buf, &out_ptr->size) ||
        !buffer_read_bytes(&buf, out_ptr->keys_root, 32) ||
        !buffer_read_bytes(&buf, out_ptr->values_root, 32)) {
        return -1;
    }

    int ret = call_check_merkle_tree_sorted_with_callback(dispatcher_context,
                                                          callback_state,
                                                          out_ptr->keys_root,
                                                          out_ptr->size,
                                                          callback,
                                                          out_ptr);
    if (ret >= 0) {
        // keys were verified to be lexicographically sorted: the map is now safe for by-key reads
        out_ptr->_keys_are_sorted = true;
    }
    return ret;
}
