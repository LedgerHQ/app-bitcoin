#include "stream_merkleized_map_value.h"

/* SDK headers */
#include "ledger_assert.h"

/* Local headers */
#include "get_merkle_leaf_index.h"
#include "stream_merkle_leaf_element.h"

int call_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                     const merkleized_map_commitment_t *map,
                                     const uint8_t *key,
                                     size_t key_len,
                                     void (*len_callback)(size_t, void *),
                                     void (*callback)(buffer_t *, void *),
                                     void *callback_state) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Reading a value by key is only sound once the map's keys have been verified sorted (hence
    // unique); otherwise a malicious client could equivocate. This must hold by construction.
    LEDGER_ASSERT(map->_keys_are_sorted, "map keys not validated as sorted");

    uint8_t key_merkle_hash[32];
    merkle_compute_element_hash(key, key_len, key_merkle_hash);

    int index =
        call_get_merkle_leaf_index(dispatcher_context, map->size, map->keys_root, key_merkle_hash);

    if (index < 0) {
        PRINTF("Key not found, or incorrect data.\n");
        return -1;
    }

    return call_stream_merkle_leaf_element(dispatcher_context,
                                           map->values_root,
                                           map->size,
                                           index,
                                           len_callback,
                                           callback,
                                           callback_state);
}
