#include <string.h>

#include "get_merkleized_map_value_hash.h"

/* SDK headers */
#include "ledger_assert.h"

/* Local headers */
#include "get_merkle_leaf_hash.h"
#include "get_merkle_leaf_index.h"

int call_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context,
                                       const merkleized_map_commitment_t *map,
                                       const uint8_t *key,
                                       size_t key_len,
                                       uint8_t out[static 32]) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Reading a value by key is only sound once the map's keys have been verified sorted (hence
    // unique); otherwise a malicious client could equivocate. This must hold by construction.
    LEDGER_ASSERT(map->_keys_are_sorted, "map keys not validated as sorted");

    uint8_t key_merkle_hash[32];
    merkle_compute_element_hash(key, key_len, key_merkle_hash);

    int index =
        call_get_merkle_leaf_index(dispatcher_context, map->size, map->keys_root, key_merkle_hash);
    if (index == MERKLE_LEAF_NOT_FOUND) {
        return MAP_VALUE_ABSENT;
    }
    if (index < 0) {
        PRINTF("Failed to look up the key.\n");
        return MAP_VALUE_ERROR;
    }

    int res =
        call_get_merkle_leaf_hash(dispatcher_context, map->values_root, map->size, index, out);
    // Normalize: the failure codes of the underlying flows overlap with MAP_VALUE_ABSENT, and
    // leaking them would make a transport error look like a missing key.
    return res < 0 ? MAP_VALUE_ERROR : res;
}
