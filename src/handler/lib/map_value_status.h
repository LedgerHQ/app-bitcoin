#pragma once

/**
 * Outcome of reading a value by key out of a merkleized map.
 *
 * The by-key readers (call_get_merkleized_map_value, call_get_merkleized_map_value_hash,
 * call_stream_merkleized_map_value) all share this contract:
 *
 * - a non-negative return means success; where the operation has a natural length (the number of
 *   bytes read) it is returned, otherwise 0;
 * - MAP_VALUE_ABSENT means that the client responded that the key is not in the map;
 * - MAP_VALUE_ERROR means the read failed and no conclusion may be drawn about the key.
 *
 * Callers that apply a default value for an optional field MUST branch on MAP_VALUE_ABSENT
 * specifically, and never on `res < 0`: doing the latter would apply the default on failures,
 * swallowing an error condition.
 *
 * SECURITY — MAP_VALUE_ABSENT is a CLIENT ASSERTION, NOT A PROOF.
 * It reflects the client answering `found = 0` to CCMD_GET_MERKLE_LEAF_INDEX. The device requests
 * no proof of absence, so it cannot distinguish an honest omission from a key the client chose to
 * suppress. Do not treat it as evidence that the committed map lacks the key.
 * Where soundness is required, derive presence from the key enumeration performed while validating
 * the map (see input_keys_callback in sign_psbt/preprocess_inputs.c): those flags are computed by
 * walking the keys tree against the committed `keys_root`, so the client cannot lie about them.
 */
typedef enum {
    MAP_VALUE_ABSENT = -1,  // the key is not in the map (client assertion - see above)
    MAP_VALUE_ERROR = -2,   // proof failure, protocol violation, oversized value, transport error
} map_value_status_t;
