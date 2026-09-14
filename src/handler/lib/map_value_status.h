#pragma once

/**
 * Outcome of the by-key merkleized map readers (call_get_merkleized_map_value[_hash],
 * call_stream_merkleized_map_value): non-negative is success (byte count, or 0 if not meaningful),
 * negative is one of the statuses below.
 *
 * Callers applying a default for an optional field MUST branch on MAP_VALUE_ABSENT, never on
 * `res < 0`, which would silently apply the default on errors too.
 *
 * SECURITY: MAP_VALUE_ABSENT is only the client asserting `found = 0`; absence is never proved, so
 * a malicious client can suppress any key. Where soundness matters, use the presence flags computed
 * while validating the map against the committed `keys_root` (see input_keys_callback in
 * sign_psbt/preprocess_inputs.c).
 */
typedef enum {
    MAP_VALUE_ABSENT = -1,  // the key is not in the map (client assertion - see above)
    MAP_VALUE_ERROR = -2,   // proof failure, protocol violation, oversized value, transport error
} map_value_status_t;
