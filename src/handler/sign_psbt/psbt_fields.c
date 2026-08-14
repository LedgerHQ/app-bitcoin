/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <string.h>

#include "psbt_fields.h"

/* SDK headers */
#include "read.h"

/* Local headers */
#include "constants.h"
#include "get_merkleized_map_value.h"
#include "psbt.h"

/* -------------------------------------------------------------------------- */
/* Reading helpers                                                            */
/* -------------------------------------------------------------------------- */

/*
 * Every PSBT key handled here is a single key-type byte, and every field has a length policy (an
 * exact size, or a maximum). These helpers apply that policy on top of the raw map reader and
 * translate its outcome into a psbt_field_status_t, so the accessors below only have to name the
 * key type and the expected shape.
 *
 * The length policy is a PSBT-level concern, which is why these live here rather than alongside
 * call_get_merkleized_map_value: the map layer has no opinion on how long a value ought to be.
 */

/**
 * Reads a value of variable length (up to `out_cap` bytes) into `out`, writing its length to
 * `*out_len`. A value longer than `out_cap` is reported as PSBT_FIELD_ERROR.
 *
 * On any non-PRESENT outcome `out` is left zeroed and `*out_len` is 0.
 */
static psbt_field_status_t read_var(dispatcher_context_t *dc,
                                    const merkleized_map_commitment_t *map,
                                    uint8_t key_type,
                                    uint8_t *out,
                                    size_t out_cap,
                                    size_t *out_len) {
    int res = call_get_merkleized_map_value(dc, map, &key_type, 1, out, out_cap);
    if (res < 0) {
        // on absent or error, zero out the output buffer and length,
        // preventing the caller from possibly using uninitialized data
        explicit_bzero(out, out_cap);
        *out_len = 0;
        return res == MAP_VALUE_ABSENT ? PSBT_FIELD_ABSENT : PSBT_FIELD_ERROR;
    }
    *out_len = (size_t) res;
    return PSBT_FIELD_PRESENT;
}

/**
 * Reads a value that must be exactly `len` bytes into `out`. A present value of any other length
 * is malformed, hence PSBT_FIELD_ERROR.
 *
 * On any non-PRESENT outcome `out` is left zeroed.
 */
static psbt_field_status_t read_fixed(dispatcher_context_t *dc,
                                      const merkleized_map_commitment_t *map,
                                      uint8_t key_type,
                                      uint8_t *out,
                                      size_t len) {
    size_t read_len;
    psbt_field_status_t status = read_var(dc, map, key_type, out, len, &read_len);
    if (status != PSBT_FIELD_PRESENT) {
        return status;
    }
    if (read_len != len) {
        // on error, zero out the output buffer, preventing the caller from
        // possibly using uninitialized data
        explicit_bzero(out, len);
        return PSBT_FIELD_ERROR;
    }
    return PSBT_FIELD_PRESENT;
}

/** Reads a value that must be exactly 4 bytes, decoded as a little-endian unsigned 32-bit int. */
static psbt_field_status_t read_u32_le_field(dispatcher_context_t *dc,
                                             const merkleized_map_commitment_t *map,
                                             uint8_t key_type,
                                             uint32_t *out) {
    uint8_t raw[4];
    psbt_field_status_t status = read_fixed(dc, map, key_type, raw, sizeof(raw));
    if (status == PSBT_FIELD_PRESENT) {
        *out = read_u32_le(raw, 0);
    }
    return status;
}

/** Reads a value that must be exactly 8 bytes, decoded as a little-endian unsigned 64-bit int. */
static psbt_field_status_t read_u64_le_field(dispatcher_context_t *dc,
                                             const merkleized_map_commitment_t *map,
                                             uint8_t key_type,
                                             uint64_t *out) {
    uint8_t raw[8];
    psbt_field_status_t status = read_fixed(dc, map, key_type, raw, sizeof(raw));
    if (status == PSBT_FIELD_PRESENT) {
        *out = read_u64_le(raw, 0);
    }
    return status;
}

/* -------------------------------------------------------------------------- */
/* Global map                                                                 */
/* -------------------------------------------------------------------------- */

psbt_field_status_t psbt_get_global_tx_version(dispatcher_context_t *dc,
                                               const merkleized_map_commitment_t *global_map,
                                               uint32_t *out) {
    return read_u32_le_field(dc, global_map, PSBT_GLOBAL_TX_VERSION, out);
}

psbt_field_status_t psbt_get_global_fallback_locktime(dispatcher_context_t *dc,
                                                      const merkleized_map_commitment_t *global_map,
                                                      uint32_t *out) {
    return read_u32_le_field(dc, global_map, PSBT_GLOBAL_FALLBACK_LOCKTIME, out);
}

/* -------------------------------------------------------------------------- */
/* Input map                                                                  */
/* -------------------------------------------------------------------------- */

psbt_field_status_t psbt_get_input_prevout_txid(dispatcher_context_t *dc,
                                                const merkleized_map_commitment_t *input_map,
                                                uint8_t out[static 32]) {
    return read_fixed(dc, input_map, PSBT_IN_PREVIOUS_TXID, out, 32);
}

psbt_field_status_t psbt_get_input_prevout_index(dispatcher_context_t *dc,
                                                 const merkleized_map_commitment_t *input_map,
                                                 uint32_t *out) {
    return read_u32_le_field(dc, input_map, PSBT_IN_OUTPUT_INDEX, out);
}

psbt_field_status_t psbt_get_input_sequence(dispatcher_context_t *dc,
                                            const merkleized_map_commitment_t *input_map,
                                            uint32_t *out) {
    return read_u32_le_field(dc, input_map, PSBT_IN_SEQUENCE, out);
}

psbt_field_status_t psbt_get_input_sighash_type(dispatcher_context_t *dc,
                                                const merkleized_map_commitment_t *input_map,
                                                uint32_t *out) {
    return read_u32_le_field(dc, input_map, PSBT_IN_SIGHASH_TYPE, out);
}

psbt_field_status_t psbt_get_input_redeem_script(dispatcher_context_t *dc,
                                                 const merkleized_map_commitment_t *input_map,
                                                 uint8_t *out,
                                                 size_t out_cap,
                                                 size_t *out_len) {
    return read_var(dc, input_map, PSBT_IN_REDEEM_SCRIPT, out, out_cap, out_len);
}

psbt_field_status_t psbt_get_input_witness_utxo_amount(dispatcher_context_t *dc,
                                                       const merkleized_map_commitment_t *input_map,
                                                       uint64_t *amount) {
    // The witness UTXO is encoded as [8-byte amount][varint scriptPubKey len][scriptPubKey]. Here
    // we only need the amount, but the whole value must fit in the buffer for the read to succeed.
    uint8_t raw[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    size_t len;
    psbt_field_status_t status =
        read_var(dc, input_map, PSBT_IN_WITNESS_UTXO, raw, sizeof(raw), &len);
    if (status != PSBT_FIELD_PRESENT) {
        return status;
    }
    if (len < 8) {
        // present, but too short to even contain the amount
        return PSBT_FIELD_ERROR;
    }
    *amount = read_u64_le(raw, 0);
    return PSBT_FIELD_PRESENT;
}

/* -------------------------------------------------------------------------- */
/* Output map                                                                 */
/* -------------------------------------------------------------------------- */

psbt_field_status_t psbt_get_output_amount(dispatcher_context_t *dc,
                                           const merkleized_map_commitment_t *output_map,
                                           uint64_t *out) {
    return read_u64_le_field(dc, output_map, PSBT_OUT_AMOUNT, out);
}

psbt_field_status_t psbt_get_output_script(dispatcher_context_t *dc,
                                           const merkleized_map_commitment_t *output_map,
                                           uint8_t *out,
                                           size_t out_cap,
                                           size_t *out_len) {
    return read_var(dc, output_map, PSBT_OUT_SCRIPT, out, out_cap, out_len);
}
