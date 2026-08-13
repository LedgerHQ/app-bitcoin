/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025, 2026 Ledger SAS.
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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Local headers */
#include "dispatcher.h"
#include "merkle.h"

/**
 * Per-field accessors for the PSBT maps read while signing.
 *
 * Each function wraps the low-level merkleized-map value reader and owns the *structural*
 * validation of one PSBT field: the key type, the expected length, whether the field is optional,
 * and how to decode it into a typed value.
 */

/**
 * Outcome of reading one PSBT field. Every accessor below returns this, so that a caller can
 * always tell a field that is simply not there from one that could not be read.
 *
 * Callers applying a default for an optional field MUST branch on PSBT_FIELD_ABSENT specifically
 * and treat PSBT_FIELD_ERROR as fatal. Testing for "not present" would silently substitute the
 * default after a Merkle proof failure, making the device sign over a value the client never
 * committed to.
 *
 * SECURITY: PSBT_FIELD_ABSENT rests on the client's word. See the note in
 * handler/lib/map_value_status.h — the device requests no proof of absence, so a suppressed key
 * cannot be told apart from an honest omission. Where that matters, use the presence flags derived
 * from key enumeration (has_witnessUtxo and friends), which are committed to by keys_root.
 */
typedef enum {
    PSBT_FIELD_ERROR = -1,   // present but malformed (wrong length), or a fetch/proof failure
    PSBT_FIELD_ABSENT = 0,   // the key is not present in the map (per the client)
    PSBT_FIELD_PRESENT = 1,  // present and well-formed; the out-parameter has been written
} psbt_field_status_t;

/* -------------------------------------------------------------------------- */
/* Global map                                                                 */
/* -------------------------------------------------------------------------- */

/** PSBT_GLOBAL_TX_VERSION: 4-byte little-endian version. Mandatory: ABSENT is a malformed PSBT. */
psbt_field_status_t psbt_get_global_tx_version(dispatcher_context_t *dc,
                                               const merkleized_map_commitment_t *global_map,
                                               uint32_t *out);

/**
 * PSBT_GLOBAL_FALLBACK_LOCKTIME: optional 4-byte little-endian locktime.
 * On ABSENT the caller must use locktime 0 (BIP-0370); ERROR must abort.
 *
 * NOTE: ABSENT currently also absorbs read failures (a value too long for the buffer, or a failed
 * proof), which preserves the behaviour that predates this refactor. Tightened in a later commit.
 */
psbt_field_status_t psbt_get_global_fallback_locktime(dispatcher_context_t *dc,
                                                      const merkleized_map_commitment_t *global_map,
                                                      uint32_t *out);

/* -------------------------------------------------------------------------- */
/* Input map                                                                  */
/* -------------------------------------------------------------------------- */

/** PSBT_IN_PREVIOUS_TXID: 32-byte prevout txid. Mandatory. */
psbt_field_status_t psbt_get_input_prevout_txid(dispatcher_context_t *dc,
                                                const merkleized_map_commitment_t *input_map,
                                                uint8_t out[static 32]);

/** PSBT_IN_OUTPUT_INDEX: 4-byte little-endian prevout index. Mandatory. */
psbt_field_status_t psbt_get_input_prevout_index(dispatcher_context_t *dc,
                                                 const merkleized_map_commitment_t *input_map,
                                                 uint32_t *out);

/**
 * PSBT_IN_SEQUENCE: optional 4-byte little-endian nSequence.
 * On ABSENT the caller must use the 0xFFFFFFFF default (BIP-0370).
 *
 * NOTE: the callers in txhashes.c currently also fall back to that default on ERROR, which
 * preserves the behaviour that predates this refactor. Tightened in a later commit.
 */
psbt_field_status_t psbt_get_input_sequence(dispatcher_context_t *dc,
                                            const merkleized_map_commitment_t *input_map,
                                            uint32_t *out);

/**
 * PSBT_IN_SIGHASH_TYPE: 4-byte little-endian sighash type. Callers that only read it once
 * has_sighash_type is set treat ABSENT as a malformed PSBT.
 */
psbt_field_status_t psbt_get_input_sighash_type(dispatcher_context_t *dc,
                                                const merkleized_map_commitment_t *input_map,
                                                uint32_t *out);

/**
 * PSBT_IN_REDEEM_SCRIPT: variable-length redeem script. On PSBT_FIELD_PRESENT, copies the value
 * into `out` and writes its length to `*out_len`. A script longer than `out_cap` yields
 * PSBT_FIELD_ERROR.
 */
psbt_field_status_t psbt_get_input_redeem_script(dispatcher_context_t *dc,
                                                 const merkleized_map_commitment_t *input_map,
                                                 uint8_t *out,
                                                 size_t out_cap,
                                                 size_t *out_len);

/**
 * PSBT_IN_WITNESS_UTXO amount: reads the witness UTXO and returns its 8-byte little-endian amount.
 * Only requires the value to be at least 8 bytes; the full structural validation of the witness
 * UTXO is done elsewhere (see get_amount_scriptpubkey_from_psbt_witness).
 */
psbt_field_status_t psbt_get_input_witness_utxo_amount(dispatcher_context_t *dc,
                                                       const merkleized_map_commitment_t *input_map,
                                                       uint64_t *amount);

/* -------------------------------------------------------------------------- */
/* Output map                                                                 */
/* -------------------------------------------------------------------------- */

/** PSBT_OUT_AMOUNT: 8-byte little-endian amount. Mandatory. */
psbt_field_status_t psbt_get_output_amount(dispatcher_context_t *dc,
                                           const merkleized_map_commitment_t *output_map,
                                           uint64_t *out);

/**
 * PSBT_OUT_SCRIPT: variable-length scriptPubKey. On PSBT_FIELD_PRESENT, copies the value into
 * `out` and writes its length to `*out_len`. A script longer than `out_cap` yields
 * PSBT_FIELD_ERROR.
 */
psbt_field_status_t psbt_get_output_script(dispatcher_context_t *dc,
                                           const merkleized_map_commitment_t *output_map,
                                           uint8_t *out,
                                           size_t out_cap,
                                           size_t *out_len);
