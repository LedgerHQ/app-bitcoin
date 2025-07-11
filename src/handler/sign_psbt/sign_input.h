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
#include <stdint.h>

#include "bitvector.h"
#include "constants.h"
#include "dispatcher.h"
#include "sign_psbt.h"
#include "sign_psbt_cache.h"

/**
 * Signs a legacy or SegwitV0 sighash using the ECDSA algorithm, and yields
 * the necessary info for the partial signature.
 *
 * @param[in] dc The dispatcher context
 * @param[in] st The signing state
 * @param[in] input_index The index of the input whose sighash is being signed
 * @param[in] sign_path The BIP32 path of the key being used to sign
 * @param[in] sign_path_len The number of derivation steps of the BIP32 path
 * @param[in] sighash_byte The sighash type byte
 * @param[in,out] sighash 32-byte sighash to sign
 * @return true on success; false on failure (in which case an error status
 *         word has already been sent).
 */
bool __attribute__((noinline)) sign_sighash_ecdsa_and_yield(dispatcher_context_t *dc,
                                                            sign_psbt_state_t *st,
                                                            unsigned int input_index,
                                                            const uint32_t sign_path[],
                                                            size_t sign_path_len,
                                                            uint8_t sighash_byte,
                                                            uint8_t sighash[static 32]);

/**
 * Signs a SegwitV1 (taproot) sighash using BIP-340 Schnorr, and yields the
 * necessary info for the partial signature.
 *
 * @param[in] tweak_data Optional tweak data to be applied after BIP-32
 * derivation. Use a zero-length array for BIP-86/BIP-386, a 32-byte taproot
 * Merkle root for taproot Script path spends, or NULL to sign with an
 * untweaked key (e.g. `rawtr()`).
 * @param[in] tapleaf_hash NULL for keypath spends; the tapleaf hash for
 * tapscript signatures.
 */
bool __attribute__((noinline)) sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                                              sign_psbt_state_t *st,
                                                              unsigned int input_index,
                                                              const uint32_t sign_path[],
                                                              size_t sign_path_len,
                                                              const uint8_t *tweak_data,
                                                              size_t tweak_data_len,
                                                              const uint8_t *tapleaf_hash,
                                                              uint8_t sighash_byte,
                                                              const uint8_t sighash[static 32]);

/**
 * Iterates over all the internal key expressions and all internal inputs,
 * producing the appropriate signature for each (legacy ECDSA, SegwitV0
 * ECDSA, SegwitV1 Schnorr, or MuSig2 partial signature).
 */
bool sign_internal_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    sign_psbt_cache_t *sign_psbt_cache,
    signing_state_t *signing_state,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]);

/**
 * Validates the transaction and displays it to the user for confirmation.
 *
 * This is a weak function that derived applications MUST replace in order to
 * implement their own transaction validation and user-facing review flow. The
 * default implementation rejects the transaction with SW_NOT_SUPPORTED.
 */
bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]);

/**
 * Signs any input that is not internal to the wallet policy.
 *
 * This is a weak function that derived applications can replace to sign custom
 * (non-policy) inputs. The default implementation is a no-op that returns true.
 */
bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]);
