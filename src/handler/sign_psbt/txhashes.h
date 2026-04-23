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

/* Local headers */
#include "dispatcher.h"
#include "sign_psbt.h"

/**
 * @brief Computes the transaction hashes required for signing.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[out] hashes Pointer to the structure where the computed hashes will be stored.
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline))
compute_tx_hashes(dispatcher_context_t *dc, sign_psbt_state_t *st, tx_hashes_t *hashes);

/**
 * @brief Computes the legacy sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] input_map Pointer to the map commitment of the input being signed for.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[in] has_redeemScript Whether the input has a redeemScript.
 * @param[in] scriptPubKey Pointer to the scriptPubKey of the input being signed for (which should
 * be obtained from the non-witness UTXO)
 * @param[in] scriptPubKey_len Length of the scriptPubKey.
 * @param[in] sighash_byte The sighash type byte.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline)) compute_sighash_legacy(dispatcher_context_t *dc,
                                                      const sign_psbt_state_t *st,
                                                      const merkleized_map_commitment_t *input_map,
                                                      unsigned int input_index,
                                                      bool has_redeemScript,
                                                      const uint8_t *scriptPubKey,
                                                      size_t scriptPubKey_len,
                                                      uint8_t sighash_byte,
                                                      uint8_t sighash[static 32]);

/**
 * @brief Computes the SegWit v0 sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] hashes Pointer to the structure containing the precomputed transaction hashes.
 * @param[in] input_map Pointer to the map commitment of the input being signed for.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[in] script Pointer to the script used for signing. It is the redeemScript if this input
 * has one; otherwise it is the scriptPubKey of the input being signed for (which should be obtained
 * from the witness UTXO).
 * @param[in] script_len Length of the script.
 * @param[in] sighash_byte The sighash type byte.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline))
compute_sighash_segwitv0(dispatcher_context_t *dc,
                         const sign_psbt_state_t *st,
                         const tx_hashes_t *hashes,
                         const merkleized_map_commitment_t *input_map,
                         unsigned int input_index,
                         const uint8_t *script,
                         size_t script_len,
                         uint8_t sighash_byte,
                         uint8_t sighash[static 32]);

/**
 * Computes the SegWit v1 (Taproot) sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] hashes Pointer to the structure containing the precomputed transaction hashes.
 * @param[in] input_map Pointer to the map commitment of the input being signed for.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[in] scriptPubKey Pointer to the scriptPubKey of the input being signed for (which should
 * be obtained from the non-witness UTXO)
 * @param[in] scriptPubKey_len Length of the scriptPubKey.
 * @param[in] tapleaf_hash Array containing the Taproot leaf hash. It must be NULL if spending using
 * the key path; otherwise, it is a pointer to a 32-byte array.
 * @param[in] sighash_byte The sighash type byte.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline))
compute_sighash_segwitv1(dispatcher_context_t *dc,
                         const sign_psbt_state_t *st,
                         const tx_hashes_t *hashes,
                         const merkleized_map_commitment_t *input_map,
                         unsigned int input_index,
                         const uint8_t *scriptPubKey,
                         size_t scriptPubKey_len,
                         const uint8_t *tapleaf_hash,
                         uint8_t sighash_byte,
                         uint8_t sighash[static 32]);
