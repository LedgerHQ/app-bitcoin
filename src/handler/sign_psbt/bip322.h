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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dispatcher.h"
#include "sign_psbt.h"

// Support for BIP-322 generic signed messages (message signing via SIGN_PSBT).
//
// A PSBT with the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE global field is a request to sign the
// BIP-322 "to_sign" virtual transaction for the contained message. Such a transaction can never
// be broadcast (its input spends the "to_spend" virtual transaction, whose own input references
// the null outpoint), so it is reviewed as a message signature, not as a transaction.
//
// The security anchor is bip322_validate(): the to_spend txid is recomputed on-device from the
// message (tagged hash) and the input's own scriptPubKey, and must match the input's prevout.
// This guarantees that the message shown to the user is exactly the message committed to by the
// produced signature, and that the signed transaction is provably unspendable.

// Maximum length of the serialization of a BIP-322 to_spend transaction:
// 4 (version) + 1 (input count) + 32 (prevout hash) + 4 (prevout index) + 1 (scriptSig length)
// + 34 (scriptSig) + 4 (sequence) + 1 (output count) + 8 (value) + 1 (script length)
// + MAX_PREVOUT_SCRIPTPUBKEY_LEN (challenge script) + 4 (locktime)
#define BIP322_TO_SPEND_MAX_LEN (94 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)

/**
 * Serializes the BIP-322 to_spend transaction for the given message hash and challenge
 * scriptPubKey into out (which must be at least BIP322_TO_SPEND_MAX_LEN bytes long).
 *
 * Returns the length of the serialization, or -1 if challenge_script_len is larger than
 * MAX_PREVOUT_SCRIPTPUBKEY_LEN.
 */
int bip322_serialize_to_spend(const uint8_t message_hash[static 32],
                              const uint8_t *challenge_script,
                              size_t challenge_script_len,
                              uint8_t out[static BIP322_TO_SPEND_MAX_LEN]);

/**
 * Computes the txid (in the byte order used inside transaction serializations, matching
 * PSBT_IN_PREVIOUS_TXID) of the BIP-322 to_spend transaction for the given message hash and
 * challenge scriptPubKey.
 *
 * Returns 0 on success, -1 on failure.
 */
int bip322_compute_to_spend_txid(const uint8_t message_hash[static 32],
                                 const uint8_t *challenge_script,
                                 size_t challenge_script_len,
                                 uint8_t out_txid[static 32]);

/**
 * Detects the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE field in the global map. If present, streams
 * the message from the client, computing its BIP-322 tagged hash, its plain sha256 (used for
 * display when the message is too long or not printable), and whether it is printable; the
 * results are stored in st->bip322.
 *
 * Returns true on success (whether or not the field is present); returns false and sends an
 * error status word on failure.
 */
bool bip322_detect(dispatcher_context_t *dc, sign_psbt_state_t *st);

/**
 * Validates that the PSBT follows the structure mandated by BIP-322 for a to_sign transaction.
 * Must be called after preprocess_inputs() and preprocess_outputs(), and only if
 * st->bip322.is_message_signing is true.
 *
 * Additional inputs beyond the first make the request a proof-of-funds: they spend real UTXOs
 * that must all belong to the wallet policy, and their total amount is later shown to the
 * user. The first input must always spend the recomputed to_spend transaction.
 *
 * On success, st->bip322.challenge_script contains the scriptPubKey being proven; for a plain
 * (single-input) message signing, the missing_nonwitnessutxo warning is cleared, as the
 * recomputed to_spend transaction fully authenticates the spent output.
 *
 * Returns true on success; returns false and sends an error status word on failure.
 */
bool bip322_validate(dispatcher_context_t *dc, sign_psbt_state_t *st);

/**
 * Shows the BIP-322 message review (account, address being proven, the total amount of the
 * proven coins for a proof-of-funds, and the message text or its sha256 hash) and asks for
 * user confirmation. The message is streamed again from the client directly into the UI
 * buffer; the second pass is authenticated by the same Merkle commitment as the first, so the
 * client cannot show a different message than the one hashed at detection time.
 *
 * Returns true if the user approved; returns false and sends an error status word otherwise.
 */
bool bip322_display_message(dispatcher_context_t *dc, sign_psbt_state_t *st);
