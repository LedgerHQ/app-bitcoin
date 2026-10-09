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

#include <stddef.h>
#include <stdint.h>

#include "cx.h"

#include "constants.h"

// BIP-322 generic signed messages: the parts of the specification that do not depend on how a
// signing request reaches the app.
//
// A BIP-322 signature for a message and a message_challenge (the scriptPubKey whose control is
// proven) is a signature of the "to_sign" virtual transaction, whose first input spends output 0
// of the "to_spend" virtual transaction. to_spend commits to the message hash and to the
// message_challenge; its own input references the null outpoint, so neither transaction can
// ever be broadcast.

/**
 * Initializes hash_context for the BIP-322 message hash: the BIP-340 tagged hash of the message
 * with the tag "BIP0322-signed-message". The message is then added with crypto_hash_update(),
 * and the hash obtained with crypto_hash_digest().
 */
void bip322_message_hash_init(cx_sha256_t *hash_context);

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
