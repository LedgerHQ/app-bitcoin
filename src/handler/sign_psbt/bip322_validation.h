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

#include "dispatcher.h"
#include "sign_psbt.h"

// Support for BIP-322 generic signed messages (message signing via SIGN_PSBT).
// This implements BIP-322 v2.0.0 (2026-06-04).
//
// A PSBT with the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE field requests signing the BIP-322
// "to_sign" virtual transaction for the contained message. It can never be broadcast (its first
// input spends "to_spend", whose input references the null outpoint, and all produced signatures
// commit to all inputs), so it is reviewed as a message signature, not as a transaction.
//
// The security anchor is validate_bip322_request(): the to_spend txid is recomputed on-device
// from the message (tagged hash) and the input's scriptPubKey, and must match the input's
// prevout. This guarantees that the displayed message is exactly the one committed to by the
// signature, and that the signed transaction is provably unspendable.
//
// Primitives (message hash, to_spend) are in common/bip322.h. Other steps live in the SIGN_PSBT
// steps they belong to: init_global_state() detects the request and hashes the message, and
// display_bip322_message() reviews it.

/**
 * Validates that the PSBT follows the structure mandated by BIP-322 for a to_sign transaction.
 * Must be called after preprocess_inputs() and preprocess_outputs(), and only if
 * st->bip322.is_message_signing is true.
 *
 * The first input must always spend the recomputed to_spend transaction: BIP-322 v2.0.0
 * clarifies that the message_challenge is not optional in a proof of funds, so a request whose
 * first input spends a real UTXO is rejected. Additional inputs make the request a
 * proof-of-funds: they must all belong to the wallet policy, and their total amount is later
 * shown to the user.
 *
 * On success, st->bip322.challenge_script contains the scriptPubKey being proven. The to_spend
 * input is exempt from the missing_nonwitnessutxo warning in preprocess_inputs() (this function
 * rejects the request unless it spends the recomputed to_spend), so that warning can only concern
 * the additional inputs of a proof-of-funds.
 *
 * Returns true on success; returns false and sends an error status word on failure.
 */
bool validate_bip322_request(dispatcher_context_t *dc, sign_psbt_state_t *st);
