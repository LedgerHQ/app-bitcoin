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
//
// A PSBT with the PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE global field is a request to sign the
// BIP-322 "to_sign" virtual transaction for the contained message. Such a transaction can never
// be broadcast (its input spends the "to_spend" virtual transaction, whose own input references
// the null outpoint), so it is reviewed as a message signature, not as a transaction.
//
// The security anchor is validate_bip322_request(): the to_spend txid is recomputed on-device from
// the message (tagged hash) and the input's own scriptPubKey, and must match the input's prevout.
// This guarantees that the message shown to the user is exactly the message committed to by the
// produced signature, and that the signed transaction is provably unspendable.
//
// The BIP-322 primitives (message hash, to_spend) are in common/bip322.h. The other steps of the
// flow live in the SIGN_PSBT steps they belong to: init_global_state() detects the request and
// hashes the message, and display_bip322_message() reviews it.

/**
 * Validates that the PSBT follows the structure mandated by BIP-322 for a to_sign transaction.
 * Must be called after preprocess_inputs() and preprocess_outputs(), and only if
 * st->bip322.is_message_signing is true.
 *
 * Additional inputs beyond the first make the request a proof-of-funds: they spend real UTXOs
 * that must all belong to the wallet policy, and their total amount is later shown to the
 * user. The first input must always spend the recomputed to_spend transaction.
 *
 * On success, st->bip322.challenge_script contains the scriptPubKey being proven. The
 * to_spend input never triggers the missing_nonwitnessutxo warning (preprocess_inputs() exempts
 * it, relying on this function to reject the request unless it spends the recomputed to_spend),
 * so the warning can only concern the additional inputs of a proof-of-funds.
 *
 * Returns true on success; returns false and sends an error status word on failure.
 */
bool validate_bip322_request(dispatcher_context_t *dc, sign_psbt_state_t *st);
