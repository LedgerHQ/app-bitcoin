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

// UI text labels defined in src/ui (used to set the "loading"/"signing"
// processing screen).
extern const char GA_LOADING_TRANSACTION[];
extern const char GA_SIGNING_TRANSACTION[];

/**
 * Drives the user-facing transaction confirmation flow:
 * - displays warnings (external inputs, non-default sighash, missing
 *   non-witness UTXO);
 * - displays each external output and the fees;
 * - asks for final user approval.
 *
 * Returns true if the user approved, false otherwise (in which case an error
 * status word has already been sent).
 */
bool display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]);

/**
 * Formats the human-readable label for a default (unregistered) account, e.g.
 * "Native SegWit #2". Returns false if the purpose is not one of the default policies.
 */
bool format_default_account_label(int bip44_purpose, uint32_t account, char *out, size_t out_len);

/**
 * Shows the input verification warnings (external inputs, non-default sighash, missing
 * non-witness UTXO), letting the user abort. Called by both the transaction review and the
 * BIP-322 message review, so that any warning added in the future is surfaced in both flows.
 *
 * Returns true if the user did not abort; returns false and sends an error status word
 * otherwise.
 */
bool display_warnings(dispatcher_context_t *dc, sign_psbt_state_t *st);
