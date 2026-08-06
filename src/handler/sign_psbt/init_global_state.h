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

#include "dispatcher.h"
#include "sign_psbt.h"

/**
 * Reads APDU input data, initializes the global signing state, and reads the
 * global PSBT map.
 *
 * Returns true on success, false on failure (in which case an error status
 * word has already been sent).
 */
bool init_global_state(dispatcher_context_t *dc, sign_psbt_state_t *st);

/**
 * For an internal key expression already discovered in the wallet policy,
 * fills in the rest of the key expression info (key derivation, internal
 * pubkey, ...) by querying the device for the master fingerprint and
 * deriving the key.
 *
 * Returns true if the key expression is internal (and the info was filled in
 * successfully); false if the key expression is external (and should be
 * skipped during signing).
 */
bool fill_keyexpr_info_if_internal(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   keyexpr_info_t *keyexpr_info);

/**
 * Walks the wallet policy AST and collects all the key expressions that may
 * be controlled by this device, populating st->account.internal_key_expressions.
 */
bool fill_internal_key_expressions(dispatcher_context_t *dc, sign_psbt_state_t *st);
