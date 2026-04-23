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

#ifdef HAVE_SWAP

#include <stdbool.h>

#include "dispatcher.h"
#include "sign_psbt.h"

/**
 * Performs the additional checks required when signing a PSBT initiated by
 * the Exchange app: validates that the wallet policy is default, that there
 * are no external inputs, that the destination address, total amount and
 * fees match those negotiated with app-exchange, and (for cross-chain swaps)
 * that the OP_RETURN payload matches the expected payin hash.
 *
 * On any check failure, sends an SW_FAIL_SWAP and calls
 * finalize_exchange_sign_transaction(false) (which never returns).
 */
bool execute_swap_checks(dispatcher_context_t *dc, sign_psbt_state_t *st);

#endif /* HAVE_SWAP */
