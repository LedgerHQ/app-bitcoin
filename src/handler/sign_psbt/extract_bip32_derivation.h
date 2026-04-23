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

/* SDK headers */
#include "bip32.h"

/* Local headers */
#include "constants.h"
#include "dispatcher.h"

/**
 * Convenience function to extract the BIP32 derivation part from a PSBT field key type
 * PSBT_{IN,OUT}_BIP32_DERIVATION or PSBT_{IN,OUT}_TAP_BIP32_DERIVATION.
 * This is needed because the tapscript versions can be very large, so it needs to
 * be parsed while streaming it.
 */
int extract_bip32_derivation(dispatcher_context_t *dc,
                             int psbt_key_type,
                             const uint8_t values_root[static 32],
                             uint32_t merkle_tree_size,
                             int index,
                             uint32_t out[static 1 + MAX_BIP32_PATH_STEPS]);
