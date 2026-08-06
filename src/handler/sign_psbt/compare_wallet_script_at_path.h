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
#include "merkle.h"
#include "sign_psbt_cache.h"
#include "wallet.h"

/**
 * TODO
 */
int compare_wallet_script_at_path(dispatcher_context_t *dispatcher_context,
                                  sign_psbt_cache_t *sign_psbt_cache,
                                  uint32_t change,
                                  uint32_t address_index,
                                  const policy_node_t *policy,
                                  int wallet_version,
                                  const uint8_t keys_merkle_root[static 32],
                                  uint32_t n_keys,
                                  const uint8_t expected_script[],
                                  size_t expected_script_len);