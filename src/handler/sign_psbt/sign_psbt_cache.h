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
#include "crypto.h"
#include "wallet.h"

// This allows to keep the cache size small, while only paying a performance hit for any extremely
// complicated policy with more than 16 key expressions in total (should that occur in practice).
#define MAX_CACHED_KEY_EXPRESSIONS 16

// This structure contains all the information that is deterministically computed during the signing
// flow, and might be accessed multiple times.
// Currently, it only contains the derived child keys of the root keys in the key expressions of the
// wallet policy.
typedef struct sign_psbt_cache_s {
    struct {
        // 0 for the receiving address, 1 for the change address
        bool is_child_pubkey_initialized[2];
        serialized_extended_pubkey_t child_pubkeys[2];
    } derived_child[MAX_CACHED_KEY_EXPRESSIONS];  // 78 * 2 * MAX_CACHED_KEY_EXPRESSIONS bytes
} sign_psbt_cache_t;

/**
 * Initializes the sign_psbt_cache_t structure.
 * It must be called before a sign_psbt_cache_t is used.
 *
 * @param[in] cache Pointer to the cache structure to be initialized.
 */
static inline void init_sign_psbt_cache(sign_psbt_cache_t *cache) {
    memset(cache, 0, sizeof(sign_psbt_cache_t));
}

/*
Public keys in a wallet policy always have two derivation steps: the first is typically 0 or 1,
while the second step is the address index and is usually not reused in different UTXOs.
Therefore, the inputs (and change addresses) will often share the same first step.
By caching the intermediate pubkeys, we avoid recomputing the same BIP-32 pubkey derivations
multiple times. This is particularly important for transactions with many inputs, as the total
number of BIP-32 derivations is cut almost by half when using the cache.
*/

/**
 * Derives the first step for a public key in a key expression, using a precomputed value from the
 * cache if available. If the key is not in the cache, it is computed and stored in the cache,
 * unless the key expression index is too large.
 *
 * @param[in] base_key Pointer to the base serialized extended public key.
 * @param[in] keyexpr Pointer to the policy node key expression, which contains derivation
 * information.
 * @param[in] cache Pointer to the cache structure used to store derived child keys.
 * @param[in] is_change true if deriving the change address, false otherwise.
 * @param[out] out_pubkey Pointer to the output serialized extended public key.
 *
 * @return 0 on success, -1 on failure.
 */
int derive_first_step_for_pubkey(const serialized_extended_pubkey_t *base_key,
                                 const policy_node_keyexpr_t *keyexpr,
                                 sign_psbt_cache_t *cache,
                                 bool is_change,
                                 serialized_extended_pubkey_t *out_pubkey);
