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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "init_global_state.h"

/* SDK headers */
#include "crypto_helpers.h"
#include "read.h"
#include "write.h"

/* Local headers */
#include "bitvector.h"
#include "buffer.h"
#include "check_merkle_tree_sorted.h"
#include "compare_wallet_script_at_path.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "error_codes.h"
#include "get_merkle_leaf_element.h"
#include "get_merkleized_map.h"
#include "get_preimage.h"
#include "musig.h"
#include "policy.h"
#include "psbt.h"
#include "psbt_fields.h"
#include "sign_psbt_cache.h"
#include "sw.h"
#include "wallet.h"

/**
 * Parses the APDU payload for the SIGN_PSBT command and populates the parts
 * of the signing state that come directly from the APDU:
 * - st->global_map (commitment to the PSBT global map)
 * - st->n_inputs / st->inputs_root
 * - st->n_outputs / st->outputs_root
 *
 * The wallet_id and wallet_hmac are returned via out parameters as they are
 * only needed to load the wallet account; they do not need to be kept in the
 * state.
 *
 * Returns true on success; on failure, an error status word has already been
 * sent.
 */
static bool __attribute__((noinline)) parse_sign_psbt_apdu(dispatcher_context_t *dc,
                                                           sign_psbt_state_t *st,
                                                           uint8_t wallet_id[static 32],
                                                           uint8_t wallet_hmac[static 32]) {
    if (!buffer_read_varint(&dc->read_buffer, &st->global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (!buffer_read_bytes(&dc->read_buffer, st->global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, st->global_map.values_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    // we already know n_inputs and n_outputs, so we skip reading from the global map

    uint64_t n_inputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->inputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (n_inputs_u64 > MAX_N_INPUTS_CAN_SIGN) {
        PRINTF("At most %d inputs are supported\n", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }
    st->n_inputs = (unsigned int) n_inputs_u64;

    uint64_t n_outputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->outputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }
    if (n_outputs_u64 > MAX_N_OUTPUTS_CAN_SIGN) {
        PRINTF("At most %d outputs are supported\n", MAX_N_OUTPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }
    st->n_outputs = (unsigned int) n_outputs_u64;

    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    return true;
}

/**
 * Verifies the integrity of the PSBT global map (already committed to by
 * st->global_map) and extracts the transaction-wide fields from it
 * (tx_version, locktime).
 *
 * Returns true on success; on failure, an error status word has already been
 * sent.
 */
static bool __attribute__((noinline)) process_global_map(dispatcher_context_t *dc,
                                                         sign_psbt_state_t *st) {
    // Check integrity of the global map (this also marks it as validated, so that its values may
    // be read by key below).
    if (call_check_merkleized_map_sorted(dc, &st->global_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read tx version
    if (PSBT_FIELD_PRESENT != psbt_get_global_tx_version(dc, &st->global_map, &st->tx_version)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read fallback locktime.
    // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
    // preferred height/block locktime. If that's relevant, the client must set the fallback
    // locktime to the appropriate value before calling sign_psbt.
    switch (psbt_get_global_fallback_locktime(dc, &st->global_map, &st->locktime)) {
        case PSBT_FIELD_ABSENT:
            st->locktime = 0;
            break;
        case PSBT_FIELD_PRESENT:
            break;
        default:  // PSBT_FIELD_ERROR: present but malformed
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
    }

    return true;
}

/**
 * Loads the wallet account: verifies the wallet HMAC (or marks the policy as
 * default if the HMAC is all-zero), fetches and parses the serialized wallet
 * policy from the client, and validates that a default policy is indeed
 * standard.
 *
 * Returns true on success; on failure, an error status word has already been
 * sent.
 */
static bool __attribute__((noinline)) load_wallet_account(dispatcher_context_t *dc,
                                                          sign_psbt_state_t *st,
                                                          const uint8_t wallet_id[static 32],
                                                          const uint8_t wallet_hmac[static 32]) {
    if (!is_array_all_zeros(wallet_hmac, 32)) {
        // Verify hmac
        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return false;
        }

        st->account.is_default = false;
    } else {
        st->account.is_default = true;
    }

    // Fetch the serialized wallet policy from the client
    uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         wallet_id,
                                                         serialized_wallet_policy,
                                                         sizeof(serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    buffer_t serialized_wallet_policy_buf =
        buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

    uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];

    int desc_temp_len = read_and_parse_wallet_policy(dc,
                                                     &serialized_wallet_policy_buf,
                                                     &st->account.wallet_header,
                                                     policy_map_descriptor,
                                                     st->account.policy_map_bytes,
                                                     MAX_WALLET_POLICY_BYTES);
    if (desc_temp_len < 0) {
        PRINTF("Failed to read or parse wallet policy");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    st->account.policy_map = (policy_node_t *) st->account.policy_map_bytes;

    if (st->account.is_default) {
        // No hmac: verify it's a default policy and capture its purpose/account for the label.
        if (!is_wallet_policy_standard(dc,
                                       &st->account.wallet_header,
                                       st->account.policy_map,
                                       &st->account.bip44_purpose,
                                       &st->account.bip44_account)) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_HMAC_FOR_NONDEFAULT_POLICY);
            return false;
        }

        if (st->account.wallet_header.name_len != 0) {
            PRINTF("Name must be zero-length for a standard wallet policy\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NO_NAME_FOR_DEFAULT_POLICY);
            return false;
        }

        // unlike in get_wallet_address, we do not check if the address_index is small:
        // if funds were already sent there, there is no point in preventing to spend them.
    }

    return true;
}

bool __attribute__((noinline)) init_global_state(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    if (!parse_sign_psbt_apdu(dc, st, wallet_id, wallet_hmac)) return false;

    if (!process_global_map(dc, st)) return false;

    if (!load_wallet_account(dc, st, wallet_id, wallet_hmac)) return false;

    st->master_key_fingerprint = crypto_get_master_key_fingerprint();
    return true;
}

static bool __attribute__((noinline)) get_and_verify_key_info(dispatcher_context_t *dc,
                                                              sign_psbt_state_t *st,
                                                              uint16_t key_index,
                                                              keyexpr_info_t *keyexpr_info) {
    policy_map_key_info_t key_info;
    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

    int key_info_len = call_get_merkle_leaf_element(dc,
                                                    st->account.wallet_header.keys_info_merkle_root,
                                                    st->account.wallet_header.n_keys,
                                                    key_index,
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;  // should never happen
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    if (parse_policy_map_key_info(&key_info_buffer, &key_info, st->account.wallet_header.version) ==
        -1) {
        return false;  // should never happen
    }

    keyexpr_info->key_derivation_length = key_info.master_key_derivation_len;
    for (int i = 0; i < key_info.master_key_derivation_len; i++) {
        keyexpr_info->key_derivation[i] = key_info.master_key_derivation[i];
    }

    keyexpr_info->fingerprint = read_u32_be(key_info.master_key_fingerprint, 0);

    memcpy(&keyexpr_info->pubkey, &key_info.ext_pubkey, sizeof(serialized_extended_pubkey_t));

    // the rest of the function verifies if the key is indeed internal, if it has our fingerprint
    uint32_t fpr = read_u32_be(key_info.master_key_fingerprint, 0);
    if (fpr != st->master_key_fingerprint) {
        return false;
    }

    // it could be a collision on the fingerprint; we verify that we can actually generate
    // the same pubkey
    serialized_extended_pubkey_t derived_pubkey;
    if (CX_OK != get_extended_pubkey_at_path(key_info.master_key_derivation,
                                             key_info.master_key_derivation_len,
                                             BIP32_PUBKEY_VERSION,
                                             &derived_pubkey)) {
        return false;
    }

    if (memcmp(&key_info.ext_pubkey, &derived_pubkey, sizeof(derived_pubkey)) != 0) {
        return false;
    }

    return true;
}

bool fill_keyexpr_info_if_internal(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   keyexpr_info_t *keyexpr_info) {
    keyexpr_info_t tmp_keyexpr_info;
    // preserve the fields that are already computed outside of this function
    memcpy(&tmp_keyexpr_info, keyexpr_info, sizeof(keyexpr_info_t));

    if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
        bool result = get_and_verify_key_info(dc,
                                              st,
                                              keyexpr_info->key_expression_ptr->k.key_index,
                                              &tmp_keyexpr_info);
        if (result) {
            memcpy(keyexpr_info, &tmp_keyexpr_info, sizeof(keyexpr_info_t));
            memcpy(&keyexpr_info->internal_pubkey,
                   &keyexpr_info->pubkey,
                   sizeof(serialized_extended_pubkey_t));
            keyexpr_info->psbt_root_key_derivation_length = keyexpr_info->key_derivation_length;
        }
        return result;
    } else if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_MUSIG) {
        // iterate through the keys of the musig() placeholder to find if a key is internal
        const musig_aggr_key_info_t *musig_info = keyexpr_info->key_expression_ptr->m.musig_info;
        const uint16_t *key_indexes = musig_info->key_indexes;

        bool has_internal_key = false;

        // collect the keys of the musig, and fill the info related to the internal key (if any)
        uint8_t keys[MAX_PUBKEYS_PER_MUSIG][33];

        LEDGER_ASSERT(musig_info->n <= MAX_PUBKEYS_PER_MUSIG, "Too many keys in musig placeholder");

        for (int idx_in_musig = 0; idx_in_musig < musig_info->n; idx_in_musig++) {
            if (get_and_verify_key_info(dc, st, key_indexes[idx_in_musig], &tmp_keyexpr_info)) {
                memcpy(keyexpr_info->key_derivation,
                       tmp_keyexpr_info.key_derivation,
                       sizeof(tmp_keyexpr_info.key_derivation));
                keyexpr_info->key_derivation_length = tmp_keyexpr_info.key_derivation_length;

                // keep track of the actual internal key of this key expression
                memcpy(&keyexpr_info->internal_pubkey,
                       &tmp_keyexpr_info.pubkey,
                       sizeof(serialized_extended_pubkey_t));

                has_internal_key = true;
            }

            memcpy(keys[idx_in_musig], tmp_keyexpr_info.pubkey.compressed_pubkey, 33);
        }

        if (has_internal_key) {
            keyexpr_info->psbt_root_key_derivation_length = 0;

            // sort the keys in ascending order
            qsort(keys, musig_info->n, sizeof(plain_pk_t), compare_plain_pk);

            musig_keyagg_context_t musig_ctx;
            if (0 > musig_key_agg(keys, musig_info->n, &musig_ctx)) {
                return false;
            }

            // compute the aggregated extended pubkey
            memset(&keyexpr_info->pubkey, 0, sizeof(keyexpr_info->pubkey));
            write_u32_be(keyexpr_info->pubkey.version, 0, BIP32_PUBKEY_VERSION);

            keyexpr_info->pubkey.compressed_pubkey[0] = (musig_ctx.Q.y[31] % 2 == 0) ? 2 : 3;
            memcpy(&keyexpr_info->pubkey.compressed_pubkey[1],
                   musig_ctx.Q.x,
                   sizeof(musig_ctx.Q.x));
            memcpy(&keyexpr_info->pubkey.chain_code, BIP_328_CHAINCODE, sizeof(BIP_328_CHAINCODE));

            keyexpr_info->fingerprint =
                crypto_get_key_fingerprint(keyexpr_info->pubkey.compressed_pubkey);
        }

        return has_internal_key;  // no internal key found in musig placeholder
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
        return false;
    }
}

bool fill_internal_key_expressions(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    size_t cur_index = 0;

    st->account.n_internal_key_expressions = 0;
    memset(st->account.internal_key_expressions, 0, sizeof(st->account.internal_key_expressions));

    // find and parse our registered key info in the wallet
    keyexpr_info_t keyexpr_info;
    memset(&keyexpr_info, 0, sizeof(keyexpr_info_t));
    while (true) {
        keyexpr_info.index = cur_index;
        const policy_node_t *tapleaf_ptr = NULL;
        int n_key_expressions = get_keyexpr_by_index(st->account.policy_map,
                                                     cur_index,
                                                     &tapleaf_ptr,
                                                     &keyexpr_info.key_expression_ptr);
        if (tapleaf_ptr != NULL) {
            // get_keyexpr_by_index returns the pointer to the tapleaf only if the key being
            // spent is indeed in a tapleaf
            keyexpr_info.tapleaf_ptr = tapleaf_ptr;
            keyexpr_info.is_tapscript = true;
        }
        if (n_key_expressions < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (cur_index >= (size_t) n_key_expressions) {
            // all keys have been processed
            break;
        }

        if (fill_keyexpr_info_if_internal(dc, st, &keyexpr_info)) {
            if (st->account.n_internal_key_expressions >= MAX_INTERNAL_KEY_EXPRESSIONS) {
                PRINTF("Too many internal key expressions. The maximum supported is %d\n",
                       MAX_INTERNAL_KEY_EXPRESSIONS);
                SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_WALLET_POLICY_TOO_MANY_INTERNAL_KEYS);
                return false;
            }

            // store this key info, as it's internal
            memcpy(&st->account.internal_key_expressions[st->account.n_internal_key_expressions],
                   &keyexpr_info,
                   sizeof(keyexpr_info_t));
            ++st->account.n_internal_key_expressions;
        }

        ++cur_index;
    }

    if (st->account.n_internal_key_expressions == 0) {
        PRINTF("No internal key found in wallet policy");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_WALLET_POLICY_HAS_NO_INTERNAL_KEY);
        return false;
    }

    return true;
}
