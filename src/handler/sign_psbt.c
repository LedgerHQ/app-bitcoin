/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
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

#include "sign_psbt.h"

/* SDK headers */
#include "crypto_helpers.h"
#include "read.h"
#include "swap.h"
#include "varint.h"
#include "write.h"

/* Local headers */
#include "amount_from_psbt.h"
#include "bitvector.h"
#include "check_merkle_tree_sorted.h"
#include "client_commands.h"
#include "commands.h"
#include "compare_wallet_script_at_path.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "display.h"
#include "error_codes.h"
#include "extract_bip32_derivation.h"
#include "get_merkle_leaf_element.h"
#include "get_merkleized_map.h"
#include "get_merkleized_map_value.h"
#include "get_preimage.h"
#include "handle_swap_sign_transaction.h"
#include "handlers.h"
#include "menu.h"
#include "merkle.h"
#include "musig.h"
#include "musig_sessions.h"
#include "musig_signing.h"
#include "policy.h"
#include "psbt.h"
#include "psbt_parse_rawtx.h"
#include "script.h"
#include "sign_psbt_cache.h"
#include "sw.h"
#include "swap_globals.h"
#include "txhashes.h"
#include "wallet.h"

/*
Current assumptions during signing:
  1) exactly one of the keys in the wallet is internal (enforce during wallet registration)
  2) all the keys in the wallet have a wildcard (that is, they end with '**'), with at most
     4 derivation steps before it.

Assumption 2 simplifies the handling of pubkeys (and their paths) used for signing,
as all the internal keys will have a path that ends with /change/address_index (BIP44-style).

It would be possible to generalize to more complex scripts, but it makes it more difficult to detect
the right paths to identify internal inputs/outputs.
*/

// HELPER FUNCTIONS

typedef struct {
    uint32_t fingerprint;
    size_t derivation_len;
    uint32_t key_origin[MAX_BIP32_PATH_STEPS];
} derivation_info_t;

extern const char GA_LOADING_TRANSACTION[];

// Convenience function to share common logic when parsing the
// PSBT_{IN|OUT}_{TAP}?_BIP32_DERIVATION fields from inputs or outputs.
// Note: This function must return -1 only on errors (causing signing to abort).
//       It returns 1 if a that might match the wallet policy is found.
//       It returns 0 otherwise (not a match, but continue the signing flow).
static int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index,
    derivation_info_t *derivation_info) {
    uint8_t bip32_derivation_pubkey[33];

    bool is_tap = psbt_key_type == PSBT_IN_TAP_BIP32_DERIVATION ||
                  psbt_key_type == PSBT_OUT_TAP_BIP32_DERIVATION;
    int key_len = is_tap ? 32 : 33;

    if (!buffer_read_bytes(data,
                           bip32_derivation_pubkey,
                           key_len)  // read compressed pubkey or x-only pubkey
        || buffer_can_read(data, 1)  // ...but should not be able to read more
    ) {
        PRINTF("Unexpected pubkey length\n");
        return -1;
    }

    // get the corresponding value in the values Merkle tree,
    // then fetch the bip32 path from the field
    uint32_t fpt_der[1 + MAX_BIP32_PATH_STEPS];

    int der_len = extract_bip32_derivation(dc,
                                           psbt_key_type,
                                           map_commitment->values_root,
                                           map_commitment->size,
                                           index,
                                           fpt_der);
    if (der_len < 0) {
        PRINTF("Failed to read BIP32_DERIVATION\n");
        return -1;
    }

    if (der_len < 2 || der_len > MAX_BIP32_PATH_STEPS) {
        PRINTF("BIP32_DERIVATION path too long\n");
        return 0;
    }

    derivation_info->fingerprint = fpt_der[0];
    for (int i = 0; i < der_len; i++) {
        derivation_info->key_origin[i] = fpt_der[i + 1];
    }
    derivation_info->derivation_len = der_len;

    return 1;
}

bool is_keyexpr_compatible_with_derivation_info(const keyexpr_info_t *keyexpr_info,
                                                const derivation_info_t *derivation_info) {
    if (keyexpr_info->fingerprint != derivation_info->fingerprint) {
        return false;
    }
    if (keyexpr_info->psbt_root_key_derivation_length + 2 != derivation_info->derivation_len) {
        return false;
    }
    for (int i = 0; i < keyexpr_info->psbt_root_key_derivation_length; i++) {
        if (keyexpr_info->key_derivation[i] != derivation_info->key_origin[i]) {
            return false;
        }
    }
    uint32_t change_step = derivation_info->key_origin[derivation_info->derivation_len - 2];
    if (change_step != keyexpr_info->key_expression_ptr->num_first &&
        change_step != keyexpr_info->key_expression_ptr->num_second) {
        return false;
    }
    return true;
}

/**
 * Verifies if a certain input/output is internal (that is, controlled by the wallet being used for
 * signing). This uses the state of sign_psbt and is not meant as a general-purpose function;
 * rather, it avoids some substantial code duplication and removes complexity from sign_psbt.
 *
 * @return 1 if the given input/output is internal; 0 if external; -1 on error.
 */
static int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                              const sign_psbt_state_t *state,
                              sign_psbt_cache_t *sign_psbt_cache,
                              const in_out_info_t *in_out_info,
                              bool is_input) {
    // If we did not find any info about the pubkey associated to the key expression we're
    // considering, then it's external
    if (!in_out_info->key_expression_found) {
        return 0;
    }

    if (!is_input && in_out_info->is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         sign_psbt_cache,
                                         in_out_info->is_change,
                                         in_out_info->address_index,
                                         state->wallet_policy_map,
                                         state->wallet_header.version,
                                         state->wallet_header.keys_info_merkle_root,
                                         state->wallet_header.n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}

static bool __attribute__((noinline))
init_global_state(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    merkleized_map_commitment_t global_map;
    if (!buffer_read_varint(&dc->read_buffer, &global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (!buffer_read_bytes(&dc->read_buffer, global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, global_map.values_root, 32)) {
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

    uint8_t wallet_hmac[32];
    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    {  // process global map
        // Check integrity of the global map
        if (call_check_merkle_tree_sorted(dc, global_map.keys_root, (size_t) global_map.size) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t raw_result[9];  // max size for a varint
        int result_len;

        // Read tx version
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_TX_VERSION},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        st->tx_version = read_u32_le(raw_result, 0);

        // Read fallback locktime.
        // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
        // preferred height/block locktime. If that's relevant, the client must set the fallback
        // locktime to the appropriate value before calling sign_psbt.
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_FALLBACK_LOCKTIME},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len < 0) {
            st->locktime = 0;
        } else if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else {
            st->locktime = read_u32_le(raw_result, 0);
        }
    }

    if (!is_array_all_zeros(wallet_hmac, sizeof(wallet_hmac))) {
        // non-default wallet policies are not supported in derived apps
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    } else {
        st->is_wallet_default = true;
    }

    st->has_no_wallet_policy = is_array_all_zeros(wallet_id, sizeof(wallet_id));

    if (!st->has_no_wallet_policy) {
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
                                                         &st->wallet_header,
                                                         policy_map_descriptor,
                                                         st->wallet_policy_map_bytes,
                                                         MAX_WALLET_POLICY_BYTES);
        if (desc_temp_len < 0) {
            PRINTF("Failed to read or parse wallet policy");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        st->wallet_policy_map = (policy_node_t *) st->wallet_policy_map_bytes;

        if (st->is_wallet_default) {
            // No hmac, verify that the policy is indeed a default one
            if (!is_wallet_policy_standard(dc, &st->wallet_header, st->wallet_policy_map)) {
                PRINTF("Non-standard policy, and no hmac provided\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_HMAC_FOR_NONDEFAULT_POLICY);
                return false;
            }

            if (st->wallet_header.name_len != 0) {
                PRINTF("Name must be zero-length for a standard wallet policy\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NO_NAME_FOR_DEFAULT_POLICY);
                return false;
            }

            // unlike in get_wallet_address, we do not check if the address_index is small:
            // if funds were already sent there, there is no point in preventing to spend them.
        }
    }

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
                                                    st->wallet_header.keys_info_merkle_root,
                                                    st->wallet_header.n_keys,
                                                    key_index,
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;  // should never happen
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    if (parse_policy_map_key_info(&key_info_buffer, &key_info, st->wallet_header.version) == -1) {
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

static bool fill_keyexpr_info_if_internal(dispatcher_context_t *dc,
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
        const musig_aggr_key_info_t *musig_info =
            r_musig_aggr_key_info(&keyexpr_info->key_expression_ptr->m.musig_info);
        const uint16_t *key_indexes = r_uint16(&musig_info->key_indexes);

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

typedef struct {
    sign_psbt_state_t *state;
    input_info_t *input;
} input_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(dispatcher_context_t *dc,
                                input_keys_callback_data_t *callback_data,
                                const merkleized_map_commitment_t *map_commitment,
                                int index,
                                buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);
        if (key_type == PSBT_IN_WITNESS_UTXO) {
            callback_data->input->has_witnessUtxo = true;
        } else if (key_type == PSBT_IN_NON_WITNESS_UTXO) {
            callback_data->input->has_nonWitnessUtxo = true;
        } else if (key_type == PSBT_IN_REDEEM_SCRIPT) {
            callback_data->input->has_redeemScript = true;
        } else if (key_type == PSBT_IN_SIGHASH_TYPE) {
            callback_data->input->has_sighash_type = true;
        } else if (key_type == PSBT_IN_BIP32_DERIVATION ||
                   key_type == PSBT_IN_TAP_BIP32_DERIVATION) {
            if (callback_data->state->has_no_wallet_policy) {
                return;  // only relevant if there is a wallet policy
            }
            derivation_info_t derivation_info;
            int res = read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                       key_type,
                                                                       data,
                                                                       map_commitment,
                                                                       index,
                                                                       &derivation_info);
            if (res < 0) {
                // there was an error; we keep track of it so an error SW is sent later
                callback_data->input->in_out.unexpected_pubkey_error = true;
            } else if (res == 0) {
                // nothing to do
            } else if (res == 1) {
                in_out_info_t *in_out = &callback_data->input->in_out;
                for (size_t i = 0; i < callback_data->state->n_internal_key_expressions; i++) {
                    keyexpr_info_t *key_expr = &callback_data->state->internal_key_expressions[i];
                    if (is_keyexpr_compatible_with_derivation_info(key_expr, &derivation_info)) {
                        key_expr->to_sign = true;

                        bool is_change =
                            key_expr->key_expression_ptr->num_second ==
                            derivation_info.key_origin[derivation_info.derivation_len - 2];

                        in_out->key_expression_found = true;
                        in_out->is_change = is_change;
                        in_out->address_index =
                            derivation_info.key_origin[derivation_info.derivation_len - 1];
                    }
                }
            } else {
                LEDGER_ASSERT(false, "Unreachable code");
            }
        } else if (key_type == PSBT_IN_MUSIG2_PUB_NONCE) {
            callback_data->state->has_musig2_pub_nonces = true;
        }
    }
}

static bool fill_internal_key_expressions(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    size_t cur_index = 0;

    st->n_internal_key_expressions = 0;
    memset(st->internal_key_expressions, 0, sizeof(st->internal_key_expressions));

    // find and parse our registered key info in the wallet
    keyexpr_info_t keyexpr_info;
    memset(&keyexpr_info, 0, sizeof(keyexpr_info_t));
    while (true) {
        keyexpr_info.index = cur_index;
        const policy_node_t *tapleaf_ptr = NULL;
        int n_key_expressions = get_keyexpr_by_index(st->wallet_policy_map,
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
            if (st->n_internal_key_expressions >= MAX_INTERNAL_KEY_EXPRESSIONS) {
                PRINTF("Too many internal key expressions. The maximum supported is %d\n",
                       MAX_INTERNAL_KEY_EXPRESSIONS);
                SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_WALLET_POLICY_TOO_MANY_INTERNAL_KEYS);
                return false;
            }

            // store this key info, as it's internal
            memcpy(&st->internal_key_expressions[st->n_internal_key_expressions],
                   &keyexpr_info,
                   sizeof(keyexpr_info_t));
            ++st->n_internal_key_expressions;
        }

        ++cur_index;
    }

    if (st->n_internal_key_expressions == 0) {
        PRINTF("No internal key found in wallet policy");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_WALLET_POLICY_HAS_NO_INTERNAL_KEY);
        return false;
    }

    return true;
}

static bool __attribute__((noinline))
preprocess_inputs(dispatcher_context_t *dc,
                  sign_psbt_state_t *st,
                  sign_psbt_cache_t *sign_psbt_cache,
                  uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(internal_inputs, 0, BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN));

    if (!st->has_no_wallet_policy) {
        if (!fill_internal_key_expressions(dc, st)) return false;
    }

    // process each input
    for (unsigned int cur_input_index = 0; cur_input_index < st->n_inputs; cur_input_index++) {
        input_info_t input;
        memset(&input, 0, sizeof(input));

        input_keys_callback_data_t callback_data = {.input = &input, .state = st};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->inputs_root,
            st->n_inputs,
            cur_input_index,
            (merkle_tree_elements_callback_t) input_keys_callback,
            &input.in_out.map);
        if (res < 0) {
            PRINTF("Failed to process input map\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (input.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // either witness utxo or non-witness utxo (or both) must be present.
        if (!input.has_nonWitnessUtxo && !input.has_witnessUtxo) {
            PRINTF("No witness utxo nor non-witness utxo present in input.\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_AND_WITNESSUTXO);
            return false;
        }

        // validate non-witness utxo (if present) and witness utxo (if present)

        if (input.has_nonWitnessUtxo) {
            uint8_t prevout_hash[32];

            // check if the prevout_hash of the transaction matches the computed one from the
            // non-witness utxo
            if (0 > call_get_merkleized_map_value(dc,
                                                  &input.in_out.map,
                                                  (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                  1,
                                                  prevout_hash,
                                                  sizeof(prevout_hash))) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // request non-witness utxo, and get the prevout's value and scriptpubkey
            // Also checks that the recomputed transaction hash matches with prevout_hash.
            if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                                 &input.in_out.map,
                                                                 &input.prevout_amount,
                                                                 input.in_out.scriptPubKey,
                                                                 &input.in_out.scriptPubKey_len,
                                                                 prevout_hash)) {
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED);
                return false;
            }

            st->inputs_total_amount += input.prevout_amount;
        }

        if (input.has_witnessUtxo) {
            size_t wit_utxo_scriptPubkey_len;
            uint8_t wit_utxo_scriptPubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            uint64_t wit_utxo_prevout_amount;

            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input.in_out.map,
                                                              &wit_utxo_prevout_amount,
                                                              wit_utxo_scriptPubkey,
                                                              &wit_utxo_scriptPubkey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            };

            if (input.has_nonWitnessUtxo) {
                // we already know the scriptPubKey, but we double check that it matches
                if (input.in_out.scriptPubKey_len != wit_utxo_scriptPubkey_len ||
                    memcmp(input.in_out.scriptPubKey,
                           wit_utxo_scriptPubkey,
                           wit_utxo_scriptPubkey_len) != 0 ||
                    input.prevout_amount != wit_utxo_prevout_amount) {
                    PRINTF(
                        "scriptPubKey or amount in non-witness utxo doesn't match with witness "
                        "utxo\n");
                    SEND_SW_EC(dc,
                               SW_INCORRECT_DATA,
                               EC_SIGN_PSBT_NONWITNESSUTXO_AND_WITNESSUTXO_MISMATCH);
                    return false;
                }
            } else {
                // we extract the scriptPubKey and prevout amount from the witness utxo
                st->inputs_total_amount += wit_utxo_prevout_amount;

                input.prevout_amount = wit_utxo_prevout_amount;
                input.in_out.scriptPubKey_len = wit_utxo_scriptPubkey_len;
                memcpy(input.in_out.scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
            }
        }

        if (!st->has_no_wallet_policy) {
            // check if the input is internal

            int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &input.in_out, true);
            if (is_internal < 0) {
                PRINTF("Error checking if input %d is internal\n", cur_input_index);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            } else if (is_internal == 0) {
                ++st->n_external_inputs;

                PRINTF("INPUT %d is external\n", cur_input_index);
                continue;
            } else {
                bitvector_set(internal_inputs, cur_input_index, 1);
                st->internal_inputs_total_amount += input.prevout_amount;
            }
        }

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);

        // For legacy inputs, the non-witness utxo must be present
        // and the witness utxo must be absent.
        // (This assumption is later relied on when signing).
        if (segwit_version == -1) {
            if (!input.has_nonWitnessUtxo || input.has_witnessUtxo) {
                PRINTF("Legacy inputs must have the non-witness utxo, but no witness utxo.\n");
                SEND_SW_EC(
                    dc,
                    SW_INCORRECT_DATA,
                    EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_OR_UNEXPECTED_WITNESSUTXO_FOR_LEGACY);
                return false;
            }
        }

        // For segwitv0 inputs, the non-witness utxo _should_ be present; we show a warning
        // to the user otherwise, but we continue nonetheless on approval
        if (segwit_version == 0 && !input.has_nonWitnessUtxo) {
            PRINTF("Non-witness utxo missing for segwitv0 input. Will show a warning.\n");
            st->warnings.missing_nonwitnessutxo = true;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !input.has_witnessUtxo) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_WITNESSUTXO_FOR_SEGWIT);
            return false;
        }

        // If any of the internal inputs has a sighash type that is not SIGHASH_DEFAULT or
        // SIGHASH_ALL, we show a warning

        if (input.has_sighash_type) {
            // get the sighash_type
            if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                          &input.in_out.map,
                                                          (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                          1,
                                                          &input.sighash_type)) {
                PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // only support ALL for legacy or segwitv0, and ALL/DEFAULT for taproot
            if (((segwit_version > 0) && (input.sighash_type == SIGHASH_DEFAULT)) ||
                (input.sighash_type == SIGHASH_ALL)) {
                PRINTF("Sighash type is SIGHASH_DEFAULT or SIGHASH_ALL\n");
            } else {
                PRINTF("Sighash flags are not supported\n");
                SEND_SW(dc, SW_NOT_SUPPORTED);
                return false;
            }
        }
    }

    return true;
}

typedef struct {
    sign_psbt_state_t *state;
    output_info_t *output;
} output_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(dispatcher_context_t *dc,
                                 output_keys_callback_data_t *callback_data,
                                 const merkleized_map_commitment_t *map_commitment,
                                 int index,
                                 buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if ((key_type == PSBT_OUT_BIP32_DERIVATION || key_type == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !callback_data->output->in_out.key_expression_found) {
            if (callback_data->state->has_no_wallet_policy) {
                return;  // only relevant if there is a wallet policy
            }
            derivation_info_t derivation_info;
            int res = read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                       key_type,
                                                                       data,
                                                                       map_commitment,
                                                                       index,
                                                                       &derivation_info);
            if (res < 0) {
                // there was an error; we keep track of it so an error SW is sent later
                callback_data->output->in_out.unexpected_pubkey_error = true;
            } else if (res == 1) {
                in_out_info_t *in_out = &callback_data->output->in_out;
                for (size_t i = 0; i < callback_data->state->n_internal_key_expressions; i++) {
                    const keyexpr_info_t *key_expr =
                        &callback_data->state->internal_key_expressions[i];
                    if (is_keyexpr_compatible_with_derivation_info(key_expr, &derivation_info)) {
                        bool is_change =
                            key_expr->key_expression_ptr->num_second ==
                            derivation_info.key_origin[derivation_info.derivation_len - 2];

                        in_out->key_expression_found = true;
                        in_out->is_change = is_change;
                        in_out->address_index =
                            derivation_info.key_origin[derivation_info.derivation_len - 1];
                        // unlike for inputs, where we want to keep track of all the key expressions
                        // we want to sign for, here we only care about finding the relevant info
                        // for this output. Therefore, we're done as soon as we have a match.
                        break;
                    }
                }
            }
        }
    }
}

static bool __attribute__((noinline))
preprocess_outputs(dispatcher_context_t *dc,
                   sign_psbt_state_t *st,
                   sign_psbt_cache_t *sign_psbt_cache,
                   uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's internal (that is, a change address).
     *  Also computes the total amount of change outputs, and the total of all outputs.
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(&st->outputs, 0, sizeof(st->outputs));

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        output_info_t output;
        memset(&output, 0, sizeof(output));

        output_keys_callback_data_t callback_data = {.output = &output, .state = st};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->outputs_root,
            st->n_outputs,
            cur_output_index,
            (merkle_tree_elements_callback_t) output_keys_callback,
            &output.in_out.map);

        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (output.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // Read output amount
        uint8_t raw_result[8];

        // Read the output's amount
        int result_len = call_get_merkleized_map_value(dc,
                                                       &output.in_out.map,
                                                       (uint8_t[]){PSBT_OUT_AMOUNT},
                                                       1,
                                                       raw_result,
                                                       sizeof(raw_result));
        if (result_len != 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t value = read_u64_le(raw_result, 0);

        output.value = value;
        st->outputs.total_amount += value;

        // Read the output's scriptPubKey
        result_len = call_get_merkleized_map_value(dc,
                                                   &output.in_out.map,
                                                   (uint8_t[]){PSBT_OUT_SCRIPT},
                                                   1,
                                                   output.in_out.scriptPubKey,
                                                   sizeof(output.in_out.scriptPubKey));

        if (result_len < 0 || result_len > (int) sizeof(output.in_out.scriptPubKey)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.in_out.scriptPubKey_len = result_len;

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &output.in_out, false);

        if (is_internal < 0) {
            PRINTF("Error checking if output %d is internal\n", cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            // external output, user needs to validate
            bitvector_set(internal_outputs, cur_output_index, 0);

            // cache external output scripts
            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                st->outputs.output_script_lengths[external_outputs_count] =
                    output.in_out.scriptPubKey_len;
                memcpy(st->outputs.output_scripts[external_outputs_count],
                       output.in_out.scriptPubKey,
                       output.in_out.scriptPubKey_len);
                st->outputs.output_amounts[external_outputs_count] = value;
            }

            ++external_outputs_count;
        } else {
            // valid change address, nothing to show to the user

            bitvector_set(internal_outputs, cur_output_index, 1);

            st->outputs.change_total_amount += output.value;
            ++st->outputs.n_change;
        }
    }

    st->n_external_outputs = external_outputs_count;

    if (st->inputs_total_amount < st->outputs.total_amount) {
        PRINTF("Negative fee is invalid\n");
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->outputs.n_change > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many outputs
        // (possibly economically not worth spending).
        PRINTF("Too many change outputs: %d\n", st->outputs.n_change);
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS);
        return false;
    }

    return true;
}

static bool __attribute__((noinline)) yield_signature(dispatcher_context_t *dc,
                                                      sign_psbt_state_t *st,
                                                      unsigned int input_index,
                                                      const uint8_t *pubkey,
                                                      uint8_t pubkey_len,
                                                      const uint8_t *tapleaf_hash,
                                                      const uint8_t *sig,
                                                      size_t sig_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    // for tapscript signatures, we concatenate the (x-only) pubkey with the tapleaf hash
    uint8_t augm_pubkey_len = pubkey_len + (tapleaf_hash != NULL ? 32 : 0);

    // the pubkey is not output in version 0 of the protocol
    if (st->protocol_version >= 1) {
        dc->add_to_response(&augm_pubkey_len, 1);
        dc->add_to_response(pubkey, pubkey_len);

        if (tapleaf_hash != NULL) {
            dc->add_to_response(tapleaf_hash, 32);
        }
    }

    dc->add_to_response(sig, sig_len);

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    return true;
}

bool __attribute__((noinline)) sign_sighash_ecdsa_and_yield(dispatcher_context_t *dc,
                                                            sign_psbt_state_t *st,
                                                            unsigned int input_index,
                                                            const uint32_t sign_path[],
                                                            size_t sign_path_len,
                                                            uint8_t sighash_byte,
                                                            uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t sig[MAX_DER_SIG_LEN + 1];  // extra byte for the appended sighash-type

    uint8_t pubkey[33];

    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(sign_path,
                                                         sign_path_len,
                                                         sighash,
                                                         pubkey,
                                                         sig,
                                                         NULL);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // append the sighash type byte
    sig[sig_len++] = sighash_byte;

    if (!yield_signature(dc, st, input_index, pubkey, 33, NULL, sig, sig_len)) return false;

    return true;
}

bool __attribute__((noinline)) sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                                              sign_psbt_state_t *st,
                                                              unsigned int input_index,
                                                              const uint32_t sign_path[],
                                                              size_t sign_path_len,
                                                              const uint8_t *tweak_data,
                                                              size_t tweak_data_len,
                                                              const uint8_t *tapleaf_hash,
                                                              uint8_t sighash_byte,
                                                              const uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

    bool error = false;
    cx_ecfp_private_key_t private_key = {0};

    // IMPORTANT: Since we do not use any syscall that might throw an exception, it is safe to avoid
    // using the TRY/CATCH block to ensure zeroing sensitive data.

    do {  // block executed once, only to allow safely breaking out on error

        uint8_t *seckey =
            private_key.d;  // convenience alias (entirely within the private_key struct)

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            error = true;
            break;
        }

        if (tweak_data != NULL) {
            crypto_tr_tweak_seckey(seckey, tweak_data, tweak_data_len, seckey);
        }

        // generate corresponding public key
        unsigned int err =
            cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_tweaked, &private_key, 1);
        if (err != CX_OK) {
            error = true;
            break;
        }

        err = cx_ecschnorr_sign_no_throw(&private_key,
                                         CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                         CX_SHA256,
                                         sighash,
                                         32,
                                         sig,
                                         &sig_len);
        if (err != CX_OK) {
            error = true;
        }
    } while (false);

    explicit_bzero(&private_key, sizeof(private_key));

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // only append the sighash type byte if it is non-zero
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        sig[sig_len++] = sighash_byte;
    }

    if (!yield_signature(dc,
                         st,
                         input_index,
                         pubkey_tweaked.W + 1,  // x-only pubkey, hence take only the x-coordinate
                         32,
                         tapleaf_hash,
                         sig,
                         sig_len))
        return false;

    return true;
}

static bool __attribute__((noinline)) sign_transaction_input(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             sign_psbt_cache_t *sign_psbt_cache,
                                                             signing_state_t *signing_state,
                                                             keyexpr_info_t *keyexpr_info,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // if the psbt does not specify the sighash flag for this input, the default
    // changes depending on the type of spend; therefore, we set it later.
    if (input->has_sighash_type) {
        // Get sighash type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &input->in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &input->sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    // compute signing derivation path
    uint32_t sign_path[MAX_BIP32_PATH_STEPS];

    for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
        sign_path[i] = keyexpr_info->key_derivation[i];
    }
    sign_path[keyexpr_info->key_derivation_length] =
        input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                : keyexpr_info->key_expression_ptr->num_first;
    sign_path[keyexpr_info->key_derivation_length + 1] = input->in_out.address_index;

    int sign_path_len = keyexpr_info->key_derivation_length + 2;

    // Sign as segwit input iff it has a witness utxo
    if (!input->has_witnessUtxo) {
        LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                      "Only plain key expressions for legacy inputs");
        // sign legacy P2PKH or P2SH

        // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

        uint64_t tmp;  // unused
        if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                             &input->in_out.map,
                                                             &tmp,
                                                             input->in_out.scriptPubKey,
                                                             &input->in_out.scriptPubKey_len,
                                                             NULL)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t sighash_byte =
            input->has_sighash_type ? (uint8_t) input->sighash_type : SIGHASH_ALL;

        uint8_t sighash[32];
        if (!compute_sighash_legacy(dc,
                                    st,
                                    &input->in_out.map,
                                    cur_input_index,
                                    input->has_redeemScript,
                                    input->in_out.scriptPubKey,
                                    input->in_out.scriptPubKey_len,
                                    sighash_byte,
                                    sighash)) {
            return false;
        }

        if (!sign_sighash_ecdsa_and_yield(dc,
                                          st,
                                          cur_input_index,
                                          sign_path,
                                          sign_path_len,
                                          sighash_byte,
                                          sighash)) {
            return false;
        }
    } else {
        {
            uint64_t amount;
            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input->in_out.map,
                                                              &amount,
                                                              input->in_out.scriptPubKey,
                                                              &input->in_out.scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            if (input->has_redeemScript) {
                // Get redeemScript
                // The redeemScript cannot be longer than standard scriptPubKeys for
                // wrapped segwit transactions that we support
                uint8_t redeemScript[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

                int redeemScript_length =
                    call_get_merkleized_map_value(dc,
                                                  &input->in_out.map,
                                                  (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                  1,
                                                  redeemScript,
                                                  sizeof(redeemScript));
                if (redeemScript_length < 0) {
                    PRINTF("Error fetching redeem script\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }

                uint8_t p2sh_redeemscript[2 + 20 + 1];
                p2sh_redeemscript[0] = 0xa9;
                p2sh_redeemscript[1] = 0x14;
                crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
                p2sh_redeemscript[22] = 0x87;

                if (input->in_out.scriptPubKey_len != 23 ||
                    memcmp(input->in_out.scriptPubKey, p2sh_redeemscript, 23) != 0) {
                    PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
                    SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISMATCHING_REDEEM_SCRIPT);
                    return false;
                }

                input->script_len = redeemScript_length;
                memcpy(input->script, redeemScript, redeemScript_length);
            } else {
                input->script_len = input->in_out.scriptPubKey_len;
                memcpy(input->script, input->in_out.scriptPubKey, input->in_out.scriptPubKey_len);
            }
        }

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);
        uint8_t sighash[32];
        if (segwit_version == 0) {
            LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                          "Only plain key expressions for SegwitV0 inputs");
            // segwitv0 inputs default to SIGHASH_ALL
            uint8_t sighash_byte =
                input->has_sighash_type ? (uint8_t) input->sighash_type : SIGHASH_ALL;

            if (!compute_sighash_segwitv0(dc,
                                          st,
                                          &signing_state->tx_hashes,
                                          &input->in_out.map,
                                          cur_input_index,
                                          input->script,
                                          input->script_len,
                                          sighash_byte,
                                          sighash))
                return false;

            if (!sign_sighash_ecdsa_and_yield(dc,
                                              st,
                                              cur_input_index,
                                              sign_path,
                                              sign_path_len,
                                              sighash_byte,
                                              sighash))
                return false;
        } else if (segwit_version == 1) {
            // segwitv1 inputs default to SIGHASH_DEFAULT
            uint8_t sighash_byte =
                input->has_sighash_type ? (uint8_t) input->sighash_type : SIGHASH_DEFAULT;

            if (!compute_sighash_segwitv1(
                    dc,
                    st,
                    &signing_state->tx_hashes,
                    &input->in_out.map,
                    cur_input_index,
                    input->in_out.scriptPubKey,
                    input->in_out.scriptPubKey_len,
                    keyexpr_info->is_tapscript ? keyexpr_info->tapleaf_hash : NULL,
                    sighash_byte,
                    sighash))
                return false;

            policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;
            if (!keyexpr_info->is_tapscript && !isnull_policy_node_tree(&policy->tree)) {
                // keypath spend, we compute the taptree hash
                if (0 > compute_taptree_hash(
                            dc,
                            &(wallet_derivation_info_t){
                                .address_index = input->in_out.address_index,
                                .change = input->in_out.is_change ? 1 : 0,
                                .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                .n_keys = st->wallet_header.n_keys,
                                .wallet_version = st->wallet_header.version,
                                .sign_psbt_cache = sign_psbt_cache},
                            r_policy_node_tree(&policy->tree),
                            input->taptree_hash)) {
                    PRINTF("Error while computing taptree hash\n");
                    SEND_SW(dc, SW_BAD_STATE);
                    return false;
                }
            }

            const uint8_t *tweak_data = NULL;
            size_t tweak_data_len = 0;
            const uint8_t *tapleaf_hash = NULL;
            if (!keyexpr_info->is_tapscript) {
                // keypath spend;
                if (isnull_policy_node_tree(&policy->tree)) {
                    // tweak as specified in BIP-86 and BIP-386
                    tweak_data = (uint8_t[]){};
                    tweak_data_len = 0;
                } else {
                    // tweak with the taptree hash, per BIP-341
                    tweak_data = input->taptree_hash;
                    tweak_data_len = 32;
                }
            } else {
                // tapscript, we need to yield the tapleaf hash together with the pubkey
                tapleaf_hash = keyexpr_info->tapleaf_hash;
            }

            if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
                if (!sign_sighash_schnorr_and_yield(dc,
                                                    st,
                                                    cur_input_index,
                                                    sign_path,
                                                    sign_path_len,
                                                    tweak_data,
                                                    tweak_data_len,
                                                    tapleaf_hash,
                                                    sighash_byte,
                                                    sighash))
                    return false;
            } else if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_MUSIG) {
                // we only execute MuSig2 round 2 if there are pubnonces in the PSBT
                // (otherwise, we are only here just for the other non-musig2 partial signatures)
                if (st->has_musig2_pub_nonces && !sign_sighash_musig_and_yield(dc,
                                                                               st,
                                                                               signing_state,
                                                                               keyexpr_info,
                                                                               input,
                                                                               cur_input_index,
                                                                               sighash))
                    return false;
            } else {
                LEDGER_ASSERT(false, "Unreachable");
            }

        } else {
            SEND_SW(dc, SW_BAD_STATE);  // can't happen
            return false;
        }
    }
    return true;
}

static bool __attribute__((noinline))
fill_taproot_keyexpr_info(dispatcher_context_t *dc,
                          sign_psbt_state_t *st,
                          const input_info_t *input,
                          const policy_node_t *tapleaf_ptr,
                          keyexpr_info_t *keyexpr_info,
                          sign_psbt_cache_t *sign_psbt_cache) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    wallet_derivation_info_t wdi = {.wallet_version = st->wallet_header.version,
                                    .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                    .n_keys = st->wallet_header.n_keys,
                                    .change = input->in_out.is_change,
                                    .address_index = input->in_out.address_index,
                                    .sign_psbt_cache = sign_psbt_cache};

    // we compute the tapscript once just to compute its length
    // this avoids having to store it
    int tapscript_len =
        get_wallet_internal_script_hash(dc, tapleaf_ptr, &wdi, WRAPPED_SCRIPT_TYPE_TAPSCRIPT, NULL);
    if (tapscript_len < 0) {
        PRINTF("Failed to compute tapleaf script\n");
        return false;
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    // we compute it again to get add the actual script code to the hash computation
    if (0 > get_wallet_internal_script_hash(dc,
                                            tapleaf_ptr,
                                            &wdi,
                                            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                            &hash_context.header)) {
        return false;  // should never happen!
    }
    crypto_hash_digest(&hash_context.header, keyexpr_info->tapleaf_hash, 32);

    return true;
}

static bool __attribute__((noinline)) produce_musig2_pubnonces(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    signing_state_t *signing_state,
    sign_psbt_cache_t *sign_psbt_cache,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        return true;  // nothing to do
    }

    // Iterate over all the key expressions that correspond to keys owned by us
    for (size_t i_keyexpr = 0; i_keyexpr < st->n_internal_key_expressions; i_keyexpr++) {
        keyexpr_info_t *keyexpr_info = &st->internal_key_expressions[i_keyexpr];
        if (!keyexpr_info->to_sign ||
            keyexpr_info->key_expression_ptr->type != KEY_EXPRESSION_MUSIG) {
            continue;
        }

        if (!fill_keyexpr_info_if_internal(dc, st, keyexpr_info)) {
            continue;
        }

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            if (bitvector_get(internal_inputs, i)) {
                input_info_t input;
                memset(&input, 0, sizeof(input));

                input_keys_callback_data_t callback_data = {.input = &input, .state = st};
                int res = call_get_merkleized_map_with_callback(
                    dc,
                    (void *) &callback_data,
                    st->inputs_root,
                    st->n_inputs,
                    i,
                    (merkle_tree_elements_callback_t) input_keys_callback,
                    &input.in_out.map);
                if (res < 0) {
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }

                // TODO: code duplication with sign_transaction_input
                if (keyexpr_info->tapleaf_ptr != NULL) {
                    if (!fill_taproot_keyexpr_info(dc,
                                                   st,
                                                   &input,
                                                   keyexpr_info->tapleaf_ptr,
                                                   keyexpr_info,
                                                   sign_psbt_cache)) {
                        return false;
                    }
                }

                policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;
                if (!isnull_policy_node_tree(&policy->tree)) {
                    if (0 > compute_taptree_hash(
                                dc,
                                &(wallet_derivation_info_t){
                                    .address_index = input.in_out.address_index,
                                    .change = input.in_out.is_change ? 1 : 0,
                                    .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                    .n_keys = st->wallet_header.n_keys,
                                    .wallet_version = st->wallet_header.version,
                                    .sign_psbt_cache = sign_psbt_cache},
                                r_policy_node_tree(&policy->tree),
                                input.taptree_hash)) {
                        PRINTF("Error while computing taptree hash\n");
                        SEND_SW(dc, SW_BAD_STATE);
                        return false;
                    }
                }

                if (!produce_and_yield_pubnonce(dc, st, signing_state, keyexpr_info, &input, i)) {
                    return false;
                }
            }
        }
    }

    return true;
}

static bool __attribute__((noinline)) sign_internal_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    sign_psbt_cache_t *sign_psbt_cache,
    signing_state_t *signing_state,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Iterate over all the key expressions that correspond to keys owned by us
    for (size_t i_keyexpr = 0; i_keyexpr < st->n_internal_key_expressions; i_keyexpr++) {
        keyexpr_info_t *keyexpr_info = &st->internal_key_expressions[i_keyexpr];
        if (!keyexpr_info->to_sign) {
            continue;
        }

        if (!fill_keyexpr_info_if_internal(dc, st, keyexpr_info)) {
            continue;
        }

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            if (bitvector_get(internal_inputs, i)) {
                input_info_t input;
                memset(&input, 0, sizeof(input));

                input_keys_callback_data_t callback_data = {.input = &input, .state = st};
                int res = call_get_merkleized_map_with_callback(
                    dc,
                    (void *) &callback_data,
                    st->inputs_root,
                    st->n_inputs,
                    i,
                    (merkle_tree_elements_callback_t) input_keys_callback,
                    &input.in_out.map);
                if (res < 0) {
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }
                if (keyexpr_info->tapleaf_ptr != NULL &&
                    !fill_taproot_keyexpr_info(dc,
                                               st,
                                               &input,
                                               keyexpr_info->tapleaf_ptr,
                                               keyexpr_info,
                                               sign_psbt_cache)) {
                    return false;
                }

                if (!sign_transaction_input(dc,
                                            st,
                                            sign_psbt_cache,
                                            signing_state,
                                            keyexpr_info,
                                            &input,
                                            i)) {
                    // we do not send a status word, since sign_transaction_input
                    // already does it on failure
                    return false;
                }
            }
        }
    }

    return true;
}

// TODO: validate_and_display_transaction and sign_custom_inputs should perhaps not have access
// to the entire sign_psbt_state_t struct, which should be opaque.
// Can we pass a subset of fields? What is it needed in derived apps?

__attribute__((weak)) // derived applications must replace this
bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    UNUSED(st), UNUSED(internal_inputs), UNUSED(internal_outputs);

    // if the derived application doesn't immplement this, we stop with an error
    PRINTF("Derived applications must implement validate_and_display_transaction\n");
    SEND_SW(dc, SW_NOT_SUPPORTED);
    return false;
}

__attribute__((weak)) // derived applications can replace this
bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    UNUSED(dc), UNUSED(st), UNUSED(tx_hashes), UNUSED(internal_inputs);

    return true;
}

// We declare this in the global space in order to use less stack space, since BOLOS enforces on
// some devices an 8kb stack limit.
// Once this is resolved in BOLOS, we should move this to the function scope to avoid unnecessarily
// reserving RAM that can only be used for the signing flow (which, at time of writing, is the most
// RAM-intensive operation command of the app).
sign_psbt_cache_t G_sign_psbt_cache;

void handler_sign_psbt(dispatcher_context_t *dc, uint8_t protocol_version) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    /* Setting transaction loading information screen */
    ui_set_processing_screen_text(GA_LOADING_TRANSACTION);

    sign_psbt_state_t st;
    memset(&st, 0, sizeof(st));

    st.protocol_version = protocol_version;

    // read APDU inputs, initialize global state and read global PSBT map
    if (!init_global_state(dc, &st)) return;

    sign_psbt_cache_t *cache = &G_sign_psbt_cache;
    init_sign_psbt_cache(cache);

    // bitmap to keep track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];
    memset(internal_inputs, 0, sizeof(internal_inputs));

    // bitmap to keep track of which inputs are internal
    uint8_t internal_outputs[BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)];
    memset(internal_outputs, 0, sizeof(internal_outputs));

    /** Inputs verification flow
     *
     *  Go through all the inputs:
     *  - verify the non_witness_utxo
     *  - compute value spent
     *  - detect internal inputs that should be signed, and if there are external inputs or unusual
     * sighashes
     */
    if (!preprocess_inputs(dc, &st, cache, internal_inputs)) return;

    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Check if it's an acceptable output.
     */
    if (!preprocess_outputs(dc, &st, cache, internal_outputs)) return;

    // check if we're only executing the MuSig2 Round 1
    bool only_signing_for_musig = true;
    for (size_t i = 0; i < st.n_internal_key_expressions; i++) {
        if (st.internal_key_expressions[i].to_sign &&
            st.internal_key_expressions[i].key_expression_ptr->type != KEY_EXPRESSION_MUSIG) {
            // at least one of the key expressions we're signing for is not a MuSig
            only_signing_for_musig = false;
        }
    }

    signing_state_t signing_state;
    memset(&signing_state, 0, sizeof(signing_state));

    // Make sure that the signing state for MuSig2 is initialized correctly
    musigsession_initialize_signing_state(&signing_state.musig);

    // compute all the tx-wide hashes
    if (!compute_tx_hashes(dc, &st, &signing_state.tx_hashes)) {
        return;
    }

    if (!st.has_musig2_pub_nonces) {
        // We execute the first round of MuSig for any musig2 key expression, producing the
        // pubnonces; this does not involve the private keys, therefore we can do it without user
        // confirmation

        if (!produce_musig2_pubnonces(dc, &st, &signing_state, cache, internal_inputs)) {
            return;
        }
    }

    // we execute the signing flow only if we're expected to produce any signature
    // (including, possibly, any MuSig2 partial signature from Round 2 of MuSig2)
    if (!only_signing_for_musig || st.has_musig2_pub_nonces) {
        /** TRANSACTION CONFIRMATION
         *
         * Derived apps implement this functionality by replacing the
         * validate_and_display_transaction method.
         */
        if (!validate_and_display_transaction(dc, &st, internal_inputs, internal_outputs)) return;

        // Signing always takes some time, so we rather not wait before showing the spinner
        io_show_processing_screen();

        /** SIGNING FLOW
         *
         * For each internal key expression, and for each internal input, sign using the
         * appropriate algorithm.
         */
        if (!st.has_no_wallet_policy) {
            int sign_result = sign_internal_inputs(dc, &st, cache, &signing_state, internal_inputs);
            if (!sign_result) {
                ui_post_processing_confirm_transaction(dc, false);
                return;
            }
        }

        /**
         * For any input that is not internal, it is the responsibility of the
         * derived app to sign it.
         */
        if (!sign_custom_inputs(dc, &st, &signing_state.tx_hashes, internal_inputs)) {
            ui_post_processing_confirm_transaction(dc, false);
            return;
        }

#ifdef HAVE_SWAP
        // Only if called from swap, the app should terminate after sending the response
        if (G_called_from_swap) {
            G_swap_state.should_exit = true;
        }
#endif /* HAVE_SWAP */
    }

    // MuSig2: if there is an active session at the end of round 1, we move it to persistent
    // storage. It is important that this is only done at the very end of the signing process,
    // end only if everything is successful.
    musigsession_commit(&signing_state.musig);

    SEND_SW(dc, SW_OK);
}
