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
extern const char GA_SIGNING_TRANSACTION[];

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

    {
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

    if (!fill_internal_key_expressions(dc, st)) return false;

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

        if (input.prevout_amount > BITCOIN_TOTAL_SUPPLY) {
            // sanity check to avoid overflows in amounts
            PRINTF("Input amount exceed Bitcoin total supply!\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // check if the input is internal; if not, continue

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &input.in_out, true);
        if (is_internal < 0) {
            PRINTF("Error checking if input %d is internal\n", cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            ++st->n_external_inputs;
            st->warnings.external_inputs = true;
            PRINTF("INPUT %d is external\n", cur_input_index);
            continue;
        }

        bitvector_set(internal_inputs, cur_input_index, 1);

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

        if (!input.has_sighash_type) {
            continue;
        }

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

        if (((segwit_version > 0) && (input.sighash_type == SIGHASH_DEFAULT)) ||
            (input.sighash_type == SIGHASH_ALL)) {
            PRINTF("Sighash type is SIGHASH_DEFAULT or SIGHASH_ALL\n");

        } else if ((segwit_version >= 0) &&
                   ((input.sighash_type == SIGHASH_NONE) ||
                    (input.sighash_type == SIGHASH_SINGLE) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_ALL)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_NONE)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE)))) {
            PRINTF("Sighash type is non-default, will show a warning.\n");
            st->warnings.non_default_sighash = true;
        } else {
            PRINTF("Unsupported sighash\n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }

        if (((input.sighash_type & SIGHASH_SINGLE) == SIGHASH_SINGLE) &&
            (cur_input_index >= st->n_outputs)) {
            PRINTF("SIGHASH_SINGLE with input idx >= n_output is not allowed \n");
            SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE);
            return false;
        }
    }

    if (st->n_external_inputs == st->n_inputs) {
        // no internal inputs, nothing to sign
        PRINTF("No internal inputs. Aborting\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
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

        if (value > BITCOIN_TOTAL_SUPPLY) {
            // sanity check to avoid overflows in amounts
            PRINTF("Output amount exceed Bitcoin total supply!\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

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

#ifdef HAVE_SWAP
static bool __attribute__((noinline))
execute_swap_checks(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Swap feature: check that wallet policy is a default one
    if (!st->is_wallet_default) {
        PRINTF("Must be a default wallet policy for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY);
        finalize_exchange_sign_transaction(false);
    }

    // No external inputs allowed
    if (st->n_external_inputs > 0) {
        PRINTF("External inputs not allowed in swap transactions\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS);
        finalize_exchange_sign_transaction(false);
    }

    if (st->warnings.missing_nonwitnessutxo || st->warnings.non_default_sighash) {
        // Do not allow transactions with missing non-witness utxos or non-default sighash flags
        PRINTF(
            "Missing non-witness utxo or non-default sighash flags are not allowed during swaps\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    // The index of the swap destination address in the cache of external outputs.
    // NB: this is _not_ the output index in the transaction, as change outputs are skipped.
    int swap_dest_idx = -1;

    if (G_swap_state.mode == SWAP_MODE_STANDARD) {
        swap_dest_idx = 0;

        // There must be only one external output
        if (st->n_external_outputs != 1) {
            PRINTF("Standard swap transaction must have exactly 1 external output\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_CROSSCHAIN) {
        // There must be exactly 2 external outputs; the first is the OP_RETURN

        swap_dest_idx = 1;

        if (st->n_external_outputs != 2) {
            PRINTF("Cross-chain swap transaction must have exactly 2 external outputs\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t *opreturn_script = st->outputs.output_scripts[0];
        size_t opreturn_script_len = st->outputs.output_script_lengths[0];
        size_t opreturn_amount = st->outputs.output_amounts[0];
        if (opreturn_script_len < 4 || opreturn_script[0] != OP_RETURN) {
            PRINTF("The first output must be OP_RETURN <data> for a cross-chain swap\n");
            SEND_SW_EC(dc,
                       SW_FAIL_SWAP,
                       EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t second_byte = opreturn_script[1];
        size_t push_opcode_size = 0;  // the length of the push opcode (1 or 2 bytes)
        size_t data_size = 0;  // the length of the actual data embedded in the OP_RETURN output
        if (2 <= second_byte && second_byte <= 75) {
            push_opcode_size = 1;
            data_size = second_byte;
        } else if (second_byte == OP_PUSHDATA1) {
            // pushing more than 75 bytes requires using OP_PUSHDATA1 <len>
            // instead of a single-byte opcode
            push_opcode_size = 2;
            data_size = opreturn_script[2];
        } else {
            // there are other valid OP_RETURN Scripts that we never expect here,
            // so we don't bother parsing.
            PRINTF("Unsupported or invalid OP_RETURN Script in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure there is a single data push
        if (opreturn_script_len != 1 + push_opcode_size + data_size) {
            PRINTF("Invalid OP_RETURN Script length in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure the output's value is 0
        if (opreturn_amount != 0) {
            PRINTF("OP_RETURN with non-zero value during cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT);
            finalize_exchange_sign_transaction(false);
        }

        // verify the hash in the data payload is the expected one
        uint8_t expected_payin_hash[32];
        cx_hash_sha256(&opreturn_script[1 + push_opcode_size], data_size, expected_payin_hash, 32);
        if (memcmp(G_swap_state.payin_extra_id + 1,
                   expected_payin_hash,
                   sizeof(expected_payin_hash)) != 0) {
            PRINTF("Mismatching payin hash in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_ERROR) {
        // an error was detected in handle_swap_sign_transaction.c::copy_transaction_parameters
        // special case only to improve error reporting in debug mode
        PRINTF("Invalid parameters for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED);
        finalize_exchange_sign_transaction(false);
    } else {
        PRINTF("Unknown swap mode: %d\n", G_swap_state.mode);
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE);
        finalize_exchange_sign_transaction(false);
    }

    LEDGER_ASSERT(0 <= swap_dest_idx && swap_dest_idx < N_CACHED_EXTERNAL_OUTPUTS,
                  "External output index out of range for swap\n");

    // Check that total amount and fees are as expected
    if (fee != G_swap_state.fees) {
        PRINTF("Mismatching fee for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_FEES);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t spent_amount = st->outputs.total_amount - st->outputs.change_total_amount;
    if (spent_amount != G_swap_state.amount) {
        PRINTF("Mismatching spent amount for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_AMOUNT);
        finalize_exchange_sign_transaction(false);
    }

    // Compute this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(st->outputs.output_scripts[swap_dest_idx],
                       st->outputs.output_script_lengths[swap_dest_idx],
                       output_description)) {
        PRINTF("Invalid or unsupported script for external output\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT);
        finalize_exchange_sign_transaction(false);
    }

    size_t output_description_len = strlen(output_description);

    // Check that the external output's address matches the request from app-exchange
    size_t swap_addr_len = strlen(G_swap_state.destination_address);
    if (swap_addr_len != output_description_len ||
        0 !=
            strncmp(G_swap_state.destination_address, output_description, output_description_len)) {
        // address did not match
        PRINTF("Mismatching address for swap\n");
        PRINTF("Expected: ");
        for (size_t i = 0; i < swap_addr_len; i++) {
            PRINTF("%c", G_swap_state.destination_address[i]);
        }
        PRINTF("\n");
        PRINTF("Found: ");
        for (size_t i = 0; i < output_description_len; i++) {
            PRINTF("%c", output_description[i]);
        }
        PRINTF("\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_DESTINATION);
        finalize_exchange_sign_transaction(false);
    }

    return true;
}
#endif /* HAVE_SWAP */

static bool __attribute__((noinline))
display_output(dispatcher_context_t *dc,
               sign_psbt_state_t *st,
               int cur_output_index,
               int external_outputs_count,
               const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
               size_t out_scriptPubKey_len,
               uint64_t out_amount) {
    UNUSED(cur_output_index);

    // show this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(out_scriptPubKey, out_scriptPubKey_len, output_description)) {
        PRINTF("Invalid or unsupported script for output %d\n", cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    // Show address to the user
    if (!ui_transaction_streaming_validate_output(dc,
                                                  external_outputs_count,
                                                  st->n_external_outputs,
                                                  output_description,
                                                  out_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool get_output_script_and_amount(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    size_t output_index,
    uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t *out_scriptPubKey_len,
    uint64_t *out_amount) {
    if (out_scriptPubKey == NULL || out_amount == NULL) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    merkleized_map_commitment_t map;

    // TODO: This might be too slow, as it checks the integrity of the map;
    //       Refactor so that the map key ordering is checked all at the beginning of sign_psbt.
    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, output_index, &map);

    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read output amount
    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &map,
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t value = read_u64_le(raw_result, 0);
    *out_amount = value;

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &map,
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                               1,
                                               out_scriptPubKey,
                                               MAX_OUTPUT_SCRIPTPUBKEY_LEN);

    if (result_len < 0 || result_len > MAX_OUTPUT_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    *out_scriptPubKey_len = result_len;

    return true;
}

static bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /**
     *  Display all the non-change outputs
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        if (!bitvector_get(internal_outputs, cur_output_index)) {
            // external output, user needs to validate
            uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            size_t out_scriptPubKey_len;
            uint64_t out_amount;

            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                // we have the output cached, no need to fetch it again
                out_scriptPubKey_len = st->outputs.output_script_lengths[external_outputs_count];
                memcpy(out_scriptPubKey,
                       st->outputs.output_scripts[external_outputs_count],
                       out_scriptPubKey_len);
                out_amount = st->outputs.output_amounts[external_outputs_count];
            } else if (!get_output_script_and_amount(dc,
                                                     st,
                                                     cur_output_index,
                                                     out_scriptPubKey,
                                                     &out_scriptPubKey_len,
                                                     &out_amount)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            ++external_outputs_count;

            // displays the output. It fails if the output is invalid or not supported
            if (!display_output(dc,
                                st,
                                cur_output_index,
                                external_outputs_count,
                                out_scriptPubKey,
                                out_scriptPubKey_len,
                                out_amount)) {
                return false;
            }
        }
    }

    return true;
}

static bool __attribute__((noinline))
display_warnings(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    // If any input has non-default sighash, we warn the user
    if (st->warnings.non_default_sighash && !ui_warn_nondefault_sighash(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If there are external inputs, it is unsafe to sign, therefore we warn the user
    if (st->warnings.external_inputs && !ui_warn_external_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If any segwitv0 input is missing the non-witness-utxo, we warn the user and ask for
    // confirmation
    if (st->warnings.missing_nonwitnessutxo && !ui_warn_unverified_segwit_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

static bool __attribute__((noinline)) display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    /** INPUT VERIFICATION ALERTS
     *
     * Show warnings and allow users to abort in any of the following conditions:
     * - pre-taproot transaction with unverified inputs (missing non-witness-utxo)
     * - external inputs
     * - non-default sighash types
     */

    // if the value of fees is 10% or more of the amount, and it's more than 100000
    st->warnings.high_fee = 10 * fee >= st->inputs_total_amount && st->inputs_total_amount > 100000;

    // Display warnings/risks information before the transaction title
    // for the both classical and streaming cases.
    if (!display_warnings(dc, st)) {
        return false;
    }

    if (st->n_external_outputs <= MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER) {
        // A simplified flow for most transactions: show it using the classical review if there is
        // exactly 0 (self-transfer) or <= MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER external outputs to show
        // to the user

        bool is_self_transfer = st->n_external_outputs == 0;

        /** TRANSACTION CONFIRMATION */
        /* Init*/
        ui_transaction_simplified_init(st->is_wallet_default ? NULL : st->wallet_header.name,
                                       is_self_transfer ? 1 : st->n_external_outputs,
                                       st->warnings);

        /* Adding outputs */
        if (!is_self_transfer) {
            for (unsigned int i = 0; i < st->n_external_outputs; i++) {
                char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];
                /* It is possible to return the following error in the middle of
                 * already shown screens of previous outputs
                 */
                if (!format_script(st->outputs.output_scripts[i],
                                   st->outputs.output_script_lengths[i],
                                   output_description)) {
                    PRINTF("Invalid or unsupported script for external output\n");
                    SEND_SW(dc, SW_NOT_SUPPORTED);
                    return false;
                }

                ui_transaction_simplified_add(is_self_transfer ? 0 : st->outputs.output_amounts[i],
                                              is_self_transfer ? NULL : output_description);
            }
        } else {
            ui_transaction_simplified_add(0, NULL);
        }

        /* Start the review */
        ui_set_processing_screen_text(GA_SIGNING_TRANSACTION);
        if (!ui_transaction_simplified_show(dc, fee)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    } else {
        // Transactions with more than one external output; show one output per page,
        // using the streaming NBGL API.

        // If it's not a default wallet policy, let's save this info to ask the user for
        // confirmation
        if (!st->is_wallet_default) {
            ui_prepare_authorize_wallet_spend(st->wallet_header.name);
        }

        // "Review transaction to send Bitcoin"
        if (!ui_transaction_streaming_prompt(dc)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }

        /** OUTPUTS CONFIRMATION
         *
         *  Display each non-change output, and transaction fees, and acquire user confirmation,
         */
        if (!display_external_outputs(dc, st, internal_outputs)) return false;

        /** TRANSACTION CONFIRMATION
         *
         *  Show summary info to the user (transaction fees), ask for final confirmation
         */
        // Show final user validation UI
        ui_set_processing_screen_text(GA_SIGNING_TRANSACTION);
        if (!ui_transaction_streaming_validate(dc, fee, st->warnings, false)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
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

static bool __attribute__((noinline))
sign_transaction(dispatcher_context_t *dc,
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
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            /** SWAP CHECKS
             *
             *  If called from the exchange app, perform the necessary additional checks.
             */

            // During swaps, the user approval was already obtained in the exchange app
            if (!execute_swap_checks(dc, &st)) return;
        } else
#endif /* HAVE_SWAP */
        {
            /** TRANSACTION CONFIRMATION
             *
             *  Display each non-change output, and transaction fees, and acquire user confirmation,
             */
            if (!display_transaction(dc, &st, internal_outputs)) return;
        }

        // Signing always takes some time, so we rather not wait before showing the spinner
        ioe_show_processing_screen();

        /** SIGNING FLOW
         *
         * For each internal key expression, and for each internal input, sign using the
         * appropriate algorithm.
         */
        int sign_result = sign_transaction(dc, &st, cache, &signing_state, internal_inputs);

#ifdef HAVE_SWAP
        if (!G_called_from_swap)
#endif /* HAVE_SWAP */
        {
            ui_post_processing_confirm_transaction(dc, sign_result);
        }

        if (!sign_result) {
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
