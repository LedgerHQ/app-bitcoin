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
#include <string.h>

#include "preprocess_inputs.h"

/* SDK headers */
#include "read.h"

/* Local headers */
#include "app_settings.h"
#include "amount_from_psbt.h"
#include "bitvector.h"
#include "buffer.h"
#include "constants.h"
#include "display.h"
#include "dispatcher.h"
#include "error_codes.h"
#include "get_merkleized_map.h"
#include "init_global_state.h"
#include "policy.h"
#include "process_in_outs.h"
#include "psbt.h"
#include "psbt_fields.h"
#include "sighash.h"
#include "sign_psbt_cache.h"
#include "sw.h"

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
void input_keys_callback(dispatcher_context_t *dc,
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
                for (size_t i = 0; i < callback_data->state->account.n_internal_key_expressions;
                     i++) {
                    keyexpr_info_t *key_expr =
                        &callback_data->state->account.internal_key_expressions[i];
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

// Track the sighash seen across the inputs we sign (DEFAULT canonicalized to ALL);
// disagreement -> sighash_mixed.
static void track_seen_sighash(sign_psbt_state_t *st, uint32_t sighash_type) {
    uint32_t canon = (sighash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : sighash_type;
    if (!st->seen_sighash_set) {
        st->seen_sighash = canon;
        st->seen_sighash_set = true;
    } else if (st->seen_sighash != canon) {
        st->sighash_mixed = true;
    }
}

bool __attribute__((noinline)) preprocess_inputs(
    dispatcher_context_t *dc,
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
            if (PSBT_FIELD_PRESENT !=
                psbt_get_input_prevout_txid(dc, &input.in_out.map, prevout_hash)) {
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

            // sanity check before accumulating, to avoid overflowing the total
            if (input.prevout_amount > BITCOIN_TOTAL_SUPPLY) {
                PRINTF("Input amount exceeds Bitcoin total supply!\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
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
                // sanity check before accumulating, to avoid overflowing the total
                if (wit_utxo_prevout_amount > BITCOIN_TOTAL_SUPPLY) {
                    PRINTF("Input amount exceeds Bitcoin total supply!\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }
                st->inputs_total_amount += wit_utxo_prevout_amount;

                input.prevout_amount = wit_utxo_prevout_amount;
                input.in_out.scriptPubKey_len = wit_utxo_scriptPubkey_len;
                memcpy(input.in_out.scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
            }
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
            if (!input.has_nonWitnessUtxo) {
                // The amount comes only from the (unverified) witness-utxo, not hash-verified
                // against the prevout txid. Trustworthy only if we sign taproot inputs (which
                // commit sha_amounts over all inputs).
                st->external_amount_unverified = true;
            }
            PRINTF("INPUT %d is external\n", cur_input_index);
            continue;
        }

        bitvector_set(internal_inputs, cur_input_index, 1);
        st->internal_inputs_total_amount += input.prevout_amount;

        int segwit_version = get_policy_segwit_version(st->account.policy_map);

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
            track_seen_sighash(st, SIGHASH_ALL);  // no explicit sighash => commits all
            continue;
        }

        // get the sighash_type
        if (PSBT_FIELD_PRESENT !=
            psbt_get_input_sighash_type(dc, &input.in_out.map, &input.sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        sighash_class_t sighash_class = classify_sighash(input.sighash_type, segwit_version);
        if (sighash_class == SIGHASH_CLASS_SAFE) {
            PRINTF("Sighash type is SIGHASH_DEFAULT or SIGHASH_ALL\n");

        } else if (sighash_class == SIGHASH_CLASS_NON_SAFE) {
            // Non-standard sighash: only allowed if the user explicitly enabled
            // "Allow non-standard sighash" in the application settings.
            if (!app_settings_get_allow_nondefault_sighash()) {
                PRINTF("Non-standard sighash rejected: setting not enabled\n");
                // Show a clear on-device status so the user understands why the
                // transaction was rejected
                ui_warn_nondefault_sighash_disabled(dc);
                SEND_SW_EC(dc,
                           SW_SECURITY_STATUS_NOT_SATISFIED,
                           EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED);
                return false;
            }
            PRINTF("Sighash type is non-default, will show a warning.\n");
            st->warnings.non_default_sighash = true;
        } else {
            PRINTF("Unsupported sighash\n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }

        // track whether any signed input leaves the inputs or outputs open
        if (!sighash_input_set_closed(input.sighash_type)) {
            st->sighash_inputs_open = true;
        }
        if (!sighash_output_set_closed(input.sighash_type)) {
            st->sighash_outputs_open = true;
        }

        track_seen_sighash(st, input.sighash_type);

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
