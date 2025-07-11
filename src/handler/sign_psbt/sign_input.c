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

#include "sign_input.h"

/* SDK headers */
#include "crypto_helpers.h"
#include "varint.h"

/* Local headers */
#include "amount_from_psbt.h"
#include "bitvector.h"
#include "client_commands.h"
#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "error_codes.h"
#include "get_merkleized_map.h"
#include "get_merkleized_map_value.h"
#include "init_global_state.h"
#include "musig_signing.h"
#include "policy.h"
#include "preprocess_inputs.h"
#include "psbt.h"
#include "sign_psbt_cache.h"
#include "sw.h"
#include "txhashes.h"

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

        int segwit_version = get_policy_segwit_version(st->account.policy_map);
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

            policy_node_tr_t *policy = (policy_node_tr_t *) st->account.policy_map;
            if (!keyexpr_info->is_tapscript && !isnull_policy_node_tree(&policy->tree)) {
                // keypath spend, we compute the taptree hash
                if (0 > compute_taptree_hash(
                            dc,
                            &(wallet_derivation_info_t){
                                .address_index = input->in_out.address_index,
                                .change = input->in_out.is_change ? 1 : 0,
                                .keys_merkle_root = st->account.wallet_header.keys_info_merkle_root,
                                .n_keys = st->account.wallet_header.n_keys,
                                .wallet_version = st->account.wallet_header.version,
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
                // keypath spend
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

    wallet_derivation_info_t wdi = {
        .wallet_version = st->account.wallet_header.version,
        .keys_merkle_root = st->account.wallet_header.keys_info_merkle_root,
        .n_keys = st->account.wallet_header.n_keys,
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

/**
 * Pre-pass: identifies which internal key expressions need processing.
 * If required_type >= 0, only key expressions matching that type are selected.
 * If required_type < 0, all signable key expressions are selected.
 */
static bool select_keyexprs_to_process(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    int required_type,
    bool keyexpr_to_process[static MAX_INTERNAL_KEY_EXPRESSIONS]) {
    bool any = false;
    for (size_t i = 0; i < st->account.n_internal_key_expressions; i++) {
        keyexpr_to_process[i] = false;
        keyexpr_info_t *keyexpr_info = &st->account.internal_key_expressions[i];
        if (!keyexpr_info->to_sign) {
            continue;
        }
        if (required_type >= 0 &&
            keyexpr_info->key_expression_ptr->type != (KeyExpressionType) required_type) {
            continue;
        }
        if (!fill_keyexpr_info_if_internal(dc, st, keyexpr_info)) {
            continue;
        }
        keyexpr_to_process[i] = true;
        any = true;
    }
    return any;
}

bool __attribute__((noinline))
sign_internal_inputs(dispatcher_context_t *dc,
                     sign_psbt_state_t *st,
                     sign_psbt_cache_t *sign_psbt_cache,
                     signing_state_t *signing_state,
                     const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    bool keyexpr_to_process[MAX_INTERNAL_KEY_EXPRESSIONS] = {0};
    if (!select_keyexprs_to_process(dc, st, -1, keyexpr_to_process)) {
        return true;
    }

    // Iterate over all internal inputs
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (!bitvector_get(internal_inputs, i)) {
            continue;
        }

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

        for (size_t i_keyexpr = 0; i_keyexpr < st->account.n_internal_key_expressions;
             i_keyexpr++) {
            if (!keyexpr_to_process[i_keyexpr]) {
                continue;
            }
            keyexpr_info_t *keyexpr_info = &st->account.internal_key_expressions[i_keyexpr];

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

    return true;
}
