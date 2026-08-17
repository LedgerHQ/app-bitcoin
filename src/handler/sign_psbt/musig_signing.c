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

#include <stdlib.h>

#include "musig_signing.h"

/* SDK headers */
#include "crypto_helpers.h"

/* Local headers */
#include "client_commands.h"
#include "commands.h"
#include "get_merkleized_map_value.h"
#include "policy.h"
#include "psbt.h"
#include "sw.h"

bool compute_musig_per_input_info(dispatcher_context_t *dc,
                                  sign_psbt_state_t *st,
                                  signing_state_t *signing_state,
                                  const input_info_t *input,
                                  const keyexpr_info_t *keyexpr_info,
                                  musig_per_input_info_t *out) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->account.policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    const policy_node_tr_t *tr_policy = (policy_node_tr_t *) st->account.policy_map;

    // plan:
    // 1) compute aggregate pubkey
    // 2) compute musig2 tweaks
    // 3) compute taproot tweak (if keypath spend)
    // 4) compute the psbt_session_id that identifies the psbt-level signing session

    wallet_derivation_info_t wdi = {
        .n_keys = st->account.wallet_header.n_keys,
        .wallet_version = st->account.wallet_header.version,
        .keys_merkle_root = st->account.wallet_header.keys_info_merkle_root,
        .change = input->in_out.is_change,
        .address_index = input->in_out.address_index,
        .sign_psbt_cache = NULL};

    serialized_extended_pubkey_t ext_pubkey;

    const policy_node_keyexpr_t *key_expr = keyexpr_info->key_expression_ptr;
    const musig_aggr_key_info_t *musig_info = key_expr->m.musig_info;
    const uint16_t *key_indexes = musig_info->key_indexes;

    LEDGER_ASSERT(musig_info->n <= MAX_PUBKEYS_PER_MUSIG, "Too many keys in musig key expression");
    for (int i = 0; i < musig_info->n; i++) {
        // we use ext_pubkey as a temporary variable; will overwrite later
        if (0 > get_extended_pubkey_from_client(dc, &wdi, key_indexes[i], &ext_pubkey)) {
            return false;
        }
        memcpy(out->keys[i], ext_pubkey.compressed_pubkey, sizeof(ext_pubkey.compressed_pubkey));
    }

    // sort the keys in ascending order
    qsort(out->keys, musig_info->n, sizeof(plain_pk_t), compare_plain_pk);

    // we already computed the aggregate (pre-tweaks) xpub in the keyexpr_info
    memcpy(&ext_pubkey, &keyexpr_info->pubkey, sizeof(serialized_extended_pubkey_t));

    // 2) compute musig2 tweaks
    // We always have exactly 2 BIP32 tweaks in wallet policies; if the musig is in the keypath
    // spend, we also have an x-only taptweak with the taproot tree hash (or BIP-86/BIP-386 style if
    // there is no taproot tree).

    uint32_t change_step = input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                                   : keyexpr_info->key_expression_ptr->num_first;
    uint32_t addr_index_step = input->in_out.address_index;

    // in wallet policies, we always have at least two bip32-tweaks, and we might have
    // one x-only tweak per BIP-0341 (if spending from the keypath).
    out->is_xonly[0] = false;
    out->is_xonly[1] = false;
    out->n_tweaks = 2;  // might be changed to 3 below

    if (0 > bip32_CKDpub(&ext_pubkey, change_step, &out->agg_key_tweaked, out->tweaks[0])) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    if (0 > bip32_CKDpub(&out->agg_key_tweaked,
                         addr_index_step,
                         &out->agg_key_tweaked,
                         out->tweaks[1])) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    // 3) compute taproot tweak (if keypath spend)
    memset(out->tweaks[2], 0, 32);
    if (!keyexpr_info->is_tapscript) {
        out->n_tweaks = 3;
        out->is_xonly[2] = true;

        crypto_tr_tagged_hash(
            BIP0341_taptweak_tag,
            sizeof(BIP0341_taptweak_tag),
            out->agg_key_tweaked.compressed_pubkey + 1,  // xonly key, after BIP-32 tweaks
            32,
            input->taptree_hash,
            // BIP-86 compliant tweak if there's no taptree, otherwise use the taptree hash
            tr_policy->tree == NULL ? 0 : 32,
            out->tweaks[2]);

        // also apply the taptweak to agg_key_tweaked

        uint8_t parity = 0;
        crypto_tr_tweak_pubkey(out->agg_key_tweaked.compressed_pubkey + 1,
                               input->taptree_hash,
                               tr_policy->tree == NULL ? 0 : 32,
                               &parity,
                               out->agg_key_tweaked.compressed_pubkey + 1);
        out->agg_key_tweaked.compressed_pubkey[0] = 0x02 + parity;
    }

    // we will no longer use the other fields of the extended pubkey, so we zero them for sanity
    memset(out->agg_key_tweaked.chain_code, 0, sizeof(out->agg_key_tweaked.chain_code));
    memset(out->agg_key_tweaked.child_number, 0, sizeof(out->agg_key_tweaked.child_number));
    out->agg_key_tweaked.depth = 0;
    memset(out->agg_key_tweaked.parent_fingerprint,
           0,
           sizeof(out->agg_key_tweaked.parent_fingerprint));
    memset(out->agg_key_tweaked.version, 0, sizeof(out->agg_key_tweaked.version));

    // The psbt_session_id identifies the musig signing session for the entire (psbt, wallet_policy)
    // pair, in both rounds 1 and 2 of the protocol; it is the same for all the musig placeholders
    // in the policy (if more than one), and it is the same for all the inputs in the psbt. By
    // making the hash depend on both the wallet policy and the transaction hashes, we make sure
    // that an accidental collision is impossible, allowing for independent, parallel MuSig2 signing
    // sessions for different transactions or wallet policies.
    // Malicious collisions are not a concern, as they would only result in a signing failure (since
    // the nonces would be incorrectly regenerated during round 2 of MuSig2).
    crypto_tr_tagged_hash(
        (uint8_t[]) {'P', 's', 'b', 't', 'S', 'e', 's', 's', 'i', 'o', 'n', 'I', 'd'},
        13,
        st->account.wallet_header
            .keys_info_merkle_root,  // TODO: wallet policy id would be more precise
        32,
        (uint8_t *) &signing_state->tx_hashes,
        sizeof(tx_hashes_t),
        out->psbt_session_id);

    return true;
}

/**
 * Derives the (secnonce, pubnonce) pair for the given (input index, key expression) pair, out of
 * the synthetic randomness of the psbt-level MuSig2 session.
 *
 * Every place that needs a nonce must go through this function: round 1 publishes the pubnonce,
 * while round 2 recomputes the corresponding secnonce. Should the two derivations ever diverge, the
 * partial signatures produced in round 2 would not match the pubnonces published in round 1, and
 * the aggregate signature would be invalid.
 *
 * On failure, the secnonce is zeroed out before returning.
 */
static bool __attribute__((noinline)) musig_derive_nonce(const musig_psbt_session_t *psbt_session,
                                                         const keyexpr_info_t *keyexpr_info,
                                                         const uint8_t aggpk[static 32],
                                                         unsigned int input_index,
                                                         musig_secnonce_t *secnonce,
                                                         musig_pubnonce_t *pubnonce) {
    uint8_t rand_i_j[32];
    compute_rand_i_j(psbt_session, input_index, keyexpr_info->index, rand_i_j);

    int res = musig_nonce_gen(rand_i_j,
                              sizeof(rand_i_j),
                              keyexpr_info->internal_pubkey.compressed_pubkey,
                              aggpk,
                              secnonce,
                              pubnonce);

    explicit_bzero(rand_i_j, sizeof(rand_i_j));

    if (0 > res) {
        PRINTF("MuSig2 nonce generation failed\n");
        explicit_bzero(secnonce, sizeof(*secnonce));
        return false;
    }

    return true;
}

static bool __attribute__((noinline)) yield_musig_data(dispatcher_context_t *dc,
                                                       sign_psbt_state_t *st,
                                                       unsigned int cur_input_index,
                                                       const uint8_t *data,
                                                       size_t data_len,
                                                       uint32_t tag,
                                                       const uint8_t participant_pk[static 33],
                                                       const uint8_t aggregate_pubkey[static 33],
                                                       const uint8_t *tapleaf_hash) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->protocol_version == 0) {
        // Only support version 1 of the protocol
        return false;
    }

    // bytes:     1       5       varint     data_len         33               33         0 or 32
    //        CMD_YIELD <tag> <input_index>   <data>    <participant_pk> <aggregate_pubkey>
    //        <leaf_hash>

    // Yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];

    // Add tag
    int tag_varint_len = varint_write(buf, 0, tag);
    dc->add_to_response(buf, tag_varint_len);

    // Add input index
    int input_index_varint_len = varint_write(buf, 0, cur_input_index);
    dc->add_to_response(buf, input_index_varint_len);

    // Add data (pubnonce or partial signature)
    dc->add_to_response(data, data_len);

    // Add participant public key
    dc->add_to_response(participant_pk, 33);

    // Add aggregate public key
    dc->add_to_response(aggregate_pubkey, 33);

    // Add tapleaf hash if provided
    if (tapleaf_hash != NULL) {
        dc->add_to_response(tapleaf_hash, 32);
    }

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        return false;
    }
    return true;
}

static bool yield_musig_pubnonce(dispatcher_context_t *dc,
                                 sign_psbt_state_t *st,
                                 unsigned int cur_input_index,
                                 const musig_pubnonce_t *pubnonce,
                                 const uint8_t participant_pk[static 33],
                                 const uint8_t aggregate_pubkey[static 33],
                                 const uint8_t *tapleaf_hash) {
    return yield_musig_data(dc,
                            st,
                            cur_input_index,
                            (const uint8_t *) pubnonce,
                            sizeof(musig_pubnonce_t),
                            CCMD_YIELD_MUSIG_PUBNONCE_TAG,
                            participant_pk,
                            aggregate_pubkey,
                            tapleaf_hash);
}

static bool yield_musig_partial_signature(dispatcher_context_t *dc,
                                          sign_psbt_state_t *st,
                                          unsigned int cur_input_index,
                                          const uint8_t psig[static 32],
                                          const uint8_t participant_pk[static 33],
                                          const uint8_t aggregate_pubkey[static 33],
                                          const uint8_t *tapleaf_hash) {
    return yield_musig_data(dc,
                            st,
                            cur_input_index,
                            psig,
                            32,
                            CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
                            participant_pk,
                            aggregate_pubkey,
                            tapleaf_hash);
}

bool produce_and_yield_pubnonce(dispatcher_context_t *dc,
                                sign_psbt_state_t *st,
                                signing_state_t *signing_state,
                                const keyexpr_info_t *keyexpr_info,
                                const input_info_t *input,
                                unsigned int cur_input_index) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    musig_per_input_info_t musig_per_input_info;
    if (!compute_musig_per_input_info(dc,
                                      st,
                                      signing_state,
                                      input,
                                      keyexpr_info,
                                      &musig_per_input_info)) {
        return false;
    }

    /**
     * Round 1 of the MuSig2 protocol: generate and yield pubnonce
     **/

    const musig_psbt_session_t *psbt_session =
        musigsession_round1_initialize(musig_per_input_info.psbt_session_id, &signing_state->musig);
    if (psbt_session == NULL) {
        // This should never happen
        PRINTF("Unexpected: failed to initialize MuSig2 round 1\n");
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    bool nonce_ok = musig_derive_nonce(psbt_session,
                                       keyexpr_info,
                                       musig_per_input_info.agg_key_tweaked.compressed_pubkey + 1,
                                       cur_input_index,
                                       &secnonce,
                                       &pubnonce);

    // round 1 only publishes the pubnonce; the secnonce is recomputed in round 2
    explicit_bzero(&secnonce, sizeof(secnonce));

    if (!nonce_ok) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    if (!yield_musig_pubnonce(dc,
                              st,
                              cur_input_index,
                              &pubnonce,
                              keyexpr_info->internal_pubkey.compressed_pubkey,
                              musig_per_input_info.agg_key_tweaked.compressed_pubkey,
                              keyexpr_info->is_tapscript ? keyexpr_info->tapleaf_hash : NULL)) {
        PRINTF("Failed yielding MuSig2 pubnonce\n");
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    return true;
}

bool __attribute__((noinline)) sign_sighash_musig_and_yield(dispatcher_context_t *dc,
                                                            sign_psbt_state_t *st,
                                                            signing_state_t *signing_state,
                                                            const keyexpr_info_t *keyexpr_info,
                                                            const input_info_t *input,
                                                            unsigned int cur_input_index,
                                                            uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    musig_per_input_info_t musig_per_input_info;
    if (!compute_musig_per_input_info(dc,
                                      st,
                                      signing_state,
                                      input,
                                      keyexpr_info,
                                      &musig_per_input_info)) {
        return false;
    }

    // Find my pubnonce is in the psbt.
    //
    // Compute musig_my_psbt_id. It is the psbt key that this signer uses to find pubnonces and
    // partial signatures (PSBT_IN_MUSIG2_PUB_NONCE and PSBT_IN_MUSIG2_PARTIAL_SIG fields). The
    // length is either 33+33 (keypath spend), or 33+33+32 bytes (tapscript spend). It's the
    // concatenation of:
    // - the 33-byte compressed pubkey of this participant
    // - the 33-byte aggregate compressed pubkey (after all the tweaks)
    // - (tapscript only) the 32-byte tapleaf hash
    uint8_t musig_my_psbt_id_key[1 + 33 + 33 + 32];
    musig_my_psbt_id_key[0] = PSBT_IN_MUSIG2_PUB_NONCE;

    uint8_t *musig_my_psbt_id = musig_my_psbt_id_key + 1;
    size_t psbt_id_len = keyexpr_info->is_tapscript ? 33 + 33 + 32 : 33 + 33;
    memcpy(musig_my_psbt_id, keyexpr_info->internal_pubkey.compressed_pubkey, 33);
    memcpy(musig_my_psbt_id + 33, musig_per_input_info.agg_key_tweaked.compressed_pubkey, 33);
    if (keyexpr_info->is_tapscript) {
        memcpy(musig_my_psbt_id + 33 + 33, keyexpr_info->tapleaf_hash, 32);
    }
    musig_pubnonce_t my_pubnonce;
    // call_get_merkleized_map_value returns int (negative on error); cast the
    // unsigned sizeof so the comparison doesn't trip UBSan's sign-change check.
    if ((int) sizeof(musig_pubnonce_t) != call_get_merkleized_map_value(dc,
                                                                        &input->in_out.map,
                                                                        musig_my_psbt_id_key,
                                                                        1 + psbt_id_len,
                                                                        my_pubnonce.raw,
                                                                        sizeof(musig_pubnonce_t))) {
        PRINTF("Missing or erroneous pubnonce in PSBT\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    /**
     * Round 2 of the MuSig2 protocol
     **/

    const musig_psbt_session_t *psbt_session =
        musigsession_round2_initialize(musig_per_input_info.psbt_session_id, &signing_state->musig);

    if (psbt_session == NULL) {
        // The PSBT contains a partial nonce, but we do not have the corresponding psbt
        // session in storage. Either it was deleted, or the pubnonces were not real. Either
        // way, we cannot continue.
        PRINTF("Missing MuSig2 session\n");
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // collect all pubnonces

    const policy_node_keyexpr_t *key_expr = keyexpr_info->key_expression_ptr;
    const musig_aggr_key_info_t *musig_info = key_expr->m.musig_info;

    musig_pubnonce_t nonces[MAX_PUBKEYS_PER_MUSIG];

    for (int i = 0; i < musig_info->n; i++) {
        uint8_t musig_ith_psbt_id_key[1 + 33 + 33 + 32];
        uint8_t *musig_ith_psbt_id = musig_ith_psbt_id_key + 1;
        // copy from musig_my_psbt_id_key, but replace the corresponding pubkey
        memcpy(musig_ith_psbt_id_key, musig_my_psbt_id_key, sizeof(musig_my_psbt_id_key));
        memcpy(musig_ith_psbt_id, musig_per_input_info.keys[i], sizeof(plain_pk_t));

        if (sizeof(musig_pubnonce_t) != call_get_merkleized_map_value(dc,
                                                                      &input->in_out.map,
                                                                      musig_ith_psbt_id_key,
                                                                      1 + psbt_id_len,
                                                                      nonces[i].raw,
                                                                      sizeof(musig_pubnonce_t))) {
            PRINTF("Missing or incorrect pubnonce for a MuSig2 cosigner\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    // compute aggregate nonce
    musig_pubnonce_t aggnonce;
    int res = musig_nonce_agg(nonces, musig_info->n, &aggnonce);
    if (res < 0) {
        PRINTF("Musig aggregation failed; disruptive signer has index %d\n", -res - 1);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // recompute secnonce from psbt_session randomness
    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;

    if (!musig_derive_nonce(psbt_session,
                            keyexpr_info,
                            musig_per_input_info.agg_key_tweaked.compressed_pubkey + 1,
                            cur_input_index,
                            &secnonce,
                            &pubnonce)) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    // generate and yield partial signature

    cx_ecfp_private_key_t private_key = {0};
    uint8_t psig[32];
    bool err = false;
    do {  // block executed once, only to allow safely breaking out on error

        // derive secret key
        uint32_t sign_path[MAX_BIP32_PATH_STEPS];

        for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
            sign_path[i] = keyexpr_info->key_derivation[i];
        }
        int sign_path_len = keyexpr_info->key_derivation_length;

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            err = true;
            break;
        }

        // Create partial signature
        uint8_t *tweaks_ptrs[3] = {
            musig_per_input_info.tweaks[0],
            musig_per_input_info.tweaks[1],
            musig_per_input_info.tweaks[2]  // the last element is ignored if n_tweaks == 2
        };
        musig_session_context_t musig_session_context = {.aggnonce = &aggnonce,
                                                         .n_keys = musig_info->n,
                                                         .pubkeys = musig_per_input_info.keys,
                                                         .n_tweaks = musig_per_input_info.n_tweaks,
                                                         .tweaks = tweaks_ptrs,
                                                         .is_xonly = musig_per_input_info.is_xonly,
                                                         .msg = sighash,
                                                         .msg_len = 32};

        if (0 > musig_sign(&secnonce, private_key.d, &musig_session_context, psig)) {
            PRINTF("Musig2 signature failed\n");
            err = true;
            break;
        }
    } while (false);

    explicit_bzero(&private_key, sizeof(private_key));
    explicit_bzero(&secnonce, sizeof(secnonce));

    if (err) {
        PRINTF("Partial signature generation failed\n");
        return false;
    }

    if (!yield_musig_partial_signature(
            dc,
            st,
            cur_input_index,
            psig,
            keyexpr_info->internal_pubkey.compressed_pubkey,
            musig_per_input_info.agg_key_tweaked.compressed_pubkey,
            keyexpr_info->is_tapscript ? keyexpr_info->tapleaf_hash : NULL)) {
        PRINTF("Failed yielding MuSig2 partial signature\n");
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    return true;
}
