/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
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

#include "lib_standard_app/crypto_helpers.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/varint.h"
#include "../common/wallet.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "lib/check_merkle_tree_sorted.h"
#include "lib/get_preimage.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/get_merkle_leaf_element.h"
#include "lib/psbt_parse_rawtx.h"

#include "handlers.h"

#include "sign_psbt/compare_wallet_script_at_path.h"
#include "sign_psbt/extract_bip32_derivation.h"
#include "sign_psbt/update_hashes_with_map_value.h"

#include "../swap/swap_globals.h"
#include "../swap/handle_swap_sign_transaction.h"

// common info that applies to either the current input or the current output
typedef struct {
    merkleized_map_commitment_t map;

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_{IN,OUT}_BIP32_DERIVATION or
                                   // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION is not the correct length.

    bool placeholder_found;  // Set to true if a matching placeholder is found in the input info

    bool is_change;
    int address_index;

    // For an output, its scriptPubKey
    // for an input, the prevout's scriptPubKey (either from the non-witness-utxo, or from the
    // witness-utxo)

    uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t scriptPubKey_len;
} in_out_info_t;

typedef struct {
    in_out_info_t in_out;
    bool has_witnessUtxo;
    bool has_nonWitnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    uint64_t prevout_amount;  // the value of the prevout of the current input

    // we no longer need the script when we compute the taptree hash right before a taproot key-path
    // spending; therefore, we reuse the same memory
    union {
        // the script used when signing, either from the witness utxo or the redeem script
        uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        uint8_t taptree_hash[32];
    };

    size_t script_len;

    uint32_t sighash_type;
} input_info_t;

typedef struct {
    in_out_info_t in_out;
    uint64_t value;
} output_info_t;

typedef struct {
    policy_node_key_placeholder_t placeholder;
    int cur_index;
    uint32_t fingerprint;
    uint8_t key_derivation_length;
    uint32_t key_derivation[MAX_BIP32_PATH_STEPS];
    serialized_extended_pubkey_t pubkey;
    bool is_tapscript;         // true if signing with a BIP342 tapleaf script path spend
    uint8_t tapleaf_hash[32];  // only used for tapscripts
} placeholder_info_t;

// Cache for partial hashes during segwit signing (avoid quadratic hashing for segwit transactions)
typedef struct {
    uint8_t sha_prevouts[32];
    uint8_t sha_amounts[32];
    uint8_t sha_scriptpubkeys[32];
    uint8_t sha_sequences[32];
    uint8_t sha_outputs[32];
} segwit_hashes_t;

#ifdef USE_NVRAM_STASH

typedef struct {
    // Aligning by 4 is necessary due to platform limitations.
    // Aligning by 64 further guarantees that most policies will fit in a single
    // NVRAM page boundary, which minimizes the amount of writes.
    __attribute__((aligned(64))) uint8_t wallet_policy_bytes[MAX_WALLET_POLICY_BYTES];
} nvram_stash_t;

const nvram_stash_t N_nvram_stash_real;
#define N_nvram_stash (*(const volatile nvram_stash_t *) PIC(&N_nvram_stash_real))

#endif

typedef struct {
    uint32_t master_key_fingerprint;
    uint32_t tx_version;
    uint32_t locktime;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    uint64_t inputs_total_amount;

    // aggregate info on outputs
    struct {
        uint64_t total_amount;         // amount of all the outputs (external + change)
        uint64_t change_total_amount;  // total amount of all change outputs
        int n_change;                  // count of outputs compatible with change outputs
        int n_external;                // count of external outputs
    } outputs;

    bool is_wallet_default;

    uint8_t protocol_version;

#ifndef USE_NVRAM_STASH
    __attribute__((aligned(4))) uint8_t wallet_policy_map_bytes[MAX_WALLET_POLICY_BYTES];
#endif
    policy_node_t *wallet_policy_map;

    int wallet_header_version;
    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;

    // if any segwitv0 input is missing the non-witness-utxo, we show a warning
    bool show_missing_nonwitnessutxo_warning;

    // if any of the internal inputs has non-default sighash, we show a warning
    bool show_nondefault_sighash_warning;
} sign_psbt_state_t;

/* BIP0341 tags for computing the tagged hashes when computing he sighash */
static const uint8_t BIP0341_sighash_tag[] = {'T', 'a', 'p', 'S', 'i', 'g', 'h', 'a', 's', 'h'};

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
// Updates the hash_context with the output of given index
// returns -1 on error. 0 on success.
static int hash_output_n(dispatcher_context_t *dc,
                         sign_psbt_state_t *st,
                         cx_hash_t *hash_context,
                         unsigned int index) {
    if (index >= st->n_outputs) {
        return -1;
    }

    // get this output's map
    merkleized_map_commitment_t ith_map;

    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, index, &ith_map);
    if (res < 0) {
        return -1;
    }

    // get output's amount
    uint8_t amount_raw[8];
    if (8 != call_get_merkleized_map_value(dc,
                                           &ith_map,
                                           (uint8_t[]){PSBT_OUT_AMOUNT},
                                           1,
                                           amount_raw,
                                           8)) {
        return -1;
    }

    crypto_hash_update(hash_context, amount_raw, 8);

    // get output's scriptPubKey

    uint8_t out_script[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    int out_script_len = call_get_merkleized_map_value(dc,
                                                       &ith_map,
                                                       (uint8_t[]){PSBT_OUT_SCRIPT},
                                                       1,
                                                       out_script,
                                                       sizeof(out_script));
    if (out_script_len < 0) {
        return -1;
    }

    crypto_hash_update_varint(hash_context, out_script_len);
    crypto_hash_update(hash_context, out_script, out_script_len);
    return 0;
}

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error. 0 on success.
static int hash_outputs(dispatcher_context_t *dc, sign_psbt_state_t *st, cx_hash_t *hash_context) {
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (hash_output_n(dc, st, hash_context, i)) {
            return -1;
        }
    }
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
static int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash) {
    // If there is no witness-utxo, it must be the case that this is a legacy input.
    // In this case, we can only retrieve the prevout amount and scriptPubKey by parsing
    // the non-witness-utxo

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  input_map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        return -1;
    }

    // SIZE_MAX is reserved by call_psbt_parse_rawtx to mean "no output is queried"
    if (prevout_n >= SIZE_MAX) {
        return -1;
    }

    txid_parser_outputs_t parser_outputs;
    // request non-witness utxo, and get the prevout's value and scriptpubkey
    int res = call_psbt_parse_rawtx(dc,
                                    input_map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    (size_t) prevout_n,
                                    &parser_outputs);
    if (res < 0) {
        PRINTF("Parsing rawtx failed\n");
        return -1;
    }

    // if expected_prevout_hash is given, check that it matches the txid obtained from the parser
    if (expected_prevout_hash != NULL &&
        memcmp(parser_outputs.txid, expected_prevout_hash, 32) != 0) {
        PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

        return -1;
    }

    *amount = parser_outputs.vout_value;

    if (parser_outputs.vout_scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    *scriptPubKey_len = parser_outputs.vout_scriptpubkey_len;
    memcpy(scriptPubKey, parser_outputs.vout_scriptpubkey, parser_outputs.vout_scriptpubkey_len);

    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the witness-utxo of a certain input in
 a PSBTv2.
 Returns -1 on failure, 0 on success.
*/
static int __attribute__((noinline))
get_amount_scriptpubkey_from_psbt_witness(dispatcher_context_t *dc,
                                          const merkleized_map_commitment_t *input_map,
                                          uint64_t *amount,
                                          uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
                                          size_t *scriptPubKey_len) {
    uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

    int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                     input_map,
                                                     (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                     1,
                                                     raw_witnessUtxo,
                                                     sizeof(raw_witnessUtxo));

    // the witness UTXO field is encoded as 8-bytes for the amount, followed by the length-prefixed
    // scriptPubkey. We make sure that we can read at least up to the scriptPubkey length, to avoid
    // reading a possibly-undefined byte at offset 8.
    if (wit_utxo_len < 8 + 1) {
        return -1;
    }
    int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

    if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
        PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
        return -1;
    }

    uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;
    uint64_t wit_utxo_prevout_amount = read_u64_le(&raw_witnessUtxo[0], 0);

    if (wit_utxo_scriptPubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    *amount = wit_utxo_prevout_amount;
    *scriptPubKey_len = wit_utxo_scriptPubkey_len;
    memcpy(scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey of a certain input in a PSBTv2.
 It first tries to obtain it from the witness-utxo field; in case of failure, it then obtains it
 from the non-witness-utxo.
 Returns -1 on failure, 0 on success.
*/
static int get_amount_scriptpubkey_from_psbt(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len) {
    int ret = get_amount_scriptpubkey_from_psbt_witness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len);
    if (ret >= 0) {
        return ret;
    }

    return get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len,
                                                        NULL);
}

// Convenience function to share common logic when processing all the
// PSBT_{IN|OUT}_{TAP}?_BIP32_DERIVATION fields.
// Note: This function must return -1 only on errors (causing signing to abort).
//       It should return 1 if a derivation that makes sense for this input/output is found.
//       It should return 0 otherwise (no match found, but continue the signing flow).
static int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    placeholder_info_t *placeholder_info,
    in_out_info_t *in_out,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index) {
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
        in_out->unexpected_pubkey_error = true;
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

    // if this derivation path matches the internal placeholder,
    // we use it to detect whether the current input is change or not,
    // and store its address index
    if (fpt_der[0] == placeholder_info->fingerprint &&
        der_len == placeholder_info->key_derivation_length + 2) {
        for (int i = 0; i < placeholder_info->key_derivation_length; i++) {
            if (placeholder_info->key_derivation[i] != fpt_der[1 + i]) {
                return 0;
            }
        }

        uint32_t change = fpt_der[1 + der_len - 2];
        uint32_t addr_index = fpt_der[1 + der_len - 1];

        // check that we can indeed derive the same key from the current placeholder
        serialized_extended_pubkey_t pubkey;
        if (0 > bip32_CKDpub(&placeholder_info->pubkey, change, &pubkey)) return -1;
        if (0 > bip32_CKDpub(&pubkey, addr_index, &pubkey)) return -1;

        int pk_offset = is_tap ? 1 : 0;
        if (memcmp(pubkey.compressed_pubkey + pk_offset, bip32_derivation_pubkey, key_len) != 0) {
            return 0;
        }

        // check if the 'change' derivation step is indeed coherent with placeholder
        if (change == placeholder_info->placeholder.num_first) {
            in_out->is_change = false;
            in_out->address_index = addr_index;
        } else if (change == placeholder_info->placeholder.num_second) {
            in_out->is_change = true;
            in_out->address_index = addr_index;
        } else {
            return 0;
        }

        in_out->placeholder_found = true;
        return 1;
    }
    return 0;
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
                              const in_out_info_t *in_out_info,
                              bool is_input) {
    // If we did not find any info about the pubkey associated to the placeholder we're considering,
    // then it's external
    if (!in_out_info->placeholder_found) {
        return 0;
    }

    if (!is_input && in_out_info->is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         in_out_info->is_change,
                                         in_out_info->address_index,
                                         state->wallet_policy_map,
                                         state->wallet_header_version,
                                         state->wallet_header_keys_info_merkle_root,
                                         state->wallet_header_n_keys,
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
    st->n_outputs = (unsigned int) n_outputs_u64;

    policy_map_wallet_header_t wallet_header;

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
        if (result_len == -1) {
            st->locktime = 0;
        } else if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else {
            st->locktime = read_u32_le(raw_result, 0);
        }
    }

    uint8_t hmac_or =
        0;  // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | wallet_hmac[i];
    }

    if (hmac_or != 0) {
        // Verify hmac
        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return false;
        }

        st->is_wallet_default = false;
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
#ifdef USE_NVRAM_STASH
        // we need a temporary array to store the parsed policy in RAM before
        // storing it in the NVRAM stash
        uint8_t wallet_policy_map_bytes[MAX_WALLET_POLICY_BYTES];
#else
        uint8_t *wallet_policy_map_bytes = st->wallet_policy_map_bytes;
#endif

        int desc_temp_len = read_and_parse_wallet_policy(dc,
                                                         &serialized_wallet_policy_buf,
                                                         &wallet_header,
                                                         policy_map_descriptor,
                                                         wallet_policy_map_bytes,
                                                         MAX_WALLET_POLICY_BYTES);
        if (desc_temp_len < 0) {
            PRINTF("Failed to read or parse wallet policy");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

#ifdef USE_NVRAM_STASH
        nvm_write((void *) N_nvram_stash.wallet_policy_bytes,
                  (void *) wallet_policy_map_bytes,
                  desc_temp_len);
        st->wallet_policy_map = (policy_node_t *) N_nvram_stash.wallet_policy_bytes;
#else
        st->wallet_policy_map = (policy_node_t *) st->wallet_policy_map_bytes;
#endif

        st->wallet_header_version = wallet_header.version;
        memcpy(st->wallet_header_keys_info_merkle_root,
               wallet_header.keys_info_merkle_root,
               sizeof(wallet_header.keys_info_merkle_root));
        st->wallet_header_n_keys = wallet_header.n_keys;

        if (st->is_wallet_default) {
            // No hmac, verify that the policy is indeed a default one
            if (!is_wallet_policy_standard(dc, &wallet_header, st->wallet_policy_map)) {
                PRINTF("Non-standard policy, and no hmac provided\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            if (wallet_header.name_len != 0) {
                PRINTF("Name must be zero-length for a standard wallet policy\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // unlike in get_wallet_address, we do not check if the address_index is small:
            // if funds were already sent there, there is no point in preventing to spend them.
        }
    }

    // Swap feature: check that wallet policy is a default one
    if (G_swap_state.called_from_swap && !st->is_wallet_default) {
        PRINTF("Must be a default wallet policy for swap feature\n");
        SEND_SW(dc, SW_FAIL_SWAP);
        finalize_exchange_sign_transaction(false);
    }

    // If it's not a default wallet policy, ask the user for confirmation, and abort if they deny
    if (!st->is_wallet_default && !ui_authorize_wallet_spend(dc, wallet_header.name)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_wallet_spend(dc, false);
        return false;
    }

    st->master_key_fingerprint = crypto_get_master_key_fingerprint();

    if (!st->is_wallet_default) {
        ui_post_processing_confirm_wallet_spend(dc, true);
    }
    return true;
}

static bool __attribute__((noinline))
fill_placeholder_info_if_internal(dispatcher_context_t *dc,
                                  sign_psbt_state_t *st,
                                  placeholder_info_t *placeholder_info) {
    policy_map_key_info_t key_info;
    {
        uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];
        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        st->wallet_header_keys_info_merkle_root,
                                                        st->wallet_header_n_keys,
                                                        placeholder_info->placeholder.key_index,
                                                        key_info_str,
                                                        sizeof(key_info_str));

        if (key_info_len < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        if (parse_policy_map_key_info(&key_info_buffer, &key_info, st->wallet_header_version) ==
            -1) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }
    }

    uint32_t fpr = read_u32_be(key_info.master_key_fingerprint, 0);
    if (fpr != st->master_key_fingerprint) {
        return false;
    }

    {
        // it could be a collision on the fingerprint; we verify that we can actually generate
        // the same pubkey
        if (0 > get_extended_pubkey_at_path(key_info.master_key_derivation,
                                            key_info.master_key_derivation_len,
                                            BIP32_PUBKEY_VERSION,
                                            &placeholder_info->pubkey)) {
            SEND_SW(dc, SW_BAD_STATE);
            return false;
        }

        if (memcmp(&key_info.ext_pubkey,
                   &placeholder_info->pubkey,
                   sizeof(placeholder_info->pubkey)) != 0) {
            return false;
        }

        placeholder_info->key_derivation_length = key_info.master_key_derivation_len;
        for (int i = 0; i < key_info.master_key_derivation_len; i++) {
            placeholder_info->key_derivation[i] = key_info.master_key_derivation[i];
        }

        placeholder_info->fingerprint = read_u32_be(key_info.master_key_fingerprint, 0);
    }

    return true;
}

// finds the first placeholder that corresponds to an internal key
static bool find_first_internal_key_placeholder(dispatcher_context_t *dc,
                                                sign_psbt_state_t *st,
                                                placeholder_info_t *placeholder_info) {
    placeholder_info->cur_index = 0;

    // find and parse our registered key info in the wallet
    while (true) {
        int n_key_placeholders = get_key_placeholder_by_index(st->wallet_policy_map,
                                                              placeholder_info->cur_index,
                                                              NULL,
                                                              &placeholder_info->placeholder);
        if (n_key_placeholders < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (placeholder_info->cur_index >= n_key_placeholders) {
            // all keys have been processed
            break;
        }

        if (fill_placeholder_info_if_internal(dc, st, placeholder_info)) {
            return true;
        }

        // Not an internal key, move on
        ++placeholder_info->cur_index;
    }

    PRINTF("No internal key found in wallet policy");
    SEND_SW(dc, SW_INCORRECT_DATA);
    return false;
}

typedef struct {
    placeholder_info_t *placeholder_info;
    input_info_t *input;
} input_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(dispatcher_context_t *dc,
                                input_keys_callback_data_t *callback_data,
                                const merkleized_map_commitment_t *map_commitment,
                                int i,
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
        } else if ((key_type == PSBT_IN_BIP32_DERIVATION ||
                    key_type == PSBT_IN_TAP_BIP32_DERIVATION) &&
                   !callback_data->input->in_out.placeholder_found) {
            if (0 >
                read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                 callback_data->placeholder_info,
                                                                 &callback_data->input->in_out,
                                                                 key_type,
                                                                 data,
                                                                 map_commitment,
                                                                 i)) {
                callback_data->input->in_out.unexpected_pubkey_error = true;
            }
        }
    }
}

static bool __attribute__((noinline))
preprocess_inputs(dispatcher_context_t *dc,
                  sign_psbt_state_t *st,
                  uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(internal_inputs, 0, BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN));

    placeholder_info_t placeholder_info;
    memset(&placeholder_info, 0, sizeof(placeholder_info));

    if (!find_first_internal_key_placeholder(dc, st, &placeholder_info)) return false;

    // process each input
    for (unsigned int cur_input_index = 0; cur_input_index < st->n_inputs; cur_input_index++) {
        input_info_t input;
        memset(&input, 0, sizeof(input));

        input_keys_callback_data_t callback_data = {.input = &input,
                                                    .placeholder_info = &placeholder_info};
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
            SEND_SW(dc, SW_INCORRECT_DATA);
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
            if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                                 &input.in_out.map,
                                                                 &input.prevout_amount,
                                                                 input.in_out.scriptPubKey,
                                                                 &input.in_out.scriptPubKey_len,
                                                                 prevout_hash)) {
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
                    SEND_SW(dc, SW_INCORRECT_DATA);
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

        // check if the input is internal; if not, continue

        int is_internal = is_in_out_internal(dc, st, &input.in_out, true);
        if (is_internal < 0) {
            PRINTF("Error checking if input %d is internal\n", cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
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
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        }

        // For segwitv0 inputs, the non-witness utxo _should_ be present; we show a warning
        // to the user otherwise, but we continue nonetheless on approval
        if (segwit_version == 0 && !input.has_nonWitnessUtxo) {
            PRINTF("Non-witness utxo missing for segwitv0 input. Will show a warning.\n");
            st->show_missing_nonwitnessutxo_warning = true;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !input.has_witnessUtxo) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
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
            st->show_nondefault_sighash_warning = true;
        } else {
            PRINTF("Unsupported sighash\n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }

        if (((input.sighash_type & SIGHASH_SINGLE) == SIGHASH_SINGLE) &&
            (cur_input_index >= st->n_outputs)) {
            PRINTF("SIGHASH_SINGLE with input idx >= n_output is not allowed \n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }
    }

    return true;
}

static bool __attribute__((noinline))
show_alerts(dispatcher_context_t *dc,
            sign_psbt_state_t *st,
            const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    size_t count_external_inputs = 0;
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (!bitvector_get(internal_inputs, i)) {
            ++count_external_inputs;
        }
    }

    // If there are external inputs, it is unsafe to sign, therefore we warn the user
    if (count_external_inputs > 0) {
        if (count_external_inputs == st->n_inputs) {
            // no internal inputs, nothing to sign
            PRINTF("No internal inputs. Aborting\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else {
            // Swap feature: no external inputs allowed
            if (G_swap_state.called_from_swap) {
                PRINTF("External inputs not allowed in swap transactions\n");
                SEND_SW(dc, SW_FAIL_SWAP);
                finalize_exchange_sign_transaction(false);
            }

            // some internal and some external inputs, warn the user first
            if (!ui_warn_external_inputs(dc)) {
                SEND_SW(dc, SW_DENY);
                return false;
            }
        }
    }

    // If any segwitv0 input is missing the non-witness-utxo, we warn the user and ask for
    // confirmation
    if (st->show_missing_nonwitnessutxo_warning && !ui_warn_unverified_segwit_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If any input has non-default sighash, we warn the user
    if (st->show_nondefault_sighash_warning && !ui_warn_nondefault_sighash(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

typedef struct {
    placeholder_info_t *placeholder_info;
    output_info_t *output;
} output_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(dispatcher_context_t *dc,
                                 output_keys_callback_data_t *callback_data,
                                 const merkleized_map_commitment_t *map_commitment,
                                 int i,
                                 buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if ((key_type == PSBT_OUT_BIP32_DERIVATION || key_type == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !callback_data->output->in_out.placeholder_found) {
            if (0 >
                read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                 callback_data->placeholder_info,
                                                                 &callback_data->output->in_out,
                                                                 key_type,
                                                                 data,
                                                                 map_commitment,
                                                                 i)) {
                callback_data->output->in_out.unexpected_pubkey_error = true;
            }
        }
    }
}

static bool __attribute__((noinline)) display_output(dispatcher_context_t *dc,
                                                     sign_psbt_state_t *st,
                                                     int cur_output_index,
                                                     int external_outputs_count,
                                                     const output_info_t *output) {
    (void) cur_output_index;

    // show this output's address
    char output_address[MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)];
    int address_len = get_script_address(output->in_out.scriptPubKey,
                                         output->in_out.scriptPubKey_len,
                                         output_address,
                                         sizeof(output_address));
    if (address_len < 0) {
        // script does not have an address; check if OP_RETURN
        if (is_opreturn(output->in_out.scriptPubKey, output->in_out.scriptPubKey_len)) {
            int res = format_opscript_script(output->in_out.scriptPubKey,
                                             output->in_out.scriptPubKey_len,
                                             output_address);
            if (res == -1) {
                PRINTF("Invalid or unsupported OP_RETURN for output %d\n", cur_output_index);
                SEND_SW(dc, SW_NOT_SUPPORTED);
                return false;
            }
        } else {
            PRINTF("Unknown or unsupported script type for output %d\n", cur_output_index);
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }
    }

    if (G_swap_state.called_from_swap) {
        // Swap feature: do not show the address to the user, but double check it matches
        // the request from app-exchange; it must be the only external output (checked
        // elsewhere).
        size_t swap_addr_len = strlen(G_swap_state.destination_address);
        if (swap_addr_len != (size_t)address_len ||
            0 != strncmp(G_swap_state.destination_address, output_address, address_len)) {
            // address did not match
            PRINTF("Mismatching address for swap\n");
            SEND_SW(dc, SW_FAIL_SWAP);
            finalize_exchange_sign_transaction(false);
        }
    } else {
        // Show address to the user
        if (!ui_validate_output(dc,
                                external_outputs_count,
                                st->outputs.n_external,
                                output_address,
                                COIN_COINID_SHORT,
                                output->value)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }
    return true;
}

static bool read_outputs(dispatcher_context_t *dc,
                         sign_psbt_state_t *st,
                         placeholder_info_t *placeholder_info,
                         bool dry_run) {
    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        output_info_t output;
        memset(&output, 0, sizeof(output));

        output_keys_callback_data_t callback_data = {.output = &output,
                                                     .placeholder_info = placeholder_info};
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

        if (!dry_run) {
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
        }

        // Read the output's scriptPubKey
        int result_len = call_get_merkleized_map_value(dc,
                                                       &output.in_out.map,
                                                       (uint8_t[]){PSBT_OUT_SCRIPT},
                                                       1,
                                                       output.in_out.scriptPubKey,
                                                       sizeof(output.in_out.scriptPubKey));

        if (result_len < 0  || result_len > (int) sizeof(output.in_out.scriptPubKey)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.in_out.scriptPubKey_len = result_len;

        int is_internal = is_in_out_internal(dc, st, &output.in_out, false);

        if (is_internal < 0) {
            PRINTF("Error checking if output %d is internal\n", cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            // external output, user needs to validate
            ++external_outputs_count;

            if (!dry_run &&
                !display_output(dc, st, cur_output_index, external_outputs_count, &output))
                return false;
        } else if (!dry_run) {
            // valid change address, nothing to show to the user

            st->outputs.change_total_amount += output.value;
            ++st->outputs.n_change;
        }
    }

    st->outputs.n_external = external_outputs_count;

    return true;
}

static bool __attribute__((noinline))
process_outputs(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Show each output that is not a change address to the user for verification.
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    placeholder_info_t placeholder_info;
    memset(&placeholder_info, 0, sizeof(placeholder_info));

    if (!find_first_internal_key_placeholder(dc, st, &placeholder_info)) return false;

    memset(&st->outputs, 0, sizeof(st->outputs));

#ifdef HAVE_NBGL
    // Only on Stax, we need to preprocess all the outputs in order to
    // compute the total number of non-change outputs.
    // As it's a time-consuming operation, we use avoid doing this useless
    // work on other models.

    if (!read_outputs(dc, st, &placeholder_info, true)) return false;

    if (!G_swap_state.called_from_swap && !ui_transaction_prompt(dc, st->outputs.n_external)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
#endif

    if (!read_outputs(dc, st, &placeholder_info, false)) return false;

    return true;
}

static bool __attribute__((noinline))
confirm_transaction(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->inputs_total_amount < st->outputs.total_amount) {
        PRINTF("Negative fee is invalid\n");
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->outputs.n_change > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many (possibly
        // unspendable) outputs.
        PRINTF("Too many change outputs: %d\n", st->outputs.n_change);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    if (G_swap_state.called_from_swap) {
        // Swap feature: there must be only one external output
        if (st->outputs.n_external != 1) {
            PRINTF("Swap transaction must have exactly 1 external output\n");
            SEND_SW(dc, SW_FAIL_SWAP);
            finalize_exchange_sign_transaction(false);
        }

        // Swap feature: check total amount and fees are as expected
        if (fee != G_swap_state.fees) {
            PRINTF("Mismatching fee for swap\n");
            SEND_SW(dc, SW_FAIL_SWAP);
            finalize_exchange_sign_transaction(false);
        }
        uint64_t spent_amount = st->outputs.total_amount - st->outputs.change_total_amount;
        if (spent_amount != G_swap_state.amount) {
            PRINTF("Mismatching spent amount for swap\n");
            SEND_SW(dc, SW_FAIL_SWAP);
            finalize_exchange_sign_transaction(false);
        }
    } else {
        // if the value of fees is 10% or more of the amount, and it's more than 10000
        if (10 * fee >= st->inputs_total_amount && st->inputs_total_amount > 10000) {
            if (!ui_warn_high_fee(dc)) {
                SEND_SW(dc, SW_DENY);
                ui_post_processing_confirm_transaction(dc, false);
                return false;
            }
        }

        // Show final user validation UI
        bool is_self_transfer = st->outputs.n_external == 0;
        if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, is_self_transfer)) {
            SEND_SW(dc, SW_DENY);
            ui_post_processing_confirm_transaction(dc, false);
            return false;
        }
    }

    return true;
}

static bool __attribute__((noinline)) compute_sighash_legacy(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index,
                                                             uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[4];
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    crypto_hash_update_varint(&sighash_context.header, st->n_inputs);

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        // get this input's map
        merkleized_map_commitment_t ith_map;

        if (i != cur_input_index) {
            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        } else {
            // Avoid requesting the same map unnecessarily
            // (might be removed once a caching mechanism is implemented)
            memcpy(&ith_map, &input->in_out.map, sizeof(input->in_out.map));
        }

        // get prevout hash and output index for the i-th input
        uint8_t ith_prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &ith_map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                ith_prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_hash, 32);

        uint8_t ith_prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               ith_prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_n_raw, 4);

        if (i != cur_input_index) {
            // empty scriptcode
            crypto_hash_update_u8(&sighash_context.header, 0x00);
        } else {
            if (!input->has_redeemScript) {
                // P2PKH, the script_code is the prevout's scriptPubKey
                crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);
                crypto_hash_update(&sighash_context.header,
                                   input->in_out.scriptPubKey,
                                   input->in_out.scriptPubKey_len);
            } else {
                // P2SH, the script_code is the redeemScript

                // update sighash_context with the length-prefixed redeem script
                int redeemScript_len =
                    update_hashes_with_map_value(dc,
                                                 &input->in_out.map,
                                                 (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                 1,
                                                 NULL,
                                                 &sighash_context.header);

                if (redeemScript_len < 0) {
                    PRINTF("Error fetching redeemScript\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }
            }
        }

        uint8_t ith_nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               ith_nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(ith_nSequence_raw, 0xFF, 4);
        }

        crypto_hash_update(&sighash_context.header, ith_nSequence_raw, 4);
    }

    // outputs
    crypto_hash_update_varint(&sighash_context.header, st->n_outputs);
    if (hash_outputs(dc, st, &sighash_context.header) == -1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // hash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv0(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               segwit_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[8];
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    {
        uint8_t dbl_hash[32];

        memset(dbl_hash, 0, 32);
        // add to hash: hashPrevouts = sha256(sha_prevouts)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY)) {
            cx_hash_sha256(hashes->sha_prevouts, 32, dbl_hash, 32);
        }

        crypto_hash_update(&sighash_context.header, dbl_hash, 32);

        memset(dbl_hash, 0, 32);
        // add to hash: hashSequence sha256(sha_sequences)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY) && (sighash_byte & 0x1f) != SIGHASH_SINGLE &&
            (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_sequences, 32, dbl_hash, 32);
        }
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    {
        // outpoint (32-byte prevout hash, 4-byte index)

        // get prevout hash and output index for the current input
        uint8_t prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_hash, 32);

        uint8_t prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_n_raw, 4);
    }

    // scriptCode
    if (is_p2wpkh(input->script, input->script_len)) {
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&sighash_context.header, 0x1976a914);
        crypto_hash_update(&sighash_context.header, input->script + 2, 20);
        crypto_hash_update_u16(&sighash_context.header, 0x88ac);
    } else if (is_p2wsh(input->script, input->script_len)) {
        // P2WSH

        // update sighash_context.header with the length-prefixed witnessScript,
        // and also compute sha256(witnessScript)
        cx_sha256_t witnessScript_hash_context;
        cx_sha256_init(&witnessScript_hash_context);

        int witnessScript_len = update_hashes_with_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_SCRIPT},
                                                             1,
                                                             &witnessScript_hash_context.header,
                                                             &sighash_context.header);

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t witnessScript_hash[32];
        crypto_hash_digest(&witnessScript_hash_context.header, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript)
        if (input->script_len != 2 + 32 || input->script[0] != 0x00 || input->script[1] != 0x20 ||
            memcmp(input->script + 2, witnessScript_hash, 32) != 0) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    {
        // input value, taken from the WITNESS_UTXO field
        uint8_t witness_utxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int witness_utxo_len = call_get_merkleized_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                             1,
                                                             witness_utxo,
                                                             sizeof(witness_utxo));
        if (witness_utxo_len < 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header,
                           witness_utxo,
                           8);  // only the first 8 bytes (amount)
    }

    // nSequence
    {
        uint8_t nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(nSequence_raw, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, nSequence_raw, 4);
    }

    {
        // compute hashOutputs = sha256(sha_outputs)

        uint8_t hashOutputs[32];
        memset(hashOutputs, 0, 32);

        if ((sighash_byte & 0x1f) != SIGHASH_SINGLE && (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_outputs, 32, hashOutputs, 32);

        } else if ((sighash_byte & 0x1f) == SIGHASH_SINGLE && cur_input_index < st->n_outputs) {
            cx_sha256_t sha_output_context;
            cx_sha256_init(&sha_output_context);
            if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            crypto_hash_digest(&sha_output_context.header, hashOutputs, 32);
            cx_hash_sha256(hashOutputs, 32, hashOutputs, 32);
        }
        crypto_hash_update(&sighash_context.header, hashOutputs, 32);
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // sighash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv1(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               segwit_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               placeholder_info_t *placeholder_info,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    crypto_tr_tagged_hash_init(&sighash_context, BIP0341_sighash_tag, sizeof(BIP0341_sighash_tag));
    // the first 0x00 byte is not part of SigMsg
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    uint8_t tmp[MAX(32, 8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)];

    // hash type
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    crypto_hash_update_u8(&sighash_context.header, sighash_byte);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    if ((sighash_byte & 0x80) != SIGHASH_ANYONECANPAY) {
        crypto_hash_update(&sighash_context.header, hashes->sha_prevouts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_amounts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_scriptpubkeys, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_sequences, 32);
    }

    if ((sighash_byte & 3) != SIGHASH_NONE && (sighash_byte & 3) != SIGHASH_SINGLE) {
        crypto_hash_update(&sighash_context.header, hashes->sha_outputs, 32);
    }

    // ext_flag
    uint8_t ext_flag = placeholder_info->is_tapscript ? 1 : 0;
    // annex is not supported
    const uint8_t annex_present = 0;
    uint8_t spend_type = ext_flag * 2 + annex_present;
    crypto_hash_update_u8(&sighash_context.header, spend_type);

    if ((sighash_byte & 0x80) == SIGHASH_ANYONECANPAY) {
        // outpoint (hash)
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                tmp,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 32);

        // outpoint (output index)
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               tmp,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);

        if (8 > call_get_merkleized_map_value(dc,
                                              &input->in_out.map,
                                              (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                              1,
                                              tmp,
                                              8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // amount
        crypto_hash_update(&sighash_context.header, tmp, 8);

        // scriptPubKey
        crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);

        crypto_hash_update(&sighash_context.header,
                           input->in_out.scriptPubKey,
                           input->in_out.scriptPubKey_len);

        // nSequence
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               tmp,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(tmp, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);
    } else {
        // input_index
        write_u32_le(tmp, 0, cur_input_index);
        crypto_hash_update(&sighash_context.header, tmp, 4);
    }

    // no annex

    if ((sighash_byte & 3) == SIGHASH_SINGLE) {
        // compute sha_output
        cx_sha256_t sha_output_context;
        cx_sha256_init(&sha_output_context);

        if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_digest(&sha_output_context.header, tmp, 32);

        crypto_hash_update(&sighash_context.header, tmp, 32);
    }

    if (placeholder_info->is_tapscript) {
        // If spending a tapscript, append the Common Signature Message Extension per BIP-0342
        crypto_hash_update(&sighash_context.header, placeholder_info->tapleaf_hash, 32);
        crypto_hash_update_u8(&sighash_context.header, 0x00);         // key_version
        crypto_hash_update_u32(&sighash_context.header, 0xffffffff);  // no OP_CODESEPARATOR
    }

    crypto_hash_digest(&sighash_context.header, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) yield_signature(dispatcher_context_t *dc,
                                                      sign_psbt_state_t *st,
                                                      unsigned int cur_input_index,
                                                      uint8_t *pubkey,
                                                      uint8_t pubkey_len,
                                                      uint8_t *tapleaf_hash,
                                                      uint8_t *sig,
                                                      size_t sig_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, cur_input_index);
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

static bool __attribute__((noinline))
sign_sighash_ecdsa_and_yield(dispatcher_context_t *dc,
                             sign_psbt_state_t *st,
                             placeholder_info_t *placeholder_info,
                             input_info_t *input,
                             unsigned int cur_input_index,
                             uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < placeholder_info->key_derivation_length; i++) {
        sign_path[i] = placeholder_info->key_derivation[i];
    }
    sign_path[placeholder_info->key_derivation_length] =
        input->in_out.is_change ? placeholder_info->placeholder.num_second
                                : placeholder_info->placeholder.num_first;
    sign_path[placeholder_info->key_derivation_length + 1] = input->in_out.address_index;

    int sign_path_len = placeholder_info->key_derivation_length + 2;

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
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    sig[sig_len++] = sighash_byte;

    if (!yield_signature(dc, st, cur_input_index, pubkey, 33, NULL, sig, sig_len)) return false;

    return true;
}

static bool __attribute__((noinline))
sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                               sign_psbt_state_t *st,
                               placeholder_info_t *placeholder_info,
                               input_info_t *input,
                               unsigned int cur_input_index,
                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

    uint8_t *tapleaf_hash = NULL;

    bool error = false;
    cx_ecfp_private_key_t private_key = {0};

    // IMPORTANT: Since we do not use any syscall that might throw an exception, it is safe to avoid
    // using the TRY/CATCH block to ensure zeroing sensitive data.

    do {  // block executed once, only to allow safely breaking out on error

        uint8_t *seckey =
            private_key.d;  // convenience alias (entirely within the private_key struct)

        uint32_t sign_path[MAX_BIP32_PATH_STEPS];

        for (int i = 0; i < placeholder_info->key_derivation_length; i++) {
            sign_path[i] = placeholder_info->key_derivation[i];
        }
        sign_path[placeholder_info->key_derivation_length] =
            input->in_out.is_change ? placeholder_info->placeholder.num_second
                                    : placeholder_info->placeholder.num_first;
        sign_path[placeholder_info->key_derivation_length + 1] = input->in_out.address_index;

        int sign_path_len = placeholder_info->key_derivation_length + 2;

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            error = true;
            break;
        }

        policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;

        if (!placeholder_info->is_tapscript) {
            if (isnull_policy_node_tree(&policy->tree)) {
                // tweak as specified in BIP-86 and BIP-386
                crypto_tr_tweak_seckey(seckey, (uint8_t[]){}, 0, seckey);
            } else {
                // tweak with the taptree hash, per BIP-341
                // The taptree hash is computed in sign_transaction_input in order to
                // reduce stack usage.
                crypto_tr_tweak_seckey(seckey, input->taptree_hash, 32, seckey);
            }
        } else {
            // tapscript, we need to yield the tapleaf hash together with the pubkey
            tapleaf_hash = placeholder_info->tapleaf_hash;
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
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        sig[sig_len++] = sighash_byte;
    }

    if (!yield_signature(dc,
                         st,
                         cur_input_index,
                         pubkey_tweaked.W + 1,  // x-only pubkey, hence take only the x-coordinate
                         32,
                         tapleaf_hash,
                         sig,
                         sig_len))
        return false;

    return true;
}

static bool __attribute__((noinline))
compute_segwit_hashes(dispatcher_context_t *dc, sign_psbt_state_t *st, segwit_hashes_t *hashes) {
    {
        // compute sha_prevouts and sha_sequences
        cx_sha256_t sha_prevouts_context, sha_sequences_context;

        // compute hashPrevouts and hashSequence
        cx_sha256_init(&sha_prevouts_context);
        cx_sha256_init(&sha_sequences_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // get prevout hash and output index for the i-th input
            uint8_t ith_prevout_hash[32];
            if (32 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                    1,
                                                    ith_prevout_hash,
                                                    32)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_hash, 32);

            uint8_t ith_prevout_n_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                   1,
                                                   ith_prevout_n_raw,
                                                   4)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_n_raw, 4);

            uint8_t ith_nSequence_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_SEQUENCE},
                                                   1,
                                                   ith_nSequence_raw,
                                                   4)) {
                // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
                memset(ith_nSequence_raw, 0xFF, 4);
            }

            crypto_hash_update(&sha_sequences_context.header, ith_nSequence_raw, 4);
        }

        crypto_hash_digest(&sha_prevouts_context.header, hashes->sha_prevouts, 32);
        crypto_hash_digest(&sha_sequences_context.header, hashes->sha_sequences, 32);
    }

    {
        // compute sha_outputs
        cx_sha256_t sha_outputs_context;
        cx_sha256_init(&sha_outputs_context);

        if (hash_outputs(dc, st, &sha_outputs_context.header) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_digest(&sha_outputs_context.header, hashes->sha_outputs, 32);
    }

    {
        // compute sha_amounts and sha_scriptpubkeys
        // TODO: could be skipped if there are no segwitv1 inputs to sign

        cx_sha256_t sha_amounts_context, sha_scriptpubkeys_context;

        cx_sha256_init(&sha_amounts_context);
        cx_sha256_init(&sha_scriptpubkeys_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint64_t in_amount;
            uint8_t in_scriptPubKey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            size_t in_scriptPubKey_len;

            if (0 > get_amount_scriptpubkey_from_psbt(dc,
                                                      &ith_map,
                                                      &in_amount,
                                                      in_scriptPubKey,
                                                      &in_scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            if (in_scriptPubKey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
                // this should never happen
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint8_t in_amount_le[8];
            write_u64_le(in_amount_le, 0, in_amount);
            crypto_hash_update(&sha_amounts_context.header, in_amount_le, 8);

            crypto_hash_update_varint(&sha_scriptpubkeys_context.header, in_scriptPubKey_len);
            crypto_hash_update(&sha_scriptpubkeys_context.header,
                               in_scriptPubKey,
                               in_scriptPubKey_len);
        }

        crypto_hash_digest(&sha_amounts_context.header, hashes->sha_amounts, 32);
        crypto_hash_digest(&sha_scriptpubkeys_context.header, hashes->sha_scriptpubkeys, 32);
    }

    return true;
}

static bool __attribute__((noinline)) sign_transaction_input(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             segwit_hashes_t *hashes,
                                                             placeholder_info_t *placeholder_info,
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

    // Sign as segwit input iff it has a witness utxo
    if (!input->has_witnessUtxo) {
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

        if (input->in_out.scriptPubKey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
            // this should never happen
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (!input->has_sighash_type) {
            // legacy input default to SIGHASH_ALL
            input->sighash_type = SIGHASH_ALL;
        }

        uint8_t sighash[32];
        if (!compute_sighash_legacy(dc, st, input, cur_input_index, sighash)) return false;

        if (!sign_sighash_ecdsa_and_yield(dc,
                                          st,
                                          placeholder_info,
                                          input,
                                          cur_input_index,
                                          sighash))
            return false;
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
                    SEND_SW(dc, SW_INCORRECT_DATA);
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
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_ALL
                input->sighash_type = SIGHASH_ALL;
            }

            if (!compute_sighash_segwitv0(dc, st, hashes, input, cur_input_index, sighash))
                return false;

            if (!sign_sighash_ecdsa_and_yield(dc,
                                              st,
                                              placeholder_info,
                                              input,
                                              cur_input_index,
                                              sighash))
                return false;
        } else if (segwit_version == 1) {
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_DEFAULT
                input->sighash_type = SIGHASH_DEFAULT;
            }

            if (!compute_sighash_segwitv1(dc,
                                          st,
                                          hashes,
                                          input,
                                          cur_input_index,
                                          placeholder_info,
                                          sighash))
                return false;

            policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;
            if (!placeholder_info->is_tapscript && !isnull_policy_node_tree(&policy->tree)) {
                // keypath spend, we compute the taptree hash so that we find it ready
                // later in sign_sighash_schnorr_and_yield (which has less available stack).
                if (0 > compute_taptree_hash(
                            dc,
                            &(wallet_derivation_info_t){
                                .address_index = input->in_out.address_index,
                                .change = input->in_out.is_change ? 1 : 0,
                                .keys_merkle_root = st->wallet_header_keys_info_merkle_root,
                                .n_keys = st->wallet_header_n_keys,
                                .wallet_version = st->wallet_header_version},
                            r_policy_node_tree(&policy->tree),
                            input->taptree_hash)) {
                    PRINTF("Error while computing taptree hash\n");
                    SEND_SW(dc, SW_BAD_STATE);
                    return false;
                }
            }

            if (!sign_sighash_schnorr_and_yield(dc,
                                                st,
                                                placeholder_info,
                                                input,
                                                cur_input_index,
                                                sighash))
                return false;

        } else {
            SEND_SW(dc, SW_BAD_STATE);  // can't happen
            return false;
        }
    }
    return true;
}

static bool __attribute__((noinline))
fill_taproot_placeholder_info(dispatcher_context_t *dc,
                              sign_psbt_state_t *st,
                              const input_info_t *input,
                              const policy_node_t *tapleaf_ptr,
                              placeholder_info_t *placeholder_info) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    // we compute the tapscript once just to compute its length
    // this avoids having to store it
    int tapscript_len = get_wallet_internal_script_hash(
        dc,
        tapleaf_ptr,
        &(wallet_derivation_info_t){.wallet_version = st->wallet_header_version,
                                    .keys_merkle_root = st->wallet_header_keys_info_merkle_root,
                                    .n_keys = st->wallet_header_n_keys,
                                    .change = input->in_out.is_change,
                                    .address_index = input->in_out.address_index},
        WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
        NULL);
    if (tapscript_len < 0) {
        PRINTF("Failed to compute tapleaf script\n");
        return false;
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    // we compute it again to get add the actual script code to the hash computation
    if (0 >
        get_wallet_internal_script_hash(
            dc,
            tapleaf_ptr,
            &(wallet_derivation_info_t){.wallet_version = st->wallet_header_version,
                                        .keys_merkle_root = st->wallet_header_keys_info_merkle_root,
                                        .n_keys = st->wallet_header_n_keys,
                                        .change = input->in_out.is_change,
                                        .address_index = input->in_out.address_index},
            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
            &hash_context.header)) {
        return false;  // should never happen!
    }
    crypto_hash_digest(&hash_context.header, placeholder_info->tapleaf_hash, 32);

    return true;
}

static bool __attribute__((noinline))
sign_transaction(dispatcher_context_t *dc,
                 sign_psbt_state_t *st,
                 const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    int placeholder_index = 0;

    segwit_hashes_t hashes;

    // compute all the tx-wide hashes
    // while this is redundant for legacy transactions, we do it here in order to
    // avoid doing it in places that have more stack limitations
    if (!compute_segwit_hashes(dc, st, &hashes)) return false;

    // Iterate over all the placeholders that correspond to keys owned by us
    while (true) {
        placeholder_info_t placeholder_info;
        memset(&placeholder_info, 0, sizeof(placeholder_info));

        const policy_node_t *tapleaf_ptr = NULL;
        int n_key_placeholders = get_key_placeholder_by_index(st->wallet_policy_map,
                                                              placeholder_index,
                                                              &tapleaf_ptr,
                                                              &placeholder_info.placeholder);

        if (n_key_placeholders < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            if (!G_swap_state.called_from_swap) {
                ui_post_processing_confirm_transaction(dc, false);
            }
            return false;
        }

        if (placeholder_index >= n_key_placeholders) {
            // all placeholders were processed
            break;
        }

        if (tapleaf_ptr != NULL) {
            // get_key_placeholder_by_index returns the pointer to the tapleaf only if the key being
            // spent is indeed in a tapleaf
            placeholder_info.is_tapscript = true;
        }

        if (fill_placeholder_info_if_internal(dc, st, &placeholder_info) == true) {
            for (unsigned int i = 0; i < st->n_inputs; i++)
                if (bitvector_get(internal_inputs, i)) {
                    input_info_t input;
                    memset(&input, 0, sizeof(input));

                    input_keys_callback_data_t callback_data = {
                        .input = &input,
                        .placeholder_info = &placeholder_info};
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
                        if (!G_swap_state.called_from_swap) {
                            ui_post_processing_confirm_transaction(dc, false);
                        }
                        return false;
                    }

                    if (tapleaf_ptr != NULL && !fill_taproot_placeholder_info(dc,
                                                                              st,
                                                                              &input,
                                                                              tapleaf_ptr,
                                                                              &placeholder_info))
                        return false;

                    if (!sign_transaction_input(dc, st, &hashes, &placeholder_info, &input, i)) {
                        if (!G_swap_state.called_from_swap) {
                            ui_post_processing_confirm_transaction(dc, false);
                        }

                        // we do not send a status word, since sign_transaction_input
                        // already does it on failure
                        return false;
                    }
                }
        }

        ++placeholder_index;
    }

    if (!G_swap_state.called_from_swap) {
        ui_post_processing_confirm_transaction(dc, true);
    }
    return true;
}

void handler_sign_psbt(dispatcher_context_t *dc, uint8_t protocol_version) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    sign_psbt_state_t st;
    memset(&st, 0, sizeof(st));

    st.protocol_version = protocol_version;

    // read APDU inputs, intialize global state and read global PSBT map
    if (!init_global_state(dc, &st)) return;

    // bitmap to keep track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];
    memset(internal_inputs, 0, sizeof(internal_inputs));

    /** Inputs verification flow
     *
     *  Go though all the inputs:
     *  - verify the non_witness_utxo
     *  - compute value spent
     *  - detect internal inputs that should be signed, and if there are external inputs or unusual
     * sighashes
     */
    if (!preprocess_inputs(dc, &st, internal_inputs)) return;

    /** INPUT VERIFICATION ALERTS
     *
     * Show warnings and allow users to abort in any of the following conditions:
     * - pre-taproot transaction with unverified inputs (missing non-witness-utxo)
     * - external inputs
     * - non-default sighash types
     */
    if (!show_alerts(dc, &st, internal_inputs)) return;

    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Show each output that is not a change address to the user for verification.
     */
    if (!process_outputs(dc, &st)) return;

    /** TRANSACTION CONFIRMATION
     *
     *  Show summary info to the user (transaction fees), ask for final confirmation
     */
    if (!confirm_transaction(dc, &st)) return;

    /** SIGNING FLOW
     *
     * For each internal placeholder, and for each internal input, sign using the
     * appropriate algorithm.
     */
    if (!sign_transaction(dc, &st, internal_inputs)) return;

    // Only if called from swap, the app should terminate after sending the response
    if (G_swap_state.called_from_swap) {
        G_swap_state.should_exit = true;
    }

    SEND_SW(dc, SW_OK);
}
