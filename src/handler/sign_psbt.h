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
#include "display.h"
#include "merkle.h"
#include "musig_sessions.h"

// common info that applies to either the current input or the current output
typedef struct {
    merkleized_map_commitment_t map;

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_{IN,OUT}_BIP32_DERIVATION or
                                   // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION is not the correct length.

    bool key_expression_found;  // Set to true if the input/output info in the psbt was correctly
                                // matched with the current key expression in the signing flow

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
    policy_node_keyexpr_t *key_expression_ptr;
    // index of this key expression in the descriptor template, in parsing order
    int index;
    uint32_t fingerprint;

    // we only sign for keys expressions for which we find a matching key derivation in the PSBT,
    // at least for one of the inputs
    bool to_sign;

    // info about the internal key of this key expression
    // used at signing time to derive the correct key
    uint32_t key_derivation[MAX_BIP32_PATH_STEPS];
    uint8_t key_derivation_length;

    // same as key_derivation_length for internal key
    // expressions; 0 for musig, as the key derivation in
    // the PSBT use the aggregate key as the root
    // used to identify the correct change/address_index from the psbt
    uint8_t psbt_root_key_derivation_length;

    // the root pubkey of this key expression
    serialized_extended_pubkey_t pubkey;
    // the pubkey of the internal key of this key expression.
    // same as `pubkey` for simple key expressions, but it's the actual
    // internal key for musig key expressions
    serialized_extended_pubkey_t internal_pubkey;

    bool is_tapscript;  // true if signing with a BIP342 tapleaf script path spend
    // only used for tapscripts
    const policy_node_t *tapleaf_ptr;
    uint8_t tapleaf_hash[32];
} keyexpr_info_t;

// Cache for partial hashes during signing (avoid quadratic hashing for segwit transactions)
typedef struct tx_hashes_s {
    uint8_t sha_prevouts[32];
    uint8_t sha_amounts[32];
    uint8_t sha_scriptpubkeys[32];
    uint8_t sha_sequences[32];
    uint8_t sha_outputs[32];
} tx_hashes_t;

// the signing state for the current transaction; it does not contain any per-input state
typedef struct signing_state_s {
    tx_hashes_t tx_hashes;
    musig_signing_state_t musig;
} signing_state_t;

// We cache the first MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER external outputs;
// This is used by the code for the simplified UX for transactions;
// Moreover, that is needed for the swap checks.
#define N_CACHED_EXTERNAL_OUTPUTS MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER

// Per-wallet-account context used during signing.
// Groups the wallet policy AST, its header, the standard/registered flag, and
// the device-controlled key expressions discovered in the policy.
typedef struct {
    policy_map_wallet_header_t wallet_header;

    // true iff the wallet policy is a default (BIP-44/49/84/86) policy used without HMAC.
    bool is_default;

    __attribute__((aligned(4))) uint8_t policy_map_bytes[MAX_WALLET_POLICY_BYTES];
    policy_node_t *policy_map;

    unsigned int n_internal_key_expressions;
    keyexpr_info_t internal_key_expressions[MAX_INTERNAL_KEY_EXPRESSIONS];
} account_ctx_t;

typedef struct {
    uint32_t master_key_fingerprint;
    uint32_t tx_version;
    uint32_t locktime;

    merkleized_map_commitment_t global_map;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    uint64_t inputs_total_amount;
    uint64_t internal_inputs_total_amount;

    unsigned int n_external_inputs;
    unsigned int n_external_outputs;

    // true if no wallet policy was passed in the initial APDU of sign_psbt;
    // in that case, all inputs and outputs are assumed external (the derived app
    // signs the custom inputs itself).
    bool has_no_wallet_policy;

    // set to true if at least a PSBT_IN_MUSIG2_PUB_NONCE field is present in the PSBT
    bool has_musig2_pub_nonces;

    // aggregate info on outputs
    struct {
        uint64_t total_amount;         // amount of all the outputs (external + change)
        uint64_t change_total_amount;  // total amount of all change outputs
        int n_change;                  // count of outputs compatible with change outputs
        size_t output_script_lengths[N_CACHED_EXTERNAL_OUTPUTS];
        uint8_t output_scripts[N_CACHED_EXTERNAL_OUTPUTS][MAX_OUTPUT_SCRIPTPUBKEY_LEN];
        uint64_t output_amounts[N_CACHED_EXTERNAL_OUTPUTS];
    } outputs;

    uint8_t protocol_version;

    // The wallet account used to sign this transaction.
    account_ctx_t account;

    tx_ux_warning_t warnings;

} sign_psbt_state_t;
