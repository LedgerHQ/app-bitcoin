/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
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

#include "bip322_validation.h"

/* Local headers */
#include "amount_from_psbt.h"
#include "bip322.h"
#include "constants.h"
#include "error_codes.h"
#include "get_merkleized_map.h"
#include "psbt_fields.h"
#include "script.h"
#include "sw.h"

bool __attribute__((noinline)) validate_bip322_request(dispatcher_context_t *dc,
                                                       sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // The to_sign transaction must have exactly one output: a zero-value bare OP_RETURN.
    // preprocess_outputs() cached it as the first (and only) external output; the read below
    // relies on the first external output always being cached.
    _Static_assert(N_CACHED_EXTERNAL_OUTPUTS >= 1, "the first external output must be cached");
    if (st->n_outputs != 1 || st->n_external_outputs != 1 || st->outputs.n_change != 0 ||
        st->outputs.total_amount != 0 || st->outputs.output_script_lengths[0] != 1 ||
        st->outputs.output_scripts[0][0] != OP_RETURN) {
        PRINTF("BIP-322: output is not a single zero-value bare OP_RETURN\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE);
        return false;
    }

    // BIP-322 upgradeable rules: the transaction version must be 0 or 2.
    // The total input amount (zero for a plain message signing; the sum of the proven coins
    // for a proof-of-funds) is shown to the user, so it must pass the same sanity bound used
    // elsewhere.
    if ((st->tx_version != 0 && st->tx_version != 2) ||
        st->inputs_total_amount > BITCOIN_TOTAL_SUPPLY) {
        PRINTF("BIP-322: invalid transaction version or input amount\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE);
        return false;
    }

    // BIP-322 required rules: all signatures use SIGHASH_ALL (or SIGHASH_DEFAULT for taproot).
    if (st->warnings.non_default_sighash) {
        PRINTF("BIP-322: only SIGHASH_ALL or SIGHASH_DEFAULT are allowed\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_FORBIDDEN_SIGHASH);
        return false;
    }

    // Timelocked BIP-322 signatures are valid per the BIP, but not supported yet.
    if (st->locktime != 0) {
        PRINTF("BIP-322: timelocks are not supported\n");
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_BIP322_UNSUPPORTED);
        return false;
    }

    // Any input beyond the first makes this a proof-of-funds. Every input must then belong to
    // the wallet policy: the total proven amount shown to the user must be trustworthy, and
    // external inputs could not be signed anyway.
    if (st->warnings.external_inputs) {
        PRINTF("BIP-322: all inputs must belong to the wallet policy\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_EXTERNAL_INPUTS);
        return false;
    }

    for (unsigned int cur_input_index = 0; cur_input_index < st->n_inputs; cur_input_index++) {
        merkleized_map_commitment_t input_map;
        if (0 > call_get_merkleized_map(dc,
                                        st->inputs_root,
                                        st->n_inputs,
                                        cur_input_index,
                                        &input_map)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // Every input must have sequence 0. A missing PSBT_IN_SEQUENCE defaults to the final
        // sequence number (0xFFFFFFFF) per BIP-370, so it must be present. (Non-zero sequences
        // only appear in the timelocked variants, which are not supported yet.)
        uint32_t sequence;
        if (PSBT_FIELD_PRESENT != psbt_get_input_sequence(dc, &input_map, &sequence) ||
            sequence != 0) {
            PRINTF("BIP-322: non-zero (or missing) sequence is not supported\n");
            SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_BIP322_UNSUPPORTED);
            return false;
        }

        if (cur_input_index != 0) {
            // Additional (proof-of-funds) inputs spend real UTXOs of the wallet policy; their
            // amounts and scripts were already verified and aggregated by preprocess_inputs().
            continue;
        }

        // The first input must spend output 0 of to_spend.
        uint32_t prevout_index;
        if (PSBT_FIELD_PRESENT != psbt_get_input_prevout_index(dc, &input_map, &prevout_index) ||
            prevout_index != 0) {
            PRINTF("BIP-322: the input does not spend the first output of to_spend\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE);
            return false;
        }

        uint8_t prevout_txid[32];
        if (PSBT_FIELD_PRESENT != psbt_get_input_prevout_txid(dc, &input_map, prevout_txid)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint64_t amount;
        uint8_t challenge_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        size_t challenge_script_len;
        if (0 > get_amount_scriptpubkey_from_psbt(dc,
                                                  &input_map,
                                                  &amount,
                                                  challenge_script,
                                                  &challenge_script_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // The virtual to_spend output has zero value; only the additional (real) inputs may
        // contribute to the proven amount.
        if (amount != 0) {
            PRINTF("BIP-322: the to_spend output must have zero value\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE);
            return false;
        }

        // The security anchor: the input's prevout txid must equal the txid of the to_spend
        // transaction recomputed from the message hash and the input's own scriptPubKey. This
        // binds the signature to the message shown to the user, and makes the signed
        // transaction provably unspendable (to_spend's input references the null outpoint).
        uint8_t expected_txid[32];
        if (0 > bip322_compute_to_spend_txid(st->bip322.message_hash,
                                             challenge_script,
                                             challenge_script_len,
                                             expected_txid)) {
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_INVALID_STRUCTURE);
            return false;
        }

        if (memcmp(expected_txid, prevout_txid, sizeof(expected_txid)) != 0) {
            PRINTF("BIP-322: the input does not spend to_spend for this message\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_BIP322_TOSPEND_MISMATCH);
            return false;
        }

        memcpy(st->bip322.challenge_script, challenge_script, challenge_script_len);
        st->bip322.challenge_script_len = challenge_script_len;
    }

    return true;
}
