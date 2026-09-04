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
#include <stdio.h>
#include <string.h>

#include "bip322.h"

/* SDK headers */
#include "write.h"

/* Local headers */
#include "amount_from_psbt.h"
#include "crypto.h"
#include "display.h"
#include "error_codes.h"
#include "get_merkleized_map.h"
#include "psbt.h"
#include "psbt_fields.h"
#include "script.h"
#include "stream_merkleized_map_value.h"
#include "sw.h"
#include "transaction_display.h"

extern const char GA_SIGNING_MESSAGE[];

// The BIP-340 tag used for the message hash, as defined by BIP-322.
static const uint8_t BIP0322_MSG_TAG[] = {'B', 'I', 'P', '0', '3', '2', '2', '-', 's', 'i', 'g',
                                          'n', 'e', 'd', '-', 'm', 'e', 's', 's', 'a', 'g', 'e'};

int bip322_serialize_to_spend(const uint8_t message_hash[static 32],
                              const uint8_t *challenge_script,
                              size_t challenge_script_len,
                              uint8_t out[static BIP322_TO_SPEND_MAX_LEN]) {
    if (challenge_script_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    size_t offset = 0;
    write_u32_le(out, offset, 0);  // nVersion = 0
    offset += 4;
    out[offset++] = 0x01;         // 1 input
    memset(out + offset, 0, 32);  // prevout hash = null
    offset += 32;
    write_u32_le(out, offset, 0xFFFFFFFF);  // prevout index
    offset += 4;
    out[offset++] = 34;    // scriptSig length
    out[offset++] = 0x00;  // OP_0
    out[offset++] = 0x20;  // push of 32 bytes
    memcpy(out + offset, message_hash, 32);
    offset += 32;
    write_u32_le(out, offset, 0);  // nSequence = 0
    offset += 4;
    out[offset++] = 0x01;        // 1 output
    memset(out + offset, 0, 8);  // value = 0
    offset += 8;
    out[offset++] = (uint8_t) challenge_script_len;
    memcpy(out + offset, challenge_script, challenge_script_len);
    offset += challenge_script_len;
    write_u32_le(out, offset, 0);  // nLockTime = 0
    offset += 4;

    return (int) offset;
}

int bip322_compute_to_spend_txid(const uint8_t message_hash[static 32],
                                 const uint8_t *challenge_script,
                                 size_t challenge_script_len,
                                 uint8_t out_txid[static 32]) {
    uint8_t to_spend[BIP322_TO_SPEND_MAX_LEN];

    int len =
        bip322_serialize_to_spend(message_hash, challenge_script, challenge_script_len, to_spend);
    if (len < 0) {
        return -1;
    }

    cx_hash_sha256(to_spend, len, out_txid, 32);
    cx_hash_sha256(out_txid, 32, out_txid, 32);
    return 0;
}

// State for the message-hashing streaming pass.
typedef struct {
    cx_sha256_t tagged_hash_context;  // BIP0322-signed-message tagged hash
    cx_sha256_t sha256_context;       // plain sha256, for display of long/unprintable messages
    bool printable;
} msg_hash_state_t;

static void message_hash_callback(buffer_t *data, void *cb_state) {
    msg_hash_state_t *state = (msg_hash_state_t *) cb_state;
    const uint8_t *bytes = data->ptr + data->offset;
    size_t len = data->size - data->offset;

    crypto_hash_update(&state->tagged_hash_context.header, bytes, len);
    crypto_hash_update(&state->sha256_context.header, bytes, len);

    for (size_t i = 0; i < len; i++) {
        // Line Feed (LF) character is handled by NBGL - let's allow it
        if ((bytes[i] < 0x20 || bytes[i] > 0x7E) && bytes[i] != '\n') {
            state->printable = false;
        }
    }
}

// State for the message-copying streaming pass (into the UI buffer).
typedef struct {
    char *out;
    size_t max;  // capacity of out, excluding the terminating NUL
    size_t offset;
    bool overflow;
} msg_copy_state_t;

static void message_copy_callback(buffer_t *data, void *cb_state) {
    msg_copy_state_t *state = (msg_copy_state_t *) cb_state;
    size_t len = data->size - data->offset;

    if (state->overflow || state->offset + len > state->max) {
        state->overflow = true;
        return;
    }
    memcpy(state->out + state->offset, data->ptr + data->offset, len);
    state->offset += len;
}

bool bip322_detect(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t key[] = {PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE};

    // Stream the message, computing its hashes and printability. The read doubles as the
    // presence check: the map reader reports a key the client says is absent distinctly from a
    // failed lookup, so no separate probe is needed.
    msg_hash_state_t hash_state;
    crypto_tr_tagged_hash_init(&hash_state.tagged_hash_context,
                               BIP0322_MSG_TAG,
                               sizeof(BIP0322_MSG_TAG));
    cx_sha256_init(&hash_state.sha256_context);
    hash_state.printable = true;

    int message_length = call_stream_merkleized_map_value(dc,
                                                          &st->global_map,
                                                          key,
                                                          sizeof(key),
                                                          NULL,
                                                          message_hash_callback,
                                                          &hash_state);
    if (message_length == MAP_VALUE_ABSENT) {
        // The client says the field is not in the map. That claim is not proved, and it does not
        // need to be: a client that hides (or never sets) the field gets the regular transaction
        // review instead, where the to_sign transaction is shown as a zero-value transaction with
        // a bare OP_RETURN output, exactly as before this feature existed. What this flow
        // guarantees is that the message review UI is only ever shown after bip322_validate() has
        // bound the displayed message to the produced signature.
        st->bip322.is_message_signing = false;
        return true;
    }
    if (message_length < 0) {  // MAP_VALUE_ERROR
        PRINTF("Failed to stream the BIP-322 message\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    st->bip322.is_message_signing = true;
    st->bip322.message_length = (uint64_t) message_length;
    st->bip322.message_printable =
        hash_state.printable && message_length <= MAX_DISPLAYBLE_MESSAGE_LENGTH;

    crypto_hash_digest(&hash_state.tagged_hash_context.header, st->bip322.message_hash, 32);
    crypto_hash_digest(&hash_state.sha256_context.header, st->bip322.message_sha256, 32);

    return true;
}

bool __attribute__((noinline)) bip322_validate(dispatcher_context_t *dc, sign_psbt_state_t *st) {
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
        // only appear in the timelocked variants, which are not supported yet.) A field that is
        // present but malformed is a protocol error rather than an unsupported request, so it
        // must not be folded into the same status word.
        uint32_t sequence;
        psbt_field_status_t sequence_status = psbt_get_input_sequence(dc, &input_map, &sequence);
        if (sequence_status == PSBT_FIELD_ERROR) {
            PRINTF("BIP-322: malformed PSBT_IN_SEQUENCE\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (sequence_status != PSBT_FIELD_PRESENT || sequence != 0) {
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

    // For a plain message signing, the only "utxo" is the to_spend transaction, which is
    // entirely recomputed on-device: the missing-non-witness-utxo warning is then unwarranted.
    // For a proof-of-funds, the warning may refer to the additional (real) inputs, whose
    // amounts are shown to the user, so it must be kept.
    if (st->n_inputs == 1) {
        st->warnings.missing_nonwitnessutxo = false;
    }

    return true;
}

bool __attribute__((noinline)) bip322_display_message(dispatcher_context_t *dc,
                                                      sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Show any input verification warnings, exactly as the transaction review does. All the
    // current warnings are either unreachable in BIP-322 mode or cleared by bip322_validate();
    // this keeps any warning added in the future from being silently skipped in this flow.
    if (!display_warnings(dc, st)) {
        return false;
    }

    char address[MAX_ADDRESS_LENGTH_STR + 1];
    if (0 > get_script_address(st->bip322.challenge_script,
                               st->bip322.challenge_script_len,
                               address,
                               sizeof(address))) {
        // wallet policies always produce scripts with an address; this should never happen
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    char account_label_buf[MAX_WALLET_NAME_LENGTH + 1];
    const char *account_label = st->account.wallet_header.name;
    if (st->account.is_default) {
        account_label = NULL;
        if (format_default_account_label(st->account.bip44_purpose,
                                         st->account.bip44_account,
                                         account_label_buf,
                                         sizeof(account_label_buf))) {
            account_label = account_label_buf;
        }
    }

    ui_bip322_message_state_t *ui_state = (ui_bip322_message_state_t *) &g_ui_state;
    bool is_hash = !st->bip322.message_printable;

    if (!is_hash) {
        // Stream the message again, this time into the UI buffer. The fetch is authenticated
        // by the same Merkle commitment as the hashing pass in bip322_detect(), so the client
        // cannot provide different contents.
        msg_copy_state_t copy_state = {.out = ui_state->message,
                                       .max = MAX_DISPLAYBLE_MESSAGE_LENGTH,
                                       .offset = 0,
                                       .overflow = false};
        int message_length =
            call_stream_merkleized_map_value(dc,
                                             &st->global_map,
                                             (uint8_t[]) {PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE},
                                             1,
                                             NULL,
                                             message_copy_callback,
                                             &copy_state);
        // Any negative result is a failure here, unlike in bip322_detect(): the client already
        // served this field once, so a MAP_VALUE_ABSENT now would be it contradicting itself.
        // The length equality further pins the value to the one that was hashed at detection.
        if (message_length < 0 || copy_state.overflow ||
            (uint64_t) message_length != st->bip322.message_length) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        ui_state->message[copy_state.offset] = '\0';
    } else {
        // The message is too long or not printable: show its sha256 hash instead, like the
        // legacy message signing flow does.
        for (int i = 0; i < 32; i++) {
            snprintf(ui_state->message + 2 * i, 3, "%02X", st->bip322.message_sha256[i]);
        }
    }

    // For a proof-of-funds, also show the total amount of the coins whose control is proven.
    bool is_proof_of_funds = st->n_inputs > 1;

    ui_set_processing_screen_text(GA_SIGNING_MESSAGE);
    if (!ui_display_bip322_message_and_confirm(dc,
                                               account_label,
                                               address,
                                               is_hash,
                                               is_proof_of_funds,
                                               st->inputs_total_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}
