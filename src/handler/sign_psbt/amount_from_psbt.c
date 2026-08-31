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

#include "amount_from_psbt.h"

/* Local headers */
#include "get_merkleized_map_value.h"
#include "psbt.h"
#include "psbt_fields.h"
#include "psbt_parse_rawtx.h"

/* SDK headers */
#include "read.h"

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness(
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
    if (PSBT_FIELD_PRESENT != psbt_get_input_prevout_index(dc, input_map, &prevout_n)) {
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
                                    (uint8_t[]) {PSBT_IN_NON_WITNESS_UTXO},
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
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_witness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len) {
    uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

    int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                     input_map,
                                                     (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                     1,
                                                     raw_witnessUtxo,
                                                     sizeof(raw_witnessUtxo));

    // the witness UTXO field is encoded as 8-bytes for the amount, followed by the length-prefixed
    // scriptPubkey. We make sure that we can read at least up to the scriptPubkey length, to avoid
    // reading a possibly-undefined byte at offset 8.
    if (wit_utxo_len < 8 + 1) {
        return -1;
    }
    size_t wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

    if ((size_t) wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
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
int get_amount_scriptpubkey_from_psbt(dispatcher_context_t *dc,
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
