#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../constants.h"

typedef struct {
    uint64_t vout_value;                 // will contain the value of the requested output
    unsigned int vout_scriptpubkey_len;  // will contain the len of the scriptPubKey
    uint8_t vout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];  // will contain the scriptPubKey
    uint8_t txid[32];                                         // will contain the computed txid
} txid_parser_outputs_t;

/**
 * Given a commitment to a merkleized map and a key, this flow parses it as a serialized bitcoin
 * transaction, computes the transaction id and optionally keeps track of the vout amunt and
 * scriptPubkey of one of the outputs.
 *
 * If output_index is SIZE_MAX, no output is queried, and only the txid field of outputs is
 * meaningful on success. Otherwise, the flow fails unless the transaction has an output with that
 * index, and its value and scriptPubKey are returned in outputs.
 *
 * On failure, the content of outputs is unspecified; on success, any field that is not filled in
 * is zeroed.
 */
int call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *map,
                          const uint8_t *key,
                          size_t key_len,
                          size_t output_index,
                          txid_parser_outputs_t *outputs);
