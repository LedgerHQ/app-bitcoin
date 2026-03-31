#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "extract_bip32_derivation.h"

/* SDK headers */
#include "read.h"
#include "varint.h"

/* Local headers */
#include "psbt.h"
#include "stream_merkle_leaf_element.h"

typedef struct {
    int psbt_key_type;
    uint8_t *out;
    int total_data_length;
    int out_data_length;  // set to -1 before it's computed on the first call of
                          // fpt_der_data_callback
    int result;
} fpt_der_callback_data_t;

static void fpt_der_data_len_callback(size_t data_length, void *callback_state) {
    fpt_der_callback_data_t *cs = (fpt_der_callback_data_t *) callback_state;

    if (data_length > INT_MAX) {
        // fail early if the conversion to int would overflow
        // by setting the error result in the callback state
        cs->result = -1;
        return;
    }
    cs->total_data_length = data_length;
}

static void fpt_der_data_callback(buffer_t *data, void *callback_state) {
    fpt_der_callback_data_t *cs = (fpt_der_callback_data_t *) callback_state;

    if (cs->result < 0) return;  // an error already happened, ignore the rest

    if (data->size == 0) {
        // ignore empty chunks
        return;
    }

    // on the first call, compute the length the fingerprint + derivation part of the message.
    // - if non-taproot, then it's the entire message;
    // - if taproot, it's the message after the hashes are removed.
    int max_out_data_length = 4 * (1 + MAX_BIP32_PATH_STEPS);
    if (cs->out_data_length == -1) {
        bool is_tap = cs->psbt_key_type == PSBT_IN_TAP_BIP32_DERIVATION ||
                      cs->psbt_key_type == PSBT_OUT_TAP_BIP32_DERIVATION;

        if (!is_tap) {
            if (cs->total_data_length > max_out_data_length) {
                PRINTF("BIP32 derivation longer than supported in psbt derivation\n");
                cs->result = -1;
                return;
            }
            cs->out_data_length = cs->total_data_length;
        } else {
            // While BIP-0174 defines the number of hashes as a compact size integer, this
            // can never be more than 128 in taproot. Since such numbers are always encoded
            // as a single byte, we simplify by reading a single byte instead of a varint.
            uint8_t n_hashes;
            if ((!buffer_read_u8(data, &n_hashes)) ||
                (cs->total_data_length < 1 + 32 * (int) n_hashes)) {
                PRINTF("Unexpected: initial callback message too short\n");
                cs->result = -1;
                return;
            }

            if (n_hashes > 128) {
                PRINTF("Unexpected: too many hashes in taproot BIP32 derivation\n");
                cs->result = -1;
                return;
            }

            int out_data_length = cs->total_data_length - 1 - 32 * (int) n_hashes;

            if (out_data_length > max_out_data_length) {
                PRINTF("BIP32 derivation longer than supported in psbt derivation\n");
                cs->result = -1;
                return;
            }
            cs->out_data_length = out_data_length;
        }
    }

    // then, keep exactly the last cs->out_data_length streamed bytes; as they might be streamed
    // across multiple messages, we need to handle it appropriately

    if (data->size >= (size_t) cs->out_data_length) {
        // only keep the last suffix of length cs->out_data_length
        // discard any pre-existing data from previous calls
        buffer_seek_end(data, cs->out_data_length);
        buffer_read_bytes(data, cs->out, cs->out_data_length);
    } else {
        buffer_seek_set(data, 0);
        // We need to concatenate the new data we are reading with any previously read data.
        // Since we can only read data->size bytes, only the last d = out_data_length - data->size
        // previous bytes are kept; they move from position out_data_length - d to position 0.
        int d = cs->out_data_length - data->size;
        memmove(cs->out, &cs->out[cs->out_data_length - d], d);
        // starting at position d, we read the entire data
        buffer_read_bytes(data, &cs->out[d], data->size);
    }
}

int extract_bip32_derivation(dispatcher_context_t *dc,
                             int psbt_key_type,
                             const uint8_t values_root[static 32],
                             uint32_t merkle_tree_size,
                             int index,
                             uint32_t out[static 1 + MAX_BIP32_PATH_STEPS]) {
    fpt_der_callback_data_t callback_state;

    // we could recycle out instead of creating a new array, but we rather keep the code
    // clean, as this is not used in memory-critical parts.
    uint8_t out_bytes[4 * (1 + MAX_BIP32_PATH_STEPS)];

    callback_state.psbt_key_type = psbt_key_type;
    callback_state.out = out_bytes;
    callback_state.out_data_length = -1;
    callback_state.result = 0;

    int len = call_stream_merkle_leaf_element(dc,
                                              values_root,
                                              merkle_tree_size,
                                              index,
                                              fpt_der_data_len_callback,
                                              fpt_der_data_callback,
                                              &callback_state);

    if (len < 0 || callback_state.result < 0 || callback_state.out_data_length < 4 ||
        callback_state.out_data_length % 4 != 0) {
        PRINTF("Unexpected error while reading a BIP32 derivation\n");
        return -1;
    }

    for (int i = 0; i < callback_state.out_data_length / 4; i++) {
        if (i == 0) {
            out[i] = read_u32_be(out_bytes, 4 * i);
        } else {
            out[i] = read_u32_le(out_bytes, 4 * i);
        }
    }

    return (callback_state.out_data_length / 4) - 1;
}
