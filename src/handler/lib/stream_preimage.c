#include <string.h>
#include <limits.h>

#include "stream_preimage.h"

/* Local headers */
#include "client_commands.h"
#include "crypto.h"
#include "sw.h"

int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 32],
                         void (*len_callback)(size_t, void *),
                         void (*callback)(buffer_t *, void *),
                         void *callback_state) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t cmd = CCMD_GET_PREIMAGE;
    dispatcher_context->add_to_response(&cmd, 1);
    uint8_t zero = 0;
    dispatcher_context->add_to_response(&zero, 1);
    dispatcher_context->add_to_response(hash, 32);
    dispatcher_context->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
        return -1;
    }

    uint64_t preimage_len_u64;  // preimage len (including the 0x00 prefix of Merkle tree leaves)

    uint8_t partial_data_len;

    if (!buffer_read_varint(&dispatcher_context->read_buffer, &preimage_len_u64) ||
        !buffer_read_u8(&dispatcher_context->read_buffer, &partial_data_len) ||
        !buffer_can_read(&dispatcher_context->read_buffer, partial_data_len)) {
        return -2;
    }

    if (preimage_len_u64 > UINT32_MAX) {
        return -10;
    }

    uint32_t preimage_len = (uint32_t) preimage_len_u64;

    if (preimage_len < 1 || partial_data_len == 0) {
        // at least the initial 0x00 prefix should be there
        return -3;
    }

    if (partial_data_len > preimage_len) {
        return -4;
    }

    if (len_callback != NULL) {
        len_callback(preimage_len - 1, callback_state);
    }

    uint8_t *data_ptr =
        dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);
    // update hash
    crypto_hash_update(&hash_context.header, data_ptr, partial_data_len);

    // call callback with data
    buffer_t initial_buf = buffer_create(data_ptr + 1, partial_data_len - 1);  // skip 0x00 prefix
    callback(&initial_buf, callback_state);

    size_t bytes_remaining = (size_t) preimage_len - partial_data_len;

    while (bytes_remaining > 0) {
        uint8_t get_more_elements_req[] = {CCMD_GET_MORE_ELEMENTS};
        SET_RESPONSE(dispatcher_context,
                     get_more_elements_req,
                     sizeof(get_more_elements_req),
                     SW_INTERRUPTED_EXECUTION);
        if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
            return -5;
        }

        // Parse response to CCMD_GET_MORE_ELEMENTS
        uint8_t n_bytes, elements_len;
        if (!buffer_read_u8(&dispatcher_context->read_buffer, &n_bytes) ||
            !buffer_read_u8(&dispatcher_context->read_buffer, &elements_len) ||
            !buffer_can_read(&dispatcher_context->read_buffer, (size_t) n_bytes * elements_len)) {
            return -6;
        }

        if (elements_len != 1) {
            PRINTF("Elements should be single bytes\n");
            return -7;
        }

        if (n_bytes > bytes_remaining) {
            PRINTF("Received more bytes than expected.\n");
            return -8;
        }

        data_ptr = dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

        // update hash
        crypto_hash_update(&hash_context.header, data_ptr, n_bytes);

        // call callback with data
        buffer_t buf = buffer_create(data_ptr, n_bytes);
        callback(&buf, callback_state);

        bytes_remaining -= n_bytes;
    }

    uint8_t computed_hash[32];

    crypto_hash_digest(&hash_context.header, computed_hash, 32);

    if (memcmp(computed_hash, hash, 32) != 0) {
        PRINTF("Hash mismatch.\n");
        return -9;
    }

    return (int) preimage_len - 1;
}
