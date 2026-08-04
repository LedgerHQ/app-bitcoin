#include <string.h>

#include "get_merkle_preimage.h"

#include "../../boilerplate/sw.h"
#include "../../common/buffer.h"
#include "../../crypto.h"
#include "../client_commands.h"

#include "debug-helpers/debug.h"

#include "cxram_stash.h"

// TODO: refactor common code with stream_preimage.c

int call_get_merkle_preimage(dispatcher_context_t *dispatcher_context,
                             const uint8_t hash[static 32],
                             uint8_t *out_ptr,
                             size_t out_ptr_len) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    PRINT_STACK_POINTER();

    uint8_t cmd = CCMD_GET_PREIMAGE;
    dispatcher_context->add_to_response(&cmd, 1);

    uint8_t zero = 0;
    dispatcher_context->add_to_response(&zero, 1);

    dispatcher_context->add_to_response(hash, 32);
    dispatcher_context->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
        return -1;
    }

    uint64_t preimage_len;

    uint8_t partial_data_len;

    if (!buffer_read_varint(&dispatcher_context->read_buffer, &preimage_len) ||
        !buffer_read_u8(&dispatcher_context->read_buffer, &partial_data_len) ||
        !buffer_can_read(&dispatcher_context->read_buffer, partial_data_len)) {
        return -2;
    }

    if (preimage_len == 0 || partial_data_len == 0) {
        return -3;
    }

    if (preimage_len - 1 > out_ptr_len) {
        PRINTF("Output buffer too short\n");
        return -4;
    }

    if (partial_data_len > preimage_len) {
        return -5;
    }

    uint8_t *data_ptr =
        dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

    // Merkle tree leaves are hashes of 0x00 || element
    if (data_ptr[0] != 0x00) {
        PRINTF("Not a Merkle tree leaf preimage\n");
        return -12;
    }

#ifdef USE_CXRAM_SECTION
    // allocate buffers inside the cxram section to save memory
    // this is safe as there are no syscalls here that use the cxram
    cx_sha256_t *hash_context = (cx_sha256_t *) get_cxram_buffer();
#else
    cx_sha256_t hash_context_obj;
    cx_sha256_t *hash_context = &hash_context_obj;
#endif

    cx_sha256_init(hash_context);

    // update hash
    crypto_hash_update(&hash_context->header, data_ptr, partial_data_len);

    buffer_t out_buffer = buffer_create(out_ptr, out_ptr_len);

    // write bytes to output
    if (!buffer_write_bytes(&out_buffer,
                            data_ptr + 1,  // we skip the first byte
                            partial_data_len - 1)) {
        return -11;
    }

    size_t bytes_remaining = (size_t) preimage_len - partial_data_len;

    while (bytes_remaining > 0) {
        uint8_t get_more_elements_req[] = {CCMD_GET_MORE_ELEMENTS};
        SET_RESPONSE(dispatcher_context, get_more_elements_req, 1, SW_INTERRUPTED_EXECUTION);
        if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
            return -6;
        }

        // Parse response to CCMD_GET_MORE_ELEMENTS
        uint8_t n_bytes, elements_len;
        if (!buffer_read_u8(&dispatcher_context->read_buffer, &n_bytes) ||
            !buffer_read_u8(&dispatcher_context->read_buffer, &elements_len) ||
            !buffer_can_read(&dispatcher_context->read_buffer, (size_t) n_bytes * elements_len)) {
            return -7;
        }

        if (elements_len != 1) {
            PRINTF("Elements should be single bytes\n");
            return -8;
        }

        if (n_bytes > bytes_remaining) {
            PRINTF("Received more bytes than expected.\n");
            return -9;
        }

        data_ptr = dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

        // update hash
        crypto_hash_update(
            &hash_context->header,
            data_ptr,
            n_bytes);

        // write bytes to output
        if (!buffer_write_bytes(&out_buffer, data_ptr, n_bytes)) {
            return -11;
        }

        bytes_remaining -= n_bytes;
    }

    // hack: we pass the address of the final accumulator inside cx_sha256_t, so we don't need
    // an additional variable in the stack to store the final hash.
    crypto_hash_digest(&hash_context->header, (uint8_t *) &hash_context->acc, 32);

    if (memcmp(hash_context->acc, hash, 32) != 0) {
        PRINTF("Hash mismatch.\n");
        return -10;
    }

    return (int) (preimage_len - 1);
}
