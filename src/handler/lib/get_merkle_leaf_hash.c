#include <string.h>

#include "get_merkle_leaf_hash.h"

/* SDK headers */
#include "buffer.h"
#include "varint.h"
#include "write.h"

/* Local headers */
#include "client_commands.h"
#include "debug.h"
#include "merkle.h"
#include "sw.h"

// Sends the GET_MERKLE_LEAF_PROOF request and verifies the reply. Body of
// call_get_merkle_leaf_hash; the wrapper below clears `out` on failure.
static int get_merkle_leaf_hash(dispatcher_context_t *dc,
                                const uint8_t merkle_root[static 32],
                                uint32_t tree_size,
                                uint32_t leaf_index,
                                uint8_t out[static 32]) {
    // LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    PRINT_STACK_POINTER();

    // make sure that tree size and leaf index are consistent
    if (tree_size == 0 || leaf_index >= tree_size) {
        PRINTF("Leaf index out of range.\n");
        return -1;
    }

    {  // make sure memory is deallocated as soon as possible
        uint8_t tmp[9];
        tmp[0] = CCMD_GET_MERKLE_LEAF_PROOF;
        dc->add_to_response(tmp, 1);

        dc->add_to_response(merkle_root, 32);

        int tree_size_len = varint_write(tmp, 0, tree_size);
        dc->add_to_response(tmp, tree_size_len);

        int leaf_index_len = varint_write(tmp, 0, leaf_index);
        dc->add_to_response(tmp, leaf_index_len);

        dc->finalize_response(SW_INTERRUPTED_EXECUTION);
    }

    if (dc->process_interruption(dc) < 0) {
        return -1;
    }

    {
        int cur_step;          // counter for the proof steps
        uint8_t cur_hash[32];  // temporary buffer for intermediate hashes
        uint8_t proof_size;
        uint8_t n_proof_elements;
        if (!buffer_read_bytes(&dc->read_buffer, cur_hash, 32) ||
            !buffer_read_u8(&dc->read_buffer, &proof_size) ||
            !buffer_read_u8(&dc->read_buffer, &n_proof_elements)) {
            return -1;
        }

        // The proof length must be exactly the depth of the leaf in the tree
        // Since the tree_size and leaf_index are validated, the first call to
        // merkle_get_ith_direction returns -1 precisely if proof_size is not smaller than the
        // correct proof size.
        if (merkle_get_ith_direction(tree_size, leaf_index, proof_size) != -1 ||
            (proof_size > 0 &&
             merkle_get_ith_direction(tree_size, leaf_index, (size_t) proof_size - 1) < 0)) {
            PRINTF("Merkle proof length does not match the depth of the leaf.\n");

            // Wrong length of the Merkle proof.
            return -1;
        }

        if (n_proof_elements > proof_size) {
            PRINTF("Received more proof data than expected.\n");

            // Wrong length of the Merkle proof.
            return -1;
        }

        if (!buffer_can_read(&dc->read_buffer, 32 * (size_t) n_proof_elements)) {
            return -1;
        }

        // Copy leaf hash to output (although it is not verified yet)
        memcpy(out, cur_hash, 32);

        // Initialize proof verification
        cur_step = 0;

        while (true) {
            int end_step = cur_step + n_proof_elements;
            for (; cur_step < end_step; cur_step++) {
                // we use the memory in the buffer directly, to avoid copying the hash unnecessarily
                const uint8_t *sibling_hash = dc->read_buffer.ptr + dc->read_buffer.offset;

                int i = proof_size - cur_step - 1;
                int direction = merkle_get_ith_direction(tree_size, leaf_index, i);

                if (direction == 0) {
                    merkle_combine_hashes(cur_hash, sibling_hash, cur_hash);
                } else if (direction == 1) {
                    merkle_combine_hashes(sibling_hash, cur_hash, cur_hash);
                } else {
                    return -1;  // unexpected, proof too long?
                }

                buffer_seek_cur(&dc->read_buffer, 32);  // consume the bytes of the sibling hash
            }

            if (cur_step == proof_size) {
                break;
            }

            uint8_t req_more[] = {CCMD_GET_MORE_ELEMENTS};
            SET_RESPONSE(dc, req_more, sizeof(req_more), SW_INTERRUPTED_EXECUTION);
            if (dc->process_interruption(dc) < 0) {
                return -1;
            }

            // Parse response to CCMD_GET_MORE_ELEMENTS
            uint8_t elements_len;
            if (!buffer_read_u8(&dc->read_buffer, &n_proof_elements) ||
                !buffer_read_u8(&dc->read_buffer, &elements_len) ||
                !buffer_can_read(&dc->read_buffer, (size_t) n_proof_elements * elements_len)) {
                return -1;
            }

            if (elements_len != 32) {
                return -1;
            }

            if (cur_step + n_proof_elements > proof_size) {
                // Receiving more data then expected
                return -1;
            }
        }

        if (memcmp(merkle_root, cur_hash, 32) != 0) {
            PRINTF("Merkle root mismatch");
            return -1;
        }
    }

    return 0;
}

int call_get_merkle_leaf_hash(dispatcher_context_t *dc,
                              const uint8_t merkle_root[static 32],
                              uint32_t tree_size,
                              uint32_t leaf_index,
                              uint8_t out[static 32]) {
    int res = get_merkle_leaf_hash(dc, merkle_root, tree_size, leaf_index, out);
    if (res < 0) {
        // The leaf hash is copied out before the proof is verified; see call_get_preimage.
        explicit_bzero(out, 32);
    }
    return res;
}
