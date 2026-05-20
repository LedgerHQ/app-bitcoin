/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "merkle.h"

/* SDK headers */
#include "buffer.h"
#include "ledger_assert.h"

/* Local headers */
#include "crypto.h"
#include "debug.h"

void merkle_compute_element_hash(const uint8_t *in,
                                 size_t in_len,
                                 uint8_t out[static CX_SHA256_SIZE]) {
    // H(0x00 | in)
    uint8_t data = 0x00;
    cx_iovec_t iovec[2] = {{.iov_base = &data, .iov_len = 1}, {.iov_base = in, .iov_len = in_len}};
    cx_sha256_hash_iovec(iovec, 2, out);
}

void merkle_combine_hashes(const uint8_t left[static CX_SHA256_SIZE],
                           const uint8_t right[static CX_SHA256_SIZE],
                           uint8_t out[static CX_SHA256_SIZE]) {
    PRINT_STACK_POINTER();

    uint8_t prefix = 0x01;
    cx_iovec_t iovec[3] = {{.iov_base = &prefix, .iov_len = 1},
                           {.iov_base = left, .iov_len = CX_SHA256_SIZE},
                           {.iov_base = right, .iov_len = CX_SHA256_SIZE}};
    cx_sha256_hash_iovec(iovec, 3, out);
}

// TODO: make this O(log n), or possibly O(1). Currently O(log^2 n).
int merkle_get_ith_direction(size_t size, size_t index, size_t i) {
    if (size <= 1 || index >= size) {
        return -1;
    }
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Bound fuzz-only inputs so pathological sizes don't drive the loop below
    // into catastrophic iteration counts.
    if (size > ((size_t) 1U << MAX_MERKLE_TREE_DEPTH)) {
        return -1;
    }
#endif
    uint8_t n_directions = 0;
    while (size > 1) {
        uint8_t depth = ceil_lg(size);

        // bitmask of the direction from the current node, where 0 = left, 1 = right;
        // also the number of leaves of the left subtree. Unsigned: depth can reach 32.
        uint32_t mask = 1U << (depth - 1);

        uint8_t is_right_child = (index & mask) != 0 ? 1 : 0;

        if (n_directions == i) {
            return is_right_child;
        }

        ++n_directions;

        if (is_right_child) {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }
    }

    return -1;
}