#pragma once
/*
 * Bitcoin CompactSize varint. Protocol-specific, so it stays here; the generic
 * endian helpers come from the SDK's os_utils.h.
 */

#include <stddef.h>
#include <stdint.h>

#include "os_utils.h"  // U4LE_ENCODE, U8LE_ENCODE

static inline size_t fuzz_write_varint(uint8_t *out, uint64_t v) {
    if (v < 0xFD) {
        out[0] = (uint8_t) v;
        return 1;
    }
    if (v <= 0xFFFF) {
        out[0] = 0xFD;
        out[1] = (uint8_t) (v & 0xFF);
        out[2] = (uint8_t) ((v >> 8) & 0xFF);
        return 3;
    }
    if (v <= 0xFFFFFFFF) {
        out[0] = 0xFE;
        U4LE_ENCODE(out + 1, 0, (uint32_t) v);
        return 5;
    }
    out[0] = 0xFF;
    U8LE_ENCODE(out + 1, 0, v);
    return 9;
}
