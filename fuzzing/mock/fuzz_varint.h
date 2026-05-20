#pragma once

#include <stddef.h>
#include <stdint.h>

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
    out[0] = 0xFE;
    for (int i = 0; i < 4; i++)
        out[1 + i] = (uint8_t) ((v >> (8 * i)) & 0xFF);
    return 5;
}

static inline void fuzz_write_u32_le(uint8_t *out, uint32_t v) {
    out[0] = (uint8_t) (v & 0xFF);
    out[1] = (uint8_t) ((v >> 8) & 0xFF);
    out[2] = (uint8_t) ((v >> 16) & 0xFF);
    out[3] = (uint8_t) ((v >> 24) & 0xFF);
}

static inline void fuzz_write_u64_le(uint8_t *out, uint64_t v) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t) ((v >> (8 * i)) & 0xFF);
}

static inline uint16_t fuzz_read_u16_le(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static inline uint32_t fuzz_read_u32_le(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline uint64_t fuzz_read_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t) p[i] << (8 * i);
    return v;
}
