/**
 * Minimal PSBT parser for unit tests.
 * See psbt_parse.h for API documentation.
 */

#include <string.h>

#include "psbt_parse.h"

/** Read a Bitcoin compact-size integer from a buffer. Returns bytes consumed, or -1 on error. */
static int read_compact_size(const uint8_t *buf, size_t buf_len, uint64_t *out) {
    if (buf_len < 1) return -1;

    uint8_t first = buf[0];
    if (first < 253) {
        *out = first;
        return 1;
    } else if (first == 253) {
        if (buf_len < 3) return -1;
        *out = (uint64_t) buf[1] | ((uint64_t) buf[2] << 8);
        return 3;
    } else if (first == 254) {
        if (buf_len < 5) return -1;
        *out = (uint64_t) buf[1] | ((uint64_t) buf[2] << 8) | ((uint64_t) buf[3] << 16) |
               ((uint64_t) buf[4] << 24);
        return 5;
    } else {
        if (buf_len < 9) return -1;
        *out = 0;
        for (int i = 0; i < 8; i++) {
            *out |= ((uint64_t) buf[1 + i]) << (8 * i);
        }
        return 9;
    }
}

/**
 * Parse one PSBT map from the current position in the buffer.
 * Advances *offset past the map's terminal 0x00 byte.
 */
static int parse_one_map(const uint8_t *data, size_t data_len, size_t *offset, psbt_map_t *map) {
    map->n_entries = 0;

    while (*offset < data_len) {
        /* Read key length */
        uint64_t key_len;
        int n = read_compact_size(data + *offset, data_len - *offset, &key_len);
        if (n < 0) return -1;
        *offset += (size_t) n;

        /* key_len == 0 means end-of-map separator */
        if (key_len == 0) {
            return 0;
        }

        if (*offset + key_len > data_len) return -1;
        if (map->n_entries >= PSBT_MAP_MAX_ENTRIES) return -1;

        psbt_kv_t *entry = &map->entries[map->n_entries];
        entry->key = data + *offset;
        entry->key_len = (size_t) key_len;
        *offset += (size_t) key_len;

        /* Read value length */
        uint64_t value_len;
        n = read_compact_size(data + *offset, data_len - *offset, &value_len);
        if (n < 0) return -1;
        *offset += (size_t) n;

        if (*offset + value_len > data_len) return -1;

        entry->value = data + *offset;
        entry->value_len = (size_t) value_len;
        *offset += (size_t) value_len;

        map->n_entries++;
    }

    /* Reached end of buffer without 0x00 separator */
    return -1;
}

int psbt_parse(const uint8_t *data,
               size_t data_len,
               size_t n_inputs,
               size_t n_outputs,
               parsed_psbt_t *out) {
    if (data_len < 5) return -1;
    if (n_inputs > PSBT_MAX_MAPS || n_outputs > PSBT_MAX_MAPS) return -1;

    /* Verify magic */
    if (memcmp(data, "psbt\xff", 5) != 0) return -1;

    memset(out, 0, sizeof(parsed_psbt_t));
    out->n_inputs = n_inputs;
    out->n_outputs = n_outputs;

    size_t offset = 5;

    /* Parse global map */
    if (parse_one_map(data, data_len, &offset, &out->global_map) < 0) return -1;

    /* Parse input maps */
    for (size_t i = 0; i < n_inputs; i++) {
        if (parse_one_map(data, data_len, &offset, &out->input_maps[i]) < 0) return -1;
    }

    /* Parse output maps */
    for (size_t i = 0; i < n_outputs; i++) {
        if (parse_one_map(data, data_len, &offset, &out->output_maps[i]) < 0) return -1;
    }

    return 0;
}

int psbt_map_find_key_type(const psbt_map_t *map, uint8_t key_type, int start) {
    for (size_t i = (size_t) start; i < map->n_entries; i++) {
        if (map->entries[i].key_len >= 1 && map->entries[i].key[0] == key_type) {
            return (int) i;
        }
    }
    return -1;
}

/* ---- Base64 decoder ---- */

static const int8_t b64_table[256] = {
    /* clang-format off */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-2,-2,-1,-1,-2,-1,-1, /*  0..15  (\t=9,\n=10,\r=13 → whitespace) */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, /* 16..31  */
    -2,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63, /* 32..47  (space=32→ws, +=43, /=47) */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-3,-1,-1, /* 48..63  (0-9=48..57, ==61→pad) */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* 64..79  (A-O) */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, /* 80..95  (P-Z) */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, /* 96..111 (a-o) */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1, /*112..127 (p-z) */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    /* clang-format on */
};

/* -1 = invalid, -2 = whitespace (skip), -3 = padding ('=') */
#define B64_INVALID (-1)
#define B64_WS      (-2)
#define B64_PAD     (-3)

int base64_decode(const char *b64, uint8_t *out, size_t out_cap) {
    size_t out_len = 0;
    uint32_t accum = 0;
    int bits = 0;
    int pad = 0;

    for (const char *p = b64; *p != '\0'; p++) {
        int8_t v = b64_table[(unsigned char) *p];
        if (v == B64_WS) continue;
        if (v == B64_PAD) {
            pad++;
            continue;
        }
        if (v == B64_INVALID) return -1;
        if (pad > 0) return -1; /* data after padding */

        accum = (accum << 6) | (uint32_t) v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (out_len >= out_cap) return -1;
            out[out_len++] = (uint8_t) (accum >> bits) & 0xFF;
        }
    }

    return (int) out_len;
}
