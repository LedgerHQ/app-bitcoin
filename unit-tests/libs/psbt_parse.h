#pragma once

/**
 * Minimal PSBT parser for unit tests.
 *
 * Parses a PSBTv2 binary blob into raw key-value maps (global, inputs, outputs)
 * without any field-level validation.
 *
 * The binary format (BIP-174 / BIP-370):
 *   - magic:    "psbt\xff" (5 bytes)
 *   - global:   key-value pairs ending with 0x00 separator
 *   - inputs:   one map per input, each ending with 0x00
 *   - outputs:  one map per output, each ending with 0x00
 *
 * Each key-value pair is: compact_size(key_len) || key || compact_size(val_len) || val
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/** Maximum entries per map. */
#define PSBT_MAP_MAX_ENTRIES 256

/** Maximum number of input or output maps. */
#define PSBT_MAX_MAPS 256

/** A single key-value entry in a PSBT map. Pointers reference the original buffer. */
typedef struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *value;
    size_t value_len;
} psbt_kv_t;

/** A PSBT map (global, input, or output). */
typedef struct {
    psbt_kv_t entries[PSBT_MAP_MAX_ENTRIES];
    size_t n_entries;
} psbt_map_t;

/** Parsed PSBT: one global map, plus arrays of input/output maps. */
typedef struct {
    psbt_map_t global_map;
    psbt_map_t input_maps[PSBT_MAX_MAPS];
    size_t n_inputs;
    psbt_map_t output_maps[PSBT_MAX_MAPS];
    size_t n_outputs;
} parsed_psbt_t;

/**
 * Parse a PSBTv2 binary blob.
 *
 * The caller must provide the number of inputs and outputs (read from the
 * PSBT_GLOBAL_INPUT_COUNT / OUTPUT_COUNT fields, or from the unsigned tx for v0).
 *
 * All key/value pointers in the result reference the original `data` buffer,
 * so `data` must remain valid for the lifetime of the result.
 *
 * @param data       Raw PSBT bytes (starting with "psbt\xff").
 * @param data_len   Length of the PSBT data.
 * @param n_inputs   Number of input maps to parse.
 * @param n_outputs  Number of output maps to parse.
 * @param out        Filled on success.
 * @return 0 on success, negative on error.
 */
int psbt_parse(const uint8_t *data,
               size_t data_len,
               size_t n_inputs,
               size_t n_outputs,
               parsed_psbt_t *out);

/**
 * Find the index of an entry matching a given key type byte in a PSBT map.
 *
 * @param map       The map to search.
 * @param key_type  The first byte of the key (the PSBT key type).
 * @param start     Start searching from this index (0 for first match).
 * @return Index of the matching entry, or -1 if not found.
 */
int psbt_map_find_key_type(const psbt_map_t *map, uint8_t key_type, int start);

/**
 * Decode a base64-encoded string into a binary buffer.
 *
 * Ignores whitespace (spaces, tabs, newlines) in the input string, allowing
 * multi-line literals. Handles standard base64 with '=' padding.
 *
 * @param b64       Null-terminated base64 string.
 * @param out       Output buffer (must be at least 3/4 * strlen(b64) bytes).
 * @param out_cap   Capacity of the output buffer.
 * @return Number of decoded bytes on success, or -1 on error.
 */
int base64_decode(const char *b64, uint8_t *out, size_t out_cap);
