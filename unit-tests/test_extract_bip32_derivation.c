/**
 * Unit tests for extract_bip32_derivation using the mock dispatcher.
 *
 * Tests verify that the function correctly extracts BIP32 derivation paths
 * from PSBT map values, for both non-taproot and taproot key types.
 *
 * The PSBTs used here are real test vectors from the app's test suite,
 * converted to PSBTv2 format.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include "mock_dispatcher.h"
#include "psbt_parse.h"

#include "client_commands.h"
#include "handler/sign_psbt/extract_bip32_derivation.h"
#include "common/psbt.h"

/* ===========================================================================
 *  Test PSBTs — base64-encoded (standard PSBT export format)
 * =========================================================================== */

/* wpkh-1to2 PSBTv2: 1 input, 2 outputs.
 * Input has PSBT_IN_BIP32_DERIVATION (0x06).
 * Output 1 has PSBT_OUT_BIP32_DERIVATION (0x02).
 *
 * Input derivation:  fingerprint=0xf5acc2fd, path=m/84'/1'/0'/1/8
 * Output derivation: fingerprint=0xf5acc2fd, path=m/84'/1'/0'/1/10
 */
static const char psbt_wpkh_1to2_b64[] =
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxG"
    "ESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXK"
    "GWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAA"
    "AAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq"
    "1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAABDiB6Kpl5VsCfjqf9KBnBqYe7FOIr+a3NryCo"
    "l2NyLO7iZAEPBAEAAAABEAT9////AAEDCKC7DQAAAAAAAQQZdqkUNEoPSMoVDsK5A4F2YLm2ixOm"
    "cCaIrAAiAgIp7EdycTHtJYiiDEbtqau32qb0n9ULr+cLnFqmlhxOzBj1rML9VAAAgAEAAIAAAACA"
    "AQAAAAoAAAABAwh0OCMAAAAAAAEEFgAU6zj6m4Eo+B8m6V7bDF/66oNpD+QA";

/* tr-1to2-sighash-default PSBTv2: 1 input, 2 outputs.
 * Input has PSBT_IN_TAP_BIP32_DERIVATION (0x16), 0 leaf hashes.
 *
 * Input tap derivation: fingerprint=0xf5acc2fd, path=m/86'/1'/0'/1/3
 */
static const char psbt_tr_1to2_b64[] =
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABASvfu5gAAAAAACJRIImQSmNI1/+a"
    "RNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqAQMEAAAAAAEOIOFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QO"
    "XY4UQM6F2W3GAQ8EAQAAAAEQBP3///8hFunGmwle0EtWKvyNQWkZNrpXPrb2ibwjZgC+T6OSb2QS"
    "GQD1rML9VgAAgAEAAIAAAACAAQAAAAMAAAABFyDpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+j"
    "km9kEgABAwiNNJcAAAAAAAEEIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg8BBSAC"
    "kIHs5WFqocuZMZ/Eh07+5H8IzrpfYARjbIxDQJpfCiEHApCB7OVhaqHLmTGfxIdO/uR/CM66X2AE"
    "Y2yMQ0CaXwoZAPWswv1WAACAAQAAgAAAAIABAAAAAgAAAAABAwighgEAAAAAAAEEFgAUE5m4oJhH"
    "oDmwNS9Y0hLBgLqxf3cA";

/** Maximum decoded PSBT size (base64 inflates ~33%, so 1024 covers our test PSBTs). */
#define MAX_PSBT_BIN 1024

/* ===========================================================================
 *  Helpers
 * =========================================================================== */

/**
 * Find the sorted-position index (value tree index) of the entry with the given
 * key type in a parsed PSBT map. When mock_dispatcher_add_map sorts entries by key,
 * the index in the values tree is the sorted rank of the key.
 *
 * Returns the sorted index, or -1 if not found.
 */
static int find_sorted_value_index(const psbt_map_t *map, uint8_t key_type) {
    /* Find the entry with this key type */
    int entry_idx = psbt_map_find_key_type(map, key_type, 0);
    if (entry_idx < 0) return -1;

    const uint8_t *target_key = map->entries[entry_idx].key;
    size_t target_key_len = map->entries[entry_idx].key_len;

    /* Count how many keys sort before this one (= its sorted index) */
    int rank = 0;
    for (size_t i = 0; i < map->n_entries; i++) {
        const uint8_t *k = map->entries[i].key;
        size_t klen = map->entries[i].key_len;
        size_t min_len = klen < target_key_len ? klen : target_key_len;
        int cmp = memcmp(k, target_key, min_len);
        if (cmp < 0 || (cmp == 0 && klen < target_key_len)) {
            rank++;
        }
    }
    return rank;
}

/* ===========================================================================
 *  Test cases
 * =========================================================================== */

/**
 * wpkh-1to2: extract PSBT_IN_BIP32_DERIVATION from the input.
 * Expected: fingerprint=0xf5acc2fd, path=m/84'/1'/0'/1/8
 */
static void test_wpkh_input_bip32_derivation(void **state) {
    mock_dispatcher_t *mock = *state;

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_wpkh_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    /* Find the PSBT_IN_BIP32_DERIVATION entry's sorted index */
    int idx = find_sorted_value_index(&parsed.input_maps[0], PSBT_IN_BIP32_DERIVATION);
    assert_true(idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    memset(out, 0, sizeof(out));

    int n_steps = extract_bip32_derivation(dc,
                                           PSBT_IN_BIP32_DERIVATION,
                                           psbt_info.input_maps[0].values_root,
                                           (uint32_t) psbt_info.input_maps[0].size,
                                           idx,
                                           out);

    assert_int_equal(n_steps, 5);
    assert_int_equal(out[0], 0xf5acc2fd);      /* fingerprint */
    assert_int_equal(out[1], 84 | 0x80000000); /* 84' */
    assert_int_equal(out[2], 1 | 0x80000000);  /* 1' */
    assert_int_equal(out[3], 0x80000000);      /* 0' */
    assert_int_equal(out[4], 1);               /* 1 */
    assert_int_equal(out[5], 8);               /* 8 */
}

/**
 * wpkh-1to2: extract PSBT_OUT_BIP32_DERIVATION from output 1 (the change output).
 * Expected: fingerprint=0xf5acc2fd, path=m/84'/1'/0'/1/10
 */
static void test_wpkh_output_bip32_derivation(void **state) {
    mock_dispatcher_t *mock = *state;

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_wpkh_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    /* Find which output has a BIP32 derivation entry */
    int out_idx = -1;
    int sorted_idx = -1;
    for (size_t i = 0; i < 2; i++) {
        sorted_idx = find_sorted_value_index(&parsed.output_maps[i], PSBT_OUT_BIP32_DERIVATION);
        if (sorted_idx >= 0) {
            out_idx = (int) i;
            break;
        }
    }
    assert_true(out_idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    memset(out, 0, sizeof(out));

    int n_steps = extract_bip32_derivation(dc,
                                           PSBT_OUT_BIP32_DERIVATION,
                                           psbt_info.output_maps[out_idx].values_root,
                                           (uint32_t) psbt_info.output_maps[out_idx].size,
                                           sorted_idx,
                                           out);

    assert_int_equal(n_steps, 5);
    assert_int_equal(out[0], 0xf5acc2fd);
    assert_int_equal(out[1], 84 | 0x80000000);
    assert_int_equal(out[2], 1 | 0x80000000);
    assert_int_equal(out[3], 0x80000000);
    assert_int_equal(out[4], 1);
    assert_int_equal(out[5], 10);
}

/**
 * tr-1to2: extract PSBT_IN_TAP_BIP32_DERIVATION from the input.
 * Expected: 0 leaf hashes, fingerprint=0xf5acc2fd, path=m/86'/1'/0'/1/3
 */
static void test_taproot_input_tap_bip32_derivation(void **state) {
    mock_dispatcher_t *mock = *state;

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_tr_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    int idx = find_sorted_value_index(&parsed.input_maps[0], PSBT_IN_TAP_BIP32_DERIVATION);
    assert_true(idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    memset(out, 0, sizeof(out));

    int n_steps = extract_bip32_derivation(dc,
                                           PSBT_IN_TAP_BIP32_DERIVATION,
                                           psbt_info.input_maps[0].values_root,
                                           (uint32_t) psbt_info.input_maps[0].size,
                                           idx,
                                           out);

    assert_int_equal(n_steps, 5);
    assert_int_equal(out[0], 0xf5acc2fd);
    assert_int_equal(out[1], 86 | 0x80000000);
    assert_int_equal(out[2], 1 | 0x80000000);
    assert_int_equal(out[3], 0x80000000);
    assert_int_equal(out[4], 1);
    assert_int_equal(out[5], 3);
}

/**
 * tr-1to2: extract PSBT_OUT_TAP_BIP32_DERIVATION from the output that has it.
 * Expected: 0 leaf hashes, fingerprint=0xf5acc2fd, path=m/86'/1'/0'/1/2
 */
static void test_taproot_output_tap_bip32_derivation(void **state) {
    mock_dispatcher_t *mock = *state;

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_tr_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    /* Find which output has a TAP_BIP32_DERIVATION entry */
    int out_idx = -1;
    int sorted_idx = -1;
    for (size_t i = 0; i < 2; i++) {
        sorted_idx = find_sorted_value_index(&parsed.output_maps[i], PSBT_OUT_TAP_BIP32_DERIVATION);
        if (sorted_idx >= 0) {
            out_idx = (int) i;
            break;
        }
    }
    assert_true(out_idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    memset(out, 0, sizeof(out));

    int n_steps = extract_bip32_derivation(dc,
                                           PSBT_OUT_TAP_BIP32_DERIVATION,
                                           psbt_info.output_maps[out_idx].values_root,
                                           (uint32_t) psbt_info.output_maps[out_idx].size,
                                           sorted_idx,
                                           out);

    assert_int_equal(n_steps, 5);
    assert_int_equal(out[0], 0xf5acc2fd);
    assert_int_equal(out[1], 86 | 0x80000000);
    assert_int_equal(out[2], 1 | 0x80000000);
    assert_int_equal(out[3], 0x80000000);
    assert_int_equal(out[4], 1);
    assert_int_equal(out[5], 2);
}

/* ===========================================================================
 *  Edge-case tests: directly register a single value with a 1-element tree.
 *  For a 1-element tree, the Merkle root equals the leaf hash, so
 *  call_stream_merkle_leaf_element returns the registered value directly.
 * =========================================================================== */

static void register_single_value(mock_dispatcher_t *mock,
                                  const uint8_t *value,
                                  size_t len,
                                  uint8_t root_out[32]) {
    const uint8_t *elems[] = {value};
    size_t lens[] = {len};
    mock_dispatcher_add_list(mock, elems, lens, 1);
    memcpy(root_out, mock->trees[mock->n_trees - 1].root, 32);
}

/**
 * Non-taproot value longer than max_out_data_length (= 4 * (1 + MAX_BIP32_PATH_STEPS)).
 * Exercises the early-reject branch in the data callback.
 */
static void test_extract_nontap_too_long(void **state) {
    mock_dispatcher_t *mock = *state;

    /* max_out_data_length = 4*(1+10) = 44 → 45 bytes is too long */
    uint8_t value[45];
    for (size_t i = 0; i < sizeof(value); i++) value[i] = (uint8_t) i;

    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/**
 * Taproot value of 1 byte where n_hashes >= 1 — total_data_length is too short
 * for the announced number of hashes.
 */
static void test_extract_tap_too_short(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t value[1] = {0x01}; /* n_hashes = 1, but no room for the hash */

    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_TAP_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/**
 * Taproot value where, after removing the leaf hashes, the remaining bytes
 * exceed max_out_data_length.
 */
static void test_extract_tap_out_too_long(void **state) {
    mock_dispatcher_t *mock = *state;

    /* n_hashes=0, 50 bytes of fingerprint+path → out_data_length = 49 > 44 */
    uint8_t value[50];
    memset(value, 0, sizeof(value));

    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_TAP_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/**
 * Taproot value with n_hashes=7 and a 28-byte derivation, total 253 bytes.
 * The 254-byte preimage spans two chunks (251 + 3); the second chunk is
 * smaller than out_data_length (=28), exercising the "carry-over" path in
 * the data callback (memmove + read into tail).
 */
static void test_extract_tap_multi_chunk(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t value[1 + 32 * 7 + 28];
    memset(value, 0, sizeof(value));
    value[0] = 7; /* n_hashes */
    /* fingerprint (BE) at offset 225 */
    value[1 + 32 * 7 + 0] = 0xAA;
    value[1 + 32 * 7 + 1] = 0xBB;
    value[1 + 32 * 7 + 2] = 0xCC;
    value[1 + 32 * 7 + 3] = 0xDD;
    /* 6 path steps (4 bytes each, LE) at offsets 229.. */
    for (int s = 0; s < 6; s++) {
        for (int b = 0; b < 4; b++) {
            value[1 + 32 * 7 + 4 + 4 * s + b] = (uint8_t) (s * 4 + b + 1);
        }
    }

    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_TAP_BIP32_DERIVATION, root, 1, 0, out);

    /* 28 bytes / 4 = 7 → n_steps = 6 (returned value = 7 - 1) */
    assert_int_equal(result, 6);
    assert_int_equal(out[0], 0xAABBCCDDu); /* fingerprint, BE */
}

/**
 * Empty value (0 bytes) — the data callback is invoked with data->size == 0,
 * exercising the empty-chunk early-return branch.  out_data_length is never
 * set, so extract_bip32_derivation reports an error.
 */
static void test_extract_empty_value(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t value[1] = {0x00}; /* unused — register_single_value needs a non-NULL ptr */

    uint8_t root[32];
    register_single_value(mock, value, 0, root);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/* ===========================================================================
 *  Adversarial tests: tampering with the preimage length to trigger checks
 *  that cannot be reached via well-formed values.
 * =========================================================================== */

/**
 * Adversarial: tamper the GET_PREIMAGE response to claim a preimage length
 * just past INT_MAX.  The len callback in extract_bip32_derivation then sees
 * data_length > INT_MAX and rejects.
 */
static int tamper_huge_preimage_len(uint8_t *response_buf,
                                    size_t *response_len,
                                    uint8_t cmd,
                                    int call_count,
                                    void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len >= 2) {
        /* Rewrite the varint header to claim preimage_len = 0x80000001
         * (> INT_MAX, still < UINT32_MAX).  Then a 0-byte partial_data_len. */
        /* Original layout: <varint preimage_len> <partial_data_len:1> <data...>
         * Replace with: <0xFE><u32 LE = 0x80000001><partial_data_len=0>
         * Note: this is interpreted by call_stream_preimage as preimage_len=0x80000001,
         * partial_data_len=0 → caught by "preimage_len<1 OR partial_data_len==0" check
         * (= -3). But we want to bypass that: set partial_data_len=1 instead. */
        response_buf[0] = 0xFE; /* 5-byte varint */
        response_buf[1] = 0x01;
        response_buf[2] = 0x00;
        response_buf[3] = 0x00;
        response_buf[4] = 0x80; /* preimage_len = 0x80000001 */
        response_buf[5] = 0x01; /* partial_data_len = 1 */
        response_buf[6] = 0x00; /* one data byte (would-be 0x00 prefix) */
        *response_len = 7;
    }
    return 0;
}

static void test_extract_huge_preimage_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t value[5] = {0, 0, 0, 0, 0};
    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    mock_dispatcher_set_tamper_hook(mock, tamper_huge_preimage_len, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/**
 * Adversarial: tamper to declare preimage_len much larger than what's actually
 * sent, while keeping a valid first byte = 130 (claimed n_hashes).  Total
 * declared length satisfies the early "too short" check but n_hashes > 128
 * triggers the rejection.
 */
static int tamper_long_len_n_hashes(uint8_t *response_buf,
                                    size_t *response_len,
                                    uint8_t cmd,
                                    int call_count,
                                    void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len >= 2) {
        /* Claim preimage_len = 5000 (= 0x1388), partial_data_len = 2,
         * partial data = [0x00, 130]. */
        response_buf[0] = 0xFD; /* 3-byte varint */
        response_buf[1] = 0x88;
        response_buf[2] = 0x13; /* 5000 LE */
        response_buf[3] = 2;    /* partial_data_len */
        response_buf[4] = 0x00; /* prefix */
        response_buf[5] = 130;  /* n_hashes */
        *response_len = 6;
    }
    return 0;
}

static void test_extract_tap_too_many_hashes(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t value[2] = {130, 0};
    uint8_t root[32];
    register_single_value(mock, value, sizeof(value), root);

    mock_dispatcher_set_tamper_hook(mock, tamper_long_len_n_hashes, NULL);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    uint32_t out[1 + MAX_BIP32_PATH_STEPS];
    int result = extract_bip32_derivation(dc, PSBT_IN_TAP_BIP32_DERIVATION, root, 1, 0, out);

    assert_int_equal(result, -1);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_wpkh_input_bip32_derivation),
        T(test_wpkh_output_bip32_derivation),
        T(test_taproot_input_tap_bip32_derivation),
        T(test_taproot_output_tap_bip32_derivation),
        T(test_extract_nontap_too_long),
        T(test_extract_tap_too_short),
        T(test_extract_tap_out_too_long),
        T(test_extract_tap_multi_chunk),
        T(test_extract_empty_value),
        T(test_extract_huge_preimage_len),
        T(test_extract_tap_too_many_hashes),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
