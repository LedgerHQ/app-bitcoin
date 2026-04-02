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

/* SDK mock stubs */
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}
#undef PIC
#define PIC(x) (x)

#include "mock_dispatcher.h"
#include "cx_hash_mock.h"
#include "psbt_parse.h"

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
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_wpkh_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(&mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    /* Find the PSBT_IN_BIP32_DERIVATION entry's sorted index */
    int idx = find_sorted_value_index(&parsed.input_maps[0], PSBT_IN_BIP32_DERIVATION);
    assert_true(idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
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
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_wpkh_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(&mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
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

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
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
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_tr_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(&mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
                     0);

    int idx = find_sorted_value_index(&parsed.input_maps[0], PSBT_IN_TAP_BIP32_DERIVATION);
    assert_true(idx >= 0);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
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
    (void) state;

    static mock_dispatcher_t mock;
    mock_dispatcher_init(&mock);
    mock_dispatcher_reset_hash_pool();

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_tr_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    mock_psbt_t psbt_info;
    assert_int_equal(mock_dispatcher_add_psbt(&mock, psbt_bin, (size_t) psbt_len, 1, 2, &psbt_info),
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

    dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);
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

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wpkh_input_bip32_derivation),
        cmocka_unit_test(test_wpkh_output_bip32_derivation),
        cmocka_unit_test(test_taproot_input_tap_bip32_derivation),
        cmocka_unit_test(test_taproot_output_tap_bip32_derivation),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
