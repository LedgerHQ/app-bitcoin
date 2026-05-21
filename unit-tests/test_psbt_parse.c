/**
 * Unit tests for the psbt_parse test utility (base64 decoder + PSBT parser).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "psbt_parse.h"

/* A valid PSBTv2 (wpkh-1to2), base64-encoded. */
static const char psbt_wpkh_1to2_b64[] =
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxG"
    "ESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXK"
    "GWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAA"
    "AAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq"
    "1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAABDiB6Kpl5VsCfjqf9KBnBqYe7FOIr+a3NryCo"
    "l2NyLO7iZAEPBAEAAAABEAT9////AAEDCKC7DQAAAAAAAQQZdqkUNEoPSMoVDsK5A4F2YLm2ixOm"
    "cCaIrAAiAgIp7EdycTHtJYiiDEbtqau32qb0n9ULr+cLnFqmlhxOzBj1rML9VAAAgAEAAIAAAACA"
    "AQAAAAoAAAABAwh0OCMAAAAAAAEEFgAU6zj6m4Eo+B8m6V7bDF/66oNpD+QA";

#define MAX_PSBT_BIN 1024

static void test_psbt_parse_global_map(void **state) {
    (void) state;

    static uint8_t psbt_bin[MAX_PSBT_BIN];
    int psbt_len = base64_decode(psbt_wpkh_1to2_b64, psbt_bin, sizeof(psbt_bin));
    assert_true(psbt_len > 0);

    static parsed_psbt_t parsed;
    assert_int_equal(psbt_parse(psbt_bin, (size_t) psbt_len, 1, 2, &parsed), 0);

    /* Global map should have entries including INPUT_COUNT(0x04) and OUTPUT_COUNT(0x05) */
    assert_true(parsed.global_map.n_entries >= 4);
    assert_true(psbt_map_find_key_type(&parsed.global_map, 0x04, 0) >= 0);
    assert_true(psbt_map_find_key_type(&parsed.global_map, 0x05, 0) >= 0);
}

static void test_psbt_parse_bad_magic(void **state) {
    (void) state;

    uint8_t bad_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x00};
    static parsed_psbt_t parsed;
    assert_true(psbt_parse(bad_data, sizeof(bad_data), 0, 0, &parsed) < 0);
}

static void test_base64_decode_basic(void **state) {
    (void) state;

    uint8_t out[64];
    /* "cHNidA==" decodes to "psbt" */
    int len = base64_decode("cHNidA==", out, sizeof(out));
    assert_int_equal(len, 4);
    assert_memory_equal(out, "psbt", 4);
}

static void test_base64_decode_invalid(void **state) {
    (void) state;

    uint8_t out[64];
    /* '@' is not valid base64 */
    assert_true(base64_decode("@@@@", out, sizeof(out)) < 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_psbt_parse_global_map),
        cmocka_unit_test(test_psbt_parse_bad_magic),
        cmocka_unit_test(test_base64_decode_basic),
        cmocka_unit_test(test_base64_decode_invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
