#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/sighash.h"

// SIGHASH constants (mirrored from constants.h for test independence)
#define SIGHASH_DEFAULT      0x00000000
#define SIGHASH_ALL          0x00000001
#define SIGHASH_NONE         0x00000002
#define SIGHASH_SINGLE       0x00000003
#define SIGHASH_ANYONECANPAY 0x00000080

// ========================================================================
// Tests for classify_sighash
// ========================================================================

// --- SAFE sighash types ---

static void test_sighash_all_is_safe_segwit_v0(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ALL, 0), SIGHASH_CLASS_SAFE);
}

static void test_sighash_all_is_safe_segwit_v1(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ALL, 1), SIGHASH_CLASS_SAFE);
}

static void test_sighash_all_is_safe_legacy(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ALL, -1), SIGHASH_CLASS_SAFE);
}

static void test_sighash_default_is_safe_taproot(void **state) {
    (void) state;
    // SIGHASH_DEFAULT (0x00) is safe only for segwit version > 0 (Taproot)
    assert_int_equal(classify_sighash(SIGHASH_DEFAULT, 1), SIGHASH_CLASS_SAFE);
}

static void test_sighash_default_is_not_safe_segwit_v0(void **state) {
    (void) state;
    // SIGHASH_DEFAULT for segwit v0 is unsupported, not safe
    assert_int_equal(classify_sighash(SIGHASH_DEFAULT, 0), SIGHASH_CLASS_UNSUPPORTED);
}

static void test_sighash_default_is_not_safe_legacy(void **state) {
    (void) state;
    // SIGHASH_DEFAULT for legacy is unsupported
    assert_int_equal(classify_sighash(SIGHASH_DEFAULT, -1), SIGHASH_CLASS_UNSUPPORTED);
}

// --- NON_SAFE sighash types (segwit v0 and v1) ---

static void test_sighash_none_is_non_safe_v0(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_NONE, 0), SIGHASH_CLASS_NON_SAFE);
}

static void test_sighash_none_is_non_safe_v1(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_NONE, 1), SIGHASH_CLASS_NON_SAFE);
}

static void test_sighash_single_is_non_safe(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_SINGLE, 0), SIGHASH_CLASS_NON_SAFE);
    assert_int_equal(classify_sighash(SIGHASH_SINGLE, 1), SIGHASH_CLASS_NON_SAFE);
}

static void test_sighash_anyonecanpay_all_is_non_safe(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_ALL, 0),
                     SIGHASH_CLASS_NON_SAFE);
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_ALL, 1),
                     SIGHASH_CLASS_NON_SAFE);
}

static void test_sighash_anyonecanpay_none_is_non_safe(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_NONE, 0),
                     SIGHASH_CLASS_NON_SAFE);
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_NONE, 1),
                     SIGHASH_CLASS_NON_SAFE);
}

static void test_sighash_anyonecanpay_single_is_non_safe(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, 0),
                     SIGHASH_CLASS_NON_SAFE);
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, 1),
                     SIGHASH_CLASS_NON_SAFE);
}

// --- NON_SAFE sighash types are unsupported for legacy (segwit_version < 0) ---

static void test_sighash_none_is_unsupported_legacy(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_NONE, -1), SIGHASH_CLASS_UNSUPPORTED);
}

static void test_sighash_single_is_unsupported_legacy(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_SINGLE, -1), SIGHASH_CLASS_UNSUPPORTED);
}

static void test_sighash_anyonecanpay_all_is_unsupported_legacy(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY | SIGHASH_ALL, -1),
                     SIGHASH_CLASS_UNSUPPORTED);
}

// --- UNSUPPORTED sighash types ---

static void test_sighash_0x80_alone_is_unsupported(void **state) {
    (void) state;
    // ANYONECANPAY alone (without base sighash) should be unsupported
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY, 0), SIGHASH_CLASS_UNSUPPORTED);
    assert_int_equal(classify_sighash(SIGHASH_ANYONECANPAY, 1), SIGHASH_CLASS_UNSUPPORTED);
}

static void test_sighash_0x84_is_unsupported(void **state) {
    (void) state;
    // 0x84 = ANYONECANPAY | 0x04, not a valid combination
    assert_int_equal(classify_sighash(0x84, 0), SIGHASH_CLASS_UNSUPPORTED);
    assert_int_equal(classify_sighash(0x84, 1), SIGHASH_CLASS_UNSUPPORTED);
}

static void test_sighash_arbitrary_values_unsupported(void **state) {
    (void) state;
    assert_int_equal(classify_sighash(0xFF, 0), SIGHASH_CLASS_UNSUPPORTED);
    assert_int_equal(classify_sighash(0x04, 0), SIGHASH_CLASS_UNSUPPORTED);
    assert_int_equal(classify_sighash(0x10, 1), SIGHASH_CLASS_UNSUPPORTED);
    assert_int_equal(classify_sighash(0xDEAD, 1), SIGHASH_CLASS_UNSUPPORTED);
}

int main() {
    const struct CMUnitTest tests[] = {
        // classify_sighash: SAFE
        cmocka_unit_test(test_sighash_all_is_safe_segwit_v0),
        cmocka_unit_test(test_sighash_all_is_safe_segwit_v1),
        cmocka_unit_test(test_sighash_all_is_safe_legacy),
        cmocka_unit_test(test_sighash_default_is_safe_taproot),
        cmocka_unit_test(test_sighash_default_is_not_safe_segwit_v0),
        cmocka_unit_test(test_sighash_default_is_not_safe_legacy),

        // classify_sighash: NON_SAFE
        cmocka_unit_test(test_sighash_none_is_non_safe_v0),
        cmocka_unit_test(test_sighash_none_is_non_safe_v1),
        cmocka_unit_test(test_sighash_single_is_non_safe),
        cmocka_unit_test(test_sighash_anyonecanpay_all_is_non_safe),
        cmocka_unit_test(test_sighash_anyonecanpay_none_is_non_safe),
        cmocka_unit_test(test_sighash_anyonecanpay_single_is_non_safe),

        // classify_sighash: legacy non-safe -> unsupported
        cmocka_unit_test(test_sighash_none_is_unsupported_legacy),
        cmocka_unit_test(test_sighash_single_is_unsupported_legacy),
        cmocka_unit_test(test_sighash_anyonecanpay_all_is_unsupported_legacy),

        // classify_sighash: UNSUPPORTED
        cmocka_unit_test(test_sighash_0x80_alone_is_unsupported),
        cmocka_unit_test(test_sighash_0x84_is_unsupported),
        cmocka_unit_test(test_sighash_arbitrary_values_unsupported),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
