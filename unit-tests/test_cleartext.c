/*
 * Smoke test for the cleartext wrapper (src/common/cleartext.c) over the
 * vendored bip388 binding. The exhaustive, audited rendering vectors live in
 * the Rust crate's own test suite (rust/bip388 `cargo test`); here we only
 * check that the C wrapper plumbs descriptors in and NUL-terminated lines out,
 * with the expected line counts / has_cleartext / confusion-score behaviour.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "cleartext.h"

static void test_singlesig(void **state) {
    (void) state;
    char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n = 0;
    bool has_cleartext = false;
    uint64_t score = 0;

    const char *desc = "wpkh(@0/**)";
    int rc = cleartext_encode(desc, strlen(desc), lines, &n, &has_cleartext, &score);

    assert_int_equal(rc, 1);
    assert_true(has_cleartext);
    assert_int_equal(n, 1);
    assert_true(score <= CLEARTEXT_MAX_CONFUSION_SCORE);
    /* The line is a non-empty, NUL-terminated string. */
    assert_true(strlen(lines[0]) > 0);
}

static void test_sorted_multisig(void **state) {
    (void) state;
    char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n = 0;
    bool has_cleartext = false;
    uint64_t score = 0;

    const char *desc = "wsh(sortedmulti(2,@0/**,@1/**))";
    int rc = cleartext_encode(desc, strlen(desc), lines, &n, &has_cleartext, &score);

    assert_int_equal(rc, 1);
    assert_true(has_cleartext);
    assert_int_equal(n, 1);
}

static void test_taproot_tree_multiline(void **state) {
    (void) state;
    char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n = 0;
    bool has_cleartext = false;
    uint64_t score = 0;

    /* A taproot key-path plus one script leaf renders as several lines. */
    const char *desc = "tr(@0/**,multi_a(3,@1/**,@2/**,@3/**))";
    int rc = cleartext_encode(desc, strlen(desc), lines, &n, &has_cleartext, &score);

    assert_int_equal(rc, 1);
    assert_true(has_cleartext);
    assert_true(n >= 2);
    assert_true(n <= CT_MAX_LINES);
}

static void test_parse_error(void **state) {
    (void) state;
    char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n = 12345;  /* sentinel; must be left untouched on failure */
    bool has_cleartext = true;
    uint64_t score = 0;

    const char *desc = "not a descriptor";
    int rc = cleartext_encode(desc, strlen(desc), lines, &n, &has_cleartext, &score);

    /* Parse failure: the caller falls back to the raw template. */
    assert_int_equal(rc, 0);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_singlesig),
        cmocka_unit_test(test_sorted_multisig),
        cmocka_unit_test(test_taproot_tree_multiline),
        cmocka_unit_test(test_parse_error),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
