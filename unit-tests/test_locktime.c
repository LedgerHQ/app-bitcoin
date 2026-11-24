#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/locktime.h"

// ========================================================================
// Tests for the BIP-0370 "Determining Lock Time" procedure.
//
// A PSBTv2 has no nLockTime field, so this derivation is the only thing that decides what every
// signature commits to. The table below is the BIP's own set of test vectors (cases tagged
// "bip370/N", in the order they appear there), followed by the cases the BIP does not cover but
// where a plausible-looking implementation goes wrong: treating PSBT_GLOBAL_FALLBACK_LOCKTIME as a
// lower bound, rejecting any PSBT that mentions both lock time types, and the value ranges.
//
// H = PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, T = PSBT_IN_REQUIRED_TIME_LOCKTIME.
// ========================================================================

// The height/time boundary, mirrored here rather than taken from constants.h: the point is to pin
// the value the app actually uses against the one BIP-0370 spells out.
#define BIP370_LOCKTIME_THRESHOLD 500000000u

#define MAX_CASE_INPUTS 3

// Brace initializers for one input's declared fields (not compound literals, so that the case
// table below can live at file scope like the other unit tests' tables).
#define LT_NONE  {0}
#define LT_H(hv) {.has_height_locktime = true, .height_locktime = (hv)}
#define LT_T(tv) {.has_time_locktime = true, .time_locktime = (tv)}
#define LT_HT(hv, tv)             \
    {.has_height_locktime = true, \
     .height_locktime = (hv),     \
     .has_time_locktime = true,   \
     .time_locktime = (tv)}

typedef struct {
    const char *name;
    locktime_input_t inputs[MAX_CASE_INPUTS];
    size_t n_inputs;
    uint32_t fallback;  // 0 also stands for "PSBT_GLOBAL_FALLBACK_LOCKTIME absent"
    locktime_status_t expected_status;
    uint32_t expected_locktime;  // only checked when expected_status is LOCKTIME_OK
} locktime_case_t;

static const locktime_case_t locktime_cases[] = {
    // --- the ten vectors from BIP-0370, in the order they appear there ---
    {"bip370/1: no input declares anything, no fallback", {LT_NONE}, 1, 0, LOCKTIME_OK, 0},
    {"bip370/2: no input declares anything, fallback 0", {LT_NONE}, 1, 0, LOCKTIME_OK, 0},
    {"bip370/3: a height, and an input declaring nothing",
     {LT_H(10000), LT_NONE},
     2,
     0,
     LOCKTIME_OK,
     10000},
    {"bip370/4: two heights -> the larger", {LT_H(10000), LT_H(9000)}, 2, 0, LOCKTIME_OK, 10000},
    {"bip370/5: a height, and an input declaring both",
     {LT_H(10000), LT_HT(9000, 1657048460)},
     2,
     0,
     LOCKTIME_OK,
     10000},
    {"bip370/6: every input declares both -> height wins",
     {LT_HT(10000, 1657048459), LT_HT(9000, 1657048460)},
     2,
     0,
     LOCKTIME_OK,
     10000},
    {"bip370/7: a time-only input forces time",
     {LT_T(1657048459), LT_HT(9000, 1657048460)},
     2,
     0,
     LOCKTIME_OK,
     1657048460},
    {"bip370/8: a time-only input forces time (other order)",
     {LT_HT(10000, 1657048459), LT_T(1657048460)},
     2,
     0,
     LOCKTIME_OK,
     1657048460},
    {"bip370/9: an input declaring nothing, and a time",
     {LT_NONE, LT_T(1657048460)},
     2,
     0,
     LOCKTIME_OK,
     1657048460},
    {"bip370/10: height-only and time-only -> undeterminable",
     {LT_H(10000), LT_T(1657048460)},
     2,
     0,
     LOCKTIME_ERR_UNDETERMINED,
     0},

    // --- the fallback is ignored, not maxed in, as soon as any input declares a lock time ---
    {"a fallback larger than the required height is ignored",
     {LT_H(10000)},
     1,
     900000,
     LOCKTIME_OK,
     10000},
    {"a fallback smaller than the required height is ignored",
     {LT_H(10000)},
     1,
     5,
     LOCKTIME_OK,
     10000},
    {"the fallback is ignored for times too",
     {LT_T(1657048460)},
     1,
     1700000000,
     LOCKTIME_OK,
     1657048460},
    {"the fallback is used verbatim when no input declares anything",
     {LT_NONE, LT_NONE},
     2,
     1901594,
     LOCKTIME_OK,
     1901594},
    {"no inputs at all: the fallback is used", {LT_NONE}, 0, 42, LOCKTIME_OK, 42},

    // --- a type conflict is a conflict whatever its shape ---
    {"undeterminable, inputs in the other order",
     {LT_T(1657048460), LT_H(10000)},
     2,
     0,
     LOCKTIME_ERR_UNDETERMINED,
     0},
    {"a third input declaring both does not rescue a conflict",
     {LT_H(10000), LT_HT(9000, 1657048459), LT_T(1657048460)},
     3,
     0,
     LOCKTIME_ERR_UNDETERMINED,
     0},
    {"a fallback does not suppress the rejection",
     {LT_H(10000), LT_T(1657048460)},
     2,
     7,
     LOCKTIME_ERR_UNDETERMINED,
     0},

    // --- ranges, from BIP-0370's field table: 0 < H < 500000000 <= T ---
    {"height 0 is invalid", {LT_H(0)}, 1, 0, LOCKTIME_ERR_RANGE, 0},
    {"height 1 is valid", {LT_H(1)}, 1, 0, LOCKTIME_OK, 1},
    {"the largest valid height",
     {LT_H(BIP370_LOCKTIME_THRESHOLD - 1)},
     1,
     0,
     LOCKTIME_OK,
     BIP370_LOCKTIME_THRESHOLD - 1},
    {"a height at the threshold is invalid",
     {LT_H(BIP370_LOCKTIME_THRESHOLD)},
     1,
     0,
     LOCKTIME_ERR_RANGE,
     0},
    {"the largest u32 is not a valid height", {LT_H(0xFFFFFFFF)}, 1, 0, LOCKTIME_ERR_RANGE, 0},
    {"time 0 is invalid", {LT_T(0)}, 1, 0, LOCKTIME_ERR_RANGE, 0},
    {"a time just below the threshold is invalid",
     {LT_T(BIP370_LOCKTIME_THRESHOLD - 1)},
     1,
     0,
     LOCKTIME_ERR_RANGE,
     0},
    {"the smallest valid time",
     {LT_T(BIP370_LOCKTIME_THRESHOLD)},
     1,
     0,
     LOCKTIME_OK,
     BIP370_LOCKTIME_THRESHOLD},
    {"the largest u32 is a valid time", {LT_T(0xFFFFFFFF)}, 1, 0, LOCKTIME_OK, 0xFFFFFFFF},
    {"an out-of-range value is caught in an input declaring both",
     {LT_HT(0, 1657048460)},
     1,
     0,
     LOCKTIME_ERR_RANGE,
     0},
};

static void run_case(size_t index, const locktime_case_t *c) {
    locktime_acc_t acc = {0};

    for (size_t i = 0; i < c->n_inputs; i++) {
        locktime_status_t status = locktime_acc_add_input(&acc, &c->inputs[i]);
        if (status != LOCKTIME_OK) {
            if (status != c->expected_status) {
                fail_msg("case[%zu] \"%s\": input %zu gave status %d, expected %d",
                         index,
                         c->name,
                         i,
                         (int) status,
                         (int) c->expected_status);
            }
            return;  // the expected per-input rejection happened; nothing further to check
        }
    }

    uint32_t locktime = 0xDEADBEEF;
    locktime_status_t status = locktime_acc_resolve(&acc, c->fallback, &locktime);

    if (status != c->expected_status) {
        fail_msg("case[%zu] \"%s\": resolve gave status %d, expected %d",
                 index,
                 c->name,
                 (int) status,
                 (int) c->expected_status);
    }
    if (status == LOCKTIME_OK && locktime != c->expected_locktime) {
        fail_msg("case[%zu] \"%s\": locktime %u, expected %u",
                 index,
                 c->name,
                 locktime,
                 c->expected_locktime);
    }
}

static void test_locktime_cases(void **state) {
    (void) state;
    for (size_t i = 0; i < sizeof(locktime_cases) / sizeof(locktime_cases[0]); i++) {
        run_case(i, &locktime_cases[i]);
    }
}

// The app's threshold must be the one BIP-0370 spells out; everything above depends on it.
static void test_threshold_matches_the_spec(void **state) {
    (void) state;
    assert_int_equal(LOCKTIME_THRESHOLD, BIP370_LOCKTIME_THRESHOLD);
}

// The accumulator holds across a full input set, not just the two or three of the vectors above.
// MAX_N_INPUTS_CAN_SIGN is the real bound the signing flow allows.
static void test_accumulates_over_many_inputs(void **state) {
    (void) state;
    locktime_acc_t acc = {0};

    for (uint32_t i = 0; i < MAX_N_INPUTS_CAN_SIGN; i++) {
        // descending, so that a "last one wins" bug would show up as 1 rather than the maximum
        locktime_input_t in = {.has_height_locktime = true,
                               .height_locktime = MAX_N_INPUTS_CAN_SIGN - i};
        assert_int_equal(LOCKTIME_OK, locktime_acc_add_input(&acc, &in));
    }

    uint32_t locktime = 0;
    assert_int_equal(LOCKTIME_OK, locktime_acc_resolve(&acc, 0, &locktime));
    assert_int_equal(MAX_N_INPUTS_CAN_SIGN, locktime);
}

// A rejected input must leave nothing behind: the caller aborts on LOCKTIME_ERR_RANGE, but an
// accumulator mutated halfway would make the failure order-dependent and hard to reason about.
static void test_a_range_error_leaves_the_accumulator_untouched(void **state) {
    (void) state;
    locktime_acc_t acc = {0};

    const locktime_input_t good = {.has_height_locktime = true, .height_locktime = 10000};
    assert_int_equal(LOCKTIME_OK, locktime_acc_add_input(&acc, &good));

    const locktime_acc_t before = acc;

    // a valid time alongside an invalid height: neither may be folded in
    const locktime_input_t bad = {.has_height_locktime = true,
                                  .height_locktime = 0,
                                  .has_time_locktime = true,
                                  .time_locktime = 1657048460};
    assert_int_equal(LOCKTIME_ERR_RANGE, locktime_acc_add_input(&acc, &bad));
    assert_memory_equal(&before, &acc, sizeof(acc));

    uint32_t locktime = 0;
    assert_int_equal(LOCKTIME_OK, locktime_acc_resolve(&acc, 0, &locktime));
    assert_int_equal(10000, locktime);
}

// resolve must not write through `out` when it cannot determine a lock time: the caller aborts,
// but a partially-written out-parameter is exactly how a "signed 0 by accident" bug starts.
static void test_resolve_does_not_write_out_when_undetermined(void **state) {
    (void) state;
    locktime_acc_t acc = {0};

    const locktime_input_t height_only = {.has_height_locktime = true, .height_locktime = 10000};
    const locktime_input_t time_only = {.has_time_locktime = true, .time_locktime = 1657048460};
    assert_int_equal(LOCKTIME_OK, locktime_acc_add_input(&acc, &height_only));
    assert_int_equal(LOCKTIME_OK, locktime_acc_add_input(&acc, &time_only));

    uint32_t locktime = 0xDEADBEEF;
    assert_int_equal(LOCKTIME_ERR_UNDETERMINED, locktime_acc_resolve(&acc, 1234, &locktime));
    assert_int_equal(0xDEADBEEF, locktime);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_threshold_matches_the_spec),
        cmocka_unit_test(test_locktime_cases),
        cmocka_unit_test(test_accumulates_over_many_inputs),
        cmocka_unit_test(test_a_range_error_leaves_the_accumulator_untouched),
        cmocka_unit_test(test_resolve_does_not_write_out_when_undetermined),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
