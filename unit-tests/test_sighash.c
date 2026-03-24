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
//
// classify_sighash is a pure (sighash_type, segwit_version) -> class mapping,
// so we test it as a truth table: each row is a (sighash_type, segwit_version,
// expected class) triple. This keeps the policy auditable at a glance and makes
// it trivial to add cases. On mismatch we fail_msg() the offending row so a
// failure is easy to pinpoint.
//
// segwit_version: -1 = legacy (pre-segwit), 0 = segwit v0, 1 = Taproot (v1).
// ========================================================================

typedef struct {
    uint32_t sighash_type;
    int segwit_version;
    sighash_class_t expected;
} sighash_case_t;

static const sighash_case_t classify_sighash_cases[] = {
    // --- SAFE: SIGHASH_ALL (any version), SIGHASH_DEFAULT (Taproot only) ---
    {SIGHASH_ALL, -1, SIGHASH_CLASS_SAFE},
    {SIGHASH_ALL, 0, SIGHASH_CLASS_SAFE},
    {SIGHASH_ALL, 1, SIGHASH_CLASS_SAFE},
    {SIGHASH_DEFAULT, 1, SIGHASH_CLASS_SAFE},
    // SIGHASH_DEFAULT (0x00) is only valid for Taproot: unsupported elsewhere
    {SIGHASH_DEFAULT, 0, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_DEFAULT, -1, SIGHASH_CLASS_UNSUPPORTED},

    // --- NON_SAFE: NONE / SINGLE / ANYONECANPAY|* on segwit inputs (v0 and v1) ---
    {SIGHASH_NONE, 0, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_NONE, 1, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_SINGLE, 0, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_SINGLE, 1, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_ALL, 0, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_ALL, 1, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_NONE, 0, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_NONE, 1, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, 0, SIGHASH_CLASS_NON_SAFE},
    {SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, 1, SIGHASH_CLASS_NON_SAFE},

    // --- Legacy (segwit_version < 0): any non-ALL sighash is UNSUPPORTED ---
    {SIGHASH_NONE, -1, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_SINGLE, -1, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_ANYONECANPAY | SIGHASH_ALL, -1, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_ANYONECANPAY | SIGHASH_NONE, -1, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_ANYONECANPAY | SIGHASH_SINGLE, -1, SIGHASH_CLASS_UNSUPPORTED},

    // --- UNSUPPORTED: malformed / unrecognized values ---
    // ANYONECANPAY alone (no base type)
    {SIGHASH_ANYONECANPAY, 0, SIGHASH_CLASS_UNSUPPORTED},
    {SIGHASH_ANYONECANPAY, 1, SIGHASH_CLASS_UNSUPPORTED},
    // 0x84 = ANYONECANPAY | 0x04, not a valid combination
    {0x84, 0, SIGHASH_CLASS_UNSUPPORTED},
    {0x84, 1, SIGHASH_CLASS_UNSUPPORTED},
    // arbitrary out-of-range values
    {0xFF, 0, SIGHASH_CLASS_UNSUPPORTED},
    {0x04, 0, SIGHASH_CLASS_UNSUPPORTED},
    {0x10, 1, SIGHASH_CLASS_UNSUPPORTED},
    {0xDEAD, 1, SIGHASH_CLASS_UNSUPPORTED},
};

static void test_classify_sighash(void **state) {
    (void) state;

    for (size_t i = 0; i < sizeof(classify_sighash_cases) / sizeof(classify_sighash_cases[0]);
         i++) {
        const sighash_case_t *c = &classify_sighash_cases[i];
        sighash_class_t got = classify_sighash(c->sighash_type, c->segwit_version);
        if (got != c->expected) {
            fail_msg("case[%zu]: classify_sighash(0x%02x, %d) = %d, expected %d",
                     i,
                     c->sighash_type,
                     c->segwit_version,
                     (int) got,
                     (int) c->expected);
        }
    }
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_classify_sighash),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
