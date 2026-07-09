#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include "common/buffer_ext.h"
#include "common/wallet.h"
#include "common/cleartext.h"

// Vector record shape — must match what gen.py emits.
typedef struct {
    const char *template_str;
    bool has_confusion_score;
    uint64_t confusion_score;
    bool has_cleartext_array;
    size_t cleartext_n;
    const char *const *cleartext;
    bool has_has_cleartext;
    bool cleartext_flag;
} ct_vector_t;

#include "cleartext_vectors.inc.c"

#define POLICY_BUF_SIZE 1024

static int parse_template(const char *s, uint8_t *out, size_t out_size) {
    buffer_t b = buffer_create((void *) s, strlen(s));
    return parse_descriptor_template(&b, out, out_size, WALLET_POLICY_VERSION_V2);
}

static void test_ct_confusion_score(void **state) {
    (void) state;

    for (size_t i = 0; i < CT_VECTORS_N; i++) {
        const ct_vector_t *v = &CT_VECTORS[i];
        if (!v->has_confusion_score) continue;

        uint8_t buf[POLICY_BUF_SIZE];
        int r = parse_template(v->template_str, buf, sizeof(buf));
        if (r < 0) {
            fprintf(stderr, "Vector %zu: parse failed for %s\n", i, v->template_str);
            fail();
        }
        const policy_node_t *root = (const policy_node_t *) buf;
        uint64_t got = cleartext_confusion_score(root);
        if (got != v->confusion_score) {
            fprintf(stderr,
                    "Vector %zu (%s): confusion_score got %llu, want %llu\n",
                    i,
                    v->template_str,
                    (unsigned long long) got,
                    (unsigned long long) v->confusion_score);
            fail();
        }
    }
}

static void test_ct_to_cleartext(void **state) {
    (void) state;

    for (size_t i = 0; i < CT_VECTORS_N; i++) {
        const ct_vector_t *v = &CT_VECTORS[i];
        if (!v->has_cleartext_array || !v->has_has_cleartext) continue;

        uint8_t buf[POLICY_BUF_SIZE];
        int r = parse_template(v->template_str, buf, sizeof(buf));
        if (r < 0) {
            fprintf(stderr, "Vector %zu: parse failed for %s\n", i, v->template_str);
            fail();
        }
        const policy_node_t *root = (const policy_node_t *) buf;
        char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
        size_t n_lines = 0;
        bool has_ct = false;
        descriptor_class_e cls = DC_OTHER;
        int rc = cleartext_encode(root, v->template_str, lines, &n_lines, &has_ct, &cls);
        if (rc <= 0) {
            fprintf(stderr,
                    "Vector %zu (%s): encode returned %d (expected >0)\n",
                    i,
                    v->template_str,
                    rc);
            fail();
        }
        if (has_ct != v->cleartext_flag) {
            fprintf(stderr,
                    "Vector %zu (%s): has_cleartext got %d, want %d\n",
                    i,
                    v->template_str,
                    (int) has_ct,
                    (int) v->cleartext_flag);
            fail();
        }
        if (n_lines != v->cleartext_n) {
            fprintf(stderr,
                    "Vector %zu (%s): n_lines got %zu, want %zu\n",
                    i,
                    v->template_str,
                    n_lines,
                    v->cleartext_n);
            for (size_t j = 0; j < n_lines; j++) {
                fprintf(stderr, "  got[%zu]=%s\n", j, lines[j]);
            }
            fail();
        }
        // Only validate the rendered line text when the descriptor renders
        // fully to cleartext. When has_cleartext == false, at least one tap-leaf
        // has no cleartext form and our encoder emits the fixed "(unknown)"
        // marker, whereas the shared vectors carry the reference Rust unparser's
        // raw-leaf rendering ("Raw policy: ..."); the text diverges by design, so
        // we check only n_lines and the has_cleartext flag (above) for these.
        // The app never shows the cleartext screen unless every line has
        // cleartext, so this divergence is not user-visible.
        if (v->cleartext_flag) {
            for (size_t j = 0; j < n_lines; j++) {
                if (strcmp(lines[j], v->cleartext[j]) != 0) {
                    fprintf(stderr,
                            "Vector %zu (%s): line %zu got %s, want %s\n",
                            i,
                            v->template_str,
                            j,
                            lines[j],
                            v->cleartext[j]);
                    fail();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Targeted edge-case tests.
//
// These reach corners of cleartext.c that depend on this port's fixed-size
// buffers and array bounds, so they can't be expressed as shared cross-
// implementation vectors (the reference has no equivalent 160-char line limit
// or 64-leaf / 32-keyexpr caps). Behaviour that *is* portable — unusual leaf
// orderings, timelock comparisons, the calendar-date branch of the timelock
// formatter, unclassified top-levels — lives in specs/bip388/test_vectors.toml
// instead and is exercised by the generic vector loop above.
// ---------------------------------------------------------------------------

// A generous buffer: some cases below build large taptrees whose parsed form
// does not fit in POLICY_BUF_SIZE.
#define BIG_POLICY_BUF_SIZE 4096

static const policy_node_t *parse_or_fail(const char *tmpl, uint8_t *buf, size_t bufsize) {
    int r = parse_template(tmpl, buf, bufsize);
    if (r < 0) {
        fprintf(stderr, "parse failed for %s\n", tmpl);
        fail();
    }
    return (const policy_node_t *) buf;
}

static void expect_score(const char *tmpl, uint64_t want) {
    uint8_t buf[BIG_POLICY_BUF_SIZE];
    const policy_node_t *root = parse_or_fail(tmpl, buf, sizeof(buf));
    uint64_t got = cleartext_confusion_score(root);
    if (got != want) {
        fprintf(stderr,
                "confusion_score(%s): got %llu, want %llu\n",
                tmpl,
                (unsigned long long) got,
                (unsigned long long) want);
        fail();
    }
}

// Encode `tmpl` and check the return code, the has_cleartext flag and, when
// `want_lines` is non-NULL, the rendered lines. Pass want_lines == NULL to skip
// the line/count checks (used when the raw fallback truncates the template).
static void expect_encode(const char *tmpl,
                          int want_rc,
                          bool want_has_ct,
                          const char *const *want_lines,
                          size_t want_n) {
    uint8_t buf[BIG_POLICY_BUF_SIZE];
    const policy_node_t *root = parse_or_fail(tmpl, buf, sizeof(buf));
    char lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1];
    size_t n_lines = 0;
    bool has_ct = false;
    descriptor_class_e cls = DC_OTHER;
    int rc = cleartext_encode(root, tmpl, lines, &n_lines, &has_ct, &cls);
    if (rc != want_rc) {
        fprintf(stderr, "encode(%s): rc got %d, want %d\n", tmpl, rc, want_rc);
        fail();
    }
    if (rc <= 0) return;  // error / no-output: nothing more to compare
    if (has_ct != want_has_ct) {
        fprintf(stderr, "encode(%s): has_cleartext got %d, want %d\n", tmpl, (int) has_ct, (int) want_has_ct);
        fail();
    }
    if (want_lines == NULL) return;
    if (n_lines != want_n) {
        fprintf(stderr, "encode(%s): n_lines got %zu, want %zu\n", tmpl, n_lines, want_n);
        for (size_t j = 0; j < n_lines; j++) fprintf(stderr, "  got[%zu]=%s\n", j, lines[j]);
        fail();
    }
    for (size_t j = 0; j < n_lines; j++) {
        if (strcmp(lines[j], want_lines[j]) != 0) {
            fprintf(stderr, "encode(%s): line %zu got %s, want %s\n", tmpl, j, lines[j], want_lines[j]);
            fail();
        }
    }
}

// Rendered line longer than CT_MAX_LINE_LEN: an and_v of two 15-of-15 multisig
// leaves produces one leaf line well over 160 chars, so rendering fails and
// cleartext_encode returns -1. The confusion score itself still computes: each
// n-of-n leaf admits 2 encodings, so 2 * 2 = 4.
static void test_ct_line_overflow(void **state) {
    (void) state;
    const char *tmpl =
        "tr(@0/**,and_v(v:multi_a(15,@1/**,@2/**,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,"
        "@10/**,@11/**,@12/**,@13/**,@14/**,@15/**),multi_a(15,@16/**,@17/**,@18/**,@19/**,"
        "@20/**,@21/**,@22/**,@23/**,@24/**,@25/**,@26/**,@27/**,@28/**,@29/**,@30/**)))";
    expect_score(tmpl, 4);
    expect_encode(tmpl, -1, false, NULL, 0);
}

// Right-nested helper is rejected by the depth guard; build a balanced taptree
// of `count` identical pk(@1/**) leaves instead (depth ~= log2(count)).
static void append_balanced(char *buf, int count) {
    if (count == 1) {
        strcat(buf, "pk(@1/**)");
        return;
    }
    strcat(buf, "{");
    append_balanced(buf, count / 2);
    strcat(buf, ",");
    append_balanced(buf, count - count / 2);
    strcat(buf, "}");
}

// Size guards for large taptrees:
//  - > CT_MAX_TAP_LEAVES (64) leaves: collect_leaves overflows and
//    cleartext_confusion_score saturates to UINT64_MAX.
//  - the many key occurrences (> CT_MAX_KEYEXPRS) make key_orderings_count
//    report the descriptor as non-canonical, so the encoder falls back to the
//    raw template (has_cleartext == false).
static void test_ct_too_many_leaves(void **state) {
    (void) state;
    static char big[BIG_POLICY_BUF_SIZE];
    strcpy(big, "tr(@0/**,");
    append_balanced(big, 65);
    strcat(big, ")");
    expect_score(big, UINT64_MAX);
    expect_encode(big, 1, false, NULL, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ct_confusion_score),
        cmocka_unit_test(test_ct_to_cleartext),
        cmocka_unit_test(test_ct_line_overflow),
        cmocka_unit_test(test_ct_too_many_leaves),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
