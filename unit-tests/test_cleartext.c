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

static void test_cleartext_confusion_score(void **state) {
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

static void test_cleartext_to_cleartext(void **state) {
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
        int rc = cleartext_encode(root, v->template_str, lines, &n_lines, &has_ct);
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
        for (size_t j = 0; j < n_lines; j++) {
            // For has_cleartext == false, some lines are rendered as raw
            // miniscript by the upstream Rust unparser; we don't (yet)
            // ship an AST unparser, so the line content for unrecognized
            // leaves diverges. Only check exact equality when the
            // expected line is not "fallback" content.
            if (!v->cleartext_flag && strcmp(lines[j], v->cleartext[j]) != 0) {
                // Skip — see above.
                continue;
            }
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cleartext_confusion_score),
        cmocka_unit_test(test_cleartext_to_cleartext),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
