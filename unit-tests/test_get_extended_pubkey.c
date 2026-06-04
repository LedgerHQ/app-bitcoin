/**
 * Unit tests for handler_get_extended_pubkey.
 *
 * Test cases are loaded from TEST_VECTORS_PATH (a TOML file) at runtime; see the
 * file's header comment for the schema. The handler source is compiled directly
 * into the test and driven through the mock dispatcher (which backs the response
 * buffer); the UI confirmation is replaced with a capturing stub. For each
 * vector we serialize the get_extended_pubkey command data exactly as the Python
 * command_builder does — display(1) || path_len(1) || path(4*len, big-endian) —
 * and run the handler twice:
 *   - display = 0: a `standard` path is exported (SW_OK) without confirmation; a
 *                  non-standard one is rejected with NOT_SUPPORTED.
 *   - display = 1: the path is always exported and the UI confirmation is shown,
 *                  which lets us check the formatted derivation path.
 * On success we compare the returned status word and (when pinned) the exact
 * base58 pubkey. A case with `error` set expects that status word for both
 * display values.
 *
 * BIP32 derivation is real (app crypto over the speculos bridge, which uses the
 * standard test seed), so no device or emulator is needed.
 */
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "mock_dispatcher.h"
#include "tomlc17.h"
#include "toml_helpers.h"

#include "buffer.h"
#include "write.h"
#include "constants.h"
#include "handler/handlers.h"
#include "sw.h"
#include "ui/display.h"  // ui_display_pubkey

#ifndef TEST_VECTORS_PATH
#error "TEST_VECTORS_PATH must be defined to point at the vectors file"
#endif

#define MAX_NAME_LEN  64
#define MAX_PATH_LEN  128
#define MAX_ERROR_LEN 32
/* A few extra slots so the over-long-path vector still parses and is rejected
 * by the length check inside the handler. */
#define MAX_PATH_STEPS (MAX_BIP32_PATH_STEPS + 6)

typedef struct {
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    bool standard;
    bool has_error;
    char error[MAX_ERROR_LEN];
    bool has_pubkey;
    char expected_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} testcase_t;

static testcase_t *g_cases = NULL;
static size_t g_n_cases = 0;

/* Records the arguments the handler passes to the UI confirmation, so the test
 * can verify the formatted path and that the displayed pubkey matches the one
 * returned to the host. Reset before each handler run. */
static struct {
    bool called;
    char path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} g_ui_capture;

/* The handler shows this when display = 1; we capture and approve. Pure UI
 * approve/reject flows are out of scope for these vectors (see the .toml). */
bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       const char *pubkey) {
    (void) context;
    g_ui_capture.called = true;
    snprintf(g_ui_capture.path_str, sizeof(g_ui_capture.path_str), "%s", bip32_path_str);
    snprintf(g_ui_capture.pubkey, sizeof(g_ui_capture.pubkey), "%s", pubkey);
    return true;
}

/* ===========================================================================
 *  TOML loader. Copies the relevant fields out of the parsed document into
 *  g_cases. Runs from main() before any test, so on malformed input we
 *  abort() the process (there is no setjmp buffer to unwind to yet).
 * =========================================================================== */
static void parse_vectors(const char *path) {
    toml_result_t r = toml_parse_file_ex(path);
    if (!r.ok) {
        fprintf(stderr, "failed to parse %s: %s\n", path, r.errmsg);
        toml_free(r);
        abort();
    }

    toml_datum_t cases = toml_get(r.toptab, "case");
    if (cases.type != TOML_ARRAY) {
        fprintf(stderr, "vectors file is missing the [[case]] array\n");
        toml_free(r);
        abort();
    }

    if (cases.u.arr.size <= 0) {
        fprintf(stderr, "vectors file has no [[case]] entries\n");
        abort();
    }

    g_n_cases = (size_t) cases.u.arr.size;
    g_cases = calloc(g_n_cases, sizeof(testcase_t));
    if (g_cases == NULL) {
        fprintf(stderr, "out of memory allocating %zu test cases\n", g_n_cases);
        abort();
    }

    for (size_t i = 0; i < g_n_cases; i++) {
        toml_datum_t tc_node = cases.u.arr.elem[i];
        if (tc_node.type != TOML_TABLE) {
            fprintf(stderr, "case %zu: not a TOML table\n", i);
            abort();
        }

        testcase_t *cur = &g_cases[i];

        copy_required_string(tc_node, "name", cur->name, sizeof(cur->name));
        copy_required_string(tc_node, "path", cur->path, sizeof(cur->path));

        toml_datum_t standard = toml_get(tc_node, "standard");
        if (standard.type != TOML_BOOLEAN) {
            fprintf(stderr, "%s: missing or non-boolean field: standard\n", cur->name);
            abort();
        }
        cur->standard = standard.u.boolean;

        cur->has_error = copy_optional_string(tc_node, "error", cur->error, sizeof(cur->error));
        cur->has_pubkey = copy_optional_string(tc_node,
                                               "expected_pubkey",
                                               cur->expected_pubkey,
                                               sizeof(cur->expected_pubkey));
    }

    toml_free(r);
}

/* ===========================================================================
 *  Helpers
 * =========================================================================== */

/* Parse a textual derivation path ("m", "m/44'/1'/0'", ...) into a uint32_t
 * array, OR-ing 0x80000000 onto hardened steps (suffix ' or h). Aborts on a
 * malformed path or one with more than MAX_PATH_STEPS steps. */
static size_t parse_bip32_path(const char *str, uint32_t out[MAX_PATH_STEPS]) {
    if (str[0] != 'm') {
        fprintf(stderr, "path %s does not start with 'm'\n", str);
        abort();
    }
    const char *p = str + 1;
    size_t n = 0;
    while (*p == '/') {
        p++;  // skip '/'
        if (*p < '0' || *p > '9') {
            fprintf(stderr, "path %s: expected a number after '/'\n", str);
            abort();
        }
        uint32_t value = 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (uint32_t) (*p - '0');
            p++;
        }
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            value |= 0x80000000u;
            p++;
        }
        if (n >= MAX_PATH_STEPS) {
            fprintf(stderr, "path %s: too many steps\n", str);
            abort();
        }
        out[n++] = value;
    }
    if (*p != '\0') {
        fprintf(stderr, "path %s: unexpected trailing characters '%s'\n", str, p);
        abort();
    }
    return n;
}

/* The human-readable path bip32_path_format produces: the input path without
 * the leading "m/" (it uses the same "'" hardened marker our vectors do), or
 * "(Master key)" for the empty path. */
static const char *expected_path_str(const char *path) {
    if (strcmp(path, "m") == 0) {
        return "(Master key)";
    }
    return path + 2;  // skip "m/"
}

/* Map an error name from the vectors file to its status word. */
static uint16_t error_name_to_sw(const char *name) {
    if (strcmp(name, "NOT_SUPPORTED") == 0) {
        return SW_NOT_SUPPORTED;
    }
    if (strcmp(name, "INCORRECT_DATA") == 0) {
        return SW_INCORRECT_DATA;
    }
    fprintf(stderr, "unknown error name: %s\n", name);
    abort();
}

/* ===========================================================================
 *  Test driver
 * =========================================================================== */

/* Per-case cmocka state: pairs a heap-allocated mock dispatcher with the
 * testcase. Mirrors test_register_wallet.c / test_sign_message.c. */
typedef struct {
    void *mock_state;
    const testcase_t *tc;
} case_state_t;

static int case_setup(void **state) {
    const testcase_t *tc = (const testcase_t *) *state;
    case_state_t *cs = calloc(1, sizeof(case_state_t));
    if (cs == NULL) {
        return -1;
    }
    if (mock_dispatcher_setup(&cs->mock_state) != 0) {
        free(cs);
        return -1;
    }
    cs->tc = tc;
    *state = cs;
    return 0;
}

static int case_teardown(void **state) {
    case_state_t *cs = *state;
    if (cs != NULL) {
        mock_dispatcher_teardown(&cs->mock_state);
        free(cs);
        *state = NULL;
    }
    return 0;
}

/* Build the command data, reset the mock and the UI capture, run the handler,
 * and return the status word plus the (NUL-terminated) response bytes. */
static void run_handler(mock_dispatcher_t *mock,
                        const testcase_t *tc,
                        uint8_t display,
                        uint16_t *sw,
                        char *resp,
                        size_t resp_size) {
    mock_dispatcher_init(mock);
    memset(&g_ui_capture, 0, sizeof(g_ui_capture));

    uint32_t path[MAX_PATH_STEPS];
    size_t path_len = parse_bip32_path(tc->path, path);

    uint8_t cdata[2 + 4 * MAX_PATH_STEPS];
    size_t off = 0;
    cdata[off++] = display;
    cdata[off++] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        write_u32_be(cdata, off, path[i]);
        off += 4;
    }

    mock->dc.read_buffer = buffer_create(cdata, off);
    handler_get_extended_pubkey(&mock->dc, 0);

    *sw = mock->last_sw;
    size_t n = mock->request_len < resp_size - 1 ? mock->request_len : resp_size - 1;
    memcpy(resp, mock->request_buf, n);
    resp[n] = '\0';
}

static void test_one_case(void **state) {
    case_state_t *cs = *state;
    mock_dispatcher_t *mock = cs->mock_state;
    const testcase_t *tc = cs->tc;

    char resp[MAX_SERIALIZED_PUBKEY_LENGTH + 2];
    uint16_t sw;

    if (tc->has_error) {
        /* The error is reported regardless of the display flag (e.g. an
         * over-max path is rejected before the export/UI step). */
        uint16_t err = error_name_to_sw(tc->error);
        run_handler(mock, tc, 0, &sw, resp, sizeof(resp));
        assert_int_equal(sw, err);
        assert_false(g_ui_capture.called);
        run_handler(mock, tc, 1, &sw, resp, sizeof(resp));
        assert_int_equal(sw, err);
        assert_false(g_ui_capture.called);
        return;
    }

    /* display = 0: behaviour is governed by the `standard` flag. */
    run_handler(mock, tc, 0, &sw, resp, sizeof(resp));
    if (tc->standard) {
        assert_int_equal(sw, SW_OK);
        if (tc->has_pubkey) {
            assert_string_equal(resp, tc->expected_pubkey);
        }
        assert_false(g_ui_capture.called);  // exported without confirmation
    } else {
        assert_int_equal(sw, SW_NOT_SUPPORTED);
        assert_false(g_ui_capture.called);
    }

    /* display = 1: always exported, and the UI confirmation is shown — which
     * lets us check the formatted path and that the displayed pubkey matches
     * the one returned to the host. */
    run_handler(mock, tc, 1, &sw, resp, sizeof(resp));
    assert_int_equal(sw, SW_OK);
    if (tc->has_pubkey) {
        assert_string_equal(resp, tc->expected_pubkey);
    }
    assert_true(g_ui_capture.called);
    assert_string_equal(g_ui_capture.path_str, expected_path_str(tc->path));
    assert_string_equal(g_ui_capture.pubkey, resp);
}

int main(void) {
    parse_vectors(TEST_VECTORS_PATH);

    /* VLA so that the cmocka_run_group_tests_name macro's sizeof-based
     * count computes correctly; a calloc'd pointer would not. */
    struct CMUnitTest tests[g_n_cases];
    for (size_t i = 0; i < g_n_cases; i++) {
        tests[i] = (struct CMUnitTest){
            .name = g_cases[i].name,
            .test_func = test_one_case,
            .setup_func = case_setup,
            .teardown_func = case_teardown,
            .initial_state = &g_cases[i],
        };
    }

    int rc = cmocka_run_group_tests_name("get_extended_pubkey", tests, NULL, NULL);
    free(g_cases);
    return rc;
}
