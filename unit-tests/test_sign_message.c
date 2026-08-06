/**
 * Unit tests for handler_sign_message (BIP-137 "Bitcoin Signed Message").
 *
 * Test cases are loaded from TEST_VECTORS_PATH (a TOML file) at runtime; see the
 * file's header comment for the schema. For each vector we:
 *   1. Split the message into 64-byte (MESSAGE_CHUNK_SIZE) chunks and register
 *      them as a Merkle list with the mock dispatcher (this is what the device
 *      streams back via call_get_merkle_leaf_element), keeping the Merkle root.
 *   2. Serialize the sign_message command data exactly as the Python
 *      command_builder does: path_len || path || varint(msg_len) || merkle_root.
 *   3. Drive handler_sign_message against the mock dispatcher.
 *   4. On success, assert the returned status word is OK and the 65-byte
 *      recoverable signature matches the pinned base64 `expected_signature`.
 *      On a deterministic rejection, assert the mapped status word.
 *
 * We also capture the arguments the handler passes to the UI confirmation
 * (ui_display_message_and_confirm) so the test can verify the printable-vs-hash
 * decision and the formatted derivation path — not just the signature.
 *
 * Signing is real (deterministic ECDSA over the speculos bridge, which uses the
 * standard test seed), so the pinned signatures reproduce without a device.
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

#include "cx.h"

#include "mock_dispatcher.h"
#include "tomlc17.h"
#include "toml_helpers.h"

#include "buffer.h"
#include "varint.h"
#include "write.h"
#include "constants.h"
#include "handler/handlers.h"
#include "sw.h"
#include "ui/display.h"  // MESSAGE_CHUNK_SIZE, ui_display_message_and_confirm

#ifndef TEST_VECTORS_PATH
#error "TEST_VECTORS_PATH must be defined to point at the vectors file"
#endif

/* Long enough for the largest vector message (~1.6 KB), with margin. */
#define MAX_MSG_LEN     4096
#define MAX_PATH_STR    128
#define MAX_PATH_STEPS  16
#define MAX_ERROR_LEN   32
/* base64 of the 65-byte recoverable signature is 88 chars. */
#define MAX_SIG_B64_LEN 96
#define SIG_LEN         65

typedef struct {
    char name[64];
    uint8_t message[MAX_MSG_LEN];
    size_t message_len;
    char path[MAX_PATH_STR];
    bool has_error;
    char error[MAX_ERROR_LEN];
    bool has_signature;
    uint8_t expected_signature[SIG_LEN];
    bool has_displayed_as;
    bool expect_hash;  // true if `displayed_as = "hash"`, false if "message"
} testcase_t;

static testcase_t *g_cases = NULL;
static size_t g_n_cases = 0;

/* Records the arguments the handler passes to the UI confirmation, so the test
 * can verify the printable-vs-hash decision and the formatted path — not just
 * the signature. Reset before each case in case_setup. */
static struct {
    bool called;
    char path_str[MAX_PATH_STR];
    char displayed[MAX_MSG_LEN];
    bool is_hash;
} g_ui_capture;

/* The handler calls this to confirm the message; we capture and approve. Pure
 * UI DENY flows are out of scope for these vectors (see sign_message.toml). */
bool ui_display_message_and_confirm(dispatcher_context_t *context,
                                    const char *path_str,
                                    const char *message,
                                    bool is_hash) {
    (void) context;
    g_ui_capture.called = true;
    g_ui_capture.is_hash = is_hash;
    snprintf(g_ui_capture.path_str, sizeof(g_ui_capture.path_str), "%s", path_str);
    snprintf(g_ui_capture.displayed, sizeof(g_ui_capture.displayed), "%s", message);
    return true;
}

/* Remaining UI hooks the handler references; linker-only, no behavior needed. */
void ui_set_processing_screen_text(const char *text) {
    (void) text;
}
bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}
const char GA_LOADING_MESSAGE[] = "Loading message";

/* ===========================================================================
 *  Helpers
 * =========================================================================== */

/* Decode a standard-alphabet base64 string into `out`, asserting it yields
 * exactly out_len bytes. Aborts on malformed input (runs before any test). */
static void decode_base64(const char *field, const char *b64, uint8_t *out, size_t out_len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int8_t rev[256];
    memset(rev, -1, sizeof(rev));
    for (int i = 0; i < 64; i++) rev[(unsigned char) alphabet[i]] = (int8_t) i;

    size_t len = strlen(b64);
    if (len % 4 != 0) {
        fprintf(stderr, "%s: base64 length not a multiple of 4\n", field);
        abort();
    }

    size_t produced = 0;
    for (size_t i = 0; i < len; i += 4) {
        int8_t v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = b64[i + k];
            if (c == '=') {
                v[k] = 0;
                pad++;
            } else {
                v[k] = rev[(unsigned char) c];
                if (v[k] < 0) {
                    fprintf(stderr, "%s: invalid base64 char '%c'\n", field, c);
                    abort();
                }
            }
        }
        uint32_t triple = ((uint32_t) v[0] << 18) | ((uint32_t) v[1] << 12) |
                          ((uint32_t) v[2] << 6) | (uint32_t) v[3];
        uint8_t bytes[3] = {(uint8_t) (triple >> 16), (uint8_t) (triple >> 8), (uint8_t) triple};
        for (int k = 0; k < 3 - pad; k++) {
            if (produced >= out_len) {
                fprintf(stderr, "%s: base64 decodes to more than %zu bytes\n", field, out_len);
                abort();
            }
            out[produced++] = bytes[k];
        }
    }
    if (produced != out_len) {
        fprintf(stderr, "%s: base64 decoded to %zu bytes (expected %zu)\n", field, produced, out_len);
        abort();
    }
}

/* Map an error name from the vectors file to its status word. */
static uint16_t error_name_to_sw(const char *name) {
    if (strcmp(name, "WRONG_DATA_LENGTH") == 0) return SW_WRONG_DATA_LENGTH;
    if (strcmp(name, "INCORRECT_DATA") == 0) return SW_INCORRECT_DATA;
    fprintf(stderr, "unknown error name: %s\n", name);
    abort();
}

/* Parse a textual derivation path ("m/44'/1'/0'/0/0") into a uint32_t array,
 * OR-ing 0x80000000 onto hardened steps (suffix ' or h). Returns the step
 * count. Aborts on a malformed path. */
static size_t parse_bip32_path(const char *str, uint32_t out[MAX_PATH_STEPS]) {
    if (str[0] != 'm') {
        fprintf(stderr, "path %s does not start with 'm'\n", str);
        abort();
    }
    const char *p = str + 1;
    size_t n = 0;
    while (*p == '/') {
        p++;
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

/* The formatted path bip32_path_format produces: the input path without the
 * leading "m/" (it uses the same "'" hardened marker our vectors do). */
static const char *expected_path_str(const char *path) {
    if (strcmp(path, "m") == 0) return "(Master key)";
    return path + 2;  // skip "m/"
}

/* ===========================================================================
 *  TOML loader
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

        /* `message` is a (possibly non-ASCII, e.g. \r / \n) UTF-8 string; we
         * keep its raw bytes. */
        toml_datum_t msg = toml_get(tc_node, "message");
        if (msg.type != TOML_STRING) {
            fprintf(stderr, "%s: missing or non-string field: message\n", cur->name);
            abort();
        }
        if ((size_t) msg.u.str.len > sizeof(cur->message)) {
            fprintf(stderr, "%s: message too long (%d > %zu)\n",
                    cur->name, msg.u.str.len, sizeof(cur->message));
            abort();
        }
        cur->message_len = (size_t) msg.u.str.len;
        memcpy(cur->message, msg.u.str.ptr, cur->message_len);

        char sig_b64[MAX_SIG_B64_LEN];
        cur->has_signature =
            copy_optional_string(tc_node, "expected_signature", sig_b64, sizeof(sig_b64));
        if (cur->has_signature) {
            decode_base64("expected_signature", sig_b64, cur->expected_signature, SIG_LEN);
        }

        cur->has_error = copy_optional_string(tc_node, "error", cur->error, sizeof(cur->error));

        if (cur->has_error == cur->has_signature) {
            fprintf(stderr,
                    "%s: must have exactly one of `error` or `expected_signature`\n",
                    cur->name);
            abort();
        }

        char displayed_as[16];
        cur->has_displayed_as =
            copy_optional_string(tc_node, "displayed_as", displayed_as, sizeof(displayed_as));
        if (cur->has_displayed_as) {
            if (strcmp(displayed_as, "hash") == 0) {
                cur->expect_hash = true;
            } else if (strcmp(displayed_as, "message") == 0) {
                cur->expect_hash = false;
            } else {
                fprintf(stderr, "%s: displayed_as must be \"message\" or \"hash\"\n", cur->name);
                abort();
            }
        }
    }

    toml_free(r);
}

/* ===========================================================================
 *  Test driver
 * =========================================================================== */
typedef struct {
    void *mock_state;
    const testcase_t *tc;
} case_state_t;

static int case_setup(void **state) {
    const testcase_t *tc = (const testcase_t *) *state;
    case_state_t *cs = calloc(1, sizeof(case_state_t));
    if (cs == NULL) return -1;
    if (mock_dispatcher_setup(&cs->mock_state) != 0) {
        free(cs);
        return -1;
    }
    cs->tc = tc;
    *state = cs;
    memset(&g_ui_capture, 0, sizeof(g_ui_capture));
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

/* Serialize the sign_message command data into `out`, returning its length.
 * Layout matches command_builder.sign_message:
 *   path_len(1) || path(4*path_len, big-endian) || varint(msg_len) || merkle_root(32). */
static size_t serialize_request(const uint32_t *path,
                                size_t path_len,
                                size_t msg_len,
                                const uint8_t merkle_root[32],
                                uint8_t *out) {
    size_t off = 0;
    out[off++] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        write_u32_be(out, off, path[i]);
        off += 4;
    }
    off += (size_t) varint_write(out, off, msg_len);
    memcpy(out + off, merkle_root, 32);
    off += 32;
    return off;
}

/* Uppercase-hex of sha256(message), as the handler builds for the hash display. */
static void message_hash_hex(const uint8_t *msg, size_t msg_len, char out[65]) {
    uint8_t h[32];
    cx_hash_sha256(msg, msg_len, h, 32);
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02X", h[i]);
}

static void test_one_case(void **state) {
    case_state_t *cs = *state;
    mock_dispatcher_t *mock = cs->mock_state;
    const testcase_t *tc = cs->tc;

    uint32_t path[MAX_PATH_STEPS];
    size_t path_len = parse_bip32_path(tc->path, path);

    /* Split the message into 64-byte chunks and register them as a Merkle list;
     * the device streams these back via call_get_merkle_leaf_element. */
    size_t n_chunks = (tc->message_len + MESSAGE_CHUNK_SIZE - 1) / MESSAGE_CHUNK_SIZE;
    uint8_t merkle_root[32] = {0};
    if (n_chunks > 0) {
        const uint8_t *chunk_ptrs[(MAX_MSG_LEN / MESSAGE_CHUNK_SIZE) + 1];
        size_t chunk_lens[(MAX_MSG_LEN / MESSAGE_CHUNK_SIZE) + 1];
        for (size_t i = 0; i < n_chunks; i++) {
            size_t off = i * MESSAGE_CHUNK_SIZE;
            chunk_ptrs[i] = tc->message + off;
            chunk_lens[i] = tc->message_len - off < MESSAGE_CHUNK_SIZE
                                ? tc->message_len - off
                                : MESSAGE_CHUNK_SIZE;
        }
        mock_dispatcher_add_list(mock, chunk_ptrs, chunk_lens, n_chunks);
        memcpy(merkle_root, mock->trees[mock->n_trees - 1].root, 32);
    }

    uint8_t cdata[1 + 4 * MAX_PATH_STEPS + 5 + 32];
    size_t cdata_len = serialize_request(path, path_len, tc->message_len, merkle_root, cdata);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    dc->read_buffer = buffer_create(cdata, cdata_len);

    handler_sign_message(dc, 0);

    if (tc->has_error) {
        assert_int_equal(mock->last_sw, error_name_to_sw(tc->error));
        /* A framing/length rejection happens before the UI confirmation. */
        assert_false(g_ui_capture.called);
        return;
    }

    /* Success: response is the 65-byte recoverable signature. */
    assert_int_equal(mock->last_sw, SW_OK);
    assert_int_equal(mock->request_len, SIG_LEN);
    assert_memory_equal(mock->request_buf, tc->expected_signature, SIG_LEN);

    /* The UI confirmation must have been shown with the formatted path. */
    assert_true(g_ui_capture.called);
    assert_string_equal(g_ui_capture.path_str, expected_path_str(tc->path));

    /* When pinned, verify the printable-vs-hash decision and the shown text. */
    if (tc->has_displayed_as) {
        assert_int_equal(g_ui_capture.is_hash, tc->expect_hash);
        if (tc->expect_hash) {
            char hash_hex[65];
            message_hash_hex(tc->message, tc->message_len, hash_hex);
            assert_string_equal(g_ui_capture.displayed, hash_hex);
        } else {
            assert_int_equal(strlen(g_ui_capture.displayed), tc->message_len);
            assert_memory_equal(g_ui_capture.displayed, tc->message, tc->message_len);
        }
    }
}

/* Hand-written case: a declared message length of 2^32 trips the explicit
 * `message_length >= (1LL << 32)` guard -> SW_INCORRECT_DATA, before any chunk
 * is fetched. The message-based vector schema can't express a 4 GB length, so
 * this lives in C. */
static void test_message_too_long(void **state) {
    mock_dispatcher_t *mock = *state;
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    memset(&g_ui_capture, 0, sizeof(g_ui_capture));

    uint8_t cdata[1 + 4 + 9 + 32];
    size_t off = 0;
    cdata[off++] = 1;                              // bip32_path_len
    write_u32_be(cdata, off, 0x8000002cu);         // 44'
    off += 4;
    off += (size_t) varint_write(cdata, off, (uint64_t) 1 << 32);  // message_length
    memset(cdata + off, 0, 32);                    // merkle root (unused, rejected first)
    off += 32;

    dc->read_buffer = buffer_create(cdata, off);
    handler_sign_message(dc, 0);

    assert_int_equal(mock->last_sw, SW_INCORRECT_DATA);
    assert_false(g_ui_capture.called);
}

int main(void) {
    parse_vectors(TEST_VECTORS_PATH);

    /* VLA so the cmocka_run_group_tests_name macro's sizeof-based count works;
     * the +1 is the hand-written over-long-length case. */
    struct CMUnitTest tests[g_n_cases + 1];
    for (size_t i = 0; i < g_n_cases; i++) {
        tests[i] = (struct CMUnitTest){
            .name = g_cases[i].name,
            .test_func = test_one_case,
            .setup_func = case_setup,
            .teardown_func = case_teardown,
            .initial_state = &g_cases[i],
        };
    }
    tests[g_n_cases] = (struct CMUnitTest){
        .name = "message_too_long",
        .test_func = test_message_too_long,
        .setup_func = mock_dispatcher_setup,
        .teardown_func = mock_dispatcher_teardown,
        .initial_state = NULL,
    };

    int rc = cmocka_run_group_tests_name("sign_message", tests, NULL, NULL);
    free(g_cases);
    return rc;
}
