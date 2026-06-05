/**
 * Unit tests for handler_register_wallet (and, indirectly, its static helpers
 * is_policy_acceptable / is_policy_name_acceptable).
 *
 * Test cases are loaded from TEST_VECTORS_PATH (a TOML file) at runtime; see
 * the file's header comment for the schema. For each vector we:
 *   1. Register the descriptor template as a preimage and the keys-info list as
 *      a Merkle tree with the mock dispatcher (this gives us the keys Merkle
 *      root the device would have received from the client).
 *   2. Serialize the register_wallet command data exactly as the Python
 *      command_builder does: varint(len(wallet_bytes)) || wallet_bytes.
 *   3. Drive handler_register_wallet against the mock dispatcher.
 *   4. On success, assert the returned status word is OK and that the response
 *      (wallet_id || hmac) matches the pinned expected_wallet_id and, when
 *      present, expected_wallet_hmac.
 *      On a deterministic rejection, assert the mapped status word.
 *
 * BIP32 derivation and the SLIP-0021 wallet HMAC are real (app crypto over the
 * speculos bridge, which uses the standard test seed), so the pinned wallet
 * HMACs reproduce without a device or emulator.
 *
 * A final, hand-written case (not from the vectors file) checks the
 * SW_WRONG_DATA_LENGTH framing branch, which the portable wallet-policy schema
 * cannot express.
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
#include "common/wallet.h"
#include "constants.h"
#include "handler/handlers.h"
#include "sw.h"
#include "ui/display.h"  // key_type_e, ui_display_register_wallet_policy

#ifndef TEST_VECTORS_PATH
#error "TEST_VECTORS_PATH must be defined to point at the vectors file"
#endif

#define MAX_KEYS_PER_CASE 16
#define MAX_KEY_INFO_LEN  (MAX_POLICY_KEY_INFO_LEN + 1)
#define MAX_TPL_LEN       (MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 + 1)
/* One slot more than MAX_WALLET_NAME_LENGTH so the over-long-name reject vector
 * still fits in the buffer (the handler is what rejects it, not the loader). */
#define MAX_NAME_LEN      (MAX_WALLET_NAME_LENGTH + 2)
#define MAX_ERROR_LEN     32
#define HASH_HEX_LEN      64

typedef struct {
    char name[MAX_NAME_LEN];
    char descriptor_template[MAX_TPL_LEN];
    char keys_info[MAX_KEYS_PER_CASE][MAX_KEY_INFO_LEN];
    size_t n_keys;
    char wallet_name[MAX_NAME_LEN];
    bool has_error;
    char error[MAX_ERROR_LEN];
    bool has_wallet_id;
    uint8_t expected_wallet_id[32];
    bool has_wallet_hmac;
    uint8_t expected_wallet_hmac[32];
    bool has_key_types;
    key_type_e key_types[MAX_KEYS_PER_CASE];
    size_t n_key_types;
} testcase_t;

static testcase_t *g_cases = NULL;
static size_t g_n_cases = 0;

/* Records the arguments the handler passes to the UI confirmation, so the test
 * can verify the per-key classification (internal/external/unspendable) the
 * handler computed — not just the aggregate status word. Reset before each case
 * in case_setup. A file-scope global is the channel: the stub's signature is
 * fixed by the UI prototype, and the shared mock dispatcher shouldn't carry
 * test-specific fields. */
static struct {
    bool called;
    size_t n_keys;
    key_type_e keys_type[MAX_N_KEYS_IN_WALLET_POLICY];
    char descriptor_template[MAX_TPL_LEN];
    char name[MAX_NAME_LEN];
    uint8_t version;
} g_ui_capture;

/* The handler calls this once the policy is accepted, just before computing the
 * HMAC. We capture its arguments and approve (return true); pure UI DENY flows
 * are out of scope for these vectors (see register_wallet.toml). */
bool ui_display_register_wallet_policy(
    dispatcher_context_t *context,
    const policy_map_wallet_header_t *wallet_header,
    const char *descriptor_template,
    const char (*keys_info)[MAX_N_KEYS_IN_WALLET_POLICY][MAX_POLICY_KEY_INFO_LEN + 1],
    const key_type_e (*keys_type)[MAX_N_KEYS_IN_WALLET_POLICY]) {
    (void) keys_info;

    g_ui_capture.called = true;
    g_ui_capture.n_keys = wallet_header->n_keys;
    g_ui_capture.version = wallet_header->version;
    for (size_t i = 0; i < wallet_header->n_keys && i < MAX_N_KEYS_IN_WALLET_POLICY; i++) {
        g_ui_capture.keys_type[i] = (*keys_type)[i];
    }
    snprintf(g_ui_capture.name, sizeof(g_ui_capture.name), "%s", wallet_header->name);
    snprintf(g_ui_capture.descriptor_template,
             sizeof(g_ui_capture.descriptor_template),
             "%s",
             descriptor_template);

    (void) context;
    return true;
}

/* Map a key-type name from the vectors file to its key_type_e. */
static key_type_e key_type_from_name(const char *name) {
    if (strcmp(name, "internal") == 0) return PUBKEY_TYPE_INTERNAL;
    if (strcmp(name, "external") == 0) return PUBKEY_TYPE_EXTERNAL;
    if (strcmp(name, "unspendable") == 0) return PUBKEY_TYPE_UNSPENDABLE;
    fprintf(stderr, "unknown key type: %s\n", name);
    abort();
}

/* ===========================================================================
 *  Helpers
 * =========================================================================== */

/* Decode exactly 64 lowercase/uppercase hex chars into 32 bytes. Aborts on a
 * bad length or a non-hex character (runs before any test, so abort() is the
 * right failure mode — there is no setjmp buffer to unwind to). */
static void decode_hash_hex(const char *field, const char *hex, uint8_t out[32]) {
    if (strlen(hex) != HASH_HEX_LEN) {
        fprintf(stderr, "%s: expected %d hex chars, got %zu\n", field, HASH_HEX_LEN, strlen(hex));
        abort();
    }
    for (size_t i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            fprintf(stderr, "%s: invalid hex\n", field);
            abort();
        }
        out[i] = (uint8_t) byte;
    }
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
 *  TOML loader. Copies the relevant fields out of the parsed document into
 *  g_cases, so the document lifetime doesn't need to outlive parsing.
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
        copy_required_string(tc_node,
                             "descriptor_template",
                             cur->descriptor_template,
                             sizeof(cur->descriptor_template));

        /* wallet_name defaults to "" (empty). */
        if (!copy_optional_string(tc_node,
                                  "wallet_name",
                                  cur->wallet_name,
                                  sizeof(cur->wallet_name))) {
            cur->wallet_name[0] = '\0';
        }

        char hex[HASH_HEX_LEN + 1];
        cur->has_wallet_id = copy_optional_string(tc_node, "expected_wallet_id", hex, sizeof(hex));
        if (cur->has_wallet_id) {
            decode_hash_hex("expected_wallet_id", hex, cur->expected_wallet_id);
        }
        cur->has_wallet_hmac =
            copy_optional_string(tc_node, "expected_wallet_hmac", hex, sizeof(hex));
        if (cur->has_wallet_hmac) {
            decode_hash_hex("expected_wallet_hmac", hex, cur->expected_wallet_hmac);
        }

        cur->has_error = copy_optional_string(tc_node, "error", cur->error, sizeof(cur->error));

        if (cur->has_error == cur->has_wallet_id) {
            fprintf(stderr,
                    "%s: must have exactly one of `error` or `expected_wallet_id`\n",
                    cur->name);
            abort();
        }

        toml_datum_t keys = toml_get(tc_node, "keys_info");
        if (keys.type != TOML_ARRAY) {
            fprintf(stderr, "%s: keys_info must be an array\n", cur->name);
            abort();
        }
        if (keys.u.arr.size <= 0 || (size_t) keys.u.arr.size > MAX_KEYS_PER_CASE) {
            fprintf(stderr,
                    "%s: keys_info has %d entries (must be 1..%d)\n",
                    cur->name,
                    keys.u.arr.size,
                    MAX_KEYS_PER_CASE);
            abort();
        }
        cur->n_keys = (size_t) keys.u.arr.size;

        for (size_t k = 0; k < cur->n_keys; k++) {
            toml_datum_t key_node = keys.u.arr.elem[k];
            if (key_node.type != TOML_STRING) {
                fprintf(stderr, "%s: keys_info[%zu] is not a string\n", cur->name, k);
                abort();
            }
            if ((size_t) key_node.u.str.len >= MAX_KEY_INFO_LEN) {
                fprintf(stderr,
                        "%s: keys_info[%zu] too long (%d >= %d)\n",
                        cur->name,
                        k,
                        key_node.u.str.len,
                        MAX_KEY_INFO_LEN);
                abort();
            }
            memcpy(cur->keys_info[k], key_node.u.str.ptr, (size_t) key_node.u.str.len);
            cur->keys_info[k][key_node.u.str.len] = '\0';
        }

        /* Optional per-key classification (one entry per key, @0,@1,... order). */
        toml_datum_t kt = toml_get(tc_node, "expected_key_types");
        cur->has_key_types = (kt.type != TOML_UNKNOWN);
        if (cur->has_key_types) {
            if (kt.type != TOML_ARRAY || (size_t) kt.u.arr.size != cur->n_keys) {
                fprintf(stderr,
                        "%s: expected_key_types must be an array of length n_keys (%zu)\n",
                        cur->name,
                        cur->n_keys);
                abort();
            }
            cur->n_key_types = cur->n_keys;
            for (size_t k = 0; k < cur->n_keys; k++) {
                toml_datum_t e = kt.u.arr.elem[k];
                if (e.type != TOML_STRING) {
                    fprintf(stderr, "%s: expected_key_types[%zu] is not a string\n", cur->name, k);
                    abort();
                }
                cur->key_types[k] = key_type_from_name(e.u.str.ptr);
            }
        }
    }

    toml_free(r);
}

/* ===========================================================================
 *  Test driver
 * =========================================================================== */

/* Per-case cmocka state: pairs a heap-allocated mock dispatcher with the
 * testcase. Mirrors test_get_wallet_address.c. */
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

/* Serialize the register_wallet command data into `out`, returning its length.
 * Layout matches command_builder.register_wallet:
 *   varint(len(wallet_bytes)) || wallet_bytes
 * with wallet_bytes =
 *   version(1) || name_len(1) || name || varint(template_len) ||
 *   sha256(template) || varint(n_keys) || keys_merkle_root(32). */
static size_t serialize_request(const testcase_t *tc,
                                const uint8_t keys_merkle_root[32],
                                uint8_t *out,
                                size_t out_size) {
    uint8_t wb[1 + 1 + MAX_NAME_LEN + 5 + 32 + 5 + 32];
    size_t wblen = 0;

    size_t name_len = strlen(tc->wallet_name);
    size_t template_len = strlen(tc->descriptor_template);

    wb[wblen++] = WALLET_POLICY_VERSION_V2;
    wb[wblen++] = (uint8_t) name_len;
    memcpy(wb + wblen, tc->wallet_name, name_len);
    wblen += name_len;

    wblen += (size_t) varint_write(wb + wblen, 0, template_len);

    cx_hash_sha256((const uint8_t *) tc->descriptor_template, template_len, wb + wblen, 32);
    wblen += 32;

    wblen += (size_t) varint_write(wb + wblen, 0, tc->n_keys);

    memcpy(wb + wblen, keys_merkle_root, 32);
    wblen += 32;

    size_t clen = 0;
    clen += (size_t) varint_write(out, 0, wblen);
    assert_true(clen + wblen <= out_size);
    memcpy(out + clen, wb, wblen);
    clen += wblen;
    return clen;
}

static void test_one_case(void **state) {
    case_state_t *cs = *state;
    mock_dispatcher_t *mock = cs->mock_state;
    const testcase_t *tc = cs->tc;

    /* The descriptor template is fetched by the device via call_get_preimage. */
    mock_dispatcher_add_preimage(mock,
                                 (const uint8_t *) tc->descriptor_template,
                                 strlen(tc->descriptor_template));

    /* Register the keys-info list; the last tree's root is the keys Merkle root
     * the device would have received in the wallet header. */
    const uint8_t *key_ptrs[MAX_KEYS_PER_CASE];
    size_t key_lens[MAX_KEYS_PER_CASE];
    for (size_t i = 0; i < tc->n_keys; i++) {
        key_ptrs[i] = (const uint8_t *) tc->keys_info[i];
        key_lens[i] = strlen(tc->keys_info[i]);
    }
    mock_dispatcher_add_list(mock, key_ptrs, key_lens, tc->n_keys);
    uint8_t keys_merkle_root[32];
    memcpy(keys_merkle_root, mock->trees[mock->n_trees - 1].root, 32);

    uint8_t cdata[MAX_TPL_LEN + 128];
    size_t cdata_len = serialize_request(tc, keys_merkle_root, cdata, sizeof(cdata));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    dc->read_buffer = buffer_create(cdata, cdata_len);

    handler_register_wallet(dc, 0);

    if (tc->has_error) {
        assert_int_equal(mock->last_sw, error_name_to_sw(tc->error));
        /* A deterministic rejection must return before the UI confirmation. */
        assert_false(g_ui_capture.called);
        return;
    }

    /* Success: response is wallet_id(32) || hmac(32), accumulated in request_buf. */
    assert_int_equal(mock->last_sw, SW_OK);
    assert_int_equal(mock->request_len, 64);
    assert_memory_equal(mock->request_buf, tc->expected_wallet_id, 32);
    if (tc->has_wallet_hmac) {
        assert_memory_equal(mock->request_buf + 32, tc->expected_wallet_hmac, 32);
    }

    /* The UI confirmation must have been shown, with the parsed header intact. */
    assert_true(g_ui_capture.called);
    assert_int_equal(g_ui_capture.version, WALLET_POLICY_VERSION_V2);
    assert_int_equal(g_ui_capture.n_keys, tc->n_keys);
    assert_string_equal(g_ui_capture.descriptor_template, tc->descriptor_template);
    assert_string_equal(g_ui_capture.name, tc->wallet_name);

    /* When pinned, verify the per-key classification (NUMS / internal-key
     * re-derivation / fingerprint-collision guard) the handler computed. */
    if (tc->has_key_types) {
        for (size_t i = 0; i < tc->n_key_types; i++) {
            assert_int_equal(g_ui_capture.keys_type[i], tc->key_types[i]);
        }
    }
}

/* Hand-written framing case: an empty command buffer makes the leading
 * buffer_read_varint fail, which the handler reports as SW_WRONG_DATA_LENGTH.
 * This branch can't be expressed via the portable wallet-policy schema. */
static void test_wrong_data_length(void **state) {
    mock_dispatcher_t *mock = *state;
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    dc->read_buffer = buffer_create((void *) "", 0);
    handler_register_wallet(dc, 0);

    assert_int_equal(mock->last_sw, SW_WRONG_DATA_LENGTH);
}

int main(void) {
    parse_vectors(TEST_VECTORS_PATH);

    /* VLA so that the cmocka_run_group_tests_name macro's sizeof-based count
     * computes correctly; the +1 is the hand-written framing case. */
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
        .name = "wrong_data_length",
        .test_func = test_wrong_data_length,
        .setup_func = mock_dispatcher_setup,
        .teardown_func = mock_dispatcher_teardown,
        .initial_state = NULL,
    };

    int rc = cmocka_run_group_tests_name("register_wallet", tests, NULL, NULL);
    free(g_cases);
    return rc;
}
