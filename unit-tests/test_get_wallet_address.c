/**
 * Unit tests for get_wallet_script + get_script_address.
 *
 * Test cases are loaded from TEST_VECTORS_PATH (a TOML file) at runtime;
 * see the file's header comment for the schema. For each vector we:
 *   1. Register the keys-info list with the mock dispatcher (this also
 *      builds the keys Merkle tree and gives us its root).
 *   2. Parse the descriptor template into the policy AST.
 *   3. Call get_wallet_script to compute the scriptPubKey.
 *   4. Call get_script_address on the resulting script.
 *   5. Compare with the expected address string.
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

#include "common/wallet.h"
#include "handler/lib/policy.h"
#include "common/script.h"
#include "constants.h"

#ifndef TEST_VECTORS_PATH
#error "TEST_VECTORS_PATH must be defined to point at the vectors file"
#endif

#define MAX_KEYS_PER_CASE 8
#define MAX_KEY_INFO_LEN  (MAX_POLICY_KEY_INFO_LEN + 1)
#define MAX_TPL_LEN       (MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 + 1)
#define MAX_ADDR_LEN      (MAX_ADDRESS_LENGTH_STR + 1)
#define MAX_NAME_LEN      64

typedef struct {
    char name[MAX_NAME_LEN];
    char descriptor_template[MAX_TPL_LEN];
    char keys_info[MAX_KEYS_PER_CASE][MAX_KEY_INFO_LEN];
    size_t n_keys;
    unsigned int change;
    unsigned int address_index;
    char expected_address[MAX_ADDR_LEN];
} testcase_t;

static testcase_t *g_cases = NULL;
static size_t g_n_cases = 0;

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
        copy_required_string(tc_node,
                             "expected_address",
                             cur->expected_address,
                             sizeof(cur->expected_address));
        cur->change = copy_required_uint(tc_node, "change");
        cur->address_index = copy_required_uint(tc_node, "address_index");

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
    }

    toml_free(r);
}

/* ===========================================================================
 *  Test driver
 * =========================================================================== */

/* Per-case cmocka state: pairs a heap-allocated mock dispatcher with the
 * testcase we're running. The mock pointer is owned by case_setup/teardown,
 * which wrap mock_dispatcher_setup/teardown so the global active-mock
 * pointer is cleared after each case. */
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

/**
 * Runs a single test case: parses the descriptor template, registers the
 * keys with the mock dispatcher, derives the script and the address, then
 * compares the produced address to the expected one.
 */
static void test_one_case(void **state) {
    case_state_t *cs = *state;
    mock_dispatcher_t *mock = cs->mock_state;
    const testcase_t *tc = cs->tc;

    const uint8_t *key_ptrs[MAX_KEYS_PER_CASE];
    size_t key_lens[MAX_KEYS_PER_CASE];
    for (size_t i = 0; i < tc->n_keys; i++) {
        key_ptrs[i] = (const uint8_t *) tc->keys_info[i];
        key_lens[i] = strlen(tc->keys_info[i]);
    }
    mock_dispatcher_add_list(mock, key_ptrs, key_lens, tc->n_keys);

    uint8_t keys_merkle_root[32];
    memcpy(keys_merkle_root, mock->trees[mock->n_trees - 1].root, 32);

    uint8_t policy_buf[MAX_WALLET_POLICY_BYTES];
    buffer_t tpl_buf =
        buffer_create((void *) tc->descriptor_template, strlen(tc->descriptor_template));
    int parse_res = parse_descriptor_template(&tpl_buf,
                                              policy_buf,
                                              sizeof(policy_buf),
                                              WALLET_POLICY_VERSION_V2);
    assert_true(parse_res >= 0);

    wallet_derivation_info_t wdi = {
        .wallet_version = WALLET_POLICY_VERSION_V2,
        .keys_merkle_root = keys_merkle_root,
        .n_keys = (uint32_t) tc->n_keys,
        .change = tc->change != 0,
        .address_index = tc->address_index,
        .sign_psbt_cache = NULL,
    };

    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int script_len = get_wallet_script(mock_dispatcher_get_dc(mock),
                                       (const policy_node_t *) policy_buf,
                                       &wdi,
                                       script);
    assert_true(script_len > 0);

    char address[MAX_ADDR_LEN];
    int addr_len = get_script_address(script, (size_t) script_len, address, sizeof(address));
    assert_true(addr_len > 0);

    assert_string_equal(address, tc->expected_address);
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

    int rc = cmocka_run_group_tests_name("get_wallet_address", tests, NULL, NULL);
    free(g_cases);
    return rc;
}
