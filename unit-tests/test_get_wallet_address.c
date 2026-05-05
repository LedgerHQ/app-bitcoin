/**
 * Unit tests for get_wallet_script and get_script_address.
 *
 * Tests derive the script for a wallet policy at a given change/address_index,
 * then compute the address, and compare against expected addresses from the
 * Python e2e tests (test_get_wallet_address.py).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

/* SDK mock stubs */
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}
#undef PIC
#define PIC(x) (x)

#include "mock_dispatcher.h"
#include "cx_hash_mock.h"
#include "sha-256.h"

#include "handler/lib/policy.h"

/* Undefine SKIP_FOR_CMOCKA to get the full declarations from script.h */
#undef SKIP_FOR_CMOCKA
#include "common/script.h"
#define SKIP_FOR_CMOCKA

#include "common/wallet.h"
#include "constants.h"

/* musig stub: not needed for singlesig tests */
int musig_key_agg(const uint8_t pubkeys[][33], size_t n_keys, void *ctx) {
    (void) pubkeys;
    (void) n_keys;
    (void) ctx;
    return -1;
}

/* ---------- Test data ---------- */

typedef struct {
    const char *descriptor_template;
    const char *key_info;
    uint8_t change;
    uint32_t address_index;
    const char *expected_address;
} test_case_t;

static const test_case_t test_cases[] = {
    // P2PKH (legacy)
    {
        .descriptor_template = "pkh(@0/**)",
        .key_info =
            "[f5acc2fd/44'/1'/0']"
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9"
            "eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        .change = 0,
        .address_index = 0,
        .expected_address = "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm",
    },
    {
        .descriptor_template = "pkh(@0/**)",
        .key_info =
            "[f5acc2fd/44'/1'/0']"
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9"
            "eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        .change = 1,
        .address_index = 15,
        .expected_address = "myFCUBRCKFjV7292HnZtiHqMzzHrApobpT",
    },
    // P2WPKH (native segwit)
    {
        .descriptor_template = "wpkh(@0/**)",
        .key_info =
            "[f5acc2fd/84'/1'/0']"
            "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8"
            "EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        .change = 0,
        .address_index = 0,
        .expected_address = "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk",
    },
    {
        .descriptor_template = "wpkh(@0/**)",
        .key_info =
            "[f5acc2fd/84'/1'/0']"
            "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8"
            "EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        .change = 1,
        .address_index = 15,
        .expected_address = "tb1qlrvzyx8jcjfj2xuy69du9trtxnsvjuped7e289",
    },
    // P2SH-P2WPKH (wrapped segwit)
    {
        .descriptor_template = "sh(wpkh(@0/**))",
        .key_info =
            "[f5acc2fd/49'/1'/0']"
            "tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8C"
            "dRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
        .change = 0,
        .address_index = 0,
        .expected_address = "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw",
    },
    {
        .descriptor_template = "sh(wpkh(@0/**))",
        .key_info =
            "[f5acc2fd/49'/1'/0']"
            "tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8C"
            "dRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
        .change = 1,
        .address_index = 15,
        .expected_address = "2NAbM4FSeBQG4o85kbXw2YNfKypcnEZS9MR",
    },
    // P2TR (taproot, key-path only)
    {
        .descriptor_template = "tr(@0/**)",
        .key_info =
            "[f5acc2fd/86'/1'/0']"
            "tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v"
            "9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
        .change = 0,
        .address_index = 0,
        .expected_address = "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7",
    },
    {
        .descriptor_template = "tr(@0/**)",
        .key_info =
            "[f5acc2fd/86'/1'/0']"
            "tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v"
            "9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
        .change = 1,
        .address_index = 0,
        .expected_address = "tb1pmr60r5vfjmdkrwcu4a2z8h39mzs7a6wf2rfhuml6qgcp940x9cxs7t9pdy",
    },
};

#define N_TEST_CASES (sizeof(test_cases) / sizeof(test_cases[0]))

/* ---------- Helper: build serialized wallet policy ---------- */

/**
 * Builds a V2 serialized wallet policy from a descriptor template and a single key.
 * Returns the length of the serialized policy written to `out`.
 */
static size_t build_serialized_wallet_policy(const char *descriptor_template,
                                             const char *key_info,
                                             uint8_t *out,
                                             size_t out_size,
                                             uint8_t keys_merkle_root[32]) {
    size_t desc_len = strlen(descriptor_template);
    size_t key_len = strlen(key_info);

    /* Compute descriptor template SHA-256 */
    uint8_t desc_sha256[32];
    calc_sha_256(desc_sha256, (const uint8_t *) descriptor_template, desc_len);

    /* Compute keys Merkle root: for a single element, root = SHA256(0x00 || element) */
    uint8_t prefixed[512];
    prefixed[0] = 0x00;
    memcpy(prefixed + 1, key_info, key_len);
    calc_sha_256(keys_merkle_root, prefixed, 1 + key_len);

    /* Build serialization:
     * version(1) | name_len(1) | varint(desc_len) | desc_sha256(32) | varint(n_keys=1) | keys_root(32)
     */
    size_t pos = 0;
    assert(out_size >= 68);

    out[pos++] = 0x02;  // version V2
    out[pos++] = 0x00;  // name_len = 0

    /* varint for descriptor_template_len */
    if (desc_len < 253) {
        out[pos++] = (uint8_t) desc_len;
    } else {
        out[pos++] = 0xFD;
        out[pos++] = (uint8_t) (desc_len & 0xFF);
        out[pos++] = (uint8_t) ((desc_len >> 8) & 0xFF);
    }

    /* descriptor template SHA-256 */
    memcpy(out + pos, desc_sha256, 32);
    pos += 32;

    /* varint for n_keys = 1 */
    out[pos++] = 0x01;

    /* keys Merkle root */
    memcpy(out + pos, keys_merkle_root, 32);
    pos += 32;

    return pos;
}

/* ---------- Helper: register preimages and keys with mock dispatcher ---------- */

static void setup_mock_for_test_case(mock_dispatcher_t *mock, const test_case_t *tc) {
    mock_dispatcher_init(mock);
    mock_dispatcher_reset_hash_pool();

    /* 1. Build serialized wallet policy and register as preimage */
    uint8_t serialized[256];
    uint8_t keys_merkle_root[32];
    size_t serialized_len = build_serialized_wallet_policy(tc->descriptor_template,
                                                           tc->key_info,
                                                           serialized,
                                                           sizeof(serialized),
                                                           keys_merkle_root);
    mock_dispatcher_add_preimage(mock, serialized, serialized_len);

    /* 2. Register the descriptor template as a preimage (for V2 policy parsing) */
    size_t desc_len = strlen(tc->descriptor_template);
    mock_dispatcher_add_preimage(mock,
                                 (const uint8_t *) tc->descriptor_template,
                                 desc_len);

    /* 3. Register the key_info in the keys Merkle tree.
     * For get_merkle_leaf_element, we need to register a list containing the single key.
     */
    const uint8_t *keys_list[] = {(const uint8_t *) tc->key_info};
    size_t key_lens[] = {strlen(tc->key_info)};
    mock_dispatcher_add_list(mock, keys_list, key_lens, 1);
}

/* ---------- The actual test function ---------- */

static void test_get_wallet_address(void **state) {
    (void) state;

    for (size_t i = 0; i < N_TEST_CASES; i++) {
        const test_case_t *tc = &test_cases[i];

        printf("  Test case %zu: %s change=%d index=%u -> %s\n",
               i,
               tc->descriptor_template,
               tc->change,
               tc->address_index,
               tc->expected_address);

        static mock_dispatcher_t mock;
        setup_mock_for_test_case(&mock, tc);

        dispatcher_context_t *dc = mock_dispatcher_get_dc(&mock);

        /* Step 1: Parse the wallet policy */
        uint8_t serialized[256];
        uint8_t keys_merkle_root[32];
        size_t serialized_len = build_serialized_wallet_policy(tc->descriptor_template,
                                                               tc->key_info,
                                                               serialized,
                                                               sizeof(serialized),
                                                               keys_merkle_root);

        buffer_t buf = buffer_create(serialized, serialized_len);

        policy_map_wallet_header_t wallet_header;
        uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];

        union {
            uint8_t bytes[MAX_WALLET_POLICY_BYTES];
            policy_node_t parsed;
        } wallet_policy_map;

        int parse_result = read_and_parse_wallet_policy(dc,
                                                        &buf,
                                                        &wallet_header,
                                                        policy_map_descriptor,
                                                        wallet_policy_map.bytes,
                                                        sizeof(wallet_policy_map.bytes));
        assert_true(parse_result >= 0);

        /* Step 2: Derive the script using get_wallet_script */
        uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        wallet_derivation_info_t wdi = {
            .wallet_version = wallet_header.version,
            .keys_merkle_root = wallet_header.keys_info_merkle_root,
            .n_keys = wallet_header.n_keys,
            .change = tc->change,
            .address_index = tc->address_index,
            .sign_psbt_cache = NULL,
        };

        int script_len = get_wallet_script(dc, &wallet_policy_map.parsed, &wdi, script);
        assert_true(script_len > 0);

        /* Step 3: Compute the address from the script */
        char address[MAX_ADDRESS_LENGTH_STR + 1];
        int addr_len = get_script_address(script, script_len, address, sizeof(address));
        assert_true(addr_len > 0);

        /* Step 4: Compare with expected address */
        assert_string_equal(address, tc->expected_address);
    }
}

/* ---------- Main ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_wallet_address),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
