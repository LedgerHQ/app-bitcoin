/**
 * Unit tests for the MuSig2 implementation in src/musig/musig.c.
 *
 * Test vectors are taken from BIP-327:
 *   https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 *
 * Only the vectors applicable to the subset of BIP-327 implemented by the app are used:
 * - key_sort_vectors.json    -> compare_plain_pk
 * - key_agg_vectors.json     -> musig_key_agg (tweaking is tested via musig_sign)
 * - nonce_agg_vectors.json   -> musig_nonce_agg
 * - sign_verify_vectors.json -> musig_sign (signing cases only; there is no verification)
 * - tweak_vectors.json       -> musig_sign with tweaks
 *
 * musig_nonce_gen only supports a subset of the optional arguments of BIP-327's NonceGen (sk, msg
 * and extra_in are always absent, while aggpk is always present), which none of the official
 * nonce_gen_vectors.json cases match; see the comment on the nonce_gen tests below.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "speculos_bridge.h"
#include "musig.h"
#include "test_assertions.h"

/* Decodes the hex string `hex` into `out`, which has capacity `out_cap`; returns the decoded
 * length. Fails the test on any malformed input. */
static size_t unhex(const char *hex, uint8_t *out, size_t out_cap) {
    size_t hex_len = strlen(hex);
    assert_int_equal(hex_len % 2, 0);
    assert_true(hex_len / 2 <= out_cap);
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        assert_int_equal(sscanf(hex + 2 * i, "%2x", &byte), 1);
        out[i] = (uint8_t) byte;
    }
    return hex_len / 2;
}

/* Like unhex, but also fails the test unless the decoded length is exactly `len`. */
static void unhex_exact(const char *hex, uint8_t *out, size_t len) {
    assert_int_equal(unhex(hex, out, len), len);
}

#define MAX_KEYS 4

/* ---------------------------------------------------------------- */
/* key_sort_vectors.json                                            */
/* ---------------------------------------------------------------- */

// clang-format off
static const char *const key_sort_pubkeys[] = {
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
};

static const char *const key_sort_sorted_pubkeys[] = {
    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
};
// clang-format on

#define N_KEY_SORT (sizeof(key_sort_pubkeys) / sizeof(key_sort_pubkeys[0]))

static void test_key_sort(void **state) {
    (void) state;

    plain_pk_t pubkeys[N_KEY_SORT];
    for (size_t i = 0; i < N_KEY_SORT; i++) {
        unhex_exact(key_sort_pubkeys[i], pubkeys[i], sizeof(plain_pk_t));
    }

    qsort(pubkeys, N_KEY_SORT, sizeof(plain_pk_t), compare_plain_pk);

    for (size_t i = 0; i < N_KEY_SORT; i++) {
        plain_pk_t expected;
        unhex_exact(key_sort_sorted_pubkeys[i], expected, sizeof(expected));
        assert_memory_equal(pubkeys[i], expected, sizeof(plain_pk_t));
    }
}

/* ---------------------------------------------------------------- */
/* key_agg_vectors.json                                             */
/* ---------------------------------------------------------------- */

// clang-format off
static const char *const key_agg_pubkeys[] = {
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
    "020000000000000000000000000000000000000000000000000000000000000005",
    "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
};

static const char *const key_agg_tweaks[] = {
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B",
};
// clang-format on

typedef struct {
    size_t n_keys;
    size_t key_indices[MAX_KEYS];
    const char *expected;  // x-only aggregate key
} key_agg_valid_case_t;

static const key_agg_valid_case_t key_agg_valid_cases[] = {
    {3, {0, 1, 2}, "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"},
    {3, {2, 1, 0}, "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"},
    {3, {0, 0, 0}, "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"},
    {4, {0, 0, 1, 1}, "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"},
};

static void load_pubkeys(const char *const table[],
                         const size_t *indices,
                         size_t n_keys,
                         plain_pk_t out[]) {
    for (size_t i = 0; i < n_keys; i++) {
        unhex_exact(table[indices[i]], out[i], sizeof(plain_pk_t));
    }
}

static void test_key_agg_valid(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(key_agg_valid_cases) / sizeof(key_agg_valid_cases[0]); t++) {
        const key_agg_valid_case_t *tc = &key_agg_valid_cases[t];

        plain_pk_t pubkeys[MAX_KEYS];
        load_pubkeys(key_agg_pubkeys, tc->key_indices, tc->n_keys, pubkeys);

        musig_keyagg_context_t ctx;
        assert_int_equal(musig_key_agg((const plain_pk_t *) pubkeys, tc->n_keys, &ctx), 0);

        uint8_t expected[32];
        unhex_exact(tc->expected, expected, sizeof(expected));
        assert_int_equal(ctx.Q.prefix, 4);
        assert_memory_equal(ctx.Q.x, expected, sizeof(expected));

        // untweaked context: gacc = 1, tacc = 0
        uint8_t one[32] = {0};
        one[31] = 1;
        assert_memory_equal(ctx.gacc, one, sizeof(one));
        assert_cleared(ctx.tacc, sizeof(ctx.tacc));
    }
}

typedef struct {
    size_t n_keys;
    size_t key_indices[MAX_KEYS];
    const char *comment;
} key_agg_invalid_pubkey_case_t;

// The error cases of key_agg_vectors.json that do not involve tweaks
static const key_agg_invalid_pubkey_case_t key_agg_invalid_pubkey_cases[] = {
    {2, {0, 3}, "Invalid public key"},
    {2, {0, 4}, "Public key exceeds field size"},
    {2, {5, 0}, "First byte of public key is not 2 or 3"},
};

static void test_key_agg_invalid_pubkey(void **state) {
    (void) state;

    for (size_t t = 0;
         t < sizeof(key_agg_invalid_pubkey_cases) / sizeof(key_agg_invalid_pubkey_cases[0]);
         t++) {
        const key_agg_invalid_pubkey_case_t *tc = &key_agg_invalid_pubkey_cases[t];
        print_message("key_agg error case: %s\n", tc->comment);

        plain_pk_t pubkeys[MAX_KEYS];
        load_pubkeys(key_agg_pubkeys, tc->key_indices, tc->n_keys, pubkeys);

        musig_keyagg_context_t ctx;
        assert_int_equal(musig_key_agg((const plain_pk_t *) pubkeys, tc->n_keys, &ctx), -1);
    }
}

/* ---------------------------------------------------------------- */
/* sign_verify_vectors.json                                         */
/* ---------------------------------------------------------------- */

// clang-format off
static const char sign_sk[] =
    "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671";

static const char *const sign_pubkeys[] = {
    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
    "020000000000000000000000000000000000000000000000000000000000000007",
};

static const char *const sign_secnonces[] = {
    "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
};

static const char *const sign_aggnonces[] = {
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
};

static const char *const sign_msgs[] = {
    "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
    "",
    "2626262626262626262626262626262626262626262626262626262626262626262626262626",
};
// clang-format on

#define MAX_MSG_LEN 64
#define MAX_TWEAKS  4

/* Inputs of a single musig_sign invocation, decoded from the hex vectors. */
typedef struct {
    uint8_t sk[32];
    musig_secnonce_t secnonce;
    plain_pk_t pubkeys[MAX_KEYS];
    musig_pubnonce_t aggnonce;
    uint8_t msg[MAX_MSG_LEN];
    uint8_t tweaks[MAX_TWEAKS][32];
    uint8_t *tweak_ptrs[MAX_TWEAKS];
    bool is_xonly[MAX_TWEAKS];
    musig_session_context_t session;
} sign_inputs_t;

typedef struct {
    const char *sk;
    const char *secnonce;
    const char *const *pubkeys;  // table indexed by key_indices
    size_t n_keys;
    const size_t *key_indices;
    const char *aggnonce;
    const char *msg;
    const char *const *tweaks;  // table indexed by tweak_indices
    size_t n_tweaks;
    const size_t *tweak_indices;
    const bool *is_xonly;
} sign_inputs_hex_t;

static void load_sign_inputs(const sign_inputs_hex_t *hex, sign_inputs_t *in) {
    memset(in, 0, sizeof(*in));

    assert_true(hex->n_keys <= MAX_KEYS);
    assert_true(hex->n_tweaks <= MAX_TWEAKS);

    unhex_exact(hex->sk, in->sk, sizeof(in->sk));
    unhex_exact(hex->secnonce, (uint8_t *) &in->secnonce, sizeof(in->secnonce));
    load_pubkeys(hex->pubkeys, hex->key_indices, hex->n_keys, in->pubkeys);
    unhex_exact(hex->aggnonce, in->aggnonce.raw, sizeof(in->aggnonce.raw));
    size_t msg_len = unhex(hex->msg, in->msg, sizeof(in->msg));
    for (size_t i = 0; i < hex->n_tweaks; i++) {
        unhex_exact(hex->tweaks[hex->tweak_indices[i]], in->tweaks[i], 32);
        in->tweak_ptrs[i] = in->tweaks[i];
        in->is_xonly[i] = hex->is_xonly[i];
    }

    in->session = (musig_session_context_t) {
        .aggnonce = &in->aggnonce,
        .n_keys = hex->n_keys,
        .pubkeys = in->pubkeys,
        .n_tweaks = hex->n_tweaks,
        .tweaks = in->tweak_ptrs,
        .is_xonly = in->is_xonly,
        .msg = in->msg,
        .msg_len = msg_len,
    };
}

typedef struct {
    size_t n_keys;
    size_t key_indices[MAX_KEYS];
    size_t aggnonce_index;
    size_t msg_index;
    const char *expected;
    const char *comment;
} sign_valid_case_t;

// The secnonce is always sign_secnonces[0], which belongs to sign_pubkeys[0]. The signer_index of
// each test case in the json file is therefore the position of key 0 in key_indices.
// nonce_indices are omitted, as they are only needed for verification.
static const sign_valid_case_t sign_valid_cases[] = {
    {3, {0, 1, 2}, 0, 0, "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB", ""},
    {3, {1, 0, 2}, 0, 0, "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52", ""},
    {3, {1, 2, 0}, 0, 0, "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900", ""},
    {2,
     {0, 1},
     1,
     0,
     "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
     "Both halves of aggregate nonce correspond to point at infinity"},
    {3,
     {0, 1, 2},
     0,
     1,
     "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
     "Empty message"},
    {3,
     {0, 1, 2},
     0,
     2,
     "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
     "38-byte message"},
};

static void test_sign_valid(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(sign_valid_cases) / sizeof(sign_valid_cases[0]); t++) {
        const sign_valid_case_t *tc = &sign_valid_cases[t];
        print_message("sign valid case %zu: %s\n", t, tc->comment);

        sign_inputs_t in;
        load_sign_inputs(&(sign_inputs_hex_t) {.sk = sign_sk,
                                               .secnonce = sign_secnonces[0],
                                               .pubkeys = sign_pubkeys,
                                               .n_keys = tc->n_keys,
                                               .key_indices = tc->key_indices,
                                               .aggnonce = sign_aggnonces[tc->aggnonce_index],
                                               .msg = sign_msgs[tc->msg_index]},
                         &in);

        uint8_t psig[32];
        assert_int_equal(musig_sign(&in.secnonce, in.sk, &in.session, psig), 0);

        uint8_t expected[32];
        unhex_exact(tc->expected, expected, sizeof(expected));
        assert_memory_equal(psig, expected, sizeof(expected));

        // the secret nonce must be erased after use, in order to prevent reuse
        assert_cleared(in.secnonce.k_1, sizeof(in.secnonce.k_1));
        assert_cleared(in.secnonce.k_2, sizeof(in.secnonce.k_2));
    }
}

typedef struct {
    size_t n_keys;
    size_t key_indices[MAX_KEYS];
    size_t aggnonce_index;
    size_t msg_index;
    size_t secnonce_index;
    const char *comment;
} sign_error_case_t;

static const sign_error_case_t sign_error_cases[] = {
    // This test case is optional in BIP-327, but the app does check that the signer's pubkey is
    // included in the list of pubkeys.
    {2, {1, 2}, 0, 0, 0, "The signers pubkey is not in the list of pubkeys"},
    {3, {1, 0, 3}, 0, 0, 0, "Signer 2 provided an invalid public key"},
    {3, {1, 2, 0}, 2, 0, 0, "Aggregate nonce is invalid due wrong tag, 0x04, in the first half"},
    {3,
     {1, 2, 0},
     3,
     0,
     0,
     "Aggregate nonce is invalid because the second half does not correspond to an X coordinate"},
    {3, {1, 2, 0}, 4, 0, 0, "Aggregate nonce is invalid because second half exceeds field size"},
    {3, {0, 1, 2}, 0, 0, 1, "Secnonce is invalid which may indicate nonce reuse"},
};

static void test_sign_error(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(sign_error_cases) / sizeof(sign_error_cases[0]); t++) {
        const sign_error_case_t *tc = &sign_error_cases[t];
        print_message("sign error case %zu: %s\n", t, tc->comment);

        sign_inputs_t in;
        load_sign_inputs(&(sign_inputs_hex_t) {.sk = sign_sk,
                                               .secnonce = sign_secnonces[tc->secnonce_index],
                                               .pubkeys = sign_pubkeys,
                                               .n_keys = tc->n_keys,
                                               .key_indices = tc->key_indices,
                                               .aggnonce = sign_aggnonces[tc->aggnonce_index],
                                               .msg = sign_msgs[tc->msg_index]},
                         &in);

        uint8_t psig[32];
        assert_int_equal(musig_sign(&in.secnonce, in.sk, &in.session, psig), -1);
    }
}

// Not part of the BIP-327 test vectors: signing twice with the same secnonce must fail, since
// musig_sign erases it on the first use.
static void test_sign_secnonce_reuse(void **state) {
    (void) state;

    const size_t key_indices[] = {0, 1, 2};
    sign_inputs_t in;
    load_sign_inputs(&(sign_inputs_hex_t) {.sk = sign_sk,
                                           .secnonce = sign_secnonces[0],
                                           .pubkeys = sign_pubkeys,
                                           .n_keys = 3,
                                           .key_indices = key_indices,
                                           .aggnonce = sign_aggnonces[0],
                                           .msg = sign_msgs[0]},
                     &in);

    uint8_t psig[32];
    assert_int_equal(musig_sign(&in.secnonce, in.sk, &in.session, psig), 0);
    assert_int_equal(musig_sign(&in.secnonce, in.sk, &in.session, psig), -1);
}

/* ---------------------------------------------------------------- */
/* tweak_vectors.json                                               */
/* ---------------------------------------------------------------- */

// clang-format off
// tweak_vectors.json shares sk, secnonce and aggnonce with sign_verify_vectors.json, and its msg is
// sign_msgs[0]. Its pubkeys differ: the third one is a valid key.
static const char *const tweak_pubkeys[] = {
    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
};

static const char *const tweak_tweaks[] = {
    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
    "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
    "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
    "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
};
// clang-format on

typedef struct {
    size_t n_tweaks;
    size_t tweak_indices[MAX_TWEAKS];
    bool is_xonly[MAX_TWEAKS];
    const char *expected;  // NULL if signing is expected to fail
    const char *comment;
} tweak_case_t;

// All the test cases use key_indices [1, 2, 0] (hence signer_index 2).
static const size_t tweak_key_indices[] = {1, 2, 0};

static const tweak_case_t tweak_cases[] = {
    {1,
     {0},
     {true},
     "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91",
     "A single x-only tweak"},
    {1,
     {0},
     {false},
     "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D",
     "A single plain tweak"},
    {2,
     {0, 1},
     {false, true},
     "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408",
     "A plain tweak followed by an x-only tweak"},
    {4,
     {0, 1, 2, 3},
     {false, false, true, true},
     "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435",
     "Four tweaks: plain, plain, x-only, x-only."},
    {4,
     {0, 1, 2, 3},
     {true, false, true, false},
     "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239",
     "Four tweaks: x-only, plain, x-only, plain."},
    // error test case
    {1, {4}, {false}, NULL, "Tweak is invalid because it exceeds group size"},
};

static void test_tweak(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(tweak_cases) / sizeof(tweak_cases[0]); t++) {
        const tweak_case_t *tc = &tweak_cases[t];
        print_message("tweak case %zu: %s\n", t, tc->comment);

        sign_inputs_t in;
        load_sign_inputs(&(sign_inputs_hex_t) {.sk = sign_sk,
                                               .secnonce = sign_secnonces[0],
                                               .pubkeys = tweak_pubkeys,
                                               .n_keys = 3,
                                               .key_indices = tweak_key_indices,
                                               .aggnonce = sign_aggnonces[0],
                                               .msg = sign_msgs[0],
                                               .tweaks = tweak_tweaks,
                                               .n_tweaks = tc->n_tweaks,
                                               .tweak_indices = tc->tweak_indices,
                                               .is_xonly = tc->is_xonly},
                         &in);

        uint8_t psig[32];
        int res = musig_sign(&in.secnonce, in.sk, &in.session, psig);
        if (tc->expected == NULL) {
            assert_int_equal(res, -1);
        } else {
            assert_int_equal(res, 0);
            uint8_t expected[32];
            unhex_exact(tc->expected, expected, sizeof(expected));
            assert_memory_equal(psig, expected, sizeof(expected));
        }
    }
}

// The last error test case of key_agg_vectors.json: tweaking the aggregate key of
// key_agg_pubkeys[6] with the plain tweak key_agg_tweaks[1] results in the point at infinity.
// Key aggregation and tweaking are only exposed through musig_sign; key_agg_pubkeys[6] happens to
// be the pubkey of sign_sk, so we can check that signing succeeds without the tweak, and fails
// with it.
// (The other tweak-related error case of key_agg_vectors.json, "Tweak is out of range", is
// equivalent to the error test case of tweak_vectors.json.)
static void test_key_agg_tweak_infinity(void **state) {
    (void) state;

    const size_t key_indices[] = {6};
    const size_t tweak_indices[] = {1};
    const bool is_xonly[] = {false};

    for (size_t n_tweaks = 0; n_tweaks <= 1; n_tweaks++) {
        sign_inputs_t in;
        load_sign_inputs(&(sign_inputs_hex_t) {.sk = sign_sk,
                                               .secnonce = sign_secnonces[0],
                                               .pubkeys = key_agg_pubkeys,
                                               .n_keys = 1,
                                               .key_indices = key_indices,
                                               .aggnonce = sign_aggnonces[0],
                                               .msg = sign_msgs[0],
                                               .tweaks = key_agg_tweaks,
                                               .n_tweaks = n_tweaks,
                                               .tweak_indices = tweak_indices,
                                               .is_xonly = is_xonly},
                         &in);

        uint8_t psig[32];
        assert_int_equal(musig_sign(&in.secnonce, in.sk, &in.session, psig),
                         n_tweaks == 0 ? 0 : -1);
    }
}

/* ---------------------------------------------------------------- */
/* nonce_agg_vectors.json                                           */
/* ---------------------------------------------------------------- */

// clang-format off
static const char *const nonce_agg_pnonces[] = {
    "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
    "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
    "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
    "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
    "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
};
// clang-format on

typedef struct {
    size_t pnonce_indices[2];
    const char *expected;  // NULL for the error cases
    int error_signer;      // for the error cases, the index of the signer to blame
    const char *comment;
} nonce_agg_case_t;

static const nonce_agg_case_t nonce_agg_cases[] = {
    {{0, 1},
     "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43"
     "C0A29A9249F2F2956FA8CFEB55C8573D0262DC8",
     0,
     ""},
    {{2, 3},
     "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000"
     "000000000000000000000000000000000000000",
     0,
     "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 "
     "zero bytes"},
    // error test cases
    {{0, 4},
     NULL,
     1,
     "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half"},
    {{5, 1},
     NULL,
     0,
     "Public nonce from signer 0 is invalid because the second half does not correspond to an X "
     "coordinate"},
    {{6, 1},
     NULL,
     0,
     "Public nonce from signer 0 is invalid because second half exceeds field size"},
};

static void test_nonce_agg(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(nonce_agg_cases) / sizeof(nonce_agg_cases[0]); t++) {
        const nonce_agg_case_t *tc = &nonce_agg_cases[t];
        print_message("nonce_agg case %zu: %s\n", t, tc->comment);

        musig_pubnonce_t pubnonces[2];
        for (size_t i = 0; i < 2; i++) {
            unhex_exact(nonce_agg_pnonces[tc->pnonce_indices[i]],
                        pubnonces[i].raw,
                        sizeof(pubnonces[i].raw));
        }

        musig_pubnonce_t aggnonce;
        int res = musig_nonce_agg(pubnonces, 2, &aggnonce);
        if (tc->expected == NULL) {
            // the return value identifies the signer to blame
            assert_int_equal(res, -tc->error_signer - 1);
        } else {
            assert_int_equal(res, 0);
            musig_pubnonce_t expected;
            unhex_exact(tc->expected, expected.raw, sizeof(expected.raw));
            assert_memory_equal(aggnonce.raw, expected.raw, sizeof(expected.raw));
        }
    }
}

/* ---------------------------------------------------------------- */
/* nonce_gen                                                        */
/*                                                                  */
/* musig_nonce_gen implements NonceGen with sk, msg and extra_in    */
/* absent, and aggpk present. None of the cases in                  */
/* nonce_gen_vectors.json match this subset, so the expected       */
/* values below were computed with nonce_gen_internal from the      */
/* BIP-327 reference implementation (bip-0327/reference.py), using  */
/* rand_, pk and aggpk from the first test case of                  */
/* nonce_gen_vectors.json (for the second case, pk from the last    */
/* test case).                                                      */
/* ---------------------------------------------------------------- */

typedef struct {
    const char *rand;
    const char *pk;
    const char *aggpk;
    const char *expected_secnonce;
    const char *expected_pubnonce;
} nonce_gen_case_t;

// clang-format off
static const nonce_gen_case_t nonce_gen_cases[] = {
    {
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
        "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "F8FAEC2D34771E67C60D6BE8B7175D2B03EBDA90D7E7DBFFA443F50679442974FB0619D1F4499019723E967A93319308D490E39830D064177D1429C4C55402C9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
        "037D1331D56E0C9294E8087C013F515D9A30F553F7E3D1B27BE1A55B7B15F8B2C10312A7963FC3EA81168EE28C408CC08B82A425CEEFF1EC3B2C12B30DC9C6BE6E91",
    },
    {
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "10472D304D995EC113ED820DB89A2E9D7FF72F974C4BE7FDBA32D23A61C56BFB9022D5083CA4142579B31510585F88B8BE5A1EF5A31819B72273B665F402BAF702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02D8ED280D294894891FCF8D2B3DD357FC1705095951CB06A890B2E35F82878EF002283AA0139AB3BE6E8FDC2218D7EC8DA02FC01D8054EF481DDE1AA10D6F71F6F1",
    },
};
// clang-format on

static void test_nonce_gen(void **state) {
    (void) state;

    for (size_t t = 0; t < sizeof(nonce_gen_cases) / sizeof(nonce_gen_cases[0]); t++) {
        const nonce_gen_case_t *tc = &nonce_gen_cases[t];

        uint8_t rand[32];
        plain_pk_t pk;
        xonly_pk_t aggpk;
        unhex_exact(tc->rand, rand, sizeof(rand));
        unhex_exact(tc->pk, pk, sizeof(pk));
        unhex_exact(tc->aggpk, aggpk, sizeof(aggpk));

        musig_secnonce_t secnonce;
        musig_pubnonce_t pubnonce;
        assert_int_equal(musig_nonce_gen(rand, sizeof(rand), pk, aggpk, &secnonce, &pubnonce), 0);

        musig_secnonce_t expected_secnonce;
        musig_pubnonce_t expected_pubnonce;
        unhex_exact(tc->expected_secnonce,
                    (uint8_t *) &expected_secnonce,
                    sizeof(expected_secnonce));
        unhex_exact(tc->expected_pubnonce, expected_pubnonce.raw, sizeof(expected_pubnonce.raw));
        assert_memory_equal(&secnonce, &expected_secnonce, sizeof(secnonce));
        assert_memory_equal(pubnonce.raw, expected_pubnonce.raw, sizeof(pubnonce.raw));
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_key_sort),
        cmocka_unit_test(test_key_agg_valid),
        cmocka_unit_test(test_key_agg_invalid_pubkey),
        cmocka_unit_test(test_key_agg_tweak_infinity),
        cmocka_unit_test(test_nonce_gen),
        cmocka_unit_test(test_nonce_agg),
        cmocka_unit_test(test_sign_valid),
        cmocka_unit_test(test_sign_error),
        cmocka_unit_test(test_sign_secnonce_reuse),
        cmocka_unit_test(test_tweak),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
