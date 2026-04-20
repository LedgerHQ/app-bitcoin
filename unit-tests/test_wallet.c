#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

// missing definitions to make it compile without the SDK
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}

#define PRINTF(...) printf
#define PIC(x)      (x)

#include "common/wallet.h"

static int parse_policy(const char *descriptor_template, uint8_t *out, size_t out_size) {
    buffer_t descriptor_template_buf =
        buffer_create((void *) descriptor_template, strlen(descriptor_template));

    return parse_descriptor_template(&descriptor_template_buf,
                                     out,
                                     out_size,
                                     WALLET_POLICY_VERSION_V2);
}

// in unit tests, size_t integers are currently 8 compiled as 8 bytes; therefore, in the app
// about half of the memory would be needed
#define MAX_WALLET_POLICY_MEMORY_SIZE 512

// convenience function to compactly check common assertions on a key placeholder pointer
static void check_key_placeholder(const policy_node_key_placeholder_t *ptr,
                                  int key_index,
                                  uint32_t num_first,
                                  uint32_t num_second) {
    assert_int_equal(ptr->key_index, key_index);
    assert_int_equal(ptr->num_first, num_first);
    assert_int_equal(ptr->num_second, num_second);
}

static void test_parse_policy_map_singlesig_1(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res = parse_policy("pkh(@0/**)", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_with_key_t *node_1 = (policy_node_with_key_t *) out;

    assert_int_equal(node_1->base.type, TOKEN_PKH);
    check_key_placeholder(r_policy_node_key_placeholder(&node_1->key_placeholder), 0, 0, 1);
}

static void test_parse_policy_map_singlesig_2(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res = parse_policy("sh(wpkh(@0/**))", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) r_policy_node(&root->script);

    assert_int_equal(inner->base.type, TOKEN_WPKH);
    check_key_placeholder(r_policy_node_key_placeholder(&inner->key_placeholder), 0, 0, 1);
}

static void test_parse_policy_map_singlesig_3(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res = parse_policy("sh(wsh(pkh(@0/**)))", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) r_policy_node(&root->script);

    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) r_policy_node(&mid->script);

    assert_int_equal(inner->base.type, TOKEN_PKH);
    check_key_placeholder(r_policy_node_key_placeholder(&inner->key_placeholder), 0, 0, 1);
}

static void test_parse_policy_map_multisig_1(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res = parse_policy("sortedmulti(2,@0/**,@1/**,@2/**)", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_multisig_t *node_1 = (policy_node_multisig_t *) out;

    assert_int_equal(node_1->base.type, TOKEN_SORTEDMULTI);
    assert_int_equal(node_1->k, 2);
    assert_int_equal(node_1->n, 3);
    check_key_placeholder(&r_policy_node_key_placeholder(&node_1->key_placeholders)[0], 0, 0, 1);
    check_key_placeholder(&r_policy_node_key_placeholder(&node_1->key_placeholders)[1], 1, 0, 1);
    check_key_placeholder(&r_policy_node_key_placeholder(&node_1->key_placeholders)[2], 2, 0, 1);
}

static void test_parse_policy_map_multisig_2(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res = parse_policy("wsh(multi(3,@0/**,@1/**,@2/**,@3/**,@4/**))", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) r_policy_node(&root->script);
    assert_int_equal(inner->base.type, TOKEN_MULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) {
        check_key_placeholder(&r_policy_node_key_placeholder(&inner->key_placeholders)[i], i, 0, 1);
    }
}

static void test_parse_policy_map_multisig_3(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    int res =
        parse_policy("sh(wsh(sortedmulti(3,@0/**,@1/**,@2/**,@3/**,@4/**)))", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->base.type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) r_policy_node(&root->script);
    assert_int_equal(mid->base.type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) r_policy_node(&mid->script);
    assert_int_equal(inner->base.type, TOKEN_SORTEDMULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) {
        check_key_placeholder(&r_policy_node_key_placeholder(&inner->key_placeholders)[i], i, 0, 1);
    }
}

static void test_parse_policy_tr(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];
    int res;

    // Simple tr without a tree
    res = parse_policy("tr(@0/**)", out, sizeof(out));

    assert_true(res >= 0);
    policy_node_tr_t *root = (policy_node_tr_t *) out;

    assert_true(isnull_policy_node_tree(&root->tree));
    check_key_placeholder(r_policy_node_key_placeholder(&root->key_placeholder), 0, 0, 1);

    // Simple tr with a TREE that is a simple script
    res = parse_policy("tr(@0/**,pk(@1/**))", out, sizeof(out));

    assert_true(res >= 0);
    root = (policy_node_tr_t *) out;

    check_key_placeholder(r_policy_node_key_placeholder(&root->key_placeholder), 0, 0, 1);

    assert_int_equal(r_policy_node_tree(&root->tree)->is_leaf, true);

    policy_node_with_key_t *tapscript =
        (policy_node_with_key_t *) r_policy_node(&r_policy_node_tree(&root->tree)->script);

    assert_int_equal(tapscript->base.type, TOKEN_PK);
    check_key_placeholder(r_policy_node_key_placeholder(&tapscript->key_placeholder), 1, 0, 1);

    // Simple tr with a TREE with two tapleaves
    res = parse_policy("tr(@0/**,{pk(@1/**),pk(@2/<5;7>/*)})", out, sizeof(out));

    assert_true(res >= 0);
    root = (policy_node_tr_t *) out;

    check_key_placeholder(r_policy_node_key_placeholder(&root->key_placeholder), 0, 0, 1);

    policy_node_tree_t *taptree = r_policy_node_tree(&root->tree);

    assert_int_equal(taptree->is_leaf, false);

    policy_node_tree_t *taptree_left =
        (policy_node_tree_t *) r_policy_node_tree(&taptree->left_tree);
    assert_int_equal(taptree_left->is_leaf, true);
    policy_node_with_key_t *tapscript_left =
        (policy_node_with_key_t *) r_policy_node(&taptree_left->script);

    assert_int_equal(tapscript_left->base.type, TOKEN_PK);
    check_key_placeholder(r_policy_node_key_placeholder(&tapscript_left->key_placeholder), 1, 0, 1);

    policy_node_tree_t *taptree_right =
        (policy_node_tree_t *) r_policy_node_tree(&taptree->right_tree);
    assert_int_equal(taptree_right->is_leaf, true);
    policy_node_with_key_t *tapscript_right =
        (policy_node_with_key_t *) r_policy_node(&taptree_right->script);

    assert_int_equal(tapscript_right->base.type, TOKEN_PK);
    check_key_placeholder(r_policy_node_key_placeholder(&tapscript_right->key_placeholder),
                          2,
                          5,
                          7);
}

static void test_parse_policy_tr_multisig(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];
    int res;

    // tr with a tree with two scripts: a multi_a and a sortedmulti_a:
    res = parse_policy("tr(@0/**,{multi_a(1,@1/**,@2/**),sortedmulti_a(2,@3/**,@4/**,@5/**)})",
                       out,
                       sizeof(out));

    assert_true(res >= 0);

    policy_node_tr_t *root = (policy_node_tr_t *) out;

    assert_int_equal(r_policy_node_key_placeholder(&root->key_placeholder)->key_index, 0);
    assert_int_equal(r_policy_node_key_placeholder(&root->key_placeholder)->num_first, 0);
    assert_int_equal(r_policy_node_key_placeholder(&root->key_placeholder)->num_second, 1);

    policy_node_tree_t *taptree = r_policy_node_tree(&root->tree);

    assert_int_equal(taptree->is_leaf, false);

    policy_node_tree_t *taptree_left =
        (policy_node_tree_t *) r_policy_node_tree(&taptree->left_tree);
    assert_int_equal(taptree_left->is_leaf, true);
    policy_node_multisig_t *tapscript_left =
        (policy_node_multisig_t *) r_policy_node(&taptree_left->script);

    assert_int_equal(tapscript_left->base.type, TOKEN_MULTI_A);
    assert_int_equal(tapscript_left->k, 1);
    assert_int_equal(tapscript_left->n, 2);
    check_key_placeholder(&r_policy_node_key_placeholder(&tapscript_left->key_placeholders)[0],
                          1,
                          0,
                          1);
    check_key_placeholder(&r_policy_node_key_placeholder(&tapscript_left->key_placeholders)[1],
                          2,
                          0,
                          1);

    policy_node_tree_t *taptree_right =
        (policy_node_tree_t *) r_policy_node_tree(&taptree->right_tree);
    assert_int_equal(taptree_right->is_leaf, true);
    policy_node_multisig_t *tapscript_right =
        (policy_node_multisig_t *) r_policy_node(&taptree_right->script);

    assert_int_equal(tapscript_right->base.type, TOKEN_SORTEDMULTI_A);
    assert_int_equal(tapscript_right->k, 2);
    assert_int_equal(tapscript_right->n, 3);
    check_key_placeholder(&r_policy_node_key_placeholder(&tapscript_right->key_placeholders)[0],
                          3,
                          0,
                          1);
    check_key_placeholder(&r_policy_node_key_placeholder(&tapscript_right->key_placeholders)[1],
                          4,
                          0,
                          1);
    check_key_placeholder(&r_policy_node_key_placeholder(&tapscript_right->key_placeholders)[2],
                          5,
                          0,
                          1);
}

static void test_get_policy_segwit_version(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];
    policy_node_t *policy = (policy_node_t *) out;

    // legacy policies (returning -1)
    parse_policy("pkh(@0/**)", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == -1);

    parse_policy("sh(multi(2,@0/**,@1/**))", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == -1);

    // segwit v0 policies
    parse_policy("wpkh(@0/**)", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 0);
    parse_policy("wsh(multi(2,@0/**,@1/**))", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 0);
    parse_policy("sh(wpkh(@0/**))", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 0);
    parse_policy("sh(wsh(multi(2,@0/**,@1/**)))", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 0);

    // segwit v1 policies
    parse_policy("tr(@0/**)", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 1);
    parse_policy("tr(@0/**,{pk(@1/**,multi(1,@2/**,@3/**)})", out, sizeof(out));
    assert(get_policy_segwit_version(policy) == 1);
}

// Regression test: parse_unsigned_decimal must reject values that overflow uint32_t.
// 5368709120 == 10 * 0x20000000 == 0x1_4000_0000 which does not fit in 32 bits;
// the old overflow check silently truncated it to 0x40000000, failing to detect
// the overflow.
static void test_parse_unsigned_decimal_overflow(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];
    assert_true(0 > parse_policy("wsh(older(5368709120))", out, sizeof(out)));
}

static void test_failures(void **state) {
    (void) state;

    uint8_t out[MAX_WALLET_POLICY_MEMORY_SIZE];

    // excess byte not allowed
    assert_true(0 > parse_policy("pkh(@0/**) ", out, sizeof(out)));

    // missing closing parenthesis
    assert_true(0 > parse_policy("pkh(@0/**", out, sizeof(out)));

    // unknown token
    assert_true(0 > parse_policy("yolo(@0/**)", out, sizeof(out)));
    assert_true(0 > parse_policy("Pkh(@0/**)", out, sizeof(out)));  // case-sensitive

    // missing or invalid key identifier
    assert_true(0 > parse_policy("pkh()", out, sizeof(out)));
    assert_true(0 > parse_policy("pkh(@)", out, sizeof(out)));
    assert_true(0 > parse_policy("pkh(0)", out, sizeof(out)));

    // sh not top-level
    assert_true(0 > parse_policy("sh(sh(pkh(@0/**)))", out, sizeof(out)));

    // wsh can only be inside sh
    assert_true(0 > parse_policy("wsh(wsh(pkh(@0/**)))", out, sizeof(out)));

    // wpkh can only be inside sh
    assert_true(0 > parse_policy("wsh(wpkh(@0/**)))", out, sizeof(out)));

    // multi with invalid threshold
    assert_true(0 > parse_policy("multi(6,@0/**,@1/**,@2/**,@3/**,@4/**)",
                                 out,
                                 sizeof(out)));  // threshold larger than n
    assert_true(0 > parse_policy("multi(0,@0/**,@1/**,@2/**,@3/**,@4/**)", out, sizeof(out)));
    // missing threshold or keys in multisig
    assert_true(0 > parse_policy("multi(@0/**,@1/**,@2/**,@3/**,@4/**)", out, sizeof(out)));
    assert_true(0 > parse_policy("multi(1)", out, sizeof(out)));
    assert_true(0 > parse_policy("multi(1,)", out, sizeof(out)));

    // invalid k in thresh (0, or too large)
    assert_true(0 >
                parse_policy("wsh(thresh(0,pk(@0/**),s:pk(@1/**),s:pk(@2/**)))", out, sizeof(out)));
    assert_true(0 >
                parse_policy("wsh(thresh(4,pk(@0/**),s:pk(@1/**),s:pk(@2/**)))", out, sizeof(out)));

    // syntactically invalid tr descriptors
    assert_true(0 > parse_policy("tr(,pk(@0))", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(pk(@0))", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(pk(@0),@1/**)", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,)", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,{})", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,@1/**)", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,{pk(@1)})", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,{pk(@1),})", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,{,pk(@1)})", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,{@1/**,pk(@2)})", out, sizeof(out)));

    // invalid tokens within tr scripts
    assert_true(0 > parse_policy("tr(@0/**,multi(2,@1,@2))", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,sortedmulti(2,@1,@2))", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,sh(pk(@0/**)))", out, sizeof(out)));
    assert_true(0 > parse_policy("tr(@0/**,wsh(pk(@0/**)))", out, sizeof(out)));
}

enum TestMode {
    TESTMODE_INVALID = 0,
    TESTMODE_VALID = 1,
    TESTMODE_NONMAL = 2,
    TESTMODE_NEEDSIG = 4,
    TESTMODE_TIMELOCKMIX = 8,  // ignored in our tests
    //! Invalid only under P2WSH context
    TESTMODE_P2WSH_INVALID = 16,
    //! Invalid only under Tapscript context
    TESTMODE_TAPSCRIPT_INVALID = 32
};

static void Test(const char *ms, const char *hexscript, int mode, int opslimit, int stacklimit) {
    char descriptor_wsh[1024];
    char descriptor_tr[1024];

    if (strlen(ms) + sizeof("wsh(") + sizeof(")") > sizeof(descriptor_wsh)) {
        assert(false);
    }

    if (strlen(ms) + sizeof("tr(@0/<100;101>/*,") + sizeof(")") > sizeof(descriptor_tr)) {
        assert(false);
    }

    // Wrap the miniscript inside "wsh"
    strcpy(descriptor_wsh, "wsh(");
    strcat(descriptor_wsh, ms);
    strcat(descriptor_wsh, ")");

    // Wrap the miniscript inside a "tr" script.
    // We make sure to use a key placeholder with derivations that
    // are not used elsewhere in the descriptor template.
    strcpy(descriptor_tr, "tr(@0/<100;101>/*,");
    strcat(descriptor_tr, ms);
    strcat(descriptor_tr, ")");
    uint8_t out_wsh[MAX_WALLET_POLICY_MEMORY_SIZE];
    uint8_t out_tr[MAX_WALLET_POLICY_MEMORY_SIZE];

    uint8_t *out;

    int res = 0;
    if ((mode & TESTMODE_P2WSH_INVALID) != 0 && (mode & TESTMODE_TAPSCRIPT_INVALID) != 0) {
        assert(false);  // at most one of TESTMODE_P2WSH_INVALID and TESTMODE_TAPSCRIPT_INVALID
    }

    buffer_t descriptor_template_wsh_buf =
        buffer_create((void *) descriptor_wsh, strlen(descriptor_wsh));

    int res_wsh = parse_descriptor_template(&descriptor_template_wsh_buf,
                                            out_wsh,
                                            sizeof(out_wsh),
                                            WALLET_POLICY_VERSION_V2);

    buffer_t descriptor_template_tr_buf =
        buffer_create((void *) descriptor_tr, strlen(descriptor_tr));

    int res_tr = parse_descriptor_template(&descriptor_template_tr_buf,
                                           out_tr,
                                           sizeof(out_tr),
                                           WALLET_POLICY_VERSION_V2);

    res = res_wsh;
    out = out_wsh;

    if (mode & TESTMODE_P2WSH_INVALID) {
        assert_true(res_wsh < 0);

        // we use the result of parsing as wsh script in the remaining
        // tests below, unless that's invalid
        res = res_tr;
        out = out_tr;
    }

    if (mode & TESTMODE_TAPSCRIPT_INVALID) {
        assert_true(res_tr < 0);
    }

    if (mode == TESTMODE_INVALID) {
        assert_true(res < 0);
    } else {
        assert_true(res >= 0);

        const policy_node_t *miniscript;
        int context;
        if (((policy_node_t *) out)->type == TOKEN_WSH) {
            miniscript = r_policy_node(&((policy_node_with_script_t *) out)->script);
            context = MINISCRIPT_CONTEXT_P2WSH;
        } else {
            assert_true(((policy_node_t *) out)->type == TOKEN_TR);
            policy_node_tr_t *tr = (policy_node_tr_t *) out;
            assert_true(r_policy_node_tree(&tr->tree)->is_leaf);

            miniscript = r_policy_node(&r_policy_node_tree(&tr->tree)->script);
            context = MINISCRIPT_CONTEXT_TAPSCRIPT;
        }

        policy_node_ext_info_t ext_info;
        res = compute_miniscript_policy_ext_info(miniscript, &ext_info, context);

        assert_true(res == 0);

        int is_expected_needsig = (mode & TESTMODE_NEEDSIG) ? 1 : 0;
        int is_expected_nonmal = (mode & TESTMODE_NONMAL) ? 1 : 0;

        int is_k = (mode & TESTMODE_TIMELOCKMIX) ? 0 : 1;

        // the hexscript is only used to compare with the script length
        // (since the pubkeys are missing in the descriptor template, the exact bytes are not known)
        int scriptlen = strlen(hexscript) / 2;

        assert_true(ext_info.s == is_expected_needsig);
        assert_true(ext_info.m == is_expected_nonmal);

        assert_true(ext_info.k == is_k);

        if (scriptlen >= 1) {
            assert_int_equal(ext_info.script_size, scriptlen);
        }

        if (opslimit != -1) {
            // if ext_info.ops.sat, we want to use 0 (consistently with bitcoin-core's
            // implementation)
            int ops_sat = (ext_info.ops.sat == -1) ? 0 : ext_info.ops.sat;

            int computed_opslimit = ext_info.ops.count + ops_sat;
            assert_int_equal(computed_opslimit, opslimit);
        }
        if (stacklimit != -1) {
            assert_true(ext_info.ss.sat >= 0);
            int computed_stacklimit = ext_info.ss.sat + 1;
            assert_int_equal(computed_stacklimit, stacklimit);
        }
    }
}

static void test_miniscript_types(void **state) {
    (void) state;

    // tests for miniscript type system
    // Tests taken from
    // https://github.com/bitcoin/bitcoin/blob/5bf65ec66e5986c9188e3f6234f1c5c0f8dc7f90/src/test/miniscript_tests.cpp,
    // except that all key expressions are replaced with placeholders @0/**, @1/**, ...

    // clang-format off
    Test("l:older(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // older(1): valid
    Test("l:older(0)", "?", TESTMODE_INVALID, -1, -1); // older(0): k must be at least 1
    Test("l:older(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // older(2147483647): valid
    Test("l:older(2147483648)", "?", TESTMODE_INVALID, -1, -1); // older(2147483648): k must be below 2^31
    Test("u:after(1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // after(1): valid
    Test("u:after(0)", "?", TESTMODE_INVALID, -1, -1); // after(0): k must be at least 1
    Test("u:after(2147483647)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // after(2147483647): valid
    Test("u:after(2147483648)", "?", TESTMODE_INVALID, -1, -1); // after(2147483648): k must be below 2^31
    Test("andor(0,1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // andor(Bdu,B,B): valid
    Test("andor(a:0,1,1)", "?", TESTMODE_INVALID, -1, -1); // andor(Wdu,B,B): X must be B
    Test("andor(0,a:1,a:1)", "?", TESTMODE_INVALID, -1, -1); // andor(Bdu,W,W): Y and Z must be B/V/K
    Test("andor(1,1,1)", "?", TESTMODE_INVALID, -1, -1); // andor(Bu,B,B): X must be d
    Test("andor(n:or_i(0,after(1)),1,1)", "?", TESTMODE_VALID, -1, -1); // andor(Bdu,B,B): valid
    Test("andor(or_i(0,after(1)),1,1)", "?", TESTMODE_INVALID, -1, -1); // andor(Bd,B,B): X must be u
    Test("c:andor(0,pk_k(@0/**),pk_k(@1/**))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // andor(Bdu,K,K): valid
    Test("t:andor(0,v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // andor(Bdu,V,V): valid
    Test("and_v(v:1,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // and_v(V,B): valid
    Test("t:and_v(v:1,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // and_v(V,V): valid
    Test("c:and_v(v:1,pk_k(@0/**))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // and_v(V,K): valid
    Test("and_v(1,1)", "?", TESTMODE_INVALID, -1, -1); // and_v(B,B): X must be V
    Test("and_v(pk_k(@0/**),1)", "?", TESTMODE_INVALID, -1, -1); // and_v(K,B): X must be V
    Test("and_v(v:1,a:1)", "?", TESTMODE_INVALID, -1, -1); // and_v(K,W): Y must be B/V/K
    Test("and_b(1,a:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // and_b(B,W): valid
    Test("and_b(1,1)", "?", TESTMODE_INVALID, -1, -1); // and_b(B,B): Y must W
    Test("and_b(v:1,a:1)", "?", TESTMODE_INVALID, -1, -1); // and_b(V,W): X must be B
    Test("and_b(a:1,a:1)", "?", TESTMODE_INVALID, -1, -1); // and_b(W,W): X must be B
    Test("and_b(pk_k(@0/**),a:1)", "?", TESTMODE_INVALID, -1, -1); // and_b(K,W): X must be B
    Test("or_b(0,a:0)", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // or_b(Bd,Wd): valid
    Test("or_b(1,a:0)", "?", TESTMODE_INVALID, -1, -1); // or_b(B,Wd): X must be d
    Test("or_b(0,a:1)", "?", TESTMODE_INVALID, -1, -1); // or_b(Bd,W): Y must be d
    Test("or_b(0,0)", "?", TESTMODE_INVALID, -1, -1); // or_b(Bd,Bd): Y must W
    Test("or_b(v:0,a:0)", "?", TESTMODE_INVALID, -1, -1); // or_b(V,Wd): X must be B
    Test("or_b(a:0,a:0)", "?", TESTMODE_INVALID, -1, -1); // or_b(Wd,Wd): X must be B
    Test("or_b(pk_k(@0/**),a:0)", "?", TESTMODE_INVALID, -1, -1); // or_b(Kd,Wd): X must be B
    Test("t:or_c(0,v:1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // or_c(Bdu,V): valid
    Test("t:or_c(a:0,v:1)", "?", TESTMODE_INVALID, -1, -1); // or_c(Wdu,V): X must be B
    Test("t:or_c(1,v:1)", "?", TESTMODE_INVALID, -1, -1); // or_c(Bu,V): X must be d
    Test("t:or_c(n:or_i(0,after(1)),v:1)", "?", TESTMODE_VALID, -1, -1); // or_c(Bdu,V): valid
    Test("t:or_c(or_i(0,after(1)),v:1)", "?", TESTMODE_INVALID, -1, -1); // or_c(Bd,V): X must be u
    Test("t:or_c(0,1)", "?", TESTMODE_INVALID, -1, -1); // or_c(Bdu,B): Y must be V
    Test("or_d(0,1)", "?", TESTMODE_VALID | TESTMODE_NONMAL, -1, -1); // or_d(Bdu,B): valid
    Test("or_d(a:0,1)", "?", TESTMODE_INVALID, -1, -1); // or_d(Wdu,B): X must be B
    Test("or_d(1,1)", "?", TESTMODE_INVALID, -1, -1); // or_d(Bu,B): X must be d
    Test("or_d(n:or_i(0,after(1)),1)", "?", TESTMODE_VALID, -1, -1); // or_d(Bdu,B): valid
    Test("or_d(or_i(0,after(1)),1)", "?", TESTMODE_INVALID, -1, -1); // or_d(Bd,B): X must be u
    Test("or_d(0,v:1)", "?", TESTMODE_INVALID, -1, -1); // or_d(Bdu,V): Y must be B
    Test("or_i(1,1)", "?", TESTMODE_VALID, -1, -1); // or_i(B,B): valid
    Test("t:or_i(v:1,v:1)", "?", TESTMODE_VALID, -1, -1); // or_i(V,V): valid
    Test("c:or_i(pk_k(@0/**),pk_k(@1/**))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // or_i(K,K): valid
    Test("or_i(a:1,a:1)", "?", TESTMODE_INVALID, -1, -1); // or_i(W,W): X and Y must be B/V/K
    Test("or_b(l:after(100),al:after(1000000000))", "?", TESTMODE_VALID, -1, -1); // or_b(timelock, heighlock) valid
    Test("and_b(after(100),a:after(1000000000))", "?", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX, -1, -1); // and_b(timelock, heighlock) invalid
    Test("pk(@0/**)", "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // alias to c:pk_k
    Test("pkh(@0/**)", "76a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, -1, -1); // alias to c:pk_h

    // Randomly generated test set that covers the majority of type and node type combinations
    Test("lltvln:after(1231488000)", "6300676300676300670400046749b1926869516868", TESTMODE_VALID | TESTMODE_NONMAL, 12, 4);
    Test("uuj:and_v(v:multi(2,@0/**,@1/**),after(1231488000))", "6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 14, 6);
    Test("or_b(un:multi(2,@0/**,@1/**),al:older(16))", "63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b", TESTMODE_VALID | TESTMODE_TAPSCRIPT_INVALID, 14, 6);
    Test("j:and_v(vdv:after(1567547623),older(2016))", "829263766304e7e06e5db169686902e007b268", TESTMODE_VALID | TESTMODE_NONMAL, 11, 2);
    Test("t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))", "6382012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876700686982012088a820ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc58851", TESTMODE_VALID | TESTMODE_NONMAL, 12, 4);
    Test("t:andor(multi(3,@0/**,@1/**,@2/**),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))", "532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TAPSCRIPT_INVALID, 13, 6);
    Test("or_d(multi(1,@0/**),or_b(multi(3,@1/**,@2/**,@3/**),su:after(500000)))", "512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TAPSCRIPT_INVALID, 15, 8);
    Test("or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))", "82012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68773646304ff64cd1db19267006864006703010040b26868", TESTMODE_VALID, 16, 2);
    Test("and_v(or_i(v:multi(2,@0/**,@1/**),v:multi(2,@2/**,@3/**)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))", "63522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb52af67522103e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a21025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52af6882012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c6887", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 11, 6);
    Test("j:and_b(multi(2,@0/**,@1/**),s:or_i(older(1),older(4252898)))", "82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68", TESTMODE_VALID | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 14, 5);
    Test("and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))", "60b27c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87736404e7e06e5db192689a", TESTMODE_VALID, 12, 2);
    Test("j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))", "82926382012088a91420195b5a3d650c17f0f29f91c33f8f6335193d078882012088a82096de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c4787736460b26868", TESTMODE_VALID, 16, 3);
    Test("and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))", "82012088aa2032ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac876b82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876b51b26c9a6c9a", TESTMODE_VALID | TESTMODE_NONMAL, 15, 3);
    Test("thresh(2,multi(2,@0/**,@1/**),a:multi(1,@2/**),ac:pk_k(@3/**))", "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 13, 7);
    Test("and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))", "82012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68876400676303e2e440b26967029000b269685168", TESTMODE_VALID, 14, 3);
    Test("or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))", "766303e2e440b26903e2e440b2696892736482012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68768", TESTMODE_VALID, 15, 3);
    Test("c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,@0/**)),pk_k(@1/**))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764512102c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db51af682103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeac", TESTMODE_VALID | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 8, 3);
    Test("c:and_v(or_c(multi(2,@0/**,@1/**),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(@2/**))", "5221036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a002102352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d552ae6482012088a6141b0f3c404d12075c68c938f9f60ebea4f74941a088682103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TAPSCRIPT_INVALID, 10, 6);
    Test("and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))", "82012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b2587640350c300b2696782012088aa20939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735886804ff64cd1db1", TESTMODE_VALID, 14, 3);
    Test("andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))", "82012088aa205f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040876482012088a61444d90e2d3714c8663b632fcf0f9d5f22192cc4c8876782926382012088a9143a2bff0da9d96868e66abc4427bea4691cf61ccd8803010040b26868", TESTMODE_VALID, 20, 3);
    Test("or_i(c:and_v(v:after(500000),pk_k(@0/**)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))", "630320a107b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac6782012088a820d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f9468768", TESTMODE_VALID | TESTMODE_NONMAL, 10, 3);
    Test("thresh(2,c:pk_h(@0/**),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))", "76a9145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f6988ac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287", TESTMODE_VALID, 18, 5);
    Test("and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(@0/**)))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764006763029000b2692103fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ceac67006868", TESTMODE_VALID | TESTMODE_NEEDSIG, 13, 4);
    Test("and_n(c:pk_k(@0/**),and_b(l:older(4252898),a:older(16)))", "2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_TIMELOCKMIX, 12, 3);
    Test("c:or_i(and_v(v:older(16),pk_h(@0/**)),pk_h(@1/**))", "6360b26976a9149fc5dbe5efdce10374a4dd4053c93af540211718886776a9142fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f8868ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, 12, 4);
    Test("or_d(c:pk_h(@0/**),andor(c:pk_k(@1/**),older(2016),after(1567547623)))", "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868", TESTMODE_VALID | TESTMODE_NONMAL, 13, 4);
    Test("c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(@1/**)))", "82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba876482012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b258876a914dd100be7d9aea5721158ebde6d6a1fd8fff93bb1886776a9149fc5dbe5efdce10374a4dd4053c93af5402117188868ac", TESTMODE_VALID | TESTMODE_NEEDSIG, 18, 4);
    Test("c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),or_i(pk_h(@1/**),pk_h(@2/**)))", "6382012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87670068646376a9149652d86bedf43ad264362e6e6eba6eb764508127886776a914751e76e8199196d454941c45d1b3a323f1433bd688686776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac", TESTMODE_VALID | TESTMODE_NEEDSIG, 23, 5);
    Test("c:or_i(andor(c:pk_h(@0/**),pk_h(@1/**),pk_h(@2/**)),pk_k(@3/**))", "6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG, 17, 6);
    Test("thresh(1,c:pk_k(@0/**),altv:after(1000000000),altv:after(100))", "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6b6300670400ca9a3bb16951686c936b6300670164b16951686c935187", TESTMODE_VALID, 18, 4);
    Test("thresh(2,c:pk_k(@0/**),ac:pk_k(@1/**),altv:after(1000000000),altv:after(100))", "2103d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac6b2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac6c936b6300670400ca9a3bb16951686c936b6300670164b16951686c935287", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_TIMELOCKMIX, 22, 5);

    // Additional Tapscript-related tests
    Test("and_v(v:multi_a(2,@0/**,@1/**),after(1231488000))", "20d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85aac205601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7ccba529d0400046749b1", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_P2WSH_INVALID, 4, 3);

    // Since 'd:' is 'u' we can use it directly inside a thresh. But we can't under P2WSH.
    Test("thresh(2,dv:older(42),s:pk(@0/**),s:pk(@1/**))", "7663012ab269687c205cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bcac937c20d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65ac935287", TESTMODE_VALID | TESTMODE_NONMAL | TESTMODE_NEEDSIG | TESTMODE_P2WSH_INVALID, 12, 4);

    // clang-format on
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_policy_map_singlesig_1),
        cmocka_unit_test(test_parse_policy_map_singlesig_2),
        cmocka_unit_test(test_parse_policy_map_singlesig_3),
        cmocka_unit_test(test_parse_policy_map_multisig_1),
        cmocka_unit_test(test_parse_policy_map_multisig_2),
        cmocka_unit_test(test_parse_policy_map_multisig_3),
        cmocka_unit_test(test_parse_policy_tr),
        cmocka_unit_test(test_parse_policy_tr_multisig),
        cmocka_unit_test(test_get_policy_segwit_version),
        cmocka_unit_test(test_parse_unsigned_decimal_overflow),
        cmocka_unit_test(test_failures),
        cmocka_unit_test(test_miniscript_types),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
