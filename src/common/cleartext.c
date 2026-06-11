/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "common/cleartext.h"
#include "common/wallet.h"
#include "constants.h"  // SEQUENCE_LOCKTIME_TYPE_FLAG, LOCKTIME_THRESHOLD

#include "ledger_assert.h"

#ifndef SKIP_FOR_CMOCKA
#include "os_pic.h"
#else
#define PIC(x) (x)
#endif

// ---------------------------------------------------------------------------
// Saturating-u64 helpers
// ---------------------------------------------------------------------------

static inline uint64_t sat_mul_u64(uint64_t a, uint64_t b) {
    if (a == 0 || b == 0) return 0;
    if (a > UINT64_MAX / b) return UINT64_MAX;
    return a * b;
}

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

// A matched class instance carries its bindings here. At most 3 dynamic
// bindings are used by any cleartext spec part (since CT_MAX_BINDINGS == 3).
#define CT_MAX_BINDINGS 3

typedef enum {
    CT_BV_NONE = 0,
    CT_BV_KEY,
    CT_BV_KEYS,
    CT_BV_NUMBER,
    CT_BV_SUB,       // a sub-policy (recursively classified at render/score time)
    CT_BV_TIMELOCK,  // unified older()/after() value
} ct_bind_kind_e;

// A unified timelock value, captured from either older(n) or after(n).
typedef struct {
    uint32_t raw;
    bool is_relative;  // true = older(), false = after()
} ct_timelock_t;

typedef struct {
    ct_bind_kind_e kind;
    union {
        const policy_node_keyexpr_t *key;
        struct {
            const policy_node_keyexpr_t *array;
            uint16_t n;
        } keys;
        uint32_t number;
        const policy_node_t *sub;
        ct_timelock_t timelock;
    } u;
} ct_value_t;

typedef struct {
    ct_value_t v[CT_MAX_BINDINGS];
    uint8_t n;
} ct_bindings_t;

typedef struct {
    descriptor_class_e cls;
    ct_bindings_t bindings;
    // For taproot, the taptree (NULL if no tree).
    const policy_node_tree_t *taptree;
} ct_top_match_t;

typedef struct {
    tapleaf_class_e cls;
    ct_bindings_t bindings;
    // The leaf script — when class is TC_OTHER, used for "raw" rendering.
    const policy_node_t *leaf_script;
} ct_leaf_match_t;

static bool match_top_level(const policy_node_t *root, ct_top_match_t *out);
static bool match_tapleaf(const policy_node_t *leaf_script, ct_leaf_match_t *out);

static int append_str(char *out, size_t cap, size_t *off, const char *s);
static int append_keyexpr(char *out, size_t cap, size_t *off, const policy_node_keyexpr_t *key);
static int append_keys_list(char *out,
                            size_t cap,
                            size_t *off,
                            const policy_node_keyexpr_t *keys,
                            uint16_t n);
static int append_uint32(char *out, size_t cap, size_t *off, uint32_t v);
static int append_timelock(char *out, size_t cap, size_t *off, ct_timelock_t tl);

static int render_spec(const cleartext_spec_t *spec, const ct_bindings_t *b, char *out, size_t cap);
static int render_spec_at(const cleartext_spec_t *spec,
                          const ct_bindings_t *b,
                          char *out,
                          size_t cap,
                          size_t *off);
static int leaf_cmp(const ct_leaf_match_t *a, const ct_leaf_match_t *b);
static uint64_t leaf_score(const ct_leaf_match_t *lm);

// ---------------------------------------------------------------------------
// Score helpers (per-class admittance count)
// ---------------------------------------------------------------------------

// Returns the number of patterns that admit the matched bindings.
// For multisig-bearing classes, the musig pattern admits iff
// threshold == n_keys.
static uint8_t admitting_pattern_count(const cleartext_spec_t *spec, const ct_bindings_t *b) {
    uint8_t n = spec->n_patterns;
    if (spec->n_musig_patterns == 0) return n;

    // Find the threshold and keys bindings (if present).
    bool has_threshold = false;
    bool has_keys = false;
    uint32_t threshold = 0;
    uint32_t n_keys = 0;
    for (uint8_t i = 0; i < b->n; i++) {
        const ct_value_t *v = &b->v[i];
        // The binding order in our specs is always:
        //   - top_level / leaf multisig: [threshold, keys, ...]
        //   - top_level Taproot/TaprootMusig: [internal_key or threshold, ...]
        if (v->kind == CT_BV_NUMBER && !has_threshold) {
            has_threshold = true;
            threshold = v->u.number;
        } else if (v->kind == CT_BV_KEYS && !has_keys) {
            has_keys = true;
            const policy_node_keyexpr_t *first = v->u.keys.array;
            if (v->u.keys.n == 1 && first != NULL && first->type == KEY_EXPRESSION_MUSIG) {
                // Musig sentinel — effective n_keys is the musig key count.
                const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&first->m.musig_info);
                n_keys = mi->n;
            } else {
                n_keys = v->u.keys.n;
            }
        }
    }
    if (!has_threshold || !has_keys) {
        // No threshold/keys pair -> assume the musig patterns always admit
        // (this is the case for TaprootMusig top-level, where the binding
        // is a single KEYS list).
        return n;
    }

    // Strip the musig contribution, add it back only when admitted.
    uint8_t base = (uint8_t) (n - spec->n_musig_patterns);
    if (threshold == n_keys) base += spec->n_musig_patterns;
    return base;
}

// ---------------------------------------------------------------------------
// Key-derivation helpers (canonical check + ordering factor)
// ---------------------------------------------------------------------------

// Fixed-size table for grouping equivalent keyexprs. The actual maximum is
// bounded by total occurrences (taproot can fit a lot in 512-byte templates,
// but in practice ≤ ~30 occurrences).
#define CT_MAX_KEYEXPRS 32

typedef struct {
    // Canonical identity hash: includes (type, key_index or sorted musig set).
    // We store the key id as the canonical key expression itself; equality is
    // determined via are_key_placeholders_identical-style compare.
    const policy_node_keyexpr_t *repr;
    // Derivation pairs collected for this class.
    uint32_t pairs[CT_MAX_KEYEXPRS][2];
    uint8_t n_pairs;
} ct_keyexpr_class_t;

// Local copy of "two keyexprs are the same key" — independent of derivation.
static bool keyexpr_same_key(const policy_node_keyexpr_t *a, const policy_node_keyexpr_t *b) {
    if (a->type != b->type) return false;
    if (a->type == KEY_EXPRESSION_NORMAL) {
        return a->k.key_index == b->k.key_index;
    }
    // KEY_EXPRESSION_MUSIG: compare the (unordered) set of indices.
    const musig_aggr_key_info_t *ai = r_musig_aggr_key_info(&a->m.musig_info);
    const musig_aggr_key_info_t *bi = r_musig_aggr_key_info(&b->m.musig_info);
    if (ai->n != bi->n) return false;
    const uint16_t *ak = r_uint16(&ai->key_indexes);
    const uint16_t *bk = r_uint16(&bi->key_indexes);
    // Both sets must contain the same elements (small n ≤ 5).
    for (uint16_t i = 0; i < ai->n; i++) {
        bool found = false;
        for (uint16_t j = 0; j < bi->n; j++) {
            if (ak[i] == bk[j]) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

// Walk all keyexprs in the policy via get_keyexpr_by_index, group by key
// identity, return:
//   *out_orderings_count = ∏ k! (saturated)
//   *out_canonical       = whether each group's derivation pairs are exactly
//                          (0,1), (2,3), (4,5), ... in some order.
//
// `get_keyexpr_by_index` lives in src/handler/lib/policy.c and is not part of
// the cmocka unit-test link set; to keep cleartext.c usable from the
// unit-test target we provide our own DFS walker that visits every keyexpr.
static int collect_keyexprs(const policy_node_t *node,
                            const policy_node_keyexpr_t **out_arr,
                            int *out_n,
                            int max);
static int collect_keyexprs_tree(const policy_node_tree_t *tree,
                                 const policy_node_keyexpr_t **out_arr,
                                 int *out_n,
                                 int max);

static int collect_keyexprs(const policy_node_t *node,
                            const policy_node_keyexpr_t **out_arr,
                            int *out_n,
                            int max) {
    if (node == NULL) return 0;
    switch (node->type) {
        case TOKEN_0:
        case TOKEN_1:
        case TOKEN_OLDER:
        case TOKEN_AFTER:
        case TOKEN_SHA256:
        case TOKEN_HASH256:
        case TOKEN_RIPEMD160:
        case TOKEN_HASH160:
            return 0;

        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_WPKH:
        case TOKEN_PK_K:
        case TOKEN_PK_H: {
            const policy_node_with_key_t *n = (const policy_node_with_key_t *) node;
            if (*out_n >= max) return -1;
            out_arr[(*out_n)++] = r_policy_node_keyexpr(&n->key);
            return 0;
        }

        case TOKEN_SH:
        case TOKEN_WSH:
        case TOKEN_A:
        case TOKEN_S:
        case TOKEN_C:
        case TOKEN_T:
        case TOKEN_D:
        case TOKEN_V:
        case TOKEN_J:
        case TOKEN_N:
        case TOKEN_L:
        case TOKEN_U: {
            const policy_node_with_script_t *n = (const policy_node_with_script_t *) node;
            return collect_keyexprs(r_policy_node(&n->script), out_arr, out_n, max);
        }

        case TOKEN_AND_V:
        case TOKEN_AND_B:
        case TOKEN_AND_N:
        case TOKEN_OR_B:
        case TOKEN_OR_C:
        case TOKEN_OR_D:
        case TOKEN_OR_I: {
            const policy_node_with_script2_t *n = (const policy_node_with_script2_t *) node;
            if (collect_keyexprs(r_policy_node(&n->scripts[0]), out_arr, out_n, max) < 0) return -1;
            return collect_keyexprs(r_policy_node(&n->scripts[1]), out_arr, out_n, max);
        }

        case TOKEN_ANDOR: {
            const policy_node_with_script3_t *n = (const policy_node_with_script3_t *) node;
            for (int i = 0; i < 3; i++) {
                if (collect_keyexprs(r_policy_node(&n->scripts[i]), out_arr, out_n, max) < 0)
                    return -1;
            }
            return 0;
        }

        case TOKEN_MULTI:
        case TOKEN_MULTI_A:
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A: {
            const policy_node_multisig_t *n = (const policy_node_multisig_t *) node;
            const policy_node_keyexpr_t *arr = r_policy_node_keyexpr(&n->keys);
            for (uint16_t i = 0; i < n->n; i++) {
                if (*out_n >= max) return -1;
                out_arr[(*out_n)++] = &arr[i];
            }
            return 0;
        }

        case TOKEN_THRESH: {
            const policy_node_thresh_t *n = (const policy_node_thresh_t *) node;
            const policy_node_scriptlist_t *cur = r_policy_node_scriptlist(&n->scriptlist);
            while (cur != NULL) {
                if (collect_keyexprs(r_policy_node(&cur->script), out_arr, out_n, max) < 0)
                    return -1;
                cur = r_policy_node_scriptlist(&cur->next);
            }
            return 0;
        }

        case TOKEN_TR: {
            const policy_node_tr_t *n = (const policy_node_tr_t *) node;
            if (*out_n >= max) return -1;
            out_arr[(*out_n)++] = r_policy_node_keyexpr(&n->key);
            const policy_node_tree_t *tree = r_policy_node_tree(&n->tree);
            return collect_keyexprs_tree(tree, out_arr, out_n, max);
        }

        default:
            return 0;
    }
}

static int collect_keyexprs_tree(const policy_node_tree_t *tree,
                                 const policy_node_keyexpr_t **out_arr,
                                 int *out_n,
                                 int max) {
    if (tree == NULL) return 0;
    if (tree->is_leaf) {
        return collect_keyexprs(r_policy_node(&tree->script), out_arr, out_n, max);
    }
    if (collect_keyexprs_tree(r_policy_node_tree(&tree->left_tree), out_arr, out_n, max) < 0)
        return -1;
    return collect_keyexprs_tree(r_policy_node_tree(&tree->right_tree), out_arr, out_n, max);
}

// Saturating factorial.
static uint64_t sat_factorial(uint32_t n) {
    uint64_t f = 1;
    for (uint32_t i = 2; i <= n; i++) {
        f = sat_mul_u64(f, i);
    }
    return f;
}

// Sort pairs by (first, second), stable insertion sort.
static void sort_pairs(uint32_t pairs[][2], uint8_t n) {
    for (uint8_t i = 1; i < n; i++) {
        uint32_t a = pairs[i][0], b = pairs[i][1];
        int8_t j = (int8_t) i - 1;
        while (j >= 0 && (pairs[j][0] > a || (pairs[j][0] == a && pairs[j][1] > b))) {
            pairs[j + 1][0] = pairs[j][0];
            pairs[j + 1][1] = pairs[j][1];
            j--;
        }
        pairs[j + 1][0] = a;
        pairs[j + 1][1] = b;
    }
}

// Returns the orderings count ∏ k!. Sets *out_canonical to true iff for every
// key, its sorted (num_first, num_second) pairs equal (0,1),(2,3),(4,5),...
static uint64_t key_orderings_count(const policy_node_t *root, bool *out_canonical) {
    const policy_node_keyexpr_t *kx[CT_MAX_KEYEXPRS];
    int n = 0;
    if (collect_keyexprs(root, kx, &n, CT_MAX_KEYEXPRS) < 0) {
        // Buffer overflow — treat as not canonical, and return saturating value.
        *out_canonical = false;
        return UINT64_MAX;
    }
    if (n == 0) {
        *out_canonical = true;
        return 1;
    }

    // Group by identity. classes[i].repr is the first keyexpr in the group;
    // classes[i].pairs collects (num_first, num_second) for each occurrence.
    ct_keyexpr_class_t classes[CT_MAX_KEYEXPRS];
    int n_classes = 0;

    for (int i = 0; i < n; i++) {
        const policy_node_keyexpr_t *k = kx[i];
        int idx = -1;
        for (int j = 0; j < n_classes; j++) {
            if (keyexpr_same_key(classes[j].repr, k)) {
                idx = j;
                break;
            }
        }
        if (idx < 0) {
            if (n_classes >= CT_MAX_KEYEXPRS) {
                *out_canonical = false;
                return UINT64_MAX;
            }
            classes[n_classes].repr = k;
            classes[n_classes].n_pairs = 0;
            idx = n_classes++;
        }
        if (classes[idx].n_pairs >= CT_MAX_KEYEXPRS) {
            *out_canonical = false;
            return UINT64_MAX;
        }
        classes[idx].pairs[classes[idx].n_pairs][0] = k->num_first;
        classes[idx].pairs[classes[idx].n_pairs][1] = k->num_second;
        classes[idx].n_pairs++;
    }

    // Canonical check: group by full key identity (musig groups stay whole) and
    // require each group's sorted derivation pairs to be (0,1),(2,3),(4,5),...
    *out_canonical = true;
    for (int i = 0; i < n_classes; i++) {
        sort_pairs(classes[i].pairs, classes[i].n_pairs);
        for (uint8_t j = 0; j < classes[i].n_pairs; j++) {
            if (classes[i].pairs[j][0] != (uint32_t) (2 * j) ||
                classes[i].pairs[j][1] != (uint32_t) (2 * j + 1)) {
                *out_canonical = false;
            }
        }
    }

    // Compute an upper bound on the possible number of orderings for the
    // derivation pairs.
    uint32_t idx_vals[CT_MAX_KEYEXPRS * MAX_PUBKEYS_PER_MUSIG];
    uint32_t idx_cnts[CT_MAX_KEYEXPRS * MAX_PUBKEYS_PER_MUSIG];
    int n_idx = 0;
    for (int i = 0; i < n; i++) {
        const policy_node_keyexpr_t *k = kx[i];
        // Build the list of plain key indices contributed by this keyexpr.
        uint32_t members[MAX_PUBKEYS_PER_MUSIG];
        uint16_t n_members;
        if (k->type == KEY_EXPRESSION_NORMAL) {
            members[0] = k->k.key_index;
            n_members = 1;
        } else {
            const musig_aggr_key_info_t *ai = r_musig_aggr_key_info(&k->m.musig_info);
            const uint16_t *ak = r_uint16(&ai->key_indexes);
            n_members = ai->n;
            for (uint16_t j = 0; j < n_members; j++) members[j] = ak[j];
        }
        for (uint16_t j = 0; j < n_members; j++) {
            int slot = -1;
            for (int s = 0; s < n_idx; s++) {
                if (idx_vals[s] == members[j]) {
                    slot = s;
                    break;
                }
            }
            if (slot < 0) {
                idx_vals[n_idx] = members[j];
                idx_cnts[n_idx] = 0;
                slot = n_idx++;
            }
            idx_cnts[slot]++;
        }
    }
    uint64_t product = 1;
    for (int i = 0; i < n_idx; i++) {
        product = sat_mul_u64(product, sat_factorial(idx_cnts[i]));
    }
    return product;
}

// ---------------------------------------------------------------------------
// Wrapper peeling
// ---------------------------------------------------------------------------

// Peel a single wrapper token if it matches the given type. Used for v: c: a: etc.
static const policy_node_t *peel_wrapper(const policy_node_t *n, PolicyNodeType t) {
    if (n == NULL || n->type != t) return n;
    const policy_node_with_script_t *w = (const policy_node_with_script_t *) n;
    return r_policy_node(&w->script);
}

// ---------------------------------------------------------------------------
// Tapleaf matchers
// ---------------------------------------------------------------------------

// A small helper to set bindings.
static void set_binding_key(ct_bindings_t *b, int i, const policy_node_keyexpr_t *k) {
    b->v[i].kind = CT_BV_KEY;
    b->v[i].u.key = k;
}

static void set_binding_keys(ct_bindings_t *b,
                             int i,
                             const policy_node_keyexpr_t *arr,
                             uint16_t n) {
    b->v[i].kind = CT_BV_KEYS;
    b->v[i].u.keys.array = arr;
    b->v[i].u.keys.n = n;
}

static void set_binding_number(ct_bindings_t *b, int i, uint32_t v) {
    b->v[i].kind = CT_BV_NUMBER;
    b->v[i].u.number = v;
}

// Returns true if `node` is `pk($keyexpr)` (the taproot single-key form),
// and writes the keyexpr to *out.
static bool match_pk_keyexpr(const policy_node_t *node, const policy_node_keyexpr_t **out) {
    if (node == NULL || node->type != TOKEN_PK) return false;
    const policy_node_with_key_t *w = (const policy_node_with_key_t *) node;
    *out = r_policy_node_keyexpr(&w->key);
    return true;
}

// Match a unified timelock node: returns true if `node` is `older($n)` or
// `after($n)`, and fills `*out` with raw + is_relative.
static bool match_lock_value(const policy_node_t *node, ct_timelock_t *out) {
    if (node == NULL) return false;
    if (node->type == TOKEN_OLDER) {
        const policy_node_with_uint32_t *u = (const policy_node_with_uint32_t *) node;
        out->raw = u->n;
        out->is_relative = true;
        return true;
    }
    if (node->type == TOKEN_AFTER) {
        const policy_node_with_uint32_t *u = (const policy_node_with_uint32_t *) node;
        out->raw = u->n;
        out->is_relative = false;
        return true;
    }
    return false;
}

static void set_binding_sub(ct_bindings_t *b, int i, const policy_node_t *sub) {
    b->v[i].kind = CT_BV_SUB;
    b->v[i].u.sub = sub;
}

static void set_binding_timelock(ct_bindings_t *b, int i, ct_timelock_t tl) {
    b->v[i].kind = CT_BV_TIMELOCK;
    b->v[i].u.timelock = tl;
}

// Match a multisig-shaped node: `multi_a(k, keys)`, `pk(musig(...))`, or
// `sortedmulti_a(k, keys)`. The first writes (threshold=k, keys=array of n),
// the second writes (threshold=n, keys=musig_array) and only if its keyexpr
// is musig. Sets *is_sorted to true for sortedmulti_a. Returns false on
// non-match.
static bool match_multisig_like(const policy_node_t *node,
                                uint32_t *out_threshold,
                                const policy_node_keyexpr_t **out_keys,
                                uint16_t *out_n,
                                bool *is_sorted,
                                bool *is_musig_pk) {
    if (node == NULL) return false;
    *is_sorted = false;
    *is_musig_pk = false;

    if (node->type == TOKEN_MULTI_A || node->type == TOKEN_SORTEDMULTI_A) {
        const policy_node_multisig_t *m = (const policy_node_multisig_t *) node;
        *out_threshold = m->k;
        *out_keys = r_policy_node_keyexpr(&m->keys);
        *out_n = m->n;
        *is_sorted = (node->type == TOKEN_SORTEDMULTI_A);
        return true;
    }
    if (node->type == TOKEN_PK) {
        const policy_node_with_key_t *w = (const policy_node_with_key_t *) node;
        const policy_node_keyexpr_t *k = r_policy_node_keyexpr(&w->key);
        if (k->type != KEY_EXPRESSION_MUSIG) return false;
        const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&k->m.musig_info);
        // We expose the musig key list via the keyexpr — but the renderer
        // needs an array of keyexprs, not raw indices. We synthesize a
        // single-element "keys" pointer that points at the (single) musig
        // keyexpr `k`; render-time will see CT_BV_KEYS with n==1 and the
        // pointer being a real keyexpr, and treat it as a musig list.
        // For the multisig spec the renderer fmt_keys handles the n==1 musig
        // case specially.
        *out_threshold = mi->n;
        *out_keys = k;
        *out_n = 1;  // sentinel: a single musig keyexpr
        *is_musig_pk = true;
        return true;
    }
    return false;
}

// Try to classify a leaf as one of the four non-combinator basic classes:
// SingleSig, BothMustSign, SortedMultisig, Multisig. Used both as a standalone
// matcher and as the inner classifier for sub-policies of Timelocked/AndV.
static bool match_basic_tapleaf(const policy_node_t *leaf, ct_leaf_match_t *out) {
    out->leaf_script = leaf;
    out->cls = TC_OTHER;
    out->bindings.n = 0;

    if (leaf == NULL) return false;

    // Try SingleSig: pk($key) where $key is a plain (non-musig) keyexpr.
    {
        const policy_node_keyexpr_t *kx;
        if (match_pk_keyexpr(leaf, &kx) && kx->type == KEY_EXPRESSION_NORMAL) {
            out->cls = TC_SINGLE_SIG;
            set_binding_key(&out->bindings, 0, kx);
            out->bindings.n = 1;
            return true;
        }
    }

    // Try BothMustSign: and_v(v:pk($key1), pk($key2)).
    if (leaf->type == TOKEN_AND_V) {
        const policy_node_with_script2_t *av = (const policy_node_with_script2_t *) leaf;
        const policy_node_t *left_inner = peel_wrapper(r_policy_node(&av->scripts[0]), TOKEN_V);
        const policy_node_t *right = r_policy_node(&av->scripts[1]);
        const policy_node_keyexpr_t *k1, *k2;
        if (match_pk_keyexpr(left_inner, &k1) && k1->type == KEY_EXPRESSION_NORMAL &&
            match_pk_keyexpr(right, &k2) && k2->type == KEY_EXPRESSION_NORMAL) {
            out->cls = TC_BOTH_MUST_SIGN;
            set_binding_key(&out->bindings, 0, k1);
            set_binding_key(&out->bindings, 1, k2);
            out->bindings.n = 2;
            return true;
        }
    }

    // Try SortedMultisig / Multisig: multi_a, sortedmulti_a, or pk(musig).
    {
        uint32_t threshold;
        const policy_node_keyexpr_t *keys;
        uint16_t n;
        bool is_sorted, is_musig_pk;
        if (match_multisig_like(leaf, &threshold, &keys, &n, &is_sorted, &is_musig_pk)) {
            out->cls = is_sorted ? TC_SORTED_MULTISIG : TC_MULTISIG;
            set_binding_number(&out->bindings, 0, threshold);
            set_binding_keys(&out->bindings, 1, keys, n);
            out->bindings.n = 2;
            return true;
        }
    }

    return false;
}

static bool match_tapleaf(const policy_node_t *leaf, ct_leaf_match_t *out) {
    if (leaf == NULL) {
        out->leaf_script = NULL;
        out->cls = TC_OTHER;
        out->bindings.n = 0;
        return false;
    }

    // First try the basic (non-combinator) classes in spec order.
    if (match_basic_tapleaf(leaf, out)) {
        return true;
    }

    // Reset to OTHER for the combinator passes below.
    out->leaf_script = leaf;
    out->cls = TC_OTHER;
    out->bindings.n = 0;

    if (leaf->type != TOKEN_AND_V) return false;

    const policy_node_with_script2_t *av = (const policy_node_with_script2_t *) leaf;
    const policy_node_t *left_inner = peel_wrapper(r_policy_node(&av->scripts[0]), TOKEN_V);
    const policy_node_t *right = r_policy_node(&av->scripts[1]);

    // Timelocked: and_v(v:$sub, $timelock). $sub must classify recursively,
    // and $timelock must be older() or after().
    ct_timelock_t tl;
    if (match_lock_value(right, &tl)) {
        ct_leaf_match_t sub_match;
        if (match_tapleaf(left_inner, &sub_match) && sub_match.cls != TC_OTHER) {
            out->cls = TC_TIMELOCKED;
            set_binding_sub(&out->bindings, 0, left_inner);
            set_binding_timelock(&out->bindings, 1, tl);
            out->bindings.n = 2;
            return true;
        }
        return false;
    }

    // AndV: and_v(v:$sub1, $sub2). Both subs must classify recursively.
    {
        ct_leaf_match_t s1, s2;
        if (match_tapleaf(left_inner, &s1) && s1.cls != TC_OTHER && match_tapleaf(right, &s2) &&
            s2.cls != TC_OTHER) {
            out->cls = TC_AND_V;
            set_binding_sub(&out->bindings, 0, left_inner);
            set_binding_sub(&out->bindings, 1, right);
            out->bindings.n = 2;
            return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// Top-level matcher
// ---------------------------------------------------------------------------

static bool match_top_level(const policy_node_t *root, ct_top_match_t *out) {
    out->cls = DC_OTHER;
    out->bindings.n = 0;
    out->taptree = NULL;
    if (root == NULL) return false;

    // pkh($key)
    if (root->type == TOKEN_PKH) {
        const policy_node_with_key_t *w = (const policy_node_with_key_t *) root;
        out->cls = DC_LEGACY_SINGLE_SIG;
        set_binding_key(&out->bindings, 0, r_policy_node_keyexpr(&w->key));
        out->bindings.n = 1;
        return true;
    }

    // wpkh($key)
    if (root->type == TOKEN_WPKH) {
        const policy_node_with_key_t *w = (const policy_node_with_key_t *) root;
        out->cls = DC_SEGWIT_SINGLE_SIG;
        set_binding_key(&out->bindings, 0, r_policy_node_keyexpr(&w->key));
        out->bindings.n = 1;
        return true;
    }

    // sh(wpkh($key))
    if (root->type == TOKEN_SH) {
        const policy_node_with_script_t *sh = (const policy_node_with_script_t *) root;
        const policy_node_t *inner = r_policy_node(&sh->script);
        if (inner != NULL && inner->type == TOKEN_WPKH) {
            const policy_node_with_key_t *w = (const policy_node_with_key_t *) inner;
            out->cls = DC_SEGWIT_SINGLE_SIG;
            set_binding_key(&out->bindings, 0, r_policy_node_keyexpr(&w->key));
            out->bindings.n = 1;
            return true;
        }
        // sh(wsh(multi|sortedmulti))
        if (inner != NULL && inner->type == TOKEN_WSH) {
            const policy_node_with_script_t *wsh = (const policy_node_with_script_t *) inner;
            const policy_node_t *inner2 = r_policy_node(&wsh->script);
            if (inner2 != NULL &&
                (inner2->type == TOKEN_MULTI || inner2->type == TOKEN_SORTEDMULTI)) {
                const policy_node_multisig_t *m = (const policy_node_multisig_t *) inner2;
                out->cls = DC_SEGWIT_MULTISIG;
                set_binding_number(&out->bindings, 0, m->k);
                set_binding_keys(&out->bindings, 1, r_policy_node_keyexpr(&m->keys), m->n);
                out->bindings.n = 2;
                return true;
            }
        }
    }

    // wsh(multi|sortedmulti)
    if (root->type == TOKEN_WSH) {
        const policy_node_with_script_t *wsh = (const policy_node_with_script_t *) root;
        const policy_node_t *inner = r_policy_node(&wsh->script);
        if (inner != NULL && (inner->type == TOKEN_MULTI || inner->type == TOKEN_SORTEDMULTI)) {
            const policy_node_multisig_t *m = (const policy_node_multisig_t *) inner;
            out->cls = DC_SEGWIT_MULTISIG;
            set_binding_number(&out->bindings, 0, m->k);
            set_binding_keys(&out->bindings, 1, r_policy_node_keyexpr(&m->keys), m->n);
            out->bindings.n = 2;
            return true;
        }
    }

    // tr($internal_key, $leaves?) or tr(musig(...), $leaves?). A leaf-less
    // taproot (key-path spend only) classifies as the *_KEY_ONLY variant, which
    // carries standalone wording; a taproot with a tree keeps the "Main path:"
    // variant followed by per-leaf lines.
    if (root->type == TOKEN_TR) {
        const policy_node_tr_t *tr = (const policy_node_tr_t *) root;
        const policy_node_keyexpr_t *kx = r_policy_node_keyexpr(&tr->key);
        bool has_tree = !isnull_policy_node_tree(&tr->tree);
        out->taptree = has_tree ? r_policy_node_tree(&tr->tree) : NULL;
        if (kx->type == KEY_EXPRESSION_NORMAL) {
            out->cls = has_tree ? DC_TAPROOT : DC_TAPROOT_KEY_ONLY;
            set_binding_key(&out->bindings, 0, kx);
            out->bindings.n = 1;
            return true;
        }
        // KEY_EXPRESSION_MUSIG
        const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&kx->m.musig_info);
        out->cls = has_tree ? DC_TAPROOT_MUSIG : DC_TAPROOT_MUSIG_KEY_ONLY;
        set_binding_number(&out->bindings, 0, mi->n);
        // Pass the keyexpr itself as the keys binding, signaling a musig list.
        set_binding_keys(&out->bindings, 1, kx, 1);
        out->bindings.n = 2;
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Tap-leaf display ordering (port of mod.rs::display_cmp)
// ---------------------------------------------------------------------------

// Number of effective member keys in a multisig `$keys` binding. For a
// multi_a/sortedmulti_a list this is the list length; for the pk(musig(...))
// sentinel (n == 1, a single musig keyexpr) it is the musig member count.
static uint16_t keys_member_count(const ct_value_t *v) {
    if (v->u.keys.n == 1 && v->u.keys.array != NULL &&
        v->u.keys.array[0].type == KEY_EXPRESSION_MUSIG) {
        return r_musig_aggr_key_info(&v->u.keys.array[0].m.musig_info)->n;
    }
    return v->u.keys.n;
}

// The j-th effective member key index of a multisig `$keys` binding.
static uint32_t keys_member_index(const ct_value_t *v, uint16_t j) {
    if (v->u.keys.n == 1 && v->u.keys.array != NULL &&
        v->u.keys.array[0].type == KEY_EXPRESSION_MUSIG) {
        const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&v->u.keys.array[0].m.musig_info);
        return r_uint16(&mi->key_indexes)[j];
    }
    return v->u.keys.array[j].k.key_index;
}

// Compare two multisig `$keys` bindings element by element by key index
// (derivation-independent). Used as a tie-breaker once the lists are known to
// be the same length, so that two same-size, same-threshold multisig leaves
// order deterministically by their keys rather than by tap-tree position
// (which is unstable across descriptors that share a cleartext rendering).
// Mirrors `cmp_keys`/`cmp_key` in the reference implementation.
static int cmp_binding_keys(const ct_value_t *a, const ct_value_t *b) {
    uint16_t na = keys_member_count(a);
    uint16_t nb = keys_member_count(b);
    uint16_t m = (na < nb) ? na : nb;
    for (uint16_t i = 0; i < m; i++) {
        uint32_t ia = keys_member_index(a, i);
        uint32_t ib = keys_member_index(b, i);
        if (ia != ib) return (ia < ib) ? -1 : 1;
    }
    return 0;
}

// Compare two matched tapleaves. Order primarily by class enum value, then
// by binding values. SUB bindings recurse; TIMELOCK bindings compare by
// is_relative ascending (relative < absolute) then by raw value.
static int leaf_cmp(const ct_leaf_match_t *a, const ct_leaf_match_t *b) {
    if (a->cls != b->cls) return (a->cls < b->cls) ? -1 : 1;
    for (uint8_t i = 0; i < a->bindings.n && i < b->bindings.n; i++) {
        const ct_value_t *va = &a->bindings.v[i];
        const ct_value_t *vb = &b->bindings.v[i];
        if (va->kind != vb->kind) return (va->kind < vb->kind) ? -1 : 1;
        switch (va->kind) {
            case CT_BV_KEY: {
                const policy_node_keyexpr_t *ka = va->u.key;
                const policy_node_keyexpr_t *kb = vb->u.key;
                if (ka->type != kb->type) return (ka->type < kb->type) ? -1 : 1;
                if (ka->type == KEY_EXPRESSION_NORMAL) {
                    if (ka->k.key_index != kb->k.key_index)
                        return (ka->k.key_index < kb->k.key_index) ? -1 : 1;
                }
                if (ka->num_first != kb->num_first) return (ka->num_first < kb->num_first) ? -1 : 1;
                if (ka->num_second != kb->num_second)
                    return (ka->num_second < kb->num_second) ? -1 : 1;
                break;
            }
            case CT_BV_KEYS: {
                if (va->u.keys.n != vb->u.keys.n) return (va->u.keys.n < vb->u.keys.n) ? -1 : 1;
                // Tie-break by the keys themselves, so multisig leaves that
                // share a size and threshold still order deterministically.
                int r = cmp_binding_keys(va, vb);
                if (r != 0) return r;
                break;
            }
            case CT_BV_NUMBER:
                if (va->u.number != vb->u.number) return (va->u.number < vb->u.number) ? -1 : 1;
                break;
            case CT_BV_SUB: {
                ct_leaf_match_t la, lb;
                if (!match_tapleaf(va->u.sub, &la)) la.cls = TC_OTHER;
                if (!match_tapleaf(vb->u.sub, &lb)) lb.cls = TC_OTHER;
                int r = leaf_cmp(&la, &lb);
                if (r != 0) return r;
                break;
            }
            case CT_BV_TIMELOCK:
                if (va->u.timelock.is_relative != vb->u.timelock.is_relative)
                    return va->u.timelock.is_relative ? -1 : 1;
                if (va->u.timelock.raw != vb->u.timelock.raw)
                    return (va->u.timelock.raw < vb->u.timelock.raw) ? -1 : 1;
                break;
            default:
                break;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Renderer — appends formatted parts to a fixed-size buffer.
// ---------------------------------------------------------------------------

static int append_str(char *out, size_t cap, size_t *off, const char *s) {
    size_t l = strlen(s);
    if (*off + l + 1 > cap) return -1;
    memcpy(out + *off, s, l);
    *off += l;
    out[*off] = 0;
    return 0;
}

static int append_keyexpr(char *out, size_t cap, size_t *off, const policy_node_keyexpr_t *key) {
    if (key->type == KEY_EXPRESSION_NORMAL) {
        char buf[8];
        snprintf(buf, sizeof(buf), "@%u", key->k.key_index);
        return append_str(out, cap, off, buf);
    }
    // KEY_EXPRESSION_MUSIG: "musig(@a,@b,@c)"
    const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&key->m.musig_info);
    const uint16_t *idx = r_uint16(&mi->key_indexes);
    if (append_str(out, cap, off, "musig(") < 0) return -1;
    for (uint16_t i = 0; i < mi->n; i++) {
        char buf[8];
        snprintf(buf, sizeof(buf), "@%u", idx[i]);
        if (append_str(out, cap, off, buf) < 0) return -1;
        if (i + 1 < mi->n) {
            if (append_str(out, cap, off, ",") < 0) return -1;
        }
    }
    return append_str(out, cap, off, ")");
}

static int append_keys_list(char *out,
                            size_t cap,
                            size_t *off,
                            const policy_node_keyexpr_t *keys,
                            uint16_t n) {
    // Special case: musig list passed through as a single keyexpr (n == 1
    // sentinel, set by `match_multisig_like` for pk(musig(...)) and by
    // `match_top_level` for TaprootMusig). In that case render the inner
    // keys as a flat Oxford-comma list (without "musig(...)" wrapping).
    if (n == 1 && keys->type == KEY_EXPRESSION_MUSIG) {
        const musig_aggr_key_info_t *mi = r_musig_aggr_key_info(&keys->m.musig_info);
        const uint16_t *idx = r_uint16(&mi->key_indexes);
        uint16_t m = mi->n;
        for (uint16_t i = 0; i < m; i++) {
            if (i > 0) {
                if (i == m - 1) {
                    if (append_str(out, cap, off, " and ") < 0) return -1;
                } else {
                    if (append_str(out, cap, off, ", ") < 0) return -1;
                }
            }
            char buf[8];
            snprintf(buf, sizeof(buf), "@%u", idx[i]);
            if (append_str(out, cap, off, buf) < 0) return -1;
        }
        return 0;
    }

    // Plain Oxford-comma list of keyexprs.
    for (uint16_t i = 0; i < n; i++) {
        if (i > 0) {
            if (i == n - 1) {
                if (append_str(out, cap, off, " and ") < 0) return -1;
            } else {
                if (append_str(out, cap, off, ", ") < 0) return -1;
            }
        }
        if (append_keyexpr(out, cap, off, &keys[i]) < 0) return -1;
    }
    return 0;
}

static int append_uint32(char *out, size_t cap, size_t *off, uint32_t v) {
    char buf[12];
    snprintf(buf, sizeof(buf), "%u", v);
    return append_str(out, cap, off, buf);
}

// Civil from days (Howard Hinnant, integer arithmetic only, valid for all
// reasonable Unix timestamps).
static void civil_from_unix(uint32_t secs,
                            int *y,
                            unsigned *m,
                            unsigned *d,
                            unsigned *hh,
                            unsigned *mm,
                            unsigned *ss) {
    int32_t z = (int32_t) (secs / 86400u);
    uint32_t rem = secs % 86400u;
    *hh = rem / 3600u;
    rem %= 3600u;
    *mm = rem / 60u;
    *ss = rem % 60u;
    z += 719468;
    int32_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint32_t doe = (uint32_t) (z - era * 146097);
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int32_t yyy = (int32_t) yoe + era * 400;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int) (yyy + (*m <= 2 ? 1 : 0));
}

// Appends a number of seconds as a human-readable duration with spelled-out,
// pluralized units (so a non-technical reader can't mistake "m" for months).
// Renders "0 seconds" for zero. Mirrors `format_seconds` in the reference
// time.rs. Example: "1 day 2 hours 30 minutes".
static int append_duration(char *out, size_t cap, size_t *off, uint32_t secs) {
    uint32_t days = secs / 86400u;
    uint32_t hours = (secs % 86400u) / 3600u;
    uint32_t minutes = (secs % 3600u) / 60u;
    uint32_t seconds = secs % 60u;
    char buf[16];
    bool any = false;
    if (days > 0) {
        snprintf(buf, sizeof(buf), "%u ", days);
        if (append_str(out, cap, off, buf) < 0) return -1;
        if (append_str(out, cap, off, days == 1 ? "day" : "days") < 0) return -1;
        any = true;
    }
    if (hours > 0) {
        if (any && append_str(out, cap, off, " ") < 0) return -1;
        snprintf(buf, sizeof(buf), "%u ", hours);
        if (append_str(out, cap, off, buf) < 0) return -1;
        if (append_str(out, cap, off, hours == 1 ? "hour" : "hours") < 0) return -1;
        any = true;
    }
    if (minutes > 0) {
        if (any && append_str(out, cap, off, " ") < 0) return -1;
        snprintf(buf, sizeof(buf), "%u ", minutes);
        if (append_str(out, cap, off, buf) < 0) return -1;
        if (append_str(out, cap, off, minutes == 1 ? "minute" : "minutes") < 0) return -1;
        any = true;
    }
    if (seconds > 0 || !any) {
        if (any && append_str(out, cap, off, " ") < 0) return -1;
        snprintf(buf, sizeof(buf), "%u ", seconds);
        if (append_str(out, cap, off, buf) < 0) return -1;
        if (append_str(out, cap, off, seconds == 1 ? "second" : "seconds") < 0) return -1;
    }
    return 0;
}

// Unified timelock formatter. Relative locks (counted from when the coins were
// received) end in "after receiving"; absolute locks (a fixed point) read
// "not before ...". Produces one of:
//   - "<N> blocks after receiving"      — relative height (raw without flag)
//   - "<duration> after receiving"      — relative time (raw with flag, ×512s)
//   - "not before block <N>"            — absolute height (raw < LOCKTIME_THRESHOLD)
//   - "not before YYYY-MM-DD[ HH:MM:SS] UTC" — absolute timestamp (raw >= threshold)
static int append_timelock(char *out, size_t cap, size_t *off, ct_timelock_t tl) {
    char buf[40];
    if (tl.is_relative) {
        if (tl.raw & SEQUENCE_LOCKTIME_TYPE_FLAG) {
            uint32_t units = tl.raw & ~SEQUENCE_LOCKTIME_TYPE_FLAG;
            if (append_duration(out, cap, off, units * 512u) < 0) return -1;
            return append_str(out, cap, off, " after receiving");
        }
        snprintf(buf, sizeof(buf), "%u blocks after receiving", tl.raw);
        return append_str(out, cap, off, buf);
    }
    // Absolute.
    if (tl.raw < LOCKTIME_THRESHOLD) {
        snprintf(buf, sizeof(buf), "not before block %u", tl.raw);
        return append_str(out, cap, off, buf);
    }
    {
        int y;
        unsigned mo, d, hh, mm, ss;
        civil_from_unix(tl.raw, &y, &mo, &d, &hh, &mm, &ss);
        if (append_str(out, cap, off, "not before ") < 0) return -1;
        if (hh == 0 && mm == 0 && ss == 0) {
            snprintf(buf, sizeof(buf), "%04d-%02u-%02u", y, mo, d);
        } else {
            snprintf(buf, sizeof(buf), "%04d-%02u-%02u %02u:%02u:%02u", y, mo, d, hh, mm, ss);
        }
        if (append_str(out, cap, off, buf) < 0) return -1;
        return append_str(out, cap, off, " UTC");
    }
}

// Renders a spec into an existing buffer at offset `*off`, recursing into
// SUB bindings. `*off` is updated to point past the appended bytes.
static int render_spec_at(const cleartext_spec_t *spec,
                          const ct_bindings_t *b,
                          char *out,
                          size_t cap,
                          size_t *off) {
    // `spec->parts` is a pointer field stored inside a `const` table in
    // flash; on Ledger devices flash pointer fields hold link-time addresses
    // and must be relocated through PIC() before being dereferenced.
    const cleartext_part_t *parts = (const cleartext_part_t *) PIC(spec->parts);
    for (uint8_t i = 0; i < spec->n_parts; i++) {
        const cleartext_part_t *p = &parts[i];
        if (p->kind == CT_PART_LITERAL) {
            if (append_str(out, cap, off, &ct_string_pool[p->lit_off]) < 0) return -1;
            continue;
        }
        const ct_value_t *val = &b->v[p->binding_idx];
        switch (p->kind) {
            case CT_PART_KEY:
                if (append_keyexpr(out, cap, off, val->u.key) < 0) return -1;
                break;
            case CT_PART_KEYS:
                if (append_keys_list(out, cap, off, val->u.keys.array, val->u.keys.n) < 0)
                    return -1;
                break;
            case CT_PART_THRESHOLD:
                if (append_uint32(out, cap, off, val->u.number) < 0) return -1;
                break;
            case CT_PART_TIMELOCK:
                if (append_timelock(out, cap, off, val->u.timelock) < 0) return -1;
                break;
            case CT_PART_SUB: {
                ct_leaf_match_t sub_lm;
                if (!match_tapleaf(val->u.sub, &sub_lm) || sub_lm.cls == TC_OTHER) {
                    return -1;
                }
                const cleartext_spec_t *sub_spec = &CT_TAPLEAF_SPECS[sub_lm.cls];
                if (render_spec_at(sub_spec, &sub_lm.bindings, out, cap, off) < 0) return -1;
                break;
            }
            default:
                return -1;
        }
    }
    return 0;
}

static int render_spec(const cleartext_spec_t *spec,
                       const ct_bindings_t *b,
                       char *out,
                       size_t cap) {
    size_t off = 0;
    if (cap == 0) return -1;
    out[0] = 0;
    return render_spec_at(spec, b, out, cap, &off);
}

// ---------------------------------------------------------------------------
// Taptree iteration: collect all leaves into a flat array.
// ---------------------------------------------------------------------------

#define CT_MAX_TAP_LEAVES 64  // bound by MAX_TAPTREE_POLICY_DEPTH (=9 -> up to 256, but we cap)

static int collect_leaves(const policy_node_tree_t *tree,
                          const policy_node_t **out,
                          int *n,
                          int max) {
    if (tree == NULL) return 0;
    if (tree->is_leaf) {
        if (*n >= max) return -1;
        out[(*n)++] = r_policy_node(&tree->script);
        return 0;
    }
    if (collect_leaves(r_policy_node_tree(&tree->left_tree), out, n, max) < 0) return -1;
    return collect_leaves(r_policy_node_tree(&tree->right_tree), out, n, max);
}

// ---------------------------------------------------------------------------
// Confusion score
// ---------------------------------------------------------------------------

// Recursive per-leaf score: multiplies the leaf's own admitting-pattern count
// with the per-leaf scores of any SUB-bound sub-policies. Mirrors the
// upstream Rust `per_leaf_score` generated by build.rs.
static uint64_t leaf_score(const ct_leaf_match_t *lm) {
    if (lm == NULL || lm->cls == TC_OTHER) return 1;
    const cleartext_spec_t *spec = &CT_TAPLEAF_SPECS[lm->cls];
    uint64_t s = admitting_pattern_count(spec, &lm->bindings);
    for (uint8_t i = 0; i < lm->bindings.n; i++) {
        if (lm->bindings.v[i].kind == CT_BV_SUB) {
            ct_leaf_match_t sub_lm;
            uint64_t sub_s = 1;
            if (match_tapleaf(lm->bindings.v[i].u.sub, &sub_lm)) {
                sub_s = leaf_score(&sub_lm);
            }
            s = sat_mul_u64(s, sub_s);
        }
    }
    return s;
}

uint64_t cleartext_confusion_score(const policy_node_t *root) {
    ct_top_match_t top;
    if (!match_top_level(root, &top) || top.cls == DC_OTHER) {
        return 1;
    }

    const cleartext_spec_t *top_spec = &CT_TOP_LEVEL_SPECS[top.cls];
    uint64_t score = admitting_pattern_count(top_spec, &top.bindings);

    if (top.cls == DC_TAPROOT || top.cls == DC_TAPROOT_MUSIG) {
        // Collect leaves.
        const policy_node_t *leaves[CT_MAX_TAP_LEAVES];
        int n_leaves = 0;
        if (top.taptree != NULL) {
            if (collect_leaves(top.taptree, leaves, &n_leaves, CT_MAX_TAP_LEAVES) < 0) {
                return UINT64_MAX;
            }
        }
        for (int i = 0; i < n_leaves; i++) {
            ct_leaf_match_t lm;
            if (!match_tapleaf(leaves[i], &lm)) {
                lm.cls = TC_OTHER;
                lm.bindings.n = 0;
            }
            score = sat_mul_u64(score, leaf_score(&lm));
        }
        if (n_leaves > 1) {
            // (2n - 3)!! = 1 * 3 * 5 * ... * (2n - 3)
            for (int i = 1; i <= 2 * n_leaves - 3; i += 2) {
                score = sat_mul_u64(score, (uint64_t) i);
            }
        }
    }

    bool canonical = true;
    uint64_t orderings = key_orderings_count(root, &canonical);
    score = sat_mul_u64(score, orderings);
    return score;
}

// Capitalize the first character of a finished top-level cleartext line if it is
// a lowercase ASCII letter. Tapleaf specs are written lowercase so they read
// correctly when composed mid-sentence inside another leaf (e.g. as the second
// operand of an `and_v`); this fixes up only the leading character of each fully
// assembled line, leaving composed sub-policies lowercase. Mirrors
// `capitalize_first` in the reference mod.rs.
static void capitalize_first(char *s) {
    if (s[0] >= 'a' && s[0] <= 'z') {
        s[0] = (char) (s[0] - 'a' + 'A');
    }
}

// ---------------------------------------------------------------------------
// Top-level encoder
// ---------------------------------------------------------------------------

int cleartext_encode(const policy_node_t *root,
                     const char *raw_template,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext) {
    *out_n_lines = 0;
    *out_has_cleartext = false;

    bool canonical = true;
    (void) key_orderings_count(root, &canonical);
    if (!canonical) {
        if (raw_template == NULL) return 0;
        size_t l = strlen(raw_template);
        if (l > CT_MAX_LINE_LEN) l = CT_MAX_LINE_LEN;
        memcpy(out_lines[0], raw_template, l);
        out_lines[0][l] = 0;
        *out_n_lines = 1;
        *out_has_cleartext = false;
        return 1;
    }

    ct_top_match_t top;
    if (!match_top_level(root, &top) || top.cls == DC_OTHER) {
        if (raw_template == NULL) return 0;
        size_t l = strlen(raw_template);
        if (l > CT_MAX_LINE_LEN) l = CT_MAX_LINE_LEN;
        memcpy(out_lines[0], raw_template, l);
        out_lines[0][l] = 0;
        *out_n_lines = 1;
        *out_has_cleartext = false;
        return 1;
    }

    // Render the primary line.
    const cleartext_spec_t *top_spec = &CT_TOP_LEVEL_SPECS[top.cls];
    if (render_spec(top_spec, &top.bindings, out_lines[0], CT_MAX_LINE_LEN + 1) < 0) return -1;
    capitalize_first(out_lines[0]);
    *out_n_lines = 1;

    if (top.cls != DC_TAPROOT && top.cls != DC_TAPROOT_MUSIG) {
        *out_has_cleartext = true;
        return 1;
    }

    // Collect leaves.
    const policy_node_t *raw_leaves[CT_MAX_TAP_LEAVES];
    int n_leaves = 0;
    if (top.taptree != NULL) {
        if (collect_leaves(top.taptree, raw_leaves, &n_leaves, CT_MAX_TAP_LEAVES) < 0) return -1;
    }
    if (n_leaves == 0) {
        *out_has_cleartext = true;
        return 1;
    }
    if ((size_t) n_leaves + 1 > CT_MAX_LINES) return -1;

    // Match each leaf and sort by display order.
    ct_leaf_match_t leaves[CT_MAX_LINES - 1];
    for (int i = 0; i < n_leaves; i++) {
        if (!match_tapleaf(raw_leaves[i], &leaves[i])) {
            leaves[i].cls = TC_OTHER;
            leaves[i].leaf_script = raw_leaves[i];
            leaves[i].bindings.n = 0;
        }
    }

    // Insertion sort (n small).
    for (int i = 1; i < n_leaves; i++) {
        ct_leaf_match_t tmp = leaves[i];
        int j = i - 1;
        while (j >= 0 && leaf_cmp(&leaves[j], &tmp) > 0) {
            leaves[j + 1] = leaves[j];
            j--;
        }
        leaves[j + 1] = tmp;
    }

    bool all_have_cleartext = true;
    for (int i = 0; i < n_leaves; i++) {
        size_t line_idx = (size_t) i + 1;
        if (leaves[i].cls == TC_OTHER) {
            // Use the raw descriptor template as fallback for this leaf:
            // we don't have an in-memory string for an arbitrary subtree, so
            // fall back to the whole descriptor template.
            all_have_cleartext = false;
            if (raw_template == NULL) {
                out_lines[line_idx][0] = 0;
            } else {
                size_t l = strlen(raw_template);
                if (l > CT_MAX_LINE_LEN) l = CT_MAX_LINE_LEN;
                memcpy(out_lines[line_idx], raw_template, l);
                out_lines[line_idx][l] = 0;
            }
        } else {
            const cleartext_spec_t *leaf_spec = &CT_TAPLEAF_SPECS[leaves[i].cls];
            if (render_spec(leaf_spec,
                            &leaves[i].bindings,
                            out_lines[line_idx],
                            CT_MAX_LINE_LEN + 1) < 0) {
                return -1;
            }
            capitalize_first(out_lines[line_idx]);
        }
    }
    *out_n_lines = (size_t) n_leaves + 1;
    *out_has_cleartext = all_have_cleartext;
    return 1;
}
