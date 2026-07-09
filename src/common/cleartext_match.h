#pragma once

// Shared runtime support for the *generated* cleartext classifier
// (cleartext_match.c, produced by specs/bip388/gen.py).
//
// This header is hand-written and stable: it holds the match-result types and
// the small runtime primitives that the generated `match_top_level` /
// `match_tapleaf` functions call. The generated classifier mirrors the
// `patterns` of specs/bip388/cleartext.toml; editing those patterns regenerates
// cleartext_match.c without touching this header or cleartext.c.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/wallet.h"
#include "common/cleartext_specs.h"
#include "constants.h"  // SEQUENCE_LOCKTIME_TYPE_FLAG, LOCKTIME_THRESHOLD

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

// ---------------------------------------------------------------------------
// Binding setters used by the generated classifier.
// ---------------------------------------------------------------------------

static inline void set_binding_key(ct_bindings_t *b, int i, const policy_node_keyexpr_t *k) {
    b->v[i].kind = CT_BV_KEY;
    b->v[i].u.key = k;
}

static inline void set_binding_keys(ct_bindings_t *b,
                                    int i,
                                    const policy_node_keyexpr_t *arr,
                                    uint16_t n) {
    b->v[i].kind = CT_BV_KEYS;
    b->v[i].u.keys.array = arr;
    b->v[i].u.keys.n = n;
}

static inline void set_binding_number(ct_bindings_t *b, int i, uint32_t v) {
    b->v[i].kind = CT_BV_NUMBER;
    b->v[i].u.number = v;
}

static inline void set_binding_sub(ct_bindings_t *b, int i, const policy_node_t *sub) {
    b->v[i].kind = CT_BV_SUB;
    b->v[i].u.sub = sub;
}

static inline void set_binding_timelock(ct_bindings_t *b, int i, ct_timelock_t tl) {
    b->v[i].kind = CT_BV_TIMELOCK;
    b->v[i].u.timelock = tl;
}

// Match a unified timelock node: returns true if `node` is `older($n)` or
// `after($n)`, and fills `*out` with raw + is_relative. The wallet-policy
// parser already validates locktime ranges, so no extra range guard is needed
// here (the tree only ever holds in-range older()/after() values).
static inline bool match_lock_value(const policy_node_t *node, ct_timelock_t *out) {
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

// ---------------------------------------------------------------------------
// Generated classifier entry points (defined in cleartext_match.c).
// ---------------------------------------------------------------------------

// Classify the root of a descriptor template. Returns true and fills *out on a
// match; on no match returns false with out->cls == DC_OTHER.
bool match_top_level(const policy_node_t *root, ct_top_match_t *out);

// Classify a single tap-leaf script. Returns true and fills *out on a match;
// on no match returns false with out->cls == TC_OTHER (out->leaf_script set to
// the unmatched node for raw rendering).
bool match_tapleaf(const policy_node_t *leaf_script, ct_leaf_match_t *out);
