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
#include "common/cleartext_match.h"
#include "common/wallet.h"
#include "constants.h"  // SEQUENCE_LOCKTIME_TYPE_FLAG, LOCKTIME_THRESHOLD
#include "policy.h"     // get_keyexpr_by_index

#include "ledger_assert.h"
#include "os_pic.h"

// Placeholder rendered for a tap-leaf whose spending policy has no cleartext
// form. We don't have an unparser, nor a pointer from the leaf node to the
// original substring of the descriptor template. Therefore, we only print the
// fixed string "(unknown)", and *out_has_cleartext is set to false
// (see cleartext_encode).
#define CT_UNKNOWN_LEAF "(unknown)"

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
//
// The match-result types (ct_value_t, ct_bindings_t, ct_top_match_t,
// ct_leaf_match_t, ct_timelock_t), the set_binding_* helpers, match_lock_value,
// and the match_top_level / match_tapleaf classifier (the latter generated into
// cleartext_match.c from specs/bip388/cleartext.toml) all live in
// common/cleartext_match.h.

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
static uint16_t keys_member_count(const ct_value_t *v);

// ---------------------------------------------------------------------------
// Score helpers (per-class admittance count)
// ---------------------------------------------------------------------------

// Scans `b` for its first CT_BV_NUMBER (threshold) and first CT_BV_KEYS (keys)
// bindings — the binding order in our specs is always:
//   - top_level / leaf multisig: [threshold, keys, ...]
//   - top_level Taproot/TaprootMusig: [internal_key or threshold, ...]
// `keys_member_count` resolves the pk(musig(...)) sentinel (a single musig
// keyexpr) to its effective member count. Returns whether both were found.
static bool find_threshold_and_keys(const ct_bindings_t *b,
                                    uint32_t *out_threshold,
                                    uint32_t *out_n_keys) {
    bool has_threshold = false;
    bool has_keys = false;
    for (uint8_t i = 0; i < b->n; i++) {
        const ct_value_t *v = &b->v[i];
        if (v->kind == CT_BV_NUMBER && !has_threshold) {
            has_threshold = true;
            *out_threshold = v->u.number;
        } else if (v->kind == CT_BV_KEYS && !has_keys) {
            has_keys = true;
            *out_n_keys = keys_member_count(v);
        }
    }
    return has_threshold && has_keys;
}

// Returns the number of patterns that admit the matched bindings.
// For multisig-bearing classes, the musig patterns admit iff
// threshold == n_keys; otherwise they are excluded from the count.
static uint8_t admitting_pattern_count(const cleartext_spec_t *spec, const ct_bindings_t *b) {
    uint8_t n_all = spec->n_patterns;

    // Classes without musig patterns: every pattern always admits.
    if (spec->n_musig_patterns == 0) return n_all;

    // Classes with musig patterns but no threshold/keys pair to test always
    // admit them (e.g. TaprootMusig top-level, whose binding is a single KEYS
    // list).
    uint32_t threshold, n_keys;
    if (!find_threshold_and_keys(b, &threshold, &n_keys)) return n_all;

    // Otherwise the musig patterns admit only in the n-of-n case.
    bool musig_admits = (threshold == n_keys);
    return musig_admits ? n_all : (uint8_t) (n_all - spec->n_musig_patterns);
}

// ---------------------------------------------------------------------------
// Key-derivation helpers (canonical check + ordering factor)
// ---------------------------------------------------------------------------

// Fixed-size table for grouping equivalent keyexprs. The actual maximum is
// bounded by total occurrences (taproot can fit a lot in 512-byte templates,
// but in practice ≤ ~30 occurrences).
#define CT_MAX_KEYEXPRS 32

typedef struct {
    // Canonical identity: the first key expression seen in the group. Equality
    // is determined via are_key_placeholders_identical (from policy.h).
    const policy_node_keyexpr_t *repr;
    // Derivation pairs collected for this class.
    uint32_t pairs[CT_MAX_KEYEXPRS][2];
    uint8_t n_pairs;
} ct_keyexpr_class_t;

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
    int n = get_keyexpr_by_index(root, 0, NULL, NULL);
    if (n < 0 || n > CT_MAX_KEYEXPRS) {
        // Error, or too many keyexprs to fit — treat as not canonical, and
        // return saturating value.
        *out_canonical = false;
        return UINT64_MAX;
    }
    if (n == 0) {
        *out_canonical = true;
        return 1;
    }

    const policy_node_keyexpr_t *kx[CT_MAX_KEYEXPRS];
    for (int i = 0; i < n; i++) {
        policy_node_keyexpr_t *k;
        if (get_keyexpr_by_index(root, i, NULL, &k) < 0) {
            *out_canonical = false;
            return UINT64_MAX;
        }
        kx[i] = k;
    }

    // Group by identity. classes[i].repr is the first keyexpr in the group;
    // classes[i].pairs collects (num_first, num_second) for each occurrence.
    ct_keyexpr_class_t classes[CT_MAX_KEYEXPRS];
    int n_classes = 0;

    for (int i = 0; i < n; i++) {
        const policy_node_keyexpr_t *k = kx[i];
        int idx = -1;
        for (int j = 0; j < n_classes; j++) {
            if (are_key_placeholders_identical(classes[j].repr, k)) {
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

static int compare_uint16(uint16_t left, uint16_t right) {
    if (left == right) return 0;
    return (left < right) ? -1 : 1;
}

static int compare_uint32(uint32_t left, uint32_t right) {
    if (left == right) return 0;
    return (left < right) ? -1 : 1;
}

static int compare_musig_keyexprs(const policy_node_keyexpr_t *left,
                                  const policy_node_keyexpr_t *right) {
    const musig_aggr_key_info_t *left_info = r_musig_aggr_key_info(&left->m.musig_info);
    const musig_aggr_key_info_t *right_info = r_musig_aggr_key_info(&right->m.musig_info);
    int order = compare_uint16(left_info->n, right_info->n);
    if (order != 0) return order;

    const uint16_t *left_indexes = r_uint16(&left_info->key_indexes);
    const uint16_t *right_indexes = r_uint16(&right_info->key_indexes);
    for (uint16_t i = 0; i < left_info->n; i++) {
        order = compare_uint16(left_indexes[i], right_indexes[i]);
        if (order != 0) return order;
    }
    return 0;
}

static int compare_keyexprs(const policy_node_keyexpr_t *left, const policy_node_keyexpr_t *right) {
    int order = compare_uint32((uint32_t) left->type, (uint32_t) right->type);
    if (order != 0) return order;

    if (left->type == KEY_EXPRESSION_NORMAL) {
        return compare_uint32(left->k.key_index, right->k.key_index);
    }
    return compare_musig_keyexprs(left, right);
}

static int compare_timelocks(ct_timelock_t left, ct_timelock_t right) {
    if (left.is_relative != right.is_relative) return left.is_relative ? -1 : 1;
    return compare_uint32(left.raw, right.raw);
}

static int compare_sub_bindings(const policy_node_t *left, const policy_node_t *right) {
    ct_leaf_match_t left_match, right_match;
    if (!match_tapleaf(left, &left_match)) left_match.cls = TC_OTHER;
    if (!match_tapleaf(right, &right_match)) right_match.cls = TC_OTHER;
    return leaf_cmp(&left_match, &right_match);
}

static int compare_non_key_list_bindings(const ct_value_t *left, const ct_value_t *right) {
    switch (left->kind) {
        case CT_BV_KEY:
            return compare_keyexprs(left->u.key, right->u.key);
        case CT_BV_NUMBER:
            return compare_uint32(left->u.number, right->u.number);
        case CT_BV_SUB:
            return compare_sub_bindings(left->u.sub, right->u.sub);
        case CT_BV_TIMELOCK:
            return compare_timelocks(left->u.timelock, right->u.timelock);
        case CT_BV_NONE:
        case CT_BV_KEYS:
            return 0;
    }
    return 0;
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
        int order = compare_uint32(ia, ib);
        if (order != 0) return order;
    }
    return 0;
}

// Compare two matched tapleaves. Order primarily by class enum value, then by
// binding values.
//
// The reference orders multisig leaves by `keys.len() -> threshold -> cmp_keys`
// (TapleafClass::display_cmp): number of keys first, then the threshold, then
// the keys element-by-element. A leaf's `$threshold` binding precedes its
// `$keys` binding, so comparing the bindings in a single positional pass would
// instead order by threshold before the key count (and by the keys before the
// threshold) -- a different order whenever the two leaves' key count and
// threshold disagree (e.g. 3-of-3 vs 2-of-5).
//
// To mirror the reference exactly we compare the bindings in three priority
// tiers, keyed purely on binding *kind* (not class identity):
//   1. KEYS member count;
//   2. every other kind, in binding order (KEY/NUMBER/SUB/TIMELOCK);
//   3. KEYS member indices (the `cmp_keys` tie-break).
// For non-multisig classes there is no KEYS binding, so tiers 1 and 3 are empty
// and this reduces to a plain positional comparison. SUB bindings recurse;
// TIMELOCK bindings compare by is_relative ascending (relative < absolute) then
// by raw value.
static int leaf_cmp(const ct_leaf_match_t *a, const ct_leaf_match_t *b) {
    if (a->cls != b->cls) return (a->cls < b->cls) ? -1 : 1;
    uint8_t n = (a->bindings.n < b->bindings.n) ? a->bindings.n : b->bindings.n;

    // Tier 1: number of keys (also catches any kind mismatch up front; with
    // equal classes the kinds always match positionally).
    for (uint8_t i = 0; i < n; i++) {
        const ct_value_t *va = &a->bindings.v[i];
        const ct_value_t *vb = &b->bindings.v[i];
        int order = compare_uint32(va->kind, vb->kind);
        if (order != 0) return order;
        if (va->kind == CT_BV_KEYS) {
            order = compare_uint16(keys_member_count(va), keys_member_count(vb));
            if (order != 0) return order;
        }
    }

    // Tier 2: every other binding kind, in binding order.
    for (uint8_t i = 0; i < n; i++) {
        const ct_value_t *va = &a->bindings.v[i];
        const ct_value_t *vb = &b->bindings.v[i];
        int order = compare_non_key_list_bindings(va, vb);
        if (order != 0) return order;
    }

    // Tier 3: tie-break by the keys themselves, so multisig leaves that share a
    // size and threshold still order deterministically rather than by tap-tree
    // position.
    for (uint8_t i = 0; i < n; i++) {
        const ct_value_t *va = &a->bindings.v[i];
        const ct_value_t *vb = &b->bindings.v[i];
        if (va->kind == CT_BV_KEYS) {
            int r = cmp_binding_keys(va, vb);
            if (r != 0) return r;
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
    // sentinel, set by the generated classifier for the pk(musig(...)) /
    // tr(musig(...)) forms). In that case render the inner keys as a flat
    // Oxford-comma list (without "musig(...)" wrapping).
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

// Returns true iff the bindings carry both a threshold and a keys list with
// threshold == number of keys (n-of-n). Used to select a multisig class's
// alternate "each of ..." rendering (`spec->parts_all`).
static bool bindings_is_n_of_n(const ct_bindings_t *b) {
    uint32_t threshold, n_keys;
    return find_threshold_and_keys(b, &threshold, &n_keys) && threshold == n_keys;
}

// Renders a spec into an existing buffer at offset `*off`, recursing into
// SUB bindings. `*off` is updated to point past the appended bytes.
static int render_spec_at(const cleartext_spec_t *spec,
                          const ct_bindings_t *b,
                          char *out,
                          size_t cap,
                          size_t *off) {
    // Multisig classes carry an alternate "each of ..." template (`parts_all`)
    // used for the n-of-n case (threshold == number of keys); fall back to the
    // primary `parts` otherwise. (The musig key-path classes are inherently
    // n-of-n, so their primary `parts` is already the "each of ..." form and
    // they declare no `parts_all`.)
    const cleartext_part_t *parts;
    uint8_t n_parts;
    if (spec->parts_all != NULL && bindings_is_n_of_n(b)) {
        parts = (const cleartext_part_t *) PIC(spec->parts_all);
        n_parts = spec->n_parts_all;
    } else {
        // `spec->parts` is a pointer field stored inside a `const` table in
        // flash; on Ledger devices flash pointer fields hold link-time addresses
        // and must be relocated through PIC() before being dereferenced.
        parts = (const cleartext_part_t *) PIC(spec->parts);
        n_parts = spec->n_parts;
    }
    for (uint8_t i = 0; i < n_parts; i++) {
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

    if (top_spec->recurses) {
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

// Emits the raw descriptor template as the sole output line. Used as the
// fallback whenever no cleartext can be produced (non-canonical keys, or an
// unclassified top level). *out_has_cleartext and *out_class are left as the
// caller already set them (false / DC_OTHER). Returns cleartext_encode's return
// value: 0 when there is no template to show, 1 when the template was emitted.
static int emit_raw_fallback(const char *raw_template,
                             char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                             size_t *out_n_lines) {
    if (raw_template == NULL) return 0;
    size_t l = strlen(raw_template);
    if (l > CT_MAX_LINE_LEN) l = CT_MAX_LINE_LEN;
    memcpy(out_lines[0], raw_template, l);
    out_lines[0][l] = 0;
    *out_n_lines = 1;
    return 1;
}

int cleartext_encode(const policy_node_t *root,
                     const char *raw_template,
                     char out_lines[CT_MAX_LINES][CT_MAX_LINE_LEN + 1],
                     size_t *out_n_lines,
                     bool *out_has_cleartext,
                     descriptor_class_e *out_class) {
    *out_n_lines = 0;
    *out_has_cleartext = false;
    // Stays DC_OTHER on every early-return path (unclassified or raw-template
    // fallback); set to the matched class only once a cleartext is rendered.
    *out_class = DC_OTHER;

    bool canonical = true;
    (void) key_orderings_count(root, &canonical);
    if (!canonical) {
        return emit_raw_fallback(raw_template, out_lines, out_n_lines);
    }

    ct_top_match_t top;
    if (!match_top_level(root, &top) || top.cls == DC_OTHER) {
        return emit_raw_fallback(raw_template, out_lines, out_n_lines);
    }

    *out_class = top.cls;

    // Render the primary line.
    const cleartext_spec_t *top_spec = &CT_TOP_LEVEL_SPECS[top.cls];
    if (render_spec(top_spec, &top.bindings, out_lines[0], CT_MAX_LINE_LEN + 1) < 0) return -1;
    capitalize_first(out_lines[0]);
    *out_n_lines = 1;

    if (!top_spec->recurses) {
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
            // This leaf has no cleartext form. We don't have an in-memory string
            // for an arbitrary subtree (no AST unparser), so we render the fixed
            // "(unknown)" marker rather than the leaf's own descriptor, and flag
            // the overall rendering as incomplete.
            all_have_cleartext = false;
            size_t off = 0;
            out_lines[line_idx][0] = 0;
            if (append_str(out_lines[line_idx], CT_MAX_LINE_LEN + 1, &off, CT_UNKNOWN_LEAF) < 0) {
                return -1;
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
