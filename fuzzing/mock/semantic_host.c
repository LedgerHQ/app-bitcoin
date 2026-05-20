#include "semantic_host.h"
#include "fuzz_sha256.h"
#include "fuzz_varint.h"

#include <string.h>

semantic_host_t g_semantic_host;

#define CCMD_YIELD                  0x10
#define CCMD_GET_PREIMAGE           0x40
#define CCMD_GET_MERKLE_LEAF_PROOF  0x41
#define CCMD_GET_MERKLE_LEAF_INDEX  0x42
#define CCMD_GET_MORE_ELEMENTS      0xA0

#define SH_INLINE_PREIMAGE_LIMIT    (200 - 10)
#define SH_INLINE_PROOF_LIMIT       4
#define SH_QUEUE_PAYLOAD_LIMIT      190
#define SH_WRONG_REPLY_THRESHOLD    13

void sh_reset(semantic_host_t *h) {
    h->n_preimages = 0;
    h->n_trees = 0;
    h->queue.data = NULL;
    h->queue.data_len = 0;
    h->queue.offset = 0;
    h->queue.elem_size = 0;
    h->active = false;
}

void sh_element_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    fuzz_sha256_ctx ctx;
    fuzz_sha256_init(&ctx);
    uint8_t prefix = 0x00;
    fuzz_sha256_update(&ctx, &prefix, 1);
    fuzz_sha256_update(&ctx, data, len);
    fuzz_sha256_final(&ctx, out);
}

void sh_combine_hashes(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    fuzz_sha256_ctx ctx;
    fuzz_sha256_init(&ctx);
    uint8_t prefix = 0x01;
    fuzz_sha256_update(&ctx, &prefix, 1);
    fuzz_sha256_update(&ctx, left, 32);
    fuzz_sha256_update(&ctx, right, 32);
    fuzz_sha256_final(&ctx, out);
}

int sh_add_preimage(semantic_host_t *h, const uint8_t *data, size_t len) {
    if (h->n_preimages >= SH_MAX_PREIMAGES || len > SH_MAX_PREIMAGE_SZ)
        return -1;
    sh_preimage_t *p = &h->preimages[h->n_preimages];
    fuzz_sha256(data, len, p->hash);
    memcpy(p->data, data, len);
    p->data_len = len;
    return h->n_preimages++;
}

int sh_tree_init(semantic_host_t *h) {
    if (h->n_trees >= SH_MAX_TREES)
        return -1;
    int idx = h->n_trees++;
    h->trees[idx].n_leaves = 0;
    memset(h->trees[idx].root, 0, 32);
    return idx;
}

int sh_tree_add_leaf(semantic_host_t *h, int tree_idx, const uint8_t *data, size_t len) {
    if (tree_idx < 0 || tree_idx >= h->n_trees)
        return -1;
    sh_tree_t *t = &h->trees[tree_idx];
    if (t->n_leaves >= SH_MAX_TREE_LEAVES)
        return -1;
    int leaf_idx = t->n_leaves++;

    sh_element_hash(data, len, t->leaf_hashes[leaf_idx]);

    uint8_t preimage[1 + SH_MAX_PREIMAGE_SZ];
    if (len + 1 > SH_MAX_PREIMAGE_SZ)
        return -1;
    preimage[0] = 0x00;
    memcpy(preimage + 1, data, len);
    sh_add_preimage(h, preimage, 1 + len);

    return leaf_idx;
}

int sh_tree_add_leaf_raw_hash(semantic_host_t *h, int tree_idx, const uint8_t hash[32]) {
    if (tree_idx < 0 || tree_idx >= h->n_trees)
        return -1;
    sh_tree_t *t = &h->trees[tree_idx];
    if (t->n_leaves >= SH_MAX_TREE_LEAVES)
        return -1;
    int leaf_idx = t->n_leaves++;
    memcpy(t->leaf_hashes[leaf_idx], hash, 32);
    return leaf_idx;
}

static int largest_power_of_2_less_than(int n) {
    int p = 1;
    while (2 * p < n) p *= 2;
    return p;
}

static void compute_root_recursive(const uint8_t hashes[][32], int begin, int size, uint8_t out[32]) {
    if (size == 1) {
        memcpy(out, hashes[begin], 32);
        return;
    }
    int lsize = largest_power_of_2_less_than(size);
    uint8_t left[32], right[32];
    compute_root_recursive(hashes, begin, lsize, left);
    compute_root_recursive(hashes, begin + lsize, size - lsize, right);
    sh_combine_hashes(left, right, out);
}

void sh_tree_finalize(semantic_host_t *h, int tree_idx) {
    sh_tree_t *t = &h->trees[tree_idx];
    if (t->n_leaves == 0) {
        memset(t->root, 0, 32);
    } else if (t->n_leaves == 1) {
        memcpy(t->root, t->leaf_hashes[0], 32);
    } else {
        compute_root_recursive(t->leaf_hashes, 0, t->n_leaves, t->root);
    }
}

const sh_preimage_t *sh_lookup_preimage(const semantic_host_t *h, const uint8_t hash[32]) {
    for (int i = 0; i < h->n_preimages; i++) {
        if (memcmp(h->preimages[i].hash, hash, 32) == 0)
            return &h->preimages[i];
    }
    return NULL;
}

const sh_tree_t *sh_lookup_tree(const semantic_host_t *h, const uint8_t root[32]) {
    for (int i = 0; i < h->n_trees; i++) {
        if (memcmp(h->trees[i].root, root, 32) == 0)
            return &h->trees[i];
    }
    return NULL;
}

int sh_tree_leaf_index(const sh_tree_t *t, const uint8_t leaf_hash[32]) {
    for (int i = 0; i < t->n_leaves; i++) {
        if (memcmp(t->leaf_hashes[i], leaf_hash, 32) == 0)
            return i;
    }
    return -1;
}

static void prove_recursive(const uint8_t hashes[][32],
                             int begin, int size, int target,
                             uint8_t proof[][32], int *proof_len) {
    if (size <= 1)
        return;
    int lsize = largest_power_of_2_less_than(size);
    if (target < begin + lsize) {
        uint8_t right[32];
        compute_root_recursive(hashes, begin + lsize, size - lsize, right);
        memcpy(proof[*proof_len], right, 32);
        (*proof_len)++;
        prove_recursive(hashes, begin, lsize, target, proof, proof_len);
    } else {
        uint8_t left[32];
        compute_root_recursive(hashes, begin, lsize, left);
        memcpy(proof[*proof_len], left, 32);
        (*proof_len)++;
        prove_recursive(hashes, begin + lsize, size - lsize,
                        target, proof, proof_len);
    }
}

int sh_tree_prove(const sh_tree_t *t, int index, uint8_t proof[][32]) {
    if (index < 0 || index >= t->n_leaves)
        return -1;
    if (t->n_leaves == 1)
        return 0;
    int proof_len = 0;
    prove_recursive(t->leaf_hashes, 0, t->n_leaves, index, proof, &proof_len);
    return proof_len;
}

static uint64_t read_varint(const uint8_t *buf, size_t len, size_t *consumed) {
    *consumed = 0;
    if (len == 0) return 0;
    uint8_t first = buf[0];
    if (first < 0xFD) { *consumed = 1; return first; }
    if (first == 0xFD && len >= 3) {
        *consumed = 3;
        return (uint64_t)buf[1] | ((uint64_t)buf[2] << 8);
    }
    if (first == 0xFE && len >= 5) {
        *consumed = 5;
        return (uint64_t)buf[1] | ((uint64_t)buf[2] << 8) |
               ((uint64_t)buf[3] << 16) | ((uint64_t)buf[4] << 24);
    }
    *consumed = 1;
    return first;
}

static int handle_get_preimage(semantic_host_t *h,
                               const uint8_t *tx_buf, size_t tx_len,
                               uint8_t *payload, size_t *payload_len) {
    if (tx_len < 34) return -1;
    const uint8_t *hash = tx_buf + 2;
    const sh_preimage_t *p = sh_lookup_preimage(h, hash);
    if (!p) return -1;

    uint8_t *out = payload;
    size_t total_len = p->data_len;
    size_t partial = total_len;
    if (partial > SH_INLINE_PREIMAGE_LIMIT) partial = SH_INLINE_PREIMAGE_LIMIT;

    out += fuzz_write_varint(out, total_len);
    *out++ = (uint8_t)partial;
    memcpy(out, p->data, partial);
    out += partial;

    if (partial < total_len) {
        h->queue.data = p->data + partial;
        h->queue.data_len = total_len - partial;
        h->queue.offset = 0;
        h->queue.elem_size = 1;
    }

    *payload_len = (size_t)(out - payload);
    return 0;
}

static int handle_get_merkle_leaf_proof(semantic_host_t *h,
                                        const uint8_t *tx_buf, size_t tx_len,
                                        uint8_t *payload, size_t *payload_len) {
    if (tx_len < 34) return -1;
    const uint8_t *root = tx_buf + 1;
    size_t pos = 33;
    size_t consumed;
    uint64_t tree_size = read_varint(tx_buf + pos, tx_len - pos, &consumed);
    pos += consumed;
    uint64_t leaf_index = read_varint(tx_buf + pos, tx_len - pos, &consumed);
    (void)tree_size;

    const sh_tree_t *t = sh_lookup_tree(h, root);
    if (!t || (int)leaf_index >= t->n_leaves) return -1;

    uint8_t proof[SH_MAX_PROOF_DEPTH][32];
    int proof_len = sh_tree_prove(t, (int)leaf_index, proof);
    if (proof_len < 0) return -1;

    uint8_t *out = payload;
    memcpy(out, t->leaf_hashes[(int)leaf_index], 32);
    out += 32;
    *out++ = (uint8_t)proof_len;

    int inline_count = proof_len;
    if (inline_count > SH_INLINE_PROOF_LIMIT) inline_count = SH_INLINE_PROOF_LIMIT;
    *out++ = (uint8_t)inline_count;
    for (int i = 0; i < inline_count; i++) {
        int proof_idx = proof_len - 1 - i;
        memcpy(out, proof[proof_idx], 32);
        out += 32;
    }

    if (inline_count < proof_len) {
        static uint8_t remaining_proof[SH_MAX_PROOF_DEPTH * 32];
        int remaining = proof_len - inline_count;
        for (int i = 0; i < remaining; i++) {
            int proof_idx = proof_len - 1 - inline_count - i;
            memcpy(remaining_proof + i * 32, proof[proof_idx], 32);
        }
        h->queue.data = remaining_proof;
        h->queue.data_len = (size_t)(remaining * 32);
        h->queue.offset = 0;
        h->queue.elem_size = 32;
    }

    *payload_len = (size_t)(out - payload);
    return 0;
}

static int handle_get_merkle_leaf_index(semantic_host_t *h,
                                        const uint8_t *tx_buf, size_t tx_len,
                                        uint8_t *payload, size_t *payload_len) {
    if (tx_len < 65) return -1;
    const uint8_t *root = tx_buf + 1;
    const uint8_t *leaf_hash = tx_buf + 33;

    const sh_tree_t *t = sh_lookup_tree(h, root);
    if (!t) {
        payload[0] = 0;
        payload[1] = 0;
        *payload_len = 2;
        return 0;
    }

    int idx = sh_tree_leaf_index(t, leaf_hash);
    if (idx < 0) {
        payload[0] = 0;
        payload[1] = 0;
        *payload_len = 2;
        return 0;
    }

    uint8_t *out = payload;
    *out++ = 1;
    out += fuzz_write_varint(out, (uint64_t) idx);
    *payload_len = (size_t)(out - payload);
    return 0;
}

static int handle_get_more_elements(semantic_host_t *h,
                                    uint8_t *payload, size_t *payload_len) {
    sh_queue_t *q = &h->queue;
    if (!q->data || q->offset >= q->data_len) {
        payload[0] = 0;
        payload[1] = (uint8_t)(q->elem_size ? q->elem_size : 1);
        *payload_len = 2;
        return 0;
    }

    size_t remaining = q->data_len - q->offset;
    size_t elem_sz = q->elem_size ? q->elem_size : 1;
    size_t max_payload = SH_QUEUE_PAYLOAD_LIMIT;
    size_t max_elems = max_payload / elem_sz;
    size_t n_elems = remaining / elem_sz;
    if (n_elems > max_elems) n_elems = max_elems;
    if (n_elems > 255) n_elems = 255;

    payload[0] = (uint8_t)n_elems;
    payload[1] = (uint8_t)elem_sz;
    size_t copy = n_elems * elem_sz;
    memcpy(payload + 2, q->data + q->offset, copy);
    q->offset += copy;
    *payload_len = 2 + copy;
    return 0;
}

int sh_handle_ccmd(semantic_host_t *h,
                   const uint8_t *tx_buf, size_t tx_len,
                   uint8_t *payload, size_t *payload_len) {
    return sh_handle_ccmd_with_disruption(h, tx_buf, tx_len, payload, payload_len, 255);
}

int sh_handle_ccmd_with_disruption(semantic_host_t *h,
                                   const uint8_t *tx_buf, size_t tx_len,
                                   uint8_t *payload, size_t *payload_len,
                                   uint8_t disruption) {
    if (tx_len == 0) return -1;

    /*
     * Forced incorrect reply: ~5% of the time, return a well-formed but
     * content-wrong response instead of a hard failure.  This tests the app's
     * resilience to unexpected host behavior at any protocol step.
     * YIELD is exempt so the conversation can still terminate.
     */
    if (disruption < SH_WRONG_REPLY_THRESHOLD && tx_buf[0] != CCMD_YIELD) {
        /* Return a minimal "not found" response rather than a hard -1 */
        payload[0] = 0;
        payload[1] = 0;
        *payload_len = 2;
        return 0;
    }

    uint8_t ccmd = tx_buf[0];

    switch (ccmd) {
        case CCMD_GET_PREIMAGE:
            return handle_get_preimage(h, tx_buf, tx_len, payload, payload_len);
        case CCMD_GET_MERKLE_LEAF_PROOF:
            return handle_get_merkle_leaf_proof(h, tx_buf, tx_len, payload, payload_len);
        case CCMD_GET_MERKLE_LEAF_INDEX:
            return handle_get_merkle_leaf_index(h, tx_buf, tx_len, payload, payload_len);
        case CCMD_GET_MORE_ELEMENTS:
            return handle_get_more_elements(h, payload, payload_len);
        case CCMD_YIELD:
            *payload_len = 0;
            return 0;
        default:
            return -1;
    }
}
