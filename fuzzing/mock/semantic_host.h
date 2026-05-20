#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SH_MAX_PREIMAGES   256
#define SH_MAX_PREIMAGE_SZ 512
#define SH_MAX_TREES        64
#define SH_MAX_TREE_LEAVES  32
#define SH_MAX_PROOF_DEPTH   8

typedef struct {
    uint8_t hash[32];
    uint8_t data[SH_MAX_PREIMAGE_SZ];
    size_t data_len;
} sh_preimage_t;

typedef struct {
    uint8_t leaf_hashes[SH_MAX_TREE_LEAVES][32];
    int n_leaves;
    uint8_t root[32];
} sh_tree_t;

typedef struct {
    const uint8_t *data;
    size_t data_len;
    size_t offset;
    size_t elem_size;
} sh_queue_t;

typedef struct {
    sh_preimage_t preimages[SH_MAX_PREIMAGES];
    int n_preimages;

    sh_tree_t trees[SH_MAX_TREES];
    int n_trees;

    sh_queue_t queue;
    bool active;
} semantic_host_t;

extern semantic_host_t g_semantic_host;

void sh_reset(semantic_host_t *h);

void sh_element_hash(const uint8_t *data, size_t len, uint8_t out[32]);
void sh_combine_hashes(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]);

int sh_add_preimage(semantic_host_t *h, const uint8_t *data, size_t len);

int sh_tree_init(semantic_host_t *h);
int sh_tree_add_leaf(semantic_host_t *h, int tree_idx, const uint8_t *data, size_t len);
void sh_tree_finalize(semantic_host_t *h, int tree_idx);

int sh_tree_add_leaf_raw_hash(semantic_host_t *h, int tree_idx, const uint8_t hash[32]);

const sh_preimage_t *sh_lookup_preimage(const semantic_host_t *h, const uint8_t hash[32]);
const sh_tree_t *sh_lookup_tree(const semantic_host_t *h, const uint8_t root[32]);

int sh_tree_leaf_index(const sh_tree_t *t, const uint8_t leaf_hash[32]);
int sh_tree_prove(const sh_tree_t *t, int index, uint8_t proof[][32]);

int sh_handle_ccmd(semantic_host_t *h,
                   const uint8_t *tx_buf,
                   size_t tx_len,
                   uint8_t *payload,
                   size_t *payload_len);

int sh_handle_ccmd_with_disruption(semantic_host_t *h,
                                   const uint8_t *tx_buf,
                                   size_t tx_len,
                                   uint8_t *payload,
                                   size_t *payload_len,
                                   uint8_t disruption);
