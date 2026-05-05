/**
 * Mock dispatcher_context_t implementation for unit testing.
 *
 * Implements the client-side command interpreter entirely in C, matching
 * the behavior of the Python ClientCommandInterpreter in client_command.py.
 */

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "mock_dispatcher.h"
#include "cx_hash_mock.h"
#include "sha-256.h"

#include "buffer.h"
#include "varint.h"
#include "common/merkle.h"
#include "client_commands.h"

/* ---- Global pointer to active mock (needed for function-pointer callbacks) ---- */
static mock_dispatcher_t *g_active_mock = NULL;

/* ---- External: reset the cx_hash_mock pool ---- */
extern int g_sha256_pool_next;

void mock_dispatcher_reset_hash_pool(void) {
    g_sha256_pool_next = 0;
}

/* ---- Helper: compute SHA-256 of a buffer ---- */
static void mock_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    calc_sha_256(out, data, len);
}

/* ===========================================================================
 *  Merkle tree builder
 *
 *  Builds a left-complete binary Merkle tree (RFC 6962 style) matching the
 *  Python MerkleTree class.  We store all node hashes in a flat array using
 *  a recursive construction.
 * =========================================================================== */

/**
 * Recursively compute the Merkle root for the sub-array hashes[begin..begin+size).
 *
 * The tree is a left-complete binary tree (RFC 6962 style): the left subtree
 * always contains the largest power of 2 that is strictly less than `size`
 * leaves, and the right subtree contains the remainder.  Internal node hashes
 * are computed by merkle_combine_hashes(left, right).
 *
 * The resulting root hash is written to `out`.
 */

static void build_merkle_root(const uint8_t hashes[][32],
                              size_t begin,
                              size_t size,
                              uint8_t out[32]) {
    if (size == 0) {
        memset(out, 0, 32);
        return;
    }
    if (size == 1) {
        memcpy(out, hashes[begin], 32);
        return;
    }

    /* Left subtree has largest-power-of-2-less-than(size) leaves */
    size_t lsize = 1;
    while (2 * lsize < size) {
        lsize *= 2;
    }
    /* lsize is the largest power of 2 < size (when size is not a power of 2)
     * or size/2 (when size is a power of 2) */

    uint8_t left_hash[32], right_hash[32];
    build_merkle_root(hashes, begin, lsize, left_hash);
    build_merkle_root(hashes, begin + lsize, size - lsize, right_hash);
    merkle_combine_hashes(left_hash, right_hash, out);
}

/**
 * Generate the Merkle proof for leaf at `leaf_index` in a tree of `size` elements.
 * Returns the proof as an array of 32-byte sibling hashes (leaf to root), and
 * sets *proof_len to the number of proof elements.
 */
static void generate_merkle_proof(const uint8_t hashes[][32],
                                  size_t begin,
                                  size_t size,
                                  size_t leaf_index,
                                  uint8_t proof[][32],
                                  size_t *proof_len) {
    if (size <= 1) {
        *proof_len = 0;
        return;
    }

    size_t lsize = 1;
    while (2 * lsize < size) {
        lsize *= 2;
    }

    uint8_t sibling_hash[32];

    if (leaf_index < lsize) {
        /* Leaf is in the left subtree; sibling is the right subtree root */
        build_merkle_root(hashes, begin + lsize, size - lsize, sibling_hash);

        size_t sub_proof_len = 0;
        generate_merkle_proof(hashes, begin, lsize, leaf_index, proof, &sub_proof_len);

        /* Append sibling at the end (proof goes leaf → root) */
        memcpy(proof[sub_proof_len], sibling_hash, 32);
        *proof_len = sub_proof_len + 1;
    } else {
        /* Leaf is in the right subtree; sibling is the left subtree root */
        build_merkle_root(hashes, begin, lsize, sibling_hash);

        size_t sub_proof_len = 0;
        generate_merkle_proof(hashes,
                              begin + lsize,
                              size - lsize,
                              leaf_index - lsize,
                              proof,
                              &sub_proof_len);

        memcpy(proof[sub_proof_len], sibling_hash, 32);
        *proof_len = sub_proof_len + 1;
    }
}

/* ===========================================================================
 *  dispatcher_context_t function-pointer implementations
 * =========================================================================== */

static void mock_add_to_response(const void *rdata, size_t rdata_len) {
    assert(g_active_mock != NULL);
    mock_dispatcher_t *m = g_active_mock;

    assert(m->request_len + rdata_len <= sizeof(m->request_buf));
    memcpy(m->request_buf + m->request_len, rdata, rdata_len);
    m->request_len += rdata_len;
}

static void mock_finalize_response(uint16_t sw) {
    assert(g_active_mock != NULL);
    g_active_mock->last_sw = sw;
}

static void mock_send_response(void) {
    /* No-op in mock: responses are consumed internally */
}

static void mock_set_ui_dirty(void) {
    /* No-op in mock */
}

/* ---- Client command handlers ---- */

static int handle_get_preimage(mock_dispatcher_t *m) {
    /* Request format: <CCMD_GET_PREIMAGE:1> <hash_type:1> <hash:32> */
    if (m->request_len < 1 + 1 + 32) {
        return -1;
    }

    const uint8_t *req_hash = m->request_buf + 2; /* skip cmd byte and hash_type */

    /* Look up the preimage */
    int found_idx = -1;
    for (size_t i = 0; i < m->n_preimages; i++) {
        if (memcmp(m->preimages[i].hash, req_hash, 32) == 0) {
            found_idx = (int) i;
            break;
        }
    }

    if (found_idx < 0) {
        /* Unknown preimage — return error */
        return -1;
    }

    const uint8_t *preimage = m->preimages[found_idx].data;
    size_t preimage_len = m->preimages[found_idx].len;

    /* Build response: <preimage_len_varint> <partial_data_len:1> <partial_data> */
    uint8_t varint_buf[9];
    int varint_len = varint_write(varint_buf, 0, (uint64_t) preimage_len);

    /* Max payload in first response: 255 - varint_len - 1 */
    size_t max_payload = 255 - (size_t) varint_len - 1;
    size_t payload_size = preimage_len < max_payload ? preimage_len : max_payload;

    /* If there's overflow, queue the remaining bytes as 1-byte elements */
    if (payload_size < preimage_len) {
        m->queue.element_size = 1;
        m->queue.count = preimage_len - payload_size;
        m->queue.head = 0;
        for (size_t i = 0; i < m->queue.count; i++) {
            m->queue.data[i][0] = preimage[payload_size + i];
        }
    }

    /* Write response */
    m->response_len = 0;
    memcpy(m->response_buf + m->response_len, varint_buf, (size_t) varint_len);
    m->response_len += (size_t) varint_len;
    m->response_buf[m->response_len++] = (uint8_t) payload_size;
    memcpy(m->response_buf + m->response_len, preimage, payload_size);
    m->response_len += payload_size;

    return 0;
}

static int handle_get_more_elements(mock_dispatcher_t *m) {
    /* Request: just the command byte */
    if (m->queue.head >= m->queue.count) {
        return -1; /* Nothing in queue */
    }

    size_t element_size = m->queue.element_size;
    size_t remaining = m->queue.count - m->queue.head;

    /* Fit as many as possible in 255 bytes: 1 (n_elements) + 1 (el_len) + n*el_len <= 255 */
    size_t max_elements = (253) / element_size;
    size_t n_elements = remaining < max_elements ? remaining : max_elements;

    m->response_len = 0;
    m->response_buf[m->response_len++] = (uint8_t) n_elements;
    m->response_buf[m->response_len++] = (uint8_t) element_size;

    for (size_t i = 0; i < n_elements; i++) {
        memcpy(m->response_buf + m->response_len, m->queue.data[m->queue.head], element_size);
        m->response_len += element_size;
        m->queue.head++;
    }

    return 0;
}

static int handle_yield(mock_dispatcher_t *m) {
    /* Store everything after the command byte as a yielded value */
    assert(m->n_yielded < MOCK_MAX_YIELDED);

    size_t data_len = m->request_len > 0 ? m->request_len - 1 : 0;
    assert(data_len <= MOCK_MAX_YIELDED_LEN);

    m->yielded[m->n_yielded].len = data_len;
    if (data_len > 0) {
        memcpy(m->yielded[m->n_yielded].data, m->request_buf + 1, data_len);
    }
    m->n_yielded++;

    /* Response is empty */
    m->response_len = 0;
    return 0;
}

static int handle_get_merkle_leaf_proof(mock_dispatcher_t *m) {
    /* Request: <cmd:1> <merkle_root:32> <tree_size:varint> <leaf_index:varint> */
    buffer_t req = buffer_create(m->request_buf + 1, m->request_len - 1);

    uint8_t root[32];
    if (!buffer_read_bytes(&req, root, 32)) return -1;

    uint64_t tree_size_u64, leaf_index_u64;
    if (!buffer_read_varint(&req, &tree_size_u64)) return -1;
    if (!buffer_read_varint(&req, &leaf_index_u64)) return -1;

    size_t tree_size = (size_t) tree_size_u64;
    size_t leaf_index = (size_t) leaf_index_u64;

    /* Find the tree by root */
    mock_merkle_tree_t *tree = NULL;
    for (size_t i = 0; i < m->n_trees; i++) {
        if (memcmp(m->trees[i].root, root, 32) == 0) {
            tree = &m->trees[i];
            break;
        }
    }
    if (tree == NULL || tree->n_elements != tree_size || leaf_index >= tree_size) {
        return -1;
    }

    /* Generate proof */
    uint8_t proof[MAX_MERKLE_TREE_DEPTH][32];
    size_t proof_len = 0;
    generate_merkle_proof((const uint8_t(*)[32]) tree->element_hashes,
                          0,
                          tree->n_elements,
                          leaf_index,
                          proof,
                          &proof_len);

    /* How many proof elements fit in first response: 255 - 32 - 1 - 1 = 221 bytes -> 221/32 = 6 */
    size_t max_first = (255 - 32 - 1 - 1) / 32;
    size_t n_response_elements = proof_len < max_first ? proof_len : max_first;
    size_t n_leftover = proof_len - n_response_elements;

    /* Queue leftover proof elements */
    if (n_leftover > 0) {
        m->queue.element_size = 32;
        m->queue.count = n_leftover;
        m->queue.head = 0;
        for (size_t i = 0; i < n_leftover; i++) {
            memcpy(m->queue.data[i], proof[n_response_elements + i], 32);
        }
    }

    /* Build response: <leaf_hash:32> <proof_size:1> <n_proof_elements:1> <proof_hashes...> */
    m->response_len = 0;
    memcpy(m->response_buf + m->response_len, tree->element_hashes[leaf_index], 32);
    m->response_len += 32;
    m->response_buf[m->response_len++] = (uint8_t) proof_len;
    m->response_buf[m->response_len++] = (uint8_t) n_response_elements;
    for (size_t i = 0; i < n_response_elements; i++) {
        memcpy(m->response_buf + m->response_len, proof[i], 32);
        m->response_len += 32;
    }

    return 0;
}

static int handle_get_merkle_leaf_index(mock_dispatcher_t *m) {
    /* Request: <cmd:1> <merkle_root:32> <leaf_hash:32> */
    if (m->request_len < 1 + 32 + 32) return -1;

    const uint8_t *root = m->request_buf + 1;
    const uint8_t *leaf_hash = m->request_buf + 1 + 32;

    /* Find tree */
    mock_merkle_tree_t *tree = NULL;
    for (size_t i = 0; i < m->n_trees; i++) {
        if (memcmp(m->trees[i].root, root, 32) == 0) {
            tree = &m->trees[i];
            break;
        }
    }

    uint8_t found = 0;
    uint64_t index = 0;

    if (tree != NULL) {
        for (size_t i = 0; i < tree->n_elements; i++) {
            if (memcmp(tree->element_hashes[i], leaf_hash, 32) == 0) {
                found = 1;
                index = (uint64_t) i;
                break;
            }
        }
    }

    /* Response: <found:1> <index:varint> */
    m->response_len = 0;
    m->response_buf[m->response_len++] = found;
    uint8_t varint_buf[9];
    int vlen = varint_write(varint_buf, 0, index);
    memcpy(m->response_buf + m->response_len, varint_buf, (size_t) vlen);
    m->response_len += (size_t) vlen;

    return 0;
}

/* ---- Main interruption handler ---- */

static int mock_process_interruption(dispatcher_context_t *dc) {
    mock_dispatcher_t *m = g_active_mock;
    assert(m != NULL);
    assert(dc == &m->dc);

    if (m->request_len == 0) {
        return -1;
    }

    uint8_t cmd = m->request_buf[0];
    int rc;

    switch (cmd) {
        case CCMD_GET_PREIMAGE:
            rc = handle_get_preimage(m);
            break;
        case CCMD_GET_MORE_ELEMENTS:
            rc = handle_get_more_elements(m);
            break;
        case CCMD_YIELD:
            rc = handle_yield(m);
            break;
        case CCMD_GET_MERKLE_LEAF_PROOF:
            rc = handle_get_merkle_leaf_proof(m);
            break;
        case CCMD_GET_MERKLE_LEAF_INDEX:
            rc = handle_get_merkle_leaf_index(m);
            break;
        default:
            fprintf(stderr, "mock_process_interruption: unknown command 0x%02X\n", cmd);
            rc = -1;
            break;
    }

    /* Reset request buffer for next round */
    m->request_len = 0;

    if (rc < 0) {
        return -1;
    }

    /* Call tamper hook if set */
    if (m->tamper_hook != NULL) {
        int tamper_rc = m->tamper_hook(m->response_buf,
                                       &m->response_len,
                                       cmd,
                                       m->tamper_call_count,
                                       m->tamper_user_data);
        m->tamper_call_count++;
        if (tamper_rc < 0) {
            return -1;
        }
    }

    /* Set read_buffer to point at the response */
    dc->read_buffer = buffer_create(m->response_buf, m->response_len);
    return 0;
}

/* ===========================================================================
 *  Public API
 * =========================================================================== */

void mock_dispatcher_init(mock_dispatcher_t *mock) {
    memset(mock, 0, sizeof(mock_dispatcher_t));

    mock->dc.add_to_response = mock_add_to_response;
    mock->dc.finalize_response = mock_finalize_response;
    mock->dc.send_response = mock_send_response;
    mock->dc.set_ui_dirty = mock_set_ui_dirty;
    mock->dc.process_interruption = mock_process_interruption;

    /* Set global pointer so callbacks can find us */
    g_active_mock = mock;
}

void mock_dispatcher_add_preimage(mock_dispatcher_t *mock, const uint8_t *data, size_t len) {
    assert(mock->n_preimages < MOCK_MAX_PREIMAGES);
    assert(len <= MOCK_BUF_SIZE);

    size_t idx = mock->n_preimages++;
    mock_sha256(data, len, mock->preimages[idx].hash);
    memcpy(mock->preimages[idx].data, data, len);
    mock->preimages[idx].len = len;
}

void mock_dispatcher_add_list(mock_dispatcher_t *mock,
                              const uint8_t *const *elements,
                              const size_t *element_lens,
                              size_t n) {
    assert(mock->n_trees < MOCK_MAX_TREES);
    assert(n <= MOCK_MAX_TREE_ELEMS);

    mock_merkle_tree_t *tree = &mock->trees[mock->n_trees++];
    memset(tree, 0, sizeof(mock_merkle_tree_t));
    tree->n_elements = n;

    /* For each element:
     *  1. Compute element_hash = SHA256(0x00 || element)
     *  2. Store the raw element
     *  3. Register the preimage (0x00 || element) so GET_PREIMAGE can retrieve it
     */
    for (size_t i = 0; i < n; i++) {
        assert(element_lens[i] <= 256);

        memcpy(tree->raw_elements[i], elements[i], element_lens[i]);
        tree->raw_element_lens[i] = element_lens[i];

        /* element_hash = SHA256(0x00 || element) */
        merkle_compute_element_hash(elements[i], element_lens[i], tree->element_hashes[i]);

        /* Register preimage: the preimage is (0x00 || element), its hash is element_hashes[i] */
        uint8_t prefixed[257];
        prefixed[0] = 0x00;
        memcpy(prefixed + 1, elements[i], element_lens[i]);
        mock_dispatcher_add_preimage(mock, prefixed, 1 + element_lens[i]);
    }

    /* Compute Merkle root */
    build_merkle_root((const uint8_t(*)[32]) tree->element_hashes, 0, n, tree->root);
}

void mock_dispatcher_add_map(mock_dispatcher_t *mock,
                             const uint8_t *const *keys,
                             const size_t *key_lens,
                             const uint8_t *const *values,
                             const size_t *value_lens,
                             size_t n,
                             merkleized_map_commitment_t *out_commitment) {
    /* Sort items by key (simple insertion sort, matching Python's sorted()) */
    size_t sorted_indices[MOCK_MAX_TREE_ELEMS];
    assert(n <= MOCK_MAX_TREE_ELEMS);
    for (size_t i = 0; i < n; i++) {
        sorted_indices[i] = i;
    }
    for (size_t i = 1; i < n; i++) {
        size_t j = i;
        while (j > 0) {
            size_t a = sorted_indices[j - 1];
            size_t b = sorted_indices[j];
            size_t min_len = key_lens[a] < key_lens[b] ? key_lens[a] : key_lens[b];
            int cmp = memcmp(keys[a], keys[b], min_len);
            if (cmp > 0 || (cmp == 0 && key_lens[a] > key_lens[b])) {
                sorted_indices[j - 1] = b;
                sorted_indices[j] = a;
                j--;
            } else {
                break;
            }
        }
    }

    /* Build sorted key and value arrays */
    const uint8_t *sorted_keys[MOCK_MAX_TREE_ELEMS];
    size_t sorted_key_lens[MOCK_MAX_TREE_ELEMS];
    const uint8_t *sorted_values[MOCK_MAX_TREE_ELEMS];
    size_t sorted_value_lens[MOCK_MAX_TREE_ELEMS];
    for (size_t i = 0; i < n; i++) {
        sorted_keys[i] = keys[sorted_indices[i]];
        sorted_key_lens[i] = key_lens[sorted_indices[i]];
        sorted_values[i] = values[sorted_indices[i]];
        sorted_value_lens[i] = value_lens[sorted_indices[i]];
    }

    /* Register both keys and values as Merkle trees (mirrors add_known_mapping) */
    size_t keys_tree_idx = mock->n_trees;
    mock_dispatcher_add_list(mock, sorted_keys, sorted_key_lens, n);

    size_t values_tree_idx = mock->n_trees;
    mock_dispatcher_add_list(mock, sorted_values, sorted_value_lens, n);

    /* Fill in the commitment */
    out_commitment->size = (uint64_t) n;
    memcpy(out_commitment->keys_root, mock->trees[keys_tree_idx].root, 32);
    memcpy(out_commitment->values_root, mock->trees[values_tree_idx].root, 32);
}

/* ---- Helper: register a psbt_map_t with the mock ---- */
static void register_psbt_map(mock_dispatcher_t *mock,
                              const psbt_map_t *map,
                              merkleized_map_commitment_t *out_commitment) {
    const uint8_t *keys[PSBT_MAP_MAX_ENTRIES];
    size_t key_lens[PSBT_MAP_MAX_ENTRIES];
    const uint8_t *values[PSBT_MAP_MAX_ENTRIES];
    size_t value_lens[PSBT_MAP_MAX_ENTRIES];

    for (size_t i = 0; i < map->n_entries; i++) {
        keys[i] = map->entries[i].key;
        key_lens[i] = map->entries[i].key_len;
        values[i] = map->entries[i].value;
        value_lens[i] = map->entries[i].value_len;
    }

    mock_dispatcher_add_map(mock,
                            keys,
                            key_lens,
                            values,
                            value_lens,
                            map->n_entries,
                            out_commitment);
}

/* ---- Helper: serialize a merkleized_map_commitment_t ---- */
static size_t serialize_commitment(const merkleized_map_commitment_t *c, uint8_t *out) {
    int vlen = varint_write(out, 0, c->size);
    memcpy(out + vlen, c->keys_root, 32);
    memcpy(out + vlen + 32, c->values_root, 32);
    return (size_t) vlen + 64;
}

int mock_dispatcher_add_psbt(mock_dispatcher_t *mock,
                             const uint8_t *psbt,
                             size_t psbt_len,
                             size_t n_inputs,
                             size_t n_outputs,
                             mock_psbt_t *out) {
    static parsed_psbt_t parsed;

    if (psbt_parse(psbt, psbt_len, n_inputs, n_outputs, &parsed) < 0) {
        return -1;
    }

    out->n_inputs = n_inputs;
    out->n_outputs = n_outputs;

    /* Register global map */
    register_psbt_map(mock, &parsed.global_map, &out->global_map);

    /* Register each input map and compute commitments */
    uint8_t input_commitment_bufs[PSBT_MAX_MAPS][73]; /* varint(9) + 32 + 32 max */
    size_t input_commitment_lens[PSBT_MAX_MAPS];
    const uint8_t *input_commitment_ptrs[PSBT_MAX_MAPS];

    for (size_t i = 0; i < n_inputs; i++) {
        register_psbt_map(mock, &parsed.input_maps[i], &out->input_maps[i]);
        input_commitment_lens[i] =
            serialize_commitment(&out->input_maps[i], input_commitment_bufs[i]);
        input_commitment_ptrs[i] = input_commitment_bufs[i];
    }

    /* Register each output map and compute commitments */
    uint8_t output_commitment_bufs[PSBT_MAX_MAPS][73];
    size_t output_commitment_lens[PSBT_MAX_MAPS];
    const uint8_t *output_commitment_ptrs[PSBT_MAX_MAPS];

    for (size_t i = 0; i < n_outputs; i++) {
        register_psbt_map(mock, &parsed.output_maps[i], &out->output_maps[i]);
        output_commitment_lens[i] =
            serialize_commitment(&out->output_maps[i], output_commitment_bufs[i]);
        output_commitment_ptrs[i] = output_commitment_bufs[i];
    }

    /* Register the list of input commitments and the list of output commitments */
    if (n_inputs > 0) {
        mock_dispatcher_add_list(mock, input_commitment_ptrs, input_commitment_lens, n_inputs);
    }
    if (n_outputs > 0) {
        mock_dispatcher_add_list(mock, output_commitment_ptrs, output_commitment_lens, n_outputs);
    }

    return 0;
}
