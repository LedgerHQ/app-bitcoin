/**
 * Unit tests for call_get_merkleized_map_value (and the
 * call_get_merkleized_map_value_u32_le convenience wrapper) using the
 * mock dispatcher.
 *
 * call_get_merkleized_map_value looks up a key in a merkleized key-value
 * map (by finding its index via Merkle leaf index), then fetches the
 * corresponding value into the output buffer.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include "mock_dispatcher.h"
#include "cx_hash_mock.h"
#include "sha-256.h"

#include "client_commands.h"
#include "common/merkle.h"
#include "handler/lib/get_merkleized_map_value.h"

/* ---------- Test cases ---------- */

/**
 * Happy path: single key-value pair, look up by key.
 */
static void test_map_value_single(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01, 0x02};
    const uint8_t value[] = {0xAA, 0xBB, 0xCC};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value(dc, &commitment, key, sizeof(key), out, sizeof(out));

    assert_int_equal(result, (int) sizeof(value));
    assert_memory_equal(out, value, sizeof(value));
}

/**
 * Happy path: three key-value pairs, look up each by key.
 */
static void test_map_value_three_pairs(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t k0[] = {0x01};
    const uint8_t k1[] = {0x02};
    const uint8_t k2[] = {0x03};
    const uint8_t v0[] = {0x10, 0x11, 0x12};
    const uint8_t v1[] = {0x20, 0x21};
    const uint8_t v2[] = {0x30, 0x31, 0x32, 0x33};

    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 3, &commitment);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 3; i++) {
        uint8_t out[64];
        memset(out, 0, sizeof(out));

        int result =
            call_get_merkleized_map_value(dc, &commitment, keys[i], key_lens[i], out, sizeof(out));

        assert_int_equal(result, (int) value_lens[i]);
        assert_memory_equal(out, values[i], value_lens[i]);
    }
}

/**
 * Happy path: keys provided in unsorted order are sorted by add_map; the
 * lookup must still work for each original key.
 */
static void test_map_value_unsorted_input(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t k0[] = {0x03};
    const uint8_t k1[] = {0x01};
    const uint8_t k2[] = {0x02};
    const uint8_t v0[] = {0x30};
    const uint8_t v1[] = {0x10};
    const uint8_t v2[] = {0x20};

    const uint8_t *keys[] = {k0, k1, k2};
    const size_t key_lens[] = {sizeof(k0), sizeof(k1), sizeof(k2)};
    const uint8_t *values[] = {v0, v1, v2};
    const size_t value_lens[] = {sizeof(v0), sizeof(v1), sizeof(v2)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 3, &commitment);

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);

    for (size_t i = 0; i < 3; i++) {
        uint8_t out[64];
        memset(out, 0, sizeof(out));

        int result =
            call_get_merkleized_map_value(dc, &commitment, keys[i], key_lens[i], out, sizeof(out));

        assert_int_equal(result, (int) value_lens[i]);
        assert_memory_equal(out, values[i], value_lens[i]);
    }
}

/**
 * Error: the key is not present in the map. call_get_merkle_leaf_index
 * returns a negative value, which must be propagated as -1.
 */
static void test_map_value_key_not_found(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xAA};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    const uint8_t missing_key[] = {0xFF};

    uint8_t out[64];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value(dc,
                                               &commitment,
                                               missing_key,
                                               sizeof(missing_key),
                                               out,
                                               sizeof(out));
    assert_int_equal(result, -1);
}

/**
 * Error: output buffer too small to hold the value. The underlying
 * call_get_merkle_leaf_element returns a negative value when the
 * preimage does not fit, which must be propagated.
 */
static void test_map_value_out_buffer_too_small(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0x11, 0x22, 0x33, 0x44, 0x55};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    /* Provide an output buffer smaller than the value length. */
    uint8_t out[2];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value(dc, &commitment, key, sizeof(key), out, sizeof(out));
    assert_true(result < 0);
}

/**
 * Edge case: 0-byte value. The lookup must succeed and return 0.
 */
static void test_map_value_empty_value(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x42};
    const uint8_t *values[] = {NULL};
    const size_t value_lens[] = {0};
    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    uint8_t out[16];
    memset(out, 0xCD, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value(dc, &commitment, key, sizeof(key), out, sizeof(out));

    assert_int_equal(result, 0);
    /* Buffer must be left untouched. */
    assert_int_equal(out[0], 0xCD);
}

/**
 * Happy path for call_get_merkleized_map_value_u32_le: a 4-byte
 * little-endian value is decoded into a uint32_t.
 */
static void test_map_value_u32_le(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x10};
    /* 0xDEADBEEF in little-endian */
    const uint8_t value[] = {0xEF, 0xBE, 0xAD, 0xDE};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    uint32_t got = 0;
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value_u32_le(dc, &commitment, key, sizeof(key), &got);

    assert_int_equal(result, 4);
    assert_int_equal(got, 0xDEADBEEFu);
}

/**
 * Error path for call_get_merkleized_map_value_u32_le: the value at the
 * key has a length different from 4. The wrapper must return -1 without
 * writing to the output.
 */
static void test_map_value_u32_le_wrong_length(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x10};
    /* Only 3 bytes — not a valid 32-bit value. */
    const uint8_t value[] = {0x01, 0x02, 0x03};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    uint32_t got = 0xCAFEBABEu;
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value_u32_le(dc, &commitment, key, sizeof(key), &got);

    assert_int_equal(result, -1);
    /* The wrapper bails out before assigning to *out. */
    assert_int_equal(got, 0xCAFEBABEu);
}

/**
 * Error path for call_get_merkleized_map_value_u32_le: the key is not
 * present in the map.
 */
static void test_map_value_u32_le_key_not_found(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x10};
    const uint8_t value[] = {0x01, 0x02, 0x03, 0x04};

    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    const uint8_t missing_key[] = {0xFF};

    uint32_t got = 0;
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value_u32_le(dc,
                                                      &commitment,
                                                      missing_key,
                                                      sizeof(missing_key),
                                                      &got);

    assert_int_equal(result, -1);
}

/**
 * Adversarial: client corrupts the leaf hash in the merkle proof for the
 * VALUES tree. After the key index is resolved correctly, the value leaf
 * retrieval must fail because the proof no longer reconstructs the root.
 */
static int tamper_corrupt_value_proof(uint8_t *response_buf,
                                      size_t *response_len,
                                      uint8_t cmd,
                                      int call_count,
                                      void *user_data) {
    (void) call_count;

    /* The first CCMD_GET_MERKLE_LEAF_PROOF response is for the keys tree
     * (issued by call_get_merkle_leaf_index). The second is for the
     * values tree (issued by call_get_merkle_leaf_element). Corrupt
     * only the second one so the key index resolution still succeeds. */
    int *proof_call = (int *) user_data;
    if (cmd == CCMD_GET_MERKLE_LEAF_PROOF) {
        if (*proof_call == 1 && *response_len >= 32) {
            response_buf[5] ^= 0x01;
        }
        (*proof_call)++;
    }
    return 0;
}

static void test_map_value_corrupted_value_proof(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t key[] = {0x01};
    const uint8_t value[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {sizeof(value)};

    merkleized_map_commitment_t commitment;
    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, &commitment);

    int proof_call = 0;
    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_value_proof, &proof_call);

    uint8_t out[64];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_merkleized_map_value(dc, &commitment, key, sizeof(key), out, sizeof(out));

    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_map_value_single),
        T(test_map_value_three_pairs),
        T(test_map_value_unsorted_input),
        T(test_map_value_key_not_found),
        T(test_map_value_out_buffer_too_small),
        T(test_map_value_empty_value),
        T(test_map_value_u32_le),
        T(test_map_value_u32_le_wrong_length),
        T(test_map_value_u32_le_key_not_found),
        T(test_map_value_corrupted_value_proof),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
