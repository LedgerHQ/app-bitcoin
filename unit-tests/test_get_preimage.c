/**
 * Unit tests for call_get_preimage using the mock dispatcher.
 *
 * Tests verify that the C implementation of call_get_preimage correctly
 * handles the client command protocol (GET_PREIMAGE / GET_MORE_ELEMENTS)
 * and validates the SHA-256 hash of the received data.
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

#include "client_commands.h"
#include "handler/lib/get_preimage.h"

/* ---------- Helpers ---------- */

static void compute_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    calc_sha_256(out, data, len);
}

/* ---------- Test cases ---------- */

/**
 * Happy path: small preimage (fits entirely in the first response, no
 * GET_MORE_ELEMENTS needed).
 */
static void test_get_preimage_small(void **state) {
    mock_dispatcher_t *mock = *state;

    /* A small preimage: 50 bytes */
    uint8_t preimage[50];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[256];
    memset(out, 0xAA, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Happy path: large preimage that requires GET_MORE_ELEMENTS to transfer
 * all the bytes.
 */
static void test_get_preimage_large(void **state) {
    mock_dispatcher_t *mock = *state;

    /* A larger preimage: 300 bytes */
    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) ((i * 7 + 13) & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Error: requesting preimage of an unknown hash should return a negative value.
 */
static void test_get_preimage_unknown_hash(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Don't register any preimage; just call with a random hash */
    uint8_t hash[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t out[256];

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* process_interruption returns -1 → call_get_preimage returns -1 */
    assert_true(result < 0);
}

/**
 * Error: output buffer too small for the preimage.
 * call_get_preimage should return -10.
 */
static void test_get_preimage_buffer_too_small(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[100];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) i;
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[50]; /* Too small! */

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -10);
}

/**
 * Edge case: minimal preimage of exactly 1 byte.
 */
static void test_get_preimage_one_byte(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[1] = {0x42};
    mock_dispatcher_add_preimage(mock, preimage, 1);

    uint8_t hash[32];
    compute_sha256(preimage, 1, hash);

    uint8_t out[64];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, 1);
    assert_int_equal(out[0], 0x42);
}

/**
 * Edge case: preimage that exactly fills the max first-response payload.
 *
 * For a preimage of length L, the varint encoding takes:
 *   1 byte if L < 253, 3 bytes if L < 65536, etc.
 * Max payload = 255 - varint_len - 1.
 * For varint_len=1: max_payload = 253.
 * So a 253-byte preimage should fit exactly with no GET_MORE_ELEMENTS.
 */
static void test_get_preimage_exact_fit(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[253];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i ^ 0xA5);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/**
 * Edge case: preimage of length 254 (one byte over the exact-fit boundary,
 * so a few bytes go through GET_MORE_ELEMENTS).
 */
static void test_get_preimage_one_byte_overflow(void **state) {
    mock_dispatcher_t *mock = *state;

    /* Varint encodings above 253 bytes (and less than 65536) take 3 bytes,
     * therefore max_payload = 255 - 3 - 1 = 251.
     * Hence, for length 254, 3 bytes go through GET_MORE_ELEMENTS.
     */
    uint8_t preimage[254];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i * 3);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    uint8_t out[512];
    memset(out, 0, sizeof(out));

    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, (int) sizeof(preimage));
    assert_memory_equal(out, preimage, sizeof(preimage));
}

/* ==========================================================================
 *  Adversarial tests: malicious client behavior
 * ========================================================================== */

/**
 * Adversarial: client returns valid structure but corrupted data bytes,
 * causing a SHA-256 hash mismatch.
 */
static int tamper_corrupt_preimage_data(uint8_t *response_buf,
                                        size_t *response_len,
                                        uint8_t cmd,
                                        int call_count,
                                        void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len > 3) {
        /* Flip a byte in the data portion (after 1-byte varint + partial_data_len) */
        response_buf[3] ^= 0xFF;
    }
    return 0;
}

static void test_get_preimage_corrupted_data(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[50];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_preimage_data, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* Must detect the hash mismatch */
    assert_true(result < 0);
}

/**
 * Adversarial: client claims partial_data_len > preimage_len.
 */
static int tamper_partial_len_overflow(uint8_t *response_buf,
                                       size_t *response_len,
                                       uint8_t cmd,
                                       int call_count,
                                       void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len >= 2) {
        uint8_t preimage_len = response_buf[0];
        if (preimage_len < 200) {
            response_buf[1] = preimage_len + 10;
        }
    }
    return 0;
}

static void test_get_preimage_partial_len_overflow(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[20];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) i;
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_partial_len_overflow, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* Detected via buffer_can_read or partial_data_len > preimage_len */
    assert_true(result < 0);
}

/**
 * Adversarial: client returns preimage_len = 0 (invalid: at minimum the prefix
 * byte should be present).
 */
static int tamper_zero_preimage_len(uint8_t *response_buf,
                                    size_t *response_len,
                                    uint8_t cmd,
                                    int call_count,
                                    void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        response_buf[0] = 0x00;
        response_buf[1] = 0x00;
        *response_len = 2;
    }
    return 0;
}

static void test_get_preimage_zero_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_zero_preimage_len, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_true(result < 0);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, client returns elements_len != 1.
 */
static int tamper_more_elements_bad_size(uint8_t *response_buf,
                                         size_t *response_len,
                                         uint8_t cmd,
                                         int call_count,
                                         void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[1] = 4; /* el_len = 4 instead of 1 */
    }
    return 0;
}

static void test_get_preimage_bad_element_size(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_elements_bad_size, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* Detected via buffer_can_read or elements_len != 1 */
    assert_true(result < 0);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, client sends more bytes than remaining.
 */
static int tamper_more_bytes_than_remaining(uint8_t *response_buf,
                                            size_t *response_len,
                                            uint8_t cmd,
                                            int call_count,
                                            void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[0] = 250; /* claim 250 elements */
    }
    return 0;
}

static void test_get_preimage_more_bytes_than_remaining(void **state) {
    mock_dispatcher_t *mock = *state;

    /* 254 bytes: varint=3 bytes, max_payload = 255-3-1 = 251, spill = 3 bytes */
    uint8_t preimage[254];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i * 7);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_bytes_than_remaining, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* n_bytes > bytes_remaining → -8, or buffer_can_read fails → -6 */
    assert_true(result < 0);
}

/**
 * Adversarial: client corrupts continuation data (GET_MORE_ELEMENTS payload),
 * causing hash mismatch at the end.
 */
static int tamper_corrupt_continuation(uint8_t *response_buf,
                                       size_t *response_len,
                                       uint8_t cmd,
                                       int call_count,
                                       void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len > 2) {
        response_buf[2] ^= 0xFF;
    }
    return 0;
}

static void test_get_preimage_corrupted_continuation(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_corrupt_continuation, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_true(result < 0);
}

/**
 * Adversarial: client returns a preimage_len > UINT32_MAX (in the 9-byte varint
 * encoding).  call_get_preimage should reject it with -11.
 */
static int tamper_preimage_len_too_big(uint8_t *response_buf,
                                       size_t *response_len,
                                       uint8_t cmd,
                                       int call_count,
                                       void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE) {
        /* Rewrite the response with a 9-byte varint encoding 2^32 (overflow). */
        response_buf[0] = 0xFF; /* 9-byte varint marker */
        /* Little-endian uint64 = 0x0000000100000000 (= 2^32) */
        response_buf[1] = 0x00;
        response_buf[2] = 0x00;
        response_buf[3] = 0x00;
        response_buf[4] = 0x00;
        response_buf[5] = 0x01;
        response_buf[6] = 0x00;
        response_buf[7] = 0x00;
        response_buf[8] = 0x00;
        response_buf[9] = 0x00; /* partial_data_len */
        *response_len = 10;
    }
    return 0;
}

static void test_get_preimage_overflow_len(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_preimage_len_too_big, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    /* preimage_len_u64 > UINT32_MAX → return -11 */
    assert_int_equal(result, -11);
}

/**
 * Adversarial: client claims partial_data_len > preimage_len, while also
 * supplying enough trailing bytes to satisfy buffer_can_read.  Must hit the
 * `partial_data_len > preimage_len` check (return -4), not -2.
 */
static int tamper_partial_len_strictly_over(uint8_t *response_buf,
                                            size_t *response_len,
                                            uint8_t cmd,
                                            int call_count,
                                            void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_PREIMAGE && *response_len >= 2) {
        uint8_t preimage_len = response_buf[0];
        /* Claim one more byte than actually exists in the preimage. */
        response_buf[1] = preimage_len + 1;
        /* Append a single dummy byte so buffer_can_read(partial_data_len) passes. */
        response_buf[*response_len] = 0xCC;
        (*response_len)++;
    }
    return 0;
}

static void test_get_preimage_partial_len_strictly_over(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[5] = {0x10, 0x20, 0x30, 0x40, 0x50};
    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_partial_len_strictly_over, NULL);

    uint8_t out[256];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -4);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, client returns elements_len != 1 while
 * setting n_bytes = 0 so buffer_can_read(0) trivially passes — exercises the
 * `elements_len != 1` rejection (return -7).
 */
static int tamper_more_elements_bad_size_strict(uint8_t *response_buf,
                                                size_t *response_len,
                                                uint8_t cmd,
                                                int call_count,
                                                void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        response_buf[0] = 0; /* n_bytes = 0 → buffer_can_read(0) is true */
        response_buf[1] = 2; /* elements_len = 2 (invalid) */
    }
    return 0;
}

static void test_get_preimage_bad_element_size_strict(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i & 0xFF);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_elements_bad_size_strict, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -7);
}

/**
 * Adversarial: during GET_MORE_ELEMENTS, client claims n_bytes > bytes_remaining
 * but pads the buffer so buffer_can_read still passes — exercises the
 * `n_bytes > bytes_remaining` rejection (return -8).
 */
static int tamper_more_bytes_with_padding(uint8_t *response_buf,
                                          size_t *response_len,
                                          uint8_t cmd,
                                          int call_count,
                                          void *user_data) {
    (void) user_data;
    (void) call_count;

    if (cmd == CCMD_GET_MORE_ELEMENTS && *response_len >= 2) {
        uint8_t orig_n = response_buf[0];
        response_buf[0] = orig_n + 1;
        /* Pad one extra byte so buffer_can_read((orig_n+1)*1) still passes. */
        response_buf[*response_len] = 0xAB;
        (*response_len)++;
    }
    return 0;
}

static void test_get_preimage_more_bytes_strict(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[254];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i * 7);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_more_bytes_with_padding, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_int_equal(result, -8);
}

/**
 * Adversarial: communication failure mid-transfer (process_interruption fails
 * on the second call).
 */
static int tamper_fail_second_call(uint8_t *response_buf,
                                   size_t *response_len,
                                   uint8_t cmd,
                                   int call_count,
                                   void *user_data) {
    (void) response_buf;
    (void) response_len;
    (void) cmd;
    (void) user_data;

    if (call_count >= 1) {
        return -1;
    }
    return 0;
}

static void test_get_preimage_communication_failure(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t preimage[300];
    for (size_t i = 0; i < sizeof(preimage); i++) {
        preimage[i] = (uint8_t) (i * 3);
    }

    mock_dispatcher_add_preimage(mock, preimage, sizeof(preimage));

    uint8_t hash[32];
    compute_sha256(preimage, sizeof(preimage), hash);

    mock_dispatcher_set_tamper_hook(mock, tamper_fail_second_call, NULL);

    uint8_t out[512];
    dispatcher_context_t *dc = mock_dispatcher_get_dc(mock);
    int result = call_get_preimage(dc, hash, out, sizeof(out));

    assert_true(result < 0);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_get_preimage_small),
        T(test_get_preimage_large),
        T(test_get_preimage_unknown_hash),
        T(test_get_preimage_buffer_too_small),
        T(test_get_preimage_one_byte),
        T(test_get_preimage_exact_fit),
        T(test_get_preimage_one_byte_overflow),
        T(test_get_preimage_corrupted_data),
        T(test_get_preimage_partial_len_overflow),
        T(test_get_preimage_zero_len),
        T(test_get_preimage_bad_element_size),
        T(test_get_preimage_more_bytes_than_remaining),
        T(test_get_preimage_corrupted_continuation),
        T(test_get_preimage_overflow_len),
        T(test_get_preimage_partial_len_strictly_over),
        T(test_get_preimage_bad_element_size_strict),
        T(test_get_preimage_more_bytes_strict),
        T(test_get_preimage_communication_failure),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
