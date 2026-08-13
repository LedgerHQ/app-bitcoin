/**
 * Unit tests for the per-field PSBT accessors in handler/sign_psbt/psbt_fields.c.
 *
 * The property under test throughout is that the three outcomes stay separated: a field that is
 * not in the map (PSBT_FIELD_ABSENT), a field that is there and well-formed (PSBT_FIELD_PRESENT),
 * and a field that is there but cannot be used (PSBT_FIELD_ERROR).
 *
 * This matters because the callers of the optional fields substitute a default value on ABSENT.
 * If a malformed or unfetchable field were reported as absent, the device would hash and sign that
 * default even though the client committed to something else.
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

#include "common/psbt.h"
#include "handler/sign_psbt/psbt_fields.h"

/* ---------- Helpers ---------- */

/**
 * Registers a map holding a single (key_type, value) pair and returns its commitment.
 */
static void map_with_one_field(mock_dispatcher_t *mock,
                               uint8_t key_type,
                               const uint8_t *value,
                               size_t value_len,
                               merkleized_map_commitment_t *out) {
    const uint8_t key[] = {key_type};
    const uint8_t *keys[] = {key};
    const size_t key_lens[] = {sizeof(key)};
    const uint8_t *values[] = {value};
    const size_t value_lens[] = {value_len};

    mock_dispatcher_add_map(mock, keys, key_lens, values, value_lens, 1, out);
}

/**
 * Registers a map holding a single unrelated field, so that lookups of anything else are absent.
 */
static void map_without_field(mock_dispatcher_t *mock, merkleized_map_commitment_t *out) {
    /* An arbitrary key type that none of the accessors under test reads. */
    const uint8_t filler[] = {0xAB};
    map_with_one_field(mock, 0xFD, filler, sizeof(filler), out);
}

/* ---------- PSBT_IN_SEQUENCE (optional) ---------- */

static void test_sequence_present(void **state) {
    mock_dispatcher_t *mock = *state;

    /* 0x12345678 little-endian */
    const uint8_t value[] = {0x78, 0x56, 0x34, 0x12};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_SEQUENCE, value, sizeof(value), &map);

    uint32_t got = 0;
    psbt_field_status_t status = psbt_get_input_sequence(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 0x12345678u);
}

static void test_sequence_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status = psbt_get_input_sequence(mock_dispatcher_get_dc(mock), &map, &got);

    /* Only this outcome may lead the caller to substitute the 0xFFFFFFFF default. */
    assert_int_equal(status, PSBT_FIELD_ABSENT);
    assert_int_equal(got, 0xCAFEBABEu);
}

/**
 * A present-but-malformed nSequence must NOT be reported as absent. This is the case that used to
 * silently yield the 0xFFFFFFFF default.
 */
static void test_sequence_wrong_length_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t too_short[] = {0x01, 0x02, 0x03};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_SEQUENCE, too_short, sizeof(too_short), &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status = psbt_get_input_sequence(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
    assert_int_equal(got, 0xCAFEBABEu);
}

static void test_sequence_too_long_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t too_long[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_SEQUENCE, too_long, sizeof(too_long), &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status = psbt_get_input_sequence(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
    assert_int_equal(got, 0xCAFEBABEu);
}

/* ---------- PSBT_GLOBAL_FALLBACK_LOCKTIME (optional) ---------- */

static void test_fallback_locktime_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t value[] = {0xD2, 0x04, 0x00, 0x00}; /* 1234 */
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_GLOBAL_FALLBACK_LOCKTIME, value, sizeof(value), &map);

    uint32_t got = 0;
    psbt_field_status_t status =
        psbt_get_global_fallback_locktime(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 1234);
}

static void test_fallback_locktime_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status =
        psbt_get_global_fallback_locktime(mock_dispatcher_get_dc(mock), &map, &got);

    /* Only this outcome may lead the caller to substitute locktime 0. */
    assert_int_equal(status, PSBT_FIELD_ABSENT);
    assert_int_equal(got, 0xCAFEBABEu);
}

static void test_fallback_locktime_wrong_length_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t wrong_length[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    merkleized_map_commitment_t map;
    map_with_one_field(mock,
                       PSBT_GLOBAL_FALLBACK_LOCKTIME,
                       wrong_length,
                       sizeof(wrong_length),
                       &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status =
        psbt_get_global_fallback_locktime(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
    assert_int_equal(got, 0xCAFEBABEu);
}

/**
 * Regression: the accessor used to read into a 9-byte buffer and map every negative result to
 * PSBT_FIELD_ABSENT. A value longer than that buffer therefore came back as "absent", and the
 * caller substituted locktime 0 for a field the client had actually committed to. It must be an
 * error.
 */
static void test_fallback_locktime_over_buffer_is_error_not_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t very_long[12];
    memset(very_long, 0x77, sizeof(very_long));

    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_GLOBAL_FALLBACK_LOCKTIME, very_long, sizeof(very_long), &map);

    uint32_t got = 0xCAFEBABEu;
    psbt_field_status_t status =
        psbt_get_global_fallback_locktime(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
    assert_int_equal(got, 0xCAFEBABEu);
}

/* ---------- Mandatory fields ---------- */

static void test_prevout_txid_present(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t txid[32];
    memset(txid, 0x5A, sizeof(txid));

    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_PREVIOUS_TXID, txid, sizeof(txid), &map);

    uint8_t got[32];
    memset(got, 0, sizeof(got));
    psbt_field_status_t status =
        psbt_get_input_prevout_txid(mock_dispatcher_get_dc(mock), &map, got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_memory_equal(got, txid, sizeof(txid));
}

static void test_prevout_txid_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint8_t got[32];
    psbt_field_status_t status =
        psbt_get_input_prevout_txid(mock_dispatcher_get_dc(mock), &map, got);

    /* Fatal for the caller either way, but still reported distinctly from a malformed value. */
    assert_int_equal(status, PSBT_FIELD_ABSENT);
}

/**
 * A short txid must be rejected rather than accepted with an uninitialized tail.
 */
static void test_prevout_txid_short_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t txid[31];
    memset(txid, 0x5A, sizeof(txid));

    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_PREVIOUS_TXID, txid, sizeof(txid), &map);

    uint8_t got[32];
    psbt_field_status_t status =
        psbt_get_input_prevout_txid(mock_dispatcher_get_dc(mock), &map, got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
}

static void test_output_amount_present(void **state) {
    mock_dispatcher_t *mock = *state;

    /* 0x0102030405060708 little-endian */
    const uint8_t value[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_OUT_AMOUNT, value, sizeof(value), &map);

    uint64_t got = 0;
    psbt_field_status_t status = psbt_get_output_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_true(got == 0x0102030405060708ull);
}

static void test_output_amount_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint64_t got = 0;
    psbt_field_status_t status = psbt_get_output_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ABSENT);
}

static void test_output_amount_wrong_length_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t value[] = {0x01, 0x02, 0x03, 0x04};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_OUT_AMOUNT, value, sizeof(value), &map);

    uint64_t got = 0;
    psbt_field_status_t status = psbt_get_output_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
}

/* ---------- Key-type pinning for the remaining fixed-width fields ---------- */

/*
 * These accessors are one-line delegations to the shared readers, whose behaviour is already
 * exercised above. What is specific to each of them - and what nothing else would catch - is that
 * it names the right PSBT key type: reading the wrong one would report the field as absent, and
 * the caller would silently carry on with a default.
 */

static void test_global_tx_version_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t value[] = {0x02, 0x00, 0x00, 0x00};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_GLOBAL_TX_VERSION, value, sizeof(value), &map);

    uint32_t got = 0;
    psbt_field_status_t status =
        psbt_get_global_tx_version(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 2);
}

static void test_prevout_index_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t value[] = {0x03, 0x00, 0x00, 0x00};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_OUTPUT_INDEX, value, sizeof(value), &map);

    uint32_t got = 0;
    psbt_field_status_t status =
        psbt_get_input_prevout_index(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 3);
}

static void test_sighash_type_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t value[] = {0x01, 0x00, 0x00, 0x00};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_SIGHASH_TYPE, value, sizeof(value), &map);

    uint32_t got = 0;
    psbt_field_status_t status =
        psbt_get_input_sighash_type(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 1);
}

/* ---------- Variable-length fields ---------- */

static void test_output_script_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t script[] = {0x76, 0xA9, 0x14, 0x01, 0x02, 0x03};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_OUT_SCRIPT, script, sizeof(script), &map);

    uint8_t got[64];
    size_t got_len = 0;
    psbt_field_status_t status =
        psbt_get_output_script(mock_dispatcher_get_dc(mock), &map, got, sizeof(got), &got_len);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got_len, sizeof(script));
    assert_memory_equal(got, script, sizeof(script));
}

static void test_output_script_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint8_t got[64];
    size_t got_len = 0;
    psbt_field_status_t status =
        psbt_get_output_script(mock_dispatcher_get_dc(mock), &map, got, sizeof(got), &got_len);

    assert_int_equal(status, PSBT_FIELD_ABSENT);
}

/**
 * A script longer than the caller's buffer is an error, not an absent field.
 */
static void test_output_script_too_long_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    uint8_t script[40];
    memset(script, 0x51, sizeof(script));

    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_OUT_SCRIPT, script, sizeof(script), &map);

    uint8_t got[16];
    size_t got_len = 0;
    psbt_field_status_t status =
        psbt_get_output_script(mock_dispatcher_get_dc(mock), &map, got, sizeof(got), &got_len);

    assert_int_equal(status, PSBT_FIELD_ERROR);
}

static void test_redeem_script_present(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t script[] = {0xA9, 0x14, 0xDE, 0xAD, 0xBE, 0xEF, 0x87};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_REDEEM_SCRIPT, script, sizeof(script), &map);

    uint8_t got[64];
    size_t got_len = 0;
    psbt_field_status_t status =
        psbt_get_input_redeem_script(mock_dispatcher_get_dc(mock), &map, got, sizeof(got), &got_len);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got_len, sizeof(script));
    assert_memory_equal(got, script, sizeof(script));
}

/* ---------- Witness UTXO amount ---------- */

/**
 * The witness UTXO is a serialized txout: [8-byte amount][varint len][scriptPubKey]. The accessor
 * reads the whole value but returns only the amount.
 */
static void test_witness_utxo_amount_present(void **state) {
    mock_dispatcher_t *mock = *state;

    /* amount 0x0000000005F5E100 (100000000) little-endian, then a 22-byte P2WPKH scriptPubKey. */
    uint8_t txout[8 + 1 + 22];
    memset(txout, 0, sizeof(txout));
    txout[0] = 0x00;
    txout[1] = 0xE1;
    txout[2] = 0xF5;
    txout[3] = 0x05;
    txout[8] = 22;
    memset(txout + 9, 0x33, 22);

    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_WITNESS_UTXO, txout, sizeof(txout), &map);

    uint64_t got = 0;
    psbt_field_status_t status =
        psbt_get_input_witness_utxo_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_PRESENT);
    assert_int_equal(got, 100000000u);
}

static void test_witness_utxo_amount_absent(void **state) {
    mock_dispatcher_t *mock = *state;

    merkleized_map_commitment_t map;
    map_without_field(mock, &map);

    uint64_t got = 0xCAFEBABEu;
    psbt_field_status_t status =
        psbt_get_input_witness_utxo_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ABSENT);
    assert_int_equal(got, 0xCAFEBABEu);
}

/**
 * A witness UTXO too short to even contain the 8-byte amount is malformed, not absent: defaulting
 * on it would mean signing over an amount the client never committed to.
 */
static void test_witness_utxo_amount_too_short_is_error(void **state) {
    mock_dispatcher_t *mock = *state;

    const uint8_t truncated[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    merkleized_map_commitment_t map;
    map_with_one_field(mock, PSBT_IN_WITNESS_UTXO, truncated, sizeof(truncated), &map);

    uint64_t got = 0xCAFEBABEu;
    psbt_field_status_t status =
        psbt_get_input_witness_utxo_amount(mock_dispatcher_get_dc(mock), &map, &got);

    assert_int_equal(status, PSBT_FIELD_ERROR);
    assert_int_equal(got, 0xCAFEBABEu);
}

/* ---------- Main ---------- */

int main(void) {
#define T(fn) cmocka_unit_test_setup_teardown(fn, mock_dispatcher_setup, mock_dispatcher_teardown)
    const struct CMUnitTest tests[] = {
        T(test_sequence_present),
        T(test_sequence_absent),
        T(test_sequence_wrong_length_is_error),
        T(test_sequence_too_long_is_error),
        T(test_fallback_locktime_present),
        T(test_fallback_locktime_absent),
        T(test_fallback_locktime_wrong_length_is_error),
        T(test_fallback_locktime_over_buffer_is_error_not_absent),
        T(test_prevout_txid_present),
        T(test_prevout_txid_absent),
        T(test_prevout_txid_short_is_error),
        T(test_output_amount_present),
        T(test_output_amount_absent),
        T(test_output_amount_wrong_length_is_error),
        T(test_global_tx_version_present),
        T(test_prevout_index_present),
        T(test_sighash_type_present),
        T(test_output_script_present),
        T(test_output_script_absent),
        T(test_output_script_too_long_is_error),
        T(test_redeem_script_present),
        T(test_witness_utxo_amount_present),
        T(test_witness_utxo_amount_absent),
        T(test_witness_utxo_amount_too_short_is_error),
    };
#undef T

    return cmocka_run_group_tests(tests, NULL, NULL);
}
