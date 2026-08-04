#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <cmocka.h>

#include "common/parser.h"

// An example parser that reads an uint32_t, an array of 8 bytes, and an uint8_t.
typedef struct {
    uint32_t a;
    uint8_t b[8];
    uint8_t c;
} parse_ABC_state_t;

static int parse_A(parse_ABC_state_t *state, buffer_t *buffers[2]) {
    return dbuffer_read_u32(buffers, &state->a, BE);
}

static int parse_B(parse_ABC_state_t *state, buffer_t *buffers[2]) {
    return dbuffer_read_bytes(buffers, state->b, 8);
}

static int parse_C(parse_ABC_state_t *state, buffer_t *buffers[2]) {
    return dbuffer_read_u8(buffers, &state->c);
}

const parsing_step_t parse_ABC_steps[] = {(parsing_step_t) parse_A,
                                          (parsing_step_t) parse_B,
                                          (parsing_step_t) parse_C};

const size_t n_ABC_STEPS = sizeof(parse_ABC_steps) / sizeof(parse_ABC_steps[0]);

// A function that simulates a parsing error while parsing B
static int parse_B_error(parse_ABC_state_t *state, buffer_t *buffers[2]) {
    return -1;
}

// A parser similar to parse_ABC, but always generates an error in the second parsing step
const parsing_step_t parse_ABC_error_steps[] = {(parsing_step_t) parse_A,
                                                (parsing_step_t) parse_B_error,
                                                (parsing_step_t) parse_C};

static void test_parser_init_context(void **state) {
    (void) state;

    parser_context_t parser_context;
    parser_context.cur_step = 42;
    parser_context.state = NULL;

    parse_ABC_state_t parser_state;

    parser_init_context(&parser_context, &parser_state);

    assert_int_equal(parser_context.cur_step, 0);
    assert_ptr_equal(parser_context.state, &parser_state);
}

static void test_parser_oneshot_from_store(void **state) {
    (void) state;

    // in this test, all the data is fetched from the store
    // clang-format off
    uint8_t store[32] = {
        0xa0, 0xa1, 0xa2, 0xa3,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xc0
    };
    // clang-format on

    uint8_t stream[32] = {0};

    buffer_t store_buf = buffer_create(store, sizeof(store));
    buffer_t stream_buf = buffer_create(stream, sizeof(stream));
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state;
    parser_context_t parser_context;

    memset(&parser_state, 0, sizeof(parser_state));

    parser_init_context(&parser_context, &parser_state);

    int result = parser_run(parse_ABC_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, 1);
    assert_int_equal(parser_context.cur_step, n_ABC_STEPS);  // parsing completed

    // Check buffer updates
    assert_int_equal(store_buf.offset, 4 + 8 + 1);
    assert_int_equal(stream_buf.offset, 0);

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(parser_state.b[i], 0xb0 + i);
    }
    assert_int_equal(parser_state.c, 0xc0);
}

static void test_parser_oneshot_with_empty_store(void **state) {
    (void) state;

    // in this test, the store is empty all the data is fetched from the stream

    uint8_t store[8];
    // clang-format off
    uint8_t stream[32] = {
        0xa0, 0xa1, 0xa2, 0xa3,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xc0
    };
    // clang-format on

    buffer_t store_buf = buffer_create(store, 0);
    buffer_t stream_buf = buffer_create(stream, 4 + 8 + 1);
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state;
    parser_context_t parser_context;

    memset(&parser_state, 0, sizeof(parser_state));

    parser_init_context(&parser_context, &parser_state);

    int result = parser_run(parse_ABC_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, 1);
    assert_int_equal(parser_context.cur_step, n_ABC_STEPS);  // parsing completed

    // Check buffer updates
    assert_int_equal(store_buf.offset, 0);
    assert_int_equal(stream_buf.offset, 4 + 8 + 1);

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(parser_state.b[i], 0xb0 + i);
    }
    assert_int_equal(parser_state.c, 0xc0);
}

static void test_parser_oneshot_part_store_part_stream(void **state) {
    (void) state;

    // in this test, some data comes from the stream, some from the

    // clang-format off
    uint8_t store[32] = {
        0, 0, 0, 0, 0, // some initial bytes that should be ignored
        0xa0, 0xa1, 0xa2, 0xa3,
        0xb0, 0xb1     // partial parsing
    };
    uint8_t stream[32] = {
        0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, // continuation of the parsing
        0xc0
    };
    // clang-format on

    buffer_t store_buf = buffer_create(store, 5 + 4 + 2);  // size includes the initial zeros
    buffer_seek_cur(&store_buf, 5);                        // skip initial zeros
    buffer_t stream_buf = buffer_create(stream, 6 + 1);
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state;
    parser_context_t parser_context;

    memset(&parser_state, 0, sizeof(parser_state));

    parser_init_context(&parser_context, &parser_state);

    int result = parser_run(parse_ABC_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, 1);
    assert_int_equal(parser_context.cur_step, n_ABC_STEPS);  // parsing completed

    // Check buffer updates
    assert_int_equal(store_buf.offset, 5 + 4 + 2);
    assert_int_equal(stream_buf.offset, 6 + 1);

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(parser_state.b[i], 0xb0 + i);
    }
    assert_int_equal(parser_state.c, 0xc0);
}

static void test_parser_stream_ends(void **state) {
    (void) state;

    // in this test, the stream is exhausted before parsing is complete
    // clang-format off
    uint8_t store[32] = {
        0, 0, 0, 0, 0, // some initial bytes that should be ignored
        0xa0, 0xa1, 0xa2, 0xa3,
        0xb0, 0xb1     // partial parsing
    };
    uint8_t stream[32] = {
        0xb2, 0xb3, 0xb4, 0xb5, 0xb6 // stream ends while parsing the B field
    };
    // clang-format on

    buffer_t store_buf = buffer_create(store, 5 + 4 + 2);  // size includes the initial zeros
    buffer_seek_cur(&store_buf, 5);                        // skip initial zeros
    buffer_t stream_buf = buffer_create(stream, 5);
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state;
    parser_context_t parser_context;

    memset(&parser_state, 0, sizeof(parser_state));

    parser_init_context(&parser_context, &parser_state);

    int result = parser_run(parse_ABC_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, 0);
    assert_int_equal(parser_context.cur_step, 1);  // second parsing step was not completed

    // Check buffer updates
    assert_int_equal(store_buf.offset, 5 + 4);  // affset after reading A
    assert_int_equal(stream_buf.offset,
                     0);  // since read failed, the offset should not have changed

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(parser_state.b[i], 0);  // not parsed yet
    }
    assert_int_equal(parser_state.c, 0);  // not parsed yet
}

static void test_parser_continue_partial(void **state) {
    (void) state;

    // this tests completes the parsing from the point it left in the previous test
    uint8_t store[32] = {
        0xb0,
        0xb1  // leftover from before
    };
    uint8_t stream[32] = {0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xc0};

    buffer_t store_buf = buffer_create(store, 2);
    buffer_t stream_buf = buffer_create(stream, 6 + 1);
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state = {.a = 0xa0a1a2a3, .b = {0}, .c = 0};
    parser_context_t parser_context;

    parser_context.state = &parser_state;
    parser_context.cur_step = 1;  // restart from step_B

    int result = parser_run(parse_ABC_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, 1);
    assert_int_equal(parser_context.cur_step, 3);  // completed

    // Check buffer updates
    assert_int_equal(store_buf.offset, 2);  // affset after reading A
    assert_int_equal(stream_buf.offset,
                     6 + 1);  // since read failed, the offset should not have changed

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(parser_state.b[i], 0xb0 + i);
    }
    assert_int_equal(parser_state.c, 0xc0);
}

static void test_parser_error(void **state) {
    (void) state;

    // in this test, the second parsing stap causes an error; that should be returned
    // clang-format off
    uint8_t store[32] = {
        0xa0, 0xa1, 0xa2, 0xa3,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xc0
    };
    // clang-format on

    uint8_t stream[32] = {0};

    buffer_t store_buf = buffer_create(store, 4 + 8 + 1);
    buffer_t stream_buf = buffer_create(stream, sizeof(stream));
    buffer_t *buffers[2] = {&store_buf, &stream_buf};

    parse_ABC_state_t parser_state;
    parser_context_t parser_context;

    memset(&parser_state, 0, sizeof(parser_state));

    parser_init_context(&parser_context, &parser_state);

    int result = parser_run(parse_ABC_error_steps, n_ABC_STEPS, &parser_context, buffers, NULL);

    assert_int_equal(result, -1);  // parsing error
    assert_int_equal(parser_context.cur_step,
                     1);  // index of the parsing function causing the error

    // Check expected parsing results
    assert_int_equal(parser_state.a, 0xa0a1a2a3);  // a should have been parsed correctly
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parser_init_context),
        cmocka_unit_test(test_parser_oneshot_from_store),
        cmocka_unit_test(test_parser_oneshot_with_empty_store),
        cmocka_unit_test(test_parser_oneshot_part_store_part_stream),
        cmocka_unit_test(test_parser_stream_ends),
        cmocka_unit_test(test_parser_continue_partial),
        cmocka_unit_test(test_parser_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
