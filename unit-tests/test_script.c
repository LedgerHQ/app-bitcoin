#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

// missing definitions to make it compile without the SDK
#define PRINTF(...) printf
#define PIC(x)      (x)

#include "common/script.h"

static void test_get_push_script_size(void **state) {
    (void) state;

    assert_int_equal(get_push_script_size((uint32_t) 0), 1);
    assert_int_equal(get_push_script_size((uint32_t) 1), 1);
    assert_int_equal(get_push_script_size((uint32_t) 15), 1);
    assert_int_equal(get_push_script_size((uint32_t) 16), 1);
    assert_int_equal(get_push_script_size((uint32_t) 17), 2);
    assert_int_equal(get_push_script_size((uint32_t) 0x7f), 2);
    assert_int_equal(get_push_script_size((uint32_t) 0x80), 3);
    assert_int_equal(get_push_script_size((uint32_t) 0xff), 3);
    assert_int_equal(get_push_script_size((uint32_t) 0x7fff), 3);
    assert_int_equal(get_push_script_size((uint32_t) 0x8000), 4);
    assert_int_equal(get_push_script_size((uint32_t) 0x7fffff), 4);
    assert_int_equal(get_push_script_size((uint32_t) 0x800000), 5);
    assert_int_equal(get_push_script_size((uint32_t) 0x7fffffff), 5);
    assert_int_equal(get_push_script_size((uint32_t) 0x80000000), 6);
    assert_int_equal(get_push_script_size((uint32_t) 0xffffffff), 6);
}

static void test_get_script_type_valid(void **state) {
    (void) state;

    uint8_t p2pkh[] = {OP_DUP, OP_HASH160, 0x14, 0x01, 0x02, 0x03,           0x04,       0x05, 0x06,
                       0x07,   0x08,       0x09, 0x0a, 0x0b, 0x0c,           0x0d,       0x0e, 0x0f,
                       0x10,   0x11,       0x12, 0x13, 0x14, OP_EQUALVERIFY, OP_CHECKSIG};
    assert_int_equal(get_script_type(p2pkh, sizeof(p2pkh)), SCRIPT_TYPE_P2PKH);

    uint8_t p2sh[] = {OP_HASH160, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,    0x06,
                      0x07,       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,    0x0e,
                      0x0f,       0x10, 0x11, 0x12, 0x13, 0x14, OP_EQUAL};
    assert_int_equal(get_script_type(p2sh, sizeof(p2sh)), SCRIPT_TYPE_P2SH);

    uint8_t p2wpkh[] = {OP_0, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14};
    assert_int_equal(get_script_type(p2wpkh, sizeof(p2wpkh)), SCRIPT_TYPE_P2WPKH);

    uint8_t p2wsh[] = {OP_0, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                       0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                       0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    assert_int_equal(get_script_type(p2wsh, sizeof(p2wsh)), SCRIPT_TYPE_P2WSH);

    uint8_t p2tr[] = {OP_1, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    assert_int_equal(get_script_type(p2tr, sizeof(p2tr)), SCRIPT_TYPE_P2TR);

    // unknown (but valid) segwit scriptPubKeys
    uint8_t unknown1[] = {OP_0, 0x2, 0x01, 0x02};
    assert_int_equal(get_script_type(unknown1, sizeof(unknown1)), SCRIPT_TYPE_UNKNOWN_SEGWIT);
    uint8_t unknown2[] = {OP_16, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                          0x0b,  0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                          0x17,  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    assert_int_equal(get_script_type(unknown2, sizeof(unknown2)), SCRIPT_TYPE_UNKNOWN_SEGWIT);
}

static void test_get_script_type_invalid(void **state) {
    (void) state;

    uint8_t opreturn[] = {OP_RETURN, OP_0};  // valid OP_RETURN, but it doesn't have an address
    assert_int_equal(get_script_type(opreturn, sizeof(opreturn)), -1);

    assert_int_equal(get_script_type(opreturn, 0), -1);  // empty script is invalid

    uint8_t p2pkh_short[] = {
        OP_DUP, OP_HASH160, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06,   0x07,       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e,   0x0f,       0x10, 0x11, 0x12, 0x13, 0x14, OP_EQUALVERIFY};  // missing OP_CHECKSIG
    assert_int_equal(get_script_type(p2pkh_short, sizeof(p2pkh_short)), -1);

    uint8_t p2pkh_long[] = {OP_DUP, OP_HASH160, 0x14,           0x01,        0x02,  0x03, 0x04,
                            0x05,   0x06,       0x07,           0x08,        0x09,  0x0a, 0x0b,
                            0x0c,   0x0d,       0x0e,           0x0f,        0x10,  0x11, 0x12,
                            0x13,   0x14,       OP_EQUALVERIFY, OP_CHECKSIG, OP_NOP};  // extra byte
    assert_int_equal(get_script_type(p2pkh_long, sizeof(p2pkh_long)), -1);

    uint8_t p2sh_short[] = {OP_HASH160, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07,       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                            0x0f,       0x10, 0x11, 0x12, 0x13, 0x14};  // missing OP_EQUAL
    assert_int_equal(get_script_type(p2sh_short, sizeof(p2sh_short)), -1);

    uint8_t p2sh_long[] = {OP_HASH160, 0x14, 0x01, 0x02, 0x03,     0x04,  0x05, 0x06, 0x07,
                           0x08,       0x09, 0x0a, 0x0b, 0x0c,     0x0d,  0x0e, 0x0f, 0x10,
                           0x11,       0x12, 0x13, 0x14, OP_EQUAL, OP_NOP};  // extra byte
    assert_int_equal(get_script_type(p2sh_long, sizeof(p2sh_long)), -1);

    uint8_t p2wpkh_short[] = {
        OP_0, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};  // one byte too short
    assert_int_equal(get_script_type(p2wpkh_short, sizeof(p2wpkh_short)), -1);

    uint8_t p2wpkh_long[] = {OP_0, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05,  0x06,
                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,  0x0e,
                             0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, OP_NOP};  // one byte too long
    assert_int_equal(get_script_type(p2wpkh_long, sizeof(p2wpkh_long)), -1);

    uint8_t p2wsh_short[] = {
        OP_0, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};  // one byte too short
    assert_int_equal(get_script_type(p2wsh_short, sizeof(p2wsh_short)), -1);

    uint8_t p2wsh_long[] = {
        OP_0, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,  0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,  0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, OP_NOP};  // one byte too long
    assert_int_equal(get_script_type(p2wsh_long, sizeof(p2wsh_long)), -1);

    uint8_t p2tr_short[] = {
        OP_1, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};  // one byte too short
    assert_int_equal(get_script_type(p2tr_short, sizeof(p2tr_short)), -1);

    uint8_t p2tr_long[] = {OP_1, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,  0x0a,
                           0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,  0x16,
                           0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, OP_NOP};
    assert_int_equal(get_script_type(p2tr_long, sizeof(p2tr_long)), -1);

    // segwit witness program must be at least 2 bytes
    uint8_t segwit_too_short[] = {OP_1, 0x01, 0x01};
    assert_int_equal(get_script_type(segwit_too_short, sizeof(segwit_too_short)), -1);

    // segwit witness program must be at most 40 bytes
    uint8_t segwit_too_long[] = {OP_16, 41, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                                 13,    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                                 28,    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 41};
    assert_int_equal(get_script_type(segwit_too_long, sizeof(segwit_too_long)), -1);
}

#define CHECK_VALID_TESTCASE(script, expected)                         \
    {                                                                  \
        char out[MAX_OPRETURN_OUTPUT_DESC_SIZE];                       \
        int ret = format_opscript_script(script, sizeof(script), out); \
        assert_int_equal(ret, sizeof(expected));                       \
        assert_string_equal(out, expected);                            \
    }

#define CHECK_INVALID_TESTCASE(script)                                 \
    {                                                                  \
        char out[MAX_OPRETURN_OUTPUT_DESC_SIZE];                       \
        int ret = format_opscript_script(script, sizeof(script), out); \
        assert_int_equal(ret, -1);                                     \
    }

static void test_format_opscript_script_valid(void **state) {
    (void) state;

    uint8_t input0[] = {OP_RETURN, OP_0};
    CHECK_VALID_TESTCASE(input0, "OP_RETURN 0");
    uint8_t input1[] = {OP_RETURN, OP_1};
    CHECK_VALID_TESTCASE(input1, "OP_RETURN 1");
    uint8_t input2[] = {OP_RETURN, OP_2};
    CHECK_VALID_TESTCASE(input2, "OP_RETURN 2");
    uint8_t input3[] = {OP_RETURN, OP_3};
    CHECK_VALID_TESTCASE(input3, "OP_RETURN 3");
    uint8_t input4[] = {OP_RETURN, OP_4};
    CHECK_VALID_TESTCASE(input4, "OP_RETURN 4");
    uint8_t input5[] = {OP_RETURN, OP_5};
    CHECK_VALID_TESTCASE(input5, "OP_RETURN 5");
    uint8_t input6[] = {OP_RETURN, OP_6};
    CHECK_VALID_TESTCASE(input6, "OP_RETURN 6");
    uint8_t input7[] = {OP_RETURN, OP_7};
    CHECK_VALID_TESTCASE(input7, "OP_RETURN 7");
    uint8_t input8[] = {OP_RETURN, OP_8};
    CHECK_VALID_TESTCASE(input8, "OP_RETURN 8");
    uint8_t input9[] = {OP_RETURN, OP_9};
    CHECK_VALID_TESTCASE(input9, "OP_RETURN 9");
    uint8_t input10[] = {OP_RETURN, OP_10};
    CHECK_VALID_TESTCASE(input10, "OP_RETURN 10");
    uint8_t input11[] = {OP_RETURN, OP_11};
    CHECK_VALID_TESTCASE(input11, "OP_RETURN 11");
    uint8_t input12[] = {OP_RETURN, OP_12};
    CHECK_VALID_TESTCASE(input12, "OP_RETURN 12");
    uint8_t input13[] = {OP_RETURN, OP_13};
    CHECK_VALID_TESTCASE(input13, "OP_RETURN 13");
    uint8_t input14[] = {OP_RETURN, OP_14};
    CHECK_VALID_TESTCASE(input14, "OP_RETURN 14");
    uint8_t input15[] = {OP_RETURN, OP_15};
    CHECK_VALID_TESTCASE(input15, "OP_RETURN 15");
    uint8_t input16[] = {OP_RETURN, OP_16};
    CHECK_VALID_TESTCASE(input16, "OP_RETURN 16");

    uint8_t input17[] = {OP_RETURN, 1, 0x42};
    CHECK_VALID_TESTCASE(input17, "OP_RETURN 0x42");

    uint8_t input18[] = {OP_RETURN, 5, 0x11, 0x22, 0x33, 0x44, 0x55};
    CHECK_VALID_TESTCASE(input18, "OP_RETURN 0x1122334455");

    uint8_t input19[] = {OP_RETURN, 75, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13,
                         14,        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                         30,        31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
                         46,        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
                         62,        63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74};
    CHECK_VALID_TESTCASE(
        input19,
        "OP_RETURN "
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"
        "262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a");

    uint8_t input21[] = {OP_RETURN, OP_PUSHDATA1, 80, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11,        12,           13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                         25,        26,           27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                         39,        40,           41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                         53,        54,           55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
                         67,        68,           69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79};
    CHECK_VALID_TESTCASE(
        input21,
        "OP_RETURN "
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
        "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");

    uint8_t input22[] = {OP_RETURN, OP_1NEGATE};
    CHECK_VALID_TESTCASE(input22, "OP_RETURN -1");

    uint8_t input23[] = {OP_RETURN, OP_0, OP_1, OP_5, OP_7, OP_16};
    CHECK_VALID_TESTCASE(input23, "OP_RETURN 0 1 5 7 16");

    uint8_t input24[] = {OP_RETURN, OP_8, OP_1NEGATE, 15,   1,    2,    3,    4,   5,  6,
                         7,         8,    9,          10,   11,   12,   13,   14,  15, OP_0,
                         7,         0x11, 0x22,       0x33, 0x44, 0x55, 0x66, 0x77};
    CHECK_VALID_TESTCASE(input24,
                         "OP_RETURN 8 -1 0x0102030405060708090a0b0c0d0e0f 0 0x11223344556677");

    // because the number 0 is encoded as OP_0, the minimal push for the byte sequence 0x00 is
    // done with OP_PUSHDATA1 (unlike pushes for 0x01 to 0x10 that would use OP_1 to OP_16)
    uint8_t input25[] = {OP_RETURN, OP_13, 1, 0x00};
    CHECK_VALID_TESTCASE(input25, "OP_RETURN 13 0x00");

    uint8_t input_26[] = {OP_RETURN};
    CHECK_VALID_TESTCASE(input_26, "OP_RETURN");
}

static void test_format_opscript_script_invalid(void **state) {
    (void) state;

    uint8_t input_empty[] = {0};  // can't declare 0-length array
    char out[MAX_OPRETURN_OUTPUT_DESC_SIZE];
    assert_int_equal(format_opscript_script(input_empty, 0, out), -1);

    uint8_t input_not_opreturn[] = {OP_DUP};
    CHECK_INVALID_TESTCASE(input_not_opreturn);

    uint8_t input_op_reserved[] = {OP_RETURN, OP_RESERVED};
    CHECK_INVALID_TESTCASE(input_op_reserved);

    // valid OP_RETURN with OP_PUSHDATA2, but we don't support it
    uint8_t input_pushdata2[] =
        {OP_RETURN, OP_PUSHDATA2, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    CHECK_INVALID_TESTCASE(input_pushdata2);

    // valid OP_RETURN with OP_PUSHDATA4, but we don't support it
    uint8_t input_pushdata4[] =
        {OP_RETURN, OP_PUSHDATA4, 0x06, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    CHECK_INVALID_TESTCASE(input_pushdata4);

    uint8_t input_extra_push[] = {OP_RETURN, 4, 1, 2, 3, 4, 42};
    CHECK_INVALID_TESTCASE(input_extra_push);

    uint8_t input_6pushes[] = {OP_RETURN, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6};
    CHECK_INVALID_TESTCASE(input_6pushes);

    // clang-format off
    uint8_t input_too_long[] = {
        OP_RETURN,
        OP_PUSHDATA1, 81,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        81
    };
    // clang-format on
    CHECK_INVALID_TESTCASE(input_too_long);

    // not minimal push encodings
    uint8_t input_pushdata_nonstandard[] =
        {OP_RETURN, OP_PUSHDATA1, 7, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    CHECK_INVALID_TESTCASE(input_pushdata_nonstandard);

    uint8_t input_negative1_notminimal_1[] = {OP_RETURN, 1, 0x81};
    CHECK_INVALID_TESTCASE(input_negative1_notminimal_1);
    uint8_t input_negative1_notminimal_2[] = {OP_RETURN, OP_PUSHDATA1, 1, 0x81};
    CHECK_INVALID_TESTCASE(input_negative1_notminimal_2);
    for (uint8_t i = 1; i <= 16; i++) {
        uint8_t input_negative1_notminimal_push_1[] = {OP_RETURN, 1, i};
        CHECK_INVALID_TESTCASE(input_negative1_notminimal_push_1);
        uint8_t input_negative1_notminimal_push_2[] = {OP_RETURN, OP_PUSHDATA1, 1, i};
        CHECK_INVALID_TESTCASE(input_negative1_notminimal_push_2);
    }

    // transaction containing non-push opcodes are not standard
    uint8_t input_non_push_opcode[] = {OP_RETURN, OP_3, OP_2, OP_ADD, OP_0};
    CHECK_INVALID_TESTCASE(input_non_push_opcode);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_push_script_size),
        cmocka_unit_test(test_get_script_type_valid),
        cmocka_unit_test(test_get_script_type_invalid),
        cmocka_unit_test(test_format_opscript_script_valid),
        cmocka_unit_test(test_format_opscript_script_invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
