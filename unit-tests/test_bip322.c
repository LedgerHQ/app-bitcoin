#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "handler/sign_psbt/bip322.h"

#include "display.h"
#include "handler/sign_psbt/amount_from_psbt.h"
#include "handler/sign_psbt/transaction_display.h"

// ---------------------------------------------------------------------------
// Stubs for the symbols referenced by the flow functions of bip322.c that are
// not under test here (the flows are covered end-to-end by the ragger tests).
// ---------------------------------------------------------------------------

ui_state_t g_ui_state;

const char GA_SIGNING_MESSAGE[] = "Signing message";

void ui_set_processing_screen_text(const char *text) {
    (void) text;
}

bool display_warnings(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    (void) dc, (void) st;
    return true;
}

int get_amount_scriptpubkey_from_psbt(dispatcher_context_t *dc,
                                      const merkleized_map_commitment_t *input_map,
                                      uint64_t *amount,
                                      uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
                                      size_t *scriptPubKey_len) {
    (void) dc, (void) input_map, (void) amount, (void) scriptPubKey, (void) scriptPubKey_len;
    return -1;
}

bool format_default_account_label(int bip44_purpose, uint32_t account, char *out, size_t out_len) {
    (void) bip44_purpose, (void) account, (void) out, (void) out_len;
    return false;
}

bool ui_display_bip322_message_and_confirm(dispatcher_context_t *context,
                                           const char *account,
                                           const char *address,
                                           bool is_hash,
                                           bool has_proven_funds,
                                           uint64_t proven_amount) {
    (void) context, (void) account, (void) address, (void) is_hash;
    (void) has_proven_funds, (void) proven_amount;
    return false;
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

// scriptPubKey of bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l, the address used by the
// test vectors of BIP-322
static const uint8_t CHALLENGE_P2WPKH[] = {0x00, 0x14, 0x2b, 0x05, 0xd5, 0x64, 0xe6, 0xa7,
                                           0xa3, 0x3c, 0x08, 0x7f, 0x16, 0xe0, 0xf7, 0x30,
                                           0xd1, 0x44, 0x01, 0x23, 0x79, 0x9d};

// BIP0322-signed-message tagged hash of ""
static const uint8_t MSG_HASH_EMPTY[32] = {
    0xc9, 0x0c, 0x26, 0x9c, 0x4f, 0x8f, 0xcb, 0xe6, 0x88, 0x0f, 0x72, 0xa7, 0x21, 0xdd, 0xfb, 0xf1,
    0x91, 0x42, 0x68, 0xa7, 0x94, 0xcb, 0xb2, 0x1c, 0xfa, 0xfe, 0xe1, 0x37, 0x70, 0xae, 0x19, 0xf1};

// BIP0322-signed-message tagged hash of "Hello World"
static const uint8_t MSG_HASH_HELLO_WORLD[32] = {
    0xf0, 0xeb, 0x03, 0xb1, 0xa7, 0x5a, 0xc6, 0xd9, 0x84, 0x7f, 0x55, 0xc6, 0x24, 0xa9, 0x91, 0x69,
    0xb5, 0xdc, 0xcb, 0xa2, 0xa3, 0x1f, 0x5b, 0x23, 0xbe, 0xa7, 0x7b, 0xa2, 0x70, 0xde, 0x0a, 0x7a};

// Expected serialization of the to_spend transaction for "Hello World" and CHALLENGE_P2WPKH.
// The to_spend transactions (and their txids below) for "" and "Hello World" are given in the
// test vectors of BIP-322.
static const uint8_t TO_SPEND_HELLO_WORLD[] = {
    // nVersion = 0
    0x00, 0x00, 0x00, 0x00,
    // 1 input: null prevout hash, index 0xffffffff
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff,
    // scriptSig: OP_0 PUSH32(message_hash)
    0x22, 0x00, 0x20, 0xf0, 0xeb, 0x03, 0xb1, 0xa7, 0x5a, 0xc6, 0xd9, 0x84, 0x7f, 0x55, 0xc6, 0x24,
    0xa9, 0x91, 0x69, 0xb5, 0xdc, 0xcb, 0xa2, 0xa3, 0x1f, 0x5b, 0x23, 0xbe, 0xa7, 0x7b, 0xa2, 0x70,
    0xde, 0x0a, 0x7a,
    // nSequence = 0
    0x00, 0x00, 0x00, 0x00,
    // 1 output: value 0, the challenge scriptPubKey
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x2b, 0x05, 0xd5, 0x64,
    0xe6, 0xa7, 0xa3, 0x3c, 0x08, 0x7f, 0x16, 0xe0, 0xf7, 0x30, 0xd1, 0x44, 0x01, 0x23, 0x79, 0x9d,
    // nLockTime = 0
    0x00, 0x00, 0x00, 0x00};

// txid of to_spend for "" (in the byte order used inside transactions, i.e. the reverse of the
// displayed c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7)
static const uint8_t TO_SPEND_TXID_EMPTY[32] = {
    0xa7, 0x99, 0x5a, 0x54, 0x3c, 0x28, 0x66, 0xb5, 0x1b, 0xa9, 0x65, 0xe7, 0x8d, 0x01, 0xde, 0x5d,
    0xb5, 0x04, 0x35, 0xcd, 0xe9, 0xd4, 0x82, 0xbf, 0x60, 0xd8, 0xb8, 0x9b, 0xa6, 0x0a, 0x68, 0xc5};

// txid of to_spend for "Hello World" (reverse of the displayed
// b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b)
static const uint8_t TO_SPEND_TXID_HELLO_WORLD[32] = {
    0x2b, 0x35, 0x03, 0xd6, 0xa2, 0x61, 0x4d, 0xea, 0xf1, 0x71, 0x6c, 0x23, 0x32, 0x5c, 0x53, 0xe0,
    0x51, 0x4b, 0x4a, 0xfc, 0x98, 0x10, 0x1c, 0x77, 0x17, 0x52, 0xad, 0x40, 0x67, 0x19, 0x9d, 0xb7};

static void test_bip322_serialize_to_spend(void **state) {
    (void) state;

    uint8_t out[BIP322_TO_SPEND_MAX_LEN];
    int len = bip322_serialize_to_spend(MSG_HASH_HELLO_WORLD,
                                        CHALLENGE_P2WPKH,
                                        sizeof(CHALLENGE_P2WPKH),
                                        out);

    assert_int_equal(len, sizeof(TO_SPEND_HELLO_WORLD));
    assert_memory_equal(out, TO_SPEND_HELLO_WORLD, sizeof(TO_SPEND_HELLO_WORLD));
}

static void test_bip322_serialize_to_spend_rejects_long_script(void **state) {
    (void) state;

    uint8_t long_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN + 1] = {0};
    uint8_t out[BIP322_TO_SPEND_MAX_LEN];
    assert_int_equal(
        bip322_serialize_to_spend(MSG_HASH_HELLO_WORLD, long_script, sizeof(long_script), out),
        -1);
}

static void test_bip322_compute_to_spend_txid(void **state) {
    (void) state;

    uint8_t txid[32];

    assert_int_equal(bip322_compute_to_spend_txid(MSG_HASH_EMPTY,
                                                  CHALLENGE_P2WPKH,
                                                  sizeof(CHALLENGE_P2WPKH),
                                                  txid),
                     0);
    assert_memory_equal(txid, TO_SPEND_TXID_EMPTY, 32);

    assert_int_equal(bip322_compute_to_spend_txid(MSG_HASH_HELLO_WORLD,
                                                  CHALLENGE_P2WPKH,
                                                  sizeof(CHALLENGE_P2WPKH),
                                                  txid),
                     0);
    assert_memory_equal(txid, TO_SPEND_TXID_HELLO_WORLD, 32);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bip322_serialize_to_spend),
        cmocka_unit_test(test_bip322_serialize_to_spend_rejects_long_script),
        cmocka_unit_test(test_bip322_compute_to_spend_txid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
