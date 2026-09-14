#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "fuzz_bip32.h"
#include "os_utils.h"  // U4LE_ENCODE
#include "fuzz_continuation_host.h"
#include "handle_swap_sign_transaction.h"
#include "handlers.h"
#include "menu.h"
#include "message_model.h"
#include "mocks.h"
#include "policy.h"
#include "psbt_model.h"
#include "mock_dispatcher.h"
#include "swap_entrypoints.h"
#include "swap_globals.h"
#include "swap_utils.h"
#include "wallet_model.h"
#include "write.h"

extern uint16_t G_output_len;

extern uint8_t fuzz_mock_ui_reject;
extern uint8_t*
    ___src_swap_handle_swap_sign_transaction_c_G_swap_sign_return_value_address;

/* Synthetic INS sentinels for swap-library entry points that do not go
 * through apdu_dispatcher().  Chosen to not collide with any real Bitcoin
 * INS (0x00/0x02/0x03/0x04/0x05/0x10). */
#define FUZZ_INS_SWAP_CHECK 0xF1
#define FUZZ_INS_SWAP_HELPERS 0xF2

/* Fault knobs read from the last 4 bytes of the fuzz tail each iteration. */
uint8_t btc_fault_kind = BTC_FAULT_CLEAN;
uint8_t btc_fault_target = 0;
uint8_t btc_fault_param[2] = {0, 0};

/* Raw-lane command map. The raw lane carries no builder payload, so it is the right
 * place for the specs that exercise the dispatcher's own front door: apdu_dispatcher()
 * rejects an unknown CLA, an unknown INS, an unexpected INS_CONTINUE and an
 * out-of-range P2 before any handler runs, and every one of those branches was
 * unreachable while both command tables held nothing but valid CLA_APP commands. */
static const fuzz_command_spec_t btc_raw_commands[6] = {
    /* p2_max above CURRENT_PROTOCOL_VERSION so dispatcher.c's SW_WRONG_P1P2 is
     * reachable; fuzz_clamp_p otherwise clamps P2 into the accepted range. */
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION + 1,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_MASTER_FINGERPRINT,
     .p2_max = CURRENT_PROTOCOL_VERSION},
    /* Unknown INS under a valid CLA -> SW_INS_NOT_SUPPORTED. */
    {.cla = CLA_APP, .ins = 0x99, .flags = FUZZ_CMD_HAS_DATA},
    /* Unknown CLA -> SW_CLA_NOT_SUPPORTED. */
    {.cla = 0xE0, .ins = SIGN_PSBT, .flags = FUZZ_CMD_HAS_DATA},
    /* INS_CONTINUE with no interrupted command in flight -> SW_BAD_STATE. */
    {.cla = CLA_FRAMEWORK, .ins = INS_CONTINUE, .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
};
static const size_t btc_raw_n_commands =
    sizeof(btc_raw_commands) / sizeof(btc_raw_commands[0]);

/* The 16 bytes after the framework control bytes are this app's builder entropy
 * (psbt_entropy), so the payload the builders see starts after them. */
#define FUZZ_APP_HEADER_LEN PSBT_ENTROPY_SIZE

/* This app adds slot-0 scenario-control mutation on top of the framework mutator. */
#define FUZZ_APP_CUSTOM_MUTATOR

/* The two lanes drive structurally different entry paths, so each gets its own
 * command table. The command byte is data[1] (see fuzz_defs.h). */
#define FUZZ_PICK_COMMAND_RAW(data, size) \
    (&btc_raw_commands[(data)[1] % btc_raw_n_commands])

/* This app copies its entropy header out of the input before dispatching. */
#define FUZZ_APP_CUSTOM_ENTRY

#include "fuzz_harness.h"

/* Structured-lane command map (16 slots): slot count == weight. */
const fuzz_command_spec_t fuzz_commands[16] = {
    /* SIGN_PSBT x 7 (43.75%) */
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    /* GET_EXTENDED_PUBKEY x 1 (6.25%) — also picked in the raw lane; a
     * structured slot drives the display/derivation path more often. */
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    /* REGISTER_WALLET x 2 (12.5%) */
    {.cla = CLA_APP,
     .ins = REGISTER_WALLET,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = REGISTER_WALLET,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    /* GET_WALLET_ADDRESS x 2 (12.5%) */
    {.cla = CLA_APP,
     .ins = GET_WALLET_ADDRESS,
     .p1_max = 1,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_WALLET_ADDRESS,
     .p1_max = 1,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    /* SIGN_MESSAGE x 2 (12.5%) */
    {.cla = CLA_APP,
     .ins = SIGN_MESSAGE,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = SIGN_MESSAGE,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    /* FUZZ_INS_SWAP_CHECK   x 1 (6.25%) */
    {.cla = CLA_APP, .ins = FUZZ_INS_SWAP_CHECK, .flags = FUZZ_CMD_HAS_DATA},
    /* FUZZ_INS_SWAP_HELPERS x 1 (6.25%) */
    {.cla = CLA_APP, .ins = FUZZ_INS_SWAP_HELPERS, .flags = FUZZ_CMD_HAS_DATA},
};
FUZZ_COMMAND_COUNT();

static const command_descriptor_t FUZZ_COMMAND_DESCRIPTORS[] = {
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .handler = (command_handler_t)handler_get_extended_pubkey},
    {.cla = CLA_APP,
     .ins = GET_WALLET_ADDRESS,
     .handler = (command_handler_t)handler_get_wallet_address},
    {.cla = CLA_APP,
     .ins = REGISTER_WALLET,
     .handler = (command_handler_t)handler_register_wallet},
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
     .handler = (command_handler_t)handler_sign_psbt},
    {.cla = CLA_APP,
     .ins = GET_MASTER_FINGERPRINT,
     .handler = (command_handler_t)handler_get_master_fingerprint},
    {.cla = CLA_APP,
     .ins = SIGN_MESSAGE,
     .handler = (command_handler_t)handler_sign_message},
};

bool get_address_from_compressed_public_key(
    unsigned char format, unsigned char* compressed_pub_key,
    unsigned short payToAddressVersion, unsigned short payToScriptHashVersion,
    const char* native_segwit_prefix, char* address,
    unsigned char max_address_length);

static size_t build_serialized_swap_path(uint32_t purpose, uint32_t change,
                                         uint32_t index, uint8_t* out,
                                         size_t out_len,
                                         uint32_t words[static 5]) {
    if (out_len < 1 + 5 * sizeof(uint32_t)) return 0;

    words[0] = 0x80000000UL | purpose;
    words[1] = 0x80000000UL | 1UL;
    words[2] = 0x80000000UL;
    words[3] = change;
    words[4] = index;

    out[0] = 5;
    for (size_t i = 0; i < 5; i++)
        write_u32_be(out + 1 + (i * sizeof(uint32_t)), 0, words[i]);
    return 1 + 5 * sizeof(uint32_t);
}

static int run_swap_check_address(const uint8_t* data, size_t size) {
    uint8_t address_parameters[1 + 1 + 5 * sizeof(uint32_t)];
    uint32_t path_words[5];
    unsigned char compressed_public_key[33];
    check_address_parameters_t params;
    char address[MAX_ADDRESS_LENGTH_STR + 1];
    unsigned char format;
    uint32_t purpose, change, index;
    size_t path_len;

    switch ((psbt_entropy[8] + (size > 0 ? data[0] : 0)) % 4) {
        case 0:
            format = 0x00;
            purpose = 44;
            break;
        case 1:
            format = 0x01;
            purpose = 49;
            break;
        case 2:
            format = 0x02;
            purpose = 84;
            break;
        default:
            format = 0x04;
            purpose = 86;
            break;
    }

    change = psbt_entropy[11] & 1U;
    index = psbt_entropy[12] % 32U;
    path_len = build_serialized_swap_path(
        purpose, change, index, address_parameters + 1,
        sizeof(address_parameters) - 1, path_words);
    if (path_len == 0) return 0;

    if (CX_OK != crypto_get_compressed_pubkey_at_path(
                     path_words, sizeof(path_words) / sizeof(path_words[0]),
                     compressed_public_key, NULL))
        return 0;

    if (!get_address_from_compressed_public_key(
            format, compressed_public_key, COIN_P2PKH_VERSION,
            COIN_P2SH_VERSION, COIN_NATIVE_SEGWIT_PREFIX, address,
            sizeof(address)))
        return 0;

    memset(&params, 0, sizeof(params));
    address_parameters[0] = format;
    params.address_parameters = address_parameters;
    params.address_parameters_length = (uint8_t)(1 + path_len);

    uint8_t check_variant = size > 1 ? data[1] : 0;
    if (check_variant % 8 == 0) {
        params.address_to_check = NULL;
    } else if (check_variant % 8 == 1 && address[0] != '\0') {
        address[0] ^= 0x42;
        params.address_to_check = address;
    } else {
        params.address_to_check = address;
    }

    (void)swap_handle_check_address(&params);
    return 0;
}

static int run_swap_helpers(const uint8_t* data, size_t size) {
    uint8_t amount[8] = {0};
    uint8_t fees[8] = {0};
    uint8_t extra_id[33] = {0};
    get_printable_amount_parameters_t printable;
    create_transaction_parameters_t tx_params;
    char destination_address[] = "tb1qfuzzqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    memset(&printable, 0, sizeof(printable));
    memset(&tx_params, 0, sizeof(tx_params));

    amount[7] = size > 0 ? data[0] : 0x2A;
    amount[6] = psbt_entropy[13];
    fees[7] = size > 1 ? data[1] : 0x05;

    size_t amount_len = 1 + (psbt_entropy[14] % sizeof(amount));
    size_t fee_len = 1 + (psbt_entropy[15] % sizeof(fees));

    printable.amount = amount + (sizeof(amount) - amount_len);
    printable.amount_length = (uint8_t)amount_len;
    printable.is_fee = (psbt_entropy[10] & 1) != 0;
    (void)swap_handle_get_printable_amount(&printable);

    {
        uint8_t raw_id = size > 2 ? data[2] : psbt_entropy[9];
        if (raw_id % 4 == 0) {
            extra_id[0] = 2; /* SWAP_MODE_CROSSCHAIN */
        } else if (raw_id % 4 == 3) {
            extra_id[0] = 1; /* triggers SWAP_MODE_ERROR */
        } else {
            extra_id[0] = 0; /* SWAP_MODE_STANDARD */
        }
    }
    tx_params.amount = amount + (sizeof(amount) - amount_len);
    tx_params.amount_length = (uint8_t)amount_len;
    tx_params.fee_amount = fees + (sizeof(fees) - fee_len);
    tx_params.fee_amount_length = (uint8_t)fee_len;
    tx_params.destination_address = destination_address;
    tx_params.destination_address_extra_id = (char*)extra_id;
    (void)swap_copy_transaction_parameters(&tx_params);
    return 0;
}

/* ── Field-aware mutator for structured PSBT tail slots ─────────── */

/* Slot 0 is reserved scenario-control space in all three builders; everything from
 * slot 1 on is tape content. So an app-specific operator is only worth having when it
 * targets a slot-0 field that a builder actually reads. These are all of them:
 *
 *   32..39  GET_WALLET_ADDRESS  (wallet_model.c: WM_ADDR_*)
 *   52..63  SIGN_PSBT           (psbt_model.c:   PM_SLOT0_*)
 *
 * Offsets 0..31 and 40..51 have no reader, so an operator writing a constant there
 * splices it into the middle of a count|klen|key|vlen|value stream at a position no
 * decoder visits as a boundary. libFuzzer's own InsertByte/EraseBytes/CopyPart do
 * that better, because they re-frame every entry downstream. */
enum {
    BTC_S0_ADDR_DISPLAY_OFF = 32,
    BTC_S0_ADDR_IS_CHANGE_OFF = 33,
    BTC_S0_ADDR_INDEX_OFF = 34,
    BTC_S0_ADDR_USE_REGISTERED_OFF = 38,
    BTC_S0_ADDR_FLIP_HMAC_OFF = 39,
    BTC_S0_TX_VERSION_OFF = 52,
    BTC_S0_LOCKTIME_OFF = 56,
    BTC_S0_N_INPUTS_OFF = 60,
    BTC_S0_N_OUTPUTS_OFF = 61,
    BTC_S0_SUBTYPE_OFF = 62,
    BTC_S0_DESC_SEED_OFF = 63,
};

enum {
    BTC_GET_XPUB_DISPLAY_OFF = 0,
    BTC_GET_XPUB_PATH_SEED_OFF = 1,
    BTC_GET_XPUB_FALLBACK_CTRL_OFF = 8,
    BTC_GET_XPUB_FALLBACK_DISPLAY_OFF = 11,
};



/* The hardened boundary at 0x80000000 is the one that matters:
 * is_path_safe_for_pubkey_export() rejects a hardened address index. */
static const uint32_t SPECIAL_ADDRESS_INDICES[] = {
    0, 1, 0x7FFFFFFFUL, 0x80000000UL, 0xFFFFFFFFUL,
};

static const uint32_t SPECIAL_TX_VERSIONS[] = {
    0, 1, 2, 3, 0xFFFFFFFFUL,
};

static const uint32_t SPECIAL_LOCKTIMES[] = {
    0, 1, 500000000UL, 840000UL, 0xFFFFFFFFUL,
};


/* Builder slots start at fuzz_tail_ptr[0] — that is, after the framework
 * control bytes and this app's entropy header. The mutator works in
 * whole-input coordinates, so it has to skip both to land on slot 0 where the
 * seed generator and the builders expect it. */
#define BTC_TAIL_OFF ((size_t) FUZZ_CTRL_LEN + FUZZ_APP_HEADER_LEN)

static size_t btc_structured_slot_count(size_t size, size_t prefix_size) {
    size_t base = prefix_size + BTC_TAIL_OFF;
    if (size <= base + FUZZ_TAIL_SLOT_SIZE) {
        return 0;
    }

    size_t n_full_slots = (size - base) / FUZZ_TAIL_SLOT_SIZE;
    if (n_full_slots > FUZZ_TAIL_N_SLOTS) {
        n_full_slots = FUZZ_TAIL_N_SLOTS;
    }
    return n_full_slots;
}

static uint8_t *btc_mut_slot(uint8_t *data, size_t prefix_size, size_t slot_idx) {
    return data + prefix_size + BTC_TAIL_OFF + slot_idx * FUZZ_TAIL_SLOT_SIZE;
}

static uint8_t *btc_mut_fault_region(uint8_t *data, size_t size) {
    return data + size - FUZZ_TAIL_FAULT_SIZE;
}




static uint32_t btc_pick_special_address_index(unsigned int seed) {
    return SPECIAL_ADDRESS_INDICES[(seed >> 12) %
        (sizeof(SPECIAL_ADDRESS_INDICES) / sizeof(SPECIAL_ADDRESS_INDICES[0]))];
}

static uint32_t btc_pick_special_tx_version(unsigned int seed) {
    return SPECIAL_TX_VERSIONS[(seed >> 12) %
        (sizeof(SPECIAL_TX_VERSIONS) / sizeof(SPECIAL_TX_VERSIONS[0]))];
}

static uint32_t btc_pick_special_locktime(unsigned int seed) {
    return SPECIAL_LOCKTIMES[(seed >> 16) %
        (sizeof(SPECIAL_LOCKTIMES) / sizeof(SPECIAL_LOCKTIMES[0]))];
}

static void btc_swap_slots(uint8_t *lhs, uint8_t *rhs) {
    uint8_t tmp[FUZZ_TAIL_SLOT_SIZE];

    memcpy(tmp, lhs, FUZZ_TAIL_SLOT_SIZE);
    memcpy(lhs, rhs, FUZZ_TAIL_SLOT_SIZE);
    memcpy(rhs, tmp, FUZZ_TAIL_SLOT_SIZE);
}

static void btc_field_aware_tweak(uint8_t *data, size_t size,
                                  size_t prefix_size, unsigned int seed) {
    size_t n_full_slots = btc_structured_slot_count(size, prefix_size);
    if (n_full_slots == 0) return;

    size_t slot_idx = seed % n_full_slots;
    uint8_t *slot = btc_mut_slot(data, prefix_size, slot_idx);

    uint8_t *slot0 = btc_mut_slot(data, prefix_size, 0);

    /* Weighted, not uniform. The three slot-0 field operators are the only ones
     * libFuzzer cannot supply itself -- it has no way to know that tail byte 62 picks
     * a sign mode -- so they get three quarters of the budget. The two coarse
     * whole-slot operators get a sixteenth each: at slot 1 and beyond a slot is tape
     * content, and zeroing or transposing 64 bytes of it destroys more structure than
     * it explores. */
    unsigned int op;
    switch ((seed >> 8) & 0x0F) {
        case 0: case 1: case 2: case 3:   op = 0; break;   /* scenario shape   */
        case 4: case 5: case 6: case 7:   op = 1; break;   /* version/locktime */
        case 8: case 9: case 10: case 11: op = 2; break;   /* address fields   */
        case 12: case 13:                 op = 5; break;   /* fault knobs      */
        case 14:                          op = 3; break;   /* transpose a slot */
        default:                          op = 4; break;   /* zero a slot      */
    }
    switch (op) {
        case 0:
            /* SIGN_PSBT scenario shape. */
            slot0[BTC_S0_N_INPUTS_OFF] = (uint8_t)((seed >> 12) & 0x07);
            slot0[BTC_S0_N_OUTPUTS_OFF] = (uint8_t)((seed >> 15) & 0x07);
            slot0[BTC_S0_SUBTYPE_OFF] = (uint8_t)((seed >> 18) & 0x0F);
            slot0[BTC_S0_DESC_SEED_OFF] = (uint8_t)((seed >> 22) & 0x0F);
            break;
        case 1:
            /* The two transaction-level fields with interesting boundaries: a
             * locktime either side of the 500000000 height/time split, and a version
             * the app may or may not accept. */
            U4LE_ENCODE(slot0 + BTC_S0_TX_VERSION_OFF, 0,
                             btc_pick_special_tx_version(seed));
            U4LE_ENCODE(slot0 + BTC_S0_LOCKTIME_OFF, 0,
                             btc_pick_special_locktime(seed));
            break;
        case 2:
            /* GET_WALLET_ADDRESS fields. The address index is the one place a
             * boundary value matters: it crosses into the hardened range at
             * 0x80000000, which is_path_safe_for_pubkey_export() rejects. */
            U4LE_ENCODE(slot0 + BTC_S0_ADDR_INDEX_OFF, 0,
                             btc_pick_special_address_index(seed));
            slot0[BTC_S0_ADDR_DISPLAY_OFF] ^= (uint8_t)((seed >> 12) & 0x01);
            slot0[BTC_S0_ADDR_IS_CHANGE_OFF] ^= (uint8_t)((seed >> 13) & 0x01);
            slot0[BTC_S0_ADDR_USE_REGISTERED_OFF] ^= (uint8_t)((seed >> 14) & 0x01);
            slot0[BTC_S0_ADDR_FLIP_HMAC_OFF] ^= (uint8_t)((seed >> 15) & 0x01);
            break;
        case 3: {
            /* Structure-agnostic block permutation: moving a 64-byte run re-frames
             * whatever the tape decodes after it, which is exactly the kind of edit
             * a length-prefixed stream responds to. */
            size_t other = (seed >> 12) % n_full_slots;
            if (other == slot_idx && n_full_slots > 1)
                other = (other + 1) % n_full_slots;
            btc_swap_slots(slot, btc_mut_slot(data, prefix_size, other));
            break;
        }
        case 4:
            memset(slot, 0, FUZZ_TAIL_SLOT_SIZE);
            break;
        case 5:
            /* Continuation faults. Only kinds 6 and 7 do anything (mocks.h), so pick
             * between those two and write all four bytes, so the per-kind parameters
             * vary too. */
            if (size >= prefix_size + BTC_TAIL_OFF + FUZZ_TAIL_FAULT_SIZE) {
                uint8_t *fault = btc_mut_fault_region(data, size);
                fault[0] = (uint8_t)(BTC_FAULT_CONT_TRUNCATE + ((seed >> 12) & 0x01));
                fault[1] = (uint8_t)((seed >> 16) & 0xFF);
                fault[2] = (uint8_t)((seed >> 20) & 0xFF);
                fault[3] = (uint8_t)((seed >> 24) & 0xFF);
            }
            break;
    }
}

/* App-specific mutation on top of the framework mutator. Structured inputs get a
 * slot-0 scenario-control tweak 30% of the time; everything else is left to
 * fuzz_custom_mutator, whose generic byte operators are the right family for a
 * length-prefixed tape because they re-frame every entry downstream. The framework
 * resolves the prefix size, so nothing here needs a prefix layout offset. */
size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size,
                               unsigned int seed) {
    size_t new_size = fuzz_custom_mutator(data, size, max_size, seed);
    size_t prefix_size = fuzz_prefix_size();

    if (new_size <= prefix_size + BTC_TAIL_OFF) return new_size;

    if (data[prefix_size] > FUZZ_STRUCTURED_LANE_THRESHOLD) {
        if (((seed >> 16) % 100) < 30) {
            btc_field_aware_tweak(data, new_size, prefix_size, seed);
        }
    }
    return new_size;
}

/* BIP-45 and BIP-48 are listed so is_path_safe_for_pubkey_export() sees all
 * case labels for the purpose switch.  BIP-48 needs a fourth hardened
 * script_type component in {1,2}, which the generic fuzz_bip32_build() does
 * not emit; patch_bip48_path() fixes that up after building. */
static const uint32_t BTC_PURPOSES[] = {44, 45, 48, 49, 84, 86};
static const fuzz_bip32_config_t btc_bip32_cfg = {
    .purposes = BTC_PURPOSES,
    .n_purposes = sizeof(BTC_PURPOSES) / sizeof(BTC_PURPOSES[0]),
    .coin_type = 0x80000000UL,
    .max_account = 3,
    .max_depth = 5,
};

/* For BIP-48, extend the path to 4 components and force the fourth hardened
 * component to script_type 1' or 2'; otherwise is_path_safe_for_pubkey_export()
 * rejects the path before reaching the BIP-48 script_type check. */
/* Takes both the written length (to read the purpose safely) and the buffer capacity
 * (to know whether a 4th component can be appended). Do not write buf[0] before the
 * capacity check: an APDU declaring depth 4 with a stale 4th component is not
 * reproducible from its own input file. */
static void patch_bip48_path(uint8_t* buf, size_t path_bytes, size_t cap,
                             const uint8_t* ctrl, size_t ctrl_len) {
    /* Need the depth byte plus a full first component before reading the purpose. */
    if (path_bytes < 5) return;
    uint8_t depth = buf[0];
    if (depth < 1) return;
    uint32_t purpose_raw = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
                           ((uint32_t)buf[3] << 8) | (uint32_t)buf[4];
    if ((purpose_raw & 0x7FFFFFFF) != 48) return;

    /* The 4th component occupies buf[13..16]. */
    if (cap < 17) return;
    if (depth < 4) {
        buf[0] = 4;
    }
    uint8_t script_type = (ctrl_len > 3 && (ctrl[3] & 1)) ? 2 : 1;
    uint32_t script_comp = 0x80000000UL | script_type;
    uint8_t* p = buf + 1 + 3 * 4;
    p[0] = (uint8_t)(script_comp >> 24);
    p[1] = (uint8_t)(script_comp >> 16);
    p[2] = (uint8_t)(script_comp >> 8);
    p[3] = (uint8_t)(script_comp);
}

static int btc_handle_ccmd(void* ctx, const uint8_t* request,
                           size_t request_len, uint8_t* response,
                           size_t* response_len) {
    mock_dispatcher_t* h = (mock_dispatcher_t*)ctx;

    int is_target_round =
        fuzz_continuation_idx == (int)(btc_fault_target & 0x0F);

    /* The old wrapper also had a "return a well-formed but wrong reply" mode, but
     * every call passed a disruption value that disabled it, so it never fired.
     * mock_dispatcher's tamper hook is the place for that if it is ever wanted. */
    size_t response_cap = *response_len; /* contract: in = capacity, out = length */
    *response_len = 0;
    int rc = mock_dispatcher_handle_ccmd(h, request, request_len, response,
                                         response_cap, response_len);
    if (rc < 0) return rc;

    if (is_target_round && *response_len > 0) {
        switch (btc_fault_kind) {
            case BTC_FAULT_CONT_TRUNCATE:
                if (*response_len > 2) {
                    *response_len =
                        1 + (btc_fault_param[0] % (*response_len - 1));
                }
                break;
            case BTC_FAULT_CONT_FLIP: {
                size_t n_flips = 1 + (btc_fault_param[0] % 4);
                for (size_t fi = 0; fi < n_flips; fi++) {
                    size_t pos =
                        (btc_fault_param[1] + fi * 7) % *response_len;
                    response[pos] ^= btc_fault_param[0];
                }
                break;
            }
            default:
                break;
        }
    }

    return 0;
}

static fuzz_continuation_host_t btc_continuation_host = {
    .handle_ccmd = btc_handle_ccmd,
    .ctx = NULL,
    .active = false,
};

/* The client-command host. Zero-initialised in BSS, then reset per input;
 * mock_dispatcher_init() is not needed because the fuzz path drives the real
 * dispatcher and never uses mock->dc. */
static mock_dispatcher_t g_btc_host;

static void btc_activate_host(void) {
    btc_continuation_host.ctx = &g_btc_host;
    btc_continuation_host.active = true;
    fuzz_continuation_host = &btc_continuation_host;
}

static void btc_deactivate_host(void) {
    btc_continuation_host.active = false;
    fuzz_continuation_host = &btc_continuation_host;
}

static size_t build_sign_psbt_payload(uint8_t* out, size_t cap);
static size_t build_get_wallet_address_payload(uint8_t* out, size_t cap);
static size_t build_register_wallet_payload(uint8_t* out, size_t cap);
static size_t build_sign_message_payload(uint8_t* out, size_t cap);
static size_t build_get_extended_pubkey_payload(uint8_t* out, size_t cap);

typedef size_t (*btc_payload_builder_t)(uint8_t* out, size_t cap);

typedef struct {
    uint8_t ins;
    btc_payload_builder_t build_payload;
} btc_payload_route_t;

static const btc_payload_route_t BTC_PAYLOAD_ROUTES[] = {
    {.ins = SIGN_PSBT, .build_payload = build_sign_psbt_payload},
    {.ins = GET_WALLET_ADDRESS, .build_payload = build_get_wallet_address_payload},
    {.ins = REGISTER_WALLET, .build_payload = build_register_wallet_payload},
    {.ins = SIGN_MESSAGE, .build_payload = build_sign_message_payload},
    {.ins = GET_EXTENDED_PUBKEY, .build_payload = build_get_extended_pubkey_payload},
};

static uint8_t g_swap_return_dummy;

static void btc_read_fault_knobs(void) {
    btc_fault_kind = BTC_FAULT_CLEAN;
    btc_fault_target = 0;
    btc_fault_param[0] = 0;
    btc_fault_param[1] = 0;

    if (!fuzz_use_structured_lane() || fuzz_tail_ptr == NULL ||
        fuzz_tail_len < FUZZ_TAIL_FAULT_SIZE) {
        return;
    }

    const uint8_t *f = fuzz_tail_ptr + fuzz_tail_len - FUZZ_TAIL_FAULT_SIZE;
    btc_fault_kind = f[0] & 0x07;
    btc_fault_target = f[1];
    btc_fault_param[0] = f[2];
    btc_fault_param[1] = f[3];
}

static btc_payload_builder_t btc_find_payload_builder(uint8_t ins) {
    size_t n_routes = sizeof(BTC_PAYLOAD_ROUTES) / sizeof(BTC_PAYLOAD_ROUTES[0]);

    for (size_t i = 0; i < n_routes; i++) {
        if (BTC_PAYLOAD_ROUTES[i].ins == ins) {
            return BTC_PAYLOAD_ROUTES[i].build_payload;
        }
    }
    return NULL;
}

static size_t build_structured_payload(uint8_t ins, uint8_t* out, size_t cap) {
    btc_payload_builder_t build_payload = btc_find_payload_builder(ins);

    /* GET_MASTER_FINGERPRINT accepts an empty APDU; no builder. */
    if (build_payload == NULL) {
        return 0;
    }
    return build_payload(out, cap);
}

/* Structured-lane payload builders: return bytes written to `out` (0 to
 * short-circuit). Builders needing continuation traffic activate the host. */

static size_t commit_apdu(uint8_t* out, size_t cap, const uint8_t* apdu,
                          size_t apdu_len) {
    if (apdu_len == 0) return 0;
    size_t n = apdu_len > cap ? cap : apdu_len;
    memcpy(out, apdu, n);
    btc_activate_host();
    return n;
}

static const uint8_t *tail_slot_data(size_t *out_len) {
    if (fuzz_tail_ptr && fuzz_tail_len > 0) {
        *out_len = fuzz_tail_len;
        return fuzz_tail_ptr;
    }
    *out_len = 0;
    return NULL;
}

static size_t build_sign_psbt_payload(uint8_t* out, size_t cap) {
    static psbt_scenario_t sc;
    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    if (pm_build_scenario(&sc, &g_btc_host, psbt_entropy,
                          PSBT_ENTROPY_SIZE, sd, sd_len) != 0) {
        return 0;
    }
    return commit_apdu(out, cap, sc.apdu, sc.apdu_len);
}

static size_t build_wallet_scenario(wallet_scenario_t* sc) {
    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    if (wm_build_scenario(sc, &g_btc_host, psbt_entropy, PSBT_ENTROPY_SIZE,
                          sd, sd_len) != 0) {
        return 0;
    }
    return sc->apdu_len;
}

static size_t build_register_wallet_payload(uint8_t* out, size_t cap) {
    static wallet_scenario_t sc;
    if (build_wallet_scenario(&sc) == 0) return 0;
    return commit_apdu(out, cap, sc.apdu, sc.apdu_len);
}

static size_t build_get_wallet_address_payload(uint8_t* out, size_t cap) {
    static wallet_scenario_t sc;
    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    if (build_wallet_scenario(&sc) == 0) return 0;
    if (wm_build_get_address_apdu(&sc, sd, sd_len) != 0) {
        return 0;
    }
    return commit_apdu(out, cap, sc.apdu, sc.apdu_len);
}

static size_t build_sign_message_payload(uint8_t* out, size_t cap) {
    static msg_scenario_t sc;
    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    if (mm_build_scenario(&sc, &g_btc_host, psbt_entropy,
                          PSBT_ENTROPY_SIZE, sd, sd_len) != 0) {
        return 0;
    }
    return commit_apdu(out, cap, sc.apdu, sc.apdu_len);
}

static const uint8_t *btc_get_pubkey_path_seed(const uint8_t *slot_data,
                                               size_t slot_data_len,
                                               size_t *seed_len) {
    if (slot_data_len > BTC_GET_XPUB_PATH_SEED_OFF) {
        *seed_len = slot_data_len - BTC_GET_XPUB_PATH_SEED_OFF;
        return slot_data + BTC_GET_XPUB_PATH_SEED_OFF;
    }

    *seed_len = (PSBT_ENTROPY_SIZE > BTC_GET_XPUB_FALLBACK_CTRL_OFF) ?
        (PSBT_ENTROPY_SIZE - BTC_GET_XPUB_FALLBACK_CTRL_OFF) : 0;
    return psbt_entropy + BTC_GET_XPUB_FALLBACK_CTRL_OFF;
}

static uint8_t btc_get_pubkey_display_flag(const uint8_t *slot_data,
                                           size_t slot_data_len) {
    if (slot_data_len > BTC_GET_XPUB_DISPLAY_OFF) {
        return slot_data[BTC_GET_XPUB_DISPLAY_OFF] & 1U;
    }
    return psbt_entropy[BTC_GET_XPUB_FALLBACK_DISPLAY_OFF] & 1U;
}

static size_t build_get_extended_pubkey_payload(uint8_t* out, size_t cap) {
    if (cap < 2) return 0;

    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    size_t path_seed_len;
    const uint8_t* path_seed = btc_get_pubkey_path_seed(sd, sd_len, &path_seed_len);

    out[0] = btc_get_pubkey_display_flag(sd, sd_len);

    size_t path_bytes = fuzz_bip32_build(
        &btc_bip32_cfg, path_seed, path_seed_len, out + 1, cap - 1);
    if (path_bytes == 0) return 0;

    patch_bip48_path(out + 1, path_bytes, cap - 1, path_seed, path_seed_len);

    /* Recompute path_bytes in case patch_bip48_path promoted depth. */
    path_bytes = 1 + (size_t)out[1] * 4;
    return 1 + path_bytes;
}

void fuzz_app_reset(void) {
    fuzz_continuation_idx = 0;
    btc_deactivate_host();
    G_output_len = 0;

    /* G_swap_state is Absolution-driven in the prefix; the return-value pointer
     * cannot be, so always point it at a static dummy. This keeps the real
     * store in finalize_exchange_sign_transaction() reachable and removes the
     * need for a production NULL guard. */
    g_swap_return_dummy = 0;
    ___src_swap_handle_swap_sign_transaction_c_G_swap_sign_return_value_address =
        &g_swap_return_dummy;
}

void fuzz_app_dispatch(void* cmd_v) {
    command_t* cmd = (command_t*)cmd_v;

    if (cmd->ins == FUZZ_INS_SWAP_CHECK) {
        (void)run_swap_check_address(cmd->data, cmd->lc);
        return;
    }
    if (cmd->ins == FUZZ_INS_SWAP_HELPERS) {
        (void)run_swap_helpers(cmd->data, cmd->lc);
        return;
    }

    btc_read_fault_knobs();

    /* Only SIGN_PSBT can be swap-capable; strip the stale swap flag from the
     * prefix for every other route so it does not leak into handlers that have
     * no business seeing it. The return-value pointer stays wired to the dummy
     * (fuzz_app_reset) so any finalize path has a valid store target. */
    if (cmd->ins != SIGN_PSBT) {
        G_called_from_swap = 0;
    }

    static uint8_t structured_buf[512];
    if (fuzz_use_structured_lane()) {
        size_t payload_len = build_structured_payload(cmd->ins, structured_buf,
                                                      sizeof(structured_buf));
        if (payload_len == 0) {
            /* The builder could not produce a payload. Skip the iteration rather
             * than dispatch with cmd->data still pointing at the raw tail: the app
             * would parse unrelated bytes as a structured payload, die on a random
             * Merkle root, and count as coverage. A skipped iteration is visible as
             * lower throughput; a fallthrough is invisible. */
            return;
        }
        cmd->lc = (uint8_t)(payload_len > 255 ? 255 : payload_len);
        cmd->data = structured_buf;
    }

    apdu_dispatcher(
        FUZZ_COMMAND_DESCRIPTORS,
        sizeof(FUZZ_COMMAND_DESCRIPTORS) / sizeof(FUZZ_COMMAND_DESCRIPTORS[0]),
        ui_menu_main, cmd);
}

int fuzz_entry(const uint8_t* data, size_t size) {
    /* Builder entropy is this app's own header, right after the framework
     * control bytes. */
    if (size >= (size_t) FUZZ_CTRL_LEN + PSBT_ENTROPY_SIZE) {
        memcpy(psbt_entropy, data + FUZZ_CTRL_LEN, PSBT_ENTROPY_SIZE);
    }
    return fuzz_harness_entry(data, size);
}
