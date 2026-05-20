#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "dispatcher.h"
#include "fuzz_bip32.h"
#include "fuzz_continuation_host.h"
#include "handle_swap_sign_transaction.h"
#include "handlers.h"
#include "menu.h"
#include "message_model.h"
#include "mocks.h"
#include "policy.h"
#include "psbt_model.h"
#include "semantic_host.h"
#include "swap_entrypoints.h"
#include "swap_globals.h"
#include "swap_utils.h"
#include "wallet_model.h"
#include "write.h"

unsigned int app_stack_canary;

extern uint16_t G_output_len;

extern bool fuzz_ui_approve;
extern uint8_t*
    ___src_swap_handle_swap_sign_transaction_c_G_swap_sign_return_value_address;

/* Synthetic INS sentinels for swap-library entry points that do not go
 * through apdu_dispatcher().  Chosen to not collide with any real Bitcoin
 * INS (0x00/0x02/0x03/0x04/0x05/0x10). */
#define FUZZ_INS_SWAP_CHECK 0xF1
#define FUZZ_INS_SWAP_HELPERS 0xF2

enum {
    BTC_LANE_RAW = 0,
    BTC_LANE_STRUCTURED = 1,
};

/* Active lane, set by FUZZ_PICK_COMMAND_* on every iteration. */
static uint8_t btc_current_lane = BTC_LANE_RAW;

/* Fault knobs read from the last 4 bytes of the fuzz tail each iteration. */
uint8_t btc_fault_kind = BTC_FAULT_CLEAN;
uint8_t btc_fault_target = 0;
uint8_t btc_fault_param[2] = {0, 0};

/* Raw-lane command map (4 slots): GET_EXTENDED_PUBKEY @ 75%,
 * GET_MASTER_FINGERPRINT @ 25%. */
static const fuzz_command_spec_t btc_raw_commands[4] = {
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_EXTENDED_PUBKEY,
     .p2_max = CURRENT_PROTOCOL_VERSION,
     .flags = FUZZ_CMD_HAS_DATA},
    {.cla = CLA_APP,
     .ins = GET_MASTER_FINGERPRINT,
     .p2_max = CURRENT_PROTOCOL_VERSION},
};
static const size_t btc_raw_n_commands =
    sizeof(btc_raw_commands) / sizeof(btc_raw_commands[0]);

/* SDK contract: fuzz_harness.h consumes these macros at include time. They
 * also stamp the active lane for the rest of the iteration. */
#define FUZZ_PICK_COMMAND_RAW(data, size) \
    ((btc_current_lane = BTC_LANE_RAW),   \
     &btc_raw_commands[(data)[1] % btc_raw_n_commands])

#define FUZZ_PICK_COMMAND_STRUCTURED(data, size) \
    ((btc_current_lane = BTC_LANE_STRUCTURED),   \
     &fuzz_commands[fuzz_ctrl[1] % fuzz_n_commands])

#include "fuzz_harness.h"

/* Structured-lane command map (16 slots): slot count == weight. */
const fuzz_command_spec_t fuzz_commands[16] = {
    /* SIGN_PSBT x 8 (50%) */
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
    {.cla = CLA_APP,
     .ins = SIGN_PSBT,
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
const size_t fuzz_n_commands = sizeof(fuzz_commands) / sizeof(fuzz_commands[0]);

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

#include "scenario_layout.h"

static void inject_token(uint8_t* region, size_t region_len,
                         unsigned int seed) {
    static const char* const tokens[] = {
        "wpkh(@0/**)", "tr(@0/**)", "sh(wpkh(@0/**))", "musig(", "wsh(multi(",
    };
    const char* token = tokens[seed % (sizeof(tokens) / sizeof(tokens[0]))];
    size_t token_len = strlen(token);
    size_t offset = region_len == 0 ? 0 : (seed % region_len);
    if (offset + token_len > region_len) token_len = region_len - offset;
    if (token_len > 0) memcpy(region + offset, token, token_len);
}

#define FUZZ_PREFIX_SIZE_FALLBACK SCEN_PREFIX_SIZE
#define FUZZ_CTRL_OFF SCEN_ENTROPY_OFF
#define FUZZ_CTRL_LEN SCEN_ENTROPY_LEN
#define fuzz_lane_is_structured(data, ps) \
    ((ps) > FUZZ_CTRL_OFF &&              \
     (data)[FUZZ_CTRL_OFF] > FUZZ_STRUCTURED_LANE_THRESHOLD)
#define FUZZ_INJECT_TOKEN(region, len, seed) \
    inject_token((region), (len), (seed))

#include "fuzz_layout_check.h"
#include "fuzz_mutator.h"

/* ── Field-aware mutator for structured PSBT tail slots ─────────── */

enum {
    BTC_PSBT_IN_OUTPUT_INDEX_OFF = 32,
    BTC_PSBT_IN_AMOUNT_OFF = 33,
    BTC_PSBT_IN_AMOUNT_TWEAK_OFF = BTC_PSBT_IN_AMOUNT_OFF + 5,
    BTC_PSBT_IN_SEQUENCE_OFF = 41,
    BTC_PSBT_IN_SIGHASH_OFF = 45,
    BTC_PSBT_SLOT0_TX_VERSION_OFF = 52,
    BTC_PSBT_SLOT0_LOCKTIME_OFF = 56,
    BTC_PSBT_SLOT0_N_INPUTS_OFF = 60,
    BTC_PSBT_SLOT0_N_OUTPUTS_OFF = 61,
    BTC_PSBT_SLOT0_SUBTYPE_OFF = 62,
    BTC_PSBT_SLOT0_DESC_SEED_OFF = 63,
};

enum {
    BTC_GET_XPUB_DISPLAY_OFF = 0,
    BTC_GET_XPUB_PATH_SEED_OFF = 1,
    BTC_GET_XPUB_FALLBACK_CTRL_OFF = 8,
    BTC_GET_XPUB_FALLBACK_DISPLAY_OFF = 11,
};

static const uint64_t BOUNDARY_AMOUNTS[] = {
    0, 1, 0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL,
    2100000000000000ULL,  /* 21M BTC in sats */
    546, 294,             /* dust thresholds */
};

static const uint32_t SPECIAL_SEQUENCES[] = {
    0, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFFFDUL, 1,
};

static const uint32_t SPECIAL_TX_VERSIONS[] = {
    0, 1, 2, 3, 0xFFFFFFFFUL,
};

static const uint32_t SPECIAL_LOCKTIMES[] = {
    0, 1, 500000000UL, 840000UL, 0xFFFFFFFFUL,
};

static const uint8_t SPECIAL_SIGHASH[] = {
    0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0xFF,
};

static void mut_write_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void mut_write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static size_t btc_structured_slot_count(size_t size, size_t prefix_size) {
    if (size <= prefix_size + FUZZ_TAIL_SLOT_SIZE) {
        return 0;
    }

    size_t n_full_slots = (size - prefix_size) / FUZZ_TAIL_SLOT_SIZE;
    if (n_full_slots > FUZZ_TAIL_N_SLOTS) {
        n_full_slots = FUZZ_TAIL_N_SLOTS;
    }
    return n_full_slots;
}

static uint8_t *btc_mut_slot(uint8_t *data, size_t prefix_size, size_t slot_idx) {
    return data + prefix_size + slot_idx * FUZZ_TAIL_SLOT_SIZE;
}

static uint8_t *btc_mut_fault_region(uint8_t *data, size_t size) {
    return data + size - FUZZ_TAIL_FAULT_SIZE;
}

static uint64_t btc_pick_boundary_amount(unsigned int seed) {
    return BOUNDARY_AMOUNTS[(seed >> 12) %
        (sizeof(BOUNDARY_AMOUNTS) / sizeof(BOUNDARY_AMOUNTS[0]))];
}

static uint32_t btc_pick_special_sequence(unsigned int seed) {
    return SPECIAL_SEQUENCES[(seed >> 12) %
        (sizeof(SPECIAL_SEQUENCES) / sizeof(SPECIAL_SEQUENCES[0]))];
}

static uint8_t btc_pick_special_sighash(unsigned int seed) {
    return SPECIAL_SIGHASH[(seed >> 12) %
        (sizeof(SPECIAL_SIGHASH) / sizeof(SPECIAL_SIGHASH[0]))];
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

    unsigned int op = (seed >> 8) % 9;
    switch (op) {
        case 0: {
            mut_write_u64_le(slot + BTC_PSBT_IN_AMOUNT_OFF,
                             btc_pick_boundary_amount(seed));
            break;
        }
        case 1: {
            mut_write_u32_le(slot + BTC_PSBT_IN_SEQUENCE_OFF,
                             btc_pick_special_sequence(seed));
            break;
        }
        case 2:
            slot[BTC_PSBT_IN_SIGHASH_OFF] = btc_pick_special_sighash(seed);
            break;
        case 3: {
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
            if (size >= FUZZ_TAIL_FAULT_SIZE) {
                uint8_t *fault = btc_mut_fault_region(data, size);
                fault[0] = (seed >> 12) & 0x07;
                fault[1] = (seed >> 16) & 0x0F;
            }
            break;
        case 6: {
            mut_write_u64_le(slot, btc_pick_boundary_amount(seed));
            break;
        }
        case 7: {
            uint8_t *slot0 = btc_mut_slot(data, prefix_size, 0);
            slot0[BTC_PSBT_SLOT0_N_INPUTS_OFF] = (uint8_t)((seed >> 12) & 0x07);
            slot0[BTC_PSBT_SLOT0_N_OUTPUTS_OFF] = (uint8_t)((seed >> 15) & 0x07);
            slot0[BTC_PSBT_SLOT0_SUBTYPE_OFF] = (uint8_t)((seed >> 18) & 0x0F);
            slot0[BTC_PSBT_SLOT0_DESC_SEED_OFF] = (uint8_t)((seed >> 22) & 0x0F);
            break;
        }
        case 8: {
            uint8_t *slot0 = btc_mut_slot(data, prefix_size, 0);
            mut_write_u32_le(slot0 + BTC_PSBT_SLOT0_TX_VERSION_OFF,
                             btc_pick_special_tx_version(seed));
            mut_write_u32_le(slot0 + BTC_PSBT_SLOT0_LOCKTIME_OFF,
                             btc_pick_special_locktime(seed));
            slot0[BTC_PSBT_IN_OUTPUT_INDEX_OFF] ^= 0x01;
            slot0[BTC_PSBT_IN_AMOUNT_TWEAK_OFF] ^= 0x01;
            break;
        }
    }
}

size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size,
                               unsigned int seed) {
    size_t new_size = fuzz_custom_mutator(data, size, max_size, seed);

    size_t prefix_size = FUZZ_PREFIX_SIZE_FALLBACK;
    if (&absolution_globals_size != NULL && absolution_globals_size != 0)
        prefix_size = absolution_globals_size;

    if (new_size > prefix_size &&
        fuzz_lane_is_structured(data, prefix_size) &&
        ((seed >> 16) % 100) < 30) {
        btc_field_aware_tweak(data, new_size, prefix_size, seed);
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
static void patch_bip48_path(uint8_t* buf, size_t path_bytes,
                             const uint8_t* ctrl, size_t ctrl_len) {
    if (path_bytes < 1) return;
    uint8_t depth = buf[0];
    if (depth < 1) return;
    uint32_t purpose_raw = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
                           ((uint32_t)buf[3] << 8) | (uint32_t)buf[4];
    if ((purpose_raw & 0x7FFFFFFF) != 48) return;
    if (depth < 4) {
        buf[0] = 4;
        if (path_bytes < 17) return;
    }
    uint8_t script_type = (ctrl_len > 3 && (ctrl[3] & 1)) ? 2 : 1;
    uint32_t script_comp = 0x80000000UL | script_type;
    uint8_t* p = buf + 1 + 3 * 4;
    p[0] = (uint8_t)(script_comp >> 24);
    p[1] = (uint8_t)(script_comp >> 16);
    p[2] = (uint8_t)(script_comp >> 8);
    p[3] = (uint8_t)(script_comp);
}

extern uint8_t* get_fuzz_for_round(int round);

static int btc_handle_ccmd(void* ctx, const uint8_t* request,
                           size_t request_len, uint8_t* response,
                           size_t* response_len) {
    semantic_host_t* h = (semantic_host_t*)ctx;

    int is_target_round =
        fuzz_continuation_idx == (int)(btc_fault_target & 0x0F);

    *response_len = 250;
    int rc = sh_handle_ccmd_with_disruption(h, request, request_len, response,
                                            response_len, 255);
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

static void btc_activate_semantic_host(void) {
    btc_continuation_host.ctx = &g_semantic_host;
    btc_continuation_host.active = true;
    fuzz_continuation_host = &btc_continuation_host;
}

static void btc_deactivate_semantic_host(void) {
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

    if (btc_current_lane != BTC_LANE_STRUCTURED || fuzz_tail_ptr == NULL ||
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

/*
 * Structured-lane payload builders.  Each returns the number of bytes
 * written into `out`, or 0 to short-circuit the iteration.  Builders that
 * need continuation traffic activate the semantic host on success.
 */

static size_t commit_apdu(uint8_t* out, size_t cap, const uint8_t* apdu,
                          size_t apdu_len) {
    if (apdu_len == 0) return 0;
    size_t n = apdu_len > cap ? cap : apdu_len;
    memcpy(out, apdu, n);
    btc_activate_semantic_host();
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
    if (pm_build_scenario(&sc, &g_semantic_host, psbt_entropy,
                          PSBT_ENTROPY_SIZE, sd, sd_len) != 0) {
        return 0;
    }
    return commit_apdu(out, cap, sc.apdu, sc.apdu_len);
}

static size_t build_wallet_scenario(wallet_scenario_t* sc) {
    size_t sd_len;
    const uint8_t* sd = tail_slot_data(&sd_len);
    if (wm_build_scenario(sc, &g_semantic_host, psbt_entropy, PSBT_ENTROPY_SIZE,
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
    if (mm_build_scenario(&sc, &g_semantic_host, psbt_entropy,
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

    patch_bip48_path(out + 1, path_bytes, path_seed, path_seed_len);

    /* Recompute path_bytes in case patch_bip48_path promoted depth. */
    path_bytes = 1 + (size_t)out[1] * 4;
    return 1 + path_bytes;
}

void fuzz_app_reset(void) {
    fuzz_continuation_idx = 0;
    btc_deactivate_semantic_host();
    G_output_len = 0;

    /* G_swap_state is Absolution-driven in the prefix; we only wire the
     * return-value pointer (cannot be prefix-driven) to a static dummy. */
    g_swap_return_dummy = 0;
    ___src_swap_handle_swap_sign_transaction_c_G_swap_sign_return_value_address =
        G_called_from_swap ? &g_swap_return_dummy : NULL;
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

    /* Only SIGN_PSBT can be swap-capable; strip any stale swap state from
     * the prefix for every other route so it does not leak into handlers
     * that have no business seeing it. */
    if (cmd->ins != SIGN_PSBT) {
        G_called_from_swap = 0;
        ___src_swap_handle_swap_sign_transaction_c_G_swap_sign_return_value_address =
            NULL;
    }

    static uint8_t structured_buf[512];
    if (btc_current_lane == BTC_LANE_STRUCTURED) {
        size_t payload_len = build_structured_payload(cmd->ins, structured_buf,
                                                      sizeof(structured_buf));
        if (payload_len > 0) {
            cmd->lc = (uint8_t)(payload_len > 255 ? 255 : payload_len);
            cmd->data = structured_buf;
        }
    }

    apdu_dispatcher(
        FUZZ_COMMAND_DESCRIPTORS,
        sizeof(FUZZ_COMMAND_DESCRIPTORS) / sizeof(FUZZ_COMMAND_DESCRIPTORS[0]),
        ui_menu_main, cmd);
}

int fuzz_entry(const uint8_t* data, size_t size) {
    return fuzz_harness_entry(data, size);
}
