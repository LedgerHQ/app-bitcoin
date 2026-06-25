#pragma once

#include <stdbool.h>
#include <stdint.h>

/* SDK headers */
#include "bip32.h"
#include "bolos_target.h"
#include "format.h"

/* Local headers */
#include "sighash.h"  // tx_display_mode_t
#include "constants.h"
#include "dispatcher.h"
#include "display.h"
#include "display_utils.h"
#include "io_ext.h"
#include "script.h"
#include "sw.h"
#include "wallet.h"

#define MESSAGE_CHUNK_SIZE 64  // Protocol specific
// Displayed message length - if the message is too long we will not display it
#define MAX_DISPLAYBLE_MESSAGE_LENGTH (10 * MESSAGE_CHUNK_SIZE)

#ifndef TARGET_ID
#error "bolos_target.h must be included (TARGET_* constants unavailable)"
#endif
#if defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_IMPORTANT IMPORTANT_CIRCLE_ICON
#define ICON_APP_WARNING   LARGE_WARNING_ICON
#define ICON_APP_HOME      C_Bitcoin_64px
#define ICON_APP_ACTION    C_Bitcoin_64px
#elif defined(TARGET_APEX_P)
#define ICON_APP_IMPORTANT IMPORTANT_CIRCLE_ICON
#define ICON_APP_WARNING   LARGE_WARNING_ICON
#define ICON_APP_HOME      C_Bitcoin_48px
#define ICON_APP_ACTION    C_Bitcoin_48px
#else
#define ICON_APP_IMPORTANT WARNING_ICON
#define ICON_APP_WARNING   WARNING_ICON
#define ICON_APP_HOME      C_bitcoin_logo
#define ICON_APP_ACTION    C_bitcoin_logo_inv
#endif

typedef struct tx_ux_warning_s {
    bool missing_nonwitnessutxo : 1;
    bool non_default_sighash : 1;
    bool external_inputs : 1;
    bool high_fee : 1;
} tx_ux_warning_t;

typedef enum {
    PUBKEY_TYPE_INTERNAL = 0,    // a key controlled by the wallet policy
    PUBKEY_TYPE_EXTERNAL = 1,    // a key not controlled by the wallet policy
    PUBKEY_TYPE_UNSPENDABLE = 2  // the provably unspendable public key defined in BIP-341
} key_type_e;

// TODO: hard to keep track of what globals are used in the same flows
//       (especially since the same flow step can be shared in different flows)

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
} ui_path_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} ui_path_and_pubkey_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_path_and_address_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char message[MAX_DISPLAYBLE_MESSAGE_LENGTH + 1];
} ui_path_and_message_state_t;

typedef struct {
    char wallet_name[MAX_WALLET_NAME_LENGTH + 1];

    // no flows show together both a policy map and an address, therefore we share memory
    union {
        char descriptor_template[MAX_DESCRIPTOR_TEMPLATE_LENGTH + 1];
        char address[MAX_ADDRESS_LENGTH_STR + 1];
    };
} ui_wallet_state_t;

// maximum length of the description of a cosigner in a wallet policy
#define MAX_KEY_LABEL_LENGTH sizeof("Key @999, unspendable")

typedef struct {
    const char *wallet_name;
    const char *descriptor_template;
    size_t n_keys;
    char keys_label[MAX_N_KEYS_IN_WALLET_POLICY][MAX_KEY_LABEL_LENGTH];
    const char *keys_info[MAX_N_KEYS_IN_WALLET_POLICY];
} ui_register_wallet_policy_state_t;

typedef struct {
    char pubkey[MAX_POLICY_KEY_INFO_LEN + 1];
    char signer_index[sizeof("Key @999 <theirs>")];
} ui_cosigner_pubkey_and_index_state_t;

// Which side of the transaction the wallet account is on, for the account review row.
typedef enum {
    ACCOUNT_ROLE_FROM,     // net spend (and the default/FULL case)
    ACCOUNT_ROLE_TO,       // net receive
    ACCOUNT_ROLE_NEUTRAL,  // direction not knowable (UNAVAILABLE)
} account_role_t;

// Amount summary for the transaction review (mode from decide_tx_display_mode).
typedef struct {
    tx_display_mode_t mode;
    uint64_t fee;           // for TX_DISPLAY_FULL
    int64_t total_spent;    // for TX_DISPLAY_NET_ONLY (negative = net receive)
    uint32_t seen_sighash;  // effective sighash, for the "Signing rule" row
    bool sighash_mixed;     // signed inputs disagree -> shown as "Mixed"
} tx_summary_t;

typedef struct {
    tx_ux_warning_t warnings;
    bool has_wallet_policy;
    char wallet_policy_name[MAX_WALLET_NAME_LENGTH + 1];
    bool is_self_transfer;
    unsigned int n_outputs;
    unsigned int output_index;
    char output_index_str[MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER][MAX_OUTPUT_INDEX_LENGTH + 1];
    char address_or_description[MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER]
                               [MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)];
    char amount[MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER][MAX_AMOUNT_LENGTH + 1];
    char fee[MAX_AMOUNT_LENGTH + 1];  // formatted: network fee, or |total_spent| for NET_ONLY

    tx_display_mode_t display_mode;
    bool spent_is_receive;        // for TX_DISPLAY_NET_ONLY: total_spent < 0
    account_role_t account_role;  // From / To / neutral for the account row
    bool account_is_default;      // default derivation vs registered policy, for the row label
    uint32_t seen_sighash;        // for the "Signing rule" row
    bool sighash_mixed;
} ui_validate_transaction_state_t;

/**
 * Union of all the states for each of the UI screens, in order to save memory.
 */
typedef union {
    ui_path_and_pubkey_state_t path_and_pubkey;
    ui_path_and_address_state_t path_and_address;
    ui_path_and_message_state_t path_and_message;
    ui_wallet_state_t wallet;
    ui_cosigner_pubkey_and_index_state_t cosigner_pubkey_and_index;
    ui_register_wallet_policy_state_t register_wallet_policy;
    ui_validate_transaction_state_t validate_transaction_simplified;
} ui_state_t;
extern ui_state_t g_ui_state;

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(dispatcher_context_t *dispatcher_context, bool);

/**
 * Display the derivation path and pubkey, and asks the confirmation to export.
 *
 * TODO: docs
 */
bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       const char *pubkey);

bool ui_display_message_and_confirm(dispatcher_context_t *context,
                                    const char *path_str,
                                    const char *message,
                                    bool is_hash);

bool ui_display_register_wallet_policy(
    dispatcher_context_t *context,
    const policy_map_wallet_header_t *wallet_header,
    const char *descriptor_template,
    const char (*keys_info)[MAX_N_KEYS_IN_WALLET_POLICY][MAX_POLICY_KEY_INFO_LEN + 1],
    const key_type_e (*keys_type)[MAX_N_KEYS_IN_WALLET_POLICY]);

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address);

bool ui_display_unusual_path(dispatcher_context_t *context, const char *bip32_path_str);

void ui_prepare_authorize_wallet_spend(const char *wallet_name,
                                       account_role_t account_role,
                                       bool account_is_default,
                                       const tx_summary_t *summary);

bool ui_warn_external_inputs(dispatcher_context_t *context);

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context);

bool ui_warn_nondefault_sighash(dispatcher_context_t *context);

// Shows a terminal status explaining that a non-standard sighash was rejected
void ui_warn_nondefault_sighash_disabled(dispatcher_context_t *context);

bool ui_warn_high_fee(dispatcher_context_t *context);

/* These 3 functions have to be called in following order:
 * 1. init - initialize the flow; the summary is applied here so the account row, the
 *           "Signing rule" line and the per-output page breaks are all available up front.
 * 2. add  - to add information for an output.
 * 3. show - to actually start showing the transaction screens.
 * These functions call respectively init, add and show functions from display_nbgl module.
 */
void ui_transaction_simplified_init(const char *wallet_policy_name,
                                    unsigned int outputs_num,
                                    tx_ux_warning_t warnings,
                                    account_role_t account_role,
                                    bool account_is_default,
                                    const tx_summary_t *summary);
void ui_transaction_simplified_add(uint64_t amount, const char *address_or_description);
bool ui_transaction_simplified_show(dispatcher_context_t *context);

bool ui_transaction_streaming_prompt(dispatcher_context_t *context);
bool ui_transaction_streaming_validate_output(dispatcher_context_t *context,
                                              int index,
                                              int total_count,
                                              const char *address_or_description,
                                              uint64_t amount);
bool ui_transaction_streaming_validate(dispatcher_context_t *context,
                                       tx_ux_warning_t warnings,
                                       bool is_self_transfer);

void set_ux_flow_response(bool approved);

/* Functions from display_nbgl.c
 * TODO: to merge display.c and display_nbgl.c
 */
void ui_display_pubkey_flow(void);

void ui_sign_message_and_confirm_flow(bool is_hash);

void ui_display_receive_in_wallet_flow(void);

void ui_display_default_wallet_address_flow(void);

void ui_display_spend_from_wallet_flow(void);

void ui_display_warning_external_inputs_flow(void);

void ui_display_unverified_segwit_inputs_flows(void);

void ui_display_nondefault_sighash_flow(void);

void ui_display_nondefault_sighash_disabled_flow(void);

void ui_warn_high_fee_flow(void);

void ui_display_register_wallet_policy_flow(void);

void ui_display_transaction_simplified_flow_init(void);
void ui_display_transaction_simplified_flow_add(void);
void ui_display_transaction_simplified_flow_show(void);

void ui_display_transaction_streaming_prompt(void);
void ui_display_transaction_streaming_output_address_amount(void);
void ui_display_transaction_streaming_flow(bool is_self_transfer);

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success);

void ui_display_post_processing_confirm_message(bool success);
void ui_display_post_processing_confirm_transaction(bool success);
void ui_set_display_prompt(void);

uint8_t get_streaming_index(void);
void reset_streaming_index(void);
void increase_streaming_index(void);
void decrease_streaming_index(void);

/**
 * Functions to get and set the text to be shown when processing.
 */
char const *ui_get_processing_screen_text(void);
void ui_set_processing_screen_text(const char *text);
