#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "display.h"

/* SDK headers */
#include "os.h"
#include "ux.h"

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.

extern bool G_was_processing_screen_shown;

static bool g_ux_flow_ended;
static bool g_ux_flow_response;
static int g_current_streaming_index;

extern dispatcher_context_t G_dispatcher_context;

ui_state_t g_ui_state;

/*
 * Pointer to the text to be shown when processing.
 * If set to NULL, a default message is shown,
 * otherwise it must be a pointer to a valid 0-terminated string.
 */
char const *G_processing_screen_text;

void send_deny_sw(dispatcher_context_t *dc) {
    SEND_SW(dc, SW_DENY);
}

void set_ux_flow_response(bool approved) {
    g_ux_flow_ended = true;
    g_ux_flow_response = approved;
}

uint8_t get_streaming_index(void) {
    return g_current_streaming_index;
}

void reset_streaming_index(void) {
    PRINTF("Reset streaming index\n");
    g_current_streaming_index = 0;
}

void increase_streaming_index(void) {
    PRINTF("Increase streaming index\n");
    g_current_streaming_index += 1;
}

void decrease_streaming_index(void) {
    PRINTF("Decrease streaming index\n");
    if (g_current_streaming_index > 0) {
        g_current_streaming_index -= 1;
    }
}

// Process UI events until the current flow terminates; does not handle any APDU exchange
// Returns true/false depending if the user accepted in the corresponding UX flow.
bool io_ui_process(dispatcher_context_t *context) {
    UNUSED(context);
    G_was_processing_screen_shown = false;

    // Setting `had_ux_flow` flag meaning that the UI interaction is launched
    // This is now UI/NBGL that is responsible to return to Home screen
    G_dispatcher_context.set_ui_dirty();

    g_ux_flow_ended = false;

    // We are not waiting for the client's input, nor we are doing computations on the device
    ioe_clear_processing_timeout();

#ifdef REVAMPED_IO
    do {
        io_seproxyhal_io_heartbeat();
    } while (!g_ux_flow_ended);
#else   // !REVAMPED_IO
    io_seproxyhal_general_status();
    do {
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();
        io_seproxyhal_general_status();
    } while (io_seproxyhal_spi_is_status_sent() && !g_ux_flow_ended);
#endif  // !REVAMPED_IO

    // We're back at work, we want to show the "Processing..." screen when appropriate
    ioe_start_processing_timeout();

    return g_ux_flow_response;
}

bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       const char *pubkey) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    ui_display_pubkey_flow();

    return io_ui_process(context);
}

bool ui_display_message_and_confirm(dispatcher_context_t *context,
                                    const char *path_str,
                                    const char *message,
                                    bool is_hash) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    strncpy(state->message, message, sizeof(state->message));

    ui_sign_message_and_confirm_flow(is_hash);

    return io_ui_process(context);
}

bool ui_display_register_wallet_policy(
    dispatcher_context_t *context,
    const policy_map_wallet_header_t *wallet_header,
    const char *descriptor_template,
    const char (*keys_info)[MAX_N_KEYS_IN_WALLET_POLICY][MAX_POLICY_KEY_INFO_LEN + 1],
    const key_type_e (*keys_type)[MAX_N_KEYS_IN_WALLET_POLICY]) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    LEDGER_ASSERT(wallet_header->n_keys <= MAX_N_KEYS_IN_WALLET_POLICY, "Too many keys");

    ui_register_wallet_policy_state_t *state = (ui_register_wallet_policy_state_t *) &g_ui_state;

    memset(state, 0, sizeof(ui_register_wallet_policy_state_t));
    state->n_keys = wallet_header->n_keys;
    state->wallet_name = wallet_header->name;
    state->descriptor_template = descriptor_template;
    for (size_t i = 0; i < wallet_header->n_keys; i++) {
        state->keys_info[i] = (*keys_info)[i];
#ifdef SCREEN_SIZE_WALLET
        const char labels[3][20] = {"Internal", "External", "Unspendable"};
#else
        const char labels[3][20] = {"Our", "Their", "Dummy"};
#endif
        unsigned int num = 0;
        switch ((*keys_type)[i]) {
            case PUBKEY_TYPE_INTERNAL:
                num = 0;
                break;
            case PUBKEY_TYPE_EXTERNAL:
                num = 1;
                break;
            case PUBKEY_TYPE_UNSPENDABLE:
                num = 2;
                break;
            default:
                LEDGER_ASSERT(false, "Unreachable code");
        }
        snprintf(state->keys_label[i], sizeof(state->keys_label[i]), "%s key@%u", labels[num], i);
    }

    ui_display_register_wallet_policy_flow();

    return io_ui_process(context);
}

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    strncpy(state->address, address, sizeof(state->address));

    if (wallet_name == NULL) {
        ui_display_default_wallet_address_flow();
    } else {
        strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ui_display_receive_in_wallet_flow();
    }

    return io_ui_process(context);
}

void ui_prepare_authorize_wallet_spend(const char *wallet_name) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    strncpy(state->wallet_policy_name, wallet_name, sizeof(state->wallet_policy_name));
    state->has_wallet_policy = true;
}

bool ui_warn_external_inputs(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_warning_external_inputs_flow();
    return io_ui_process(context);
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_unverified_segwit_inputs_flows();
    return io_ui_process(context);
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_nondefault_sighash_flow();
    return io_ui_process(context);
}

bool ui_transaction_streaming_prompt(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_transaction_streaming_prompt();
    return io_ui_process(context);
}

bool ui_transaction_streaming_validate_output(dispatcher_context_t *context,
                                              int index,
                                              int total_count,
                                              const char *address_or_description,
                                              uint64_t amount) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_output_index(index, total_count, state->output_index_str[0]);

    strncpy(state->address_or_description[0],
            address_or_description,
            sizeof(state->address_or_description[0]));
    format_sats_amount(COIN_COINID_SHORT, amount, state->amount[0]);

    ui_display_transaction_streaming_output_address_amount();

    return io_ui_process(context);
}

bool ui_transaction_streaming_validate(dispatcher_context_t *context,
                                       uint64_t fee,
                                       tx_ux_warning_t warnings,
                                       bool is_self_transfer) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(COIN_COINID_SHORT, fee, state->fee);
    state->warnings = warnings;

    ui_display_transaction_streaming_flow(is_self_transfer);

    return io_ui_process(context);
}

void ui_transaction_simplified_init(const char *wallet_policy_name,
                                    unsigned int outputs_num,
                                    tx_ux_warning_t warnings) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    memset(state, 0, sizeof(ui_validate_transaction_state_t));

    if (wallet_policy_name != NULL) {
        strncpy(state->wallet_policy_name, wallet_policy_name, sizeof(state->wallet_policy_name));
        state->has_wallet_policy = true;
    } else {
        memset(state->wallet_policy_name, 0, sizeof(state->wallet_policy_name));
    }
    state->n_outputs = outputs_num;
    state->warnings = warnings;

    ui_display_transaction_simplified_flow_init();
}

void ui_transaction_simplified_add(uint64_t amount, const char *address_or_description) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(COIN_COINID_SHORT, amount, state->amount[state->output_index]);
    if (address_or_description == NULL) {
        state->is_self_transfer = true;
    } else {
        strncpy(state->address_or_description[state->output_index],
                address_or_description,
                sizeof(state->address_or_description[state->output_index]));
    }
    format_output_index(state->output_index + 1,
                        state->n_outputs,
                        state->output_index_str[state->output_index]);

    ui_display_transaction_simplified_flow_add();
    state->output_index++;
}

bool ui_transaction_simplified_show(dispatcher_context_t *context, uint64_t fee) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(COIN_COINID_SHORT, fee, state->fee);

    ui_display_transaction_simplified_flow_show();

    return io_ui_process(context);
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    UNUSED(context);
    ui_display_post_processing_confirm_transaction(success);

    return true;
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    UNUSED(context);
    ui_display_post_processing_confirm_message(success);

    return true;
}

char const *ui_get_processing_screen_text(void) {
    return (G_processing_screen_text != NULL) ? G_processing_screen_text : "Loading";
}

void ui_set_processing_screen_text(const char *text) {
    G_processing_screen_text = text;
}
