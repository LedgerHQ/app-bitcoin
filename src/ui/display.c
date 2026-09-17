#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset
#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "./display.h"

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.

extern bool G_was_processing_screen_shown;

static bool g_ux_flow_ended;
static bool g_ux_flow_response;
static int g_current_streaming_index;

extern dispatcher_context_t G_dispatcher_context;

ui_state_t g_ui_state;

/**
 * Drop-in replacement for `strncpy(dst, src, dst_size)` for the strings displayed by this module.
 *
 * Copies the 0-terminated string `src` into the `dst_size`-byte buffer `dst`, terminator included.
 * Unlike `strncpy`, the result is always 0-terminated, and the copy is never truncated: if `src`
 * does not fit (or has no terminator within the first `dst_size` bytes), that is a programming
 * error and the app is halted, rather than continuing with a possibly misrepresented UI flow.
 */
static void copy_ui_string(char *dst, const char *src, size_t dst_size) {
    size_t len = strnlen(src, dst_size);
    LEDGER_ASSERT(len < dst_size, "String does not fit in the UI buffer");
    memcpy(dst, src, len + 1);
}

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
// This method also sets the UI state as "dirty" according to the input parameter
// so that the dispatcher refreshes resets the UI at the end of the command handler.
// Returns true/false depending if the user accepted in the corresponding UX flow.
static bool io_ui_process(dispatcher_context_t *context, bool set_dirty) {
    G_was_processing_screen_shown = false;

    g_ux_flow_ended = false;

    if (set_dirty) {
        context->set_ui_dirty();
    }

    // We are not waiting for the client's input, nor we are doing computations on the device
    io_clear_processing_timeout();

    io_seproxyhal_general_status();
    do {
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();
        io_seproxyhal_general_status();
    } while (io_seproxyhal_spi_is_status_sent() && !g_ux_flow_ended);

    // We're back at work, we want to show the "Processing..." screen when appropriate
    io_start_processing_timeout();

    return g_ux_flow_response;
}

bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       bool is_path_suspicious,
                       const char *pubkey) {
    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    copy_ui_string(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    copy_ui_string(state->pubkey, pubkey, sizeof(state->pubkey));

    if (!is_path_suspicious) {
        ui_display_pubkey_flow();
    } else {
        ui_display_pubkey_suspicious_flow();
    }

    return io_ui_process(context, true);
}

bool ui_display_path_and_message_content(dispatcher_context_t *context,
                                         const char *path_str,
                                         const char *message_content,
                                         uint8_t pageCount) {
    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    copy_ui_string(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    copy_ui_string(state->message, message_content, sizeof(state->message));

    ui_sign_message_content_flow(pageCount);

    return io_ui_process(context, true);
}

bool ui_display_message_path_hash_and_confirm(dispatcher_context_t *context,
                                              const char *path_str,
                                              const char *message_hash) {
    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    copy_ui_string(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    copy_ui_string(state->message, message_hash, sizeof(state->message));

    ui_sign_message_path_hash_and_confirm_flow();

    return io_ui_process(context, true);
}

bool ui_display_message_confirm(dispatcher_context_t *context) {
    (void) context;
    ui_sign_message_confirm_flow();

    return io_ui_process(context, true);
}

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    copy_ui_string(state->wallet_name, wallet_header->name, sizeof(state->wallet_name));
    state->wallet_name[wallet_header->name_len] = 0;
    copy_ui_string(state->descriptor_template, policy_descriptor, sizeof(state->descriptor_template));
    state->descriptor_template[wallet_header->descriptor_template_len] = 0;

    ui_display_register_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           key_type_e key_type) {
    (void) (n_keys);

    ui_cosigner_pubkey_and_index_state_t *state =
        (ui_cosigner_pubkey_and_index_state_t *) &g_ui_state;

    copy_ui_string(state->pubkey, pubkey, sizeof(state->pubkey));

    if (key_type == PUBKEY_TYPE_INTERNAL) {
        snprintf(state->signer_index, sizeof(state->signer_index), "Key @%u, ours", cosigner_index);
    } else if (key_type == PUBKEY_TYPE_EXTERNAL) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, theirs",
                 cosigner_index);
    } else if (key_type == PUBKEY_TYPE_UNSPENDABLE) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, dummy",
                 cosigner_index);
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
    }
    ui_display_policy_map_cosigner_pubkey_flow();

    return io_ui_process(context, true);
}

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    copy_ui_string(state->address, address, sizeof(state->address));

    if (wallet_name == NULL) {
        ui_display_default_wallet_address_flow();
    } else {
        copy_ui_string(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ui_display_receive_in_wallet_flow();
    }

    return io_ui_process(context, true);
}

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    copy_ui_string(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    ui_display_spend_from_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_warn_external_inputs(dispatcher_context_t *context) {
    ui_display_warning_external_inputs_flow();
    return io_ui_process(context, true);
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
    ui_display_unverified_segwit_inputs_flows();
    return io_ui_process(context, true);
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context) {
    ui_display_nondefault_sighash_flow();
    return io_ui_process(context, true);
}

bool ui_transaction_prompt(dispatcher_context_t *context, const int external_outputs_total_count) {
    ui_display_transaction_prompt(external_outputs_total_count);
    return io_ui_process(context, true);
}

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        int total_count,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount) {
    ui_validate_output_state_t *state = (ui_validate_output_state_t *) &g_ui_state;

    copy_ui_string(state->address_or_description,
            address_or_description,
            sizeof(state->address_or_description));
    format_sats_amount(coin_name, amount, state->amount);

    if (total_count == 1) {
        ui_display_output_address_amount_no_index_flow(index);
    } else {
        ui_display_output_address_amount_flow(index);
    }

    return io_ui_process(context, true);
}

bool ui_warn_high_fee(dispatcher_context_t *context) {
    ui_warn_high_fee_flow();

    return io_ui_process(context, true);
}

bool ui_validate_transaction(dispatcher_context_t *context,
                             const char *coin_name,
                             uint64_t fee,
                             bool is_self_transfer) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(coin_name, fee, state->fee);

    ui_accept_transaction_flow(is_self_transfer);

    return io_ui_process(context, true);
}

#ifdef HAVE_BAGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

void ui_pre_processing_message(void) {
    return;
}
#endif  // HAVE_BAGL

#ifdef HAVE_NBGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_wallet_registation(success);

    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_wallet_spend(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_transaction(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_message(success);

    return true;
}

void ui_pre_processing_message(void) {
    ui_set_display_prompt();
}
#endif  // HAVE_NBGL
