#include <assert.h>
#include <stdint.h>

/* SDK headers */
#include "nbgl_use_case.h"

/* Local headers */
#include "display.h"
#include "io_ext.h"
#include "menu.h"

#define REVIEW_CONFIRM FIRST_USER_TOKEN + 1

static const char *confirmed_status;  // text displayed in confirmation page (after long press)
static const char *rejected_status;   // text displayed in rejection page (after reject confirmed)

/* Graphical resources (GA) used by the application and NBGL */
#ifdef SCREEN_SIZE_WALLET
const char GA_SIGN_TRANSACTION[] = "Sign transaction\nto send bitcoin?";
const char GA_SIGN_MESSAGE[] = "Sign message?";
const char GA_REGISTER_ACCOUNT[] = "Register account?";
#else
const char GA_SIGN_TRANSACTION[] = "Sign transaction";
const char GA_SIGN_MESSAGE[] = "Sign message";
const char GA_REGISTER_ACCOUNT[] = "Register account";
#endif /* #ifdef SCREEN_SIZE_WALLET */

#ifdef SCREEN_SIZE_WALLET
const char GA_SECURITY_RISK_TITLE[] = "Security risk detected";
const char GA_WARN_HIGH_FEES_TITLE[] = "High fees warning";
const char GA_RISK_EXTERNAL_INPUTS[] =
    "This transaction has external inputs. You could spend more than expected.";
const char GA_RISK_NON_STD_SIGHASH[] =
    "This transaction uses non-standard signing rules (modified sighash). You could spend more "
    "than expected.";
const char GA_WARN_HIGH_FEES[] =
    "This transaction has fees higher than 10% of the amount you're sending.";
#else
const char GA_SECURITY_RISK_TITLE[] = "Security risk";
const char GA_WARN_HIGH_FEES_TITLE[] = "High fees warning";
const char GA_RISK_EXTERNAL_INPUTS[] = "There are external inputs\nReject if not sure";
const char GA_RISK_NON_STD_SIGHASH[] = "Non-default sighash";
const char GA_WARN_HIGH_FEES[] = "Fees are above 10%\n of total amount";
#endif

const char GA_BACK_TO_SAFETY[] = "Back to safety";
const char GA_CONTINUE_ANYWAY[] = "Continue anyway";
const char GA_RISK_UNVERIFIED_INPUTS[] = "Unverified inputs\nUpdate your wallet software";
const char GA_REVIEW_TRANSACTION[] = "Review transaction\nto send bitcoin";
const char GA_REVIEW_MESSAGE[] = "Review message";
const char GA_LOADING_TRANSACTION[] = "Loading transaction";
const char GA_SIGNING_TRANSACTION[] = "Signing transaction";
const char GA_LOADING_MESSAGE[] = "Loading message";

#define N_UX_PAIRS 51

static nbgl_layoutTagValue_t pairs[N_UX_PAIRS];
static unsigned int n_pairs;
static nbgl_layoutTagValueList_t pairList;

extern bool G_was_processing_screen_shown;

static void finish_transaction_flow(bool choice);

static nbgl_layoutTagValueList_t *make_pair_list(unsigned int nbPairs, bool wrapping) {
    pairList = (nbgl_layoutTagValueList_t) {
        .pairs = pairs,
        .nbPairs = nbPairs,
        .nbMaxLinesForValue = 0,
        .wrapping = wrapping,
    };

    return &pairList;
}

// ux_flow_response
static void ux_flow_response_false(void) {
    set_ux_flow_response(false);
}

static void ux_flow_response_true(void) {
    set_ux_flow_response(true);
}

// Statuses
static void status_operation_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseStatus(rejected_status, false, ui_menu_main);
}

static void status_transaction_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
}

static void status_message_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
}

static void status_address_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
}

static void status_operation_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseStatus(confirmed_status, true, ui_menu_main);
    } else {
        status_operation_cancel();
    }
}

static void status_address_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        status_address_cancel();
    }
}

static void start_processing_transaction_callback(bool confirm) {
    if (confirm) {
        G_was_processing_screen_shown = true;
        nbgl_useCaseSpinner(ui_get_processing_screen_text());
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

static void start_processing_message_callback(bool confirm) {
    if (confirm) {
        G_was_processing_screen_shown = true;
        nbgl_useCaseSpinner(ui_get_processing_screen_text());
        ux_flow_response_true();
    } else {
        status_message_cancel();
    }
}

static void start_transaction_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

#define COMBINE(a, b) a b

// create the string "0 <coind_id> (self-transfer)"
#define SELF_TRANSFER_DESCRIPTION COMBINE("0 ", COMBINE(COIN_COINID_SHORT, " (self-transfer)"))

void ui_display_transaction_simplified_flow_init(void) {
    /* 1 From + MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER*3 + 1 Fees + 1 High fees */
    _Static_assert(N_UX_PAIRS >= (1 + MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER * 3 + 1 + 1),
                   "Insufficient pairs for this flow");
    n_pairs = 0;

    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    if (state->has_wallet_policy) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "From",
            .value = state->wallet_policy_name,
        };
    }
}

void ui_display_transaction_simplified_flow_add(void) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    unsigned int output_index = state->output_index;
    if (!state->is_self_transfer) {
        if (state->n_outputs > 1) {
            pairs[n_pairs++] =
                (nbgl_layoutTagValue_t) {.item = "Transaction output",
                                         .value = state->output_index_str[output_index],
                                         .forcePageStart = true};
        }
        pairs[n_pairs++] = (nbgl_layoutTagValue_t) {.item = "Amount",
                                                    .value = state->amount[output_index],
                                                    .forcePageStart = false};

        pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "To",
            .value = state->address_or_description[output_index],
        };
    } else {
        pairs[n_pairs++] =
            (nbgl_layoutTagValue_t) {.item = "Amount", .value = SELF_TRANSFER_DESCRIPTION};
    }
}

void ui_display_transaction_simplified_flow_show(void) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    if (state->warnings.high_fee) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t) {.item = GA_WARN_HIGH_FEES_TITLE,
                                                     .value = GA_WARN_HIGH_FEES,
                                                     .centeredInfo = true,
                                                     .valueIcon = &ICON_APP_IMPORTANT};
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {.item = "Fees",
                                                .value = state->fee,
                                                .forcePageStart = state->n_outputs > 1 ? 1 : 0};

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       make_pair_list(n_pairs, false),
                       &ICON_APP_ACTION,
                       GA_REVIEW_TRANSACTION,
                       NULL,
                       GA_SIGN_TRANSACTION,
                       start_transaction_callback);
}

void ui_display_transaction_streaming_prompt(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION,
                                     &ICON_APP_ACTION,
                                     GA_REVIEW_TRANSACTION,
                                     NULL,
                                     start_transaction_callback);
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    if (state->has_wallet_policy) {
        pairs[0] = (nbgl_layoutTagValue_t) {
            .item = "From",
            .value = state->wallet_policy_name,
        };

        nbgl_useCaseReviewStreamingContinue(make_pair_list(1, false), start_transaction_callback);
    }
}

void ui_display_transaction_streaming_output_address_amount(void) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    pairs[0].item = "Transaction output";
    pairs[0].value = state->output_index_str[0];

    pairs[1].item = "Amount";
    pairs[1].value = state->amount[0];

    pairs[2].item = "Address";
    pairs[2].value = state->address_or_description[0];

    nbgl_useCaseReviewStreamingContinue(make_pair_list(3, false), start_transaction_callback);
}

void ui_display_transaction_streaming_flow(bool is_self_transfer) {
    unsigned int l_n_pairs = 0;
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    if (state->warnings.high_fee) {
        pairs[l_n_pairs++] = (nbgl_contentTagValue_t) {.item = GA_WARN_HIGH_FEES_TITLE,
                                                       .value = GA_WARN_HIGH_FEES,
                                                       .centeredInfo = true,
                                                       .valueIcon = &ICON_APP_IMPORTANT};
    }

    if (!is_self_transfer) {
        pairs[l_n_pairs].item = "Fees";
        pairs[l_n_pairs++].value = state->fee;
    } else {
        pairs[l_n_pairs].item = "Amount";
        pairs[l_n_pairs++].value = "Self-transfer";

        pairs[l_n_pairs].item = "Fees";
        pairs[l_n_pairs++].value = state->fee;
    }

    nbgl_useCaseReviewStreamingContinue(make_pair_list(l_n_pairs, false), finish_transaction_flow);
}

static void finish_transaction_flow(bool choice) {
    if (choice) {
        nbgl_useCaseReviewStreamingFinish(GA_SIGN_TRANSACTION,
                                          start_processing_transaction_callback);
    } else {
        status_transaction_cancel();
    }
}

// Continue light notify callback
void ui_display_pubkey_flow(void) {
    confirmed_status = "Public key\napproved";
    rejected_status = "Public key rejected";

    pairs[0].item = "Path";
    pairs[0].value = g_ui_state.path_and_pubkey.bip32_path_str;

    pairs[1].item = "Public key";
    pairs[1].value = g_ui_state.path_and_pubkey.pubkey;

    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            make_pair_list(2, false),
                            &ICON_APP_ACTION,
                            "Confirm public key",
                            NULL,
                            "Approve public key",
                            status_operation_callback);
}

void ui_display_receive_in_wallet_flow(void) {
    // Setup list
    pairs[0].item = "Account name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              make_pair_list(1, false),
                              &ICON_APP_ACTION,
                              "Verify bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

void ui_display_register_wallet_policy_flow(void) {
    _Static_assert(N_UX_PAIRS >= 3 + MAX_N_KEYS_IN_WALLET_POLICY + CT_MAX_LINES,
                   "Insufficient pairs for this flow");

    confirmed_status = "Account registered";
    rejected_status = "Account rejected";

    n_pairs = 0;

    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Account name",
        .value = g_ui_state.register_wallet_policy.wallet_name,
    };

    // Cleartext spending-path block, when available.
    if (g_ui_state.register_wallet_policy.n_cleartext_lines > 0 &&
        g_ui_state.register_wallet_policy.cleartext_lines != NULL) {
        static char path_labels[CT_MAX_LINES][sizeof("Spending path #99")];
        size_t n = g_ui_state.register_wallet_policy.n_cleartext_lines;
        for (size_t i = 0; i < n; i++) {
            const char *label;
            if (n == 1) {
                label = "Spending policy";
            } else if (i == 0) {
                label = "Primary spending path";
            } else {
                snprintf(path_labels[i], sizeof(path_labels[i]), "Spending path #%u", (unsigned) i);
                label = path_labels[i];
            }
            pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
                .item = label,
                .value = g_ui_state.register_wallet_policy.cleartext_lines[i],
            };
        }
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
#ifdef SCREEN_SIZE_WALLET
        .item = "Descriptor template",
#else
        .item = "Wallet policy",
#endif
        .value = g_ui_state.register_wallet_policy.descriptor_template,
    };

    pairs[n_pairs++] = (nbgl_contentTagValue_t) {.centeredInfo = true,
                                                 .item = "Review co-signer\npublic keys",
                                                 .value = ""};

    for (size_t i = 0; i < g_ui_state.register_wallet_policy.n_keys; i++) {
        pairs[n_pairs++] =
            (nbgl_layoutTagValue_t) {.item = g_ui_state.register_wallet_policy.keys_label[i],
                                     .value = g_ui_state.register_wallet_policy.keys_info[i]};
    }

    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            make_pair_list(n_pairs, false),
                            &ICON_APP_ACTION,
                            "Review account\nto register",
                            NULL,
                            GA_REGISTER_ACCOUNT,
                            status_operation_callback);
}

void ui_sign_message_and_confirm_flow(bool is_hash) {
    pairs[0].item = "Path";
    pairs[0].value = g_ui_state.path_and_message.bip32_path_str;

    if (!is_hash) {
#ifdef SCREEN_SIZE_WALLET
        pairs[1].item = "Message content";
#else
        pairs[1].item = "Message";
#endif
    } else {
        pairs[1].item = "Message hash";
    }

    pairs[1].value = g_ui_state.path_and_message.message;

    nbgl_useCaseReview(TYPE_MESSAGE,
                       make_pair_list(2, true),
                       &ICON_APP_ACTION,
                       GA_REVIEW_MESSAGE,
                       NULL,
                       GA_SIGN_MESSAGE,
                       start_processing_message_callback);
}

// Address flow
void ui_display_default_wallet_address_flow(void) {
    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              NULL,
                              &ICON_APP_ACTION,
                              "Verify bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

#ifdef SCREEN_SIZE_WALLET
static void display_warning_generic_callback(bool confirm) {
    if (!confirm) {
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}
#endif /* #ifdef SCREEN_SIZE_WALLET */

void ui_display_warning_generic(const char *msg) {
    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       GA_SECURITY_RISK_TITLE,
                       msg,
#ifdef SCREEN_SIZE_WALLET
                       GA_BACK_TO_SAFETY,
                       GA_CONTINUE_ANYWAY,
                       display_warning_generic_callback);
#else
                       GA_CONTINUE_ANYWAY,
                       GA_BACK_TO_SAFETY,
                       start_transaction_callback);
#endif /* #ifdef SCREEN_SIZE_WALLET */
}

// Warning/Security risks flows
void ui_display_warning_external_inputs_flow(void) {
    ui_display_warning_generic(GA_RISK_EXTERNAL_INPUTS);
}

void ui_display_unverified_segwit_inputs_flows(void) {
    ui_display_warning_generic(GA_RISK_UNVERIFIED_INPUTS);
}

void ui_display_nondefault_sighash_flow(void) {
    ui_display_warning_generic(GA_RISK_NON_STD_SIGHASH);
}

// Statuses
void ui_display_post_processing_confirm_message(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
    }
}

void ui_display_post_processing_confirm_transaction(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}
