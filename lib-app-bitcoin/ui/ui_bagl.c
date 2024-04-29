/*******************************************************************************
 *   Ledger App - Bitcoin Wallet
 *   (c) 2022 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#ifdef HAVE_BAGL
//////////////////////////////////////////////////////////////////////
#include "context.h"
#include "display_variables.h"
#include "transaction.h"
#include "ui.h"

#include "extensions.h"

bagl_element_t tmp_element;

static unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e) {
  UNUSED(e);
  // user denied the transaction, tell the USB side
  if (!user_action(0)) {
    // redraw ui
    ui_idle_flow();
  }
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e) {
  UNUSED(e);
  // user accepted the transaction, tell the USB side
  if (!user_action(1)) {
    // redraw ui
    ui_idle_flow();
  }
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e) {
  UNUSED(e);
  // user denied the transaction, tell the USB side
  user_action_message_signing(0);
  // redraw ui
  ui_idle_flow();
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e) {
  UNUSED(e);
  // user accepted the transaction, tell the USB side
  user_action_message_signing(1);
  // redraw ui
  ui_idle_flow();
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int
io_seproxyhal_touch_display_cancel(const bagl_element_t *e) {
  UNUSED(e);
  // user denied the transaction, tell the USB side
  user_action_display(0);
  // redraw ui
  ui_idle_flow();
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int io_seproxyhal_touch_display_ok(const bagl_element_t *e) {
  UNUSED(e);
  // user accepted the transaction, tell the USB side
  // redraw ui
  ui_idle_flow();
  return user_action_display(1);
}

static unsigned int io_seproxyhal_touch_sign_cancel(const bagl_element_t *e) {
  UNUSED(e);
  // user denied the transaction, tell the USB side
  user_action_signtx(0, 0);
  // redraw ui
  ui_idle_flow();
  return 0; // DO NOT REDRAW THE BUTTON
}

static unsigned int io_seproxyhal_touch_sign_ok(const bagl_element_t *e) {
  UNUSED(e);
  // user accepted the transaction, tell the USB side
  user_action_signtx(1, 0);
  // redraw ui
  ui_idle_flow();
  return 0; // DO NOT REDRAW THE BUTTON
}

void io_seproxyhal_display(const bagl_element_t *element) {
  if ((element->component.type & (~BAGL_TYPE_FLAGS_MASK)) != BAGL_NONE) {
    io_seproxyhal_display_default((bagl_element_t *)element);
  }
}
//////////////////////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_idle_flow_1_step, nn,
             {
                 "Application",
                 "is ready",
             });
UX_STEP_NOCB(ux_idle_flow_2_step, bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_CB(ux_idle_flow_3_step, pb, os_sched_exit(-1),
           {
               &C_icon_dashboard_x,
               "Quit",
           });
UX_FLOW(ux_idle_flow, &ux_idle_flow_1_step, &ux_idle_flow_2_step,
        &ux_idle_flow_3_step, FLOW_LOOP);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_sign_flow_1_step, pnn,
             {
                 &C_icon_certificate,
                 "Sign",
                 "message",
             });
UX_STEP_NOCB(ux_sign_flow_2_step, bnnn_paging,
             {
                 .title = "Message hash",
                 .text = vars.tmp.fullAddress,
             });
UX_STEP_CB(ux_sign_flow_3_step, pbb,
           io_seproxyhal_touch_message_signature_verify_ok(NULL),
           {
               &C_icon_validate_14,
               "Sign",
               "message",
           });
UX_STEP_CB(ux_sign_flow_4_step, pbb,
           io_seproxyhal_touch_message_signature_verify_cancel(NULL),
           {
               &C_icon_crossmark,
               "Cancel",
               "signature",
           });

UX_FLOW(ux_sign_flow, &ux_sign_flow_1_step, &ux_sign_flow_2_step,
        &ux_sign_flow_3_step, &ux_sign_flow_4_step);

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_confirm_single_flow_1_step, pnn,
             {
                 &C_icon_eye, "Review",
                 vars.tmp.feesAmount, // output #
             });
UX_STEP_NOCB(ux_confirm_single_flow_2_step, bnnn_paging,
             {
                 .title = "Amount",
                 .text = vars.tmp.fullAmount,
             });
UX_STEP_NOCB(ux_confirm_single_flow_3_step, bnnn_paging,
             {
                 .title = "Address",
                 .text = vars.tmp.fullAddress,
             });
UX_STEP_CB(ux_confirm_single_flow_5_step, pb,
           io_seproxyhal_touch_verify_ok(NULL),
           {
               &C_icon_validate_14,
               "Accept",
           });
UX_STEP_CB(ux_confirm_single_flow_6_step, pb,
           io_seproxyhal_touch_verify_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject",
           });
// confirm_single: confirm output #x(feesAmount) / Amount: fullAmount / Address:
// fullAddress
UX_FLOW(ux_confirm_single_flow, &ux_confirm_single_flow_1_step,
        &ux_confirm_single_flow_2_step, &ux_confirm_single_flow_3_step,
        &ux_confirm_single_flow_5_step, &ux_confirm_single_flow_6_step);

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_finalize_flow_1_step, pnn,
             {&C_icon_eye, "Confirm", "transaction"});
UX_STEP_NOCB(ux_finalize_flow_4_step, bnnn_paging,
             {
                 .title = "Fees",
                 .text = vars.tmp.feesAmount,
             });
UX_STEP_CB(ux_finalize_flow_5_step, pbb, io_seproxyhal_touch_verify_ok(NULL),
           {&C_icon_validate_14, "Accept", "and send"});
UX_STEP_CB(ux_finalize_flow_6_step, pb, io_seproxyhal_touch_verify_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject",
           });
// finalize: confirm transaction / Fees: feesAmount
UX_FLOW(ux_finalize_flow, &ux_finalize_flow_1_step, &ux_finalize_flow_4_step,
        &ux_finalize_flow_5_step, &ux_finalize_flow_6_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_display_public_flow_1_step, pnn,
             {
                 &C_icon_warning,
                 "The derivation",
                 "path is unusual!",
             });
UX_STEP_NOCB(ux_display_public_flow_2_step, bnnn_paging,
             {
                 .title = "Derivation path",
                 .text = vars.tmp_warning.derivation_path,
             });
UX_STEP_CB(ux_display_public_flow_3_step, pnn,
           io_seproxyhal_touch_display_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject if you're",
               "not sure",
           });
UX_STEP_NOCB(ux_display_public_flow_4_step, pnn,
             {
                 &C_icon_validate_14,
                 "Approve derivation",
                 "path",
             });
UX_STEP_NOCB(ux_display_public_flow_5_step, bnnn_paging,
             {
                 .title = "Address",
                 .text = (char *)G_io_apdu_buffer + 200,
             });
UX_STEP_CB(ux_display_public_flow_6_step, pb,
           io_seproxyhal_touch_display_ok(NULL),
           {
               &C_icon_validate_14,
               "Approve",
           });
UX_STEP_CB(ux_display_public_flow_7_step, pb,
           io_seproxyhal_touch_display_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_display_public_with_warning_flow, &ux_display_public_flow_1_step,
        &ux_display_public_flow_2_step, &ux_display_public_flow_3_step,
        &ux_display_public_flow_4_step, FLOW_BARRIER,
        &ux_display_public_flow_5_step, &ux_display_public_flow_6_step,
        &ux_display_public_flow_7_step);

UX_FLOW(ux_display_public_flow, &ux_display_public_flow_5_step,
        &ux_display_public_flow_6_step, &ux_display_public_flow_7_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_CB(ux_display_token_flow_1_step, pbb,
           io_seproxyhal_touch_display_ok(NULL),
           {
               &C_icon_validate_14,
               "Confirm token",
               (char *)G_io_apdu_buffer + 200,
           });
UX_STEP_CB(ux_display_token_flow_2_step, pb,
           io_seproxyhal_touch_display_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_display_token_flow, &ux_display_token_flow_1_step,
        &ux_display_token_flow_2_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_CB(ux_request_pubkey_approval_flow_1_step, pbb,
           io_seproxyhal_touch_display_ok(NULL),
           {
               &C_icon_validate_14,
               "Export",
               "public key?",
           });
UX_STEP_CB(ux_request_pubkey_approval_flow_2_step, pb,
           io_seproxyhal_touch_display_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_request_pubkey_approval_flow,
        &ux_request_pubkey_approval_flow_1_step,
        &ux_request_pubkey_approval_flow_2_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_request_change_path_approval_flow_1_step, pbb,
             {
                 &C_icon_eye,
                 "The change path",
                 "is unusual",
             });
UX_STEP_NOCB(ux_request_change_path_approval_flow_2_step, bnnn_paging,
             {
                 .title = "Change path",
                 .text = vars.tmp_warning.derivation_path,
             });
UX_STEP_CB(ux_request_change_path_approval_flow_3_step, pbb,
           io_seproxyhal_touch_display_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject if you're",
               "not sure",
           });
UX_STEP_CB(ux_request_change_path_approval_flow_4_step, pb,
           io_seproxyhal_touch_display_ok(NULL),
           {
               &C_icon_validate_14,
               "Approve",
           });

UX_FLOW(ux_request_change_path_approval_flow,
        &ux_request_change_path_approval_flow_1_step,
        &ux_request_change_path_approval_flow_2_step,
        &ux_request_change_path_approval_flow_3_step,
        &ux_request_change_path_approval_flow_4_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_request_sign_path_approval_flow_1_step, pbb,
             {
                 &C_icon_eye,
                 "The sign path",
                 "is unusual",
             });
UX_STEP_NOCB(ux_request_sign_path_approval_flow_2_step, bnnn_paging,
             {
                 .title = "Sign path",
                 .text = vars.tmp_warning.derivation_path,
             });
UX_STEP_CB(ux_request_sign_path_approval_flow_3_step, pbb,
           io_seproxyhal_touch_sign_cancel(NULL),
           {
               &C_icon_crossmark,
               "Reject if you're",
               "not sure",
           });
UX_STEP_CB(ux_request_sign_path_approval_flow_4_step, pb,
           io_seproxyhal_touch_sign_ok(NULL),
           {
               &C_icon_validate_14,
               "Approve",
           });

UX_FLOW(ux_request_sign_path_approval_flow,
        &ux_request_sign_path_approval_flow_1_step,
        &ux_request_sign_path_approval_flow_2_step,
        &ux_request_sign_path_approval_flow_3_step,
        &ux_request_sign_path_approval_flow_4_step);

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_request_segwit_input_approval_flow_1_step, pb,
             {.icon = &C_icon_warning, .line1 = "Unverified inputs"});
UX_STEP_NOCB(ux_request_segwit_input_approval_flow_2_step, nn,
             {.line1 = "Update", .line2 = " Ledger Live"});
UX_STEP_NOCB(ux_request_segwit_input_approval_flow_3_step, nn,
             {.line1 = "or third party", .line2 = "wallet software"});
UX_STEP_CB(ux_request_segwit_input_approval_flow_4_step, pb,
           io_seproxyhal_touch_display_cancel(NULL),
           {.icon = &C_icon_crossmark, .line1 = "Cancel"});
UX_STEP_CB(ux_request_segwit_input_approval_flow_5_step, pb,
           io_seproxyhal_touch_display_ok(NULL),
           {&C_icon_validate_14, "Continue"});

UX_FLOW(ux_request_segwit_input_approval_flow,
        &ux_request_segwit_input_approval_flow_1_step,
        &ux_request_segwit_input_approval_flow_2_step,
        &ux_request_segwit_input_approval_flow_3_step,
        &ux_request_segwit_input_approval_flow_4_step,
        &ux_request_segwit_input_approval_flow_5_step);

void ui_sign_message_flow(void) { ux_flow_init(0, ux_sign_flow, NULL); }

void ui_confirm_single_flow(void) {
  snprintf(vars.tmp.feesAmount, sizeof(vars.tmp.feesAmount), "output #%d",
           context.totalOutputs - context.remainingOutputs + 1);
  ux_flow_init(0, ux_confirm_single_flow, NULL);
}

void ui_finalize_flow(void) { ux_flow_init(0, ux_finalize_flow, NULL); }

void ui_display_public_with_warning_flow(void) {
  ux_flow_init(0, ux_display_public_with_warning_flow, NULL);
}

void ui_display_public_flow(void) {
  ux_flow_init(0, ux_display_public_flow, NULL);
}

void ui_display_token_flow(void) {
  ux_flow_init(0, ux_display_token_flow, NULL);
}

void ui_request_pubkey_approval_flow(void) {
  ux_flow_init(0, ux_request_pubkey_approval_flow, NULL);
}

void ui_request_change_path_approval_flow(void) {
  ux_flow_init(0, ux_request_change_path_approval_flow, NULL);
}

void ui_request_sign_path_approval_flow(void) {
  ux_flow_init(0, ux_request_sign_path_approval_flow, NULL);
}

void ui_request_segwit_input_approval_flow(void) {
  ux_flow_init(0, ux_request_segwit_input_approval_flow, NULL);
}

void ui_idle_flow(void) {
  if (G_ux.stack_count == 0) {
    ux_stack_push();
  }
  ux_flow_init(0, ux_idle_flow, NULL);
}

void ui_transaction_error(void) {}

void ui_transaction_finish(void) {}

#endif // HAVE_BAGL
