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

#ifdef HAVE_NBGL
#include "context.h"
#include "display_variables.h"
#include "nbgl_use_case.h"
#include "ui.h"

#include "extensions.h"

static nbgl_layoutTagValue_t pairs[3];
static nbgl_layoutTagValueList_t pairList;

bool transaction_prompt_done;

static void (*start_transaction_callback)(bool);
static char text[40];

// User action callbacks
static void approved_user_action_callback(void) { user_action(1); }

static void approved_user_action_processing_callback(void) {
  if (!user_action(1)) {
    nbgl_useCaseSpinner("Processing");
  }
}

static void abandon_user_action_callback(void) { user_action(0); }

static void approved_user_action_message_signing_callback(void) {
  user_action_message_signing(1);
}

static void abandon_user_action_message_signing_callback(void) {
  user_action_message_signing(0);
}

static void approved_user_action_display_callback(void) {
  user_action_display(1);
}

static void abandon_user_action_display_callback(void) {
  user_action_display(0);
}

static void approved_user_action_signtx_callback(void) {
  user_action_signtx(1, 0);
}

static void abandon_user_action_signtx_callback(void) {
  transaction_prompt_done = false;
  user_action_signtx(0, 0);
  nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle_flow);
}

// Flow entry point
static void sign_transaction_callback(bool confirmed) {
  if (confirmed) {
    approved_user_action_processing_callback();
  } else {
    transaction_prompt_done = false;
    abandon_user_action_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle_flow);
  }
}

static void sign_transaction_processing_callback(bool confirmed) {
  if (confirmed) {
    approved_user_action_processing_callback();
  } else {
    transaction_prompt_done = false;
    abandon_user_action_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle_flow);
  }
}

static void continue_single_flow(bool confirmed) {
  if (confirmed) {
    snprintf(vars.tmp.feesAmount, sizeof(vars.tmp.feesAmount), "#%d",
             context.totalOutputs - context.remainingOutputs + 1);

    pairs[0].item = "Output";
    pairs[0].value = vars.tmp.feesAmount;

    pairs[1].item = "Amount";
    pairs[1].value = vars.tmp.fullAmount;

    pairs[2].item = "Address";
    pairs[2].value = vars.tmp.fullAddress;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 3;
    pairList.pairs = pairs;

    nbgl_useCaseReviewStreamingContinue(&pairList, sign_transaction_callback);
  } else {
    sign_transaction_callback(false);
  }
}

static void start_transaction_flow(void) {
  snprintf(text, sizeof(text), "Review transaction\nto send %s?",
           COIN_COINID_NAME);
  transaction_prompt_done = true;
  nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION, &COIN_ICON, text, NULL,
                                   start_transaction_callback);
}

void ui_confirm_single_flow(void) {
  if (!transaction_prompt_done) {
    start_transaction_callback = continue_single_flow;
    start_transaction_flow();
  }

  else {
    continue_single_flow(true);
  }
}

static void finish_transaction_flow(bool choice) {
  if (choice) {
    nbgl_useCaseReviewStreamingFinish("Sign transaction\nto send Bitcoin?",
                                      sign_transaction_processing_callback);
  } else {
    sign_transaction_processing_callback(false);
  }
}

static void continue_finalize_flow(bool confirmed) {
  if (confirmed) {
    pairs[0].item = "Fees";
    pairs[0].value = vars.tmp.feesAmount;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;
    pairList.nbPairs = 1;

    nbgl_useCaseReviewStreamingContinue(&pairList, finish_transaction_flow);
  } else {
    finish_transaction_flow(false);
  }
}

void ui_finalize_flow(void) {
  if (!transaction_prompt_done) {
    start_transaction_callback = continue_finalize_flow;
    start_transaction_flow();
  } else {
    continue_finalize_flow(true);
  }
}

static void request_approval_callback(bool confirmed) {
  if (confirmed) {
    approved_user_action_processing_callback();
  } else {
    transaction_prompt_done = false;
    abandon_user_action_display_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle_flow);
  }
}

static void continue_change_path_approval_flow(bool confirmed) {
  if (confirmed) {
    nbgl_useCaseChoice(&C_Important_Circle_64px, "Unusual\nchange path",
                       vars.tmp_warning.derivation_path, "Continue",
                       "Reject if not sure", request_approval_callback);
  } else {
    request_approval_callback(false);
  }
}

void ui_request_change_path_approval_flow(void) {
  if (!transaction_prompt_done) {
    start_transaction_callback = continue_change_path_approval_flow;
    start_transaction_flow();
  } else {
    continue_change_path_approval_flow(false);
  }
}

static void continue_segwit_input_approval_flow(bool confirmed) {
  if (confirmed) {
    nbgl_useCaseChoice(&C_Important_Circle_64px, "Unverified inputs",
                       "Update Ledger Live\nor third party software",
                       "Continue", "Reject if not sure",
                       request_approval_callback);
  } else {
    request_approval_callback(false);
  }
}

void ui_request_segwit_input_approval_flow(void) {
  if (!transaction_prompt_done) {
    start_transaction_callback = continue_segwit_input_approval_flow;
    start_transaction_flow();
  } else {
    continue_change_path_approval_flow(false);
  }
}

void ui_request_pubkey_approval_flow(void) {
  nbgl_useCaseChoice(&COIN_ICON, "Export public key", NULL, "Approve", "Reject",
                     request_approval_callback);
}

static void user_action_signtx_callback(bool confirmed) {
  if (confirmed) {
    nbgl_useCaseSpinner("Processing");
    approved_user_action_signtx_callback();
  } else {
    abandon_user_action_signtx_callback();
  }
}

void ui_request_sign_path_approval_flow(void) {
  nbgl_useCaseChoice(&C_Important_Circle_64px, "Unusual\nsign path",
                     vars.tmp_warning.derivation_path, "Continue",
                     "Reject if not sure", user_action_signtx_callback);
}

static void sign_message_callback(bool confirmed) {
  if (confirmed) {
    nbgl_useCaseSpinner("Processing");
    approved_user_action_message_signing_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_idle_flow);
  } else {
    abandon_user_action_message_signing_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_idle_flow);
  }
}
void ui_sign_message_flow(void) {
  // Setup data to display
  pairs[0].item = "Message hash";
  pairs[0].value = vars.tmp.fullAddress;

  // Setup list
  pairList.nbMaxLinesForValue = 0;
  pairList.nbPairs = 1;
  pairList.pairs = pairs;

  nbgl_useCaseReview(TYPE_MESSAGE, &pairList, &COIN_ICON, "Review\nmessage",
                     NULL, "Sign message", sign_message_callback);
}

static void token_flow_callback(bool confirmed) {
  if (confirmed) {
    approved_user_action_display_callback();
    nbgl_useCaseStatus("Token\nconfirmed", true, ui_idle_flow);
  } else {
    abandon_user_action_display_callback();
    nbgl_useCaseStatus("Token\nrejected", false, ui_idle_flow);
  }
}

void ui_display_token_flow(void) {
  nbgl_useCaseChoice(&COIN_ICON, "Confirm token",
                     (char *)G_io_apdu_buffer + 200, "Approve", "Reject",
                     token_flow_callback);
}

static void public_flow_callback(bool confirmed) {
  if (confirmed) {
    approved_user_action_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle_flow);
  } else {
    abandon_user_action_callback();
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle_flow);
  }
}

static void public_post_warning_flow(bool confirmed) {
  if (confirmed) {
    pairs[0].item = "Derivation path";
    pairs[0].value = vars.tmp_warning.derivation_path;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    snprintf(text, sizeof(text), "Verify %s\naddress", COIN_COINID_NAME);
    nbgl_useCaseAddressReview((char *)G_io_apdu_buffer + 200, &pairList,
                              &COIN_ICON, text, NULL, public_flow_callback);
  } else {
    public_flow_callback(false);
  }
}

void ui_display_public_with_warning_flow(void) {
  nbgl_useCaseChoice(&C_Important_Circle_64px, "Unusual\nderivation path", NULL,
                     "Continue", "Reject if not sure",
                     public_post_warning_flow);
}

void ui_display_public_flow(void) {
  snprintf(text, sizeof(text), "Verify %s\naddress", COIN_COINID_NAME);
  nbgl_useCaseAddressReview((char *)G_io_apdu_buffer + 200, NULL, &COIN_ICON,
                            text, NULL, public_flow_callback);
}

void ui_transaction_finish(void) {
  if (transaction_prompt_done) {
    transaction_prompt_done = false;
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle_flow);
  }
}

void ui_transaction_error(void) {
  transaction_prompt_done = false;
  nbgl_useCaseStatus("Transaction\nerror", false, ui_idle_flow);
}
#endif // HAVE_NBGL
