/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025, 2026 Ledger SAS.
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
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "sign_psbt.h"
#include "sign_psbt/init_global_state.h"
#include "sign_psbt/preprocess_inputs.h"
#include "sign_psbt/preprocess_outputs.h"
#include "sign_psbt/sign_input.h"
#include "sign_psbt/swap_checks.h"
#include "sign_psbt/transaction_display.h"

/* SDK headers */
#include "swap.h"

/* Local headers */
#include "bitvector.h"
#include "constants.h"
#include "display.h"
#include "dispatcher.h"
#include "handle_swap_sign_transaction.h"
#include "musig_sessions.h"
#include "sign_psbt_cache.h"
#include "swap_globals.h"
#include "sw.h"
#include "txhashes.h"

void handler_sign_psbt(dispatcher_context_t *dc, uint8_t protocol_version) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    /* Setting transaction loading information screen */
    ui_set_processing_screen_text(GA_LOADING_TRANSACTION);

    sign_psbt_state_t st;
    memset(&st, 0, sizeof(st));

    st.protocol_version = protocol_version;

    // read APDU inputs, initialize global state and read global PSBT map
    if (!init_global_state(dc, &st)) return;

    sign_psbt_cache_t cache;
    init_sign_psbt_cache(&cache);

    // bitmap to keep track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];
    memset(internal_inputs, 0, sizeof(internal_inputs));

    // bitmap to keep track of which inputs are internal
    uint8_t internal_outputs[BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)];
    memset(internal_outputs, 0, sizeof(internal_outputs));

    /** Inputs verification flow
     *
     *  Go through all the inputs:
     *  - verify the non_witness_utxo
     *  - compute value spent
     *  - detect internal inputs that should be signed, and if there are external inputs or unusual
     * sighashes
     */
    if (!preprocess_inputs(dc, &st, &cache, internal_inputs)) return;

    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Check if it's an acceptable output.
     */
    if (!preprocess_outputs(dc, &st, &cache, internal_outputs)) return;

    // check if we're only executing the MuSig2 Round 1
    bool only_signing_for_musig = true;
    for (size_t i = 0; i < st.account.n_internal_key_expressions; i++) {
        if (st.account.internal_key_expressions[i].to_sign &&
            st.account.internal_key_expressions[i].key_expression_ptr->type !=
                KEY_EXPRESSION_MUSIG) {
            // at least one of the key expressions we're signing for is not a MuSig
            only_signing_for_musig = false;
        }
    }

    signing_state_t signing_state;
    memset(&signing_state, 0, sizeof(signing_state));

    // Make sure that the signing state for MuSig2 is initialized correctly
    musigsession_initialize_signing_state(&signing_state.musig);

    // compute all the tx-wide hashes
    if (!compute_tx_hashes(dc, &st, &signing_state.tx_hashes)) {
        return;
    }

    if (!st.has_musig2_pub_nonces) {
        // We execute the first round of MuSig for any musig2 key expression, producing the
        // pubnonces; this does not involve the private keys, therefore we can do it without user
        // confirmation

        if (!produce_musig2_pubnonces(dc, &st, &signing_state, &cache, internal_inputs)) {
            return;
        }
    }

    // we execute the signing flow only if we're expected to produce any signature
    // (including, possibly, any MuSig2 partial signature from Round 2 of MuSig2)
    if (!only_signing_for_musig || st.has_musig2_pub_nonces) {
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            /** SWAP CHECKS
             *
             *  If called from the exchange app, perform the necessary additional checks.
             */

            // During swaps, the user approval was already obtained in the exchange app
            if (!execute_swap_checks(dc, &st)) return;
        } else
#endif /* HAVE_SWAP */
        {
            /** TRANSACTION CONFIRMATION
             *
             *  Display each non-change output, and transaction fees, and acquire user confirmation,
             */
            if (!display_transaction(dc, &st, internal_outputs)) return;
        }

        // Signing always takes some time, so we rather not wait before showing the spinner
        ioe_show_processing_screen();

        /** SIGNING FLOW
         *
         * For each internal key expression, and for each internal input, sign using the
         * appropriate algorithm.
         */
        int sign_result = sign_transaction(dc, &st, &cache, &signing_state, internal_inputs);

#ifdef HAVE_SWAP
        if (!G_called_from_swap)
#endif /* HAVE_SWAP */
        {
            ui_post_processing_confirm_transaction(dc, sign_result);
        }

        if (!sign_result) {
            return;
        }

#ifdef HAVE_SWAP
        // Only if called from swap, the app should terminate after sending the response
        if (G_called_from_swap) {
            G_swap_state.should_exit = true;
        }
#endif /* HAVE_SWAP */
    }

    // MuSig2: if there is an active session at the end of round 1, we move it to persistent
    // storage. It is important that this is only done at the very end of the signing process,
    // end only if everything is successful.
    musigsession_commit(&signing_state.musig);

    SEND_SW(dc, SW_OK);
}
