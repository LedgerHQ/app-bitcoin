/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
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

#include "io_ext.h"

/* SDK headers */
#include "buffer.h"
#include "nbgl_touch.h"
#include "nbgl_use_case.h"
#include "os.h"
#include "swap.h"
#include "ux.h"
#include "write.h"

/* Local headers */
#include "dispatcher.h"
#include "display.h"
#include "sw.h"

uint16_t G_output_len = 0;

// Counter incremented at every tick
// The initial value does not matter, as only the difference between timeframes is used.
uint16_t G_ticks;

struct {
    bool interruption : 1;
    bool processing : 1;
} G_is_timeout_active;

// set to true when the "Processing..." screen is shown, in order for the dispatcher to know if the
// UX is not in idle state at the end of a command handler.
bool G_was_processing_screen_shown;

uint16_t G_interruption_timeout_start_tick;
uint16_t G_processing_timeout_start_tick;

void ioe_start_interruption_timeout() {
    G_interruption_timeout_start_tick = G_ticks;
    G_is_timeout_active.interruption = true;
}

void ioe_clear_interruption_timeout() {
    G_is_timeout_active.interruption = false;
}

void ioe_start_processing_timeout() {
    G_processing_timeout_start_tick = G_ticks;
    G_is_timeout_active.processing = true;
}

void ioe_clear_processing_timeout() {
    G_is_timeout_active.processing = false;
}

void ioe_reset_timeouts() {
    ioe_clear_interruption_timeout();
    ioe_clear_processing_timeout();
    G_was_processing_screen_shown = false;
}

void ioe_show_processing_screen() {
    if (!G_was_processing_screen_shown) {
        G_was_processing_screen_shown = true;
#ifdef HAVE_SWAP
        if (!G_called_from_swap) {
#endif /* HAVE_SWAP */
            nbgl_useCaseSpinner(ui_get_processing_screen_text());
#ifdef HAVE_SWAP
        }
#endif /* HAVE_SWAP */
    }
}

// This function can be used to declare a callback to SEPROXYHAL_TAG_TICKER_EVENT in the application
void app_ticker_event_callback(void) {
    ++G_ticks;

    if (G_is_timeout_active.processing &&
        (uint16_t) (G_ticks - G_processing_timeout_start_tick) >= PROCESSING_TIMEOUT_TICKS) {
        ioe_clear_processing_timeout();

        ioe_show_processing_screen();
    }

    if (G_is_timeout_active.interruption &&
        (uint16_t) (G_ticks - G_interruption_timeout_start_tick) >= INTERRUPTION_TIMEOUT_TICKS) {
        ioe_clear_interruption_timeout();

        // TODO: It would be better to have the dispatcher be notified somehow.
        //       This would require some tampering with the io_exchange in
        //       process_interruption.
        THROW(EXCEPTION_IO_RESET);
    }
}

void ioe_add_to_response(const void *rdata, size_t rdata_len) {
    if (G_output_len > IO_APDU_BUFFER_SIZE - 2) {
        // No room left for the status word
        G_output_len = IO_APDU_BUFFER_SIZE;
        write_u16_be(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, SW_WRONG_RESPONSE_LENGTH);
        return;
    }

    size_t remaining = (IO_APDU_BUFFER_SIZE - 2) - G_output_len;

    if (rdata_len > remaining) {
        // Truncate: copy only what fits, then finalize with error SW
        memmove(G_io_apdu_buffer + G_output_len, rdata, remaining);
        G_output_len = IO_APDU_BUFFER_SIZE;
        write_u16_be(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, SW_WRONG_RESPONSE_LENGTH);
    } else {
        memmove(G_io_apdu_buffer + G_output_len, rdata, rdata_len);
        G_output_len += rdata_len;
    }
}

void ioe_finalize_response(uint16_t sw) {
    if (G_output_len >= IO_APDU_BUFFER_SIZE - 2) {
        G_output_len = IO_APDU_BUFFER_SIZE;
        write_u16_be(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, SW_WRONG_RESPONSE_LENGTH);
    } else {
        write_u16_be(G_io_apdu_buffer, G_output_len, sw);
        G_output_len += 2;
    }
}

int ioe_send_response() {
    int ret = io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, G_output_len);
    G_output_len = 0;

    return ret;
}

int ioe_send_sw(uint16_t sw) {
    G_output_len = 0;
    ioe_finalize_response(sw);
    return ioe_send_response();
}
