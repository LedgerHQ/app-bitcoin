/*******************************************************************************
*   Ledger Blue - Bitcoin Wallet
*   (c) 2016 Ledger
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

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"

#include "btchip_internal.h"

#include "btchip_bagl_extensions.h"

void io_usb_enable(unsigned char enabled);
void os_boot(void);

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

volatile unsigned char uiDoneAfterDraw;
volatile unsigned char uiDone;
volatile unsigned char transactionVerified;
volatile unsigned int current_element;
volatile bagl_element_t *active_screen;
volatile unsigned int active_screen_element_count;
volatile bagl_element_t *active_screen2;
volatile unsigned int active_screen2_element_count;
volatile unsigned char display_changed;
volatile enum {
    BAGL_BTCHIP_IDLE,
    BAGL_BTCHIP_VERIFY,
} btchip_ui_mode = BAGL_BTCHIP_IDLE;

volatile char fullAmount[20];     // full amount
volatile char addressSummary[20]; // beginning of the output address ... end of
                                  // the address
volatile char address1[20];       // full first part of the output address
volatile char address2[20];       // full last part of the output address

volatile unsigned char generalStatus;

unsigned int io_seproxyhal_touch_verify_cancel(bagl_element_t *e);
unsigned int io_seproxyhal_touch_verify_ok(bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(bagl_element_t *e);

static const bagl_element_t const bagl_ui_erase_all[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

static const bagl_element_t const bagl_ui_idle[] = {
    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Ledger Blue",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 90, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "$DEVICENAME",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 150, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Ready",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 225, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "EXIT",
     0,
     0x37ae99,
     0xF9F9F9,
     (bagl_element_callback_t)io_seproxyhal_touch_exit,
     NULL,
     NULL},

};

bagl_element_t const bagl_ui_verify[] = {
    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Ledger Blue",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     (bagl_element_callback_t)io_seproxyhal_touch_verify_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM TRANSACTION",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 185, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Default wallet",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 217, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 280, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 310, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)address1,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 330, 320, 33, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (const char *)address2,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    display_changed = 1;
    io_seproxyhal_display_default((bagl_element_t *)element);
}

void display_init(void) {
    uiDone = 0;
    uiDoneAfterDraw = 0;
    display_changed = 0;
    active_screen2 = NULL;
}

void displayHome(void) {
    btchip_ui_mode = BAGL_BTCHIP_IDLE;
    current_element = 0;
    active_screen_element_count = sizeof(bagl_ui_idle) / sizeof(bagl_element_t);
    active_screen = (bagl_element_t *)bagl_ui_idle;
    io_seproxyhal_display(&bagl_ui_erase_all[0]);
}

// off
unsigned int io_seproxyhal_touch_exit(bagl_element_t *e) {
    /*
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_DEVICE_OFF;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 0;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 3);
    */
    // go back to the home screen
    os_sched_exit(0);
    return 0; // DO NOT REDRAW THE BUTTON
}

// verify cancel
unsigned int io_seproxyhal_touch_verify_cancel(bagl_element_t *e) {
    transactionVerified = 0;
    uiDoneAfterDraw = 1;
    displayHome();
    return 0; // DO NOT REDRAW THE BUTTON
}

// verify ok
unsigned int io_seproxyhal_touch_verify_ok(bagl_element_t *e) {
    transactionVerified = 1;
    uiDoneAfterDraw = 1;
    displayHome();
    return 0; // DO NOT REDRAW THE BUTTON
}

void reset(void) {
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing recPeived from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

unsigned int usb_enable_request;
unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed
    unsigned int offset = 0;

    // just reply "amen"
    // add a "pairing ok" tag if necessary
    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_BLE_PAIRING_ATTEMPT_EVENT:
        G_io_seproxyhal_spi_buffer[offset++] = SEPROXYHAL_TAG_PAIRING_STATUS;
        G_io_seproxyhal_spi_buffer[offset++] = 0;
        G_io_seproxyhal_spi_buffer[offset++] = 1;
        G_io_seproxyhal_spi_buffer[offset++] = 1;
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, offset);
        break;

    case SEPROXYHAL_TAG_FINGER_EVENT:
        // TOUCH & RELEASE
        display_changed = 0; // detect screen display requests, to determine if
                             // general status is required or not
        io_seproxyhal_touch((const bagl_element_t *)active_screen,
                            active_screen_element_count,
                            (G_io_seproxyhal_spi_buffer[4] << 8) |
                                (G_io_seproxyhal_spi_buffer[5] & 0xFF),
                            (G_io_seproxyhal_spi_buffer[6] << 8) |
                                (G_io_seproxyhal_spi_buffer[7] & 0xFF),
                            // map events
                            G_io_seproxyhal_spi_buffer[3]);
        if (!display_changed) {
            goto general_status;
        }
        break;

#ifdef HAVE_BLE
    // Make automatically discoverable again when disconnected

    case SEPROXYHAL_TAG_BLE_CONNECTION_EVENT:
        if (G_io_seproxyhal_spi_buffer[3] == 0) {
            // TODO : cleaner reset sequence
            // first disable BLE before turning it off
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            // send BLE power on (default parameters)
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
        }
        goto general_status;
#endif        

    case SEPROXYHAL_TAG_SESSION_START_EVENT:
#ifdef HAVE_BLE    
        // send BLE power on (default parameters)
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
        G_io_seproxyhal_spi_buffer[1] = 0;
        G_io_seproxyhal_spi_buffer[2] = 1;
        G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
#endif        

        // request usb startup after display done
        usb_enable_request = 1;

        display_init();

        // display the home (erase the loader screen is mandatory, and not done
        // by the loader)
        displayHome();
        // goto general_status;
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (active_screen2 != NULL) {
            if (current_element < active_screen2_element_count) {
                // continue displaying element if any to be processed again
                io_seproxyhal_display(
                    (const bagl_element_t *)&active_screen2[current_element++]);
                break;
            } else {
                active_screen2 = NULL;
                current_element = active_screen_element_count;
            }
        } else {
            if (current_element < active_screen_element_count) {
                // continue displaying element if any to be processed again
                io_seproxyhal_display(
                    (const bagl_element_t *)&active_screen[current_element++]);
                break;
            }
        }
        if (usb_enable_request) {
            // enable usb support
            io_usb_enable(1);

            usb_enable_request = 0;
        }
        if (uiDoneAfterDraw) {
            // Top level handle the general status along with the APDU response
            uiDoneAfterDraw = 0;
            uiDone = 1;
            break;
        }
        // no break is intentional: always a general status after display event
        generalStatus = 1;

    default:
    general_status:
        // send a general status last command
        offset = 0;
        G_io_seproxyhal_spi_buffer[offset++] = SEPROXYHAL_TAG_GENERAL_STATUS;
        G_io_seproxyhal_spi_buffer[offset++] = 0;
        G_io_seproxyhal_spi_buffer[offset++] = 2;
        G_io_seproxyhal_spi_buffer[offset++] =
            SEPROXYHAL_TAG_GENERAL_STATUS_LAST_COMMAND >> 8;
        G_io_seproxyhal_spi_buffer[offset++] =
            SEPROXYHAL_TAG_GENERAL_STATUS_LAST_COMMAND;
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, offset);
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

uint8_t prepare_full_output(unsigned int outputPos) {
    unsigned int offset = 0;
    int numberOutputs;
    int i;
    unsigned int currentPos = 0;
    unsigned char amount[8], totalOutputAmount[8], fees[8];
    char tmp[100];
    // Parse output
    os_memset(totalOutputAmount, 0, sizeof(totalOutputAmount));
    numberOutputs = btchip_context_D.currentOutput[offset++];
    if (numberOutputs > 3) {
        screen_printf("Error : Too many outputs");
        goto error;
    }
    for (i = 0; i < numberOutputs; i++) {
        unsigned char nullAmount = 1;
        unsigned int j;
        for (j = 0; j < 8; j++) {
            if (btchip_context_D.currentOutput[offset + j] != 0) {
                nullAmount = 0;
                break;
            }
        }
        btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
        transaction_amount_add_be(totalOutputAmount, totalOutputAmount, amount);
        offset += 8; // skip amount
        if (!btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                             offset) &&
            !btchip_output_script_is_p2sh(btchip_context_D.currentOutput +
                                          offset) &&
            !(nullAmount && btchip_output_script_is_op_return(
                                btchip_context_D.currentOutput + offset))) {
            screen_printf("Error : Unrecognized input script");
            goto error;
        }
        offset += 1 + btchip_context_D.currentOutput[offset];
    }
    if (transaction_amount_sub_be(
            fees, btchip_context_D.transactionContext.transactionAmount,
            totalOutputAmount)) {
        screen_printf("Error : Fees not consistant");
        goto error;
    }
    // Format validation message
    offset = 1;
    btchip_context_D.tmp = (unsigned char *)tmp;
    for (i = 0; i < numberOutputs; i++) {
        if (!btchip_output_script_is_op_return(btchip_context_D.currentOutput +
                                               offset + 8)) {
            int addressOffset;
            unsigned char address[21];
            btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset,
                              8);
            offset += 8;
            if (btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                                offset)) {
                addressOffset = offset + 4;
                address[0] = N_btchip.bkp.config.payToAddressVersion;
            } else {
                addressOffset = offset + 3;
                address[0] = N_btchip.bkp.config.payToScriptHashVersion;
            }
            os_memmove(address + 1,
                       btchip_context_D.currentOutput + addressOffset, 20);
            if (currentPos == outputPos) {
                unsigned short textSize;
                textSize = btchip_public_key_to_encoded_base58(
                    address, 21, (unsigned char *)tmp, sizeof(tmp), 0, 1);
                tmp[textSize] = '\0';
                // Prepare address
                os_memmove((void *)address1, tmp, 18);
                address1[18] = '\0';
                os_memmove((void *)address2, tmp + 18, strlen(tmp) - 18);
                address2[strlen(tmp) - 18] = '\0';
                os_memmove((void *)addressSummary, tmp, 5);
                os_memmove((void *)(addressSummary + 5), " ... ", 5);
                os_memmove((void *)(addressSummary + 10), tmp + strlen(tmp) - 4,
                           4);
                addressSummary[14] = '\0';
                // Prepare amount
                // TODO : match current coin version
                btchip_context_D.tmp = (unsigned char *)fullAmount;
                textSize = btchip_convert_hex_amount_to_displayable(amount);
                os_memmove((void *)(fullAmount + textSize), " BTC", 4);
                fullAmount[textSize + 4] = '\0';
                break;
            }
        } else {
            offset += 8;
        }
        offset += 1 + btchip_context_D.currentOutput[offset];
        currentPos++;
    }
    return 1;
error:
    return 0;
}

uint8_t btchip_bagl_confirm_full_output(unsigned int outputPos) {
    uiDone = 0;
    uiDoneAfterDraw = 0;
    transactionVerified = 0;
    if (!prepare_full_output(outputPos)) {
        return 0;
    }
    btchip_ui_mode = BAGL_BTCHIP_VERIFY;
    current_element = 0;
    active_screen_element_count =
        sizeof(bagl_ui_verify) / sizeof(bagl_element_t);
    active_screen = (bagl_element_t *)bagl_ui_verify;
    io_seproxyhal_display(&bagl_ui_erase_all[0]);
    // Loop on the UI, general status will be sent when all components are
    // displayed
    while (!uiDone) {
        unsigned int rx_len;
        rx_len = io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                        sizeof(G_io_seproxyhal_spi_buffer), 0);
        if ((rx_len - 3) != (unsigned int)U2(G_io_seproxyhal_spi_buffer[1],
                                             G_io_seproxyhal_spi_buffer[2])) {
            continue;
        }
        io_event(CHANNEL_SPI);
    }
    return transactionVerified;
}

void main_continue(void) {
    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            screen_printf("ST31_APP booted.\n");

            // fake the session start event
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SESSION_START_EVENT;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_event(CHANNEL_SPI);

            btchip_context_init();

            app_main();
        }
        CATCH_ALL {
            for (;;)
                ;
        }
        FINALLY {
        }
    }
    END_TRY;
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    main_continue();

    return 0;
}
