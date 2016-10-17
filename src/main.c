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

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

volatile char fullAmount[20];     // full amount
volatile char addressSummary[20]; // beginning of the output address ... end of
                                  // the address
volatile char feesAmount[20];     // fees
volatile char address1[20];       // full first part of the output address
volatile char address2[20];       // full last part of the output address

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);

ux_state_t ux;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *)bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *)bin)) & 0xF];
        bin = (const void *)((unsigned int)bin + 1);
    }
    *strbuf = 0; // EOS
}

static const bagl_element_t const ui_idle_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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
     io_seproxyhal_touch_exit,
     NULL,
     NULL},

};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

#ifdef COIN_BITCOIN
    {{BAGL_ICON, 0x01, 12, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_BITCOIN_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
#endif // COIN_BITCOIN
    {{BAGL_LABELINE, 0x01, 33, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Use wallet to",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 34, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "view accounts",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x01, 118, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DOWN},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x02, 29, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DASHBOARD_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //{{BAGL_LABELINE                       , 0x02,   0,   3, 128,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000,
    //BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "view
    //accounts", 0, 0, 0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x02, 50, 19, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Quit app",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x02, 3, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_UP},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

unsigned int ui_idle_nanos_state;
unsigned int ui_idle_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (ui_idle_nanos_state == element->component.userid - 1);
    }
    return 1;
}

bagl_element_t const ui_verify_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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
     io_seproxyhal_touch_verify_cancel,
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
     io_seproxyhal_touch_verify_ok,
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

unsigned int ui_verify_blue_button(unsigned int button_mask,
                                   unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_verify_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 21, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_TRANSACTION_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 42, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 43, 26, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 11, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Recipient address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 0, 26, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x04, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Fees",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x04, 23, 26, 82, 11, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /*
    {{BAGL_LABELINE                       , 0x03,   0,  26, 128,  11, 0, 0, 0
    , 0xFFFFFF, 0x000000,
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, address1,
    0, 0, 0, NULL, NULL, NULL },
    {{BAGL_LABELINE                       , 0x04,   0,  26, 128,  11, 0, 0, 0
    , 0xFFFFFF, 0x000000,
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, address2,
    0, 0, 0, NULL, NULL, NULL },
    */

};
unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter);

bagl_element_t const ui_verify_p2sh_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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
     io_seproxyhal_touch_verify_cancel,
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
     io_seproxyhal_touch_verify_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM P2SH TRANSACTION",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_verify_p2sh_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_verify_p2sh_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 32, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_TRANSACTION_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 53, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 53, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "P2SH",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};
unsigned int ui_verify_p2sh_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter);

// display or not according to step, and adjust delay
unsigned int ui_verify_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                io_seproxyhal_setup_ticker(2000);
                break;
            case 2:
                io_seproxyhal_setup_ticker(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 3:
                io_seproxyhal_setup_ticker(3000);
                break;
            case 4:
                io_seproxyhal_setup_ticker(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

bagl_element_t const ui_verify_message_signature_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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
     io_seproxyhal_touch_message_signature_verify_cancel,
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
     io_seproxyhal_touch_message_signature_verify_ok,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM SIGNATURE",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 185, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int
ui_verify_message_signature_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}

const bagl_element_t ui_verify_message_signature_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 28, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_TRANSACTION_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 50, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Sign the",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 49, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "message",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Message hash",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};
unsigned int
ui_verify_message_signature_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter);

unsigned int ui_verify_message_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        switch (element->component.userid) {
        case 1:
            io_seproxyhal_setup_ticker(2000);
            break;
        case 2:
            io_seproxyhal_setup_ticker(3000);
            break;
        }
        return (ux_step == element->component.userid - 1);
    }
    return 1;
}

void ui_idle(void) {
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        UX_DISPLAY(ui_idle_blue, NULL);
    } else {
        ui_idle_nanos_state = 0; // start by displaying the idle first screen
        UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
    }
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // go back to the home screen
    os_sched_exit(0);
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // UP
        if (ui_idle_nanos_state == 1) {
            ui_idle_nanos_state = 0;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // DOWN
        if (ui_idle_nanos_state == 0) {
            ui_idle_nanos_state = 1;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // EXIT
        if (ui_idle_nanos_state == 1) {
            io_seproxyhal_touch_exit(NULL);
        }
        break;
    }
    return 0;
}

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    btchip_bagl_user_action(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    btchip_bagl_user_action(1);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    btchip_bagl_user_action_message_signing(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    btchip_bagl_user_action_message_signing(1);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int ui_verify_p2sh_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_verify_ok(NULL);
        break;
    }
    return 0;
}

unsigned int
ui_verify_message_signature_nanos_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_message_signature_verify_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_message_signature_verify_ok(NULL);
        break;
    }
    return 0;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
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
            return 0; // nothing received from the master so far (it's a tx
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

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (UX_DISPLAYED()) {
        UX_DISPLAYED_:
#ifdef COIN_LITECOIN
            // extra elements per screen, only for idle screen
            if (ux.elements == ui_idle_nanos && ui_idle_nanos_state == 0) {
                // could be used to perform extra print after an array has been
                // displayed
                switch (ux.elements_count - ux.elements_current) {
                case 0: {
                    extern unsigned int const C_icon_litecoin_colors[];
                    extern unsigned char const C_icon_litecoin_bitmap[];
                    io_seproxyhal_display_bitmap(12, 9, 14, 14,
                                                 C_icon_litecoin_colors, 1,
                                                 C_icon_litecoin_bitmap);
                    break;
                }

                // case 1: // next extra element
                // case 2: // next next extra element ...

                default:
                    break;
                }
                ux.elements_current++;
            }
#endif // COIN_LITECOIN
            ;
        } else {
            UX_DISPLAY_PROCESSED_EVENT();
            // nothing displayed, then it's likely the end of the screen
            if (!io_seproxyhal_spi_is_status_sent()) {
                goto UX_DISPLAYED_;
            }
        }
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        // prepare next screen
        ux_step = (ux_step + 1) % ux_step_count;
        // redisplay screen
        UX_REDISPLAY();
        break;

    default:
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
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
    if (btchip_context_D.transactionContext.consumeP2SH) {
        fullAmount[0] = '\0';
        feesAmount[0] = '\0';
        strcpy(addressSummary, "P2SH");
        return 1;
    }
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
        screen_printf("Error : Fees not consistent");
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

                os_memset(addressSummary, 0, sizeof(addressSummary));
                os_memmove((void *)addressSummary, tmp, 5);
                os_memmove((void *)(addressSummary + 5), "...", 3);
                os_memmove((void *)(addressSummary + 8), tmp + strlen(tmp) - 4,
                           4);

                // Prepare amount

                os_memmove(fullAmount, btchip_context_D.shortCoinId,
                           btchip_context_D.shortCoinIdLength);
                fullAmount[btchip_context_D.shortCoinIdLength] = ' ';
                btchip_context_D.tmp =
                    (unsigned char *)(fullAmount +
                                      btchip_context_D.shortCoinIdLength + 1);
                textSize = btchip_convert_hex_amount_to_displayable(amount);
                fullAmount[textSize + btchip_context_D.shortCoinIdLength + 1] =
                    '\0';

                // prepare fee display
                os_memmove(feesAmount, btchip_context_D.shortCoinId,
                           btchip_context_D.shortCoinIdLength);
                feesAmount[btchip_context_D.shortCoinIdLength] = ' ';
                btchip_context_D.tmp =
                    (unsigned char *)(feesAmount +
                                      btchip_context_D.shortCoinIdLength + 1);
                textSize = btchip_convert_hex_amount_to_displayable(fees);
                feesAmount[textSize + btchip_context_D.shortCoinIdLength + 1] =
                    '\0';
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

#define HASH_LENGTH 4
uint8_t prepare_message_signature() {
    unsigned char hash[32];
    cx_hash(&btchip_context_D.transactionHashAuthorization.header, CX_LAST,
            hash, 0, hash);
    array_hexstr(addressSummary, hash, HASH_LENGTH / 2);
    addressSummary[HASH_LENGTH / 2 * 2] = '.';
    addressSummary[HASH_LENGTH / 2 * 2 + 1] = '.';
    addressSummary[HASH_LENGTH / 2 * 2 + 2] = '.';
    array_hexstr(addressSummary + HASH_LENGTH / 2 * 2 + 3,
                 hash + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);
    return 1;
}

// reset interface
void btchip_bagl_idle(void) {
    // here shall wait until all ui is displayed
    // ui_idle();
}

unsigned int btchip_bagl_confirm_full_output(unsigned int outputPos) {
    // TODO : remove when supporting multi output
    if (btchip_context_D.transactionContext.consumeP2SH) {
        if (os_seph_features() &
            SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
            UX_DISPLAY(ui_verify_p2sh_blue, NULL);
        } else {
            // no preprocessing
            UX_DISPLAY(ui_verify_p2sh_nanos, NULL);
        }
        return 1;
    }

    if (!prepare_full_output(outputPos)) {
        return 0;
    }

    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        UX_DISPLAY(ui_verify_blue, NULL);
    } else {
        ux_step = 0;
        ux_step_count = 4;
        UX_DISPLAY(ui_verify_nanos, ui_verify_prepro);
    }
    return 1;
}

void btchip_bagl_confirm_message_signature() {
    if (!prepare_message_signature()) {
        return;
    }
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        UX_DISPLAY(ui_verify_message_signature_blue, NULL);
    } else {
        ux_step = 0;
        ux_step_count = 2;
        UX_DISPLAY(ui_verify_message_signature_nanos, ui_verify_message_prepro);
    }
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    UX_INIT();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            btchip_context_init();

            USB_power(1);

#ifdef HAVE_BLE
            BLE_power(1, "Ledger Wallet");
#endif // HAVE_BLE

            ui_idle();

            app_main();
        }
        CATCH_ALL {
            // exit :)
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();

    return 0;
}
