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

#include "glyphs.h"

#define __NAME3(a, b, c) a##b##c
#define NAME3(a, b, c) __NAME3(a, b, c)

#ifdef HAVE_U2F

#include "u2f_service.h"
#include "u2f_transport.h"

volatile unsigned char u2fMessageBuffer[U2F_MAX_MESSAGE_SIZE];

extern void USB_power_U2F(unsigned char enabled, unsigned char fido);
extern bool fidoActivated;
volatile uint8_t fidoTransport;

#endif

bagl_element_t tmp_element;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH 10
#define BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH 8
#define MAX_CHAR_PER_LINE 25

#define COLOR_BG_1 0xF9F9F9
#define COLOR_APP COLOR_HDR      // bitcoin 0xFCB653
#define COLOR_APP_LIGHT COLOR_DB // bitcoin 0xFEDBA9

#if TARGET_ID == 0x31000002

volatile char fullAmount[40]; // full amount
volatile char fullAddress[65];
volatile char addressSummary[40]; // beginning of the output address ... end of
                                  // the address
volatile char feesAmount[40];     // fees

#else

volatile char fullAmount[20]; // full amount
volatile char fullAddress[20];
volatile char addressSummary[20]; // beginning of the output address ... end of
                                  // the address
volatile char feesAmount[20];     // fees

#endif

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_cancel(const bagl_element_t *e);
unsigned int
io_seproxyhal_touch_message_signature_verify_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_display_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
void ui_idle(void);

ux_state_t ux;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

#ifdef HAVE_U2F

volatile u2f_service_t u2fService;

void u2f_proxy_response(u2f_service_t *service, unsigned int tx) {
    os_memset(service->messageBuffer, 0, 5);
    os_memmove(service->messageBuffer + 5, G_io_apdu_buffer, tx);
    service->messageBuffer[tx + 5] = 0x90;
    service->messageBuffer[tx + 6] = 0x00;
    u2f_send_fragmented_response(service, U2F_CMD_MSG, service->messageBuffer,
                                 tx + 7, true);
}

#endif

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *)bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *)bin)) & 0xF];
        bin = (const void *)((unsigned int)bin + 1);
    }
    *strbuf = 0; // EOS
}

const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

#if TARGET_ID == 0x31000002
const bagl_icon_details_t ui_blue_gif = {
    .bpp = NAME3(GLYPH_badge_, COINID, _BPP),
    .colors = NAME3(C_badge_, COINID, _colors),
    .bitmap = NAME3(C_badge_, COINID, _bitmap),
};

unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
const bagl_element_t ui_idle_blue[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     COINID_UPCASE,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
#ifdef HAVE_U2F
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 56, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_SETTINGS,
     0,
     COLOR_APP,
     0xFFFFFF,
     io_seproxyhal_touch_settings,
     NULL,
     NULL},
#endif
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_DASHBOARD,
     0,
     COLOR_APP,
     0xFFFFFF,
     io_seproxyhal_touch_exit,
     NULL,
     NULL},

    // BADGE_<COINID>.GIF
    {{BAGL_ICON, 0x00, 135, 178, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &ui_blue_gif,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 270, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Open " COINID_NAME " wallet",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 308, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Connect your Ledger Blue and open your",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 331, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "preferred wallet to view your accounts.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Validation requests will show automatically.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    return 0;
}
#endif // #if TARGET_ID == 0x31000002

#if TARGET_ID == 0x31100002

const ux_menu_entry_t menu_main[];
const ux_menu_entry_t menu_settings[];
const ux_menu_entry_t menu_settings_browser[];

#ifdef HAVE_U2F
// change the setting
void menu_settings_browser_change(unsigned int enabled) {
    fidoTransport = enabled;
    nvm_write(&N_btchip.fidoTransport, (void *)&fidoTransport, sizeof(uint8_t));
    USB_power_U2F(0, 0);
    USB_power_U2F(1, N_btchip.fidoTransport);
    // go back to the menu entry
    UX_MENU_DISPLAY(0, menu_settings, NULL);
}

// show the currently activated entry
void menu_settings_browser_init(unsigned int ignored) {
    UNUSED(ignored);
    UX_MENU_DISPLAY(N_btchip.fidoTransport ? 1 : 0, menu_settings_browser,
                    NULL);
}

const ux_menu_entry_t menu_settings_browser[] = {
    {NULL, menu_settings_browser_change, 0, NULL, "No", NULL, 0, 0},
    {NULL, menu_settings_browser_change, 1, NULL, "Yes", NULL, 0, 0},
    UX_MENU_END};

const ux_menu_entry_t menu_settings[] = {
    {NULL, menu_settings_browser_init, 0, NULL, "Browser support", NULL, 0, 0},
    {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};
#endif // HAVE_U2F

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
#ifdef HAVE_U2F
    {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
#else
    {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
#endif // HAVE_U2F
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {NULL, NULL, 0, &NAME3(C_icon_, COINID, ), "Use wallet to", "view accounts",
     33, 12},
#ifdef HAVE_U2F
    {menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
#endif // HAVE_U2F
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

#endif // #if TARGET_ID == 0x31100002

#if TARGET_ID == 0x31000002
// reuse addressSummary for each line content
const char *ui_details_title;
const char *ui_details_content;
typedef void (*callback_t)(void);
callback_t ui_details_back_callback;

// don't perform any draw/color change upon finger event over settings
const bagl_element_t *ui_settings_out_over(const bagl_element_t *e) {
    return NULL;
}

#ifdef HAVE_U2F

const bagl_element_t *ui_settings_blue_toggle_browser(const bagl_element_t *e) {
    // swap setting and request redraw of settings elements
    uint8_t setting = N_btchip.fidoTransport ? 0 : 1;
    nvm_write(&N_btchip.fidoTransport, (void *)&setting, sizeof(uint8_t));

    // only refresh settings mutable drawn elements
    UX_REDISPLAY_IDX(8);

    // won't redisplay the bagl_none
    return 0;
}

#endif

const bagl_element_t *
ui_details_blue_back_callback(const bagl_element_t *element) {
    ui_details_back_callback();
    return 0;
}

unsigned int ui_settings_back_callback(const bagl_element_t *e) {
    // go back to idle
    ui_idle();
    return 0;
}

#ifdef HAVE_U2F

const bagl_icon_details_t ui_blue_item_set_gif = {
    .bpp = GLYPH_icon_toggle_set_BPP,
    .colors = C_icon_toggle_set_colors,
    .bitmap = C_icon_toggle_set_bitmap,
};

const bagl_icon_details_t ui_blue_item_reset_gif = {
    .bpp = GLYPH_icon_toggle_reset_BPP,
    .colors = C_icon_toggle_reset_colors,
    .bitmap = C_icon_toggle_reset_bitmap,
};

const bagl_element_t ui_settings_blue[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "SETTINGS",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 50, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_LEFT,
     0,
     COLOR_APP,
     0xFFFFFF,
     ui_settings_back_callback,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_DASHBOARD,
     0,
     COLOR_APP,
     0xFFFFFF,
     io_seproxyhal_touch_exit,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 105, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     "Browser support",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 30, 126, 260, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, 0},
     "Enable integrated browser support",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 78, 320, 68, 0, 0, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_settings_blue_toggle_browser,
     ui_settings_out_over,
     ui_settings_out_over},

    {{BAGL_ICON, 0x01, 258, 98, 32, 18, 0, 0, BAGL_FILL, 0x000000, COLOR_BG_1,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t *ui_settings_blue_prepro(const bagl_element_t *e) {
    // none elements are skipped
    if ((e->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
        return 0;
    }
    // swap icon buffer to be displayed depending on if corresponding setting is
    // enabled or not.
    if (e->component.userid) {
        os_memmove(&tmp_element, e, sizeof(bagl_element_t));
        switch (e->component.userid) {
        case 0x01:
            // swap icon content
            if (N_btchip.fidoTransport) {
                tmp_element.text = &ui_blue_item_set_gif;
            } else {
                tmp_element.text = &ui_blue_item_reset_gif;
            }
            break;
        }
        return &tmp_element;
    }
    return 1;
}

unsigned int ui_settings_blue_button(unsigned int button_mask,
                                     unsigned int button_mask_counter) {
    return 0;
}

unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e) {
    UX_DISPLAY(ui_settings_blue, ui_settings_blue_prepro);
    return 0; // do not redraw button, screen has switched
}

#endif

const bagl_element_t ui_details_blue[] = {
    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x01, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 50, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_LEFT,
     0,
     COLOR_APP,
     0xFFFFFF,
     ui_details_blue_back_callback,
     NULL,
     NULL},
    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //io_seproxyhal_touch_exit, NULL, NULL},

    {{BAGL_LABELINE, 0x00, 30, 106, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "VALUE",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x10, 30, 136, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x11, 30, 159, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 30, 182, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x13, 30, 205, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x14, 30, 228, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x15, 30, 251, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x16, 30, 274, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x17, 30, 297, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x18, 30, 320, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //"..." at the end if too much
    {{BAGL_LABELINE, 0x19, 30, 343, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Review the whole value before continuing.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_details_blue_prepro(const bagl_element_t *element) {
    if (element->component.userid == 1) {
        strcpy(addressSummary, ui_details_title);
    } else if (element->component.userid > 0) {
        unsigned int length = strlen(ui_details_content);
        if (length >= (element->component.userid & 0xF) * MAX_CHAR_PER_LINE) {
            os_memset(addressSummary, 0, MAX_CHAR_PER_LINE + 1);
            os_memmove(
                addressSummary,
                ui_details_content +
                    (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
                MIN(length -
                        (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
                    MAX_CHAR_PER_LINE));
            return 1;
        }
        // nothing to draw for this line
        return 0;
    }
    return 1;
}

unsigned int ui_details_blue_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    return 0;
}

void ui_details_init(const char *title, const char *content,
                     callback_t back_callback) {
    ui_details_title = title;
    ui_details_content = content;
    ui_details_back_callback = back_callback;
    UX_DISPLAY(ui_details_blue, ui_details_blue_prepro);
}

const bagl_icon_details_t ui_blue_transaction_gif = {
    .bpp = GLYPH_badge_transaction_BPP,
    .colors = C_badge_transaction_colors,
    .bitmap = C_badge_transaction_bitmap,
};

void ui_transaction_blue_init(void);

bagl_element_callback_t ui_transaction_blue_ok;
bagl_element_callback_t ui_transaction_blue_cancel;

const bagl_element_t *ui_transaction_blue_ok_callback(const bagl_element_t *e) {
    return ui_transaction_blue_ok(e);
}

const bagl_element_t *
ui_transaction_blue_cancel_callback(const bagl_element_t *e) {
    return ui_transaction_blue_cancel(e);
}

const bagl_element_t *
ui_transaction_blue_amount_details(const bagl_element_t *e) {
    if (strlen(fullAmount) * BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
        160) {
        // display details screen
        ui_details_init("AMOUNT", fullAmount, ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t *
ui_transaction_blue_address_details(const bagl_element_t *e) {
    if (strlen(fullAddress) * BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
        160) {
        ui_details_init(addressSummary, fullAddress, ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t *
ui_transaction_blue_fees_details(const bagl_element_t *e) {
    if (strlen(feesAmount) * BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
        160) {
        ui_details_init("FEES", feesAmount, ui_transaction_blue_init);
    }
    return 0;
};

const bagl_element_t ui_transaction_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM TRANSACTION",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //io_seproxyhal_touch_exit, NULL, NULL},

    // BADGE_TRANSACTION.GIF
    {{BAGL_ICON, 0x00, 30, 98, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &ui_blue_transaction_gif,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 100, 117, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     "Transaction details",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 100, 138, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, 0},
     "Check and confirm values",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 196, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "AMOUNT",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x01, 130, 200, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_RIGHT,
      0},
     fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x11, 284, 196, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 168, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_amount_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x11, 0, 168, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 30, 216, 260, 1, 1, 0, 0, 0xEEEEEE, COLOR_BG_1, 0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 245, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x02, 130, 245, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 284, 245, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 217, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_address_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x12, 0, 217, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 30, 265, 260, 1, 1, 0, 0, 0xEEEEEE, COLOR_BG_1, 0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 294, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "FEES",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x03, 130, 294, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x13, 284, 294, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 266, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_fees_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x13, 0, 266, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 40, 414, 115, 36, 0, 18,
      BAGL_FILL, 0xCCCCCC, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "REJECT",
     0,
     0xB7B7B7,
     COLOR_BG_1,
     ui_transaction_blue_cancel_callback,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 165, 414, 115, 36, 0, 18,
      BAGL_FILL, 0x41ccb4, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x3ab7a2,
     COLOR_BG_1,
     ui_transaction_blue_ok_callback,
     NULL,
     NULL},
};

const bagl_element_t *
ui_transaction_blue_prepro(const bagl_element_t *element) {
    // none elements are skipped
    if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
        return 0;
    } else {
        switch (element->component.userid) {
        case 0x01:
            if (strlen(fullAmount) *
                    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
                160) {
                os_memmove(&tmp_element, element, sizeof(bagl_element_t));
                tmp_element.component.x -= 18;
                return &tmp_element;
            }
            break;
        case 0x11:
            return strlen(fullAmount) *
                       BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
                   160;

        case 0x02:
            if (strlen(fullAddress) *
                    BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
                160) {
                os_memmove(&tmp_element, element, sizeof(bagl_element_t));
                tmp_element.component.x -= 18;
                return &tmp_element;
            }
            break;
        case 0x12:
            return strlen(fullAddress) *
                       BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
                   160;

        case 0x03:
            if (strlen(feesAmount) *
                    BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
                160) {
                os_memmove(&tmp_element, element, sizeof(bagl_element_t));
                tmp_element.component.x -= 18;
                return &tmp_element;
            }
            break;
        case 0x13:
            return strlen(feesAmount) *
                       BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
                   160;
        }
    }
    return 1;
}
unsigned int ui_transaction_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}
#endif // #if TARGET_ID == 0x31000002

#if TARGET_ID == 0x31100002

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

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x04, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Fees",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x04, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_verify_nanos_button(unsigned int button_mask,
                                    unsigned int button_mask_counter);

const bagl_element_t ui_verify_output_nanos[] = {
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

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x03, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x03, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     addressSummary,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL}};
unsigned int ui_verify_output_nanos_button(unsigned int button_mask,
                                           unsigned int button_mask_counter);

const bagl_element_t ui_finalize_nanos[] = {
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

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Fees",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     feesAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_finalize_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter);

// display or not according to step, and adjust delay
unsigned int ui_verify_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 3:
                UX_CALLBACK_SET_INTERVAL(3000);
                break;
            case 4:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_verify_output_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 3:
                UX_CALLBACK_SET_INTERVAL(3000);
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_finalize_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
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

    //{{BAGL_ICON                           , 0x01,  28,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Sign the",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
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
            UX_CALLBACK_SET_INTERVAL(2000);
            break;
        case 2:
            UX_CALLBACK_SET_INTERVAL(3000);
            break;
        }
        return (ux_step == element->component.userid - 1);
    }
    return 1;
}

const bagl_element_t ui_display_address_nanos[] = {
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

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 12, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // Hax, avoid wasting space
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     G_io_apdu_buffer + 200,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_display_address_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter);

unsigned int ui_display_address_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

#endif // #if TARGET_ID == 0x31100002

void ui_idle(void) {
    ux_step_count = 0;

#if TARGET_ID == 0x31000002
    UX_DISPLAY(ui_idle_blue, NULL);
#elif TARGET_ID == 0x31100002
    UX_MENU_DISPLAY(0, menu_main, NULL);
#endif // #if TARGET_ID
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // go back to the home screen
    os_sched_exit(0);
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_verify_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    if (!btchip_bagl_user_action(0)) {
        // redraw ui
        ui_idle();
    }
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_verify_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    if (!btchip_bagl_user_action(1)) {
        // redraw ui
        ui_idle();
    }
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

unsigned int io_seproxyhal_touch_display_cancel(const bagl_element_t *e) {
    // user denied the transaction, tell the USB side
    btchip_bagl_user_action_display(0);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

unsigned int io_seproxyhal_touch_display_ok(const bagl_element_t *e) {
    // user accepted the transaction, tell the USB side
    btchip_bagl_user_action_display(1);
    // redraw ui
    ui_idle();
    return 0; // DO NOT REDRAW THE BUTTON
}

#if TARGET_ID == 0x31100002
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

unsigned int ui_verify_output_nanos_button(unsigned int button_mask,
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

unsigned int ui_finalize_nanos_button(unsigned int button_mask,
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

unsigned int ui_display_address_nanos_button(unsigned int button_mask,
                                             unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_display_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_display_ok(NULL);
        break;
    }
    return 0;
}

#endif // #if TARGET_ID == 0x31100002

#if TARGET_ID == 0x31000002
void ui_transaction_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    strcpy(addressSummary, "ADDRESS");
    UX_DISPLAY(ui_transaction_blue, ui_transaction_blue_prepro);
}

void ui_message_signature_blue_init(void) {
    ui_transaction_blue_ok = (bagl_element_callback_t)
        io_seproxyhal_touch_message_signature_verify_ok;
    ui_transaction_blue_cancel = (bagl_element_callback_t)
        io_seproxyhal_touch_message_signature_verify_cancel;
    snprintf(fullAddress, 65, "%.*H", 32, fullAmount);
    strcpy(fullAmount, "SIGNATURE");
    strcpy(feesAmount, "SIGNATURE");
    strcpy(addressSummary, "HASH");
    UX_DISPLAY(ui_transaction_blue, ui_transaction_blue_prepro);
}

void ui_transaction_p2sh_blue_init(void) {
    ui_transaction_blue_ok =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_ok;
    ui_transaction_blue_cancel =
        (bagl_element_callback_t)io_seproxyhal_touch_verify_cancel;
    strcpy(fullAmount, "P2SH");
    strcpy(fullAddress, "P2SH");
    strcpy(feesAmount, "P2SH");
    strcpy(addressSummary, "ADDRESS");
    UX_DISPLAY(ui_transaction_blue, ui_transaction_blue_prepro);
}
#endif // #if TARGET_ID == 0x31000002

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

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // don't redisplay if UX not allowed (pin locked in the common bolos
            // ux ?)
            if (ux_step_count && UX_ALLOWED) {
                // prepare next screen
                ux_step = (ux_step + 1) % ux_step_count;
                // redisplay screen
                UX_REDISPLAY();
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

uint8_t prepare_fees() {
    if (btchip_context_D.transactionContext.relaxed) {
        os_memmove(feesAmount, "UNKNOWN", 7);
        feesAmount[7] = '\0';
    } else {
        unsigned char fees[8];
        unsigned short textSize;
        if (transaction_amount_sub_be(
                fees, btchip_context_D.transactionContext.transactionAmount,
                btchip_context_D.totalOutputAmount)) {
            PRINTF("Error : Fees not consistent");
            goto error;
        }
        os_memmove(feesAmount, btchip_context_D.shortCoinId,
                   btchip_context_D.shortCoinIdLength);
        feesAmount[btchip_context_D.shortCoinIdLength] = ' ';
        btchip_context_D.tmp =
            (unsigned char *)(feesAmount + btchip_context_D.shortCoinIdLength +
                              1);
        textSize = btchip_convert_hex_amount_to_displayable(fees);
        feesAmount[textSize + btchip_context_D.shortCoinIdLength + 1] = '\0';
    }
    return 1;
error:
    return 0;
}

uint8_t prepare_single_output() {
    // TODO : special display for OP_RETURN
    unsigned char amount[8];
    char tmp[40];
    unsigned int offset = 0;
    unsigned char versionSize;
    int addressOffset;
    unsigned char address[22];
    unsigned short version;
    unsigned short textSize;

    btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
    offset += 8;
    if (btchip_output_script_is_op_return(btchip_context_D.currentOutput +
                                          offset)) {
        os_memmove(addressSummary, "OP_RETURN", 9);
        os_memmove(fullAddress, "OP_RETURN", 9);
        addressSummary[10] = '\0';
        fullAddress[10] = '\0';
        fullAmount[0] = '\0';
        return 1;
    } else if (btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                               offset)) {
        addressOffset = offset + 4;
        version = btchip_context_D.payToAddressVersion;
    } else {
        addressOffset = offset + 3;
        version = btchip_context_D.payToScriptHashVersion;
    }
    if (version > 255) {
        versionSize = 2;
        address[0] = (version >> 8);
        address[1] = version;
    } else {
        versionSize = 1;
        address[0] = version;
    }
    os_memmove(address + versionSize,
               btchip_context_D.currentOutput + addressOffset, 20);

    // Prepare address
    textSize = btchip_public_key_to_encoded_base58(address, 20 + versionSize,
                                                   (unsigned char *)tmp,
                                                   sizeof(tmp), version, 1);
    tmp[textSize] = '\0';

#if TARGET_ID == 0x31000002
    os_memmove(fullAddress, tmp, textSize + 1);
#endif

    os_memset(addressSummary, 0, sizeof(addressSummary));
    os_memmove((void *)addressSummary, tmp, 5);
    os_memmove((void *)(addressSummary + 5), "...", 3);
    os_memmove((void *)(addressSummary + 8), tmp + strlen(tmp) - 4, 4);

    // Prepare amount

    os_memmove(fullAmount, btchip_context_D.shortCoinId,
               btchip_context_D.shortCoinIdLength);
    fullAmount[btchip_context_D.shortCoinIdLength] = ' ';
    btchip_context_D.tmp =
        (unsigned char *)(fullAmount + btchip_context_D.shortCoinIdLength + 1);
    textSize = btchip_convert_hex_amount_to_displayable(amount);
    fullAmount[textSize + btchip_context_D.shortCoinIdLength + 1] = '\0';

    return 1;
}

uint8_t prepare_full_output(uint8_t checkOnly) {
    unsigned int offset = 0;
    int numberOutputs;
    int i;
    unsigned int currentPos = 0;
    unsigned char amount[8], totalOutputAmount[8], fees[8];
    char tmp[40];
    unsigned char outputPos = 0, changeFound = 0;
    if (btchip_context_D.transactionContext.relaxed &&
        !btchip_context_D.transactionContext.consumeP2SH) {
        if (!checkOnly) {
            PRINTF("Error : Mixed inputs");
        }
        goto error;
    }
    if (btchip_context_D.transactionContext.consumeP2SH) {
        if (checkOnly) {
            goto error;
        }
        fullAmount[0] = '\0';
        feesAmount[0] = '\0';
        strcpy(addressSummary, "P2SH");
        return 1;
    }
    // Parse output, locate the change output location
    os_memset(totalOutputAmount, 0, sizeof(totalOutputAmount));
    numberOutputs = btchip_context_D.currentOutput[offset++];
    if (numberOutputs > 3) {
        if (!checkOnly) {
            PRINTF("Error : Too many outputs");
        }
        goto error;
    }
    for (i = 0; i < numberOutputs; i++) {
        unsigned char nullAmount = 1;
        unsigned int j;
        unsigned char isOpReturn, isP2sh;
        for (j = 0; j < 8; j++) {
            if (btchip_context_D.currentOutput[offset + j] != 0) {
                nullAmount = 0;
                break;
            }
        }
        btchip_swap_bytes(amount, btchip_context_D.currentOutput + offset, 8);
        transaction_amount_add_be(totalOutputAmount, totalOutputAmount, amount);
        offset += 8; // skip amount
        isOpReturn = btchip_output_script_is_op_return(
            btchip_context_D.currentOutput + offset);
        isP2sh = btchip_output_script_is_p2sh(btchip_context_D.currentOutput +
                                              offset);
        if (!btchip_output_script_is_regular(btchip_context_D.currentOutput +
                                             offset) &&
            !isP2sh && !(nullAmount && isOpReturn)) {
            if (!checkOnly) {
                PRINTF("Error : Unrecognized input script");
            }
            goto error;
        }
        if (btchip_context_D.tmpCtx.output.changeInitialized && !isOpReturn) {
            unsigned char addressOffset =
                (isP2sh ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH
                        : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
            if (os_memcmp(btchip_context_D.currentOutput + offset +
                              addressOffset,
                          btchip_context_D.tmpCtx.output.changeAddress + 1,
                          20) == 0) {
                if (changeFound) {
                    if (!checkOnly) {
                        PRINTF("Error : Multiple change output found");
                    }
                    goto error;
                }
                changeFound = 1;
            } else {
                outputPos = currentPos;
            }
        }
        offset += 1 + btchip_context_D.currentOutput[offset];
        currentPos++;
    }
    if (btchip_context_D.tmpCtx.output.changeInitialized && !changeFound) {
        if (!checkOnly) {
            PRINTF("Error : change output not found");
        }
        goto error;
    }
    if (transaction_amount_sub_be(
            fees, btchip_context_D.transactionContext.transactionAmount,
            totalOutputAmount)) {
        if (!checkOnly) {
            PRINTF("Error : Fees not consistent");
        }
        goto error;
    }
    if (!checkOnly) {
        // Format validation message
        currentPos = 0;
        offset = 1;
        btchip_context_D.tmp = (unsigned char *)tmp;
        for (i = 0; i < numberOutputs; i++) {
            if (!btchip_output_script_is_op_return(
                    btchip_context_D.currentOutput + offset + 8)) {
                unsigned char versionSize;
                int addressOffset;
                unsigned char address[22];
                unsigned short version;
                btchip_swap_bytes(amount,
                                  btchip_context_D.currentOutput + offset, 8);
                offset += 8;
                if (btchip_output_script_is_regular(
                        btchip_context_D.currentOutput + offset)) {
                    addressOffset = offset + 4;
                    version = btchip_context_D.payToAddressVersion;
                } else {
                    addressOffset = offset + 3;
                    version = btchip_context_D.payToScriptHashVersion;
                }
                if (version > 255) {
                    versionSize = 2;
                    address[0] = (version >> 8);
                    address[1] = version;
                } else {
                    versionSize = 1;
                    address[0] = version;
                }
                os_memmove(address + versionSize,
                           btchip_context_D.currentOutput + addressOffset, 20);
                if (currentPos == outputPos) {
                    unsigned short textSize;
                    // Prepare address
                    textSize = btchip_public_key_to_encoded_base58(
                        address, 20 + versionSize, (unsigned char *)tmp,
                        sizeof(tmp), version, 1);
                    tmp[textSize] = '\0';

#if TARGET_ID == 0x31000002
                    os_memmove(fullAddress, tmp, textSize + 1);
#endif

                    os_memset(addressSummary, 0, sizeof(addressSummary));
                    os_memmove((void *)addressSummary, tmp, 5);
                    os_memmove((void *)(addressSummary + 5), "...", 3);
                    os_memmove((void *)(addressSummary + 8),
                               tmp + strlen(tmp) - 4, 4);

                    // Prepare amount

                    os_memmove(fullAmount, btchip_context_D.shortCoinId,
                               btchip_context_D.shortCoinIdLength);
                    fullAmount[btchip_context_D.shortCoinIdLength] = ' ';
                    btchip_context_D.tmp =
                        (unsigned char *)(fullAmount +
                                          btchip_context_D.shortCoinIdLength +
                                          1);
                    textSize = btchip_convert_hex_amount_to_displayable(amount);
                    fullAmount[textSize + btchip_context_D.shortCoinIdLength +
                               1] = '\0';

                    // prepare fee display
                    os_memmove(feesAmount, btchip_context_D.shortCoinId,
                               btchip_context_D.shortCoinIdLength);
                    feesAmount[btchip_context_D.shortCoinIdLength] = ' ';
                    btchip_context_D.tmp =
                        (unsigned char *)(feesAmount +
                                          btchip_context_D.shortCoinIdLength +
                                          1);
                    textSize = btchip_convert_hex_amount_to_displayable(fees);
                    feesAmount[textSize + btchip_context_D.shortCoinIdLength +
                               1] = '\0';
                    break;
                }
            } else {
                offset += 8;
            }
            offset += 1 + btchip_context_D.currentOutput[offset];
            currentPos++;
        }
    }
    return 1;
error:
    return 0;
}

#define HASH_LENGTH 4
uint8_t prepare_message_signature() {
    cx_hash(&btchip_context_D.transactionHashAuthorization.header, CX_LAST,
            fullAmount, 0, fullAmount);

    array_hexstr(addressSummary, fullAmount, HASH_LENGTH / 2);
    addressSummary[HASH_LENGTH / 2 * 2] = '.';
    addressSummary[HASH_LENGTH / 2 * 2 + 1] = '.';
    addressSummary[HASH_LENGTH / 2 * 2 + 2] = '.';
    array_hexstr(addressSummary + HASH_LENGTH / 2 * 2 + 3,
                 fullAmount + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);
    return 1;
}

unsigned int btchip_bagl_confirm_full_output() {
    if (!prepare_full_output(0)) {
        return 0;
    }

#if TARGET_ID == 0x31000002
    ui_transaction_blue_init();
#elif TARGET_ID == 0x31100002
    ux_step = 0;
    ux_step_count = 4;
    UX_DISPLAY(ui_verify_nanos, ui_verify_prepro);
#endif // #if TARGET_ID
    return 1;
}

unsigned int btchip_bagl_confirm_single_output() {
// TODO : remove when supporting multi output
#if TARGET_ID == 0x31000002
    if (btchip_context_D.transactionContext.consumeP2SH) {
        ui_transaction_p2sh_blue_init();
        return 1;
    }
#endif

    if (!prepare_single_output()) {
        return 0;
    }

#if TARGET_ID == 0x31000002
    ui_transaction_blue_init();
#elif TARGET_ID == 0x31100002
    snprintf(fullAddress, sizeof(fullAddress), "output #%d",
             btchip_context_D.totalOutputs - btchip_context_D.remainingOutputs +
                 1);
    ux_step = 0;
    ux_step_count = 3;
    UX_DISPLAY(ui_verify_output_nanos, ui_verify_output_prepro);
#endif // #if TARGET_ID
    return 1;
}

unsigned int btchip_bagl_finalize_tx() {
    if (!prepare_fees()) {
        return 0;
    }

#if TARGET_ID == 0x31000002

#error "TODO BLUE FINALIZE TX"

    ui_transaction_blue_init();
#elif TARGET_ID == 0x31100002
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_finalize_nanos, ui_finalize_prepro);
#endif // #if TARGET_ID
    return 1;
}

void btchip_bagl_confirm_message_signature() {
    if (!prepare_message_signature()) {
        return;
    }

#if TARGET_ID == 0x31000002
    ui_message_signature_blue_init();
#elif TARGET_ID == 0x31100002
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_verify_message_signature_nanos, ui_verify_message_prepro);
#endif // #if TARGET_ID
}

unsigned int btchip_bagl_display_public_key() {
#if TARGET_ID == 0x31000002

#error "TODO BLUE FINALIZE DISPLAY PUBLIC KEY"

#elif TARGET_ID == 0x31100002
    // append and prepend a white space to the address
    G_io_apdu_buffer[199] = ' ';
    strcat(G_io_apdu_buffer + 200, " ");
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_display_address_nanos, ui_display_address_prepro);
#endif // #if TARGET_ID
    return 1;
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

#ifdef HAVE_U2F
            os_memset((unsigned char *)&u2fService, 0, sizeof(u2fService));
            u2fService.inputBuffer = G_io_apdu_buffer;
            u2fService.outputBuffer = G_io_apdu_buffer;
            u2fService.messageBuffer = (uint8_t *)u2fMessageBuffer;
            u2fService.messageBufferSize = U2F_MAX_MESSAGE_SIZE;
            u2f_initialize_service((u2f_service_t *)&u2fService);

            USB_power_U2F(1, N_btchip.fidoTransport);
#else
            USB_power_U2F(1, 0);
#endif

#ifdef HAVE_BLE
            BLE_power(1, "Ledger Wallet");
#endif // HAVE_BLE

#if TARGET_ID == 0x31000002
            // setup the status bar colors (remembered after wards, even more if
            // another app does not resetup after app switch)
            UX_SET_STATUS_BAR_COLOR(0xFFFFFF, COLOR_APP);
#endif // TARGET_ID

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
