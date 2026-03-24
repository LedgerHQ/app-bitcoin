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

/* SDK headers */
#include "nbgl_use_case.h"

/* Local headers */
#include "app_settings.h"
#include "display.h"
#include "menu.h"

// Tokens for settings switches
enum {
    ALLOW_NONDEFAULT_SIGHASH_TOKEN = FIRST_USER_TOKEN,
};

#define SETTING_INFO_NB 3
static const char* const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer", "Copyright"};
static const char* const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Ledger", "(c) 2026 Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

// Settings switch descriptor (mutable so initState can be updated)
static nbgl_contentSwitch_t settingsSwitches[1];

// Saved settings page index, so we can restore it after a confirmation dialog
static uint8_t initSettingPage;

static void enable_sighash_choice_callback(bool confirm);
static void settings_controls_callback(int token, uint8_t index, int page);

static const nbgl_content_t settingsContentsList[] = {{
    .type = SWITCHES_LIST,
    .content.switchesList.nbSwitches = 1,
    .content.switchesList.switches = settingsSwitches,
    .contentActionCallback = settings_controls_callback,
}};

static const nbgl_genericContents_t settingsContents = {
    .callbackCallNeeded = false,
    .contentsList = settingsContentsList,
    .nbContents = 1,
};

extern void app_exit(void);

// Forward-declare so the confirmation callback can re-display the home/settings
void ui_menu_main(void);
void ui_menu_main_with_settings_page(uint8_t settingsPage);

// Callback for the "are you sure?" confirmation dialog when enabling non-standard sighash
static void enable_sighash_choice_callback(bool confirm) {
    if (confirm) {
        app_settings_set_allow_nondefault_sighash(true);
        settingsSwitches[0].initState = ON_STATE;
    }
    // Re-display the home + settings (returning to the settings page)
    ui_menu_main_with_settings_page(initSettingPage);
}

static void settings_controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);

    initSettingPage = page;

    if (token == ALLOW_NONDEFAULT_SIGHASH_TOKEN) {
        if (!app_settings_get_allow_nondefault_sighash()) {
            // About to enable: show a warning confirmation dialog
            nbgl_useCaseChoice(&ICON_APP_WARNING,
#ifdef SCREEN_SIZE_WALLET
                               "Non-standard sighash",
#else
                               "Sighash types",
#endif
                               "Are you sure to allow\nnon-standard signing rules?",
                               "I understand, enable",
                               "Cancel",
                               enable_sighash_choice_callback);
        } else {
            // Disabling: no confirmation needed
            app_settings_set_allow_nondefault_sighash(false);
            settingsSwitches[0].initState = OFF_STATE;
        }
    }
}

void ui_menu_main_with_settings_page(uint8_t settingsPage) {
    // Initialize settings switch state from NVRAM
    settingsSwitches[0] = (nbgl_contentSwitch_t) {
#ifdef SCREEN_SIZE_WALLET
        .text = "Non-standard sighash",
        .subText = "Allow non-standard signing rules with warning",
#else
        .text = "Sighash types",
        .subText = "Allow non-default sighash types",
#endif
        .initState = app_settings_get_allow_nondefault_sighash() ? ON_STATE : OFF_STATE,
        .token = ALLOW_NONDEFAULT_SIGHASH_TOKEN,
    };

    nbgl_useCaseHomeAndSettings(
#if BIP44_COIN_TYPE == 1
        "Bitcoin Testnet",
#else
        APPNAME,
#endif /* #if BIP44_COIN_TYPE == 1 */
        &ICON_APP_HOME,
#ifdef BITCOIN_RECOVERY
        "This is a recovery tool.\nNot for day-to-day operations!",
#elif BIP44_COIN_TYPE == 1 && defined(SCREEN_SIZE_WALLET)
        "This app enables signing\ntransactions on all the Bitcoin\ntest "
        "networks.",
#else
        NULL,
#endif /* #ifdef BITCOIN_RECOVERY */
        settingsPage,
        &settingsContents,
        &infoList,
        NULL,
        app_exit);
}

void ui_menu_main(void) {
    ui_menu_main_with_settings_page(INIT_HOME_PAGE);
}
