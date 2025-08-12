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
#include "display.h"
#include "menu.h"

#define SETTING_INFO_NB 3
static const char* const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer", "Copyright"};
static const char* const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, APP_DEVELOPER, "(c) 2026 Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

extern void app_exit(void);

void ui_menu_main(void) {
    nbgl_useCaseHomeAndSettings(
        APPNAME,
        &ICON_APP_HOME,
#ifdef SCREEN_SIZE_WALLET
        APP_DESCRIPTION,
#else
        NULL,
#endif
        INIT_HOME_PAGE,
        NULL,
        &infoList,
        NULL,
        app_exit);
}
