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
#include "display_variables.h"
#include "ui.h"

#include "extensions.h"
#include "nbgl_use_case.h"

#define SETTING_INFO_NB 3
static const char *const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer",
                                                        "Copyright"};
static const char *const INFO_CONTENTS[SETTING_INFO_NB] = {
    APPVERSION, APPDEVELOPPER, APPCOPYRIGHT};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static void exit(void) { os_sched_exit(-1); }

void ui_idle_flow(void) {
  nbgl_useCaseHomeAndSettings(COIN_COINID_NAME, &COIN_ICON, NULL,
                              INIT_HOME_PAGE, NULL, &infoList, NULL, exit);
}
#endif // HAVE_NBGL
