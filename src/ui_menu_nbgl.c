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
#include "btchip_display_variables.h"
#include "btchip_internal.h"
#include "ui.h"

#include "btchip_bagl_extensions.h"
#include "nbgl_use_case.h"

#define NB_INFO_FIELDS 2
#define PAGE_START 0
#define NB_PAGE_SETTING 2
#define IS_TOUCHABLE false

#define NB_SETTINGS_SWITCHES 1
#define SWITCH_PUBLIC_KEY_SET_TOKEN FIRST_USER_TOKEN

#define SETTING_INFO_NB 2
static const char *const infoTypes[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const infoContents[SETTING_INFO_NB] = {APPVERSION, "Ledger"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = infoTypes,
    .infoContents = infoContents,
};

static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES];

static void settings_control_cb(int token, uint8_t index, int page);

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = NB_SETTINGS_SWITCHES,
     .content.switchesList.switches = switches,
     .contentActionCallback = settings_control_cb}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void quit_cb(void) {
    os_sched_exit(-1);
}

static void switch_public_key(void) {
  uint8_t value = (N_btchip.pubKeyRequestRestriction != 0 ? 0 : 1);
  nvm_write((void *)&N_btchip.pubKeyRequestRestriction, &value, 1);
  switches[0].initState = value;
}

static void settings_control_cb(int token, uint8_t index, int page) {
  UNUSED(index);
  UNUSED(page);
  switch (token) {
  case SWITCH_PUBLIC_KEY_SET_TOKEN:
    switch_public_key();
    break;

  default:
    PRINTF("Should not happen !");
    break;
  }
}

void ui_idle_flow(void) {
  switches[0].text = "Public key export";
  switches[0].subText = "Auto / manual export mode";
  switches[0].token = SWITCH_PUBLIC_KEY_SET_TOKEN;
  switches[0].tuneId = TUNE_TAP_CASUAL;
  switches[0].initState = N_btchip.pubKeyRequestRestriction;

  nbgl_useCaseHomeAndSettings(APPNAME,
                              &C_zcash_64px,
                              NULL,
                              INIT_HOME_PAGE,
                              &settingContents,
                              &infoList,
                              NULL,
                              quit_cb);
}
#endif // HAVE_NBGL
