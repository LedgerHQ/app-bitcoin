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

static char text[20];
static const char *const infoTypes[] = {"Version", "Developer"};
static const char *const infoContents[] = {APPVERSION, "Ledger"};

static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES];

static void quit_cb(void) {
    os_sched_exit(-1);
}

static void switch_public_key(void) {
  uint8_t value = (N_btchip.pubKeyRequestRestriction != 0 ? 0 : 1);
  nvm_write((void *)&N_btchip.pubKeyRequestRestriction, &value, 1);
}

static bool settings_navigation_cb(uint8_t page, nbgl_pageContent_t *content) {
  if (page == 0) {
    content->type = INFOS_LIST;
    content->infosList.nbInfos = NB_INFO_FIELDS;
    content->infosList.infoTypes = (const char **)infoTypes;
    content->infosList.infoContents = (const char **)infoContents;
  } else if (page == 1) {
    switches[0].text = "Public key export";
    switches[0].subText = "Auto / manual export mode";
    switches[0].token = SWITCH_PUBLIC_KEY_SET_TOKEN;
    switches[0].tuneId = TUNE_TAP_CASUAL;
    switches[0].initState = N_btchip.pubKeyRequestRestriction;

    content->type = SWITCHES_LIST;
    content->switchesList.nbSwitches = NB_SETTINGS_SWITCHES;
    content->switchesList.switches = (nbgl_layoutSwitch_t *)switches;
  } else {
    return false;
  }
  return true;
}

static void display_settings_menu(void);

static void settings_control_cb(int token, uint8_t index) {
  UNUSED(index);
  switch (token) {
  case SWITCH_PUBLIC_KEY_SET_TOKEN:
    switch_public_key();
    break;

  default:
    PRINTF("Should not happen !");
    break;
  }
}

static void display_settings_menu(void) {
  snprintf(text, sizeof(text), "%s settings", G_coin_config->name);

  nbgl_useCaseSettings(text, PAGE_START, NB_PAGE_SETTING, IS_TOUCHABLE,
                       ui_idle_flow, settings_navigation_cb,
                       settings_control_cb);
}

void ui_idle_flow(void) {
  nbgl_useCaseHome(G_coin_config->name, &G_coin_config->img_nbgl, NULL, true,
                   display_settings_menu, quit_cb);
}
#endif // HAVE_NBGL
