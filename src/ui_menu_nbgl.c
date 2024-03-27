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
#include "internal.h"
#include "ui.h"

#include "bagl_extensions.h"
#include "nbgl_use_case.h"

#define NB_INFO_FIELDS 2
#define PAGE_START 0
#define NB_PAGE_SETTING 1
#define IS_TOUCHABLE true

#define NB_SETTINGS_SWITCHES 1
#define SWITCH_PUBLIC_KEY_SET_TOKEN FIRST_USER_TOKEN

static char text[20];
static const char *const infoTypes[] = {"Version", "Developer"};
static const char *const infoContents[] = {APPVERSION, "Ledger"};

static void quit_cb(void) {
    os_sched_exit(-1);
}

static bool settings_navigation_cb(uint8_t page, nbgl_pageContent_t *content) {
  if (page == 0) {
    content->type = INFOS_LIST;
    content->infosList.nbInfos = NB_INFO_FIELDS;
    content->infosList.infoTypes = (const char **)infoTypes;
    content->infosList.infoContents = (const char **)infoContents;
  } else {
    return false;
  }
  return true;
}

static void display_settings_menu(void);

static void display_settings_menu(void) {
  snprintf(text, sizeof(text), "%s settings", COIN_COINID_NAME);

  nbgl_useCaseSettings(text, PAGE_START, NB_PAGE_SETTING, IS_TOUCHABLE,
                       ui_idle_flow, settings_navigation_cb,
                       NULL);
}

void ui_idle_flow(void) {
  nbgl_useCaseHome(COIN_COINID_NAME, &COIN_ICON, NULL, true,
                   display_settings_menu, quit_cb);
}
#endif // HAVE_NBGL
