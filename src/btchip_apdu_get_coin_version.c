/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define P1_VERSION_ONLY 0x00
#define P1_VERSION_COINID 0x01

unsigned short btchip_apdu_get_coin_version() {
    uint8_t offset = 0;

    SB_CHECK(N_btchip.bkp.config.operationMode);
    if ((SB_GET(N_btchip.bkp.config.operationMode) ==
         BTCHIP_MODE_SETUP_NEEDED) ||
        (SB_GET(N_btchip.bkp.config.operationMode) == BTCHIP_MODE_ISSUER)) {
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    G_io_apdu_buffer[offset++] = G_coin_config->p2pkh_version >> 8;
    G_io_apdu_buffer[offset++] = G_coin_config->p2pkh_version;
    G_io_apdu_buffer[offset++] = G_coin_config->p2sh_version >> 8;
    G_io_apdu_buffer[offset++] = G_coin_config->p2sh_version;
    G_io_apdu_buffer[offset++] = G_coin_config->family;
    G_io_apdu_buffer[offset++] = strlen(G_coin_config->coinid);
    os_memmove(G_io_apdu_buffer + offset, G_coin_config->coinid,
               strlen(G_coin_config->coinid));
    offset += strlen(G_coin_config->coinid);
    G_io_apdu_buffer[offset++] = strlen(G_coin_config->name_short);
    os_memmove(G_io_apdu_buffer + offset, G_coin_config->name_short,
               strlen(G_coin_config->name_short));
    offset += strlen(G_coin_config->name_short);
    btchip_context_D.outLength = offset;

    return BTCHIP_SW_OK;
}
