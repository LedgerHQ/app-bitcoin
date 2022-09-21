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

    G_io_apdu_buffer[offset++] = COIN_P2PKH_VERSION >> 8;
    G_io_apdu_buffer[offset++] = COIN_P2PKH_VERSION;
    G_io_apdu_buffer[offset++] = COIN_P2SH_VERSION >> 8;
    G_io_apdu_buffer[offset++] = COIN_P2SH_VERSION;
    G_io_apdu_buffer[offset++] = COIN_FAMILY;
    G_io_apdu_buffer[offset++] = sizeof(COIN_COINID) - 1;
    os_memmove(G_io_apdu_buffer + offset, COIN_COINID,
               sizeof(COIN_COINID) - 1);
    offset += sizeof(COIN_COINID) - 1;
    G_io_apdu_buffer[offset++] = sizeof(COIN_COINID_SHORT) - 1;
    os_memmove(G_io_apdu_buffer + offset, COIN_COINID_SHORT,
               sizeof(COIN_COINID_SHORT) - 1);
    offset += sizeof(COIN_COINID_SHORT) - 1;
    btchip_context_D.outLength = offset;

    return BTCHIP_SW_OK;
}
