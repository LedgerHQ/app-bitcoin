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

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

unsigned short btchip_apdu_set_alternate_coin_version() {
    if (G_io_apdu_buffer[ISO_OFFSET_LC] != 0x02) {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }

    SB_CHECK(N_btchip.bkp.config.operationMode);
    if ((SB_GET(N_btchip.bkp.config.operationMode) ==
         BTCHIP_MODE_SETUP_NEEDED) ||
        (SB_GET(N_btchip.bkp.config.operationMode) == BTCHIP_MODE_ISSUER)) {
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (!os_global_pin_is_validated()) {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    btchip_context_D.payToAddressVersion = G_io_apdu_buffer[ISO_OFFSET_CDATA];
    btchip_context_D.payToScriptHashVersion =
        G_io_apdu_buffer[ISO_OFFSET_CDATA + 1];

    return BTCHIP_SW_OK;
}
