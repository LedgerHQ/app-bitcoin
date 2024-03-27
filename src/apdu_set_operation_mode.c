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

// TODO BAGL : validate operation mode change

#include "internal.h"
#include "apdu_constants.h"

#define P1_DISABLE_KEYCARD 0x00
#define P1_ENABLE_KEYCARD 0x01
#define P1_ENABLE_KEYCARD_PERMANENTLY 0x02

unsigned short apdu_set_operation_mode() {
    unsigned char operationMode;

    if (G_io_apdu_buffer[ISO_OFFSET_LC] != 0x01) {
        return SW_INCORRECT_LENGTH;
    }

    SB_CHECK(N_btchip.bkp.config.operationMode);
    if ((SB_GET(N_btchip.bkp.config.operationMode) ==
         MODE_SETUP_NEEDED) ||
        (SB_GET(N_btchip.bkp.config.operationMode) == MODE_ISSUER)) {
        return SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }
    operationMode = G_io_apdu_buffer[ISO_OFFSET_CDATA];

    if (operationMode == MODE_WALLET) {
    }

    if (operationMode == SB_GET(N_btchip.bkp.config.operationMode)) {
        return SW_OK;
    }

    switch (operationMode) {
    case MODE_WALLET:
    case MODE_RELAXED_WALLET:
    case MODE_SERVER:
    case MODE_DEVELOPER:
        break;
    default:
        return SW_INCORRECT_DATA;
    }

    SB_CHECK(N_btchip.bkp.config.supportedModes);
    if ((SB_GET(N_btchip.bkp.config.supportedModes) & operationMode) == 0) {
        return SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    // commit new operation
    set_operation_mode(operationMode);

    return SW_OK;
}
