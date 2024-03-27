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

#include "internal.h"
#include "apdu_constants.h"

#define P1_GET_OPERATION_MODE 0x00
#define P1_GET_SECOND_FACTOR_MODE 0x01

unsigned short apdu_get_operation_mode() {
    SB_CHECK(N_btchip.bkp.config.operationMode);
    if ((SB_GET(N_btchip.bkp.config.operationMode) ==
         MODE_SETUP_NEEDED) ||
        (SB_GET(N_btchip.bkp.config.operationMode) == MODE_ISSUER)) {
        return SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    switch (G_io_apdu_buffer[ISO_OFFSET_P1]) {
    case P1_GET_OPERATION_MODE:
        G_io_apdu_buffer[0] = SB_GET(N_btchip.bkp.config.operationMode);
        break;

    default:
        return SW_INCORRECT_P1_P2;
    }

    context_D.outLength = 1;

    return SW_OK;
}
