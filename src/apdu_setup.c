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

unsigned short apdu_setup() {
    return SW_INS_NOT_SUPPORTED;
}

// Setup with WALLET mode only, deterministic signatures only
void autosetup() {
    config_t config;
    unsigned char i;
    unsigned char tmp[32];
    memset(&config, 0, sizeof(config_t));
    config.options |= OPTION_DETERMINISTIC_SIGNATURE;
    config.options |= OPTION_SKIP_2FA_P2SH; // TODO : remove when
                                                   // supporting multi output
    SB_SET(config.supportedModes, MODE_WALLET);
    SB_SET(config.operationMode, MODE_WALLET);

    nvm_write((void *)&N_btchip.bkp.config, &config, sizeof(config));
    cx_rng(tmp, sizeof(tmp));
    nvm_write((void *)&N_btchip.bkp.trustedinput_key, tmp, sizeof(tmp));
    i = 1;
    nvm_write((void *)&N_btchip.config_valid, &i, 1);
}
