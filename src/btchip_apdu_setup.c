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

unsigned short btchip_apdu_setup() {
    return BTCHIP_SW_INS_NOT_SUPPORTED;
}

// Setup with WALLET mode only, deterministic signatures only
void btchip_autosetup() {
    btchip_config_t config;
    unsigned char i;
    cx_des_key_t desKey;
    unsigned char tmp[16];
    os_memset(&config, 0, sizeof(btchip_config_t));
    config.options |= BTCHIP_OPTION_DETERMINISTIC_SIGNATURE;
    SB_SET(config.supportedModes, BTCHIP_MODE_WALLET);
    SB_SET(config.operationMode, BTCHIP_MODE_WALLET);
#ifdef HAVE_DEFAULT_TESTNET
    config.payToAddressVersion = 111;
    config.payToScriptHashVersion = 196;
#else
    config.payToAddressVersion = 0;
    config.payToScriptHashVersion = 5;
#endif
    nvm_write((void *)&N_btchip.bkp.config, &config, sizeof(config));
    cx_rng(tmp, sizeof(tmp));
    cx_des_init_key(tmp, sizeof(tmp), &desKey);
    nvm_write((void *)&N_btchip.bkp.trustedinput_key, &desKey, sizeof(desKey));
    i = 1;
    nvm_write((void *)&N_btchip.config_valid, &i, 1);
}
