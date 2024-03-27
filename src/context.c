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

void autosetup(void);

/**
 * Initialize the application context on boot
 */
void context_init() {
    PRINTF("Context init\n");
    PRINTF("Backup size %d\n", sizeof(N_btchip.bkp));
    memset(&context_D, 0, sizeof(context_D));
    SB_SET(context_D.halted, 0);
    context_D.called_from_swap = 0;
    context_D.currentOutputOffset = 0;
    context_D.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
    memset(context_D.totalOutputAmount, 0,
              sizeof(context_D.totalOutputAmount));
    context_D.changeOutputFound = 0;
    context_D.segwitWarningSeen = 0;

    if (N_btchip.config_valid != 0x01) {
        autosetup();
    }

    if (!N_btchip.config_valid) {
        unsigned char defaultMode;
        PRINTF("No configuration found\n");
        defaultMode = MODE_SETUP_NEEDED;

        set_operation_mode(defaultMode);
    } else {
        SB_CHECK(N_btchip.bkp.config.operationMode);
    }
    if (!N_btchip.storageInitialized) {
        unsigned char initialized = 1, denied=1;

        nvm_write((void *)&N_btchip.pubKeyRequestRestriction, &denied, 1);
        nvm_write((void *)&N_btchip.storageInitialized, &initialized, 1);
    }
}
