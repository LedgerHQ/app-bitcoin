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

#include "context.h"
#include "filesystem.h"

context_t context;
storage_t const N_real;

/**
 * Initialize the application context on boot
 */
void context_init() {
    PRINTF("Context init\n");
    PRINTF("Backup size %d\n", sizeof(g_nvram_data.bkp));
    memset(&context, 0, sizeof(context));
    context.currentOutputOffset = 0;
    context.outputParsingState = OUTPUT_PARSING_NUMBER_OUTPUTS;
    memset(context.totalOutputAmount, 0,
              sizeof(context.totalOutputAmount));
    context.changeOutputFound = 0;
    context.segwitWarningSeen = 0;
}

