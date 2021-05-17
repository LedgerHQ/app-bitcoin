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

#ifndef BTCHIP_FS_TX_H

#define BTCHIP_FS_TX_H

#include "os.h"

#define MAX_BIP32_PATH 10
#define MAX_BIP32_PATH_LENGTH (4 * MAX_BIP32_PATH) + 1
#define BIP44_PATH_LEN 5
#define BIP44_PURPOSE_OFFSET 0
#define BIP44_COIN_TYPE_OFFSET 1
#define BIP44_ACCOUNT_OFFSET 2
#define BIP44_CHANGE_OFFSET 3
#define BIP44_ADDRESS_INDEX_OFFSET 4
#define MAX_BIP44_ACCOUNT_RECOMMENDED 100
#define MAX_BIP44_ADDRESS_INDEX_RECOMMENDED 50000

struct btchip_transaction_summary_s {
    unsigned char active;
    unsigned char payToAddressVersion;
    unsigned char payToScriptHashVersion;
    unsigned char authorizationHash[32];
    unsigned char keyPath[MAX_BIP32_PATH_LENGTH];
    unsigned char transactionNonce[8]; // used to bind to the current set of inputs
    unsigned short messageLength;
    unsigned char sighashType;
};
typedef struct btchip_transaction_summary_s btchip_transaction_summary_t;

#endif
