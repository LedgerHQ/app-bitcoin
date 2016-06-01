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

// TODO BAGL : change logic - display each part, approve, sign.
// TODO 1.0.2 : report logic

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define P1_PREPARE 0x00
#define P1_SIGN 0x80

//#define MAX_MESSAGE_SIZE 140

#define BITID_NONE 0
#define BITID_POWERCYCLE 1
#define BITID_MULTIPLE 2

#define SLIP_13 0x8000000D

unsigned char checkBitId(unsigned char *bip32Path) {
    unsigned char i;
    unsigned char bip32PathLength = bip32Path[0];
    bip32Path++;
    if ((bip32PathLength != 0) &&
        (btchip_read_u32(bip32Path, 1, 0) == SLIP_13)) {
        return BITID_MULTIPLE;
    }
    for (i = 0; i < bip32PathLength; i++) {
        unsigned short account = btchip_read_u32(bip32Path, 1, 0);
        bip32Path += 4;

        if (account == BITID_DERIVE) {
            return BITID_POWERCYCLE;
        }
        if (account == BITID_DERIVE_MULTIPLE) {
            return BITID_MULTIPLE;
        }
    }
    return BITID_NONE;
}

unsigned short btchip_apdu_sign_message() {
    return BTCHIP_SW_INS_NOT_SUPPORTED;
}
