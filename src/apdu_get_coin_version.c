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

#define P1_VERSION_ONLY 0x00
#define P1_VERSION_COINID 0x01

unsigned short apdu_get_coin_version() {
    uint8_t offset = 0;

    G_io_apdu_buffer[offset++] = COIN_P2PKH_VERSION >> 8;
    G_io_apdu_buffer[offset++] = COIN_P2PKH_VERSION;
    G_io_apdu_buffer[offset++] = COIN_P2SH_VERSION >> 8;
    G_io_apdu_buffer[offset++] = COIN_P2SH_VERSION;
    G_io_apdu_buffer[offset++] = COIN_FAMILY;
    G_io_apdu_buffer[offset++] = strlen(COIN_COINID);
    memmove(G_io_apdu_buffer + offset, COIN_COINID,
               strlen(COIN_COINID));
    offset += strlen(COIN_COINID);
    G_io_apdu_buffer[offset++] = strlen(COIN_COINID_SHORT);
    memmove(G_io_apdu_buffer + offset, COIN_COINID_SHORT,
               strlen(COIN_COINID_SHORT));
    offset += strlen(COIN_COINID_SHORT);
    context_D.outLength = offset;

    return SW_OK;
}
