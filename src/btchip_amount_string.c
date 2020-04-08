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

#include "btchip_internal.h"

#define MAX_DECIMALS 20
#define SATOSHIS_PER_BTC 100000000

static uint64_t readUint64BE(uint8_t *buffer) {
    return (((uint64_t)buffer[0]) << 56) | (((uint64_t)buffer[1]) << 48) |
           (((uint64_t)buffer[2]) << 40) | (((uint64_t)buffer[3]) << 32) |
           (((uint64_t)buffer[4]) << 24) | (((uint64_t)buffer[5]) << 16) |
           (((uint64_t)buffer[6]) << 8) | (((uint64_t)buffer[7]));
}

static char* print_uint64(uint64_t value, char *output) {
    char *current = output + 20;
    *current = '\0';
    do {
        uint32_t digit = value % 10;
        *current--;
        *current = '0' + digit;
        value = value / 10;
    } while (value != 0);
    return current;
}

int btchip_convert_amount_string(uint8_t *amountBuffer, uint8_t decimals, unsigned char *output, size_t outputSize) {
    char quotientBuffer[21], remainderBuffer[21];
    char *q, *r, *tmp;
    uint64_t tenPow = 1, amount = readUint64BE(amountBuffer);
    uint8_t padSize, extraSize = 0, tmpDecimals;    
    if ((output == NULL) || (decimals > MAX_DECIMALS)) {
        return -1;
    }
    if (decimals == 8) {
        tenPow = SATOSHIS_PER_BTC;
    }
    else {
        tmpDecimals = decimals;
        while (tmpDecimals != 0) {
            tenPow *= 10;
            tmpDecimals--;
        }
    }
    q = print_uint64(amount / tenPow, quotientBuffer);
    if (decimals == 0) {
        if (outputSize < strlen(q)) {
            return -1;
        }
        strcpy(output, q);
        return 0;
    }
    r = print_uint64(amount % tenPow, remainderBuffer);
    padSize = decimals - strlen(r);
    tmp = r + strlen(r) - 1;
    while ((*tmp == '0') && (tmp >= r)) {
        tmp--;
    }
    if (tmp >= r) {
        tmp[1] = 0;
        extraSize = strlen(tmp) + 1;
    }
    if (outputSize < strlen(q) + padSize + extraSize) {
        return -1;
    }
    strcpy(output, q);
    tmp = output + strlen(output);
    if (extraSize != 0) {
        uint8_t i;
        *(tmp++) = '.';
        for (i=0; i<padSize; i++) {
            *(tmp++) = '0';
        }
        *tmp = 0;
        strcat(output, r);
    }
    return 0;
}

