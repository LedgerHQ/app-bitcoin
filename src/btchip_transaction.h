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

#ifndef _BTCHIP_TRANSACTION_H_
#define _BTCHIP_TRANSACTION_H_

#include "btchip_secure_value.h"

#define TRANSACTION_HASH_NONE 0x00
#define TRANSACTION_HASH_FULL 0x01
#define TRANSACTION_HASH_AUTHORIZATION 0x02
#define TRANSACTION_HASH_BOTH 0x03

#define PARSE_MODE_TRUSTED_INPUT 0x01
#define PARSE_MODE_SIGNATURE 0x02

#define TRUSTED_INPUT_SIZE   48
#define TRUSTED_INPUT_TOTAL_SIZE (TRUSTED_INPUT_SIZE + 8)

void transaction_parse(unsigned char parseMode);

// target = a + b
unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b);

// target = a - b
unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b);

#endif /* _BTCHIP_TRANSACTION_H_ */
