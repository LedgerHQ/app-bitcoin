/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2019 Ledger
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

#ifndef _LIQUID_ASSETS_H__
#define _LIQUID_ASSETS_H__

#include <stdint.h>

typedef struct assetDefinition_t {
    uint8_t tag[32];
    uint8_t generator[65]; // to be removed once seeded generators are supported
    uint8_t ticker[10];
    uint8_t decimals;
} assetDefinition_t;

#ifdef HAVE_LIQUID_TEST

#define NUM_LIQUID_ASSETS 8 

#else

#define NUM_LIQUID_ASSETS 6 

#endif

extern assetDefinition_t const LIQUID_ASSETS[NUM_LIQUID_ASSETS];

#endif

