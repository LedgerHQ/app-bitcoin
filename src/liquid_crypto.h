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

#ifndef _LIQUID_CRYPTO_H__
#define _LIQUID_CRYPTO_H__

#include <stdint.h>

int liquid_crypto_pedersen_commit(const uint8_t *blindingFactor, const uint8_t *value64BE, const uint8_t *generator, uint8_t *output);
int liquid_crypto_generator_tweak_full(const unsigned char *generator, const unsigned char *blindingFactor, unsigned char *output, unsigned char *tmp65); 
void liquid_crypto_generator_compress(unsigned char *generator);

void liquid_crypto_test(void);

#endif
