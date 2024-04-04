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

#pragma once

#include "context.h"
#include "filesystem_tx.h"
#include "os.h"

enum family_e {
  FAMILY_BITCOIN = 0x01,
  FAMILY_PEERCOIN = 0x02,
  FAMILY_STEALTH = 0x04
};

typedef struct backup_area_s {
  uint8_t trustedinput_key[32];
} backup_area_t;

typedef struct storage_s {
  backup_area_t bkp;
} storage_t;

// the global nvram memory variable
extern storage_t const N_real;
#define g_nvram_data (*(volatile storage_t *)PIC(&N_real))
