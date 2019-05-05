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

#ifndef _BTCHIP_ROM_VARIABLES_
#define _BTCHIP_ROM_VARIABLES_

#include "btchip_internal.h"

#define SIGNMAGIC_LENGTH 17

extern unsigned char const HEXDIGITS[16];
extern unsigned char const BASE58TABLE[128];
extern unsigned char const BASE58ALPHABET[58];

extern unsigned char const SIGNMAGIC[SIGNMAGIC_LENGTH];

extern unsigned char const OVERWINTER_PARAM_PREVOUTS[16];
extern unsigned char const OVERWINTER_PARAM_SEQUENCE[16];
extern unsigned char const OVERWINTER_PARAM_OUTPUTS[16];
extern unsigned char const OVERWINTER_PARAM_SIGHASH[16];
extern unsigned char const OVERWINTER_NO_JOINSPLITS[32];

#define HDKEY_VERSION_LENGTH 4

extern unsigned char const TWOPOWER[8];

#define APDU_DEBUG_LENGTH 0

#define APDU_NFCPAYMENT_LENGTH 0

#define APDU_BIP70_LENGTH 0

#define APDU_MOFN_LENGTH 0

#define APDU_KEYCARD_LENGTH 0

#define APDU_PORTABLE_LENGTH 5

#define APDU_KEYBOARD_LENGTH 0

#define APDU_LEGACY_SETUP_LENGTH 0

#define APDU_DEVELOPER_MODE_LENGTH 0

#define APDU_BASE_LENGTH 13

#define DISPATCHER_APDUS 14

typedef unsigned short (*apduProcessingFunction)(void);

extern unsigned char const DISPATCHER_CLA[DISPATCHER_APDUS];
extern unsigned char const DISPATCHER_INS[DISPATCHER_APDUS];
extern unsigned char const DISPATCHER_DATA_IN[DISPATCHER_APDUS];
extern apduProcessingFunction const DISPATCHER_FUNCTIONS[DISPATCHER_APDUS];

#endif /* _BTCHIP_ROM_VARIABLES_ */