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

#ifdef HAVE_LIQUID

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define P1_ABF 0x01
#define P1_VBF 0x02
#define P1_BLINDING_KEY 0x03

unsigned short btchip_apdu_liquid_get_blinding_factor() {
        uint8_t p1 = G_io_apdu_buffer[ISO_OFFSET_P1];

        if ((p1 != P1_ABF) && (p1 != P1_VBF) && (p1 != P1_BLINDING_KEY)) {
            return BTCHIP_SW_INCORRECT_P1_P2;
        }

        if (((p1 == P1_ABF) || (p1 == P1_VBF)) && (G_io_apdu_buffer[ISO_OFFSET_LC] < 4)) {
            return BTCHIP_SW_INCORRECT_LENGTH;                        
        }

        if (btchip_context_D.transactionContext.transactionState != BTCHIP_TRANSACTION_PRESIGN_READY) {
            return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        }

        if ((p1 == P1_ABF) || (p1 == P1_VBF)) {
            uint32_t outputIndex;
            outputIndex = btchip_read_u32(G_io_apdu_buffer + ISO_OFFSET_CDATA, 1, 0);
            btchip_derive_abf_vbf(outputIndex, (p1 == P1_ABF), G_io_apdu_buffer);    
        }
        else {
            btchip_derive_tx_blinding_key(G_io_apdu_buffer);
        }

        btchip_context_D.outLength = 32;

        return BTCHIP_SW_OK;
}

#endif

