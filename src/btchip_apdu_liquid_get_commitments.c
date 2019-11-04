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

#define P1_GENERATE_ALL 0x01
#define P1_USE_VBF 0x02

unsigned short btchip_apdu_liquid_get_commitments() {
        uint8_t assetTag[32];
        uint8_t value[8];
        uint32_t outputIndex;
        uint8_t abf[32];
        uint8_t vbf[32];        
        uint8_t generator[65];
        uint8_t commitment[33];
        uint8_t p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
        uint8_t assetIndex;
        uint8_t offset = 0;

        if ((p1 != P1_GENERATE_ALL) && (p1 != P1_USE_VBF)) {
            return BTCHIP_SW_INCORRECT_P1_P2;
        }

        if (btchip_context_D.transactionContext.transactionState != BTCHIP_TRANSACTION_PRESIGN_READY) {
            return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        }

        if (G_io_apdu_buffer[ISO_OFFSET_LC] != 32 + 8 + 4 + (p1 == P1_USE_VBF ? 32 : 0)) {
            return BTCHIP_SW_INCORRECT_LENGTH;            
        }

        os_memmove(assetTag, G_io_apdu_buffer + ISO_OFFSET_CDATA, 32);

        for (assetIndex=0; assetIndex<NUM_LIQUID_ASSETS; assetIndex++) {
            if (os_memcmp(assetTag, LIQUID_ASSETS[assetIndex].tag, sizeof(assetTag)) == 0) {
                break;
            }
        }
        if (assetIndex == NUM_LIQUID_ASSETS) {
            return BTCHIP_SW_INCORRECT_DATA;
        }

        os_memmove(value, G_io_apdu_buffer + ISO_OFFSET_CDATA + 32, 8);
        outputIndex = btchip_read_u32(G_io_apdu_buffer + ISO_OFFSET_CDATA + 32 + 8, 1, 0);
        if (p1 == P1_USE_VBF) {
            os_memmove(vbf, G_io_apdu_buffer + ISO_OFFSET_CDATA + 32 + 8 + 4, 32);
        }
        else {
            btchip_derive_abf_vbf(outputIndex, false, vbf);
        }
        btchip_derive_abf_vbf(outputIndex, true, abf);
            
        liquid_crypto_generator_tweak_full(LIQUID_ASSETS[assetIndex].generator, abf, generator);
        liquid_crypto_pedersen_commit(vbf, value, generator, commitment);

        os_memmove(G_io_apdu_buffer + offset, abf, 32);
        offset += 32;
        os_memmove(G_io_apdu_buffer + offset, vbf, 32);
        offset += 32;
        G_io_apdu_buffer[offset++] = (p1 == P1_USE_VBF ? LIQUID_TRUSTED_COMMITMENT_FLAG_HOST_PROVIDED_VBF : 0);
        btchip_write_u32_be(G_io_apdu_buffer + offset, outputIndex);
        offset += 4;
        os_memmove(G_io_apdu_buffer + offset, generator, 65);
        liquid_crypto_generator_compress(G_io_apdu_buffer + offset);
        offset += 33;
        os_memmove(G_io_apdu_buffer + offset, commitment, 33);
        offset += 33;
        os_memmove(G_io_apdu_buffer + offset, assetTag, 32);
        offset += 32;
        os_memmove(G_io_apdu_buffer + offset, value, 8);
        offset += 8;

        cx_hmac_sha256(N_btchip.bkp.trustedinput_key, sizeof(N_btchip.bkp.trustedinput_key), 
                G_io_apdu_buffer + 64, offset - 64,
                G_io_apdu_buffer + offset, 32);

        btchip_context_D.outLength = offset + 32;

        return BTCHIP_SW_OK;
}

#endif

