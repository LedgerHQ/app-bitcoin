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

unsigned short btchip_apdu_liquid_get_public_blinding_key() {
		cx_ecfp_private_key_t privateKey;
		cx_ecfp_public_key_t publicKey;

		BEGIN_TRY {
			TRY {
				btchip_derive_private_blinding_key(G_io_apdu_buffer + ISO_OFFSET_CDATA, G_io_apdu_buffer[ISO_OFFSET_LC], &privateKey);
				cx_ecfp_generate_pair(BTCHIP_CURVE, &publicKey, &privateKey, 1);
				memmove(G_io_apdu_buffer, publicKey.W, sizeof(publicKey.W));
				btchip_context_D.outLength = sizeof(publicKey.W);
			}
			FINALLY {
				memset(&privateKey, 0, sizeof(privateKey));
			}
		}
		END_TRY;

    return BTCHIP_SW_OK;
}

#endif

