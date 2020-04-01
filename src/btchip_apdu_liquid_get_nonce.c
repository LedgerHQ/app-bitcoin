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

unsigned short btchip_apdu_liquid_get_nonce() {
		cx_ecfp_private_key_t privateKey;
		uint8_t tmp[65];

	  if (G_io_apdu_buffer[ISO_OFFSET_LC] < 65) {
	  	return BTCHIP_SW_INCORRECT_LENGTH;
	  }
	  BEGIN_TRY {
	  	TRY {
		  btchip_derive_private_blinding_key(G_io_apdu_buffer + ISO_OFFSET_CDATA + 65, G_io_apdu_buffer[ISO_OFFSET_LC] - 65, &privateKey);
			cx_ecdh(&privateKey, CX_ECDH_POINT, G_io_apdu_buffer + ISO_OFFSET_CDATA, 65, tmp, sizeof(tmp));
			btchip_compress_public_key_value(tmp);
			cx_hash_sha256(tmp, 33, tmp, 32);
			cx_hash_sha256(tmp, 32, G_io_apdu_buffer, 32);
	  	}
			FINALLY {
				memset(&privateKey, 0, sizeof(privateKey));
				memset(tmp, 0, sizeof(tmp));
			}	  	
	  }
	  END_TRY;

		btchip_context_D.outLength = 32;
		return BTCHIP_SW_OK;
}

#endif
