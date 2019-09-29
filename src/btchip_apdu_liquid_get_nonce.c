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
#include "btchip_apdu_constants.h"

unsigned short btchip_apdu_liquid_get_nonce() {
		uint8_t masterBlindingKey[65];
		cx_ecfp_private_key_t privateKey;

	  if (G_io_apdu_buffer[ISO_OFFSET_LC] < 65) {
	  	return BTCHIP_SW_INCORRECT_LENGTH;
	  }
		btchip_derive_master_blinding_key(masterBlindingKey);
		cx_hmac_sha256(masterBlindingKey, 32, 
			G_io_apdu_buffer + ISO_OFFSET_CDATA + 65, G_io_apdu_buffer[ISO_OFFSET_LC] - 65, 
			masterBlindingKey, sizeof(masterBlindingKey));
		cx_ecdsa_init_private_key(BTCHIP_CURVE, masterBlindingKey, 32, &privateKey);
		cx_ecdh(&privateKey, CX_ECDH_POINT, G_io_apdu_buffer + ISO_OFFSET_CDATA, 65, masterBlindingKey, sizeof(masterBlindingKey));
		btchip_compress_public_key_value(masterBlindingKey);
		cx_hash_sha256(masterBlindingKey, 33, masterBlindingKey, 32);
		cx_hash_sha256(masterBlindingKey, 32, G_io_apdu_buffer, 32);

		btchip_context_D.outLength = 32;
		return BTCHIP_SW_OK;
}
