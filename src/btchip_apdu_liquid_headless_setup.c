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

#ifdef HAVE_LIQUID_HEADLESS

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"
#include "headless_storage.h"

unsigned short btchip_apdu_liquid_headless_setup() {
	bool keySet = false;
	cx_ecfp_public_key_t publicKey;

	if ((G_io_apdu_buffer[ISO_OFFSET_P1] != 0) || (G_io_apdu_buffer[ISO_OFFSET_P2] != 0)) {
		return BTCHIP_SW_INCORRECT_P1_P2;
	}

	if (G_io_apdu_buffer[ISO_OFFSET_LC] != 65) {
		return BTCHIP_SW_INCORRECT_LENGTH;
	}

	if (N_storage.headless) {
		return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
	}

	BEGIN_TRY {
		TRY {
			cx_ecfp_init_public_key(CX_CURVE_256K1, G_io_apdu_buffer + ISO_OFFSET_CDATA, 65, &publicKey);
			keySet = true;
		}
		CATCH(INVALID_PARAMETER) {			
		}
		FINALLY {			
		}
	}
	END_TRY;

	if (!keySet) {
		return BTCHIP_SW_INCORRECT_DATA;
	}

	os_memmove(G_io_apdu_buffer + 150, G_io_apdu_buffer + ISO_OFFSET_CDATA, 65);
	snprintf(G_io_apdu_buffer, 150, "%.*H", 65, G_io_apdu_buffer + 150);		
	btchip_context_D.outLength = 130;

	btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
	btchip_bagl_liquid_display_headless_authorization_key();

	return BTCHIP_SW_OK;
}

#endif
