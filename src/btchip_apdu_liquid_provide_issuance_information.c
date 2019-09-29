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

#define ISSUANCE_P1_MORE 0x00
#define ISSUANCE_P1_LAST 0x80

unsigned short btchip_apdu_liquid_provide_issuance_information() {
	unsigned char apduLength;
	unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];

	apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

	if ((p1 != ISSUANCE_P1_MORE) && (p1 != ISSUANCE_P1_LAST)) {
		return BTCHIP_SW_INCORRECT_P1_P2;
	}
	if (btchip_context_D.transactionContext.transactionState != BTCHIP_TRANSACTION_WAIT_LIQUID_ISSUANCE) {
		return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
	}

	cx_hash(&btchip_context_D.transactionHashFull.sha256.header,
		(p1 == ISSUANCE_P1_LAST ? CX_LAST : 0),
		G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength,
		btchip_context_D.segwit.cache.hashedIssuance, 32);

	if (p1 == ISSUANCE_P1_LAST) {
		cx_sha256_init(&btchip_context_D.transactionHashFull.sha256);
		cx_hash(&btchip_context_D.transactionHashFull.sha256.header,
			CX_LAST,
			btchip_context_D.segwit.cache.hashedIssuance,
			sizeof(btchip_context_D.segwit.cache.hashedIssuance),
			btchip_context_D.segwit.cache.hashedIssuance, 32);
		btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_NONE;
	}

	return BTCHIP_SW_OK;
}
