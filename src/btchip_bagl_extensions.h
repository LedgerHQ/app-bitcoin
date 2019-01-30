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

#ifndef _BTCHIP_BAGL_H_
#define _BTCHIP_BAGL_H_

// btchip asking the legacy grouped UI
unsigned int btchip_bagl_confirm_full_output(void);

// btchip asking the per-output UI
unsigned int btchip_bagl_confirm_single_output(void);

// btchip display token
void btchip_bagl_display_token(void);

// btchip finalizing the transaction
unsigned int btchip_bagl_finalize_tx(void);

// UI response to btchip to finish the exchange
unsigned char btchip_bagl_user_action(unsigned char confirming);

// request the UI to redisplay the idle screen
void btchip_bagl_idle(void);

// btchip asking message signing confirmation
void btchip_bagl_confirm_message_signature(void);

// UI response to message signature
void btchip_bagl_user_action_message_signing(unsigned char confirming);

// Public key display
void btchip_bagl_display_public_key(unsigned char *derivation_path);
void btchip_bagl_user_action_display(unsigned char confirming);

void btchip_bagl_request_pubkey_approval(void);
void btchip_bagl_request_change_path_approval(unsigned char* change_path);

#endif /* _BTCHIP_BAGL_H_ */