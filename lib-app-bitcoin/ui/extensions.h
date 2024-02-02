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

// btchip asking the per-output UI
unsigned int confirm_single_output(void);

// btchip display token
void display_token(void);

// btchip finalizing the transaction
unsigned int finalize_tx(void);

// UI response to btchip to finish the exchange
unsigned char user_action(unsigned char confirming);

// request the UI to redisplay the idle screen
void idle(void);

// btchip asking message signing confirmation
void confirm_message_signature(void);

// UI response to message signature
int user_action_message_signing(unsigned char confirming);

// Public key display
uint8_t set_key_path_to_display(const unsigned char* keyPath);
void display_public_key(uint8_t is_derivation_path_unusual);
int user_action_display(unsigned char confirming);

void request_pubkey_approval(void);
void request_change_path_approval(unsigned char* change_path);

// UI to confirm processing of tx with segwit inputs
void request_segwit_input_approval(void);

// UI to confirm signing path
void request_sign_path_approval(unsigned char* change_path);
int user_action_signtx(unsigned char confirming, unsigned char direct);
