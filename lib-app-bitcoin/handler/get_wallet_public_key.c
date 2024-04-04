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

#include "apdu_constants.h"
#include "context.h"
#include "helpers.h"

#include "extensions.h"

#include "cashaddr.h"
#include "io.h"
#include "lib_standard_app/read.h"
#include "segwit_addr.h"
#include "swap.h"

#define P1_NO_DISPLAY 0x00
#define P1_DISPLAY 0x01
#define P1_REQUEST_TOKEN 0x02

#define P2_LEGACY 0x00
#define P2_SEGWIT 0x01
#define P2_NATIVE_SEGWIT 0x02
#define P2_CASHADDR 0x03

static int get_public_key_chain_code(const unsigned char *keyPath,
                                     size_t keyPath_len,
                                     unsigned char *publicKey,
                                     unsigned char *chainCode) {
  uint8_t public_key[65];
  int keyLength = 0;

  if (get_public_key(keyPath, keyPath_len, public_key, chainCode)) {
    return keyLength;
  }
  // Then encode it
  compress_public_key_value(public_key);
  keyLength = 33;

  memmove(publicKey, public_key, sizeof(public_key));
  return keyLength;
}

WEAK unsigned short handler_get_wallet_public_key(buffer_t *buffer, uint8_t p1,
                                                  uint8_t p2) {
  unsigned char keyLength;
  unsigned char chainCode[32];
  uint8_t is_derivation_path_unusual = 0;

  bool display = (p1 == P1_DISPLAY);
  bool segwit = (p2 == P2_SEGWIT);
  bool nativeSegwit = (p2 == P2_NATIVE_SEGWIT);
  bool cashAddr = (p2 == P2_CASHADDR);

  if (display && G_called_from_swap) {
    PRINTF("Refused INS when in SWAP mode\n");
    return io_send_sw(SW_INS_NOT_SUPPORTED);
  }

  if (p1 != P1_NO_DISPLAY && p1 != P1_DISPLAY) {
    PRINTF("Wrong P1 value\n");
    return io_send_sw(SW_INCORRECT_P1_P2);
  }

  if (p2 == P2_NATIVE_SEGWIT && !COIN_NATIVE_SEGWIT_PREFIX) {
    PRINTF("Wrong P2 value\n");
    return io_send_sw(SW_INCORRECT_P1_P2);
  }

  if (p2 == P2_CASHADDR && COIN_KIND != COIN_KIND_BITCOIN_CASH) {
    PRINTF("Wrong P2 value\n");
    return io_send_sw(SW_INCORRECT_P1_P2);
  }

  if (p2 != P2_NATIVE_SEGWIT && p2 != P2_LEGACY && p2 != P2_SEGWIT &&
      p2 != P2_CASHADDR) {
    PRINTF("Wrong P2 value\n");
    return io_send_sw(SW_INCORRECT_P1_P2);
  }

  if (buffer->size < 0x01) {
    PRINTF("Wrong size\n");
    return io_send_sw(SW_INCORRECT_LENGTH);
  }

  if (display) {
    is_derivation_path_unusual = set_key_path_to_display(buffer->ptr);
  }

  unsigned char bip44_enforced = enforce_bip44_coin_type(buffer->ptr, true);

  G_io_apdu_buffer[0] = 65;
  keyLength = get_public_key_chain_code(buffer->ptr, MAX_BIP32_PATH_LENGTH,
                                        G_io_apdu_buffer + 1, chainCode);

  if (keyLength == 0) {
    return io_send_sw(SW_TECHNICAL_PROBLEM);
  }

  if (cashAddr) {
    uint8_t tmp[20];
    public_key_hash160(G_io_apdu_buffer + 1, // IN
                       keyLength,            // INLEN
                       tmp);
    keyLength =
        cashaddr_encode(tmp, 20, G_io_apdu_buffer + 67, 50, CASHADDR_P2PKH);
  } else if (!(segwit || nativeSegwit)) {
    keyLength = public_key_to_encoded_base58(G_io_apdu_buffer + 1,  // IN
                                             keyLength,             // INLEN
                                             G_io_apdu_buffer + 67, // OUT
                                             150,                   // MAXOUTLEN
                                             COIN_P2PKH_VERSION, 0);
  } else {
    uint8_t tmp[22];
    tmp[0] = 0x00;
    tmp[1] = 0x14;
    public_key_hash160(G_io_apdu_buffer + 1, // IN
                       keyLength,            // INLEN
                       tmp + 2               // OUT
    );
    if (!nativeSegwit) {
      keyLength = public_key_to_encoded_base58(tmp,                   // IN
                                               22,                    // INLEN
                                               G_io_apdu_buffer + 67, // OUT
                                               150, // MAXOUTLEN
                                               COIN_P2SH_VERSION, 0);
    } else {
      if (COIN_NATIVE_SEGWIT_PREFIX) {
        keyLength = segwit_addr_encode((char *)(G_io_apdu_buffer + 67),
                                       (char *)PIC(COIN_NATIVE_SEGWIT_PREFIX),
                                       0, tmp + 2, 20);
        if (keyLength == 1) {
          keyLength = strlen((char *)(G_io_apdu_buffer + 67));
        }
      }
    }
  }
  G_io_apdu_buffer[66] = keyLength;
  PRINTF("Length %d\n", keyLength);
  // Restore for the full key component
  G_io_apdu_buffer[1] = 0x04;

  // output chain code
  memmove(G_io_apdu_buffer + 1 + 65 + 1 + keyLength, chainCode,
          sizeof(chainCode));
  context.outLength = 1 + 65 + 1 + keyLength + sizeof(chainCode);

  // privacy : force display the address if the path isn't standard
  // and could reveal another fork holdings according to BIP 44 rules
  if (!display && !bip44_enforced) {
    display = true;
  }

  if (display) {
    if (keyLength > 50) {
      return io_send_sw(SW_INCORRECT_DATA);
    }
    // Hax, avoid wasting space
    memmove(G_io_apdu_buffer + 200, G_io_apdu_buffer + 67, keyLength);
    G_io_apdu_buffer[200 + keyLength] = '\0';
    display_public_key(is_derivation_path_unusual);
    return 0;
  }
  return io_send_response_pointer(G_io_apdu_buffer, context.outLength, SW_OK);
}

int user_action_display(unsigned char confirming) {
  // confirm and finish the apdu exchange //spaghetti
  if (confirming) {
    return io_send_response_pointer(G_io_apdu_buffer, context.outLength, SW_OK);

  } else {
    context.outLength = 0;
    return io_send_sw(SW_CONDITIONS_OF_USE_NOT_SATISFIED);
  }
}
