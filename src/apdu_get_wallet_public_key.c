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

#include "internal.h"
#include "apdu_constants.h"

#include "bagl_extensions.h"

#include "segwit_addr.h"
#include "cashaddr.h"
#include "apdu_get_wallet_public_key.h"
#include "lib_standard_app/read.h"
#include "swap.h"

int get_public_key_chain_code(unsigned char* keyPath, size_t keyPath_len, unsigned char* publicKey, unsigned char* chainCode) {
    uint8_t public_key[65];
    int keyLength = 0;

    if (get_public_key(keyPath, keyPath_len, public_key, chainCode)) {
        return keyLength;
    }
    // Then encode it
    compress_public_key_value(public_key);
    keyLength = 33;

    memmove(publicKey, public_key,
               sizeof(public_key));
    return keyLength;
}

unsigned short apdu_get_wallet_public_key() {
    unsigned char keyLength;
    unsigned char chainCode[32];
    uint8_t is_derivation_path_unusual = 0;

    bool display = (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_DISPLAY);
    bool segwit = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_SEGWIT);
    bool nativeSegwit = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NATIVE_SEGWIT);
    bool cashAddr = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_CASHADDR);
    if (display && G_called_from_swap) {
        return SW_INCORRECT_DATA;
    }
    switch (G_io_apdu_buffer[ISO_OFFSET_P1]) {
    case P1_NO_DISPLAY:
    case P1_DISPLAY:
    case P1_REQUEST_TOKEN:
        break;
    default:
        return SW_INCORRECT_P1_P2;
    }

    switch (G_io_apdu_buffer[ISO_OFFSET_P2]) {
    case P2_NATIVE_SEGWIT:
        if (!(COIN_NATIVE_SEGWIT_PREFIX)) {
            return SW_INCORRECT_P1_P2;
        }
        __attribute__((fallthrough));
    case P2_LEGACY:
    case P2_SEGWIT:
        break;
    case P2_CASHADDR:
        if (COIN_KIND != COIN_KIND_BITCOIN_CASH) {
            return SW_INCORRECT_P1_P2;
        }
        break;
    default:
        return SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < 0x01) {
        return SW_INCORRECT_LENGTH;
    }
    if (display) {
        is_derivation_path_unusual = set_key_path_to_display(G_io_apdu_buffer + ISO_OFFSET_CDATA);
    }

    unsigned char bip44_enforced = enforce_bip44_coin_type(G_io_apdu_buffer + ISO_OFFSET_CDATA, true);

    G_io_apdu_buffer[0] = 65;
    keyLength = get_public_key_chain_code(G_io_apdu_buffer + ISO_OFFSET_CDATA, MAX_BIP32_PATH_LENGTH, G_io_apdu_buffer + 1, chainCode);

    if (keyLength == 0) {
        return SW_TECHNICAL_PROBLEM;
    }

    if (cashAddr) {
        uint8_t tmp[20];
        public_key_hash160(G_io_apdu_buffer + 1, // IN
                                  keyLength,            // INLEN
                                  tmp);
        keyLength =
            cashaddr_encode(tmp, 20, G_io_apdu_buffer + 67, 50, CASHADDR_P2PKH);
    } else if (!(segwit || nativeSegwit)) {
        keyLength = public_key_to_encoded_base58(
            G_io_apdu_buffer + 1,  // IN
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
            keyLength = public_key_to_encoded_base58(
                tmp,                   // IN
                22,                    // INLEN
                G_io_apdu_buffer + 67, // OUT
                150,                   // MAXOUTLEN
                COIN_P2SH_VERSION, 0);
        } else {
            if (COIN_NATIVE_SEGWIT_PREFIX) {
                keyLength = segwit_addr_encode(
                    (char *)(G_io_apdu_buffer + 67),
                    (char *)PIC(COIN_NATIVE_SEGWIT_PREFIX), 0, tmp + 2, 20);
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
    context_D.outLength = 1 + 65 + 1 + keyLength + sizeof(chainCode);

    // privacy : force display the address if the path isn't standard
    // and could reveal another fork holdings according to BIP 44 rules
    if (!display && !bip44_enforced) {
        display = true;
    }

    if (display) {
        if (keyLength > 50) {
            return SW_INCORRECT_DATA;
        }
        // Hax, avoid wasting space
        memmove(G_io_apdu_buffer + 200, G_io_apdu_buffer + 67, keyLength);
        G_io_apdu_buffer[200 + keyLength] = '\0';
        context_D.io_flags |= IO_ASYNCH_REPLY;
        bagl_display_public_key(is_derivation_path_unusual);
    }

    return SW_OK;
}

void bagl_user_action_display(unsigned char confirming) {
    unsigned short sw = SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming) {
        context_D.outLength -=
            2; // status was already set by the last call

    } else {
        sw = SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        context_D.outLength = 0;
    }
    G_io_apdu_buffer[context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[context_D.outLength++] = sw;

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, context_D.outLength);
}
