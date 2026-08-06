#ifdef HAVE_SWAP

#include <string.h>

/* SDK headers */
#include "bip32_path.h"
#include "os.h"
#include "swap_lib_calls.h"

/* Local headers */
#include "crypto.h"
#include "segwit_addr.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// constants previously defined in btchip_apdu_get_wallet_public_key.h
#define P1_NO_DISPLAY    0x00
#define P1_DISPLAY       0x01
#define P1_REQUEST_TOKEN 0x02

#define P2_LEGACY        0x00
#define P2_SEGWIT        0x01
#define P2_NATIVE_SEGWIT 0x02  // bech32
#define P2_CASHADDR      0x03
#define P2_TAPROOT       0x04  // bech32m

bool get_address_from_compressed_public_key(unsigned char format,
                                            unsigned char* compressed_pub_key,
                                            unsigned short payToAddressVersion,
                                            unsigned short payToScriptHashVersion,
                                            const char* native_segwit_prefix,
                                            char* address,
                                            unsigned char max_address_length) {
    int address_length;

    // clang-format off
    if (format == P2_LEGACY) {
        // clang-format on
        uint8_t tmp[20];
        crypto_hash160(compressed_pub_key, 33, tmp);
        address_length =
            base58_encode_address(tmp, payToAddressVersion, address, max_address_length - 1);
        if (address_length < 0) {
            return false;
        }
        address[address_length] = 0;
    } else {
        uint8_t script[22];
        script[0] = 0x00;
        script[1] = 0x14;
        crypto_hash160(compressed_pub_key,  // IN
                       33,                  // INLEN
                       script + 2           // OUT
        );
        if (format == P2_SEGWIT) {
            // wrapped segwit
            uint8_t tmp[20];
            crypto_hash160(script, 22, tmp);
            // wrapped segwit
            address_length =
                base58_encode_address(tmp, payToScriptHashVersion, address, max_address_length - 1);
            if (address_length < 0) {
                return false;
            }
            address[address_length] = 0;
        } else {  // native segwit or taproot
            if (!native_segwit_prefix) return false;
            if (format == P2_NATIVE_SEGWIT) {
                if (!segwit_addr_encode(address, native_segwit_prefix, 0, script + 2, 20)) {
                    return false;
                }
            } else if (format == P2_TAPROOT) {
                uint8_t tweaked_key[32];

                uint8_t parity;
                crypto_tr_tweak_pubkey(compressed_pub_key + 1,
                                       (uint8_t[]) {},
                                       0,
                                       &parity,
                                       tweaked_key);

                if (!segwit_addr_encode(address, native_segwit_prefix, 1, tweaked_key, 32)) {
                    return false;
                }
            } else {
                PRINTF("Expected native segwit or taproot address\n");
                return false;
            }
        }
    }
    return true;
}

static int os_strcmp(const char* s1, const char* s2) {
    size_t size = strlen(s1) + 1;
    return memcmp(s1, s2, size);
}

void swap_handle_check_address(check_address_parameters_t* params) {
    unsigned char compressed_public_key[33];
    PRINTF("Params on the address %d\n", (unsigned int) params);
    PRINTF("Address to check %s\n", params->address_to_check);
    PRINTF("Inside handle_check_address\n");
    params->result = 0;
    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return;
    }
    bip32_path_t path;
    if (!parse_serialized_path(&path,
                               params->address_parameters + 1,
                               params->address_parameters_length - 1)) {
        PRINTF("Can't parse path\n");
        return;
    }

    if (CX_OK !=
        crypto_get_compressed_pubkey_at_path(path.path, path.length, compressed_public_key, NULL)) {
        return;
    }
    char address[MAX_ADDRESS_LENGTH_STR + 1];
    if (!get_address_from_compressed_public_key(params->address_parameters[0],
                                                compressed_public_key,
                                                COIN_P2PKH_VERSION,
                                                COIN_P2SH_VERSION,
                                                COIN_NATIVE_SEGWIT_PREFIX,
                                                address,
                                                sizeof(address))) {
        PRINTF("Can't create address from given public key\n");
        return;
    }
    if (os_strcmp(address, params->address_to_check) != 0) {
        PRINTF("Addresses don't match\n");
        return;
    }
    PRINTF("Addresses match\n");
    params->result = 1;
}

#endif /* HAVE_SWAP */
