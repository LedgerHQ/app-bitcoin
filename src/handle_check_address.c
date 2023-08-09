#include "handle_check_address.h"
#include "os.h"
#include "btchip_helpers.h"
#include "bip32_path.h"
#include "btchip_ecc.h"
#include "btchip_apdu_get_wallet_public_key.h"
#include "cashaddr.h"
#include "segwit_addr.h"
#include <string.h>

bool derive_compressed_public_key(
    unsigned char* serialized_path, unsigned char serialized_path_length,
    unsigned char* public_key, unsigned char public_key_length) {
    UNUSED(public_key_length);
    uint8_t pubKey[65];

    if (btchip_get_public_key(serialized_path, serialized_path_length, pubKey, NULL)){
        return false;
    }

    btchip_compress_public_key_value(pubKey);
    memcpy(public_key, pubKey, 33);
    return true;
}

bool get_address_from_compressed_public_key(
    unsigned char format,
    unsigned char* compressed_pub_key,
    unsigned short payToAddressVersion,
    unsigned short payToScriptHashVersion,
    const char* native_segwit_prefix,
    char * address,
    unsigned char max_address_length
) {
    bool segwit = (format == P2_SEGWIT);
    bool nativeSegwit = (format == P2_NATIVE_SEGWIT);
    bool cashAddr = (format == P2_CASHADDR);
    int address_length;
    if (cashAddr) {
        uint8_t tmp[20];
        btchip_public_key_hash160(compressed_pub_key,   // IN
                                  33,                   // INLEN
                                  tmp);
        if (!cashaddr_encode(tmp, 20, (uint8_t *)address, max_address_length, CASHADDR_P2PKH))
            return false;
    } else if (!(segwit || nativeSegwit)) {
        // btchip_public_key_to_encoded_base58 doesn't add terminating 0,
        // so we will do this ourself
        address_length = btchip_public_key_to_encoded_base58(
            compressed_pub_key,     // IN
            33,                     // INLEN
            (uint8_t *)address,                // OUT
            max_address_length - 1, // MAXOUTLEN
            payToAddressVersion, 0);
        address[address_length] = 0;
    } else {
        uint8_t tmp[22];
        tmp[0] = 0x00;
        tmp[1] = 0x14;
        btchip_public_key_hash160(compressed_pub_key,   // IN
                                  33,                   // INLEN
                                  tmp + 2               // OUT
                                  );
        if (!nativeSegwit) {
            address_length = btchip_public_key_to_encoded_base58(
                tmp,                   // IN
                22,                    // INLEN
                (uint8_t *)address,    // OUT
                150,                   // MAXOUTLEN
                payToScriptHashVersion, 0);
            address[address_length] = 0;
        } else {
            if (!native_segwit_prefix)
                return false;
            if (!segwit_addr_encode(
                address,
                native_segwit_prefix, 0, tmp + 2, 20)) {
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

int handle_check_address(check_address_parameters_t* params) {
    unsigned char compressed_public_key[33];
    PRINTF("Params on the address %d\n",(unsigned int)params);
    PRINTF("Address to check %s\n",params->address_to_check);
    PRINTF("Inside handle_check_address\n");
    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return 0;
    }
    if (!derive_compressed_public_key(
        params->address_parameters + 1,
        params->address_parameters_length - 1,
        compressed_public_key,
        sizeof(compressed_public_key))) {
        return 0;
    }

    char address[51];
    if (!get_address_from_compressed_public_key(
        params->address_parameters[0],
        compressed_public_key,
        COIN_P2PKH_VERSION,
        COIN_P2SH_VERSION,
        0,
        address,
        sizeof(address))) {
        PRINTF("Can't create address from given public key\n");
        return 0;
    }
    if (os_strcmp(address,params->address_to_check) != 0) {
        PRINTF("Addresses don't match\n");
        return 0;
    }
    PRINTF("Addresses match\n");
    return 1;
}