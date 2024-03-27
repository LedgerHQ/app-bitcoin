#include "handle_check_address.h"
#include "os.h"
#include "helpers.h"
#include "bip32_path.h"
#include "ecc.h"
#include "apdu_get_wallet_public_key.h"
#include "cashaddr.h"
#include "segwit_addr.h"
#include <string.h>

bool derive_compressed_public_key(
    unsigned char* serialized_path, unsigned char serialized_path_length,
    unsigned char* public_key, unsigned char public_key_length) {
    UNUSED(public_key_length);
    uint8_t pubKey[65];

    if (get_public_key(serialized_path, serialized_path_length, pubKey, NULL)){
        return false;
    }

    compress_public_key_value(pubKey);
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
        public_key_hash160(compressed_pub_key,   // IN
                                  33,                   // INLEN
                                  tmp);
        if (!cashaddr_encode(tmp, 20, (uint8_t *)address, max_address_length, CASHADDR_P2PKH))
            return false;
    } else if (!(segwit || nativeSegwit)) {
        // public_key_to_encoded_base58 doesn't add terminating 0,
        // so we will do this ourself
        address_length = public_key_to_encoded_base58(
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
        public_key_hash160(compressed_pub_key,   // IN
                                  33,                   // INLEN
                                  tmp + 2               // OUT
                                  );
        if (!nativeSegwit) {
            address_length = public_key_to_encoded_base58(
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

void swap_handle_check_address(check_address_parameters_t* params) {
    PRINTF("Inside swap_handle_check_address\n");
    params->result = 0;

    if (params->address_parameters == NULL) {
        PRINTF("derivation path expected\n");
        return;
    }

    if (params->address_to_check == NULL) {
        PRINTF("Address to check expected\n");
        return;
    }
    PRINTF("Address to check %s\n", params->address_to_check);

    if (params->extra_id_to_check == NULL) {
        PRINTF("extra_id_to_check expected\n");
        return;
    } else if (params->extra_id_to_check[0] != '\0') {
        PRINTF("extra_id_to_check expected empty, not '%s'\n", params->extra_id_to_check);
        return;
    }

    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return;
    }

    unsigned char compressed_public_key[33];
    if (!derive_compressed_public_key(
        params->address_parameters + 1,
        params->address_parameters_length - 1,
        compressed_public_key,
        sizeof(compressed_public_key))) {
        PRINTF("Failed to derive public key\n");
        return;
    }

    char address[51];
    if (!get_address_from_compressed_public_key(
        params->address_parameters[0],
        compressed_public_key,
        COIN_P2PKH_VERSION,
        COIN_P2SH_VERSION,
        COIN_NATIVE_SEGWIT_PREFIX,
        address,
        sizeof(address))) {
        PRINTF("Can't create address from given public key\n");
        return;
    }
    if (strcmp(params->address_to_check, address) != 0) {
        PRINTF("Address %s != %s\n", params->address_to_check, address);
        return;
    }

    PRINTF("Addresses match\n");

    params->result = 1;
    return;
}