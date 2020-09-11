#ifndef _BIP32_PATH_H_
#define _BIP32_PATH_H_

#include "stdbool.h"

#define MAX_BIP32_PATH 10
#define MAX_BIP32_PATH_LENGTH (4 * MAX_BIP32_PATH) + 1

typedef struct bip32_path {
    unsigned char length;
    unsigned int path[MAX_BIP32_PATH];
} bip32_path_t;

bool parse_serialized_path(bip32_path_t* path, unsigned char* serialized_path, unsigned char serialized_path_length);

#endif