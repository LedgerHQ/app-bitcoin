#include "bip32_path.h"
#include "btchip_helpers.h"

bool parse_serialized_path(bip32_path_t* path, unsigned char* serialized_path, unsigned char serialized_path_length) {
    if (serialized_path_length < 1 ||
        serialized_path[0] > MAX_BIP32_PATH ||
        serialized_path[0] * 4 + 1 > serialized_path_length)
        return false;
    path->length = serialized_path[0];
    serialized_path++;
    for (int i = 0; i < path->length; i += 1, serialized_path += 4) {
        path->path[i] = btchip_read_u32(serialized_path, 1, 0);
    }
    return true;
}
