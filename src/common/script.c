#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "script.h"

/* SDK headers */
#include "bip32.h"
#include "buffer.h"
#include "read.h"

/* Local headers */
#include "segwit_addr.h"
#include "../crypto.h"

size_t get_push_script_size(uint32_t n) {
    if (n <= 16)
        return 1;  // OP_0 and OP_1 .. OP_16
    else if (n < 0x80)
        return 2;  // 01 nn
    else if (n < 0x8000)
        return 3;  // 02 nnnn
    else if (n < 0x800000)
        return 4;  // 03 nnnnnn
    else if (n < 0x80000000)
        return 5;  // 04 nnnnnnnn
    else
        return 6;  // 05 nnnnnnnnnn
}

int get_script_type(const uint8_t script[], size_t script_len) {
    if (script_len == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 0x14 &&
        script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        return SCRIPT_TYPE_P2PKH;
    }

    if (script_len == 23 && script[0] == OP_HASH160 && script[1] == 0x14 &&
        script[22] == OP_EQUAL) {
        return SCRIPT_TYPE_P2SH;
    }

    if (script_len == 22 && script[0] == 0x00 && script[1] == 0x14) {
        return SCRIPT_TYPE_P2WPKH;
    }

    if (script_len == 34 && script[0] == OP_0 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2WSH;
    }

    if (script_len == 34 && script[0] == OP_1 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2TR;
    }

    // match if it is a potentially valid future segwit scriptPubKey as per BIP-0141
    if (script_len >= 4 && script_len <= 42 &&
        (script[0] == 0 || (script[0] >= OP_1 && script[0] <= OP_16))) {
        uint8_t push_len = script[1];
        if (script_len == 1 + 1 + push_len) {
            return SCRIPT_TYPE_UNKNOWN_SEGWIT;
        }
    }

    // unknown/invalid, or doesn't have an address
    return -1;
}

// TODO: add unit tests
int get_script_address(const uint8_t script[], size_t script_len, char *out, size_t out_len) {
    int script_type = get_script_type(script, script_len);
    int addr_len;

    if (out_len == 0) return -1;

    switch (script_type) {
        case SCRIPT_TYPE_P2PKH:
        case SCRIPT_TYPE_P2SH: {
            int offset = (script_type == SCRIPT_TYPE_P2PKH) ? 3 : 2;
            int ver = (script_type == SCRIPT_TYPE_P2PKH) ? COIN_P2PKH_VERSION : COIN_P2SH_VERSION;
            addr_len = base58_encode_address(script + offset, ver, out, out_len - 1);
            if (addr_len < 0) {
                return -1;
            }
            break;
        }
        case SCRIPT_TYPE_P2WPKH:
        case SCRIPT_TYPE_P2WSH:
        case SCRIPT_TYPE_P2TR:
        case SCRIPT_TYPE_UNKNOWN_SEGWIT: {
            uint8_t prog_len = script[1];  // length of the witness program

            // witness program version
            int version = (script[0] == 0 ? 0 : script[0] - 80);

            // make sure that the output buffer is long enough
            if (out_len < 73 + strlen(COIN_NATIVE_SEGWIT_PREFIX)) {
                return -1;
            }

            int ret =
                segwit_addr_encode(out, COIN_NATIVE_SEGWIT_PREFIX, version, script + 2, prog_len);

            if (ret != 1) {
                return -1;  // should never happen
            }

            addr_len = strlen(out);
            break;
        }
        default:
            return -1;
    }
    if (addr_len >= 0) {
        out[addr_len] = '\0';
    }
    return addr_len;
}

int format_opscript_script(const uint8_t script[],
                           size_t script_len,
                           char out[static MAX_OPRETURN_OUTPUT_DESC_SIZE]) {
    if (script_len == 0 || script[0] != OP_RETURN) {
        return -1;
    }

    if (script_len > 83) {
        // a script that is more than 83 bytes violates the "max 80 bytes total data" rule
        // (+ 3 bytes of opcodes) and is therefore not standard in Bitcoin Core.
        return -1;
    }

    strncpy(out, "OP_RETURN ", MAX_OPRETURN_OUTPUT_DESC_SIZE);
    int out_ctr = 10;

    // If the length of the script is 1 (just "OP_RETURN"), then it's not standard per bitcoin-core.
    // However, signing such outputs is part of BIP-0322, and there's no danger in allowing them.

    if (script_len == 1) {
        out[out_ctr - 1] = '\0';  // remove extra space
        return out_ctr;
    }

    size_t offset = 1;  // start after OP_RETURN
    int num_pushes = 0;
    const char hex[] = "0123456789abcdef";

    while (offset < script_len && num_pushes < 5) {
        uint8_t opcode = script[offset++];
        size_t hex_length = 0;  // Data length to process

        if (opcode > OP_16 || opcode == OP_RESERVED || opcode == OP_PUSHDATA2 ||
            opcode == OP_PUSHDATA4) {
            return -1;  // unsupported
        }

        if (opcode == OP_0) {
            out[out_ctr++] = '0';
        } else if (opcode >= 1 && opcode <= 75) {
            // opcodes between 1 and 75 indicate a data push of the corresponding length
            hex_length = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            // the next byte is the length
            if (offset >= script_len) {
                return -1;  // out of bounds for length byte
            }
            hex_length = script[offset++];
            if (hex_length <= 75) {
                return -1;  // non-standard, should have used the minimal push opcode
            }
        } else if (opcode == OP_1NEGATE) {
            out[out_ctr++] = '-';
            out[out_ctr++] = '1';
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            uint8_t num = opcode - 0x50;
            // num is a number between 1 and 16 (included)
            if (num >= 10) {
                out[out_ctr++] = '1';
                num -= 10;
            }
            out[out_ctr++] = '0' + num;
        } else {
            // any other opcode is invalid or unsupported
            return -1;
        }

        if (offset + hex_length > script_len) {
            // overflow, not enough bytes to read in the script
            return -1;
        }

        if (hex_length == 1) {
            if (script[offset] == 0x81 || (1 <= script[offset] && script[offset] <= 16)) {
                // non-standard, it should use OP_1NEGATE, or one of OP_1, ..., OP_16
                return -1;
            }
        }

        if (hex_length > 0) {
            out[out_ctr++] = '0';
            out[out_ctr++] = 'x';
            for (unsigned int i = 0; i < hex_length; i++) {
                uint8_t data = script[offset + i];
                out[out_ctr++] = hex[data / 16];
                out[out_ctr++] = hex[data % 16];
            }
            offset += hex_length;
        }

        num_pushes++;
        out[out_ctr++] = ' ';
    }

    if (offset < script_len) {
        // if there are still more opcodes left, we do not support this script
        // (for example: more than 5 push opcodes)
        return -1;
    }

    out[out_ctr - 1] = '\0';
    return out_ctr;
}

bool format_script(const uint8_t script[],
                   size_t script_len,
                   char out[static MAX_OUTPUT_SCRIPT_DESC_SIZE]) {
    int address_len = get_script_address(script, script_len, out, MAX_OUTPUT_SCRIPT_DESC_SIZE);
    if (address_len < 0) {
        // script does not have an address; check if OP_RETURN
        if (is_opreturn(script, script_len)) {
            if (0 > format_opscript_script(script, script_len, out)) {
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}
