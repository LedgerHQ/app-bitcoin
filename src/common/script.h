#pragma once

#include <stdbool.h>

/* SDK headers */
#include "os.h"

/* Local headers */
#include "constants.h"

/** Script opcodes */
// from bitcoin-core
enum opcodetype {
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CLTV = OP_CHECKLOCKTIMEVERIFY,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_CSV = OP_CHECKSEQUENCEVERIFY,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,
};

typedef enum {
    SCRIPT_TYPE_P2PKH = 0x00,
    SCRIPT_TYPE_P2SH = 0x01,
    SCRIPT_TYPE_P2WPKH = 0x02,
    SCRIPT_TYPE_P2WSH = 0x03,
    SCRIPT_TYPE_P2TR = 0x04,
    SCRIPT_TYPE_UNKNOWN_SEGWIT = 0xFF  // a valid but undefined segwit script
} script_type_e;

static inline bool is_p2wpkh(const uint8_t script[], size_t script_len) {
    return script_len == 22 && script[0] == 0x00 && script[1] == 0x14;
}

static inline bool is_p2wsh(const uint8_t script[], size_t script_len) {
    return script_len == 34 && script[0] == 0x00 && script[1] == 0x20;
}

static inline bool is_opreturn(const uint8_t script[], size_t script_len) {
    return script_len > 0 && script_len <= 83 && script[0] == OP_RETURN;
}

/**
 * Returns the size in bytes of the minimal push opcode for <n>, where n a uint32_t.
 */
size_t get_push_script_size(uint32_t n);

/**
 * Returns a constant of type `script_type_e` indicating the type of known script type with an
 * address, or -1 for any invalid script, or valid script without an address.
 *
 * @param script the script
 * @param script_len the length of the script
 * @return a `script_type_e` on success, -1 on failure.
 */
int get_script_type(const uint8_t script[], size_t script_len);

/**
 * Computes the address corresponding to the given script, if it has one.
 * The termination character is added.
 *
 * @param script the scriptPubKey
 * @param script_len the length of `script`
 * @param out the output buffer
 * @param out_len the length of the output buffer
 * @return the length of the computed address on success; -1 if the script is invalid, if it does
 * not have an associated address (e.g. OP_RETURN), or the resulting address is too long to fit in
 * out.
 */
int get_script_address(const uint8_t script[], size_t script_len, char *out, size_t out_len);

// the longest OP_RETURN description is upper bounded by:
// - 9 bytes for "OP_RETURN"
// - 5 times 3 for the " 0x"
// - up to 2 * 80 = 160 hexadecimal bytes
// - the termination null character
#define MAX_OPRETURN_OUTPUT_DESC_SIZE (9 + 5 * 3 + 2 * 80 + 1)

/**
 * Formats a valid OP_RETURN script for user verification. The resulting string is "OP_RETURN
 * <data>", where <data> is written according to the rules below. Only scripts with up to 5 push
 * opcodes are supported, and OP_PUSHDATA2 and OP_PUSHDATA4 are not supported. OP_1NEGATE is
 * represented as "-1", and OP_0, OP_1, ..., OP_16 are represented in decimal ("0", "1", ..., "16").
 * For other push opcodes, the data is represented in hexadecimal, two characters per byte, with the
 * "0x" prefix.
 *
 * As a best-effort measure, this function returns an error if the transaction is non-standard
 * according to the default rules of Bitcoin Core (maximum 80 bytes of data, only push
 * instructions). Such transactions, even if valid, would not easily be relayed in the default
 * mempool.
 * An exception is an output script with a single OP_RETURN is accepted despite being non-standard,
 * as such an output is used in BIP-0322.
 *
 * The string is written onto `out` and is 0-terminated. Its length is returned.
 *
 * @param script the script to parse and format.
 * @param script_len the length of the script.
 * @param out the output array, that must be at least MAX_OPRETURN_OUTPUT_DESC_SIZE bytes long.
 * @return The length of the string written into `out` (including the terminating 0) on success; -1
 * on error, or if such an output would make the transaction be non-standard per the default relay
 * rules of Bitcoin Core.
 */
int format_opscript_script(const uint8_t script[],
                           size_t script_len,
                           char out[static MAX_OPRETURN_OUTPUT_DESC_SIZE]);

// the maximum length of the description of an output that we can display (address or OP_RETURN),
// including the terminating null character
#define MAX_OUTPUT_SCRIPT_DESC_SIZE MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)

/**
 * Formats a bitcoin Script in the format that is displayed to the user. Only scripts with an
 * address are supported, or OP_RETURN scripts as documented in format_opscript_script.
 *
 * The string is written onto `out` and is 0-terminated.
 *
 * @param[in] script the script to parse and format.
 * @param[in] script_len the length of the script.
 * @param[out] out the output array, that must be at least MAX_OPRETURN_OUTPUT_DESC_SIZE bytes long.
 * @return `true` the script is a supported one that can be shown to the user, `false` otherwise.
 */
bool format_script(const uint8_t script[],
                   size_t script_len,
                   char out[static MAX_OUTPUT_SCRIPT_DESC_SIZE]);
