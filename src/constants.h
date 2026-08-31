#pragma once

/* SDK headers */
#include "bip32.h"
#include "bolos_target.h"

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP 0xE1

/**
 * APDU instruction class for command defined by the framework.
 */
#define CLA_FRAMEWORK 0xF8

/**
 * Framework instruction to continue execution after an interruption.
 */
#define INS_CONTINUE 0x01

/**
 * Encodes the protocol version, which is passed in the p2 field of APDUs.
 */
#define CURRENT_PROTOCOL_VERSION 1

/**
 * Maximum length of a serialized address (in characters).
 * Segwit addresses can reach 74 characters; 76 on regtest because of the longer "bcrt" prefix.
 */
#define MAX_ADDRESS_LENGTH_STR (72 + sizeof(COIN_NATIVE_SEGWIT_PREFIX))

/**
 * Maximum DER-encoded signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72U

/**
 * Maximum scriptPubKey length for an input that we can sign.
 */
#define MAX_PREVOUT_SCRIPTPUBKEY_LEN 34U  // P2WSH's scriptPubKeys are the longest supported

/**
 * Maximum scriptPubKey length for an output that we can recognize.
 */
#define MAX_OUTPUT_SCRIPTPUBKEY_LEN 83U  // max 83 for OP_RETURN; other scripts are shorter

/**
 * Maximum length of a wallet registered into the device (characters), excluding terminating NULL.
 */
#define MAX_WALLET_NAME_LENGTH 64U

/**
 * Maximum length of output index string
 */
#define MAX_OUTPUT_INDEX_LENGTH sizeof("101 of 203")

/**
 * Maximum number of external outputs handled simultaneously.
 * On the Nano X, the stack size is limited to 8K at the OS level,
 * so the stack consumption has to be limited as well.
 */
#ifndef TARGET_ID
#error "bolos_target.h must be included (TARGET_* constants unavailable)"
#endif
#ifdef TARGET_NANOX
#define MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER 8U
#else
#define MAX_EXT_OUTPUT_SIMPLIFIED_NUMBER 16U
#endif

/**
 * Maximum length (characters) of a base58check-encoded serialized extended pubkey.
 */
#define MAX_SERIALIZED_PUBKEY_LENGTH 113U

/**
 * Maximum number of inputs supported while signing a transaction.
 */
#define MAX_N_INPUTS_CAN_SIGN 512U

/**
 * Maximum number of outputs supported while signing a transaction.
 */
#define MAX_N_OUTPUTS_CAN_SIGN 512U

/**
 * Maximum supported number of internal key expressions in a wallet policy.
 * A key expression is internal if we can sign for it (either as an individual key,
 * or as part of a MuSig key expression).
 */
#define MAX_INTERNAL_KEY_EXPRESSIONS 8U

// SIGHASH flags
#define SIGHASH_DEFAULT      0x00000000U
#define SIGHASH_ALL          0x00000001U
#define SIGHASH_NONE         0x00000002U
#define SIGHASH_SINGLE       0x00000003U
#define SIGHASH_ANYONECANPAY 0x00000080U

#define SEQUENCE_LOCKTIME_TYPE_FLAG (1U << 22)
#define LOCKTIME_THRESHOLD          500000000U

#define MAX_STANDARD_P2WSH_STACK_ITEMS 100U
#define MAX_STANDARD_P2WSH_SCRIPT_SIZE 3600U
#define MAX_OPS_PER_SCRIPT             201U

/* BIP-32, BIP-44 and BIP-388 constants */
/**
 * Maximum number of derivation steps for a wallet policy xpub (BIP-388).
 */
#define MAX_BIP388_XPUB_DERIVATION_STEPS 8U

/**
 * Maximum number of derivation steps allowed for SIGN_PSBT operations,
 * taking "/change/addr_index" steps into account.
 */
#define MAX_BIP32_PATH_STEPS (MAX_BIP388_XPUB_DERIVATION_STEPS + 2)

/* Build-time check to ensure our constant matches the SDK's MAX_BIP32_PATH */
_Static_assert(MAX_BIP32_PATH_STEPS == MAX_BIP32_PATH,
               "MAX_BIP32_PATH_STEPS must equal MAX_BIP32_PATH from SDK");

/**
 * Maximum length of a string representing a BIP32 derivation path.
 * Each step is up to 11 characters (10 decimal digits, plus the "hardened" symbol),
 * and there is 1 separator before each step.
 */
#define MAX_SERIALIZED_BIP32_PATH_LENGTH (12 * MAX_BIP32_PATH_STEPS)

/**
 * Index of first hardened child according to BIP32; it can also be used as the bitmask for hardened
 * children.
 */
#define BIP32_FIRST_HARDENED_CHILD 0x80000000U

#define MAX_BIP44_ACCOUNT_RECOMMENDED       100U
#define MAX_BIP44_ADDRESS_INDEX_RECOMMENDED 50000U

// Upper bound of Bitcoin's total supply in satoshis
#define BITCOIN_TOTAL_SUPPLY (21000000ULL * 100000000UL)
