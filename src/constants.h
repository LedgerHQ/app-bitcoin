#pragma once

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP 0xE1

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
#define MAX_DER_SIG_LEN 72

/**
 * Maximum scriptPubKey length for an input that we can sign.
 */
#define MAX_PREVOUT_SCRIPTPUBKEY_LEN 34  // P2WSH's scriptPubKeys are the longest supported

/**
 * Maximum scriptPubKey length for an output that we can recognize.
 */
#define MAX_OUTPUT_SCRIPTPUBKEY_LEN 83  // max 83 for OP_RETURN; other scripts are shorter

/**
 * Maximum length of a wallet registered into the device (characters), excluding terminating NULL.
 */
#define MAX_WALLET_NAME_LENGTH 64

/**
 * Maximum length (characters) of a base58check-encoded serialized extended pubkey.
 */
#define MAX_SERIALIZED_PUBKEY_LENGTH 113

/**
 * Maximum number of inputs supported while signing a transaction.
 */
#define MAX_N_INPUTS_CAN_SIGN 512

/**
 * Maximum number of outputs supported while signing a transaction.
 */
#define MAX_N_OUTPUTS_CAN_SIGN 512

// SIGHASH flags
#define SIGHASH_DEFAULT      0x00000000
#define SIGHASH_ALL          0x00000001
#define SIGHASH_NONE         0x00000002
#define SIGHASH_SINGLE       0x00000003
#define SIGHASH_ANYONECANPAY 0x00000080

#define SEQUENCE_LOCKTIME_TYPE_FLAG (1 << 22)
#define LOCKTIME_THRESHOLD          500000000

#define MAX_STANDARD_P2WSH_STACK_ITEMS 100U
#define MAX_STANDARD_P2WSH_SCRIPT_SIZE 3600U
#define MAX_OPS_PER_SCRIPT             201U