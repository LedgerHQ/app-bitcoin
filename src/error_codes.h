#pragma once

/* SDK headers */
#ifdef HAVE_SWAP
#include "swap_error_code_helpers.h"
#endif /* HAVE_SWAP */

/**
 * REGISTER_WALLET
 */

// The name of the policy is not acceptable
#define EC_REGISTER_WALLET_UNACCEPTABLE_POLICY_NAME 0x0000

// The wallet policy does not respect the requirement of BIP-388, or the sanity rules of miniscript
#define EC_REGISTER_WALLET_POLICY_NOT_SANE 0x0001

// No key in the wallet policy was recognized as internal.
#define EC_REGISTER_WALLET_POLICY_HAS_NO_INTERNAL_KEY 0x0002

/**
 * SIGN_PSBT
 */

// The wallet policy is not standard; it must be registered first and the HMAC must be provided.
#define EC_SIGN_PSBT_MISSING_HMAC_FOR_NONDEFAULT_POLICY 0x0000

// For standard wallet policies, the name must be zero-length (empty).
#define EC_SIGN_PSBT_NO_NAME_FOR_DEFAULT_POLICY 0x0001

// No key in the wallet policy was recognized as internal.
#define EC_SIGN_PSBT_WALLET_POLICY_HAS_NO_INTERNAL_KEY 0x0002

// Depending on the transaction type, at least one of the non-witness UTXO or witness UTXO must be
// present in the PSBT. Check in BIP-174 for the specific requirements for the transaction type.
#define EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_AND_WITNESSUTXO 0x0003

// Failed to check the txid recomputed from the non-witness-utxo. Make sure that the
// non-witness-utxo and the PSBT_IN_PREVIOUS_TXID fields are filled correctly.
#define EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED 0x0004

// The scriptpubkey or the amount in the non-witness-utxo does not match the one in the
// witness-utxo.
#define EC_SIGN_PSBT_NONWITNESSUTXO_AND_WITNESSUTXO_MISMATCH 0x0005

// Per BIP-174, legacy inputs must have the non-witness-utxo, but no witness-utxo.
#define EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_OR_UNEXPECTED_WITNESSUTXO_FOR_LEGACY 0x0006

// Per BIP-174, all segwit (or taproot) inputs must have the witness-utxo field.
#define EC_SIGN_PSBT_MISSING_WITNESSUTXO_FOR_SEGWIT 0x0007

// If an input has SIGHASH_SINGLE, its index must be less than the number of outputs.
#define EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE 0x0008

// The number of change outputs is larger than the maximum that is allowed.
#define EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS 0x0009

// The witness script in the PSBT is incorrect.
#define EC_SIGN_PSBT_MISMATCHING_WITNESS_SCRIPT 0x000a

// The redeem Script in the PSBT is incorrect.
#define EC_SIGN_PSBT_MISMATCHING_REDEEM_SCRIPT 0x000b

// The wallet policy has too many internal keys.
#define EC_SIGN_PSBT_WALLET_POLICY_TOO_MANY_INTERNAL_KEYS 0x000c

// Non-standard sighash types are not allowed unless the user has explicitly enabled them
// in the application settings. Enable "Allow non-standard sighash" in the app settings to proceed.
#define EC_SIGN_PSBT_NONDEFAULT_SIGHASH_NOT_ALLOWED 0x000d

/**
 * Swap
 */

// For swap error codes, the first byte is standardized across apps.
// Refer to the documentation of app-exchange.

// Internal application error, forward to the firmware team for analysis.
#define EC_SWAP_ERROR_INTERNAL 0x0000

// The amount does not match the one validated in Exchange.
#define EC_SWAP_ERROR_WRONG_AMOUNT 0x0100

// The destination address does not match the one validated in Exchange.
#define EC_SWAP_ERROR_WRONG_DESTINATION 0x0200

// The fees are different from what was validated in Exchange.
#define EC_SWAP_ERROR_WRONG_FEES 0x0300

// The method used is invalid in Exchange context.
#define EC_SWAP_ERROR_WRONG_METHOD 0x0400
// Only default wallet policies can be used in swaps.
#define EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY 0x0401
// No external inputs allowed in swap transactions.
#define EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS 0x0402
// Segwit transaction in swap must have the non-witness UTXO in the PSBT.
#define EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO 0x0403
// Standard swap transaction must have exactly 1 external output.
#define EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS 0x0404
// Invalid or unsupported script for external output.
#define EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT 0x0405

// The mode used for the cross-chain hash validation is not supported.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_MODE 0x0500

// The method used is invalid in cross-chain Exchange context.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD 0x0600
// The first output must be OP_RETURN <data> for a cross-chain swap.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT 0x0601
// OP_RETURN with non-zero value is not supported.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT 0x0602

// The hash for the cross-chain transaction does not match the validated value.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH 0x0700

// A generic or unspecified error not covered by the specific error codes above. Refer to the
// remaining bytes for further details on the error.
#define EC_SWAP_ERROR_GENERIC 0xFF00
// Unknown swap mode.
#define EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE 0xFF01
// handle_swap_sign_transaction.c::copy_transaction_parameters failed.
#define EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED 0xFF02

// Checking the match for the SWAP error codes with the SDK ones
#ifdef HAVE_SWAP

#define ASSERT_SWAP_ERR_CODE(btc_err_code, sdk_err_code)         \
    _Static_assert(((btc_err_code >> 8) & 0xFF) == sdk_err_code, \
                   "SWAP error code value does not match the SDK one")

ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_INTERNAL, SWAP_EC_ERROR_INTERNAL);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_AMOUNT, SWAP_EC_ERROR_WRONG_AMOUNT);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_DESTINATION, SWAP_EC_ERROR_WRONG_DESTINATION);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_FEES, SWAP_EC_ERROR_WRONG_FEES);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD, SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY, SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS, SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO, SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS, SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT,
                     SWAP_EC_ERROR_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_CROSSCHAIN_WRONG_MODE, SWAP_EC_ERROR_CROSSCHAIN_WRONG_MODE);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD, SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT,
                     SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT,
                     SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH, SWAP_EC_ERROR_CROSSCHAIN_WRONG_HASH);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_GENERIC, SWAP_EC_ERROR_GENERIC);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE, SWAP_EC_ERROR_GENERIC);
ASSERT_SWAP_ERR_CODE(EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED,
                     SWAP_EC_ERROR_GENERIC);

#endif /* HAVE_SWAP */
