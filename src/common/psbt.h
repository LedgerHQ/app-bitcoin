#pragma once

// clang-format off

enum PsbtGlobalType {
	PSBT_GLOBAL_UNSIGNED_TX             = 0x00,
	PSBT_GLOBAL_XPUB                    = 0x01,
	PSBT_GLOBAL_TX_VERSION              = 0x02,
	PSBT_GLOBAL_FALLBACK_LOCKTIME       = 0x03,
	PSBT_GLOBAL_INPUT_COUNT             = 0x04,
	PSBT_GLOBAL_OUTPUT_COUNT            = 0x05,
	PSBT_GLOBAL_TX_MODIFIABLE           = 0x06,
	PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE  = 0x09,
	PSBT_GLOBAL_VERSION                 = 0xFB,
	PSBT_GLOBAL_PROPRIETARY             = 0xFC
};

enum PsbtInputType {
	PSBT_IN_NON_WITNESS_UTXO            = 0x00,
	PSBT_IN_WITNESS_UTXO                = 0x01,
	PSBT_IN_PARTIAL_SIG                 = 0x02,
	PSBT_IN_SIGHASH_TYPE                = 0x03,
	PSBT_IN_REDEEM_SCRIPT               = 0x04,
	PSBT_IN_WITNESS_SCRIPT              = 0x05,
	PSBT_IN_BIP32_DERIVATION            = 0x06,
	PSBT_IN_FINAL_SCRIPTSIG             = 0x07,
	PSBT_IN_FINAL_SCRIPTWITNESS         = 0x08,
	PSBT_IN_POR_COMMITMENT              = 0x09,
	PSBT_IN_RIPEMD160                   = 0x0A,
	PSBT_IN_SHA256                      = 0x0B,
	PSBT_IN_HASH160                     = 0x0C,
	PSBT_IN_HASH256                     = 0x0D,
	PSBT_IN_PREVIOUS_TXID               = 0x0E,
	PSBT_IN_OUTPUT_INDEX                = 0x0F,
	PSBT_IN_SEQUENCE                    = 0x10,
	PSBT_IN_REQUIRED_TIME_LOCKTIME      = 0x11,
	PSBT_IN_REQUIRED_HEIGHT_LOCKTIME    = 0x12,
	PSBT_IN_TAP_KEY_SIG                 = 0x13,
	PSBT_IN_TAP_SCRIPT_SIG              = 0x14,
	PSBT_IN_TAP_LEAF_SCRIPT             = 0x15,
	PSBT_IN_TAP_BIP32_DERIVATION        = 0x16,
	PSBT_IN_TAP_INTERNAL_KEY            = 0x17,
	PSBT_IN_TAP_MERKLE_ROOT             = 0x18,
	PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS  = 0x1A,
	PSBT_IN_MUSIG2_PUB_NONCE            = 0x1B,
	PSBT_IN_MUSIG2_PARTIAL_SIG          = 0x1C,
	PSBT_IN_PROPRIETARY                 = 0xFC
};

enum PsbtOutputType {
	PSBT_OUT_REDEEM_SCRIPT              = 0x00,
	PSBT_OUT_WITNESS_SCRIPT             = 0x01,
	PSBT_OUT_BIP32_DERIVATION           = 0x02,
	PSBT_OUT_AMOUNT                     = 0x03,
	PSBT_OUT_SCRIPT                     = 0x04,
	PSBT_OUT_TAP_INTERNAL_KEY           = 0x05,
	PSBT_OUT_TAP_TREE                   = 0x06,
	PSBT_OUT_TAP_BIP32_DERIVATION       = 0x07,
	PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08,
	PSBT_OUT_PROPRIETARY                = 0xFC
};
